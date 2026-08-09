# MEX

A hybrid off-chain/on-chain DEX: an off-chain matching engine and gossip
mesh produce trades, a Groth16 ZK circuit proves batches of them were
matched correctly, and Solidity (with Solana/CosmWasm equivalents)
contracts settle proven batches on-chain.

## Architecture

```
trader --HTTP/WS--> api (matching, order log, WS fills)
                      |
                      |--- protocol: gossip mesh, order sequencing,
                      |    quorum/consensus across replicas
                      |
                      v
                   batcher --> prover (Groth16/bn254, arkworks) --> proof
                      |
                      v
              chain-ethereum (alloy) --settleBatchWithFees--> SettlementFactory.sol
                      |                                             |
                      |                                        NodeRegistry.sol
                      v                                        (stake, slashing,
                 watchtower                                     reputation)
            (pre-flight fraud/fee/
             deadline checks)
```

Every accepted order and match is recorded in an append-only,
hash-chained log (`orderlog`) a third party can independently replay
and verify against what the server claims it did. State is durable
(WAL + periodic snapshots, `crates/api/src/persistence.rs`) and
survives a crash/restart without data loss.

## Crates

Core pipeline:
- `common` -- shared types (`Order`, fee schedule, `SettlementPreference`)
- `engine` -- the matching engine (in-memory order book, price-time priority)
- `protocol` -- gossip mesh, order sequencing, quorum/consensus for
  multi-replica deployments
- `api` -- the axum HTTP/WS server: order intake, matching, persistence,
  settlement submission, rate limiting, auth
- `batcher` -- groups confirmed matches into proof-ready batches
- `prover` -- Groth16/bn254 circuit (`DEXBatchCircuit`) and backend
  (arkworks); see `crates/prover/circom/` for the equivalence-checked
  circom port used for the trusted setup ceremony
- `storage` / `orderlog` -- WAL persistence and the hash-chained
  accountability log
- `chain` -- chain-agnostic settlement trait (`ChainAdapter`)
- `chain-ethereum` / `chain-solana` / `chain-cosmwasm` -- per-chain
  adapters (Ethereum via alloy is the only one wired into a runnable
  binary today)
- `watchtower` -- pre-flight fraud/fee/deadline detection, wired into
  `api`'s real settlement loop
- `reputation`, `tss`, `security`, `sandbox`, `topology`, `heartbeat` --
  supporting subsystems (P2P scoring, threshold signatures, packet
  encryption, WASM strategy sandboxing, mesh topology, liveness)

Contracts (`contracts/ethereum`, `contracts/solana`, `contracts/cosmwasm`):
`SettlementFactory`/`TraderEscrow` (commit-then-settle trade lifecycle,
fee handling, missed-deadline slashing via `claimSlash`), `NodeRegistry`
(stake, reputation, slashing authority), `BatchVerifier` (on-chain Groth16
verifier).

Test/demo crates: `integration` (end-to-end scenarios, exploit demos,
100-node scale test), `security_tests`, `stress_tests`, `benchmarks`,
`agent-sim`, `trader-client` (CLI for driving a live node).

## Running

```sh
cargo build --workspace --all-targets
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt --check

npx hardhat compile   # run from the repo root -- hardhat.config.js points at contracts/ethereum
```

To run the API server, see the full env var reference at the top of
`crates/api/src/main.rs` (auth, RPC/contract addresses, mesh, order
sequencing, persistence, rate limiting, fees). Minimum to boot against a
live Ethereum RPC:

```sh
MEX_API_KEY=... \
MEX_RPC_URL=... \
MEX_NODE_PRIVATE_KEY=... \
MEX_FACTORY_ADDRESS=... \
MEX_REGISTRY_ADDRESS=... \
MEX_SETTLEMENT_NODE_PUBKEY=... \
cargo run --release -p api
```

`MEX_API_KEY` is required in a `--release` build (the server panics at
startup rather than falling back to a known default); a debug build
(`cargo run` without `--release`) uses a dev default with a loud warning
if unset, so local development needs no setup.

CI (`.github/workflows/ci.yml`) runs `cargo build/test/clippy/fmt` across
the workspace and a Hardhat contract-compile check on every push/PR to
`master`.

## Known limitations

- **ZK trusted setup**: `crates/prover/trusted_setup.bin` is a
  single-party-generated placeholder, not production-safe. A real
  multi-party ceremony is scoped and documented in
  `crates/prover/circom/CEREMONY.md` (circuit equivalence already
  verified, see `crates/prover/circom/EQUIVALENCE.md`) but has not been
  run. Once it has, wiring `arkworks-rs/circom-compat` into `crates/prover`
  to consume the resulting key is separate, not-yet-started work.
- **Only Ethereum is wired into a runnable binary.** `chain-solana` and
  `chain-cosmwasm` exist as adapters but nothing in `crates/api` or
  elsewhere constructs and runs against them yet.
- **No deployment automation.** No Dockerfile or orchestration manifests
  exist; running this in production today means building and deploying
  the `api` binary (and the contracts) by hand.
- **clippy is not run with `-D warnings`** in CI -- the codebase has
  pre-existing lint warnings not yet triaged. Tightening this is a
  deliberate future step once they're addressed, not an oversight.
- **`watchtower`'s on-chain actions are limited to what the deployed
  contracts actually support**: an invalid proof is rejected atomically
  by `settleBatchWithFees` itself (no separate dispute step exists to
  wire up), and there's no on-chain call to slash a trader for a fee
  mismatch. `watchtower` runs as a pre-flight gate in the real
  settlement loop (skips submitting chunks it can prove are wrong,
  reports missed deadlines on-chain) rather than as a post-hoc
  dispute/slashing system -- see `crates/watchtower/src/lib.rs`'s docs.
