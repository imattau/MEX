# frg-settlement

MEX's settlement contract for [FRG](https://github.com/imattau/FRG), playing
the role `SettlementFactory.sol`/`BatchVerifier.sol` play on Ethereum:
verify a Groth16 batch proof, record which trades it covers as settled.

Standalone crate, not a member of the root MEX Cargo workspace (`[workspace]`
in this crate's own `Cargo.toml` stops it there) -- it's a deploy artifact
for a different chain, not linked into any MEX binary. Its `dev-dependencies`
reach into `crates/prover`/`engine`/`common` by path purely so its test
suite can generate real proofs to verify against.

## Scope

This is **not** a full port of `SettlementFactory.sol`. It verifies a batch
proof and marks trades settled; it does not implement trader escrow
deposits, fee-tier transfers, or missed-deadline slashing -- those would
need FRG's `frg::transfer` host function and a much larger design (real
per-trader balances held in the contract, a deposit/withdraw flow, a
slashing authority), deliberately left for later rather than half-built
here. This covers exactly what `chain::ChainAdapter::submit_settlement_batch`
and `::is_trade_settled` need: did this batch's proof verify, and is this
trade covered by a settled batch.

## Build

```sh
cargo build --release --target wasm32-unknown-unknown
```

Produces `target/wasm32-unknown-unknown/release/frg_settlement.wasm`,
importing only from FRG's `"frg"` host-function module (verified via
`wasm-tools print` against FRG's `core/contract/runtime.go`'s
`validateModule`, which rejects any other import module).

```sh
cargo test
```

Runs the pure-math test suite (`src/groth16.rs`) on the host target: real
proofs from `crates/prover`'s checked-in trusted setup, round-tripped
through this contract's calldata format and verification math, cross-checked
against an independent `ark_bn254::Bn254::multi_pairing` call (not the
`bn254_pairing_check` host function itself, which only exists inside a real
FRG node). This is the strongest verification possible without a live FRG
devnet -- it has not been deployed against one.

## Deploy

```sh
curl -X POST http://127.0.0.1:8090/contracts/deploy \
  -H 'content-type: application/json' \
  -d "{\"wasm_hex\":\"$(xxd -p -c 0 target/wasm32-unknown-unknown/release/frg_settlement.wasm)\",\"value_quanta\":\"0\"}"
```

(via `frg-wallet`'s HTTP API -- see `crates/chain-frg/src/wallet.rs`'s
`deploy_contract`, which wraps exactly this call.)

## ABI

Exported WASM functions, selected by the literal ASCII bytes of the calldata's
first 4 bytes (FRG's contract calling convention -- see
`core/contract/contract.go`'s `Call`):

- `init` -- no-op. The verifying key is compiled in (`src/vk.rs`), not
  passed at deploy time: FRG's `Deploy` never populates `init`'s calldata
  (`RuntimeConfig.CallData` is left unset), so there's no constructor-style
  argument channel the way `BatchVerifier.sol`'s constructor takes the VK.
  A new trusted setup means recompiling and redeploying this contract, not
  reconfiguring it.
- `sett` -- verifies a batch proof and, if valid, records each covered
  trade's hash as settled (`state_set(trade_hash, [1])`). Traps (WASM
  `unreachable`) on malformed calldata or failed verification, which FRG
  surfaces as a failed transaction with all state changes discarded.

### `sett` calldata (after the 4-byte selector -- see `src/groth16.rs`'s
module docs for the authoritative spec)

```text
[0..32)    pre_root, big-endian Fr  (the proof's 1st public input)
[32..64)   post_root, big-endian Fr (the proof's 2nd public input)
[64]       trade_count, 1..=8
[65..)     trade_count trade_hash entries, 32 bytes each
[..+256)   Groth16 proof: a.x(32) a.y(32) | b.x.c0(32) b.x.c1(32) b.y.c0(32) b.y.c1(32) | c.x(32) c.y(32)
```

`pre_root`/`post_root` are trusted directly as the proof's public inputs,
not recomputed on-chain from the trades -- mirroring `BatchVerifier.sol`,
whose `verifyProof` does the same. `chain::SettlementTrade` has no `price`
field to recompute a root from in the first place; the trade-hash list only
picks which trades get flagged settled after a successful proof check.

`a`/`c`/`b` use the same big-endian, arkworks-native-G2-order layout
`prover::decode_proof_calldata`'s `ProofCalldata` already produces --
building this calldata from that struct needs no extra reordering.

### Reading settlement status

No dedicated read function: `state_set` was called with `key = trade_hash`
(exactly 32 bytes) and `value = [1]`, so it's queryable directly via FRG's
generic contract-state API with no WASM call involved --
`GetContractState`/`/contracts/state?contract_address=...&key_hex=<trade_hash>`.
`found: true` means settled. This is what `chain::ChainAdapter::is_trade_settled`
should be wired to once `chain-frg` gets a `settlement_contract_address`
configured (see `crates/chain-frg/src/lib.rs`'s `FrgAdapter`, currently a
stub for exactly this reason).

## Regenerating `src/vk.rs`

The constants in `src/vk.rs` are `prover::export_verifying_key_calldata()`'s
output against `crates/prover/trusted_setup.bin`, dumped once and pasted in
by hand. If that trusted setup ever changes, `vk.rs` must be regenerated to
match -- `vk_constants_are_valid_points` (in `src/groth16.rs`'s tests) checks
the constants are valid curve points, but can't detect a stale-but-still-valid
key on its own.
