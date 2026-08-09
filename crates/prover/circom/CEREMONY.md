# DEXBatch trusted setup ceremony

This document is the operational runbook for the Groth16 trusted setup
ceremony for `dex_batch.circom` (the equivalence-checked port of
`DEXBatchCircuit` -- see `EQUIVALENCE.md`). It exists so any participant
can run their step correctly and so any observer can verify the whole
chain afterward, without having to ask anyone questions or trust
anyone's word.

The currently checked-in `crates/prover/trusted_setup.bin` was generated
by a single party (this repo's own history) and must be treated as
permanently compromised for production use -- it is dev/test-only. This
ceremony produces its replacement.

## 0. Circuit freeze

Before recruiting a single participant: tag the exact commit whose
`crates/prover/circom/dex_batch.circom` the ceremony will run against,
e.g.

```sh
git tag ceremony-circuit-v1 <commit>
git push origin ceremony-circuit-v1
```

**Any subsequent change to `dex_batch.circom` invalidates the ceremony.**
If the circuit changes after this point, retag and restart Phase 2 from
a fresh `groth16 setup` against the new `.r1cs`. Participants should be
told the tag they're contributing against, and can independently
recompile it and compare the "Circuit Hash" printed by `groth16 setup`
(see step 2) to confirm they're working on the same circuit as everyone
else.

## 1. Phase 1 (Powers of Tau) -- reuse, do not regenerate

Phase 1 is circuit-agnostic (just a large enough power-of-tau for the
circuit's constraint count) and several high-participation public
ceremonies already exist and are safe to reuse -- there is no reason to
run a new one. Use a `.ptau` file from an established ceremony such as
[Perpetual Powers of Tau](https://github.com/privacy-scaling-explorations/perpetualpowersoftau)
(hundreds of contributors, includes a random beacon finalization).

- Download the smallest `.ptau` file whose declared power covers this
  circuit. `dex_batch.circom` compiles to 32 constraints, so `2^10`
  (`powersOfTau28_hez_final_10.ptau`, power=10 covers up to 1024
  constraints) is comfortably enough headroom.
- **Verify the file's hash against the ceremony's own published
  manifest** before using it -- do not trust the download alone.
- Confirm it's already phase-2-prepared (Perpetual Powers of Tau's
  `_final` files are); if starting from a raw contribution instead, run
  `snarkjs powersoftau prepare phase2 <in>.ptau <out>.ptau -v` once,
  which is a deterministic, non-trust-sensitive transform.

This step was dry-run tested locally with a throwaway, single-contributor
`powersoftau new`/`contribute`/`beacon`/`prepare phase2` chain purely to
confirm the commands and file formats work -- that throwaway output is
**not** used here; a real ceremony must start from a real, independently
verified public `.ptau`.

## 2. Phase 2 (circuit-specific) -- init

From the tagged commit, with `circom` and `snarkjs` (v0.7+) on `PATH`:

```sh
cd crates/prover/circom
circom dex_batch.circom --r1cs --sym --wasm -o .
snarkjs groth16 setup dex_batch.r1cs <phase1>.ptau dex_batch_0000.zkey
```

This prints a **Circuit Hash** -- publish it immediately (coordination
channel, see section 5) as the reference value every participant and
observer cross-checks against for the rest of the ceremony. Publish
`dex_batch_0000.zkey`'s own hash (`sha256sum dex_batch_0000.zkey`) too,
as the literal starting artifact.

## 3. Phase 2 contributions -- sequential, one participant at a time

Each participant, in turn, takes the previous participant's `.zkey`,
contributes fresh entropy, and passes the result to the next:

```sh
snarkjs zkey contribute dex_batch_<NNNN>.zkey dex_batch_<NNNN+1>.zkey \
  --name="<participant name or handle>" -v -e="<participant's own private random entropy>"
```

- The entropy (`-e`) must be generated privately by the participant
  (e.g. `head -c64 /dev/urandom | xxd -p`, dice rolls, mouse jitter --
  anything with real randomness) and **never shared or logged**. The
  security of the whole ceremony rests on at least one participant's
  entropy staying secret and being genuinely random.
- The command prints two hashes participants must publish immediately,
  before passing the `.zkey` along:
  - **Circuit Hash** -- constant across all contributions; must match
    the value published in step 2. If it doesn't, stop -- something is
    wrong with the file you were handed.
  - **Contribution Hash** -- unique to this contribution; this is your
    proof you actually participated and what your entropy was applied
    to. Publish this hash plus `sha256sum` of your output `.zkey` to the
    shared coordination channel before sending the file to the next
    participant.
- After contributing, **securely delete** the entropy and any
  intermediate state. Keep the output `.zkey` file itself (or ensure the
  coordinator retains it) -- that's the auditable ceremony artifact, not
  a secret.

Repeat for every participant, numbering sequentially
(`dex_batch_0001.zkey`, `dex_batch_0002.zkey`, ...).

## 4. Finalization -- public beacon

After the last participant contributes, close the ceremony with a public
randomness beacon nobody could have predicted in advance (e.g. a future
Bitcoin/Ethereum block hash, drand round, or similar public source
decided and announced ahead of time):

```sh
snarkjs zkey beacon dex_batch_<final_contrib>.zkey dex_batch_final.zkey \
  <beacon_hex> <iterations_exp> -n="<description of beacon source, e.g. block height/hash>"
```

`<iterations_exp>` of `10` (i.e. 2^10 hash iterations applied to the
beacon value) matches common practice and was used in local dry-run
testing; publish whatever value is used alongside the beacon's own
source description so it's independently reproducible.

## 5. Public verification (no trust required)

Anyone -- not just participants -- can verify the *entire* contribution
chain end to end:

```sh
snarkjs zkey verify dex_batch.r1cs <phase1>.ptau dex_batch_final.zkey
```

This independently recomputes and prints every contribution's hash in
order (including the final beacon) and reports `ZKey Ok!` only if the
whole chain is internally consistent with the circuit and Phase 1 file.
Anyone with the published `.r1cs`, the Phase 1 `.ptau`, and
`dex_batch_final.zkey` can and should run this themselves rather than
taking anyone's word for it.

Finally, export the production verifying key:

```sh
snarkjs zkey export verificationkey dex_batch_final.zkey verification_key.json
```

Sanity-check `verification_key.json`'s `"nPublic"` field is `2`,
matching `DEXBatchCircuit`'s two public inputs (`pre_root`, `post_root`).

## 6. Participant recruitment

Target roughly **10-15 participants**. Past a reasonable floor, security
comes from *diversity* of participant, not raw count -- the ceremony is
secure as long as at least one participant is honest and actually
discards their entropy, so the goal is making collusion or coercion of
every single participant implausible, not maximizing headcount.

Aim for a mix of:

- **Project-affiliated participants**: node operators already staked in
  `NodeRegistry`, who have skin in the game and reputational stake in
  the ceremony being legitimate.
- **Fully independent outside participants**: people with no financial
  or organizational tie to this project (other ZK projects' contributors,
  independent security researchers, etc.), who have no incentive to
  collude with project insiders.

Recruitment itself (identifying and inviting specific people/orgs) is a
human coordination task, not something automatable from this repo.

## 7. Coordination channel and timeline

- Announce the circuit-freeze tag, Phase 1 `.ptau` source+hash, and
  contribution order/schedule in a durable, public channel (e.g. a
  pinned GitHub Discussion or issue) before Phase 2 begins.
- Each participant gets an assigned slot with a **reasonable response
  window** (e.g. 72 hours) after being handed the previous `.zkey`; if
  they don't respond in time, skip to the next participant in the
  sequence and flag the skip publicly (do not silently reorder without
  a public note -- observers need the full, honest sequence of what
  happened to verify it).
- Every contribution hash (step 3) is posted to this same channel
  **as it happens**, not batched at the end -- this lets anyone catch
  tampering, stalling, or a skipped step early rather than after the
  fact.

## 8. Post-ceremony integration

1. Publish `dex_batch_final.zkey`, `verification_key.json`, and the full
   `snarkjs zkey verify` transcript alongside this document.
2. Replace `crates/prover/trusted_setup.bin` with the artifact derived
   from `dex_batch_final.zkey` and remove the single-party-generated one
   from active use (keep it only if still needed for non-production
   test paths, clearly labeled as such).
3. **Not yet done, separate follow-up work**: wiring
   [`arkworks-rs/circom-compat`](https://github.com/arkworks-rs/circom-compat)
   into `crates/prover` so the Rust proving/verification path consumes
   the circom-derived key directly, instead of `crates/prover/src/bn254.rs`'s
   current arkworks-native setup. Remember `circom-compat` requires
   `CircomReduction` (not arkworks' default R1CS-to-QAP reduction) when
   consuming a circom-format proving key -- an easy-to-miss mismatch
   that silently produces invalid proofs rather than an error.

## Command reference (verified)

Every command above was dry-run end-to-end against the real
`dex_batch.r1cs` compiled from this directory before being written down
here (throwaway Phase 1 `.ptau`, two throwaway Phase 2 contributions,
beacon, verify, export) -- `ZKey Ok!` and a correct `"nPublic": 2` export
were both confirmed. Only the Phase 1 source differs between the dry run
and a real ceremony (throwaway `powersoftau new` vs. a real published
`.ptau`, per section 1).
