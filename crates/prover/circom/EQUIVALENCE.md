# dex_batch.circom <-> DEXBatchCircuit equivalence

Stage P6-1b of the ZK trusted-setup-ceremony effort. `dex_batch.circom`
is a port of `crates/prover/src/lib.rs`'s `DEXBatchCircuit<F>` (an
arkworks `ConstraintSynthesizer`). Once a ceremony runs, it runs against
*this circom file*, not the Rust struct -- so the whole point of this
document is establishing, as rigorously as practical, that the two
actually encode the same constraint system before that happens. A
ceremony run against a circuit that's subtly different from what
`crates/prover` actually proves/verifies would be worthless (or worse,
misleading) security theater.

Two independent checks, complementary rather than either alone
sufficient:

## 1. Witness-level cross-testing (concrete, several fixtures)

`./check_equivalence.sh` (requires `circom`, `snarkjs`, `node`, and
`cargo` on PATH -- deliberately NOT part of the default `cargo test`
toolchain, see the script's own header) runs five fixtures through the
compiled circom circuit's witness generator, each with an identical
numeric counterpart asserted in a Rust test in
`crates/prover/src/lib.rs`, so neither side was invented independently
of the other:

| fixture | circom input | Rust test |
|---|---|---|
| one real trade | `input_valid.json` | `test_zk_circuit_satisfied` |
| one real trade, tampered `makerPost` | `input_tampered.json` | `test_zk_circuit_unsatisfied_tampered_post_balance` |
| 3 real trades + 5 padding | `input_multi_trade.json` | `test_multi_trade_fixture_satisfied` |
| same, tampered | `input_multi_trade_tampered.json` | `test_multi_trade_fixture_tampered_is_unsatisfied` |
| all 8 slots padding (no real trades) | `input_all_padding.json` | `test_all_padding_fixture_satisfied` |

The multi-trade fixture's numbers are cross-referenced from
`crates/prover/src/bn254.rs`'s own
`test_bn254_prove_and_verify_multi_trade_batch` (same 3 trades, same
balances, same `total_value = 44920`), not invented fresh. The
all-padding case exercises a boundary `TradeBatch::prove_batch` itself
never reaches (it refuses an empty trade list at the Rust-API level),
but the circuit's own constraint system has no such refusal built in --
worth checking directly.

Every "must be accepted" fixture produces a witness satisfying all 32
constraints (`snarkjs wchk` reports "WITNESS IS CORRECT"); every
"tampered" fixture fails witness generation at a constraint assertion.

## 2. Structural R1CS matrix diff (symbolic, covers every possible witness)

Witness testing only checks the specific numbers you happened to try.
`dump_matrices.rs` (arkworks side) and `dump_circom_matrices.js` +
`diff_matrices.js` (circom side, run as the final step of
`check_equivalence.sh`) instead extract and compare the actual R1CS
constraint *structure* -- which holds for every possible witness, not
just the ones tested above.

This turned out to be less mechanical than "diff two matrices" once
actually attempted, for two real reasons found by doing it (not
assumed going in):

- **Raw column indices aren't comparable at all.** circom allocates
  wires by signal array (all of `makerPre[]` together, then all of
  `takerPre[]`, etc.); arkworks allocates per-trade-slot (slot 0's
  `maker_pre, taker_pre, amount, ..., next_root`, then slot 1's, ...).
  Same variables, completely different raw ordering. Fixed by labeling
  every column semantically (`trade[i].maker_pre`, `pre_root`, etc.) on
  both sides before comparing anything -- `dump_matrices.rs` builds its
  labels from the exact allocation order in
  `DEXBatchCircuit::generate_constraints`'s source; `dump_circom_matrices.js`
  builds its labels from the compiled circuit's `.sym` file.

- **The same linear equation has more than one valid R1CS encoding.**
  arkworks encodes `makerPost = makerPre + val` as
  `(makerPre + val) * 1 = makerPost` (isolate one side in C, multiply
  the other by the constant 1). circom's compiler instead encodes the
  identical equation as `0 * 0 = (makerPre + val - makerPost)` (fold
  the whole thing into C, leaving A and B empty). Both are correct;
  neither a raw-row comparison nor an "allow an overall sign flip"
  heuristic (tried first, and wrong) can recognize them as the same
  constraint, because they're not related by any simple scalar
  operation applied to matching roles -- they factor the identity
  differently across A/B/C entirely.

  The only comparison that's actually correct: for each constraint,
  expand `A*B - C` into the polynomial it forces to be zero (a sum of
  monomials, degree <=2 since R1CS is bilinear), then compare the two
  circuits' expanded polynomials up to an overall nonzero scalar
  (`P(x)=0` and `k*P(x)=0` are the same constraint for any nonzero
  `k`) -- computed by picking a canonical pivot term and normalizing
  every coefficient relative to it. This is what `diff_matrices.js`
  actually does, and it's factorization-independent: it doesn't matter
  *how* either compiler chose to split the identity across A/B/C, only
  what equation the constraint actually enforces.

  (A genuine bug was caught and fixed while building this, worth
  recording: the first version of `diff_matrices.js` used
  `21888...5616` as the BN254 scalar field modulus `P` -- that's
  actually `P - 1` (the field's own representation of `-1`), off by
  one from the true prime `21888...5617`. Every modular-inverse
  computation was silently wrong as a result, and the checker reported
  0/32 matches even though the constraints were genuinely equivalent.
  Fixed by correcting the constant; worth flagging as a reminder that
  the checking tooling itself needs the same scrutiny as the thing it's
  checking.)

Result: **all 32 constraints represent the identical polynomial
identity on both sides**, with zero unmatched constraints in either
direction.

## What this does NOT prove

The matrix diff is a real, symbolic, witness-independent equivalence
check -- stronger than the witness-level testing alone -- but it's not
a *formally verified* proof (no proof assistant, no independent formal
methods tool checked this; it's arithmetic done in a hand-written,
also-fallible JS script, as the bug above demonstrates). Before a real
ceremony runs, an independent second implementation of this same check
(ideally in a different language/toolchain, to reduce the chance of a
shared blind spot) would meaningfully raise confidence further.

## Reproducing

```sh
cd crates/prover/circom
./check_equivalence.sh
```

Compiled artifacts (`dex_batch.r1cs`, `dex_batch.sym`, `dex_batch_js/`,
`*.wtns`) and intermediate diff JSON are build outputs, regenerated by
the script -- not committed (see `.gitignore` in this directory). Only
the circom source, this document, the JS tooling, and the input
fixtures are checked in.
