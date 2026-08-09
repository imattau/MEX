pragma circom 2.1.0;

// Stage P6-1b: a faithful circom port of crates/prover/src/lib.rs's
// DEXBatchCircuit<F> -- see that Rust struct's own docs for the full
// semantics (why the "root" is a running SUM of traded value, not a
// hash; why there are deliberately no range/overflow checks here; why
// only preRoot/postRoot are public). This file, once verified
// constraint-equivalent to the Rust circuit (see this crate's
// circom_equivalence tests), is the artifact any trusted-setup
// ceremony actually runs against -- NOT the Rust struct directly.
//
// Per-trade constraints (must stay EXACTLY these four, matching
// DEXBatchCircuit::generate_constraints one-for-one, in the same
// order):
//   1. val       = amount * price
//   2. makerPost = makerPre + val
//   3. takerPost = takerPre - val
//   4. nextRoot  = runningRoot + val   (nextRoot is postRoot on the
//                                       last slot, an intermediateRoots
//                                       entry otherwise)
//
// Deliberately absent, matching the Rust circuit exactly -- do NOT add
// any of these without also re-deriving DEXBatchCircuit in lockstep
// and re-running the whole ceremony:
//   - no range checks on amount/price/balances (off-circuit code
//     trusts the u64 -> field embedding; BN254's ~254-bit scalar field
//     never wraps a real u64)
//   - no underflow guard on takerPost = takerPre - val (a malformed
//     witness with val > takerPre wraps the field silently instead of
//     failing; the real solvency check lives off-circuit, see
//     bn254.rs's prove_batch/verify_proof)
template DEXBatch(N) {
    signal input makerPre[N];
    signal input takerPre[N];
    signal input amount[N];
    signal input price[N];
    signal input makerPost[N];
    signal input takerPost[N];
    // Root after each trade except the last (whose resulting root IS
    // postRoot) -- length N - 1, matching
    // DEXBatchCircuit::intermediate_roots exactly.
    signal input intermediateRoots[N - 1];
    signal input preRoot;
    signal input postRoot;

    // Internal signals only -- not circuit inputs, matching arkworks'
    // `cs.new_witness_variable` calls for `val`/`next_root` (the
    // non-last-slot case): their values are DERIVED inside the
    // circuit via <==, not supplied externally the way makerPost/
    // takerPost/intermediateRoots/postRoot are (those use === below,
    // since they already carry an externally-supplied value that's
    // merely being checked, not assigned).
    signal val[N];
    signal runningRoot[N + 1];
    runningRoot[0] <== preRoot;

    for (var i = 0; i < N; i++) {
        // Constraint 1: val = amount * price -- the one genuine
        // multiplication; everything else here is linear.
        val[i] <== amount[i] * price[i];

        // Constraint 2: makerPost = makerPre + val
        makerPost[i] === makerPre[i] + val[i];

        // Constraint 3: takerPost = takerPre - val
        takerPost[i] === takerPre[i] - val[i];

        // Constraint 4: nextRoot = runningRoot + val. The last slot's
        // "next root" is the public postRoot input itself (matching
        // DEXBatchCircuit's `if i == MAX_BATCH_TRADES - 1 {
        // post_root_var } else { ... }` branch exactly); every earlier
        // slot's is the corresponding intermediateRoots entry.
        if (i == N - 1) {
            postRoot === runningRoot[i] + val[i];
            runningRoot[i + 1] <== postRoot;
        } else {
            intermediateRoots[i] === runningRoot[i] + val[i];
            runningRoot[i + 1] <== intermediateRoots[i];
        }
    }
}

// N = 8, matching crates/prover/src/lib.rs's MAX_BATCH_TRADES exactly.
// Changing this changes the circuit's shape and invalidates any
// ceremony run against it -- same rule MAX_BATCH_TRADES's own docs
// state for the Rust side. {public [...]} marks ONLY preRoot/postRoot
// as public circuit inputs -- every other signal above is private by
// default, matching DEXBatchCircuit's new_input_variable (2 of them)
// vs new_witness_variable (everything else) split exactly.
component main {public [preRoot, postRoot]} = DEXBatch(8);
