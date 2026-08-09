#!/usr/bin/env bash
# Stage P6-1b: reproduces the circom<->arkworks equivalence check for
# dex_batch.circom against crates/prover/src/lib.rs's DEXBatchCircuit.
# See EQUIVALENCE.md for the full reasoning -- this script is just the
# witness-level half (structural counts are checked by a plain `cargo
# test -p prover test_constraint_counts_match_the_circom_port`, no
# external tooling needed for that half).
#
# Requires: circom (https://github.com/iden3/circom, v2.1.0+) and
# snarkjs (`npm install -g snarkjs`) on PATH. Neither is part of the
# normal `cargo test` toolchain -- this is deliberately a separate,
# manually-run (or dedicated-CI-job) script, not wired into the default
# build, so the rest of this repo never needs circom/node installed.
set -euo pipefail
cd "$(dirname "$0")"

echo "== compiling dex_batch.circom =="
circom dex_batch.circom --r1cs --sym --wasm -o .

echo
echo "== valid fixture (must be accepted) =="
echo "   matches crates/prover/src/lib.rs's batch_circuit_one_real_trade(false)"
node dex_batch_js/generate_witness.js dex_batch_js/dex_batch.wasm input_valid.json witness_valid.wtns
snarkjs wchk dex_batch.r1cs witness_valid.wtns

echo
echo "== tampered fixture (must be REJECTED) =="
echo "   matches crates/prover/src/lib.rs's batch_circuit_one_real_trade(true)"
if node dex_batch_js/generate_witness.js dex_batch_js/dex_batch.wasm input_tampered.json witness_tampered.wtns 2>/tmp/tampered_stderr.txt; then
    echo "FAIL: the tampered fixture's witness generation succeeded -- it must fail (constraint violation), matching test_zk_circuit_unsatisfied_tampered_post_balance's expectation that this is UNSATISFIABLE"
    exit 1
else
    if grep -q "Assert Failed" /tmp/tampered_stderr.txt; then
        echo "OK: tampered fixture correctly rejected at constraint enforcement (same outcome as the Rust circuit's own tamper test)"
    else
        echo "FAIL: witness generation failed, but not from a constraint assertion -- something else is wrong:"
        cat /tmp/tampered_stderr.txt
        exit 1
    fi
fi

echo
echo "== all checks passed =="
