#!/usr/bin/env bash
# Stage P6-1b: reproduces the circom<->arkworks equivalence check for
# dex_batch.circom against crates/prover/src/lib.rs's DEXBatchCircuit.
# See EQUIVALENCE.md for the full reasoning. Two independent checks:
#
#   1. Witness-level cross-testing (this script's main body): several
#      concrete fixtures, each also asserted against the SAME numbers
#      in a Rust test, run through circom's witness generator and
#      checked accept/reject as expected.
#   2. Structural R1CS matrix diff (this script's final step): every
#      constraint's actual polynomial identity, not just its raw (A,B,C)
#      row shape -- see diff_matrices.js's own docs for why a naive row
#      comparison isn't sufficient (the two compilers factor linear
#      constraints across A/B/C differently, despite being equally
#      valid encodings of the same equation).
#
# Requires: circom (https://github.com/iden3/circom, v2.1.0+), snarkjs
# (`npm install -g snarkjs`), node, and cargo -- all on PATH. Circom/
# snarkjs/node are deliberately NOT part of the normal `cargo test`
# toolchain -- this is a separate, manually-run (or dedicated-CI-job)
# script, not wired into the default build.
set -euo pipefail
cd "$(dirname "$0")"

echo "== compiling dex_batch.circom =="
circom dex_batch.circom --r1cs --sym --wasm -o .

check_fixture() {
    local name="$1" input="$2" must_be_valid="$3"
    echo
    echo "== $name (must be $([ "$must_be_valid" = "1" ] && echo ACCEPTED || echo REJECTED)) =="
    if node dex_batch_js/generate_witness.js dex_batch_js/dex_batch.wasm "$input" "witness_${name}.wtns" 2>/tmp/circom_check_stderr.txt; then
        if [ "$must_be_valid" = "1" ]; then
            snarkjs wchk dex_batch.r1cs "witness_${name}.wtns"
        else
            echo "FAIL: $name was expected to be REJECTED but witness generation succeeded"
            exit 1
        fi
    else
        if [ "$must_be_valid" = "1" ]; then
            echo "FAIL: $name was expected to be ACCEPTED but witness generation failed:"
            cat /tmp/circom_check_stderr.txt
            exit 1
        elif grep -q "Assert Failed" /tmp/circom_check_stderr.txt; then
            echo "OK: correctly rejected at constraint enforcement"
        else
            echo "FAIL: witness generation failed, but not from a constraint assertion:"
            cat /tmp/circom_check_stderr.txt
            exit 1
        fi
    fi
}

# Each fixture here has an identical numeric counterpart asserted in
# crates/prover/src/lib.rs's test module -- see each input file's
# matching Rust test for the cross-reference.
check_fixture "valid" input_valid.json 1                       # test_zk_circuit_satisfied
check_fixture "tampered" input_tampered.json 0                 # test_zk_circuit_unsatisfied_tampered_post_balance
check_fixture "multi_trade" input_multi_trade.json 1           # test_multi_trade_fixture_satisfied
check_fixture "multi_trade_tampered" input_multi_trade_tampered.json 0  # test_multi_trade_fixture_tampered_is_unsatisfied
check_fixture "all_padding" input_all_padding.json 1            # test_all_padding_fixture_satisfied
rm -f /tmp/circom_check_stderr.txt

echo
echo "== structural R1CS matrix diff =="
( cd ../../.. && cargo run -p prover --bin dump_matrices -- /tmp/mex_arkworks_matrices.json )
snarkjs r1cs export json dex_batch.r1cs /tmp/mex_circom_r1cs.json
node dump_circom_matrices.js /tmp/mex_circom_r1cs.json dex_batch.sym /tmp/mex_circom_matrices.json
node diff_matrices.js /tmp/mex_arkworks_matrices.json /tmp/mex_circom_matrices.json

echo
echo "== all checks passed =="
