// Live, one-shot proof of the full ZK pipeline against a real chain: builds
// a multi-trade TradeBatch, generates a real Groth16 proof covering all of
// it via the same Bn254Groth16Backend used in production, and submits it
// directly to a deployed BatchVerifier's verifyProof -- bypassing
// SettlementFactory's escrow/trade bookkeeping entirely, since the only
// thing being tested here is whether a real batch proof against a real
// deployed verifying key actually passes the on-chain pairing check (or
// correctly fails a tampered one).
//
// Usage: cargo run -p prover --bin verify_onchain_smoke -- <rpc_url> <private_key> <batch_verifier_address>

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use common::SettlementPreference;
use engine::Match;
use prover::{decode_proof_calldata, Bn254Groth16Backend, ProverBackend, TradeBatch};

sol! {
    #[sol(rpc)]
    interface IBatchVerifier {
        function verifyProof(
            uint256[2] calldata a,
            uint256[2][2] calldata b,
            uint256[2] calldata c,
            uint256[] calldata input
        ) external returns (bool);
    }
}

fn u64_to_bytes32(val: u64) -> [u8; 32] {
    let mut result = [0u8; 32];
    result[24..32].copy_from_slice(&val.to_be_bytes());
    result
}

// A real MULTI-trade batch (not just one) -- this is the actual thing
// being validated here: one proof, covering several distinct trades
// between the same maker/taker pair, verified in a single on-chain call.
fn build_batch() -> TradeBatch {
    let maker_balance = 1_000_000u64;
    let taker_balance = 1_000_000u64;

    let trade_terms = [(3000u64, 5u64), (2950u64, 3u64), (3010u64, 7u64)];
    let make_match = |price: u64, amount: u64, i: usize| Match {
        maker_order_id: [i as u8 + 1; 32],
        taker_order_id: [i as u8 + 100; 32],
        maker_trader: [0u8; 32],
        taker_trader: [0u8; 32],
        price,
        amount,
        timestamp_us: 1_700_000_000,
        settlement_tier: SettlementPreference::Standard,
        fee_basis_points: 5,
        seller: [0u8; 32],
        fee_payer: [0u8; 32],
        symbol: "ETH-USD".to_string(),
        assigned_node: [0u8; 32],
        settlement_deadline: 0,
    };
    let trades: Vec<Match> = trade_terms.iter().enumerate().map(|(i, &(p, a))| make_match(p, a, i)).collect();
    let total_value: u64 = trades.iter().map(|t| t.price * t.amount).sum();

    TradeBatch {
        trades,
        maker_balance,
        taker_balance,
        pre_state_root: [0u8; 32],
        post_state_root: u64_to_bytes32(total_value),
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rpc_url = args.get(1).expect("usage: verify_onchain_smoke <rpc_url> <private_key> <batch_verifier_address>");
    let private_key = args.get(2).expect("missing private_key");
    let verifier_address: Address = args.get(3).expect("missing batch_verifier_address").parse().expect("invalid address");

    let signer: PrivateKeySigner = private_key
        .trim_start_matches("0x")
        .parse()
        .expect("invalid private key");
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url.parse().expect("invalid RPC URL"))
        .erased();

    let verifier = IBatchVerifier::new(verifier_address, &provider);

    let batch = build_batch();
    let backend = Bn254Groth16Backend;
    let proof_bytes = backend.prove_batch(&batch).expect("prove_batch failed");
    assert!(backend.verify_proof(&proof_bytes, &batch), "off-chain verification of our own proof failed -- something is wrong before we even touch the chain");
    println!("generated a real Groth16 proof and verified it off-chain: OK");

    let calldata = decode_proof_calldata(&proof_bytes).expect("decode_proof_calldata failed");
    let a = [U256::from_be_bytes(calldata.a[0]), U256::from_be_bytes(calldata.a[1])];
    let b = [
        [U256::from_be_bytes(calldata.b[0][0]), U256::from_be_bytes(calldata.b[0][1])],
        [U256::from_be_bytes(calldata.b[1][0]), U256::from_be_bytes(calldata.b[1][1])],
    ];
    let c = [U256::from_be_bytes(calldata.c[0]), U256::from_be_bytes(calldata.c[1])];
    let input: Vec<U256> = calldata.public_inputs.iter().map(|bytes| U256::from_be_bytes(*bytes)).collect();

    // 1. The real proof against the real deployed verifying key -- must succeed.
    let receipt = verifier
        .verifyProof(a, b, c, input.clone())
        .send()
        .await
        .expect("verifyProof send failed")
        .get_receipt()
        .await
        .expect("verifyProof receipt failed");
    println!("REAL PROOF submitted on-chain, tx {:#x}, status: {:?}", receipt.transaction_hash, receipt.status());
    assert!(receipt.status(), "real proof's on-chain transaction should have succeeded");

    // Read back the ProofVerified event to confirm the pairing check itself
    // returned true, not just that the call didn't revert.
    let call_result = verifier.verifyProof(a, b, c, input.clone()).call().await.expect("verifyProof call (real proof) failed");
    println!("real proof pairing check result (should be true): {call_result}");
    assert!(call_result, "real proof must verify as true");

    // 2. The same (valid, on-curve) proof but against a tampered public
    // input -- must fail, proving the verifier is doing real cryptographic
    // work rather than rubber-stamping every call. (Corrupting a raw curve
    // point coordinate instead, as an earlier version of this test did,
    // isn't a meaningful negative case: an arbitrary byte flip usually
    // isn't a valid point on the curve at all, so the pairing precompile
    // itself reverts rather than the verification math evaluating to
    // false. A public input is just a scalar, so incrementing it stays
    // well-formed and genuinely exercises the "wrong but valid" case.)
    let mut tampered_input = input.clone();
    tampered_input[0] += U256::from(1);
    let tampered_result = verifier
        .verifyProof(a, b, c, tampered_input)
        .call()
        .await
        .expect("verifyProof call (tampered public input) failed");
    println!("tampered public input pairing check result (should be false): {tampered_result}");
    assert!(!tampered_result, "a proof checked against the wrong public input must NOT verify as true");

    println!("\nZK PIPELINE SMOKE TEST PASSED: real trusted setup -> real proof -> real on-chain BatchVerifier -> correct accept/reject");
}
