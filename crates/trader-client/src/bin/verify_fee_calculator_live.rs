// Confirms the live `api` server (crates/api/src/main.rs) actually reads
// MEX_FEE_BASE_GAS_PRICE/MEX_FEE_BATCH_UTILIZATION/MEX_FEE_VOLATILITY_INDEX
// and applies them to real matches, instead of the fixed 5/15/50 bps
// schedule that used to be the ONLY thing this server could ever charge
// (FeeCalculator existed and was tested in isolation, but nothing in
// main.rs ever called set_fee_calculator before this).
//
// Places one Standard-tier order pair against a live server and checks the
// returned match's fee_basis_points. Run it twice against two separately
// started server processes to see the full effect:
//   - server started with no MEX_FEE_* env vars set -> expect exactly 5
//   - server started with MEX_FEE_BASE_GAS_PRICE=200 (4x baseline) ->
//     expect > 5 (calculate_fee_basis_points scales linearly with gas price)
//
// Usage:
//   cargo run -p trader-client --bin verify_fee_calculator_live -- <api_base_url> <expected_fee_bps>

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;

fn serialize_order_message(order: &serde_json::Value) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(order["id"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap() as u8).collect::<Vec<u8>>().as_slice());
    msg.extend_from_slice(order["trader"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap() as u8).collect::<Vec<u8>>().as_slice());
    msg.extend_from_slice(order["symbol"].as_str().unwrap().as_bytes());
    msg.extend_from_slice(&order["price"].as_u64().unwrap().to_be_bytes());
    msg.extend_from_slice(&order["amount"].as_u64().unwrap().to_be_bytes());
    msg.extend_from_slice(&order["nonce"].as_u64().unwrap().to_be_bytes());
    msg.extend_from_slice(&order["expiry"].as_u64().unwrap().to_be_bytes());
    msg
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let api_base = args.get(1).expect("usage: verify_fee_calculator_live <api_base_url> <expected_fee_bps>").trim_end_matches('/').to_string();
    let expected_fee_bps: u32 = args.get(2).expect("missing expected_fee_bps").parse().unwrap();

    let mut csprng = OsRng;
    let seller_offchain = SigningKey::generate(&mut csprng);
    let seller_pubkey = seller_offchain.verifying_key().to_bytes();
    let buyer_offchain = SigningKey::generate(&mut csprng);
    let buyer_pubkey = buyer_offchain.verifying_key().to_bytes();

    let http = reqwest::Client::new();
    let api_key = std::env::var("MEX_API_KEY").unwrap_or_else(|_| "dev-default-key".to_string());

    let build_and_sign = |sk: &SigningKey, trader: [u8; 32], side: &str, price: u64, amount: u64, nonce: u64| -> serde_json::Value {
        let mut order_id = [0u8; 32];
        order_id[0..16].copy_from_slice(&trader[0..16]);
        order_id[16..24].copy_from_slice(&nonce.to_be_bytes());
        let unsigned = serde_json::json!({
            "id": order_id, "trader": trader, "symbol": "ETH-USD", "side": side,
            "price": price, "amount": amount, "nonce": nonce, "expiry": 0,
        });
        let msg = serialize_order_message(&unsigned);
        let signature = sk.sign(&msg).to_vec();
        serde_json::json!({
            "trader": trader, "symbol": "ETH-USD", "side": side,
            "price": price, "amount": amount, "signature": signature,
            "nonce": nonce, "expiry": 0,
        })
    };

    let sell_req = build_and_sign(&seller_offchain, seller_pubkey, "Sell", 3000, 1, 1);
    let sell_resp: serde_json::Value = http.post(format!("{api_base}/api/v1/order"))
        .header("X-API-Key", &api_key).json(&sell_req).send().await.unwrap().json().await.unwrap();
    assert_eq!(sell_resp["success"], true, "sell order rejected: {sell_resp:?}");

    let buy_req = build_and_sign(&buyer_offchain, buyer_pubkey, "Buy", 3000, 1, 1);
    let buy_resp: serde_json::Value = http.post(format!("{api_base}/api/v1/order"))
        .header("X-API-Key", &api_key).json(&buy_req).send().await.unwrap().json().await.unwrap();
    assert_eq!(buy_resp["success"], true, "buy order rejected: {buy_resp:?}");
    let matches = buy_resp["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 1, "expected exactly one real match from the live matching engine");
    let fee_basis_points: u32 = serde_json::from_value(matches[0]["fee_basis_points"].clone()).unwrap();

    println!("live match fee_basis_points = {fee_basis_points} (expected {expected_fee_bps})");
    assert_eq!(fee_basis_points, expected_fee_bps, "server's live FeeCalculator configuration did not produce the expected fee");
    println!("\nFEE CALCULATOR LIVE WIRING TEST PASSED");
}
