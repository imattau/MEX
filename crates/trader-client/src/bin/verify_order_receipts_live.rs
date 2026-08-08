// Confirms a live `api` server actually returns a signed OrderReceipt on
// every successful order submission, and that the receipt verifies
// independently (no further trust in the server needed) via
// api::receipts::verify_receipt.
//
// Usage:
//   cargo run -p trader-client --bin verify_order_receipts_live -- <api_base_url>

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
    let api_base = args.get(1).expect("usage: verify_order_receipts_live <api_base_url>").trim_end_matches('/').to_string();

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

    // Resting order (no match yet) -- still must get a receipt.
    let sell_req = build_and_sign(&seller_offchain, seller_pubkey, "Sell", 3000, 1, 1);
    let sell_resp: serde_json::Value = http.post(format!("{api_base}/api/v1/order"))
        .header("X-API-Key", &api_key).json(&sell_req).send().await.unwrap().json().await.unwrap();
    assert_eq!(sell_resp["success"], true, "sell order rejected: {sell_resp:?}");
    let sell_receipt = sell_resp["receipt"].clone();
    assert!(!sell_receipt.is_null(), "resting order must still get a receipt");
    println!("resting sell order got a receipt: OK");
    println!("  received_at_us = {}", sell_receipt["received_at_us"]);

    // Matching order -- also gets its own receipt.
    let buy_req = build_and_sign(&buyer_offchain, buyer_pubkey, "Buy", 3000, 1, 1);
    let buy_resp: serde_json::Value = http.post(format!("{api_base}/api/v1/order"))
        .header("X-API-Key", &api_key).json(&buy_req).send().await.unwrap().json().await.unwrap();
    assert_eq!(buy_resp["success"], true, "buy order rejected: {buy_resp:?}");
    let matches = buy_resp["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 1, "expected exactly one real match");
    let buy_receipt = buy_resp["receipt"].clone();
    assert!(!buy_receipt.is_null(), "matched order must also get its own receipt");
    println!("matching buy order got a receipt: OK");

    // Invalid-signature order -- must NOT get a receipt (it never entered the book).
    let mut bad_req = build_and_sign(&seller_offchain, seller_pubkey, "Sell", 2999, 1, 2);
    bad_req["signature"] = serde_json::json!(vec![0u8; 64]); // corrupt the signature
    let bad_resp: serde_json::Value = http.post(format!("{api_base}/api/v1/order"))
        .header("X-API-Key", &api_key).json(&bad_req).send().await.unwrap().json().await.unwrap();
    assert_eq!(bad_resp["success"], false, "corrupted-signature order should be rejected");
    assert!(bad_resp["receipt"].is_null(), "rejected order must not get a receipt");
    println!("rejected (bad signature) order correctly got NO receipt: OK");

    // Independent verification -- this binary has no direct dependency on
    // `api`, deliberately: parse the receipt's raw fields from JSON and
    // rebuild + check the signature exactly as api::receipts::verify_receipt
    // would, proving a trader (or any third party) could do this without
    // trusting the server again.
    for (label, receipt) in [("sell", &sell_receipt), ("buy", &buy_receipt)] {
        let order_id: [u8; 32] = serde_json::from_value(receipt["order_id"].clone()).unwrap();
        let trader: [u8; 32] = serde_json::from_value(receipt["trader"].clone()).unwrap();
        let symbol: String = serde_json::from_value(receipt["symbol"].clone()).unwrap();
        let side_byte: u8 = if receipt["side"] == "Buy" { 0 } else { 1 };
        let price: u64 = serde_json::from_value(receipt["price"].clone()).unwrap();
        let amount: u64 = serde_json::from_value(receipt["amount"].clone()).unwrap();
        let nonce: u64 = serde_json::from_value(receipt["nonce"].clone()).unwrap();
        let expiry: u64 = serde_json::from_value(receipt["expiry"].clone()).unwrap();
        let received_at_us: u64 = serde_json::from_value(receipt["received_at_us"].clone()).unwrap();
        let node_pubkey: [u8; 32] = serde_json::from_value(receipt["node_pubkey"].clone()).unwrap();
        let signature: Vec<u8> = serde_json::from_value(receipt["signature"].clone()).unwrap();

        let mut msg = Vec::new();
        msg.extend_from_slice(&order_id);
        msg.extend_from_slice(&trader);
        msg.extend_from_slice(symbol.as_bytes());
        msg.push(side_byte);
        msg.extend_from_slice(&price.to_be_bytes());
        msg.extend_from_slice(&amount.to_be_bytes());
        msg.extend_from_slice(&nonce.to_be_bytes());
        msg.extend_from_slice(&expiry.to_be_bytes());
        msg.extend_from_slice(&received_at_us.to_be_bytes());

        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&node_pubkey).unwrap();
        let sig_bytes: [u8; 64] = signature.try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        use ed25519_dalek::Verifier;
        verifying_key.verify(&msg, &sig).unwrap_or_else(|_| panic!("{label} receipt failed independent signature verification"));
        println!("{label} receipt independently verified against node_pubkey {}: OK", hex::encode(node_pubkey));
    }

    println!("\nORDER RECEIPTS LIVE TEST PASSED");
}
