// Confirms Stage A of connecting the gossip mesh to the live api server:
// submits a real order over HTTP to a running `api` process started with
// MEX_MESH_* configured, and checks a real UDP Flood message carrying
// that same order actually arrives at a peer address -- not just that
// the HTTP call succeeded.
//
// Usage:
//   cargo run -p trader-client --bin verify_mesh_flood_live -- <api_base_url> <observer_bind_addr> <mesh_node_addr> <mesh_node_id>
//   e.g. ... -- http://127.0.0.1:8085 127.0.0.1:19002 127.0.0.1:19001 1

use ed25519_dalek::{Signer, SigningKey};
use protocol::{UdpTransport, WireMessage};
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
    let api_base = args.get(1).expect("usage: verify_mesh_flood_live <api_base_url> <observer_bind_addr> <mesh_node_addr> <mesh_node_id>").trim_end_matches('/').to_string();
    let observer_addr: std::net::SocketAddr = args.get(2).expect("missing observer_bind_addr").parse().unwrap();
    let mesh_node_addr: std::net::SocketAddr = args.get(3).expect("missing mesh_node_addr").parse().unwrap();
    let mesh_node_id: u32 = args.get(4).expect("missing mesh_node_id").parse().unwrap();

    let mut observer = UdpTransport::bind(observer_addr, None).await.unwrap();
    observer.register_peer(common::NodeId(mesh_node_id), mesh_node_addr, [0u8; 32]);

    let mut csprng = OsRng;
    let seller_offchain = SigningKey::generate(&mut csprng);
    let seller_pubkey = seller_offchain.verifying_key().to_bytes();

    let http = reqwest::Client::new();
    let api_key = std::env::var("MEX_API_KEY").unwrap_or_else(|_| "dev-default-key".to_string());

    let order_id_seed = 55u64;
    let mut order_id = [0u8; 32];
    order_id[0..16].copy_from_slice(&seller_pubkey[0..16]);
    order_id[16..24].copy_from_slice(&order_id_seed.to_be_bytes());
    let unsigned = serde_json::json!({
        "id": order_id, "trader": seller_pubkey, "symbol": "ETH-USD", "side": "Sell",
        "price": 3000, "amount": 1, "nonce": order_id_seed, "expiry": 0,
    });
    let msg = serialize_order_message(&unsigned);
    let signature = seller_offchain.sign(&msg).to_vec();
    let req = serde_json::json!({
        "trader": seller_pubkey, "symbol": "ETH-USD", "side": "Sell",
        "price": 3000, "amount": 1, "signature": signature,
        "nonce": order_id_seed, "expiry": 0,
    });

    println!("submitting real order via HTTP to {api_base}...");
    let resp: serde_json::Value = http.post(format!("{api_base}/api/v1/order"))
        .header("X-API-Key", &api_key).json(&req).send().await.unwrap().json().await.unwrap();
    assert_eq!(resp["success"], true, "order rejected: {resp:?}");
    println!("order accepted by the live server: OK\n");

    println!("waiting for the server's mesh node ({mesh_node_addr}, id={mesh_node_id}) to flood this order to {observer_addr}...");
    let flood = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            match observer.recv().await {
                Ok((from, WireMessage::Flood(fm))) => return (from, fm),
                _ => continue,
            }
        }
    })
    .await
    .expect("timed out waiting for the server's mesh node to flood the order");

    let (from, fm) = flood;
    assert_eq!(from.0, mesh_node_id, "flood should arrive from the server's own configured mesh node id");
    assert_eq!(fm.order.id, order_id, "flooded order id should match the order actually submitted over HTTP");
    assert_eq!(fm.order.trader, seller_pubkey);
    assert_eq!(fm.order.price, 3000);

    println!("received a real Flood over UDP carrying the exact order submitted over HTTP: OK");
    println!("\nMESH STAGE A LIVE TEST PASSED: an order submitted through the live api server was actually gossiped over the real mesh network, not just matched locally.");
}
