// One-shot test tool for Stage D: sends a deliberately invalid
// SettlementProof directly to a running watchtower_node, to trigger its
// misconduct-detection-and-broadcast path without needing a real trade
// lifecycle. Not part of the mesh itself -- a bare injector, same
// technique used throughout protocol's own tests.
//
// Usage:
//   cargo run -p trader-client --bin inject_bad_proof -- <target_addr> <target_node_id>

use common::{NodeId, SettlementPreference};
use engine::Match;
use prover::{ProverBackend, TradeBatch, BACKEND};
use protocol::{UdpTransport, WireMessage};

fn u64_to_bytes32(val: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&val.to_be_bytes());
    out
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let target_addr: std::net::SocketAddr = args.get(1).expect("usage: inject_bad_proof <target_addr> <target_node_id>").parse().unwrap();
    let target_id: u32 = args.get(2).expect("missing target_node_id").parse().unwrap();

    let batch = TradeBatch {
        trades: vec![Match {
            maker_order_id: [1u8; 32],
            taker_order_id: [2u8; 32],
            maker_trader: [3u8; 32],
            taker_trader: [4u8; 32],
            price: 3000,
            amount: 5,
            timestamp_us: 0,
            settlement_tier: SettlementPreference::Standard,
            fee_basis_points: 5,
            seller: [4u8; 32],
            fee_payer: [4u8; 32],
            symbol: "BTC-USD".to_string(),
            assigned_node: [0u8; 32],
            settlement_deadline: 0,
        }],
        pre_state_root: [0u8; 32],
        post_state_root: u64_to_bytes32(3000 * 5),
        maker_balances: vec![1_000_000],
        taker_balances: vec![1_000_000],
    };
    let proof = BACKEND.prove_batch(&batch).expect("proving a valid batch must succeed");

    // Tamper AFTER proving -- the proof stays valid for the original
    // batch, but no longer matches this one, exactly the "submitter lied
    // about what it settled" scenario watchtower_node exists to catch.
    let mut tampered = batch.clone();
    tampered.post_state_root[0] ^= 0xFF;
    assert!(!BACKEND.verify_proof(&proof, &tampered), "sanity check: tampering must actually break verification");

    let injector = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), None).await.unwrap();
    let mut injector = injector;
    injector.register_peer(NodeId(target_id), target_addr, [0u8; 32]);

    injector
        .send(NodeId(target_id), WireMessage::SettlementProof { batch: tampered, proof })
        .await
        .unwrap();

    println!("sent a deliberately tampered SettlementProof to node {target_id} at {target_addr}");
}
