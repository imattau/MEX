// Live, end-to-end validation of Stage 4c: a REAL EthereumAdapter querying
// a REAL deployed NodeRegistry (not injected fake data, unlike
// crates/protocol/tests/chain_gated_quorum_test.rs, which validates the
// gating LOGIC in isolation) -- confirms
// api::mesh_chain_status::run_mesh_chain_status_loop actually resolves two
// mesh peers' pubkeys against on-chain state and pushes a snapshot that
// MisconductQuorum gating (require_staked_reporters) correctly acts on.
//
// Requires two mesh peer pubkeys already known to the caller: one that
// SHOULD resolve active on this NodeRegistry, one that should NOT (either
// never registered, or registered then deactivated) -- this script doesn't
// register anything itself, so run scripts/register_node.js first for
// whichever pubkeys you want active. See scripts/register_node.js's docs.
//
// Usage:
//   cargo run -p trader-client --bin verify_mesh_chain_status -- \
//     <rpc_url> <query_private_key> <factory_address> <registry_address> \
//     <active_pubkey_hex> <inactive_pubkey_hex> <expect_quorum: yes|no>
//
// query_private_key just needs to be ANY funded account -- is_node_active/
// get_node_stake are view calls, this key never sends a transaction here.

use api::{run_mesh_chain_status_loop, MeshChainStatusConfig};
use common::{NodeId, Region};
use protocol::{MeshConfig, MeshNode, UdpTransport, WireMessage};
use std::time::Duration;

fn parse_pubkey(hex_str: &str, label: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str.trim_start_matches("0x"))
        .unwrap_or_else(|e| panic!("{label} is not valid hex: {e}"));
    bytes.try_into().unwrap_or_else(|v: Vec<u8>| panic!("{label} must be exactly 32 bytes, got {}", v.len()))
}

fn now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).init();
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 8 {
        eprintln!("usage: verify_mesh_chain_status <rpc_url> <query_private_key> <factory_address> <registry_address> <active_pubkey_hex> <inactive_pubkey_hex> <expect_quorum: yes|no>");
        std::process::exit(1);
    }
    let rpc_url = args[1].clone();
    let query_private_key = args[2].clone();
    let factory_address = args[3].clone();
    let registry_address = args[4].clone();
    let active_pubkey = parse_pubkey(&args[5], "active_pubkey_hex");
    let inactive_pubkey = parse_pubkey(&args[6], "inactive_pubkey_hex");
    let expect_quorum = match args[7].as_str() {
        "yes" => true,
        "no" => false,
        other => {
            eprintln!("expect_quorum must be 'yes' or 'no', got '{other}'");
            std::process::exit(1);
        }
    };

    let detector_addr: std::net::SocketAddr = "127.0.0.1:19500".parse().unwrap();
    let mut detector = MeshNode::new(MeshConfig {
        node_id: NodeId(1),
        region: Region::UsEast1,
        listen_addr: detector_addr,
        peers: vec![
            (NodeId(20), "127.0.0.1:19998".parse().unwrap(), active_pubkey),
            (NodeId(21), "127.0.0.1:19999".parse().unwrap(), inactive_pubkey),
        ],
        node_key: None,
        mesh_encryption_key: None,
        heartbeat_interval_ms: 5000.0,
        max_missed_heartbeats: 100,
        schedule: None,
        artificial_forward_delay_ms: None,
        require_staked_reporters: true,
    })
    .await
    .expect("failed to bind detector mesh node");

    let mut confirmed = detector.confirmed_misconduct_receiver();
    let chain_status_tx = detector.chain_status_sender();

    tokio::spawn(run_mesh_chain_status_loop(MeshChainStatusConfig {
        rpc_url,
        node_private_key: query_private_key,
        factory_address,
        registry_address,
        peer_pubkeys: vec![active_pubkey, inactive_pubkey],
        poll_interval: Duration::from_secs(2),
        chain_status_tx,
    }));

    tokio::spawn(detector.run());

    println!("waiting for at least one real NodeRegistry poll to land...");
    tokio::time::sleep(Duration::from_secs(4)).await;

    let mut injector = UdpTransport::bind("127.0.0.1:19501".parse().unwrap(), None).await.unwrap();
    injector.register_peer(NodeId(1), detector_addr, [0u8; 32]);
    let subject = NodeId(99);
    for reporter in [NodeId(20), NodeId(21)] {
        injector.send(NodeId(1), WireMessage::MisconductReport {
            reporter,
            subject,
            reason: format!("{reporter:?}'s live-chain-gated claim"),
            timestamp: now_secs(),
        }).await.unwrap();
    }

    let result = tokio::time::timeout(Duration::from_secs(3), confirmed.recv()).await;
    let quorum_reached = matches!(result, Ok(Some(s)) if s == subject);

    println!("quorum_reached = {quorum_reached} (expected {expect_quorum})");
    if quorum_reached == expect_quorum {
        println!("PASS: live NodeRegistry-gated quorum behaved as expected.");
    } else {
        eprintln!("FAIL: expected quorum_reached={expect_quorum}, got {quorum_reached}");
        std::process::exit(1);
    }
}
