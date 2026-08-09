// Stage 2 live validation: genuine topological redundancy (a diamond,
// not the linear chains used everywhere else in this test suite) lets a
// node cross-check one relay's anomalous timing against what an
// INDEPENDENT path for the SAME order looked like.
//
// Topology:
//        origin (0)
//       /          \
//   node1 (1)      node4 (4)     <- both real MeshNodes, both upstream of node2
//   (delayed)       (honest)
//       \          /
//        node2 (5)                <- sees both paths, does the cross-check
//              \
//               node6 (6)          <- pure observer, receives node2's broadcast
//
// node1 delays its forward by 300ms (same technique as
// latency_anomaly_test); node4 forwards honestly. node2 receives the
// SAME order via both, and should flag node1's hop as anomalous AND
// corroborated (node4's independent path for the identical order looked
// normal) -- not just anomalous in isolation, which is all
// latency_anomaly_test (linear chain, single path, no possible
// corroboration) could ever show.
//
// node6 exists for the same reason Stage D's original test needed a
// third node: report_misconduct broadcasts to peers, it doesn't loop
// back to the reporting node's own receiver -- node2 can't observe its
// own report.

use common::{FloodMessage, NodeId, Region};
use ed25519_dalek::Signer;
use protocol::{MeshConfig, MeshNode, UdpTransport, WireMessage};
use std::time::Duration;

fn addr(port: u16) -> std::net::SocketAddr {
    format!("127.0.0.1:{}", port).parse().unwrap()
}

fn signed_order(seed: u8, nonce: u64) -> common::Order {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let trader = signing_key.verifying_key().to_bytes();
    let mut order = common::Order {
        id: [seed; 32],
        trader,
        symbol: "ETH-USD".to_string(),
        side: common::OrderSide::Buy,
        price: 3000,
        amount: 1,
        signature: vec![],
        nonce,
        expiry: 0,
        settlement_preference: common::SettlementPreference::Standard,
        settlement_requester: common::SettlementRequester::Seller,
    };
    let msg_bytes = validation::OrderValidator::serialize_order_message(&order);
    order.signature = signing_key.sign(&msg_bytes).to_vec();
    order
}

fn now_ms() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
        * 1000.0
}

async fn spawn_node(
    id: u32,
    listen_addr: std::net::SocketAddr,
    peers: Vec<(NodeId, std::net::SocketAddr)>,
    artificial_forward_delay_ms: Option<u64>,
) -> MeshNode {
    MeshNode::new(MeshConfig {
        node_id: NodeId(id),
        region: Region::UsEast1,
        listen_addr,
        peers: peers.into_iter().map(|(id, addr)| (id, addr, [0u8; 32])).collect(),
        node_key: None,
        mesh_encryption_key: None,
        heartbeat_interval_ms: 5000.0,
        max_missed_heartbeats: 100,
        schedule: None,
        artificial_forward_delay_ms,
        require_staked_reporters: false,
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn test_cross_witness_corroboration_on_a_diamond_topology() {
    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::TRACE).try_init();
    let a0 = addr(11000); // origin (bare injector)
    let a1 = addr(11001); // node1 -- delayed
    let a4 = addr(11004); // node4 -- honest
    let a5 = addr(11005); // node2 -- detector
    let a6 = addr(11006); // node6 -- pure observer

    let node1 = spawn_node(1, a1, vec![(NodeId(0), a0), (NodeId(5), a5)], Some(300)).await;
    let node4 = spawn_node(4, a4, vec![(NodeId(0), a0), (NodeId(5), a5)], None).await;
    let node2 = spawn_node(5, a5, vec![(NodeId(1), a1), (NodeId(4), a4), (NodeId(6), a6)], None).await;
    let mut node6 = spawn_node(6, a6, vec![(NodeId(5), a5)], None).await;
    let mut misconduct = node6.misconduct_receiver();

    tokio::spawn(node1.run());
    tokio::spawn(node4.run());
    tokio::spawn(node2.run());
    tokio::spawn(node6.run());

    // Let real Ping/Pong establish RTT baselines on both node2<->node1
    // and node2<->node4 before sending anything to judge against them.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let mut injector = UdpTransport::bind(a0, None).await.unwrap();
    injector.register_peer(NodeId(1), a1, [0u8; 32]);
    injector.register_peer(NodeId(4), a4, [0u8; 32]);

    let order = signed_order(41, 1);
    // Sent to BOTH node1 and node4 -- this is the redundant, multi-path
    // propagation the whole cross-witness mechanism depends on. A real
    // deployment would get this from genuine mesh topology (both being
    // downstream of a common upstream, or the origin itself dual-homed);
    // this test injects it directly for a controlled, deterministic path.
    let msg1 = FloodMessage { order: order.clone(), hop_count: 0, path: vec![NodeId(0)], timestamp: now_ms(), source_region: Region::UsEast1 };
    let msg4 = FloodMessage { order: order.clone(), hop_count: 0, path: vec![NodeId(0)], timestamp: now_ms(), source_region: Region::UsEast1 };
    injector.send(NodeId(1), WireMessage::Flood(msg1)).await.unwrap();
    injector.send(NodeId(4), WireMessage::Flood(msg4)).await.unwrap();

    let event = tokio::time::timeout(Duration::from_secs(2), misconduct.recv())
        .await
        .expect("timed out waiting for node2 to report node1's anomalous hop")
        .expect("misconduct channel closed unexpectedly");

    assert_eq!(event.subject, NodeId(1), "node1 -- the relay on the delayed path -- should be the reported subject");
    assert_eq!(event.reporter, NodeId(5), "node2 -- the node that saw both paths -- should be the reporter");
    println!("reason: {}", event.reason);
    assert!(
        event.reason.contains("corroborated:"),
        "with a genuine independent second path (via node4) that looked normal, the report should say so, not \"uncorroborated\" -- got: {}",
        event.reason
    );
}
