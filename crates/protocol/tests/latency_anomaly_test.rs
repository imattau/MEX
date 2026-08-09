// Live validation of the minimal network-time-ordering hypothesis: can
// real, RTT-baseline-derived latency bounds distinguish a deliberately
// withholding relay from ordinary network jitter, using real MeshNode
// processes and real UDP sockets -- not a simulation?
//
// Topology for both tests: injector(0) -> node1 -> node2 -> node3
// (observer). node2 is the one that actually detects an anomaly on the
// node1->node2 hop (it establishes a real RTT baseline with node1 via
// Ping/Pong, then compares the observed transit time of a real order
// against that baseline); node3 only exists to receive node2's
// MisconductReport broadcast, proving the detection actually propagates
// to a peer that never independently measured anything itself, the same
// property Stage D's misconduct reporting was built to test.
//
// Explicit scope, not proven here: this is naive-withholding detection
// (a relay that delays its Flood forward but doesn't also delay its own
// HopWitness commitment -- see node.rs's docs on why the witness is sent
// immediately, decoupled from artificial_forward_delay_ms). A
// sophisticated adversary who deliberately delays its own witness too
// would defeat this specific mechanism. That's a real, acknowledged
// limit, not something this test claims to cover.

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

#[allow(clippy::too_many_arguments)]
async fn spawn_relay(
    id: u32,
    listen_addr: std::net::SocketAddr,
    upstream: (NodeId, std::net::SocketAddr),
    downstream: Option<(NodeId, std::net::SocketAddr)>,
    artificial_forward_delay_ms: Option<u64>,
) -> MeshNode {
    let mut peers = vec![(upstream.0, upstream.1, [0u8; 32])];
    if let Some(d) = downstream {
        peers.push((d.0, d.1, [0u8; 32]));
    }
    MeshNode::new(MeshConfig {
        node_id: NodeId(id),
        region: Region::UsEast1,
        listen_addr,
        peers,
        node_key: None,
        mesh_encryption_key: None,
        // Fast enough to build a usable RTT baseline within the sleep
        // window below; see node.rs's own docs on why this is much
        // faster than a production cadence would want to be.
        heartbeat_interval_ms: 5000.0,
        max_missed_heartbeats: 100,
        schedule: None,
        artificial_forward_delay_ms,
        require_staked_reporters: false,
        misconduct_stake_threshold: 0,
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn test_no_false_positive_under_normal_conditions() {
    let base = 10800u16;
    let addrs: Vec<_> = (0..4).map(|i| addr(base + i)).collect();

    let node1 = spawn_relay(
        1,
        addrs[1],
        (NodeId(0), addrs[0]),
        Some((NodeId(2), addrs[2])),
        None,
    )
    .await;
    let node2 = spawn_relay(
        2,
        addrs[2],
        (NodeId(1), addrs[1]),
        Some((NodeId(3), addrs[3])),
        None,
    )
    .await;
    let mut node3 = spawn_relay(3, addrs[3], (NodeId(2), addrs[2]), None, None).await;
    let mut misconduct = node3.misconduct_receiver();

    tokio::spawn(node1.run());
    tokio::spawn(node2.run());
    tokio::spawn(node3.run());

    // Let real Ping/Pong establish an RTT baseline before sending
    // anything that could be judged against it.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let mut injector = UdpTransport::bind(addrs[0], None).await.unwrap();
    injector.register_peer(NodeId(1), addrs[1], [0u8; 32]);

    let order = signed_order(31, 1);
    let flood_msg = FloodMessage {
        order,
        hop_count: 0,
        path: vec![NodeId(0)],
        timestamp: now_ms(),
        source_region: Region::UsEast1,
    };
    injector
        .send(NodeId(1), WireMessage::Flood(flood_msg))
        .await
        .unwrap();

    let result = tokio::time::timeout(Duration::from_millis(700), misconduct.recv()).await;
    assert!(
        result.is_err(),
        "a real order forwarded honestly and promptly under normal localhost jitter must NOT trigger a misconduct report, got: {result:?}"
    );
}

#[tokio::test]
async fn test_detects_a_deliberately_delayed_relay() {
    let base = 10900u16;
    let addrs: Vec<_> = (0..4).map(|i| addr(base + i)).collect();

    // node1 delays its own Flood forward by 300ms -- deliberate
    // withholding, simulated. Its HopWitness commitment is NOT delayed
    // (see node.rs), so this is exactly the naive-withholding case this
    // mechanism is scoped to catch.
    let node1 = spawn_relay(
        1,
        addrs[1],
        (NodeId(0), addrs[0]),
        Some((NodeId(2), addrs[2])),
        Some(300),
    )
    .await;
    let node2 = spawn_relay(
        2,
        addrs[2],
        (NodeId(1), addrs[1]),
        Some((NodeId(3), addrs[3])),
        None,
    )
    .await;
    let mut node3 = spawn_relay(3, addrs[3], (NodeId(2), addrs[2]), None, None).await;
    let mut misconduct = node3.misconduct_receiver();

    tokio::spawn(node1.run());
    tokio::spawn(node2.run());
    tokio::spawn(node3.run());

    tokio::time::sleep(Duration::from_millis(1500)).await;

    let mut injector = UdpTransport::bind(addrs[0], None).await.unwrap();
    injector.register_peer(NodeId(1), addrs[1], [0u8; 32]);

    let order = signed_order(32, 1);
    let flood_msg = FloodMessage {
        order,
        hop_count: 0,
        path: vec![NodeId(0)],
        timestamp: now_ms(),
        source_region: Region::UsEast1,
    };
    injector
        .send(NodeId(1), WireMessage::Flood(flood_msg))
        .await
        .unwrap();

    let event = tokio::time::timeout(Duration::from_secs(2), misconduct.recv())
        .await
        .expect("timed out waiting for node3 to receive a misconduct report from node2")
        .expect("misconduct channel closed unexpectedly");

    assert_eq!(
        event.subject,
        NodeId(1),
        "node1 -- the relay that actually delayed its forward -- should be the reported subject"
    );
    assert_eq!(
        event.reporter,
        NodeId(2),
        "node2 -- the peer that measured the anomalous transit time -- should be the reporter"
    );
    println!("detected: {}", event.reason);
}
