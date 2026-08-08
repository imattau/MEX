// Real multi-hop mesh tests: several genuine MeshNode instances, each a
// real tokio task with a real bound UDP socket on localhost, relaying a
// real flood message through each other -- not the simulated topology
// math in integration::scale_100_test, and not the single-hop check in
// mesh_test.rs. This is what "does the mesh actually forward across
// multiple real nodes, and what happens when one is down" looks like
// tested for real rather than assumed.
//
// Topology for both tests: injector(0) -> node1 -> node2 -> node3 ->
// observer(4), a straight chain. MeshNode's peer-splitting rule (lower
// NodeId = upstream, higher = downstream, see protocol::MeshNode::new)
// means each relay only forwards toward higher IDs, so this chain
// propagates in exactly one direction with no risk of loops.

use common::{FloodMessage, NodeId, Order, OrderSide, Region, SettlementPreference, SettlementRequester};
use ed25519_dalek::Signer;
use protocol::{MeshConfig, MeshNode, UdpTransport, WireMessage};

fn addr(port: u16) -> std::net::SocketAddr {
    format!("127.0.0.1:{}", port).parse().unwrap()
}

fn signed_order(seed: u8, nonce: u64) -> Order {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let trader = signing_key.verifying_key().to_bytes();
    let mut order = Order {
        id: [seed; 32],
        trader,
        symbol: "ETH-USD".to_string(),
        side: OrderSide::Buy,
        price: 3000,
        amount: 1,
        signature: vec![],
        nonce,
        expiry: 0,
        settlement_preference: SettlementPreference::Standard,
        settlement_requester: SettlementRequester::Seller,
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

// Reads from `transport` until a Flood arrives (skipping heartbeats and
// any message that fails to authenticate, exactly like
// mesh_test.rs::test_flood_forwarding_over_udp), or the timeout elapses.
async fn wait_for_flood(transport: &UdpTransport, timeout: std::time::Duration) -> Option<(NodeId, FloodMessage)> {
    tokio::time::timeout(timeout, async {
        loop {
            match transport.recv().await {
                Ok((from, WireMessage::Flood(fm))) => return (from, fm),
                _ => continue,
            }
        }
    })
    .await
    .ok()
}

#[tokio::test]
async fn test_multi_hop_forwarding_across_three_real_relay_nodes() {
    let base = 10400u16;
    let addrs: Vec<_> = (0..5).map(|i| addr(base + i)).collect(); // 0=injector,1..3=relays,4=observer

    // Each relay's peers: (lower id, its addr) upstream, (higher id, its
    // addr) downstream -- see MeshNode::new's split rule.
    for i in 1..=3u32 {
        let node = MeshNode::new(MeshConfig {
            node_id: NodeId(i),
            region: Region::UsEast1,
            listen_addr: addrs[i as usize],
            peers: vec![
                (NodeId(i - 1), addrs[(i - 1) as usize], [0u8; 32]),
                (NodeId(i + 1), addrs[(i + 1) as usize], [0u8; 32]),
            ],
            heartbeat_interval_ms: 5000.0, // slow enough to not interfere with the short recv window below
            max_missed_heartbeats: 100,
            node_key: None,
            mesh_encryption_key: None,
            schedule: None,
        })
        .await
        .unwrap();
        tokio::spawn(node.run());
    }
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let mut injector = UdpTransport::bind(addrs[0], None).await.unwrap();
    injector.register_peer(NodeId(1), addrs[1], [0u8; 32]);
    let mut observer = UdpTransport::bind(addrs[4], None).await.unwrap();
    observer.register_peer(NodeId(3), addrs[3], [0u8; 32]); // so resolve_sender can identify the final relay

    let order = signed_order(11, 1);
    let flood_msg = FloodMessage {
        order: order.clone(),
        hop_count: 0,
        path: vec![NodeId(0)],
        timestamp: now_ms(),
        source_region: Region::UsEast1,
    };
    injector.send(NodeId(1), WireMessage::Flood(flood_msg)).await.unwrap();

    let (from, fm) = wait_for_flood(&observer, std::time::Duration::from_secs(2))
        .await
        .expect("observer never received the flood message after 3 real relay hops");

    assert_eq!(from, NodeId(3), "final hop should arrive from node3, the last real relay");
    assert_eq!(fm.order.id, order.id);
    assert_eq!(fm.hop_count, 3, "three real relay hops (node1, node2, node3) should bring hop_count to 3");
    assert_eq!(
        fm.path,
        vec![NodeId(0), NodeId(1), NodeId(2), NodeId(3)],
        "path should record the injector and all three real relays, in order"
    );
}

// The honest finding this is designed to surface: MeshNode's routing
// table has no rerouting or self-healing when a peer is unreachable --
// dead peers are only ever removed from the routing table on heartbeat
// timeout (see MeshNode::run's heartbeat_tick branch), never replaced
// with an alternate path. On a straight chain, a single relay being down
// creates a hard break: everything downstream of it simply never
// receives anything, with no error surfaced anywhere (UDP send to a dead
// address just succeeds locally -- there's nothing to fail).
#[tokio::test]
async fn test_down_relay_silently_breaks_downstream_propagation() {
    let base = 10500u16;
    let addrs: Vec<_> = (0..5).map(|i| addr(base + i)).collect();

    // Only node1 and node3 actually run -- node2 is configured into both
    // neighbors' peer lists (as any real deployment would) but never
    // started, simulating it being down/crashed/unreachable.
    for i in [1u32, 3u32] {
        let node = MeshNode::new(MeshConfig {
            node_id: NodeId(i),
            region: Region::UsEast1,
            listen_addr: addrs[i as usize],
            peers: vec![
                (NodeId(i - 1), addrs[(i - 1) as usize], [0u8; 32]),
                (NodeId(i + 1), addrs[(i + 1) as usize], [0u8; 32]),
            ],
            heartbeat_interval_ms: 5000.0,
            max_missed_heartbeats: 100,
            node_key: None,
            mesh_encryption_key: None,
            schedule: None,
        })
        .await
        .unwrap();
        tokio::spawn(node.run());
    }
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let mut injector = UdpTransport::bind(addrs[0], None).await.unwrap();
    injector.register_peer(NodeId(1), addrs[1], [0u8; 32]);
    let observer = UdpTransport::bind(addrs[4], None).await.unwrap();

    let order = signed_order(22, 1);
    let flood_msg = FloodMessage {
        order: order.clone(),
        hop_count: 0,
        path: vec![NodeId(0)],
        timestamp: now_ms(),
        source_region: Region::UsEast1,
    };
    injector.send(NodeId(1), WireMessage::Flood(flood_msg)).await.unwrap();

    // node1 receives and forwards to node2's address -- node2 isn't
    // running, so that UDP send succeeds locally (nothing to reject it)
    // and the message is simply gone. Confirm the observer never sees it.
    let result = wait_for_flood(&observer, std::time::Duration::from_millis(800)).await;
    assert!(
        result.is_none(),
        "observer should NEVER receive the message when the relay between it and the source is down -- \
         got {result:?}, which would mean either rerouting exists (it doesn't, per the code) or this test's \
         topology is wrong"
    );
}
