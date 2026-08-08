use common::{FloodMessage, NodeId, Order, OrderSide, Region, SettlementPreference, SettlementRequester};
use protocol::{UdpTransport, WireMessage};

fn addr(port: u16) -> std::net::SocketAddr {
    format!("127.0.0.1:{}", port).parse().unwrap()
}

#[tokio::test]
async fn test_udp_transport_send_recv_flood() {
    let mut a = UdpTransport::bind(addr(10100), None).await.unwrap();
    let mut b = UdpTransport::bind(addr(10101), None).await.unwrap();
    a.register_peer(NodeId(1), addr(10101), [0u8; 32]);
    b.register_peer(NodeId(0), addr(10100), [0u8; 32]);

    let order = Order {
        id: [1u8; 32],
        trader: [0u8; 32],
        symbol: "ETH-USD".to_string(),
        side: OrderSide::Buy,
        price: 3000,
        amount: 5,
        signature: vec![],
        nonce: 1,
        expiry: 0,
        settlement_preference: SettlementPreference::Standard,
        settlement_requester: SettlementRequester::Seller,
    };

    let msg = FloodMessage {
        order: order.clone(),
        hop_count: 0,
        path: vec![NodeId(0)],
        timestamp: 0.0,
        source_region: Region::UsEast1,
    };

    a.send(NodeId(1), WireMessage::Flood(msg)).await.unwrap();

    let (_from, received) = b.recv().await.unwrap();
    match received {
        WireMessage::Flood(fm) => {
            assert_eq!(fm.order.id, order.id);
            assert_eq!(fm.order.price, 3000);
        }
        _ => panic!("Expected Flood"),
    }
}

#[tokio::test]
async fn test_udp_transport_send_recv_heartbeat() {
    let mut a = UdpTransport::bind(addr(10200), None).await.unwrap();
    let mut b = UdpTransport::bind(addr(10201), None).await.unwrap();
    a.register_peer(NodeId(1), addr(10201), [0u8; 32]);
    b.register_peer(NodeId(0), addr(10200), [0u8; 32]);

    a.send(
        NodeId(1),
        WireMessage::Heartbeat {
            node_id: NodeId(0),
            timestamp: 100.0,
        },
    )
    .await
    .unwrap();

    let (_from, msg) = b.recv().await.unwrap();
    match msg {
        WireMessage::Heartbeat { node_id, timestamp } => {
            assert_eq!(node_id, NodeId(0));
            assert!((timestamp - 100.0).abs() < 1.0);
        }
        _ => panic!("Expected Heartbeat"),
    }
}

// Was previously `let _ = n1_tx;` at the end with no assertion at all --
// it exercised the code path but never actually checked node1 forwarded
// anything. Fixed to prove real forwarding: node2 is a bare UdpTransport
// standing in as an observer (same technique the injector already uses),
// registered as node1's ONLY downstream peer, so if node1's real
// MeshNode::run() loop doesn't forward, this test now fails instead of
// silently passing.
#[tokio::test]
async fn test_flood_forwarding_over_udp() {
    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::DEBUG).try_init();
    use ed25519_dalek::Signer;
    use protocol::MeshConfig;
    use protocol::MeshNode;

    let addr_0 = addr(10300);
    let addr_1 = addr(10301);
    let addr_2 = addr(10302);

    let node1 = MeshNode::new(MeshConfig {
        node_id: NodeId(1),
        region: Region::UsEast1,
        listen_addr: addr_1,
        // NodeId(0) < 1 -> upstream (the injector); NodeId(2) > 1 ->
        // downstream (where a forward should go).
        peers: vec![(NodeId(0), addr_0, [0u8; 32]), (NodeId(2), addr_2, [0u8; 32])],
        heartbeat_interval_ms: 1000.0,
        max_missed_heartbeats: 100,
        node_key: None,
        mesh_encryption_key: None,
        schedule: None,
    })
    .await
    .unwrap();

    tokio::spawn(node1.run());
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let mut injector = UdpTransport::bind(addr_0, None).await.unwrap();
    injector.register_peer(NodeId(1), addr_1, [0u8; 32]);
    let mut observer = UdpTransport::bind(addr_2, None).await.unwrap();
    // node1 also sends this peer periodic signed heartbeats (it's in
    // node1's peer list) -- registering it here mirrors what any real
    // neighboring peer does, and lets recv() below skip past heartbeats
    // to find the forwarded Flood message.
    observer.register_peer(NodeId(1), addr_1, [0u8; 32]);

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let trader = signing_key.verifying_key().to_bytes();
    let mut order = Order {
        id: [7u8; 32],
        trader,
        symbol: "BTC-USD".to_string(),
        side: OrderSide::Sell,
        price: 60000,
        amount: 1,
        signature: vec![],
        nonce: 7,
        expiry: 0,
        settlement_preference: SettlementPreference::Standard,
        settlement_requester: SettlementRequester::Seller,
    };
    let msg_bytes = validation::OrderValidator::serialize_order_message(&order);
    order.signature = signing_key.sign(&msg_bytes).to_bytes().to_vec();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
        * 1000.0;
    let flood_msg = FloodMessage {
        order: order.clone(),
        hop_count: 0,
        path: vec![NodeId(0)],
        timestamp: now_ms,
        source_region: Region::UsEast1,
    };

    injector
        .send(NodeId(1), WireMessage::Flood(flood_msg))
        .await
        .unwrap();

    // node1 also sends periodic (signed) heartbeats to this peer -- this
    // observer registered node1 under a dummy pubkey (real verification
    // isn't the point of this test), so those heartbeats fail signature
    // checks and recv() errors for them. Skip past both those errors and
    // any non-Flood message to find the forwarded Flood, under an overall
    // timeout.
    let flood = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            match observer.recv().await {
                Ok((from, WireMessage::Flood(fm))) => return (from, fm),
                _ => continue,
            }
        }
    })
    .await
    .expect("timed out waiting for node1 to forward the flood message to node2");

    let (from, fm) = flood;
    assert_eq!(from, NodeId(1), "forwarded message should arrive from node1, not be re-sent by the original injector");
    assert_eq!(fm.order.id, order.id);
    assert_eq!(fm.hop_count, 1, "one real hop through node1 should increment hop_count to 1");
    assert_eq!(fm.path, vec![NodeId(0), NodeId(1)], "path should record the injector and node1, in order");
}
