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

#[tokio::test]
async fn test_flood_forwarding_over_udp() {
    use protocol::MeshConfig;
    use protocol::MeshNode;

    let addr_0 = addr(10300);
    let addr_1 = addr(10301);

    let node1 = MeshNode::new(MeshConfig {
        node_id: NodeId(1),
        region: Region::UsEast1,
        listen_addr: addr_1,
        peers: vec![(NodeId(0), addr_0, [0u8; 32])],
        heartbeat_interval_ms: 1000.0,
        max_missed_heartbeats: 100,
        node_key: None,
        mesh_encryption_key: None,
        schedule: None,
    })
    .await
    .unwrap();

    let n1_tx = node1.sender();
    tokio::spawn(node1.run());

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let mut transport = UdpTransport::bind(addr_0, None).await.unwrap();
    transport.register_peer(NodeId(1), addr_1, [0u8; 32]);

    let order = Order {
        id: [7u8; 32],
        trader: [0u8; 32],
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

    let flood_msg = FloodMessage {
        order: order.clone(),
        hop_count: 0,
        path: vec![NodeId(0)],
        timestamp: 0.0,
        source_region: Region::UsEast1,
    };

    transport
        .send(NodeId(1), WireMessage::Flood(flood_msg))
        .await
        .unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

    let _ = n1_tx;
}
