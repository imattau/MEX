// Stage O1 live validation of the core network-time-ordering hypothesis:
// do two INDEPENDENTLY-POSITIONED nodes, each correcting only its own
// locally-observed arrival time by its own locally-measured one-way
// latency baseline, derive estimated origin times for two orders that
// (a) each individually rank the orders in the TRUE emission order, and
// (b) agree closely with each other's independently-derived estimates,
// without either node coordinating with the other or with a third party
// beyond the ordinary Flood gossip both already receive?
//
// Topology: a bare origin injector sends order A, then (after a REAL,
// known gap) order B, directly to two separate detector MeshNodes --
// D1 and D2, both one hop from origin, but each independently measuring
// its own real (if small, on localhost) one-way latency to origin via
// real Ping/Pong. This deliberately stays within Stage O1's documented
// scope (immediate-witnessing-hop-IS-the-origin) -- see
// protocol::ordering::OriginTimeEstimator's docs for why arbitrary
// multi-hop distance isn't validated by this test.

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

async fn spawn_detector(
    id: u32,
    listen_addr: std::net::SocketAddr,
    origin_addr: std::net::SocketAddr,
) -> MeshNode {
    MeshNode::new(MeshConfig {
        node_id: NodeId(id),
        region: Region::UsEast1,
        listen_addr,
        peers: vec![(NodeId(0), origin_addr, [0u8; 32])],
        node_key: None,
        mesh_encryption_key: None,
        heartbeat_interval_ms: 5000.0,
        max_missed_heartbeats: 100,
        schedule: None,
        artificial_forward_delay_ms: None,
        require_staked_reporters: false,
        misconduct_stake_threshold: 0,
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn test_independently_positioned_nodes_agree_on_order_and_converge_on_origin_time() {
    let origin_addr = addr(13000);
    let d1_addr = addr(13001);
    let d2_addr = addr(13002);

    let mut origin_bind = UdpTransport::bind(origin_addr, None).await.unwrap();
    origin_bind.register_peer(NodeId(1), d1_addr, [0u8; 32]);
    origin_bind.register_peer(NodeId(2), d2_addr, [0u8; 32]);
    let origin = std::sync::Arc::new(origin_bind);

    // D1/D2 treat origin as a real mesh peer (it's in their `peers`
    // config) and Ping it to build their one-way latency baseline --
    // unlike cross_witness_test.rs's bare injector (which never needed
    // to answer Pings, since nothing there measured latency TO the
    // origin itself), THIS test's whole mechanism depends on that
    // baseline existing, so origin needs a real Ping/Pong responder --
    // and it must be listening BEFORE run() starts pinging it, or every
    // ping during the warm-up sleep below just goes nowhere.
    // UdpTransport::send/recv both take &self, so the same bound socket
    // can be shared between this responder task and the Flood-sending
    // code below via Arc, no separate listener needed.
    {
        let origin = origin.clone();
        tokio::spawn(async move {
            loop {
                if let Ok((from, WireMessage::Ping { nonce, .. })) = origin.recv().await {
                    let _ = origin.send(from, WireMessage::Pong { nonce }).await;
                }
            }
        });
    }

    let d1 = spawn_detector(1, d1_addr, origin_addr).await;
    let d2 = spawn_detector(2, d2_addr, origin_addr).await;
    let d1_query = d1.origin_time_query_sender();
    let d2_query = d2.origin_time_query_sender();

    tokio::spawn(d1.run());
    tokio::spawn(d2.run());

    // Let real Ping/Pong establish each detector's own one-way latency
    // baseline to origin before anything is measured against it.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let order_a = signed_order(41, 1);
    let order_b = signed_order(42, 2);
    const TRUE_GAP_MS: f64 = 150.0;

    let t_a = now_ms();
    let msg_a1 = FloodMessage {
        order: order_a.clone(),
        hop_count: 0,
        path: vec![NodeId(0)],
        timestamp: t_a,
        source_region: Region::UsEast1,
    };
    let msg_a2 = msg_a1.clone();
    origin
        .send(NodeId(1), WireMessage::Flood(msg_a1))
        .await
        .unwrap();
    origin
        .send(NodeId(2), WireMessage::Flood(msg_a2))
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(TRUE_GAP_MS as u64)).await;

    let t_b = now_ms();
    let msg_b1 = FloodMessage {
        order: order_b.clone(),
        hop_count: 0,
        path: vec![NodeId(0)],
        timestamp: t_b,
        source_region: Region::UsEast1,
    };
    let msg_b2 = msg_b1.clone();
    origin
        .send(NodeId(1), WireMessage::Flood(msg_b1))
        .await
        .unwrap();
    origin
        .send(NodeId(2), WireMessage::Flood(msg_b2))
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;

    async fn query(
        sender: &tokio::sync::mpsc::Sender<([u8; 32], tokio::sync::oneshot::Sender<Option<f64>>)>,
        order_id: [u8; 32],
    ) -> Option<f64> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        sender.send((order_id, tx)).await.unwrap();
        rx.await.unwrap()
    }

    let d1_a = query(&d1_query, order_a.id)
        .await
        .expect("D1 should have an estimate for order A");
    let d1_b = query(&d1_query, order_b.id)
        .await
        .expect("D1 should have an estimate for order B");
    let d2_a = query(&d2_query, order_a.id)
        .await
        .expect("D2 should have an estimate for order A");
    let d2_b = query(&d2_query, order_b.id)
        .await
        .expect("D2 should have an estimate for order B");

    println!("D1: A={d1_a:.2} B={d1_b:.2} (gap={:.2})", d1_b - d1_a);
    println!("D2: A={d2_a:.2} B={d2_b:.2} (gap={:.2})", d2_b - d2_a);
    println!(
        "cross-node agreement on A: |D1-D2|={:.2}ms",
        (d1_a - d2_a).abs()
    );
    println!(
        "cross-node agreement on B: |D1-D2|={:.2}ms",
        (d1_b - d2_b).abs()
    );

    // (a) each node individually ranks A before B, matching true emission order.
    assert!(
        d1_a < d1_b,
        "D1 must independently rank order A before order B -- got A={d1_a}, B={d1_b}"
    );
    assert!(
        d2_a < d2_b,
        "D2 must independently rank order A before order B -- got A={d2_a}, B={d2_b}"
    );

    // (b) the two independently-derived estimates for the SAME order
    // converge -- neither node told the other anything beyond ordinary
    // gossip, yet their corrected estimates should land close together.
    // 50ms is generous for a localhost test (well under half of
    // TRUE_GAP_MS), while still being a real, non-trivial assertion.
    assert!((d1_a - d2_a).abs() < 50.0, "D1 and D2's independent estimates for order A should converge -- got |{d1_a} - {d2_a}| = {}", (d1_a - d2_a).abs());
    assert!((d1_b - d2_b).abs() < 50.0, "D1 and D2's independent estimates for order B should converge -- got |{d1_b} - {d2_b}| = {}", (d1_b - d2_b).abs());

    // The corrected gap between A and B should be reasonably close to
    // the TRUE injected gap, not just ordinally correct -- demonstrating
    // real numeric convergence toward ground truth, not just a
    // coincidentally-correct ranking.
    let d1_gap = d1_b - d1_a;
    let d2_gap = d2_b - d2_a;
    assert!(
        (d1_gap - TRUE_GAP_MS).abs() < 50.0,
        "D1's corrected gap should be close to the true {TRUE_GAP_MS}ms gap -- got {d1_gap}ms"
    );
    assert!(
        (d2_gap - TRUE_GAP_MS).abs() < 50.0,
        "D2's corrected gap should be close to the true {TRUE_GAP_MS}ms gap -- got {d2_gap}ms"
    );
}
