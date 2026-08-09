// Stage O2 live validation: when two orders' estimated origin times are
// too close to trust a raw timestamp compare, does MeshNode::compare_orders
// still reach a STABLE, AGREED-UPON ranking across two independently-
// observing nodes -- the actual property that matters, not which branch
// (ByTimestamp vs TieBroken) either one happens to take? Small real
// timing variance between D1 and D2 could legitimately put one just
// inside the ambiguity window and the other just outside it; asserting
// exact branch equality between them would be over-constraining and
// flaky. Agreement on the final relative order is what a real ordering
// scheme actually needs.
//
// Same topology as origin_time_estimate_test.rs (Stage O1) -- both
// detectors directly downstream of a shared origin, so this stays within
// this mechanism's documented single-shared-witnessing-hop scope. See
// protocol::ordering's module docs.

use common::{FloodMessage, NodeId, Region};
use ed25519_dalek::Signer;
use protocol::{MeshConfig, MeshNode, OrderingDecision, UdpTransport, WireMessage};
use std::cmp::Ordering as CmpOrdering;
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

fn decision_ordering(d: OrderingDecision) -> CmpOrdering {
    match d {
        OrderingDecision::ByTimestamp(o) => o,
        OrderingDecision::TieBroken(o) => o,
    }
}

async fn setup(
    base_port: u16,
) -> (
    std::sync::Arc<UdpTransport>,
    tokio::sync::mpsc::Sender<(
        [u8; 32],
        [u8; 32],
        tokio::sync::oneshot::Sender<Option<OrderingDecision>>,
    )>,
    tokio::sync::mpsc::Sender<(
        [u8; 32],
        [u8; 32],
        tokio::sync::oneshot::Sender<Option<OrderingDecision>>,
    )>,
) {
    let origin_addr = addr(base_port);
    let d1_addr = addr(base_port + 1);
    let d2_addr = addr(base_port + 2);

    let mut origin_bind = UdpTransport::bind(origin_addr, None).await.unwrap();
    origin_bind.register_peer(NodeId(1), d1_addr, [0u8; 32]);
    origin_bind.register_peer(NodeId(2), d2_addr, [0u8; 32]);
    let origin = std::sync::Arc::new(origin_bind);

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
    let d1_query = d1.compare_orders_query_sender();
    let d2_query = d2.compare_orders_query_sender();

    tokio::spawn(d1.run());
    tokio::spawn(d2.run());

    tokio::time::sleep(Duration::from_millis(1500)).await;

    (origin, d1_query, d2_query)
}

async fn query(
    sender: &tokio::sync::mpsc::Sender<(
        [u8; 32],
        [u8; 32],
        tokio::sync::oneshot::Sender<Option<OrderingDecision>>,
    )>,
    order_a: [u8; 32],
    order_b: [u8; 32],
) -> Option<OrderingDecision> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    sender.send((order_a, order_b, tx)).await.unwrap();
    rx.await.unwrap()
}

#[tokio::test]
async fn test_independently_observing_nodes_agree_on_ranking_under_ambiguous_timing() {
    let (origin, d1_query, d2_query) = setup(14000).await;

    let order_a = signed_order(51, 1);
    let order_b = signed_order(52, 2);

    // Sent back-to-back with no deliberate gap -- the real gap is
    // whatever these two UDP sends and their propagation cost, well
    // inside the ambiguity window, so this exercises the tie-break path
    // (or, if timing noise puts one node just outside the window, the
    // ByTimestamp path with a razor-thin margin) rather than forcing it
    // artificially.
    let t = now_ms();
    let msg_a1 = FloodMessage {
        order: order_a.clone(),
        hop_count: 0,
        path: vec![NodeId(0)],
        timestamp: t,
        source_region: Region::UsEast1,
    };
    let msg_a2 = msg_a1.clone();
    let msg_b1 = FloodMessage {
        order: order_b.clone(),
        hop_count: 0,
        path: vec![NodeId(0)],
        timestamp: t,
        source_region: Region::UsEast1,
    };
    let msg_b2 = msg_b1.clone();
    origin
        .send(NodeId(1), WireMessage::Flood(msg_a1))
        .await
        .unwrap();
    origin
        .send(NodeId(2), WireMessage::Flood(msg_a2))
        .await
        .unwrap();
    origin
        .send(NodeId(1), WireMessage::Flood(msg_b1))
        .await
        .unwrap();
    origin
        .send(NodeId(2), WireMessage::Flood(msg_b2))
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;

    let d1_decision = query(&d1_query, order_a.id, order_b.id)
        .await
        .expect("D1 should be able to compare both orders");
    let d2_decision = query(&d2_query, order_a.id, order_b.id)
        .await
        .expect("D2 should be able to compare both orders");

    println!("D1 decision: {d1_decision:?}");
    println!("D2 decision: {d2_decision:?}");

    let d1_ord = decision_ordering(d1_decision);
    let d2_ord = decision_ordering(d2_decision);
    assert_eq!(
        d1_ord, d2_ord,
        "two independently-observing nodes must agree on the final relative order even under ambiguous timing -- D1 said {d1_decision:?}, D2 said {d2_decision:?}"
    );

    // Repeating the SAME query must be stable -- not a fresh coin-flip
    // each call.
    let d1_decision_again = query(&d1_query, order_a.id, order_b.id).await.unwrap();
    assert_eq!(
        d1_decision, d1_decision_again,
        "repeated comparisons of the same evidence must be stable"
    );

    // Comparing in the reverse order must invert cleanly.
    let d1_reversed = query(&d1_query, order_b.id, order_a.id).await.unwrap();
    assert_eq!(
        decision_ordering(d1_reversed),
        d1_ord.reverse(),
        "comparing B-then-A must be the exact reverse of A-then-B"
    );
}

#[tokio::test]
async fn test_clearly_separated_orders_use_timestamp_not_tie_break() {
    let (origin, d1_query, d2_query) = setup(14010).await;

    let order_a = signed_order(61, 1);
    let order_b = signed_order(62, 2);
    const TRUE_GAP_MS: u64 = 200; // comfortably clear of AMBIGUITY_WINDOW_MS

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

    tokio::time::sleep(Duration::from_millis(TRUE_GAP_MS)).await;

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

    let d1_decision = query(&d1_query, order_a.id, order_b.id).await.unwrap();
    let d2_decision = query(&d2_query, order_a.id, order_b.id).await.unwrap();

    println!("D1 decision: {d1_decision:?}");
    println!("D2 decision: {d2_decision:?}");

    assert_eq!(d1_decision, OrderingDecision::ByTimestamp(CmpOrdering::Less), "a {TRUE_GAP_MS}ms real gap is far outside the ambiguity window -- D1 should rank by timestamp, not fall back to a tie-break, got {d1_decision:?}");
    assert_eq!(d2_decision, OrderingDecision::ByTimestamp(CmpOrdering::Less), "a {TRUE_GAP_MS}ms real gap is far outside the ambiguity window -- D2 should rank by timestamp, not fall back to a tie-break, got {d2_decision:?}");
}
