// Stage P1 live validation: does OrderSequencer, fed real network-time
// evidence from a real MeshNode, correct a batch whose LOCAL/HTTP-style
// arrival order is wrong relative to true emission order -- the actual
// point of the whole O1-O3 arc, now applied to something that looks like
// real order sequencing instead of just a pairwise comparison?
//
// Topology: same single-shared-origin pattern as O1-O3's tests (detector
// directly downstream of origin, staying within OriginTimeEstimator's
// documented scope). Origin emits three orders A, B, C in TRUE order
// (A first, then B, then C), but the test deliberately calls
// OrderSequencer::add() in a SHUFFLED sequence (C, A, B) -- simulating
// out-of-order HTTP arrival at a sequencer (e.g. from submission-path
// jitter unrelated to when the orders actually originated). flush()
// should recover the TRUE order using the detector's own independently-
// measured network-time evidence, not the shuffled add() order.

use common::{FloodMessage, NodeId, Region};
use ed25519_dalek::Signer;
use protocol::{MeshConfig, MeshNode, OrderSequencer, UdpTransport, WireMessage};
use std::collections::HashMap;
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

async fn query_witness(
    sender: &tokio::sync::mpsc::Sender<(
        [u8; 32],
        tokio::sync::oneshot::Sender<Option<(NodeId, f64)>>,
    )>,
    order_id: [u8; 32],
) -> Option<(NodeId, f64)> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    sender.send((order_id, tx)).await.unwrap();
    rx.await.unwrap()
}

#[tokio::test]
async fn test_sequencer_flush_recovers_true_order_despite_shuffled_arrival() {
    let origin_addr = addr(16000);
    let detector_addr = addr(16001);

    let mut origin_bind = UdpTransport::bind(origin_addr, None).await.unwrap();
    origin_bind.register_peer(NodeId(1), detector_addr, [0u8; 32]);
    let origin = std::sync::Arc::new(origin_bind);

    // Detector treats origin as a real mesh peer and Pings it to build a
    // latency baseline -- same requirement, same responder pattern, as
    // origin_time_estimate_test.rs (Stage O1).
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

    let detector = MeshNode::new(MeshConfig {
        node_id: NodeId(1),
        region: Region::UsEast1,
        listen_addr: detector_addr,
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
    .unwrap();
    let witness_query = detector.earliest_witness_query_sender();

    tokio::spawn(detector.run());

    tokio::time::sleep(Duration::from_millis(1500)).await;

    let order_a = signed_order(81, 1);
    let order_b = signed_order(82, 2);
    let order_c = signed_order(83, 3);
    const GAP_MS: u64 = 100;

    for order in [&order_a, &order_b, &order_c] {
        let msg = FloodMessage {
            order: (*order).clone(),
            hop_count: 0,
            path: vec![NodeId(0)],
            timestamp: now_ms(),
            source_region: Region::UsEast1,
        };
        origin
            .send(NodeId(1), WireMessage::Flood(msg))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(GAP_MS)).await;
    }

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Simulates out-of-order HTTP/local arrival at the sequencer --
    // deliberately NOT in true emission order (A, B, C).
    let mut sequencer = OrderSequencer::new();
    sequencer.add(order_c.id);
    sequencer.add(order_a.id);
    sequencer.add(order_b.id);
    assert_eq!(
        sequencer.pending_order_ids(),
        vec![order_c.id, order_a.id, order_b.id],
        "sanity check: add() order is indeed shuffled relative to truth"
    );

    let mut evidence = HashMap::new();
    for order in [&order_a, &order_b, &order_c] {
        let w = query_witness(&witness_query, order.id)
            .await
            .expect("detector should have evidence for every order");
        evidence.insert(order.id, w);
    }

    let flushed = sequencer.flush(&evidence);

    println!("shuffled add() order: C, A, B");
    println!(
        "flushed order:         {:?}",
        flushed.iter().map(|id| id[0]).collect::<Vec<_>>()
    );

    assert_eq!(
        flushed,
        vec![order_a.id, order_b.id, order_c.id],
        "flush() must recover the TRUE emission order (A, B, C) from real network-time evidence, not the shuffled add() order (C, A, B)"
    );
}

#[tokio::test]
async fn test_sequencer_places_evidence_lacking_order_last_even_with_live_evidence_for_others() {
    let origin_addr = addr(16010);
    let detector_addr = addr(16011);

    let mut origin_bind = UdpTransport::bind(origin_addr, None).await.unwrap();
    origin_bind.register_peer(NodeId(1), detector_addr, [0u8; 32]);
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

    let detector = MeshNode::new(MeshConfig {
        node_id: NodeId(1),
        region: Region::UsEast1,
        listen_addr: detector_addr,
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
    .unwrap();
    let witness_query = detector.earliest_witness_query_sender();

    tokio::spawn(detector.run());
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let order_a = signed_order(91, 1);
    let order_ghost = signed_order(92, 2); // never sent through the mesh at all

    let msg = FloodMessage {
        order: order_a.clone(),
        hop_count: 0,
        path: vec![NodeId(0)],
        timestamp: now_ms(),
        source_region: Region::UsEast1,
    };
    origin
        .send(NodeId(1), WireMessage::Flood(msg))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut sequencer = OrderSequencer::new();
    // The evidence-lacking order added FIRST -- would win under raw
    // arrival order, must not win here.
    sequencer.add(order_ghost.id);
    sequencer.add(order_a.id);

    let mut evidence = HashMap::new();
    if let Some(w) = query_witness(&witness_query, order_a.id).await {
        evidence.insert(order_a.id, w);
    }
    // Deliberately no evidence entry for order_ghost.

    let flushed = sequencer.flush(&evidence);
    assert_eq!(
        flushed,
        vec![order_a.id, order_ghost.id],
        "the evidence-backed order must rank first even though the evidence-lacking one was added first"
    );
}
