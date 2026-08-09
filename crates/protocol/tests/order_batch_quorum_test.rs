// Stage P3a live validation of the core hypothesis: do two
// INDEPENDENTLY-POSITIONED nodes, each resolving the SAME set of orders
// via ONLY their own locally-measured network-time evidence (same
// topology and evidence-generation pattern as O1-O2's tests), propose
// the IDENTICAL resolved-batch hash to each other and reach quorum on
// it -- without either one being told what the other computed, only
// exchanging the hash itself as a vote?
//
// This directly builds on protocol::sequencer::OrderSequencer (Stage
// P1, validated in order_sequencer_test.rs) -- each node here
// independently runs its own OrderSequencer::flush against its own
// evidence snapshot, then feeds the RESULT into propose_batch. If P1's
// mechanism and O1's convergence property both hold, both nodes should
// resolve to the exact same sequence and therefore the exact same hash.

use common::{FloodMessage, NodeId, Region};
use ed25519_dalek::Signer;
use protocol::{batch_quorum, MeshConfig, MeshNode, OrderSequencer, UdpTransport, WireMessage};
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
async fn test_two_independently_positioned_nodes_reach_batch_quorum_on_identical_hash() {
    let origin_addr = addr(18000);
    let d1_addr = addr(18001);
    let d2_addr = addr(18002);

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

    // D1 and D2 are peers of EACH OTHER too, so propose_batch's
    // broadcast (and the resulting BatchProposal) actually reaches the
    // other side -- not just peers of origin, unlike O1-O2's topology.
    let d1 = MeshNode::new(MeshConfig {
        node_id: NodeId(1),
        region: Region::UsEast1,
        listen_addr: d1_addr,
        peers: vec![
            (NodeId(0), origin_addr, [0u8; 32]),
            (NodeId(2), d2_addr, [0u8; 32]),
        ],
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
    let d2 = MeshNode::new(MeshConfig {
        node_id: NodeId(2),
        region: Region::UsEast1,
        listen_addr: d2_addr,
        peers: vec![
            (NodeId(0), origin_addr, [0u8; 32]),
            (NodeId(1), d1_addr, [0u8; 32]),
        ],
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

    let d1_witness_query = d1.earliest_witness_query_sender();
    let d2_witness_query = d2.earliest_witness_query_sender();
    let d1_propose = d1.propose_batch_sender();
    let d2_propose = d2.propose_batch_sender();
    let mut d1 = d1;
    let mut d2 = d2;
    let mut d1_confirmed = d1.confirmed_batch_receiver();
    let mut d2_confirmed = d2.confirmed_batch_receiver();

    tokio::spawn(d1.run());
    tokio::spawn(d2.run());

    // Let real Ping/Pong establish baselines -- both to origin AND
    // between D1/D2 themselves (needed for propose_batch's broadcast to
    // actually be a "peer", per register_peer's requirements -- though
    // sending doesn't require a latency baseline, only receiving
    // evidence does).
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let order_a = signed_order(41, 1);
    let order_b = signed_order(42, 2);
    let order_c = signed_order(43, 3);

    for order in [&order_a, &order_b, &order_c] {
        let msg1 = FloodMessage {
            order: (*order).clone(),
            hop_count: 0,
            path: vec![NodeId(0)],
            timestamp: now_ms(),
            source_region: Region::UsEast1,
        };
        let msg2 = msg1.clone();
        origin
            .send(NodeId(1), WireMessage::Flood(msg1))
            .await
            .unwrap();
        origin
            .send(NodeId(2), WireMessage::Flood(msg2))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    let order_ids = vec![order_c.id, order_a.id, order_b.id]; // deliberately shuffled input, mirrors P1's test
    let batch_key = batch_quorum::compute_batch_key(&order_ids);

    // Each node independently builds its OWN evidence snapshot and
    // resolves its OWN sequence -- no coordination beyond the mesh
    // gossip both already received.
    let mut d1_sequencer = OrderSequencer::new();
    let mut d2_sequencer = OrderSequencer::new();
    for &id in &order_ids {
        d1_sequencer.add(id);
        d2_sequencer.add(id);
    }

    let mut d1_evidence = HashMap::new();
    let mut d2_evidence = HashMap::new();
    for &id in &order_ids {
        if let Some(w) = query_witness(&d1_witness_query, id).await {
            d1_evidence.insert(id, w);
        }
        if let Some(w) = query_witness(&d2_witness_query, id).await {
            d2_evidence.insert(id, w);
        }
    }

    let d1_resolved = d1_sequencer.flush(&d1_evidence);
    let d2_resolved = d2_sequencer.flush(&d2_evidence);
    println!(
        "D1 resolved: {:?}",
        d1_resolved.iter().map(|id| id[0]).collect::<Vec<_>>()
    );
    println!(
        "D2 resolved: {:?}",
        d2_resolved.iter().map(|id| id[0]).collect::<Vec<_>>()
    );

    d1_propose.send((batch_key, d1_resolved)).await.unwrap();
    d2_propose.send((batch_key, d2_resolved)).await.unwrap();

    let (d1_key, d1_hash) = tokio::time::timeout(Duration::from_secs(2), d1_confirmed.recv())
        .await
        .expect("D1 should reach batch quorum")
        .expect("confirmation channel closed unexpectedly");
    let (d2_key, d2_hash) = tokio::time::timeout(Duration::from_secs(2), d2_confirmed.recv())
        .await
        .expect("D2 should reach batch quorum")
        .expect("confirmation channel closed unexpectedly");

    assert_eq!(d1_key, batch_key);
    assert_eq!(d2_key, batch_key);
    assert_eq!(d1_hash, d2_hash, "both independently-positioned nodes must confirm the SAME agreed hash -- their evidence-driven resolutions must have genuinely matched, not just both reached SOME quorum independently");

    let expected_hash =
        batch_quorum::compute_proposal_hash(&vec![order_a.id, order_b.id, order_c.id]);
    assert_eq!(d1_hash, expected_hash, "the agreed hash should correspond to the TRUE emission order (A, B, C), not the shuffled input order");
}
