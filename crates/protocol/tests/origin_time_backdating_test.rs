// Stage O3 live validation of the actual attack this stage closes: NOT
// the classic delay/withholding case (Stage 1-2's tests already cover
// that, and it turns out O1's earliest-wins/min selection already
// defeats it for free -- delaying a forward can only make an estimate
// LATER, which min already discards in favor of any honest faster
// path). The real, previously-open gap is the OTHER direction: a relay
// that inflates its OWN measured latency baseline (simply by delaying
// its Pong replies -- RTT here is derived entirely from the detector's
// own clock, so a peer can never make it appear smaller than physically
// possible, only larger) can make `local_arrival_time - baseline`
// (see ordering::OriginTimeEstimator's docs) look artificially EARLY for
// anything relayed through it, even while forwarding and witnessing
// every order completely honestly and promptly otherwise. That's a real
// backdating / priority-grinding vector: is_anomalous alone (one-sided,
// "too slow" only) would never catch it.
//
// Topology: origin sends order A to BOTH a malicious relay (a bare,
// hand-rolled task -- not a real MeshNode, since this specific dishonest
// behavior, delaying ONLY Pong while forwarding everything else
// honestly, isn't something MeshNode's existing artificial_forward_delay_ms
// knob can express) and an honest relay (a real MeshNode), both direct
// peers of the detector. The malicious relay delays its Pong replies by
// 300ms (inflating the detector's measured baseline to it) but forwards
// AND witnesses order A immediately and honestly. Without Stage O3, the
// detector's origin_time estimate via the malicious relay would be
// ~150ms EARLIER than the true emission time and (being numerically
// smaller) would win under plain earliest-wins selection. With Stage
// O3's is_implausibly_fast check, that witness gets flagged and excluded
// in favor of the honest relay's correct estimate.

use common::{FloodMessage, NodeId, Region};
use ed25519_dalek::Signer;
use protocol::{MeshConfig, MeshNode, UdpTransport, WireMessage};
use std::sync::Arc;
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

async fn query(
    sender: &tokio::sync::mpsc::Sender<([u8; 32], tokio::sync::oneshot::Sender<Option<f64>>)>,
    order_id: [u8; 32],
) -> Option<f64> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    sender.send((order_id, tx)).await.unwrap();
    rx.await.unwrap()
}

#[tokio::test]
async fn test_baseline_inflating_relay_cannot_backdate_order_priority() {
    let origin_addr = addr(15000);
    let malicious_addr = addr(15001);
    let honest_addr = addr(15004);
    let detector_addr = addr(15005);

    // Widened from an initial 300ms after `cargo test --workspace` (many
    // processes contending for CPU, unlike this crate's tests run alone)
    // produced a real, reproducible false failure -- normal scheduling
    // jitter under load pushed the honest estimate further from true
    // than a tight tolerance survives, same root cause
    // latency::MIN_TOLERANCE_MS's own docs describe. 600ms keeps the
    // backdating effect (~300ms, half the RTT) comfortably separated
    // from realistic jitter even under load.
    const PONG_DELAY_MS: u64 = 600;

    // The malicious relay: a bare UdpTransport, not a real MeshNode --
    // delays ONLY its Pong replies (inflating the detector's measured
    // baseline to it), forwards and witnesses every Flood immediately
    // and honestly otherwise.
    let mut malicious_bind = UdpTransport::bind(malicious_addr, None).await.unwrap();
    malicious_bind.register_peer(NodeId(0), origin_addr, [0u8; 32]);
    malicious_bind.register_peer(NodeId(5), detector_addr, [0u8; 32]);
    let malicious = Arc::new(malicious_bind);
    {
        let malicious = malicious.clone();
        tokio::spawn(async move {
            loop {
                match malicious.recv().await {
                    Ok((from, WireMessage::Ping { nonce, .. })) => {
                        let malicious = malicious.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(PONG_DELAY_MS)).await;
                            let _ = malicious.send(from, WireMessage::Pong { nonce }).await;
                        });
                    }
                    Ok((_, WireMessage::Flood(flood_msg))) => {
                        let now = now_ms();
                        let order_id = flood_msg.order.id;
                        // Forwarded and witnessed IMMEDIATELY -- this
                        // relay is honest about everything except its
                        // own latency baseline.
                        let _ = malicious.send(NodeId(5), WireMessage::Flood(flood_msg)).await;
                        let _ = malicious.send(NodeId(5), WireMessage::HopWitness {
                            order_id,
                            hop_node: NodeId(1),
                            forwarded_at: now,
                        }).await;
                    }
                    _ => {}
                }
            }
        });
    }

    let honest = MeshNode::new(MeshConfig {
        node_id: NodeId(4),
        region: Region::UsEast1,
        listen_addr: honest_addr,
        peers: vec![(NodeId(0), origin_addr, [0u8; 32]), (NodeId(5), detector_addr, [0u8; 32])],
        node_key: None,
        mesh_encryption_key: None,
        heartbeat_interval_ms: 5000.0,
        max_missed_heartbeats: 100,
        schedule: None,
        artificial_forward_delay_ms: None,
        require_staked_reporters: false,
        misconduct_stake_threshold: 0,
    }).await.unwrap();

    let detector = MeshNode::new(MeshConfig {
        node_id: NodeId(5),
        region: Region::UsEast1,
        listen_addr: detector_addr,
        peers: vec![(NodeId(1), malicious_addr, [0u8; 32]), (NodeId(4), honest_addr, [0u8; 32])],
        node_key: None,
        mesh_encryption_key: None,
        heartbeat_interval_ms: 5000.0,
        max_missed_heartbeats: 100,
        schedule: None,
        artificial_forward_delay_ms: None,
        require_staked_reporters: false,
        misconduct_stake_threshold: 0,
    }).await.unwrap();
    let detector_query = detector.origin_time_query_sender();

    tokio::spawn(honest.run());
    tokio::spawn(detector.run());

    // Let real Ping/Pong establish baselines -- including the
    // malicious relay's deliberately inflated one -- before anything is
    // measured against them. Comfortably longer than a few PONG_DELAY_MS
    // round trips so the baseline is well established, not one lucky
    // sample.
    tokio::time::sleep(Duration::from_millis(4000)).await;

    let mut origin = UdpTransport::bind(origin_addr, None).await.unwrap();
    origin.register_peer(NodeId(1), malicious_addr, [0u8; 32]);
    origin.register_peer(NodeId(4), honest_addr, [0u8; 32]);

    let order_a = signed_order(71, 1);
    let t_true = now_ms();
    let msg_to_malicious = FloodMessage { order: order_a.clone(), hop_count: 0, path: vec![NodeId(0)], timestamp: t_true, source_region: Region::UsEast1 };
    let msg_to_honest = msg_to_malicious.clone();
    origin.send(NodeId(1), WireMessage::Flood(msg_to_malicious)).await.unwrap();
    origin.send(NodeId(4), WireMessage::Flood(msg_to_honest)).await.unwrap();

    tokio::time::sleep(Duration::from_millis(500)).await;

    let final_estimate = query(&detector_query, order_a.id).await.expect("detector should have an estimate for order A");

    println!("true emission time:   {t_true:.2}");
    println!("final estimate:       {final_estimate:.2} (delta from true: {:.2}ms)", final_estimate - t_true);

    // Without Stage O3, the malicious relay's estimate would be roughly
    // t_true - 300ms (half the 600ms inflated RTT) and, being smaller,
    // would win under plain earliest-wins selection -- a ~300ms
    // backdating win for whoever controls that relay. With O3, the
    // final estimate should track the TRUE emission time (via the
    // honest relay), not the artificially-backdated one. 120ms is
    // generous for realistic jitter (see PONG_DELAY_MS's docs on why it
    // was widened) while staying well clear of the ~300ms attack signal.
    assert!(
        (final_estimate - t_true).abs() < 120.0,
        "final estimate should track the TRUE emission time via the honest relay (within realistic jitter), not the malicious relay's ~300ms-early backdated one -- true={t_true:.2}, got={final_estimate:.2}, delta={:.2}ms",
        final_estimate - t_true
    );
}
