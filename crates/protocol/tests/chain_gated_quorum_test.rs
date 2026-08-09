// Stage 4b live validation: with require_staked_reporters on, does a
// reporter's vote actually get ignored unless its NodeId resolves (via
// peer_pubkey, Stage 4a) to a pubkey the node's chain_status snapshot
// marks active -- closing the gap misconduct_quorum_test.rs's own docs
// flag (any NodeId gets a free vote, no cost to mint one)?
//
// set_chain_status is the injection point a real deployment would feed
// from a periodic NodeRegistry poll (see chain::ChainAdapter) -- this
// test injects a fake snapshot directly, the same way
// latency_anomaly_test.rs injects fake delay rather than needing a real
// slow network, since the point here is validating the GATING LOGIC, not
// standing up a real chain.

use common::{NodeId, Region};
use protocol::{ChainNodeStatus, MeshConfig, MeshNode, UdpTransport, WireMessage};
use std::collections::HashMap;
use std::time::Duration;

fn addr(port: u16) -> std::net::SocketAddr {
    format!("127.0.0.1:{}", port).parse().unwrap()
}

fn now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

// reporter_20 and reporter_21 are pre-registered as peers (with pinned
// pubkeys) of the detector -- required for peer_pubkey to resolve them
// at all, chain status or not. Their listen addrs are never actually
// dialed in these tests (the detector never broadcasts to them), so
// dummy unbound ports are fine.
async fn spawn_gated_detector(id: u32, listen_addr: std::net::SocketAddr) -> MeshNode {
    MeshNode::new(MeshConfig {
        node_id: NodeId(id),
        region: Region::UsEast1,
        listen_addr,
        peers: vec![
            (NodeId(20), addr(19999), [20u8; 32]),
            (NodeId(21), addr(19998), [21u8; 32]),
        ],
        node_key: None,
        mesh_encryption_key: None,
        heartbeat_interval_ms: 5000.0,
        max_missed_heartbeats: 100,
        schedule: None,
        artificial_forward_delay_ms: None,
        require_staked_reporters: true,
        misconduct_stake_threshold: 0,
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn test_reporters_without_active_chain_status_never_reach_quorum() {
    let detector_addr = addr(12100);
    let mut detector = spawn_gated_detector(13, detector_addr).await;
    let mut confirmed = detector.confirmed_misconduct_receiver();
    // Deliberately no set_chain_status call -- chain_status stays empty,
    // so every reporter is "unknown", not "active".
    tokio::spawn(detector.run());
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut injector = UdpTransport::bind(addr(12101), None).await.unwrap();
    injector.register_peer(NodeId(13), detector_addr, [0u8; 32]);
    let subject = NodeId(99);

    for reporter in [NodeId(20), NodeId(21)] {
        injector.send(NodeId(13), WireMessage::MisconductReport {
            reporter,
            subject,
            reason: format!("{reporter:?}'s claim, no known chain status"),
            timestamp: now_secs(),
        }).await.unwrap();
    }

    let result = tokio::time::timeout(Duration::from_millis(500), confirmed.recv()).await;
    assert!(
        result.is_err(),
        "two reporters with no on-chain active status must not reach quorum when require_staked_reporters is on -- got: {result:?}"
    );
}

#[tokio::test]
async fn test_reporters_marked_active_in_chain_status_do_reach_quorum() {
    let detector_addr = addr(12110);
    let mut detector = spawn_gated_detector(14, detector_addr).await;
    let mut confirmed = detector.confirmed_misconduct_receiver();

    let mut snapshot = HashMap::new();
    snapshot.insert([20u8; 32], ChainNodeStatus { active: true, stake: 10_000 });
    snapshot.insert([21u8; 32], ChainNodeStatus { active: true, stake: 10_000 });
    detector.set_chain_status(snapshot);

    tokio::spawn(detector.run());
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut injector = UdpTransport::bind(addr(12111), None).await.unwrap();
    injector.register_peer(NodeId(14), detector_addr, [0u8; 32]);
    let subject = NodeId(99);

    for reporter in [NodeId(20), NodeId(21)] {
        injector.send(NodeId(14), WireMessage::MisconductReport {
            reporter,
            subject,
            reason: format!("{reporter:?}'s claim, active on chain"),
            timestamp: now_secs(),
        }).await.unwrap();
    }

    let result = tokio::time::timeout(Duration::from_secs(2), confirmed.recv())
        .await
        .expect("timed out waiting for quorum from two chain-active reporters")
        .expect("confirmation channel closed unexpectedly");

    assert_eq!(result, subject, "the confirmed subject should be the one both chain-eligible reporters accused");
}

#[tokio::test]
async fn test_one_active_one_inactive_reporter_does_not_reach_quorum() {
    let detector_addr = addr(12120);
    let mut detector = spawn_gated_detector(15, detector_addr).await;
    let mut confirmed = detector.confirmed_misconduct_receiver();

    // Only reporter 20 is active; reporter 21 is a REGISTERED peer (so
    // peer_pubkey resolves) but explicitly inactive on chain -- distinct
    // from the "unknown" case above, and the more realistic one (a
    // deregistered or slashed-out node still gets replies, it just isn't
    // eligible to vote).
    let mut snapshot = HashMap::new();
    snapshot.insert([20u8; 32], ChainNodeStatus { active: true, stake: 10_000 });
    snapshot.insert([21u8; 32], ChainNodeStatus { active: false, stake: 0 });
    detector.set_chain_status(snapshot);

    tokio::spawn(detector.run());
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut injector = UdpTransport::bind(addr(12121), None).await.unwrap();
    injector.register_peer(NodeId(15), detector_addr, [0u8; 32]);
    let subject = NodeId(99);

    for reporter in [NodeId(20), NodeId(21)] {
        injector.send(NodeId(15), WireMessage::MisconductReport {
            reporter,
            subject,
            reason: format!("{reporter:?}'s claim"),
            timestamp: now_secs(),
        }).await.unwrap();
    }

    let result = tokio::time::timeout(Duration::from_millis(500), confirmed.recv()).await;
    assert!(
        result.is_err(),
        "one active + one inactive reporter is only ONE real vote -- must not reach a threshold-2 quorum. Got: {result:?}"
    );
}
