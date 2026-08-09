// Stage 4d live validation: does quorum actually weigh votes by real
// on-chain stake, not just gate them pass/fail (that was already covered
// by chain_gated_quorum_test.rs)? Two reporters each individually active
// but each holding only DUST stake must not be able to manufacture
// quorum just by being two distinct identities -- that's exactly the gap
// Stage 4b/4c's own docs flagged as still open (an adversary staking the
// on-chain minimum under several identities still got one full vote per
// identity). And the flip side: even a single reporter whose stake alone
// clears the threshold must NOT be enough on its own -- min_reporters is
// a hard floor Stage 4d deliberately keeps, so weighting never lets one
// voice decide alone (see MisconductQuorum's docs in node.rs).

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

const STAKE_THRESHOLD: u64 = 5_000;

async fn spawn_weighted_detector(id: u32, listen_addr: std::net::SocketAddr) -> MeshNode {
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
        misconduct_stake_threshold: STAKE_THRESHOLD,
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn test_two_active_but_dust_staked_reporters_do_not_reach_quorum() {
    let detector_addr = addr(12200);
    let mut detector = spawn_weighted_detector(16, detector_addr).await;
    let mut confirmed = detector.confirmed_misconduct_receiver();

    // Both genuinely active, both would have passed Stage 4b/4c's plain
    // gate -- but combined stake (200) is far below STAKE_THRESHOLD
    // (5,000). This is the case Stage 4b/4c alone could not defend
    // against: an adversary satisfying "active" cheaply with two
    // near-minimum-stake identities.
    let mut snapshot = HashMap::new();
    snapshot.insert([20u8; 32], ChainNodeStatus { active: true, stake: 100 });
    snapshot.insert([21u8; 32], ChainNodeStatus { active: true, stake: 100 });
    detector.set_chain_status(snapshot);

    tokio::spawn(detector.run());
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut injector = UdpTransport::bind(addr(12201), None).await.unwrap();
    injector.register_peer(NodeId(16), detector_addr, [0u8; 32]);
    let subject = NodeId(99);

    for reporter in [NodeId(20), NodeId(21)] {
        injector.send(NodeId(16), WireMessage::MisconductReport {
            reporter,
            subject,
            reason: format!("{reporter:?}'s dust-staked claim"),
            timestamp: now_secs(),
        }).await.unwrap();
    }

    let result = tokio::time::timeout(Duration::from_millis(500), confirmed.recv()).await;
    assert!(
        result.is_err(),
        "two active but dust-staked reporters (100 + 100 = 200, threshold 5000) must NOT reach quorum -- got: {result:?}"
    );
}

#[tokio::test]
async fn test_two_reporters_with_sufficient_combined_stake_reach_quorum() {
    let detector_addr = addr(12210);
    let mut detector = spawn_weighted_detector(17, detector_addr).await;
    let mut confirmed = detector.confirmed_misconduct_receiver();

    // Neither alone clears STAKE_THRESHOLD (3,000 < 5,000), but their
    // SUM (6,000) does -- and there are still 2 distinct reporters, so
    // min_reporters is satisfied too.
    let mut snapshot = HashMap::new();
    snapshot.insert([20u8; 32], ChainNodeStatus { active: true, stake: 3_000 });
    snapshot.insert([21u8; 32], ChainNodeStatus { active: true, stake: 3_000 });
    detector.set_chain_status(snapshot);

    tokio::spawn(detector.run());
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut injector = UdpTransport::bind(addr(12211), None).await.unwrap();
    injector.register_peer(NodeId(17), detector_addr, [0u8; 32]);
    let subject = NodeId(99);

    for reporter in [NodeId(20), NodeId(21)] {
        injector.send(NodeId(17), WireMessage::MisconductReport {
            reporter,
            subject,
            reason: format!("{reporter:?}'s claim"),
            timestamp: now_secs(),
        }).await.unwrap();
    }

    let result = tokio::time::timeout(Duration::from_secs(2), confirmed.recv())
        .await
        .expect("timed out waiting for quorum from two reporters whose combined stake clears the threshold")
        .expect("confirmation channel closed unexpectedly");

    assert_eq!(result, subject, "the confirmed subject should be the one both reporters, whose combined stake clears threshold, accused");
}

#[tokio::test]
async fn test_single_whale_reporter_alone_never_reaches_quorum() {
    let detector_addr = addr(12220);
    let mut detector = spawn_weighted_detector(18, detector_addr).await;
    let mut confirmed = detector.confirmed_misconduct_receiver();

    // Reporter 20's stake alone (1,000,000) vastly exceeds STAKE_THRESHOLD
    // (5,000) -- if min_reporters weren't a hard floor, this single vote
    // would confirm the accusation by itself. It must not: Stage 4d
    // strengthens what a vote is WORTH, it never relaxes "more than one
    // independent voice must agree" (see MisconductQuorum's docs).
    // Reporter 21 never accuses here at all.
    let mut snapshot = HashMap::new();
    snapshot.insert([20u8; 32], ChainNodeStatus { active: true, stake: 1_000_000 });
    detector.set_chain_status(snapshot);

    tokio::spawn(detector.run());
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut injector = UdpTransport::bind(addr(12221), None).await.unwrap();
    injector.register_peer(NodeId(18), detector_addr, [0u8; 32]);
    let subject = NodeId(99);

    injector.send(NodeId(18), WireMessage::MisconductReport {
        reporter: NodeId(20),
        subject,
        reason: "reporter 20's enormous-stake, but SOLE, claim".to_string(),
        timestamp: now_secs(),
    }).await.unwrap();

    let result = tokio::time::timeout(Duration::from_millis(500), confirmed.recv()).await;
    assert!(
        result.is_err(),
        "a single reporter must never reach quorum alone, no matter how much stake it holds -- got: {result:?}"
    );
}
