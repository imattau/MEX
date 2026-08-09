// Stage 3 live validation: does quorum actually gate the reputation
// consequence, using a real MeshNode's real receive path (not just
// MisconductQuorum's unit tests in isolation)?
//
// MisconductReport's `reporter` field is part of the message content
// itself, not derived from which address it physically arrived from --
// so this test can send reports claiming to be from different reporters
// via bare UdpTransport injectors without needing a multi-node mesh to
// generate genuinely independent traffic. That's a real property of the
// wire protocol worth being honest about: nothing here cryptographically
// ties a report to the sender's actual identity (see
// MisconductReport's own docs on this).

use common::{NodeId, Region};
use protocol::{MeshConfig, MeshNode, UdpTransport, WireMessage};
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

async fn spawn_detector(id: u32, listen_addr: std::net::SocketAddr) -> MeshNode {
    MeshNode::new(MeshConfig {
        node_id: NodeId(id),
        region: Region::UsEast1,
        listen_addr,
        peers: vec![],
        node_key: None,
        mesh_encryption_key: None,
        heartbeat_interval_ms: 5000.0,
        max_missed_heartbeats: 100,
        schedule: None,
        artificial_forward_delay_ms: None,
        require_staked_reporters: false,
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn test_single_accusation_never_reaches_quorum() {
    let detector_addr = addr(12000);
    let mut detector = spawn_detector(10, detector_addr).await;
    let mut confirmed = detector.confirmed_misconduct_receiver();
    tokio::spawn(detector.run());
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut injector = UdpTransport::bind(addr(12001), None).await.unwrap();
    injector.register_peer(NodeId(10), detector_addr, [0u8; 32]);
    let subject = NodeId(99);
    injector.send(NodeId(10), WireMessage::MisconductReport {
        reporter: NodeId(20),
        subject,
        reason: "a single accuser's unverified claim".to_string(),
        timestamp: now_secs(),
    }).await.unwrap();

    let result = tokio::time::timeout(Duration::from_millis(500), confirmed.recv()).await;
    assert!(
        result.is_err(),
        "a single, uncorroborated accusation must NOT reach quorum on its own -- that's the entire point of Stage 3, defending against exactly this false-accusation attack surface. Got: {result:?}"
    );
}

#[tokio::test]
async fn test_two_independent_reporters_reach_quorum() {
    let detector_addr = addr(12010);
    let mut detector = spawn_detector(11, detector_addr).await;
    let mut confirmed = detector.confirmed_misconduct_receiver();
    tokio::spawn(detector.run());
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut injector = UdpTransport::bind(addr(12011), None).await.unwrap();
    injector.register_peer(NodeId(11), detector_addr, [0u8; 32]);
    let subject = NodeId(99);

    // First reporter -- alone, per the previous test, should not be
    // enough.
    injector.send(NodeId(11), WireMessage::MisconductReport {
        reporter: NodeId(20),
        subject,
        reason: "reporter 20's claim".to_string(),
        timestamp: now_secs(),
    }).await.unwrap();

    // A DIFFERENT, independent reporter accusing the SAME subject.
    injector.send(NodeId(11), WireMessage::MisconductReport {
        reporter: NodeId(21),
        subject,
        reason: "reporter 21's independent claim".to_string(),
        timestamp: now_secs(),
    }).await.unwrap();

    let result = tokio::time::timeout(Duration::from_secs(2), confirmed.recv())
        .await
        .expect("timed out waiting for quorum to be reached with two independent reporters")
        .expect("confirmation channel closed unexpectedly");

    assert_eq!(result, subject, "the confirmed subject should be the one both independent reporters accused");
}

#[tokio::test]
async fn test_two_reports_from_the_same_reporter_do_not_reach_quorum() {
    let detector_addr = addr(12020);
    let mut detector = spawn_detector(12, detector_addr).await;
    let mut confirmed = detector.confirmed_misconduct_receiver();
    tokio::spawn(detector.run());
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut injector = UdpTransport::bind(addr(12021), None).await.unwrap();
    injector.register_peer(NodeId(12), detector_addr, [0u8; 32]);
    let subject = NodeId(99);

    // Same reporter, sent twice -- MisconductQuorum counts DISTINCT
    // reporters, so this must not count as two votes. Without this, a
    // single malicious node could just spam repeated reports about an
    // honest peer to manufacture "quorum" on its own.
    for _ in 0..2 {
        injector.send(NodeId(12), WireMessage::MisconductReport {
            reporter: NodeId(20),
            subject,
            reason: "reporter 20's claim, sent twice".to_string(),
            timestamp: now_secs(),
        }).await.unwrap();
    }

    let result = tokio::time::timeout(Duration::from_millis(500), confirmed.recv()).await;
    assert!(
        result.is_err(),
        "repeated reports from the SAME reporter must not manufacture quorum -- got: {result:?}"
    );
}
