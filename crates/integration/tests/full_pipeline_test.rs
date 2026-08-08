use common::{FloodMessage, NodeId, Order, OrderSide, Region, SettlementPreference, SettlementRequester};
use engine::OrderBook;
use rdma::{TraderMemoryRegionManager, PullScheduler};
use validation::OrderValidator;
use topology::{NetworkTopology, TopologyNode};
use security::{encrypt_packet, decrypt_packet};
use heartbeat::DeterministicHeartbeat;
use protocol::{MeshConfig, MeshNode, UdpTransport, WireMessage};
use prover::{TradeBatch, BACKEND, ProverBackend};
use watchtower::{WatchtowerClient, MockOnChainState, OnChainClient};
use tss::TssSigner;
use storage::{TradeLogger, LogEntry};

use ed25519_dalek::Signer;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::time::Duration;

fn u64_to_bytes32(val: u64) -> [u8; 32] {
    let mut result = [0u8; 32];
    result[24..32].copy_from_slice(&val.to_be_bytes());
    result
}

fn pick_port(offset: u16) -> std::net::SocketAddr {
    format!("127.0.0.1:{}", 20000 + offset).parse().unwrap()
}

fn make_order(id: u8, trader: [u8; 32], side: OrderSide, price: u64, amount: u64, nonce: u64) -> Order {
    let mut oid = [0u8; 32];
    oid[0] = id;
    Order { id: oid, trader, symbol: "ETH-USD".to_string(), side, price, amount, signature: vec![], nonce, expiry: 0, settlement_preference: SettlementPreference::Standard, settlement_requester: SettlementRequester::Seller }
}

#[tokio::test]
async fn test_full_pipeline_all_13_layers() {
    // ============================================================
    //   LAYERS 1-2: Topology + Heartbeat
    // ============================================================
    let zone_defs = vec![
        (1, "US".to_string(), (37.7749, -122.4194)),
        (2, "EU".to_string(), (53.3498, -6.2603)),
    ];
    let nodes = vec![
        TopologyNode { id: NodeId(0), region: Region::UsEast1, position: (37.7, -122.4), zone_id: 1 },
        TopologyNode { id: NodeId(1), region: Region::EuWest1, position: (53.3, -6.2), zone_id: 2 },
    ];
    let topology = NetworkTopology::generate(nodes, &zone_defs);
    assert_eq!(topology.zones.len(), 2);

    let peers = vec![NodeId(1)];
    let mut peer_zones = HashMap::new();
    peer_zones.insert(NodeId(1), 2);
    let _hb = DeterministicHeartbeat::new(&peers, 0, 100, 3, &topology.zone_connectivity, 1, &peer_zones);

    // ============================================================
    //   LAYER 3 (transport): P2P Mesh Node + UDP Transport
    // ============================================================
    let region = Region::UsEast1;

    let node_a = MeshNode::new(MeshConfig {
        node_id: NodeId(10),
        region,
        listen_addr: pick_port(0),
        peers: vec![(NodeId(20), pick_port(1), [0u8; 32])],
        heartbeat_interval_ms: 500.0,
        max_missed_heartbeats: 20,
        node_key: None,
        mesh_encryption_key: None,
        schedule: None,
        artificial_forward_delay_ms: None,
    }).await.expect("mesh node A");

    let node_b = MeshNode::new(MeshConfig {
        node_id: NodeId(20),
        region,
        listen_addr: pick_port(1),
        peers: vec![(NodeId(10), pick_port(0), [0u8; 32])],
        heartbeat_interval_ms: 500.0,
        max_missed_heartbeats: 20,
        node_key: None,
        mesh_encryption_key: None,
        schedule: None,
        artificial_forward_delay_ms: None,
    }).await.expect("mesh node B");

    tokio::spawn(node_a.run());
    tokio::spawn(node_b.run());
    tokio::time::sleep(Duration::from_millis(300)).await;

    // P2P mesh is running with heartbeats flowing between nodes.

    // ============================================================
    //   LAYERS 4-6: RDMA Pull → Signature Validation → Matching
    // ============================================================
    let mut csprng = OsRng;
    let sk_a = ed25519_dalek::SigningKey::generate(&mut csprng);
    let pk_a = sk_a.verifying_key().to_bytes();
    let sk_b = ed25519_dalek::SigningKey::generate(&mut csprng);
    let pk_b = sk_b.verifying_key().to_bytes();

    let mut mr_manager = TraderMemoryRegionManager::new();
    mr_manager.register(pk_a, 4096, 0x1111);
    mr_manager.register(pk_b, 4096, 0x2222);

    let mut pull_scheduler = PullScheduler::new(100);
    pull_scheduler.add_trader(pk_a);
    pull_scheduler.add_trader(pk_b);

    let order_a = make_order(1, pk_a, OrderSide::Buy, 3000, 10, 101);
    let mut signed_a = order_a.clone();
    signed_a.signature = sk_a.sign(&OrderValidator::serialize_order_message(&order_a)).to_vec();

    let order_b = make_order(2, pk_b, OrderSide::Sell, 3000, 10, 202);
    let mut signed_b = order_b.clone();
    signed_b.signature = sk_b.sign(&OrderValidator::serialize_order_message(&order_b)).to_vec();

    mr_manager.get_region_mut(&pk_a).unwrap().write_orders(&[signed_a]).unwrap();
    mr_manager.get_region_mut(&pk_b).unwrap().write_orders(&[signed_b]).unwrap();

    let (mut pulled, _) = pull_scheduler.perform_pull(&mr_manager);
    let (p2, _) = pull_scheduler.perform_pull(&mr_manager);
    pulled.extend(p2);
    assert_eq!(pulled.len(), 2);

    let mut validator = OrderValidator::new(100);
    let mut valid_orders = Vec::new();
    for o in &pulled {
        assert!(validator.validate_order(o), "sig validation failed for nonce {}", o.nonce);
        valid_orders.push(o.clone());
    }

    let mut order_book = OrderBook::new("ETH-USD".to_string());
    let mut matches = Vec::new();
    for o in valid_orders {
        matches.extend(order_book.add_order(o));
    }
    assert_eq!(matches.len(), 1);
    let mtch = &matches[0];
    assert_eq!(mtch.price, 3000);
    assert_eq!(mtch.amount, 10);

    // ============================================================
    //   LAYER 7: Flood Propagation via P2P Mesh
    // ============================================================
    let mut flood_transport = UdpTransport::bind(pick_port(3), None).await.unwrap();
    flood_transport.register_peer(NodeId(10), pick_port(0), [0u8; 32]);

    let flood_order = Order {
        id: [9u8; 32],
        trader: pk_a,
        symbol: "ETH-USD".to_string(),
        side: OrderSide::Buy,
        price: 2999,
        amount: 1,
        signature: vec![],
        nonce: 999,
        expiry: 0,
        settlement_preference: SettlementPreference::Standard,
        settlement_requester: SettlementRequester::Seller,
    };

    let flood_msg = FloodMessage {
        order: flood_order.clone(),
        timestamp: 0.0,
        hop_count: 0,
        source_region: Region::UsEast1,
        path: vec![NodeId(10)],
    };

    flood_transport.send(NodeId(10), WireMessage::Flood(flood_msg)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // ============================================================
    //   LAYER 8: AEAD Encryption (ChaCha20-Poly1305)
    // ============================================================
    let key = [0xAAu8; 32];
    let payload = serde_json::to_vec(&matches[0]).unwrap();
    let encrypted = encrypt_packet(&key, &payload).expect("encrypt");
    let decrypted = decrypt_packet(&key, &encrypted).expect("decrypt");
    let restored: engine::Match = serde_json::from_slice(&decrypted).unwrap();
    assert_eq!(restored.price, 3000);

    // Tamper test
    let mut tampered = encrypted.clone();
    tampered[15] ^= 0xFF;
    assert!(decrypt_packet(&key, &tampered).is_err());

    // ============================================================
    //   LAYERS 9-10: ZK Proving (Groth16) + Watchtower Audit
    // ============================================================
    // Root = sum of each trade's (amount * price), not maker_balance +
    // taker_balance -- see prover::DEXBatchCircuit's docs.
    let post_root_val: u64 = matches.iter().map(|m| m.amount * m.price).sum();
    let batch = TradeBatch {
        maker_balances: vec![1_000_000; matches.len()],
        taker_balances: vec![1_000_000; matches.len()],
        trades: matches.clone(),
        pre_state_root: [0u8; 32],
        post_state_root: u64_to_bytes32(post_root_val),
    };

    let proof = BACKEND.prove_batch(&batch).expect("ZK prove failed");
    assert!(!proof.is_empty());

    let mut chain_state = MockOnChainState::new();
    let wt = WatchtowerClient;
    assert!(wt.monitor_batch(&batch, &proof, &BACKEND, &mut chain_state));
    assert_eq!(chain_state.disputes_raised(), 0);

    // Fraud detection: tampered batch
    let mut tampered_batch = batch.clone();
    tampered_batch.post_state_root[0] ^= 0xFF;
    let mut chain2 = MockOnChainState::new();
    assert!(!wt.monitor_batch(&tampered_batch, &proof, &BACKEND, &mut chain2));
    assert_eq!(chain2.disputes_raised(), 1);
    assert!(chain2.is_rolled_back());

    // ============================================================
    //   LAYER 11: TSS Threshold Signing (FROST)
    // ============================================================
    let mut tss = TssSigner::new(2, 3);
    let shares = tss.keygen();
    assert_eq!(shares.len(), 3);

    let settlement_msg = b"Settle batch #42: 1 match, 3000 USD value";
    let tss_sig = tss.sign_message(&[shares[0].clone(), shares[1].clone()], settlement_msg)
        .expect("TSS sign failed");
    assert!(tss_sig.len() > 32);

    // Insufficient shares
    assert!(tss.sign_message(&[shares[0].clone()], settlement_msg).is_err());

    // ============================================================
    //   LAYER 12: Storage WAL (sled)
    // ============================================================
    let db_path = std::env::temp_dir().join("chronos_full_pipeline_test");
    let _ = std::fs::remove_dir_all(&db_path);

    let logger = TradeLogger::open(&db_path).expect("open sled");

    logger.append(LogEntry::OrderMatched {
        buy_order_id: matches[0].maker_order_id,
        sell_order_id: matches[0].taker_order_id,
        price: matches[0].price,
        amount: matches[0].amount,
    }).expect("append");

    let recovered = logger.recover_all().expect("recover");
    assert_eq!(recovered.len(), 1);
    match &recovered[0] {
        LogEntry::OrderMatched { price, amount, .. } => {
            assert_eq!(*price, 3000);
            assert_eq!(*amount, 10);
        }
        _ => panic!("expected OrderMatched"),
    }

    drop(logger);
    let _ = std::fs::remove_dir_all(&db_path);

    // ============================================================
    //   LAYER 13: VK Export (ZK support)
    // ============================================================
    let vk = BACKEND.export_verifying_key();
    assert!(vk.get("alpha").is_some());
    assert!(vk.get("ic").unwrap().as_array().unwrap().len() >= 1);
}
