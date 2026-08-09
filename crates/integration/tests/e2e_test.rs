use common::{NodeId, Order, OrderSide, Region, SettlementPreference, SettlementRequester};
use engine::OrderBook;
use heartbeat::DeterministicHeartbeat;
use prover::{ProverBackend, TradeBatch, BACKEND};
use rdma::{PullScheduler, TraderMemoryRegionManager};
use security::{decrypt_packet, encrypt_packet};
use topology::{NetworkTopology, TopologyNode};
use validation::OrderValidator;
use watchtower::{MockOnChainState, WatchtowerClient};

use ed25519_dalek::Signer;
use rand::rngs::OsRng;
use std::collections::HashMap;

fn u64_to_bytes32(val: u64) -> [u8; 32] {
    let mut result = [0u8; 32];
    result[24..32].copy_from_slice(&val.to_be_bytes());
    result
}

#[test]
fn test_e2e_trade_lifecycle() {
    // 1. Setup Network Topology
    let zone_defs = vec![
        (1, "US".to_string(), (37.7749, -122.4194)),
        (2, "EU".to_string(), (53.3498, -6.2603)),
        (3, "AP".to_string(), (1.3521, 103.8198)),
    ];
    let nodes = vec![
        TopologyNode {
            id: NodeId(0),
            region: Region::UsEast1,
            position: (37.7, -122.4),
            zone_id: 1,
        },
        TopologyNode {
            id: NodeId(1),
            region: Region::EuWest1,
            position: (53.3, -6.2),
            zone_id: 2,
        },
        TopologyNode {
            id: NodeId(2),
            region: Region::ApSoutheast1,
            position: (1.3, 103.8),
            zone_id: 3,
        },
    ];
    let topology = NetworkTopology::generate(nodes, &zone_defs);
    assert_eq!(topology.zones.len(), 3);

    // 2. Setup Heartbeat and Health Checking
    let peers = vec![NodeId(1), NodeId(2)];
    let mut peer_zones = HashMap::new();
    peer_zones.insert(NodeId(1), 2);
    peer_zones.insert(NodeId(2), 3);
    let _heartbeat_tracker = DeterministicHeartbeat::new(
        &peers,
        0,   // base_time
        100, // 100ms interval
        3,   // max_missed
        &topology.zone_connectivity,
        1, // local_zone_id
        &peer_zones,
    );

    // 3. Register Traders and Memory Regions
    let mut csprng = OsRng;
    let signing_key_a = ed25519_dalek::SigningKey::generate(&mut csprng);
    let public_key_a = signing_key_a.verifying_key();
    let trader_a_bytes = public_key_a.to_bytes();

    let signing_key_b = ed25519_dalek::SigningKey::generate(&mut csprng);
    let public_key_b = signing_key_b.verifying_key();
    let trader_b_bytes = public_key_b.to_bytes();

    let mut mr_manager = TraderMemoryRegionManager::new();
    mr_manager.register(trader_a_bytes, 4096, 0x1111);
    mr_manager.register(trader_b_bytes, 4096, 0x2222);

    let mut pull_scheduler = PullScheduler::new(100);
    pull_scheduler.add_trader(trader_a_bytes);
    pull_scheduler.add_trader(trader_b_bytes);

    // 4. Simulate Trader Order Signing and Memory Submissions
    let order_a = Order {
        id: [1u8; 32],
        trader: trader_a_bytes,
        symbol: "ETH-USD".to_string(),
        side: OrderSide::Buy,
        price: 3000,
        amount: 10,
        signature: Vec::new(),
        nonce: 101,
        expiry: 0,
        settlement_preference: SettlementPreference::Standard,
        settlement_requester: SettlementRequester::Seller,
    };
    let mut order_a_signed = order_a.clone();
    let msg_a = OrderValidator::serialize_order_message(&order_a);
    order_a_signed.signature = signing_key_a.sign(&msg_a).to_vec();

    let order_b = Order {
        id: [2u8; 32],
        trader: trader_b_bytes,
        symbol: "ETH-USD".to_string(),
        side: OrderSide::Sell,
        price: 3000,
        amount: 10,
        signature: Vec::new(),
        nonce: 202,
        expiry: 0,
        settlement_preference: SettlementPreference::Standard,
        settlement_requester: SettlementRequester::Seller,
    };
    let mut order_b_signed = order_b.clone();
    let msg_b = OrderValidator::serialize_order_message(&order_b);
    order_b_signed.signature = signing_key_b.sign(&msg_b).to_vec();

    mr_manager
        .get_region_mut(&trader_a_bytes)
        .unwrap()
        .write_orders(&[order_a_signed])
        .unwrap();
    mr_manager
        .get_region_mut(&trader_b_bytes)
        .unwrap()
        .write_orders(&[order_b_signed])
        .unwrap();

    // 5. Ingestion, Validation, and Matching
    let (mut pulled_orders, _) = pull_scheduler.perform_pull(&mr_manager);
    let (pulled_orders_2, _) = pull_scheduler.perform_pull(&mr_manager);
    pulled_orders.extend(pulled_orders_2);

    let mut validator = OrderValidator::new(100);
    let mut validated_orders = Vec::new();

    for order in pulled_orders {
        let valid = validator.validate_order(&order);
        assert!(valid);
        validated_orders.push(order);
    }

    let mut order_book = OrderBook::new("ETH-USD".to_string());
    let mut matches = Vec::new();
    for order in validated_orders {
        let res = order_book.add_order(order);
        matches.extend(res);
    }
    assert_eq!(matches.len(), 1);

    // 6. Mesh Security and Flooding Propagation
    let mesh_symmetric_key = [0x55u8; 32];
    let payload = serde_json::to_vec(&matches[0]).unwrap();

    let encrypted_packet = encrypt_packet(&mesh_symmetric_key, &payload).unwrap();
    let decrypted_payload = decrypt_packet(&mesh_symmetric_key, &encrypted_packet).unwrap();
    let decrypted_match: engine::Match = serde_json::from_slice(&decrypted_payload).unwrap();
    assert_eq!(decrypted_match.price, 3000);

    // 7. ZK Proving and Watchtower Fraud Disputes
    let maker_balance = 1_000_000u64;
    let taker_balance = 1_000_000u64;
    // Root = sum of each trade's (amount * price), not maker_balance +
    // taker_balance -- see prover::DEXBatchCircuit's docs.
    let post_root_val: u64 = matches.iter().map(|m| m.amount * m.price).sum();
    let batch = TradeBatch {
        maker_balances: vec![maker_balance; matches.len()],
        taker_balances: vec![taker_balance; matches.len()],
        trades: matches.clone(),
        pre_state_root: [0u8; 32],
        post_state_root: u64_to_bytes32(post_root_val),
    };

    let proof = BACKEND.prove_batch(&batch).unwrap();
    let mut blockchain_state = MockOnChainState::new();
    let watchtower = WatchtowerClient;
    let audit_passed = watchtower.monitor_batch(&batch, &proof, &BACKEND, &mut blockchain_state);
    assert!(audit_passed);
}
