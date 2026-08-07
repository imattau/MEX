use common::{Order, OrderSide, NodeId, Region};
use engine::OrderBook;
use rdma::{TraderMemoryRegionManager, PullScheduler};
use validation::OrderValidator;
use topology::{NetworkTopology, TopologyNode};
use security::{encrypt_packet, decrypt_packet};
use heartbeat::DeterministicHeartbeat;
use prover::{TradeBatch, ZKProver};
use watchtower::{WatchtowerClient, MockOnChainState};

use ed25519_dalek::Signer;
use rand::rngs::OsRng;
use std::collections::HashMap;

#[test]
fn test_scale_100_nodes_e2e() {
    println!("Starting 100+ Node Scale E2E Test...");

    // 1. Setup 10 Geographic Zones (Global Datacenters)
    let zone_defs = vec![
        (1, "US-East".to_string(), (37.7749, -122.4194)),
        (2, "US-West".to_string(), (47.6062, -122.3321)),
        (3, "EU-West".to_string(), (53.3498, -6.2603)),
        (4, "EU-Central".to_string(), (50.1109, 8.6821)),
        (5, "AP-Southeast".to_string(), (1.3521, 103.8198)),
        (6, "AP-Northeast".to_string(), (35.6762, 139.6503)),
        (7, "SA-East".to_string(), (-23.5505, -46.6333)),
        (8, "CA-Central".to_string(), (45.5017, -73.5673)),
        (9, "AF-South".to_string(), (-33.9249, 18.4241)),
        (10, "ME-Central".to_string(), (25.2048, 55.2708)),
    ];

    // 2. Provision 10 nodes per zone = 100 virtual nodes
    let mut nodes = Vec::new();
    let mut node_idx = 0;
    for &(zone_id, _, pos) in &zone_defs {
        for _ in 0..10 {
            nodes.push(TopologyNode {
                id: NodeId(node_idx),
                region: match zone_id {
                    1 | 2 | 8 => Region::UsEast1,
                    3 | 4 => Region::EuWest1,
                    _ => Region::ApSoutheast1,
                },
                position: (pos.0 + (node_idx as f64 * 0.001), pos.1 + (node_idx as f64 * 0.001)),
                zone_id,
            });
            node_idx += 1;
        }
    }
    assert_eq!(nodes.len(), 100);

    let topology = NetworkTopology::generate(nodes, &zone_defs);
    println!("  Generated network topology for {} nodes.", topology.routing_tables.len());

    // 3. Setup Scaled Heartbeat Tracker
    let mut peers = Vec::new();
    let mut peer_zones = HashMap::new();
    for i in 1..100 {
        let peer_id = NodeId(i as u32);
        peers.push(peer_id);
        // Map peers to their zone ID
        let zone = ((i / 10) + 1) as u32;
        peer_zones.insert(peer_id, zone);
    }

    let _heartbeat_tracker = DeterministicHeartbeat::new(
        &peers,
        0,
        100,
        3,
        &topology.zone_connectivity,
        1, // Local Node 0 in US-East
        &peer_zones,
    );

    // 4. Register Multi-Zone Traders
    let mut csprng = OsRng;
    let signing_key_a = ed25519_dalek::SigningKey::generate(&mut csprng);
    let trader_a_bytes = signing_key_a.verifying_key().to_bytes();

    let signing_key_b = ed25519_dalek::SigningKey::generate(&mut csprng);
    let trader_b_bytes = signing_key_b.verifying_key().to_bytes();

    let mut mr_manager = TraderMemoryRegionManager::new();
    mr_manager.register(trader_a_bytes, 4096, 0x9999);
    mr_manager.register(trader_b_bytes, 4096, 0x8888);

    let mut pull_scheduler = PullScheduler::new(50);
    pull_scheduler.add_trader(trader_a_bytes);
    pull_scheduler.add_trader(trader_b_bytes);

    // 5. Submit signed orders representing trade entries
    let order_a = Order {
        id: [10u8; 32],
        trader: trader_a_bytes,
        symbol: "ETH-USD".to_string(),
        side: OrderSide::Buy,
        price: 3100,
        amount: 5,
        signature: Vec::new(),
        nonce: 777,
        expiry: 0,
    };
    let mut order_a_signed = order_a.clone();
    let msg_a = OrderValidator::serialize_order_message(&order_a);
    order_a_signed.signature = signing_key_a.sign(&msg_a).to_vec();

    let order_b = Order {
        id: [20u8; 32],
        trader: trader_b_bytes,
        symbol: "ETH-USD".to_string(),
        side: OrderSide::Sell,
        price: 3100,
        amount: 5,
        signature: Vec::new(),
        nonce: 888,
        expiry: 0,
    };
    let mut order_b_signed = order_b.clone();
    let msg_b = OrderValidator::serialize_order_message(&order_b);
    order_b_signed.signature = signing_key_b.sign(&msg_b).to_vec();

    mr_manager.get_region_mut(&trader_a_bytes).unwrap().write_orders(&[order_a_signed]).unwrap();
    mr_manager.get_region_mut(&trader_b_bytes).unwrap().write_orders(&[order_b_signed]).unwrap();

    // 6. Pull, Validate, and Match orders
    let (mut pulled_orders, _) = pull_scheduler.perform_pull(&mr_manager);
    let (pulled_orders_2, _) = pull_scheduler.perform_pull(&mr_manager);
    pulled_orders.extend(pulled_orders_2);

    let mut validator = OrderValidator::new(100);
    let mut validated_orders = Vec::new();
    for order in pulled_orders {
        assert!(validator.validate_order(&order));
        validated_orders.push(order);
    }

    let mut order_book = OrderBook::new("ETH-USD".to_string());
    let mut matches = Vec::new();
    for order in validated_orders {
        matches.extend(order_book.add_order(order));
    }
    assert_eq!(matches.len(), 1);

    // 7. Encrypt, Decrypt and verify mesh delivery integrity
    let mesh_key = [0x99u8; 32];
    let payload = serde_json::to_vec(&matches[0]).unwrap();
    let ciphertext = encrypt_packet(&mesh_key, &payload).unwrap();
    let decrypted = decrypt_packet(&mesh_key, &ciphertext).unwrap();
    let matched_trade: engine::Match = serde_json::from_slice(&decrypted).unwrap();
    assert_eq!(matched_trade.price, 3100);

    // 8. Generate ZK transition proof & settle batch
    let batch = TradeBatch {
        trades: matches.clone(),
        pre_state_root: [0x55u8; 32],
        post_state_root: [0x77u8; 32],
    };

    let proof = ZKProver::prove_batch(&batch).unwrap();
    let mut blockchain_state = MockOnChainState::new();
    let watchtower = WatchtowerClient;
    assert!(watchtower.monitor_batch(&batch, &proof, &mut blockchain_state));

    println!("100+ Node Scale E2E Test successfully passed!");
}
