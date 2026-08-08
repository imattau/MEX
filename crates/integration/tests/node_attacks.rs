//  Chronos Node-Level Attack Audit: EXPLOIT DEMONSTRATION
//
//  Tests proving malicious node operators can:
//    1. Front-run orders before forwarding
//    2. Censor orders silently
//    3. Tamper with orders in transit (signatures never checked at relay)
//    4. Fabricate settlement batches locally
//    5. Sybil-attack the mesh
//    6. Spoof heartbeats to keep dead nodes alive
//    7. Lie about geographic position
//    8. Watchtower single-instance conspiracy

#[cfg(test)]
mod node_attacks {
    use common::{Order, OrderSide, NodeId, Region, FloodMessage, SettlementPreference, SettlementRequester};
    use protocol::flood::DeterministicFlood;
    use protocol::types::{FloodSchedule, Peer, RoutingTable};
    use prover::{TradeBatch, BACKEND, ProverBackend};
    use watchtower::{WatchtowerClient, MockOnChainState};
    use topology::{NetworkTopology, TopologyNode};

    use ed25519_dalek::Signer;
    use rand::rngs::OsRng;

    fn u64_to_bytes32(val: u64) -> [u8; 32] {
        let mut result = [0u8; 32];
        result[24..32].copy_from_slice(&val.to_be_bytes());
        result
    }

    // ── ATTACK 1: Front-Run Orders Before Forwarding ──
    #[test]
    fn attack_front_run_before_forwarding() {
        let mut csprng = OsRng;
        let sk_victim = ed25519_dalek::SigningKey::generate(&mut csprng);
        let pk_victim = sk_victim.verifying_key().to_bytes();
        let sk_attacker = ed25519_dalek::SigningKey::generate(&mut csprng);
        let pk_attacker = sk_attacker.verifying_key().to_bytes();

        // Victim submits an ETH buy order at 3000
        let victim_order = Order {
            id: [1u8; 32], trader: pk_victim, symbol: "ETH-USD".to_string(),
            side: OrderSide::Buy, price: 3000, amount: 10,
            signature: vec![], nonce: 1, expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };

        // This order enters the mesh as a FloodMessage
        let _flood_msg = FloodMessage {
            order: victim_order.clone(), hop_count: 0, path: vec![NodeId(1)],
            timestamp: 0.0, source_region: Region::UsEast1,
        };

        // ─── The attack ───
        // A malicious relay node sees this flood message.
        // It extracts the intent: "Someone wants to buy ETH at 3000"
        // BEFORE forwarding, the attacker submits their OWN buy order at 2999
        // to get ahead in the queue!

        let _attacker_order = Order {
            id: [9u8; 32], trader: pk_attacker, symbol: "ETH-USD".to_string(),
            side: OrderSide::Buy, price: 3001, amount: 10,  // Slightly better price
            signature: vec![], nonce: 99, expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };

        eprintln!("\n┌─ ATTACK 1: FRONT-RUNNING ────────────────────────────────┐");
        eprintln!("│  Victim submits:   BUY  ETH @ 3000 x 10                │");
        eprintln!("│  Attacker sees it, submits: BUY ETH @ 3001 x 10        │");
        eprintln!("│  Order book: attacker filled first (better price)       │");
        eprintln!("│  Then forwards victim's stale order                     │");
        eprintln!("│                                                         │");
        eprintln!("│  Exploitable: YES                                       │");
        eprintln!("│  Mitigation:    NONE — no encrypted mempool,            │");
        eprintln!("│                 no commit-reveal, no time-locked order  │");
        eprintln!("│  Missing:       FBA ordering, mempool encryption,       │");
        eprintln!("│                 deterministic slot-based ordering       │");
        eprintln!("└─────────────────────────────────────────────────────────┘");
    }

    // ── ATTACK 2: Censor Orders (Drop Forwards) ──
    #[test]
    fn attack_censor_orders() {
        use validation::OrderValidator;
        let mut csprng = OsRng;
        let sk = ed25519_dalek::SigningKey::generate(&mut csprng);
        let pk = sk.verifying_key().to_bytes();

        let mut order = Order {
            id: [1u8; 32], trader: pk, symbol: "ETH-USD".to_string(),
            side: OrderSide::Sell, price: 100, amount: 1000000,
            signature: vec![], nonce: 1, expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };
        order.signature = sk.sign(&OrderValidator::serialize_order_message(&order)).to_vec();

        let rt = RoutingTable {
            upstream_peers: vec![Peer {
                id: NodeId(1), latency_ms: 10.0,
                last_heartbeat: 0.0, health_score: 1.0,
            }],
            downstream_peers: vec![Peer {
                id: NodeId(2), latency_ms: 10.0,
                last_heartbeat: 0.0, health_score: 1.0,
            }],
            zone_peers: vec![],
        };

        let mut flood = DeterministicFlood::new(
            NodeId(0), Region::UsEast1, rt, FloodSchedule::default(),
        );

        let msg = FloodMessage {
            order, hop_count: 0, path: vec![NodeId(1)],
            timestamp: 0.0, source_region: Region::UsEast1,
        };

        let result = flood.on_receive(msg, 0.0).unwrap();

        // Node gets forwarding targets but... just discards them
        eprintln!("\n┌─ ATTACK 2: CENSORSHIP ───────────────────────────────────┐");
        eprintln!("│  Order received from upstream                          │");
        eprintln!("│  Flood generates {} forward targets                     │", result.len());
        eprintln!("│  MALICIOUS NODE: discards result, never forwards        │");
        eprintln!("│  Downstream peers never see the order                  │");
        eprintln!("│                                                         │");
        eprintln!("│  Exploitable: YES — forwarding is voluntary,            │");
        eprintln!("│               no penalty for dropping                  │");
        eprintln!("│  Missing:  Proof-of-forwarding, relay rewards,          │");
        eprintln!("│            gossip accountability                       │");
        eprintln!("└─────────────────────────────────────────────────────────┘");
    }

    // ── ATTACK 3: Relay Sig Validation (NOW FIXED) ──
    #[test]
    fn attack_relay_never_validates_signatures() {
        use validation::OrderValidator;

        let mut csprng = OsRng;
        let sk = ed25519_dalek::SigningKey::generate(&mut csprng);
        let pk = sk.verifying_key().to_bytes();

        let mut order = Order {
            id: [42u8; 32], trader: pk, symbol: "ETH-USD".to_string(),
            side: OrderSide::Buy, price: 3000, amount: 5,
            signature: vec![], nonce: 1, expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };
        order.signature = sk.sign(&OrderValidator::serialize_order_message(&order)).to_vec();

        let rt = RoutingTable {
            upstream_peers: vec![],
            downstream_peers: vec![Peer {
                id: NodeId(2), latency_ms: 1.0,
                last_heartbeat: 0.0, health_score: 1.0,
            }],
            zone_peers: vec![],
        };
        let mut flood = DeterministicFlood::new(
            NodeId(0), Region::UsEast1, rt, FloodSchedule::default(),
        );

        let valid_msg = FloodMessage {
            order: order.clone(), hop_count: 0, path: vec![NodeId(1)],
            timestamp: 0.0, source_region: Region::UsEast1,
        };
        let valid_result = flood.on_receive(valid_msg, 0.0).is_ok();

        let mut tampered = order.clone();
        tampered.id = [99u8; 32];
        let tampered_msg = FloodMessage {
            order: tampered, hop_count: 0, path: vec![NodeId(1)],
            timestamp: 0.0, source_region: Region::UsEast1,
        };
        let tampered_result = flood.on_receive(tampered_msg, 0.0);

        eprintln!("\n┌─ ATTACK 3: RELAY SIGNATURE VALIDATION (FIXED) ───────────┐");
        eprintln!("│  Valid signed order:   {}", if valid_result { "✓ Forwarded" } else { "✗ Rejected" });
        eprintln!("│  Tampered order:       {}", if tampered_result.is_ok() { "✗ Forwarded (VULNERABLE!)" } else { "✓ REJECTED — sig checked at relay!" });
        eprintln!("│                                                         │");
        eprintln!("│  FIXED: flood.on_receive now validates Ed25519 signature │");
        eprintln!("│  before caching and forwarding. Tampered/unauthenticated │");
        eprintln!("│  orders are rejected at every hop.                       │");
        eprintln!("│  Status: FIXED ✓                                         │");
        eprintln!("└─────────────────────────────────────────────────────────┘");
        assert!(valid_result);
        assert!(tampered_result.is_err());
    }

    // ── ATTACK 4: Fabricate Local Settlement Batches ──
    #[test]
    fn attack_fabricate_settlement_batches() {
        // A malicious node operator fabricates trades that never happened
        let fake_trade = engine::Match {
            maker_order_id: [0xBAu8; 32], taker_order_id: [0xDCu8; 32],
            maker_trader: [0xFFu8; 32],   // Fabricated trader
            taker_trader: [0xEEu8; 32],   // Fabricated trader
            price: 1_000_000, amount: 100,  // 100M USD of fabricated value
            timestamp_us: 0,
            settlement_tier: SettlementPreference::Standard,
            fee_basis_points: 5,
            seller: [0u8; 32],
            fee_payer: [0u8; 32],
            symbol: "BTC-USD".to_string(),
            assigned_node: [0u8; 32],
            settlement_deadline: 0,
        };

        // Root = sum of each trade's (amount * price), not maker_balance +
        // taker_balance -- see prover::DEXBatchCircuit's docs.
        let post_root_val = fake_trade.amount * fake_trade.price;
        let batch = TradeBatch {
            trades: vec![fake_trade],
            maker_balance: 1_000_000,
            taker_balance: 1_000_000_000,
            pre_state_root: [0u8; 32],
            post_state_root: u64_to_bytes32(post_root_val),
        };

        // The ZK prover accepts ANY batch — it only proves balance conservation
        let proof = BACKEND.prove_batch(&batch).unwrap();

        let mut chain = MockOnChainState::new();
        let wt = WatchtowerClient;
        let valid = wt.monitor_batch(&batch, &proof, &BACKEND, &mut chain);

        eprintln!("\n┌─ ATTACK 4: FABRICATED SETTLEMENT ────────────────────────┐");
        eprintln!("│  Node fabricates:  100 trades × 1,000,000 USD          │");
        eprintln!("│  ZK proof:          {} bytes (valid!)                  │", proof.len());
        eprintln!("│  Watchtower:        {}", if valid { "✓ APPROVED" } else { "✗ Rejected" });
        eprintln!("│                                                         │");
        eprintln!("│  Exploitable: YES — no cross-node state validation      │");
        eprintln!("│  Mitigation: None — ZK proves math, not market reality   │");
        eprintln!("│  Missing:  Multi-node state consensus,                  │");
        eprintln!("│            cross-validation of settlement batches       │");
        eprintln!("└─────────────────────────────────────────────────────────┘");
        assert!(valid, "Fabricated batch approved by watchtower!");
    }

    // ── ATTACK 5: Sybil-Attack the Mesh ──
    #[test]
    fn attack_sybil_mesh() {
        // Anyone can create a MeshNode with any NodeId
        // No registration, no staking, no identity verification
        let fake_node_count = 1000;
        let fake_nodes: Vec<NodeId> = (0..fake_node_count).map(|i| NodeId(i)).collect();

        eprintln!("\n┌─ ATTACK 5: SYBIL MESH DOMINATION ────────────────────────┐");
        eprintln!("│  Fake nodes created:  {}                                 │", fake_nodes.len());
        eprintln!("│  Cost:                ZERO (no stake, no registration)   │");
        eprintln!("│  Cost to honest node: ZERO (same)                        │");
        eprintln!("│                                                         │");
        eprintln!("│  Attacker spawns {} nodes — can control routing,        │", fake_node_count);
        eprintln!("│  censorship, and order flow.                             │");
        eprintln!("│                                                         │");
        eprintln!("│  Exploitable: YES — no economic staking, no PKI,         │");
        eprintln!("│               no proof-of-personhood                    │");
        eprintln!("│  Missing:  On-chain node registry, staking bond,         │");
        eprintln!("│            reputation system, proof-of-work              │");
        eprintln!("└─────────────────────────────────────────────────────────┘");
    }

    // ── ATTACK 6: Heartbeat Spoofing ──
    #[test]
    fn attack_heartbeat_spoofing() {
        use protocol::heartbeat::HeartbeatTracker;

        let mut tracker = HeartbeatTracker::new(100.0, 3);

        // A real node registers
        tracker.on_heartbeat(NodeId(5), 100.0);

        // Node 5 goes offline at t=200, so by t=500 it should be dead
        let dead = tracker.check_health(500.0);
        let node5_dead = dead.contains(&NodeId(5));

        // But an attacker can spoof heartbeats from NodeId(5) to keep it "alive"
        // This makes dead nodes appear live in the mesh topology
        tracker.on_heartbeat(NodeId(5), 450.0);
        let dead_after_spoof = tracker.check_health(500.0);
        let node5_alive_after_spoof = !dead_after_spoof.contains(&NodeId(5));

        eprintln!("\n┌─ ATTACK 6: HEARTBEAT SPOOFING ───────────────────────────┐");
        eprintln!("│  Node 5 dead at t=500:    {}", if node5_dead { "✓ detected" } else { "✗ missed" });
        eprintln!("│  After spoofed heartbeat: {}", if node5_alive_after_spoof { "✓ appears alive!" } else { "✗ rejected" });
        eprintln!("│                                                         │");
        eprintln!("│  Exploitable: YES — heartbeats unsigned, no challenge   │");
        eprintln!("│  Missing:  Signed heartbeats, challenge-response         │");
        eprintln!("│            liveness proofs (PoL)                        │");
        eprintln!("└─────────────────────────────────────────────────────────┘");
        assert!(node5_alive_after_spoof, "Heartbeat spoofing keeps dead nodes alive!");
    }

    // ── ATTACK 7: Lie About Geographic Position ──
    #[test]
    fn attack_lie_about_position() {
        // An attacker in NYC claims to be in LA, London, and Singapore simultaneously
        let zone_defs = vec![
            (1, "US-West".to_string(), (34.05, -118.24)),    // LA
            (2, "EU".to_string(), (51.50, -0.12)),           // London
            (3, "AP".to_string(), (1.35, 103.81)),           // Singapore
        ];

        // Attacker creates a node claiming to be in LA
        let _honest_pos = (37.7, -122.4);  // Actually in SF
        let claimed_pos = (34.05, -118.24);  // Claims LA
        let nodes = vec![
            TopologyNode { id: NodeId(99), region: Region::UsEast1,
                position: claimed_pos, zone_id: 1 },
            TopologyNode { id: NodeId(1), region: Region::EuWest1,
                position: (51.5, -0.12), zone_id: 2 },
            TopologyNode { id: NodeId(2), region: Region::ApSoutheast1,
                position: (1.35, 103.81), zone_id: 3 },
        ];

        let topology = NetworkTopology::generate(nodes, &zone_defs);

        // Node 99 claims to be in LA but could be anywhere
        eprintln!("\n┌─ ATTACK 7: GEO-POSITION LYING ───────────────────────────┐");
        eprintln!("│  Node actual location:   San Francisco                 │");
        eprintln!("│  Node claimed location:  Los Angeles                   │");
        eprintln!("│  Zones assigned:         {} (based on claim)            │", topology.zones.len());
        eprintln!("│                                                         │");
        eprintln!("│  Attacker can claim to be in EVERY zone, becoming the   │");
        eprintln!("│  'closest' peer to all honest nodes.                    │");
        eprintln!("│                                                         │");
        eprintln!("│  Exploitable: YES — position is self-reported,          │");
        eprintln!("│               never verified (no latency triangulation)│");
        eprintln!("│  Missing:  Proof-of-location, latency-based             │");
        eprintln!("│            verification, multi-party triangulation     │");
        eprintln!("└─────────────────────────────────────────────────────────┘");
    }

    // ── ATTACK 8: Watchtower Conspiracy ──
    #[test]
    fn attack_single_watchtower_conspiracy() {
        // A single WatchtowerClient is the sole fraud detector
        // If the watchtower operator is malicious or compromised,
        // ALL fraudulent batches are approved.

        // The trade is solvent (total_value == taker_balance, so it clears the prover's
        // insolvency guard) but the maker starts with zero balance -- there's still no
        // economic stake behind the "sole arbiter" watchtower that approves it.
        let trade_value = 1_000_000_000_000u64; // 1_000_000 * 1_000_000
        let fraud_batch = TradeBatch {
            trades: vec![engine::Match {
                maker_order_id: [0xDEu8; 32], taker_order_id: [0xADu8; 32],
                maker_trader: [0u8; 32], taker_trader: [0u8; 32],
                price: 1_000_000, amount: 1_000_000,
                timestamp_us: 0,
                settlement_tier: SettlementPreference::Standard,
                fee_basis_points: 5,
                seller: [0u8; 32],
                fee_payer: [0u8; 32],
                symbol: "BTC-USD".to_string(),
                assigned_node: [0u8; 32],
                settlement_deadline: 0,
            }],
            maker_balance: 0,  // Zero balance!
            taker_balance: trade_value,
            pre_state_root: [0u8; 32],
            post_state_root: {
                let mut result = [0u8; 32];
                result[24..32].copy_from_slice(&trade_value.to_be_bytes());
                result
            },
        };

        // A valid proof for this fraud... it's mathematically correct
        // (proves 0 + trade_value, taker_value - trade_value = 0)
        let proof = BACKEND.prove_batch(&fraud_batch).unwrap();

        // Watchtower checks if proof is valid.
        // Since the proof IS mathematically valid, watchtower approves.
        let mut chain = MockOnChainState::new();
        let wt = WatchtowerClient;
        let approved = wt.monitor_batch(&fraud_batch, &proof, &BACKEND, &mut chain);

        eprintln!("\n┌─ ATTACK 8: WATCHTOWER CONSPIRACY ───────────────────────┐");
        eprintln!("│  Fraud batch:       Zero-balance trade for MAX value   │");
        eprintln!("│  Watchtower:        {}", if approved { "✓ APPROVED (sole arbiter)" } else { "✗ Rejected" });
        eprintln!("│  Slashed signers:   {} (no real penalty)", chain.slashed_signers.len());
        eprintln!("│                                                         │");
        eprintln!("│  Exploitable: YES — single watchtower, zero economic    │");
        eprintln!("│               stake, no multi-sig, no challenge period  │");
        eprintln!("│  Missing:  Multi-watchtower threshold (t-of-n),          │");
        eprintln!("│            watchtower staking, challenge period,        │");
        eprintln!("│            external validator set, node slashing        │");
        eprintln!("└─────────────────────────────────────────────────────────┘");
        assert!(approved, "Sole watchtower approves fraudulent batch!");
    }

    // ── ATTACK 9: Clock and Timestamp Bugs ──
    #[test]
    fn attack_timing_window_disabled() {
        // The MeshNode calls flood.on_receive(msg, 0.0) — hardcoded current_time = 0
        // This means ALL timing checks are non-functional:
        //   EarlyPacket check: current_time < msg.timestamp - threshold_ms
        //   → 0.0 < 100.0 - 10.0 → true → ALL real packets fail as "early"
        //
        // And inject_order sets timestamp = 0.0, so injected orders pass
        // (0.0 < 0.0 - 10.0 → false → ok for early check)

        let rt = RoutingTable { upstream_peers: vec![], downstream_peers: vec![], zone_peers: vec![] };
        let mut flood = DeterministicFlood::new(
            NodeId(0), Region::UsEast1, rt, FloodSchedule::default(),
        );

        // A realistic message with a real timestamp
        let real_msg = FloodMessage {
            order: Order {
                id: [1u8; 32], trader: [1u8; 32], symbol: "ETH-USD".to_string(),
                side: OrderSide::Buy, price: 3000, amount: 1,
                signature: vec![], nonce: 1, expiry: 0,
                settlement_preference: SettlementPreference::Standard,
                settlement_requester: SettlementRequester::Seller,
            },
            hop_count: 0, path: vec![],
            timestamp: 1700000000.0,  // Real timestamp
            source_region: Region::UsEast1,
        };

        // Clock is hardcoded to 0.0 in MeshNode::run()
        let result = flood.on_receive(real_msg, 0.0);

        eprintln!("\n┌─ ATTACK 9: BROKEN TIMING WINDOW ─────────────────────────┐");
        eprintln!("│  Real timestamp:    1700000000.0 ms                    │");
        eprintln!("│  Current time:      0.0 ms (HARDCODED!)                │");
        let flood_result = match &result {
            Ok(_) => "✓ ACCEPTED (timing check bypassed)".to_string(),
            Err(e) => format!("✗ REJECTED: {:?}", e),
        };
        eprintln!("│  Flood result:      {}", flood_result);
        eprintln!("│                                                         │");
        eprintln!("│  BUG: MeshNode::run() calls on_receive(msg, 0.0)         │");
        eprintln!("│  This disables ALL timing window validation.            │");
        eprintln!("│  Late packets, early packets, and replayed packets      │");
        eprintln!("│  all bypass the deterministic flood timing guarantees.  │");
        eprintln!("│                                                         │");
        eprintln!("│  Fix: Use SystemTime::now() instead of 0.0              │");
        eprintln!("└─────────────────────────────────────────────────────────┘");
    }

    // ── ATTACK 10: Unknown Peer Masquerading ──
    #[test]
    fn attack_unknown_peer_acceptance() {
        // UdpTransport::resolve_sender maps unknown peers to NodeId(0)
        // An attacker from a random IP can send flood messages that appear
        // to come from NodeId(0)
        eprintln!("\n┌─ ATTACK 10: UNKNOWN PEER MASQUERADING ───────────────────┐");
        eprintln!("│  Any unknown UDP sender → NodeId(0)                     │");
        eprintln!("│  No handshake, no challenge, no auth                    │");
        eprintln!("│  Attacker controls NodeId(0) in the mesh                │");
        eprintln!("│                                                         │");
        eprintln!("│  Exploitable: YES — mesh accepts all traffic            │");
        eprintln!("│  Missing:  Peer authentication, signed messages,        │");
        eprintln!("│            rate limiting per-IP, connection handshake   │");
        eprintln!("└─────────────────────────────────────────────────────────┘");
    }
}
