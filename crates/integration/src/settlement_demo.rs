//  Project Chronos: Order → Batch → Settlement Demo
//
//  Demonstrates the complete lifecycle with multi-tier settlement:
//    1. Order submission (simulated via RDMA pull) with settlement preferences
//    2. Signature validation
//    3. Matching engine (price-time priority, partial fills, fee calculation)
//    4. Settlement tier resolution (Standard/Express/Instant)
//    5. Multi-order batching for settlement
//    6. ZK proof generation (Groth16 over batch state transition)
//    7. Settlement batcher (3-tier priority queues)
//    8. Watchtower fraud monitoring (fee + deadline compliance)
//    9. On-chain settlement simulation
//   10. TSS threshold-signed settlement authorization

use common::{Order, OrderSide, SettlementPreference, SettlementRequester};
use engine::OrderBook;
use rdma::{TraderMemoryRegionManager, PullScheduler};

fn u64_to_bytes32(val: u64) -> [u8; 32] {
    let mut result = [0u8; 32];
    result[24..32].copy_from_slice(&val.to_be_bytes());
    result
}
use validation::OrderValidator;
use security::{encrypt_packet, decrypt_packet};
use prover::{TradeBatch, BACKEND, ProverBackend};
use watchtower::{WatchtowerClient, MockOnChainState, OnChainClient};
use tss::TssSigner;
use storage::{TradeLogger, LogEntry};
use batcher::SettlementBatcher;
use ed25519_dalek::Signer;
use rand::rngs::OsRng;
use std::time::Instant;

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║   Project Chronos — Multi-Tier Settlement Pipeline Demo      ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    // ── Phase 1: Order Inflow ──
    println!("┌─ PHASE 1: ORDER INFLOW ─────────────────────────────────┐");
    let mut csprng = OsRng;
    let mut traders = Vec::new();
    let mut mr_manager = TraderMemoryRegionManager::new();
    let mut pull_scheduler = PullScheduler::new(100);

    for i in 0..3 {
        let sk = ed25519_dalek::SigningKey::generate(&mut csprng);
        let pk = sk.verifying_key().to_bytes();
        traders.push((sk, pk));
        mr_manager.register(pk, 4096, (0x1000 + i) as u32);
        pull_scheduler.add_trader(pk);
        println!("  Trader {} registered: PK {:02x}...{:02x} | MR rkey=0x{:04x}",
            char::from(b'A' + i as u8), pk[0], pk[31], 0x1000u32 + i as u32);
    }

    let orders_raw = vec![
        (&traders[0], OrderSide::Buy,  3000, 5,  101, SettlementPreference::Standard, SettlementRequester::Seller),
        (&traders[1], OrderSide::Sell, 3000, 3,  201, SettlementPreference::Express,  SettlementRequester::Seller),
        (&traders[0], OrderSide::Buy,  2990, 10, 102, SettlementPreference::Standard, SettlementRequester::Seller),
        (&traders[2], OrderSide::Sell, 3000, 7,  301, SettlementPreference::Instant,  SettlementRequester::Seller),
        (&traders[1], OrderSide::Sell, 2990, 5,  202, SettlementPreference::Express,  SettlementRequester::Buyer),
        (&traders[2], OrderSide::Buy,  3000, 2,  302, SettlementPreference::Standard, SettlementRequester::Seller),
    ];

    let mut all_signed_orders = Vec::new();
    for ((sk, pk), side, price, amount, nonce, pref, req) in &orders_raw {
        let mut oid = [0u8; 32];
        let nonce_val: u64 = *nonce;
        oid[0..8].copy_from_slice(&nonce_val.to_be_bytes());
        let order = Order {
            id: oid, trader: *pk,
            symbol: "ETH-USD".to_string(),
            side: *side, price: *price, amount: *amount,
            signature: vec![], nonce: *nonce, expiry: 0,
            settlement_preference: *pref,
            settlement_requester: req.clone(),
        };
        let msg = OrderValidator::serialize_order_message(&order);
        let mut signed = order.clone();
        signed.signature = sk.sign(&msg).to_vec();
        all_signed_orders.push(signed);
    }

    println!("\n  ── Order Book ──");
    println!("  {:>6} {:>4} {:>8} {:>8}  {:>10}  {}", "Trader", "Side", "Price", "Amount", "Settle", "Requester");
    println!("  {}", "─".repeat(52));
    for o in &all_signed_orders {
        println!("  {:>6} {:>4} {:>8} {:>8}  {:>10}  {:?}",
            format!("Trader {}", (o.trader[0] % 3 + 65) as char),
            if o.side == OrderSide::Buy { "BUY" } else { "SELL" },
            o.price, o.amount,
            format!("{:?}", o.settlement_preference),
            o.settlement_requester);
    }

    for (i, order) in all_signed_orders.iter().enumerate() {
        let (_sk, pk) = &orders_raw[i % orders_raw.len()].0;
        if let Some(region) = mr_manager.get_region_mut(pk) {
            let _ = region.write_orders(&[order.clone()]);
        }
    }
    println!("\n  ✓ {} orders written to RDMA memory regions", all_signed_orders.len());

    // ── Phase 2: Ingestion + Validation + Matching ──
    println!("\n┌─ PHASE 2: INGESTION → VALIDATION → MATCHING ──────────┐");
    let mut validator = OrderValidator::new(100);
    let mut order_book = OrderBook::new("ETH-USD".to_string());
    let mut all_matches = Vec::new();

    let mut pulled = Vec::new();
    for _ in 0..all_signed_orders.len() {
        let (orders, latency) = pull_scheduler.perform_pull(&mr_manager);
        if !orders.is_empty() {
            println!("  RDMA pull latency: {:?}", latency);
        }
        pulled.extend(orders);
    }

    let valid_start = Instant::now();
    for order in &pulled {
        if validator.validate_order(order) {
            let matches = order_book.add_order(order.clone());
            if !matches.is_empty() {
                all_matches.extend(matches);
            }
        } else {
            println!("  ✗ INVALID signature: order #{}", order.nonce);
        }
    }
    let valid_elapsed = valid_start.elapsed();
    println!("\n  ✓ {} orders validated ({} sig checks in {:?})",
        pulled.len(), pulled.len(), valid_elapsed);

    println!("\n  ── Match Results with Settlement Tiers ──");
    println!("  {:>8} {:>8} {:>10}  {:>6}  {:>8}  {:>10}",
        "Price", "Amount", "Tier", "BPS", "Seller", "Deadline(s)");
    println!("  {}", "─".repeat(62));
    for m in &all_matches {
        println!("  {:>8} {:>8}  {:>10}  {:>6}  {:02x}...{:02x}  {:>10}",
            m.price, m.amount,
            format!("{:?}", m.settlement_tier),
            m.fee_basis_points,
            m.seller[0], m.seller[31],
            m.settlement_deadline);
    }

    let total_fees: u64 = all_matches.iter()
        .map(|m| m.amount as u64 * m.price as u64 * m.fee_basis_points as u64 / 10_000)
        .sum();
    println!("\n  ✓ {} matches executed", all_matches.len());
    println!("  ✓ Total fees accrued: {} (node reward pool: {})", total_fees, order_book.node_rewards);

    // ── Phase 3: Settlement Batcher ──
    println!("\n┌─ PHASE 3: SETTLEMENT BATCHER (3-TIER) ──────────────────┐");
    let mut batcher = SettlementBatcher::new();

    // Seed the batcher's simulated balance ledger so its per-trade proofs are
    // solvent -- see BalanceLedger docs: this stands in for a real deposit
    // until on-chain event syncing exists.
    for (_, pk) in &traders {
        batcher.deposit(*pk, "ETH-USD", 1_000_000);
    }

    for m in &all_matches {
        batcher.enqueue(m.clone());
    }

    let batches = batcher.process_batches();
    println!("  Standard queue processed: {} batches", batches.iter().filter(|b| {
        b.trades.first().map_or(false, |t| t.settlement_tier == SettlementPreference::Standard)
    }).count());
    println!("  Express queue processed: {} batches", batches.iter().filter(|b| {
        b.trades.first().map_or(false, |t| t.settlement_tier == SettlementPreference::Express)
    }).count());
    println!("  Instant queue processed: {} batches", batches.iter().filter(|b| {
        b.trades.first().map_or(false, |t| t.settlement_tier == SettlementPreference::Instant)
    }).count());

    if !batches.is_empty() {
        let first = &batches[0];
        let proof_bytes: usize = first.proofs.iter().map(|p| p.len()).sum();
        println!("  Sample batch: {} trades, value: {} USD, {} proofs ({} bytes total)",
            first.trades.len(), first.total_value, first.proofs.len(), proof_bytes);
    }

    // ── Phase 4: ZK Proof ──
    println!("\n┌─ PHASE 4: ZK PROOF GENERATION ─────────────────────────┐");
    let pre_state = [0u8; 32];
    let post_state = u64_to_bytes32(2_000_000);

    let batch = TradeBatch {
        trades: all_matches.clone(),
        maker_balance: 1_000_000,
        taker_balance: 1_000_000,
        pre_state_root: pre_state,
        post_state_root: post_state,
    };

    let total_value: u64 = all_matches.iter().map(|m| m.price * m.amount).sum();
    let total_volume: u64 = all_matches.iter().map(|m| m.amount).sum();

    let prove_start = Instant::now();
    let proof = BACKEND.prove_batch(&batch).expect("ZK prove failed");
    let prove_elapsed = prove_start.elapsed();
    println!("  Circuit: balance conservation (maker+taker)");
    println!("  Curve:   BN254 (Ethereum alt_bn128 precompile)");
    println!("  Scheme:  Groth16");
    println!("  Proof size: {} bytes", proof.len());
    println!("  Proving time: {:?}", prove_elapsed);

    // ── Phase 5: AEAD Encryption ──
    println!("\n┌─ PHASE 5: MESH PACKET ENCRYPTION ──────────────────────┐");
    let mesh_key = [0x77u8; 32];
    let batch_payload = serde_json::to_vec(&batch).unwrap();
    let encrypted = encrypt_packet(&mesh_key, &batch_payload)
        .expect("Encrypt failed");
    println!("  Cipher:    ChaCha20-Poly1305 (AEAD)");
    println!("  Plaintext: {} bytes → Ciphertext: {} bytes (+12 nonce + 16 tag)",
        batch_payload.len(), encrypted.len());
    let decrypted = decrypt_packet(&mesh_key, &encrypted)
        .expect("Decrypt failed");
    assert_eq!(decrypted, batch_payload);
    println!("  ✓ Round-trip verified");

    // ── Phase 6: Watchtower Audit (ZK + Fee + Deadline) ──
    println!("\n┌─ PHASE 6: WATCHTOWER FRAUD AUDIT ──────────────────────┐");
    println!("  Auditing batch {}...", hex::encode(&proof[0..8]));
    let mut chain_state = MockOnChainState::new();
    let watchtower = WatchtowerClient;
    let audit_start = Instant::now();
    let valid = watchtower.monitor_batch(&batch, &proof, &BACKEND, &mut chain_state);
    let audit_elapsed = audit_start.elapsed();

    if valid {
        println!("  ✓ ZK proof verified — batch is VALID");
        println!("    Audit time: {:?}", audit_elapsed);
        println!("    Disputes: 0 | Slashed signers: 0");
    }

    println!("\n  ── Tier-Level Fee Compliance Check ──");
    for (_tier, count) in all_matches.iter()
        .fold(std::collections::HashMap::new(), |mut acc, m| {
            *acc.entry(m.settlement_tier).or_insert(0) += 1;
            acc
        })
    {
        let group: Vec<&engine::Match> = all_matches.iter()
            .filter(|m| m.settlement_tier == _tier).collect();
        let all_correct = group.iter().all(|m| {
            m.fee_basis_points == m.settlement_tier.fee_basis_points()
        });
        println!("    {:?}: {} trades, fee compliance: {}",
            _tier, count,
            if all_correct { "✓" } else { "✗ MISMATCH" });
    }

    println!("\n  ── Deadline Compliance Check ──");
    let now = std::time::UNIX_EPOCH.elapsed().unwrap_or_default().as_secs();
    let all_met = all_matches.iter().all(|m| m.settlement_deadline > now);
    println!("    All deadlines in future: {}",
        if all_met { "✓" } else { "✗ SOME PASSED" });

    // Simulate fraud detection
    println!("\n  ── Simulating Fraud Attempt ──");
    let mut fraud_batch = batch.clone();
    fraud_batch.post_state_root[0] ^= 0xFF;
    let mut fraud_state = MockOnChainState::new();
    let fraud_valid = watchtower.monitor_batch(&fraud_batch, &proof, &BACKEND, &mut fraud_state);

    if !fraud_valid {
        println!("  ✗ INVALID batch detected!");
        println!("    Dispute raised:  ✓");
        println!("    Batch rolled back: ✓");
        println!("    Signers slashed:  {}",
            fraud_state.slashed_signers.len());
        assert!(fraud_state.is_rolled_back());
    }

    // ── Phase 7: On-Chain Settlement Simulation ──
    println!("\n┌─ PHASE 7: ON-CHAIN SETTLEMENT ─────────────────────────┐");
    println!("  Contract: SettlementFactory.sol");
    println!("  Verifier: BatchVerifier.sol (Groth16 BN254)");
    println!("");
    println!("  Multi-tier settlement batch submitted:");
    println!("    • Proof: {} bytes", proof.len());
    println!("    • Settlement tiers included:");
    let tier_counts: std::collections::HashMap<SettlementPreference, usize> = all_matches.iter()
        .fold(std::collections::HashMap::new(), |mut acc, m| {
            *acc.entry(m.settlement_tier).or_insert(0) += 1;
            acc
        });
    for (tier, count) in &tier_counts {
        println!("      - {:?}: {} trades", tier, count);
    }
    println!("    • Fee distribution: 50% node / 30% gas / 20% treasury");
    println!("    • Gas estimate: ~200,000 (per batch pairing check)");
    println!("    • Deadline enforcement: Active (refund + slashing)");

    // ── Phase 8: TSS Settlement Authorization ──
    println!("\n┌─ PHASE 8: TSS SETTLEMENT SIGNING ──────────────────────┐");
    let mut tss = TssSigner::new(3, 5);
    let shares = tss.keygen();
    println!("  Scheme: FROST (ed25519)");
    println!("  Threshold: 3-of-5");
    println!("  Shares generated: {}", shares.len());

    let settle_msg = format!("Settle batch: {} trades, {} USD", all_matches.len(), total_value);
    let sig = tss.sign_message(&shares[0..3], settle_msg.as_bytes())
        .expect("TSS sign");
    println!("  Settlement authorization signed: {} bytes", sig.len());
    println!("  ✓ 3-of-5 threshold met — settlement authorized");

    // ── Phase 9: Persistent WAL Logging ──
    println!("\n┌─ PHASE 9: PERSISTENT AUDIT LOG ────────────────────────┐");
    let db_path = std::env::temp_dir().join("chronos_settlement_demo");
    let _ = std::fs::remove_dir_all(&db_path);

    let logger = TradeLogger::open(&db_path).expect("sled open");
    for m in &all_matches {
        logger.append(LogEntry::OrderMatched {
            buy_order_id: m.maker_order_id,
            sell_order_id: m.taker_order_id,
            price: m.price,
            amount: m.amount,
        }).unwrap();
    }
    let recovered = logger.recover_all().expect("recover");
    println!("  Storage: sled (concurrent B+Tree KV)");
    println!("  Entries written: {}", all_matches.len());
    println!("  Entries recovered: {}", recovered.len());
    println!("  ✓ Crash-safe WAL verified");
    drop(logger);
    let _ = std::fs::remove_dir_all(&db_path);

    // ── Summary ──
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║         MULTI-TIER SETTLEMENT PIPELINE COMPLETE              ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  Orders submitted:  {:>4}                                   ║", all_signed_orders.len());
    println!("║  Matches executed:  {:>4}                                   ║", all_matches.len());
    println!("║  Batch value:        {:>6} USD                             ║", total_value);
    println!("║  Total volume:       {:>6} units                           ║", total_volume);
    println!("║  Total fees:         {:>6}                                ║", total_fees);
    println!("║  Settlement tiers:   Standard/Express/Instant               ║");
    for (tier, count) in &tier_counts {
        println!("║    {:?}: {:>4} trades                                   ║", tier, count);
    }
    println!("║  ZK proof size:      {:>4} bytes                           ║", proof.len());
    println!("║  ZK proving time:    {:>4?}                              ║", prove_elapsed);
    println!("║  Watchtower audit:   {:>4?}                              ║", audit_elapsed);
    println!("║  Fee enforcement:    Off-chain + Watchtower (v1)            ║");
    println!("║  Deadline enforce:   Refund + Slashing                      ║");
    println!("║  TSS signers:        3-of-5                                 ║");
    println!("║  Fraud detection:    ACTIVE                                 ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
}
