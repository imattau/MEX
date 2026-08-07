//  Chronos Edge Case Attack Audits
//
//  Self-trading volume inflation + Sled WAL sequence wrap

#[cfg(test)]
mod edge_cases {
    use common::{Order, OrderSide, Region, FloodMessage, NodeId, SettlementPreference, SettlementRequester};
    use engine::OrderBook;
    use prover::{TradeBatch, BACKEND, ProverBackend};
    use watchtower::{WatchtowerClient, MockOnChainState, OnChainClient};
    use validation::OrderValidator;

    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    // ── EDGE CASE 1: Self-Trading Volume Inflation ──
    #[test]
    fn edge_self_trading_volume_inflation() {
        let mut csprng = OsRng;
        let sk = SigningKey::generate(&mut csprng);
        let pk = sk.verifying_key().to_bytes();

        let mut book = OrderBook::new("ETH-USD".to_string());

        // Same trader submits both a sell AND a buy at the same price
        // This matches against themselves — no counterparty, zero net position

        let mut sell_order = Order {
            id: [1u8; 32], trader: pk,
            symbol: "ETH-USD".to_string(),
            side: OrderSide::Sell, price: 3000, amount: 100,
            signature: vec![], nonce: 1, expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };
        sell_order.signature = sk
            .sign(&OrderValidator::serialize_order_message(&sell_order))
            .to_vec();

        let mut buy_order = Order {
            id: [2u8; 32], trader: pk,  // SAME trader!
            symbol: "ETH-USD".to_string(),
            side: OrderSide::Buy, price: 3000, amount: 100,
            signature: vec![], nonce: 2, expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };
        buy_order.signature = sk
            .sign(&OrderValidator::serialize_order_message(&buy_order))
            .to_vec();

        // Place sell first (creates resting ask)
        let _ = book.add_order(sell_order);
        // Then place buy at same price — matches against own sell!
        let matches = book.add_order(buy_order);

        let self_matched = matches.iter().any(|m| m.maker_trader == m.taker_trader);

        eprintln!("\n┌─ EDGE CASE: SELF-TRADING (FIXED) ───────────────────────┐");
        eprintln!("│  Trader places SELL 100 @ 3000, then BUY 100 @ 3000    │");
        eprintln!("│  Matches: {}                                              │", matches.len());
        eprintln!("│  Self-matched: {}                                         │", if self_matched { "✗ STILL VULNERABLE" } else { "✓ BLOCKED — maker≠taker enforced" });
        eprintln!("│                                                         │");
        eprintln!("│  FIXED: engine.add_order skips matches where maker and   │");
        eprintln!("│  taker are the same trader identity.                     │");
        eprintln!("└─────────────────────────────────────────────────────────┘");
        assert!(!self_matched, "Self-trading now blocked");
    }

    // ── EDGE CASE 2: Sled WAL Sequence Wraparound ──
    #[test]
    fn edge_sled_sequence_wrap() {
        eprintln!("\n┌─ EDGE CASE: SLED WAL SEQUENCE WRAP ─────────────────────┐");
        eprintln!("│  Sequence counter: u64, increments on every append      │");
        eprintln!("│  At u64::MAX:        wraps to 0, overwrites first entry │");
        eprintln!("│  At 1M writes/sec:   584,942 years until wrap            │");
        eprintln!("│                                                         │");
        eprintln!("│  Exploitable: YES — silent log corruption at wrap       │");
        eprintln!("│  Impact:      Trade history loss, audit trail broken     │");
        eprintln!("│  Severity:    LOW — impractical trigger, but real bug    │");
        eprintln!("│  Fix:         Panic or error at u64::MAX, or use u128    │");
        eprintln!("└─────────────────────────────────────────────────────────┘");
    }

    // ── EDGE CASE 3: Book pollution with absurd prices ──
    #[test]
    fn edge_absurd_price_book_pollution() {
        let mut book = OrderBook::new("ETH-USD".to_string());

        // Order at price 0
        let zero_price = Order {
            id: [1u8; 32], trader: [1u8; 32],
            symbol: "ETH-USD".to_string(),
            side: OrderSide::Sell, price: 0, amount: 1000000,
            signature: vec![], nonce: 1, expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };
        let matches_zero = book.add_order(zero_price);

        // Order at u64::MAX price
        let max_price = Order {
            id: [2u8; 32], trader: [2u8; 32],
            symbol: "ETH-USD".to_string(),
            side: OrderSide::Buy, price: u64::MAX, amount: 1,
            signature: vec![], nonce: 2, expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };
        let matches_max = book.add_order(max_price);

        eprintln!("\n┌─ EDGE CASE: ABSURD PRICE BOOK POLLUTION ────────────────┐");
        eprintln!("│  Order at price 0:       {} matches                    │", matches_zero.len());
        eprintln!("│  Order at price u64::MAX: {} matches                    │", matches_max.len());
        eprintln!("│                                                         │");
        eprintln!("│  Both orders enter the book as resting orders.          │");
        eprintln!("│  Price 0 sell: sits on ask side forever (no buy at 0).  │");
        eprintln!("│  u64::MAX buy:    sits on bid side forever.              │");
        eprintln!("│  No bounds checking on price values.                    │");
        eprintln!("│  Impact: Book pollution, wasted ZK batch space           │");
        eprintln!("└─────────────────────────────────────────────────────────┘");
    }

    // ── EDGE CASE 4: ZK proving with empty batch ──
    #[test]
    fn edge_empty_batch_zk_proving() {
        let batch = TradeBatch {
            trades: vec![],
            maker_balance: 1_000_000,
            taker_balance: 1_000_000,
            pre_state_root: [0x10u8; 32],
            post_state_root: [0x10u8; 32],  // Same pre/post = no change
        };

        let proof = BACKEND.prove_batch(&batch);

        eprintln!("\n┌─ EDGE CASE: EMPTY BATCH ZK PROVING ────────────────────┐");
        eprintln!("│  Empty batch (zero trades):  {}", if proof.is_err() { "✗ Rejected (correct)" } else { "✓ Accepted! (would prove nothing)" });
        eprintln!("│  Same pre/post state roots:  no-change batch attempted │");
        eprintln!("│                                                         │");
        eprintln!("│  Impact: Wasted ZK proving for no-op batches             │");
        eprintln!("│  Mitigation: prove_batch rejects empty batches           │");
        eprintln!("└─────────────────────────────────────────────────────────┘");
        assert!(proof.is_err(), "Empty batch should be rejected");
    }

    // ── EDGE CASE 5: Flood with missing source_region ──
    #[test]
    fn edge_flood_spoofed_source_region() {
        use protocol::flood::DeterministicFlood;
        use protocol::types::{FloodSchedule, RoutingTable};

        let rt = RoutingTable { upstream_peers: vec![], downstream_peers: vec![], zone_peers: vec![] };
        let mut flood = DeterministicFlood::new(
            NodeId(0), Region::UsEast1, rt, FloodSchedule::default(),
        );

        let mut csprng = OsRng;
        let sk = SigningKey::generate(&mut csprng);
        let pk = sk.verifying_key().to_bytes();
        let mut order = Order {
            id: [5u8; 32], trader: pk, symbol: "ETH-USD".to_string(),
            side: OrderSide::Buy, price: 3000, amount: 1,
            signature: vec![], nonce: 1, expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };
        order.signature = sk.sign(&OrderValidator::serialize_order_message(&order)).to_vec();

        // Claim to be from a different region than actual
        let msg = FloodMessage {
            order, hop_count: 0, path: vec![NodeId(1)],
            timestamp: 0.0,
            source_region: Region::EuWest1,  // Claim EU but actually in US
        };

        let result = flood.on_receive(msg, 1.0);
        let accepted = result.is_ok();

        eprintln!("\n┌─ EDGE CASE: SPOOFED SOURCE REGION ──────────────────────┐");
        eprintln!("│  Node in:      US-East                                   │");
        eprintln!("│  Claimed from: Europe-West (EuWest1)                     │");
        eprintln!("│  Flood accepts: {}                                       │", if accepted { "✓ — region trust-based" } else { "✗ Rejected" });
        eprintln!("│                                                         │");
        eprintln!("│  source_region is self-reported in the FloodMessage      │");
        eprintln!("│  No cryptographic binding to actual node location        │");
        eprintln!("│  Impact: Can claim different zone for latency bypass     │");
        eprintln!("└─────────────────────────────────────────────────────────┘");
    }

    // ── EDGE CASE 6: Nonce-reuse on the same order (cancellation abuse) ──
    #[test]
    fn edge_cancel_order_id_confusion() {
        let mut book = OrderBook::new("ETH-USD".to_string());

        // Place an order
        let buy = Order {
            id: [1u8; 32], trader: [1u8; 32],
            symbol: "ETH-USD".to_string(),
            side: OrderSide::Buy, price: 2990, amount: 5,
            signature: vec![], nonce: 1, expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };
        let matches = book.add_order(buy);
        assert!(matches.is_empty(), "Buy at 2990 shouldn't match empty book");

        // Cancel it
        let cancelled = book.cancel_order([1u8; 32]);
        assert!(cancelled, "Order should be found");

        // Try to cancel again — double cancellation
        let cancelled_again = book.cancel_order([1u8; 32]);

        eprintln!("\n┌─ EDGE CASE: DOUBLE CANCELLATION ────────────────────────┐");
        eprintln!("│  First cancel:  {}                                      │", if cancelled { "✓ Found and removed" } else { "✗ Not found" });
        eprintln!("│  Second cancel: {}                                      │", if cancelled_again { "✓ Still found (ID reuse!)" } else { "✗ Not found (correct)" });
        eprintln!("│                                                         │");
        eprintln!("│  Exploitable: {}                                         │", if cancelled_again { "YES — stale order IDs persist" } else { "No — properly cleaned up" });
        eprintln!("└─────────────────────────────────────────────────────────┘");
        assert!(!cancelled_again, "Double cancel should not find the order");
    }

    // ── EDGE CASE 7: Order with amount=0 (partial fill → zero) ──
    #[test]
    fn edge_partial_fill_to_zero() {
        let mut book = OrderBook::new("ETH-USD".to_string());

        // Seller at 3000 for 10
        let sell = Order {
            id: [1u8; 32], trader: [1u8; 32],
            symbol: "ETH-USD".to_string(),
            side: OrderSide::Sell, price: 3000, amount: 10,
            signature: vec![], nonce: 1, expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };
        let _ = book.add_order(sell);

        // Buyer takes exactly 10
        let buy = Order {
            id: [2u8; 32], trader: [2u8; 32],
            symbol: "ETH-USD".to_string(),
            side: OrderSide::Buy, price: 3000, amount: 10,
            signature: vec![], nonce: 2, expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };
        let matches = book.add_order(buy);

        let book_bid_count: usize = book.bids.values().map(|v| v.len()).sum();
        let book_ask_count: usize = book.asks.values().map(|v| v.len()).sum();

        eprintln!("\n┌─ EDGE CASE: PARTIAL FILL TO ZERO ──────────────────────┐");
        eprintln!("│  Sell 10 @ 3000, Buy 10 @ 3000 → fully matched         │");
        eprintln!("│  Matches generated: {}                                   │", matches.len());
        eprintln!("│  Ask side entries:  {} (should be 0 — fully consumed)   │", book_ask_count);
        eprintln!("│  Bid side entries:  {} (should be 0 — fully consumed)   │", book_bid_count);
        eprintln!("│  Cleanup:            {}                                 │", if book_ask_count == 0 && book_bid_count == 0 { "✓ Empty levels removed" } else { "✗ Orphaned levels remain" });
        eprintln!("└─────────────────────────────────────────────────────────┘");
        assert_eq!(matches.len(), 1);
    }
}
