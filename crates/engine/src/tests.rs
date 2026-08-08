#[cfg(test)]
mod tests {
    use crate::types::OrderBook;
    use common::{Order, OrderSide, SettlementPreference, SettlementRequester};

    fn create_test_order(id: u8, side: OrderSide, price: u64, amount: u64) -> Order {
        let mut order_id = [0u8; 32];
        order_id[0] = id;
        let mut trader = [0u8; 32];
        trader[0] = id;
        Order {
            id: order_id,
            trader,
            symbol: "ETH-USD".to_string(),
            side,
            price,
            amount,
            signature: Vec::new(),
            nonce: id as u64,
            expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        }
    }

    // The actual point of wiring FeeCalculator in: an OrderBook configured
    // with a non-default calculator must charge a genuinely different fee
    // than the old fixed 5/15/50 bps schedule, not silently ignore it.
    #[test]
    fn test_configured_fee_calculator_changes_match_fee() {
        let mut default_book = OrderBook::new("ETH-USD".to_string());
        default_book.add_order(create_test_order(1, OrderSide::Buy, 3000, 10));
        let default_matches = default_book.add_order(create_test_order(2, OrderSide::Sell, 3000, 10));
        assert_eq!(default_matches[0].fee_basis_points, 5, "default calculator must match the old static Standard-tier rate");

        let mut configured_book = OrderBook::new("ETH-USD".to_string());
        // 2x the baseline gas price, no batching discount, no volatility --
        // gas_multiplier alone should exactly double the Standard rate.
        configured_book.set_fee_calculator(common::FeeCalculator::new(100, 0.0, 0.0));
        configured_book.add_order(create_test_order(3, OrderSide::Buy, 3000, 10));
        let configured_matches = configured_book.add_order(create_test_order(4, OrderSide::Sell, 3000, 10));
        assert_eq!(configured_matches[0].fee_basis_points, 10, "2x gas price must double the fee rate");
        assert_ne!(
            configured_matches[0].fee_basis_points, default_matches[0].fee_basis_points,
            "a configured FeeCalculator must actually change the charged fee, not be silently ignored"
        );
    }

    #[test]
    fn test_empty_book_add() {
        let mut book = OrderBook::new("ETH-USD".to_string());
        let buy = create_test_order(1, OrderSide::Buy, 3000, 10);
        let matches = book.add_order(buy);
        assert!(matches.is_empty());
        assert_eq!(book.bids.get(&3000).unwrap().len(), 1);
    }

    #[test]
    fn test_exact_match() {
        let mut book = OrderBook::new("ETH-USD".to_string());
        let buy = create_test_order(1, OrderSide::Buy, 3000, 10);
        book.add_order(buy);

        let sell = create_test_order(2, OrderSide::Sell, 3000, 10);
        let matches = book.add_order(sell);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].price, 3000);
        assert_eq!(matches[0].amount, 10);
        assert_eq!(matches[0].maker_order_id[0], 1);
        assert_eq!(matches[0].taker_order_id[0], 2);
        assert!(book.bids.is_empty());
        assert!(book.asks.is_empty());
    }

    #[test]
    fn test_partial_match() {
        let mut book = OrderBook::new("ETH-USD".to_string());
        let buy = create_test_order(1, OrderSide::Buy, 3000, 10);
        book.add_order(buy);

        let sell = create_test_order(2, OrderSide::Sell, 3000, 4);
        let matches = book.add_order(sell);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].amount, 4);
        assert_eq!(book.bids.get(&3000).unwrap()[0].amount, 6);
    }

    #[test]
    fn test_price_time_priority() {
        let mut book = OrderBook::new("ETH-USD".to_string());
        book.add_order(create_test_order(1, OrderSide::Buy, 3000, 5));
        book.add_order(create_test_order(2, OrderSide::Buy, 3000, 5));
        book.add_order(create_test_order(3, OrderSide::Buy, 3005, 5));

        let sell = create_test_order(4, OrderSide::Sell, 3000, 12);
        let matches = book.add_order(sell);

        assert_eq!(matches.len(), 3);
        assert_eq!(matches[0].maker_order_id[0], 3);
        assert_eq!(matches[0].amount, 5);

        assert_eq!(matches[1].maker_order_id[0], 1);
        assert_eq!(matches[1].amount, 5);

        assert_eq!(matches[2].maker_order_id[0], 2);
        assert_eq!(matches[2].amount, 2);

        assert_eq!(book.bids.get(&3000).unwrap()[0].amount, 3);
    }

    #[test]
    fn test_self_trade_preserves_amounts() {
        let mut book = OrderBook::new("ETH-USD".to_string());
        let mut trader = [0u8; 32];
        trader[0] = 99;

        let sell = Order {
            id: [1u8; 32],
            trader,
            symbol: "ETH-USD".to_string(),
            side: OrderSide::Sell,
            price: 3000,
            amount: 10,
            signature: Vec::new(),
            nonce: 1,
            expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };
        book.add_order(sell);
        assert_eq!(book.asks.get(&3000).unwrap()[0].amount, 10);

        let buy = Order {
            id: [2u8; 32],
            trader,
            symbol: "ETH-USD".to_string(),
            side: OrderSide::Buy,
            price: 3000,
            amount: 10,
            signature: Vec::new(),
            nonce: 2,
            expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };
        let matches = book.add_order(buy);

        assert!(matches.is_empty(), "Self-trade should produce no matches");
        assert_eq!(book.asks.get(&3000).unwrap()[0].amount, 10, "Maker amount should be preserved");
        assert_eq!(book.bids.get(&3000).unwrap()[0].amount, 10, "Taker amount should be preserved");
    }

    #[test]
    fn test_self_trade_partial_preserves_amounts() {
        let mut book = OrderBook::new("ETH-USD".to_string());
        let mut trader_a = [0u8; 32];
        trader_a[0] = 1;
        let mut trader_b = [0u8; 32];
        trader_b[0] = 2;

        let sell_a = Order {
            id: [1u8; 32],
            trader: trader_a,
            symbol: "ETH-USD".to_string(),
            side: OrderSide::Sell,
            price: 3000,
            amount: 5,
            signature: Vec::new(),
            nonce: 1,
            expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };
        let sell_b = Order {
            id: [2u8; 32],
            trader: trader_b,
            symbol: "ETH-USD".to_string(),
            side: OrderSide::Sell,
            price: 3000,
            amount: 5,
            signature: Vec::new(),
            nonce: 2,
            expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };
        book.add_order(sell_a);
        book.add_order(sell_b);

        let buy_a = Order {
            id: [3u8; 32],
            trader: trader_a,
            symbol: "ETH-USD".to_string(),
            side: OrderSide::Buy,
            price: 3000,
            amount: 10,
            signature: Vec::new(),
            nonce: 3,
            expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };
        let matches = book.add_order(buy_a);

        assert_eq!(matches.len(), 1, "Should only match against trader_b's order");
        assert_eq!(matches[0].maker_trader, trader_b);
        assert_eq!(matches[0].amount, 5);
        assert_eq!(book.asks.get(&3000).unwrap()[0].amount, 5, "Trader A's sell should be preserved");
        assert_eq!(book.bids.get(&3000).unwrap()[0].amount, 5, "Remaining buy amount should rest");
    }

    #[test]
    fn test_order_cancellation() {
        let mut book = OrderBook::new("ETH-USD".to_string());
        let buy = create_test_order(5, OrderSide::Buy, 3000, 10);
        book.add_order(buy);
        assert_eq!(book.bids.get(&3000).unwrap().len(), 1);

        let mut cancel_id = [0u8; 32];
        cancel_id[0] = 5;
        let cancelled = book.cancel_order(cancel_id);
        assert!(cancelled);
        assert_eq!(book.bids.get(&3000).unwrap().len(), 0);

        let cancel_non_existent = book.cancel_order([99u8; 32]);
        assert!(!cancel_non_existent);
    }

    #[test]
    fn test_match_has_no_assigned_node_by_default() {
        let mut book = OrderBook::new("ETH-USD".to_string());
        book.add_order(create_test_order(1, OrderSide::Buy, 3000, 10));
        let matches = book.add_order(create_test_order(2, OrderSide::Sell, 3000, 10));

        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].assigned_node, [0u8; 32],
            "with no active nodes configured, a match must get the zero-pubkey sentinel, not a fabricated node"
        );
    }

    #[test]
    fn test_assigned_node_round_robins_across_matches() {
        let mut book = OrderBook::new("ETH-USD".to_string());
        let node_a = [1u8; 32];
        let node_b = [2u8; 32];
        book.set_active_nodes(vec![node_a, node_b]);

        // One resting buy order per match, so each add_order call produces
        // exactly one Match and therefore exactly one assign_node() call.
        book.add_order(create_test_order(1, OrderSide::Buy, 3000, 10));
        let m1 = book.add_order(create_test_order(2, OrderSide::Sell, 3000, 10));
        book.add_order(create_test_order(3, OrderSide::Buy, 3000, 10));
        let m2 = book.add_order(create_test_order(4, OrderSide::Sell, 3000, 10));
        book.add_order(create_test_order(5, OrderSide::Buy, 3000, 10));
        let m3 = book.add_order(create_test_order(6, OrderSide::Sell, 3000, 10));

        assert_eq!(m1[0].assigned_node, node_a);
        assert_eq!(m2[0].assigned_node, node_b);
        assert_eq!(m3[0].assigned_node, node_a, "cursor must wrap back to the first node");
    }

    #[test]
    fn test_set_active_nodes_resets_round_robin_cursor() {
        let mut book = OrderBook::new("ETH-USD".to_string());
        book.set_active_nodes(vec![[1u8; 32], [2u8; 32]]);

        book.add_order(create_test_order(1, OrderSide::Buy, 3000, 10));
        let m1 = book.add_order(create_test_order(2, OrderSide::Sell, 3000, 10));
        assert_eq!(m1[0].assigned_node, [1u8; 32]);

        // Reconfiguring the active set mid-flight must not leave the cursor
        // pointing at a stale, out-of-range, or otherwise meaningless
        // position relative to the new list.
        book.set_active_nodes(vec![[9u8; 32]]);
        book.add_order(create_test_order(3, OrderSide::Buy, 3000, 10));
        let m2 = book.add_order(create_test_order(4, OrderSide::Sell, 3000, 10));
        assert_eq!(m2[0].assigned_node, [9u8; 32]);
    }

    #[test]
    fn test_multiple_matches_in_one_add_order_call_each_get_a_turn() {
        // A single incoming order can match against several resting orders
        // in one add_order call, producing multiple Matches at once -- each
        // one must still get its own turn in the round-robin, not all get
        // the same node from a cursor that only advances once per call.
        let mut book = OrderBook::new("ETH-USD".to_string());
        let node_a = [1u8; 32];
        let node_b = [2u8; 32];
        book.set_active_nodes(vec![node_a, node_b]);

        book.add_order(create_test_order(1, OrderSide::Sell, 3000, 5));
        book.add_order(create_test_order(2, OrderSide::Sell, 3000, 5));

        let matches = book.add_order(create_test_order(3, OrderSide::Buy, 3000, 10));

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].assigned_node, node_a);
        assert_eq!(matches[1].assigned_node, node_b);
    }
}
