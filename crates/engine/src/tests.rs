#[cfg(test)]
mod tests {
    use crate::types::OrderBook;
    use common::{Order, OrderSide};

    fn create_test_order(id: u8, side: OrderSide, price: u64, amount: u64) -> Order {
        let mut order_id = [0u8; 32];
        order_id[0] = id;
        Order {
            id: order_id,
            trader: [0u8; 32],
            symbol: "ETH-USD".to_string(),
            side,
            price,
            amount,
            signature: Vec::new(),
            nonce: id as u64,
            expiry: 0,
        }
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
}
