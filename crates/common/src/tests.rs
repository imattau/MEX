#[cfg(test)]
mod tests {
    use crate::types::{
        FloodMessage, NodeId, Order, OrderSide, Region, SettlementPreference, SettlementRequester,
    };

    #[test]
    fn test_order_serialization() {
        let order = Order {
            id: [7u8; 32],
            trader: [9u8; 32],
            symbol: "BTC-USD".to_string(),
            side: OrderSide::Sell,
            price: 55000,
            amount: 2,
            signature: vec![1, 2, 3],
            nonce: 1001,
            expiry: 2000,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };

        let serialized = serde_json::to_string(&order).unwrap();
        let deserialized: Order = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.id, order.id);
        assert_eq!(deserialized.trader, order.trader);
        assert_eq!(deserialized.symbol, order.symbol);
        assert_eq!(deserialized.side, order.side);
        assert_eq!(deserialized.price, order.price);
        assert_eq!(deserialized.amount, order.amount);
        assert_eq!(deserialized.signature, order.signature);
        assert_eq!(deserialized.nonce, order.nonce);
        assert_eq!(deserialized.expiry, order.expiry);
    }

    #[test]
    fn test_flood_message_serialization() {
        let order = Order {
            id: [1u8; 32],
            trader: [2u8; 32],
            symbol: "ETH-USD".to_string(),
            side: OrderSide::Buy,
            price: 3000,
            amount: 10,
            signature: vec![0xAA; 64],
            nonce: 42,
            expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };

        let msg = FloodMessage {
            order,
            hop_count: 2,
            path: vec![NodeId(0), NodeId(1)],
            timestamp: 1234.56,
            source_region: Region::EuWest1,
        };

        let serialized = serde_json::to_string(&msg).unwrap();
        let deserialized: FloodMessage = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.hop_count, 2);
        assert_eq!(deserialized.path.len(), 2);
        assert_eq!(deserialized.path[0], NodeId(0));
        assert_eq!(deserialized.path[1], NodeId(1));
        assert_eq!(deserialized.timestamp, 1234.56);
        assert_eq!(deserialized.source_region, Region::EuWest1);
    }
}
