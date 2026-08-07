#[cfg(test)]
mod tests {
    use crate::flood::DeterministicFlood;
    use crate::heartbeat::HeartbeatTracker;
    use crate::types::{FloodError, FloodSchedule, Peer, RoutingTable};
    use common::{FloodMessage, NodeId, Order, OrderSide, Region, SettlementPreference, SettlementRequester};
    use ed25519_dalek::{Signer, SigningKey};

    fn make_signed_order(id: u8) -> Order {
        let mut csprng = rand::thread_rng();
        let sk = SigningKey::generate(&mut csprng);
        let pk = sk.verifying_key().to_bytes();
        let mut order_id = [0u8; 32];
        order_id[0] = id;
        let msg = Order::serialize_for_signing(&order_id, &pk, "ETH-USD", 3000, 5, id as u64, 0);
        let order = Order {
            id: order_id,
            trader: pk,
            symbol: "ETH-USD".to_string(),
            side: OrderSide::Buy,
            price: 3000,
            amount: 5,
            signature: sk.sign(&msg).to_vec(),
            nonce: id as u64,
            expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };
        order
    }

    trait OrderSigning {
        fn serialize_for_signing(
            id: &[u8; 32], trader: &[u8; 32], symbol: &str,
            price: u64, amount: u64, nonce: u64, expiry: u64,
        ) -> Vec<u8>;
    }

    impl OrderSigning for Order {
        fn serialize_for_signing(
            id: &[u8; 32], trader: &[u8; 32], symbol: &str,
            price: u64, amount: u64, nonce: u64, expiry: u64,
        ) -> Vec<u8> {
            let mut msg = Vec::new();
            msg.extend_from_slice(id);
            msg.extend_from_slice(trader);
            msg.extend_from_slice(symbol.as_bytes());
            msg.extend_from_slice(&price.to_be_bytes());
            msg.extend_from_slice(&amount.to_be_bytes());
            msg.extend_from_slice(&nonce.to_be_bytes());
            msg.extend_from_slice(&expiry.to_be_bytes());
            msg
        }
    }

    #[test]
    fn test_flood_timing_and_window_validation() {
        let routing_table = RoutingTable {
            upstream_peers: Vec::new(),
            downstream_peers: vec![Peer {
                id: NodeId(1),
                latency_ms: 10.0,
                last_heartbeat: 0.0,
                health_score: 1.0,
            }],
            zone_peers: Vec::new(),
        };

        let mut flood = DeterministicFlood::new(
            NodeId(0),
            Region::UsEast1,
            routing_table,
            FloodSchedule::default(),
        );

        let order = make_signed_order(1);

        // 1. Success validation
        let msg = FloodMessage {
            order: order.clone(),
            hop_count: 0,
            path: vec![NodeId(2)],
            timestamp: 100.0,
            source_region: Region::UsEast1,
        };
        let res = flood.on_receive(msg.clone(), 105.0);
        assert!(res.is_ok());
        let forwards = res.unwrap();
        assert_eq!(forwards.len(), 1);
        assert_eq!(forwards[0].0, NodeId(1));

        // 2. Reject duplicate packet
        let res_dup = flood.on_receive(msg.clone(), 106.0);
        assert_eq!(res_dup.unwrap_err(), FloodError::DuplicatePacket);

        // 3. Reject early packet (future timestamp)
        let order_2 = make_signed_order(2);
        let msg_early = FloodMessage {
            order: order_2.clone(),
            hop_count: 0,
            path: vec![NodeId(2)],
            timestamp: 200.0,
            source_region: Region::UsEast1,
        };
        let res_early = flood.on_receive(msg_early, 180.0);
        assert_eq!(res_early.unwrap_err(), FloodError::EarlyPacket);

        // 4. Reject late packet
        let order_3 = make_signed_order(3);
        let msg_late = FloodMessage {
            order: order_3.clone(),
            hop_count: 1,
            path: vec![NodeId(2)],
            timestamp: 200.0,
            source_region: Region::UsEast1,
        };
        let res_late = flood.on_receive(msg_late, 600.0);
        assert_eq!(res_late.unwrap_err(), FloodError::LatePacket);
    }

    #[test]
    fn test_heartbeat_timeout_tracking() {
        let mut tracker = HeartbeatTracker::new(10.0, 3);

        tracker.on_heartbeat(NodeId(1), 10.0);
        tracker.on_heartbeat(NodeId(2), 10.0);

        let dead = tracker.check_health(20.0);
        assert!(dead.is_empty());

        let dead = tracker.check_health(50.0);
        assert_eq!(dead.len(), 2);
        assert!(dead.contains(&NodeId(1)));
        assert!(dead.contains(&NodeId(2)));
    }
}
