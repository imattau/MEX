#[cfg(test)]
mod tests {
    use crate::flood::DeterministicFlood;
    use crate::heartbeat::HeartbeatTracker;
    use crate::types::{FloodError, FloodSchedule, Peer, RoutingTable};
    use common::{FloodMessage, NodeId, Order, OrderSide, Region};

    fn test_order(id: u8) -> Order {
        let mut order_id = [0u8; 32];
        order_id[0] = id;
        Order {
            id: order_id,
            trader: [0u8; 32],
            symbol: "ETH-USD".to_string(),
            side: OrderSide::Buy,
            price: 3000,
            amount: 5,
            signature: Vec::new(),
            nonce: id as u64,
            expiry: 0,
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

        let order = test_order(1);

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
        let order_2 = test_order(2);
        let msg_early = FloodMessage {
            order: order_2.clone(),
            hop_count: 0,
            path: vec![NodeId(2)],
            timestamp: 200.0,
            source_region: Region::UsEast1,
        };
        let res_early = flood.on_receive(msg_early, 180.0); // 20ms before threshold -> rejected
        assert_eq!(res_early.unwrap_err(), FloodError::EarlyPacket);

        // 4. Reject late packet
        let order_3 = test_order(3);
        let msg_late = FloodMessage {
            order: order_3.clone(),
            hop_count: 1,
            path: vec![NodeId(2)],
            timestamp: 200.0,
            source_region: Region::UsEast1,
        };
        let res_late = flood.on_receive(msg_late, 600.0); // 400ms delay (> max 350ms) -> rejected
        assert_eq!(res_late.unwrap_err(), FloodError::LatePacket);
    }

    #[test]
    fn test_heartbeat_timeout_tracking() {
        let mut tracker = HeartbeatTracker::new(10.0, 3); // 10ms interval, 3 missed limit

        tracker.on_heartbeat(NodeId(1), 10.0);
        tracker.on_heartbeat(NodeId(2), 10.0);

        // Checks at 20ms (interval is 10ms, max_missed is 3, i.e. limit is 30ms elapsed, so 10 + 30 = 40ms threshold)
        let dead = tracker.check_health(20.0);
        assert!(dead.is_empty());

        // Checks at 50ms (elapsed is 40ms > 30ms limit) -> Node 1 and Node 2 are dead
        let dead = tracker.check_health(50.0);
        assert_eq!(dead.len(), 2);
        assert!(dead.contains(&NodeId(1)));
        assert!(dead.contains(&NodeId(2)));
    }
}
