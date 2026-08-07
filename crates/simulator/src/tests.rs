#[cfg(test)]
mod tests {
    use crate::types::{Event, ScheduledEvent};
    use common::{NodeId, Order, OrderSide};
    use std::collections::BinaryHeap;

    #[test]
    fn test_event_queue_priority_sorting() {
        let order = Order {
            id: [0u8; 32],
            trader: [0u8; 32],
            symbol: "ETH-USD".to_string(),
            side: OrderSide::Buy,
            price: 3000,
            amount: 5,
            signature: Vec::new(),
            nonce: 0,
            expiry: 0,
        };

        let mut queue = BinaryHeap::new();
        queue.push(ScheduledEvent {
            time: 250.5,
            event: Event::OrderGenerated { order: order.clone(), source_node: NodeId(1) },
        });
        queue.push(ScheduledEvent {
            time: 50.2,
            event: Event::OrderGenerated { order: order.clone(), source_node: NodeId(2) },
        });
        queue.push(ScheduledEvent {
            time: 500.0,
            event: Event::OrderGenerated { order: order.clone(), source_node: NodeId(3) },
        });

        // Min-heap check: 50.2 should come out first
        let ev1 = queue.pop().unwrap();
        assert_eq!(ev1.time, 50.2);

        let ev2 = queue.pop().unwrap();
        assert_eq!(ev2.time, 250.5);

        let ev3 = queue.pop().unwrap();
        assert_eq!(ev3.time, 500.0);
    }
}
