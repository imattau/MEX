use common::{FloodMessage, NodeId, Order};
use protocol::{FloodSchedule, RoutingTable};
use lru::LruCache;
use std::num::NonZeroUsize;

pub struct SimpleFlood {
    pub received_cache: LruCache<[u8; 32], ()>,
    pub order_book_orders: Vec<Order>,
}

impl SimpleFlood {
    pub fn new() -> Self {
        Self {
            received_cache: LruCache::new(NonZeroUsize::new(100_000).unwrap()),
            order_book_orders: Vec::new(),
        }
    }

    pub fn on_receive(
        &mut self,
        msg: FloodMessage,
        node_id: NodeId,
        routing: &RoutingTable,
        schedule: &FloodSchedule,
    ) -> Result<Vec<(NodeId, FloodMessage)>, ()> {
        if self.received_cache.contains(&msg.order.id) {
            return Err(());
        }

        if msg.order.amount == 0
            || msg.order.price == 0
            || msg.order.price > 1_000_000_000_000
        {
            return Err(());
        }

        if msg.hop_count >= schedule.max_hops {
            self.received_cache.put(msg.order.id, ());
            self.order_book_orders.push(msg.order);
            return Err(());
        }

        let order = msg.order.clone();
        self.received_cache.put(order.id, ());
        self.order_book_orders.push(order.clone());

        let mut forwards = Vec::new();
        for peer in &routing.downstream_peers {
            if msg.path.contains(&peer.id) || peer.id == node_id {
                continue;
            }
            let mut fwd = FloodMessage {
                order: order.clone(),
                hop_count: msg.hop_count + 1,
                path: msg.path.clone(),
                timestamp: msg.timestamp,
                source_region: msg.source_region,
            };
            fwd.path.push(node_id);
            forwards.push((peer.id, fwd));
        }

        Ok(forwards)
    }
}
