use crate::types::{FloodError, FloodSchedule, RoutingTable};
use common::{FloodMessage, NodeId, Order, Region};
use lru::LruCache;
use std::num::NonZeroUsize;
use validation::OrderValidator;

const CACHE_SIZE: usize = 100_000;

pub struct DeterministicFlood {
    pub node_id: NodeId,
    pub region: Region,
    pub routing_table: RoutingTable,
    pub schedule: FloodSchedule,
    // Was LruCache<[u8; 32], ()> -- pure membership, no memory of WHO an
    // order arrived from or WHEN, beyond the first sighting. A second
    // arrival of the same order via a different upstream path used to be
    // silently discarded as FloodError::DuplicatePacket, throwing away
    // exactly the redundant, independent evidence a real mesh (multiple
    // paths from origin to any node) could use to cross-check one relay's
    // claimed timing against what everyone else saw. Now records every
    // arrival (from, current_time), not just the first -- see
    // arrivals_for and on_receive's docs.
    pub received_cache: LruCache<[u8; 32], Vec<(NodeId, f64)>>,
    pub order_book_orders: Vec<Order>,
    pub sig_validator: OrderValidator,
}

impl DeterministicFlood {
    pub fn new(node_id: NodeId, region: Region, routing_table: RoutingTable, schedule: FloodSchedule) -> Self {
        Self {
            node_id,
            region,
            routing_table,
            schedule,
            received_cache: LruCache::new(NonZeroUsize::new(CACHE_SIZE).unwrap()),
            order_book_orders: Vec::new(),
            sig_validator: OrderValidator::new(10_000),
        }
    }

    // `from` is who this specific arrival came from (the immediate
    // sender, not the order's ultimate origin) -- needed so a duplicate
    // arrival's evidence (who else forwarded this, and when) can be
    // recorded instead of discarded. See received_cache's docs.
    pub fn on_receive(
        &mut self,
        msg: FloodMessage,
        from: NodeId,
        current_time: f64,
    ) -> Result<Vec<(NodeId, FloodMessage)>, FloodError> {
        if let Some(arrivals) = self.received_cache.get_mut(&msg.order.id) {
            arrivals.push((from, current_time));
            return Err(FloodError::DuplicatePacket);
        }

        if !self.sig_validator.validate_order(&msg.order) {
            return Err(FloodError::InvalidOrder);
        }

        if current_time < msg.timestamp - self.schedule.retransmit_threshold_ms {
            return Err(FloodError::EarlyPacket);
        }

        let max_allowed_delay = (msg.hop_count as f64) * 250.0 + 100.0;
        if current_time - msg.timestamp > max_allowed_delay {
            return Err(FloodError::LatePacket);
        }

        self.received_cache.put(msg.order.id, vec![(from, current_time)]);
        self.order_book_orders.push(msg.order.clone());

        if msg.hop_count >= self.schedule.max_hops {
            return Err(FloodError::MaxHopsReached);
        }

        let mut forwards = Vec::new();
        for peer in &self.routing_table.downstream_peers {
            if !msg.path.contains(&peer.id) && peer.id != self.node_id {
                let mut forward_msg = msg.clone();
                forward_msg.hop_count += 1;
                forward_msg.path.push(self.node_id);
                forwards.push((peer.id, forward_msg));
            }
        }

        Ok(forwards)
    }

    // Every independently-recorded arrival of `order_id` this node has
    // seen -- the first (which passed full validation and was forwarded)
    // plus every later duplicate (which wasn't forwarded again, but whose
    // timing is still real evidence of when THAT peer had it). Used by
    // Stage 2's cross-witness consistency checks. &mut self because
    // LruCache::get touches recency ordering, same as everywhere else
    // this cache is read.
    pub fn arrivals_for(&mut self, order_id: &[u8; 32]) -> Option<&Vec<(NodeId, f64)>> {
        self.received_cache.get(order_id)
    }

    #[allow(dead_code)]
    fn calculate_arrival_time(&self, sent_at: f64, hops: u8) -> f64 {
        let index = hops as usize;
        let base_delay = if index < self.schedule.hop_delays.len() {
            self.schedule.hop_delays[index]
        } else {
            self.schedule.hop_delays.last().copied().unwrap_or(0.0)
        };
        let slot_delay = (hops as f64) * self.schedule.slot_duration_ms;
        sent_at + base_delay + slot_delay
    }
}
