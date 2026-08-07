use crate::types::{FloodError, FloodSchedule, RoutingTable};
use common::{FloodMessage, NodeId, Order, Region};
use std::collections::HashSet;

pub struct DeterministicFlood {
    pub node_id: NodeId,
    pub region: Region,
    pub routing_table: RoutingTable,
    pub schedule: FloodSchedule,
    pub received_cache: HashSet<[u8; 32]>,
    pub order_book_orders: Vec<Order>,
}

impl DeterministicFlood {
    pub fn new(node_id: NodeId, region: Region, routing_table: RoutingTable, schedule: FloodSchedule) -> Self {
        Self {
            node_id,
            region,
            routing_table,
            schedule,
            received_cache: HashSet::new(),
            order_book_orders: Vec::new(),
        }
    }

    pub fn on_receive(
        &mut self,
        msg: FloodMessage,
        current_time: f64,
    ) -> Result<Vec<(NodeId, FloodMessage)>, FloodError> {
        if self.received_cache.contains(&msg.order.id) {
            return Err(FloodError::DuplicatePacket);
        }

        if current_time < msg.timestamp - self.schedule.retransmit_threshold_ms {
            return Err(FloodError::EarlyPacket);
        }

        let max_allowed_delay = (msg.hop_count as f64) * 250.0 + 100.0;
        if current_time - msg.timestamp > max_allowed_delay {
            return Err(FloodError::LatePacket);
        }

        self.received_cache.insert(msg.order.id);
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
