use common::{FloodMessage, NodeId, Order, Region};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct Peer {
    pub id: NodeId,
    pub latency_ms: f64,
    pub last_heartbeat: f64,
    pub health_score: f64,
}

#[derive(Debug, Clone)]
pub struct RoutingTable {
    pub upstream_peers: Vec<Peer>,
    pub downstream_peers: Vec<Peer>,
    pub zone_peers: Vec<Peer>,
}

#[derive(Debug, Clone)]
pub struct FloodSchedule {
    pub slot_duration_ms: f64,
    pub max_hops: u8,
    pub retransmit_threshold_ms: f64,
    pub hop_delays: Vec<f64>,
}

impl Default for FloodSchedule {
    fn default() -> Self {
        Self {
            slot_duration_ms: 5.0,
            max_hops: 7,
            retransmit_threshold_ms: 10.0,
            // Pre-calculated or configured cumulative latency per hop
            hop_delays: vec![0.0, 15.0, 30.0, 45.0, 60.0, 75.0, 90.0, 105.0],
        }
    }
}

pub struct HeartbeatTracker {
    pub last_heartbeat: HashMap<NodeId, f64>,
    pub missed_count: HashMap<NodeId, u32>,
    pub max_missed: u32,
    pub heartbeat_interval: f64,
}

impl HeartbeatTracker {
    pub fn new(heartbeat_interval: f64, max_missed: u32) -> Self {
        Self {
            last_heartbeat: HashMap::new(),
            missed_count: HashMap::new(),
            max_missed,
            heartbeat_interval,
        }
    }

    pub fn on_heartbeat(&mut self, node_id: NodeId, current_time: f64) {
        self.last_heartbeat.insert(node_id, current_time);
        self.missed_count.insert(node_id, 0);
    }

    pub fn check_health(&mut self, current_time: f64) -> Vec<NodeId> {
        let mut dead_nodes = Vec::new();
        for (&node_id, &last_time) in &self.last_heartbeat {
            if current_time - last_time > self.heartbeat_interval * (self.max_missed as f64) {
                dead_nodes.push(node_id);
            }
        }
        for node_id in &dead_nodes {
            let count = self.missed_count.entry(*node_id).or_insert(0);
            *count += 1;
        }
        dead_nodes
    }
}

pub struct DeterministicFlood {
    pub node_id: NodeId,
    pub region: Region,
    pub routing_table: RoutingTable,
    pub schedule: FloodSchedule,
    pub received_cache: HashSet<[u8; 32]>,
    pub order_book_orders: Vec<Order>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FloodError {
    EarlyPacket,
    LatePacket,
    InvalidOrder,
    DuplicatePacket,
    MaxHopsReached,
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
        // 1. Check if we already processed this message
        if self.received_cache.contains(&msg.order.id) {
            return Err(FloodError::DuplicatePacket);
        }

        // 2. Validate timing (prevent future timestamps due to clock skew, and late packets)
        if current_time < msg.timestamp - self.schedule.retransmit_threshold_ms {
            return Err(FloodError::EarlyPacket);
        }

        // Check if packet is excessively late (e.g. over 250ms per hop + buffer)
        let max_allowed_delay = (msg.hop_count as f64) * 250.0 + 100.0;
        if current_time - msg.timestamp > max_allowed_delay {
            return Err(FloodError::LatePacket);
        }

        // 3. Mark as received and save
        self.received_cache.insert(msg.order.id);
        self.order_book_orders.push(msg.order.clone());

        // 4. Determine forward actions
        if msg.hop_count >= self.schedule.max_hops {
            return Err(FloodError::MaxHopsReached);
        }

        let mut forwards = Vec::new();
        // Forward to downstream peers that are not in the message's propagation path
        for peer in &self.routing_table.downstream_peers {
            if !msg.path.contains(&peer.id) && peer.id != self.node_id {
                let mut forward_msg = msg.clone();
                forward_msg.hop_count += 1;
                forward_msg.path.push(self.node_id);
                // The forward will be sent to the peer.
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
