use common::{FloodMessage, NodeId, Order, Region};
use serde::Serialize;
use std::cmp::Ordering;

#[derive(Debug, Clone)]
pub enum Event {
    OrderGenerated {
        order: Order,
        source_node: NodeId,
    },
    PacketDeliver {
        to_node: NodeId,
        msg: FloodMessage,
    },
    NodeStatusChange {
        node_id: NodeId,
        online: bool,
    },
}

#[derive(Debug, Clone)]
pub struct ScheduledEvent {
    pub time: f64,
    pub event: Event,
}

impl PartialEq for ScheduledEvent {
    fn eq(&self, other: &Self) -> bool {
        self.time == other.time
    }
}

impl Eq for ScheduledEvent {}

impl PartialOrd for ScheduledEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScheduledEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        // Min-heap behavior: smaller time comes first
        other.time.partial_cmp(&self.time).unwrap_or(Ordering::Equal)
    }
}

pub struct NodeInfo {
    pub id: NodeId,
    pub region: Region,
    pub online: bool,
}

#[derive(Serialize)]
pub struct Measurement {
    pub order_id: String,
    pub latency_ms: f64,
    pub hops: u8,
    pub source_region: String,
    pub dest_region: String,
}

#[derive(Serialize)]
pub struct SimulationResultJson {
    pub scenario: String,
    pub total_orders_injected: usize,
    pub total_deliveries: usize,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_9_latency_ms: f64,
    pub t_max_ms: f64,
    pub verified: bool,
}
