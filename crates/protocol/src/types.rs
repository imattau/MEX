use common::NodeId;

#[derive(Debug, Clone, PartialEq)]
pub struct Peer {
    pub id: NodeId,
    pub latency_ms: f64,
    pub last_heartbeat: f64,
    pub health_score: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RoutingTable {
    pub upstream_peers: Vec<Peer>,
    pub downstream_peers: Vec<Peer>,
    pub zone_peers: Vec<Peer>,
}

#[derive(Debug, Clone, PartialEq)]
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
            hop_delays: vec![0.0, 15.0, 30.0, 45.0, 60.0, 75.0, 90.0, 105.0],
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum FloodError {
    EarlyPacket,
    LatePacket,
    InvalidOrder,
    DuplicatePacket,
    MaxHopsReached,
}
