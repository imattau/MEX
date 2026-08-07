use common::NodeId;
use std::collections::HashMap;

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
