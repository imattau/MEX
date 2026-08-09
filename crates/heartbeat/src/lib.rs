use common::NodeId;
use std::collections::{HashMap, HashSet};

pub struct DeterministicHeartbeat {
    pub heartbeat_interval_ms: u64,
    pub max_missed: u8,
    pub last_heartbeats: HashMap<NodeId, u64>,
    pub missed_count: HashMap<NodeId, u8>,
    // Precomputed slot arrival times: NodeId -> Vec of timestamps
    pub expected_schedule: HashMap<NodeId, Vec<u64>>,
    pub unhealthy_nodes: HashSet<NodeId>,
}

impl DeterministicHeartbeat {
    pub fn new(
        peers: &[NodeId],
        base_time: u64,
        heartbeat_interval_ms: u64,
        max_missed: u8,
        zone_connectivity: &HashMap<(u32, u32), f64>,
        local_zone_id: u32,
        peer_zones: &HashMap<NodeId, u32>,
    ) -> Self {
        let mut expected_schedule = HashMap::new();

        for &peer in peers {
            let peer_zone = peer_zones.get(&peer).copied().unwrap_or(local_zone_id);
            let latency_ms = zone_connectivity
                .get(&(local_zone_id, peer_zone))
                .copied()
                .unwrap_or(5.0);

            // Precompute expected arrival times for the first 100 cycles
            let arrival_times: Vec<u64> = (0..100)
                .map(|i| {
                    let scheduled_send = base_time + (i as u64 * heartbeat_interval_ms);
                    scheduled_send + latency_ms as u64
                })
                .collect();

            expected_schedule.insert(peer, arrival_times);
        }

        Self {
            heartbeat_interval_ms,
            max_missed,
            last_heartbeats: HashMap::new(),
            missed_count: HashMap::new(),
            expected_schedule,
            unhealthy_nodes: HashSet::new(),
        }
    }

    pub fn on_heartbeat(&mut self, from: NodeId, received_at: u64, seq: usize) {
        if let Some(expected_times) = self.expected_schedule.get(&from) {
            let expected_time = expected_times[seq % expected_times.len()];

            // Tolerance window for synchronization checks (e.g. 5ms)
            let tolerance = 5;
            let diff = (received_at as i64 - expected_time as i64).abs();

            if diff > tolerance {
                // Clock skew or network jitter violation
                self.unhealthy_nodes.insert(from);
                return;
            }

            self.last_heartbeats.insert(from, received_at);
            self.missed_count.insert(from, 0);
        }
    }

    pub fn check_health(&mut self, current_time: u64, current_seq: usize) -> Vec<NodeId> {
        let mut dead_nodes = Vec::new();

        for (&peer, expected_times) in &self.expected_schedule {
            let last_seen = self.last_heartbeats.get(&peer).copied().unwrap_or(0);
            let expected_next = expected_times[current_seq % expected_times.len()];

            if current_time > expected_next && last_seen < expected_next {
                let elapsed_since_expected = current_time - expected_next;
                let missed = (elapsed_since_expected / self.heartbeat_interval_ms) as u8;

                self.missed_count.insert(peer, missed);

                if missed >= self.max_missed {
                    dead_nodes.push(peer);
                    self.unhealthy_nodes.insert(peer);
                }
            }
        }

        dead_nodes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heartbeat_scheduling_and_skew() {
        let peers = vec![NodeId(1), NodeId(2)];
        let mut peer_zones = HashMap::new();
        peer_zones.insert(NodeId(1), 1); // Local zone
        peer_zones.insert(NodeId(2), 2); // Remote zone

        let mut zone_connectivity = HashMap::new();
        zone_connectivity.insert((1, 1), 5.0); // 5ms intra-zone latency
        zone_connectivity.insert((1, 2), 80.0); // 80ms inter-zone latency

        let base_time = 1000;
        let mut tracker = DeterministicHeartbeat::new(
            &peers,
            base_time,
            100, // 100ms interval
            3,   // 3 missed threshold
            &zone_connectivity,
            1,
            &peer_zones,
        );

        // Expected arrival for Node 1, seq 0: 1000 + 0 + 5 = 1005ms
        // 1. Success on correct timing
        tracker.on_heartbeat(NodeId(1), 1006, 0); // Within 5ms tolerance
        assert!(!tracker.unhealthy_nodes.contains(&NodeId(1)));

        // Expected arrival for Node 2, seq 0: 1000 + 0 + 80 = 1080ms
        // 2. Failure on skew timing (e.g. arriving too early at 1020ms)
        tracker.on_heartbeat(NodeId(2), 1020, 0);
        assert!(tracker.unhealthy_nodes.contains(&NodeId(2)));
    }

    #[test]
    fn test_heartbeat_dead_nodes() {
        let peers = vec![NodeId(1)];
        let mut peer_zones = HashMap::new();
        peer_zones.insert(NodeId(1), 1);
        let mut zone_connectivity = HashMap::new();
        zone_connectivity.insert((1, 1), 5.0);

        let mut tracker =
            DeterministicHeartbeat::new(&peers, 1000, 100, 3, &zone_connectivity, 1, &peer_zones);

        // Advance virtual time to 1350ms (Seq 0 expected at 1005, Seq 1 at 1105, Seq 2 at 1205)
        // Deadline for Seq 2 with 3 missed intervals is: 1205 + 300 = 1505.
        // Let's check health at 1550ms without any heartbeats received.
        let dead = tracker.check_health(1550, 2);
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0], NodeId(1));
    }
}
