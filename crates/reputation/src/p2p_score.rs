use crate::types::P2PMetrics;
use common::NodeId;
use std::collections::HashMap;

const WINDOW_SIZE: usize = 100;
const DECAY_FACTOR: f64 = 0.9;

pub struct P2PScoreEngine {
    score_history: HashMap<NodeId, Vec<f64>>,
    window_size: usize,
}

#[derive(Debug, Clone, Default)]
pub struct P2PScoreUpdate {
    pub echo_rtt_ms: Option<f64>,
    pub expected_echo_rtt_ms: Option<f64>,
    pub heartbeat_miss: bool,
    pub censorship_flag: bool,
    pub flood_relayed: bool,
    pub flood_dropped: bool,
}

impl P2PScoreEngine {
    pub fn new() -> Self {
        Self {
            score_history: HashMap::new(),
            window_size: WINDOW_SIZE,
        }
    }

    pub fn compute_p2p_score(&self, _node_id: NodeId, metrics: &P2PMetrics) -> f64 {
        let mut score = 0.0;
        let mut weight = 0.0;

        if metrics.heartbeat_miss_count > 0 {
            let miss_penalty =
                (1.0 - (metrics.heartbeat_miss_count as f64 / 10.0).clamp(0.0, 1.0)).max(0.0);
            score += miss_penalty * 0.3;
            weight += 0.3;
        } else {
            score += 1.0 * 0.3;
            weight += 0.3;
        }

        if metrics.censorship_flags > 0 {
            let flag_penalty =
                (1.0 - (metrics.censorship_flags as f64 / 5.0).clamp(0.0, 1.0)).max(0.0);
            score += flag_penalty * 0.3;
            weight += 0.3;
        } else {
            score += 1.0 * 0.3;
            weight += 0.3;
        }

        if metrics.echo_rtt_ms > 0.0 {
            let latency_score = (1.0 - (metrics.echo_rtt_ms / 500.0).clamp(0.0, 1.0)).max(0.0);
            score += latency_score * 0.2;
        } else {
            score += 0.5 * 0.2;
        }
        weight += 0.2;

        let total_relays = metrics.flood_relay_count + metrics.flood_drop_count;
        if total_relays > 0 {
            let relay_ratio = metrics.flood_relay_count as f64 / total_relays as f64;
            score += relay_ratio * 0.2;
        } else {
            score += 0.5 * 0.2;
        }
        weight += 0.2;

        if weight == 0.0 {
            return 0.5;
        }
        (score / weight).clamp(0.0, 1.0)
    }

    pub fn update_and_smooth(&mut self, node_id: NodeId, raw_score: f64) -> f64 {
        let entry = self.score_history.entry(node_id).or_insert_with(Vec::new);
        entry.push(raw_score);

        if entry.len() > self.window_size {
            entry.remove(0);
        }

        let mut weighted_sum = 0.0;
        let mut total_weight = 0.0;

        for (i, &s) in entry.iter().enumerate() {
            let weight = DECAY_FACTOR.powf((entry.len() - i) as f64);
            weighted_sum += s * weight;
            total_weight += weight;
        }

        if total_weight > 0.0 {
            weighted_sum / total_weight
        } else {
            raw_score
        }
    }

    pub fn reset_history(&mut self, node_id: NodeId) {
        self.score_history.remove(&node_id);
    }
}

impl Default for P2PScoreEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_perfect_node_scores_high() {
        let engine = P2PScoreEngine::new();
        let metrics = P2PMetrics {
            echo_rtt_ms: 10.0,
            heartbeat_miss_count: 0,
            censorship_flags: 0,
            flood_relay_count: 100,
            flood_drop_count: 0,
            last_heartbeat_time: 1.0,
            peer_verified: true,
        };
        let score = engine.compute_p2p_score(NodeId(1), &metrics);
        assert!(score > 0.8);
    }

    #[test]
    fn test_bad_node_scores_low() {
        let engine = P2PScoreEngine::new();
        let metrics = P2PMetrics {
            echo_rtt_ms: 1000.0,
            heartbeat_miss_count: 10,
            censorship_flags: 5,
            flood_relay_count: 1,
            flood_drop_count: 100,
            last_heartbeat_time: 1.0,
            peer_verified: false,
        };
        let score = engine.compute_p2p_score(NodeId(2), &metrics);
        assert!(score < 0.2);
    }

    #[test]
    fn test_smoothing_converges() {
        let mut engine = P2PScoreEngine::new();
        let initial = engine.update_and_smooth(NodeId(1), 0.0);
        assert_eq!(initial, 0.0);
        let after_good = engine.update_and_smooth(NodeId(1), 1.0);
        assert!(after_good > 0.0);
    }
}
