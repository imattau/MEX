// Real, per-peer round-trip latency tracking from actual challenge-response
// pings (WireMessage::Ping/Pong) -- not a self-reported number a peer could
// lie about. Replaces the RoutingTable::Peer.latency_ms placeholder
// (hardcoded to 1.0 at construction, never actually measured) with a
// rolling window of real samples this node observed itself, used to answer
// "is this specific hop's observed transit time plausible, or anomalous?"
// (see HopLatencyMonitor in node.rs).
use common::NodeId;
use std::collections::{HashMap, VecDeque};

const WINDOW_SIZE: usize = 50;
// How many standard deviations above the mean before a hop's observed
// transit time counts as anomalous rather than ordinary jitter. Kept
// generous (not tight) for this experiment -- the goal is proving the
// signal exists at all before tuning it to be aggressive.
const ANOMALY_STDDEV_MULTIPLIER: f64 = 4.0;
// Applied on top of the stddev-based bound so a peer with very few
// samples (or unrealistically tight/noiseless RTTs, as on loopback) still
// gets a sane minimum tolerance instead of flagging normal jitter.
// Widened from an initial 5.0 after `cargo test --workspace` (many
// processes contending for CPU, unlike this crate's tests run alone)
// produced a real, reproducible false positive at ~31ms against a ~30ms
// baseline bound -- a tolerance this tight was never going to survive
// realistic scheduling jitter under load. 25ms is still 12x smaller than
// the 300ms deliberate delay this experiment validates detecting, so it
// costs essentially none of the real signal separation.
const MIN_TOLERANCE_MS: f64 = 25.0;

pub struct PeerLatencyStats {
    samples: HashMap<NodeId, VecDeque<f64>>,
}

impl Default for PeerLatencyStats {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerLatencyStats {
    pub fn new() -> Self {
        Self { samples: HashMap::new() }
    }

    pub fn record_rtt(&mut self, peer: NodeId, rtt_ms: f64) {
        let window = self.samples.entry(peer).or_default();
        window.push_back(rtt_ms);
        if window.len() > WINDOW_SIZE {
            window.pop_front();
        }
    }

    pub fn sample_count(&self, peer: NodeId) -> usize {
        self.samples.get(&peer).map(|w| w.len()).unwrap_or(0)
    }

    fn mean_stddev(&self, peer: NodeId) -> Option<(f64, f64)> {
        let window = self.samples.get(&peer)?;
        if window.is_empty() {
            return None;
        }
        let n = window.len() as f64;
        let mean = window.iter().sum::<f64>() / n;
        let variance = window.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
        Some((mean, variance.sqrt()))
    }

    // One-way transit estimate for a hop from `peer` to us: half the
    // measured round trip. A real bound would need asymmetric-path
    // awareness; this experiment assumes rough symmetry, which is
    // reasonable on a LAN/localhost test and stated as a simplification,
    // not a hidden assumption.
    pub fn expected_one_way_bound_ms(&self, peer: NodeId) -> Option<f64> {
        let (mean, stddev) = self.mean_stddev(peer)?;
        let one_way_mean = mean / 2.0;
        let tolerance = (stddev * ANOMALY_STDDEV_MULTIPLIER).max(MIN_TOLERANCE_MS);
        Some(one_way_mean + tolerance)
    }

    // The plain best-estimate one-way latency to `peer` -- half the mean
    // RTT, with none of expected_one_way_bound_ms's extra tolerance
    // padding. That padding exists to avoid flagging ordinary jitter as
    // anomalous (a detection concern); ordering::OriginTimeEstimator
    // wants the closest real estimate of actual transit time instead, so
    // padding it would only push every corrected timestamp later than
    // it needs to be, for no benefit.
    pub fn mean_one_way_ms(&self, peer: NodeId) -> Option<f64> {
        let (mean, _) = self.mean_stddev(peer)?;
        Some(mean / 2.0)
    }

    // None (not yet enough data to judge) is treated as "not anomalous"
    // by callers -- a node with no established baseline for a peer yet
    // has no basis to accuse it of anything.
    pub fn is_anomalous(&self, peer: NodeId, observed_one_way_ms: f64) -> bool {
        match self.expected_one_way_bound_ms(peer) {
            Some(bound) => observed_one_way_ms > bound,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_samples_never_flags_anomaly() {
        let stats = PeerLatencyStats::new();
        assert!(!stats.is_anomalous(NodeId(1), 10_000.0));
    }

    #[test]
    fn test_consistent_low_latency_flags_large_outlier() {
        let mut stats = PeerLatencyStats::new();
        for _ in 0..20 {
            stats.record_rtt(NodeId(1), 2.0);
        }
        assert!(!stats.is_anomalous(NodeId(1), 1.5), "well within baseline must not be flagged");
        assert!(stats.is_anomalous(NodeId(1), 200.0), "100x the established one-way estimate must be flagged");
    }

    #[test]
    fn test_noisy_baseline_tolerates_its_own_jitter() {
        let mut stats = PeerLatencyStats::new();
        let samples = [1.0, 5.0, 2.0, 8.0, 3.0, 6.0, 1.0, 9.0, 2.0, 7.0];
        for &s in &samples {
            stats.record_rtt(NodeId(1), s);
        }
        // Every sample the baseline was actually built from must be
        // judged plausible against itself.
        for &s in &samples {
            assert!(!stats.is_anomalous(NodeId(1), s / 2.0), "sample {s} (one-way {}) should not be anomalous against a baseline built partly from itself", s / 2.0);
        }
    }
}
