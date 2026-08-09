// Stage O1: derives each node's own independent estimate of when an
// order was likely first emitted, purely from data already flowing
// through the mesh -- no new wire messages, no coordination between
// nodes. Reuses PeerLatencyStats' real (Ping/Pong-derived) one-way
// latency baseline to correct a node's own LOCAL arrival clock reading
// back toward the moment the order actually originated: a node standing
// 3 hops from an origin and one standing 1 hop away see wildly different
// raw arrival times for the identical order, but each can independently
// subtract its own measured distance from its own arrival reading, and
// land on comparable estimates -- without either one telling the other
// anything beyond the normal gossip that already happens.
//
// Scope of this stage: only the IMMEDIATE witnessing hop -- whoever
// physically delivered this specific arrival to this node (the UDP
// sender) -- is used, corrected by this node's own Ping/Pong RTT-derived
// baseline to that specific peer. This is exact when that peer IS the
// origin (or the very first relay), and increasingly UNDER-corrected
// (systematically late) the more additional hops sit between the true
// origin and that witnessing peer, since those earlier hops' own transit
// time isn't accounted for -- there's no witness chain back through
// multiple relays yet (that needs every intermediate relay's own
// HopWitness aggregated, not just the last one -- a real further step,
// not built here). Valid for the topology this stage's test validates
// (every observing node directly downstream of a shared source), not yet
// for arbitrary multi-hop distance.
//
// Also assumes, and does not itself provide, roughly-synced wall clocks
// across nodes (e.g. NTP) -- two nodes' own local arrival-time readings
// need to already agree closely for their INDEPENDENTLY-computed
// estimates to be comparable at all. Unlike the correction term itself
// (derived purely from each node's own local Ping/Pong RTT measurements,
// never touching a remote clock), clock skew between nodes' own local
// clocks is a real, unaddressed assumption here.
//
// This stage deliberately does NOT yet factor in HopLatencyMonitor's
// anomaly verdicts (a withholding relay's delayed arrival would just
// produce a later, uncorrected estimate, same as ordinary jitter) --
// resisting deliberate manipulation by preferring corroborated,
// non-anomalous witnesses is a later stage's job, not this one's.

use common::NodeId;

pub struct OriginTimeEstimator {
    // order_id -> every (witnessing_hop, estimated_origin_time_ms) this
    // node has independently derived for it so far -- kept as a Vec, not
    // just the running minimum, since a later stage (robustness against
    // a withholding relay) needs to distinguish estimates by which hop
    // produced them, not just their value.
    estimates: lru::LruCache<[u8; 32], Vec<(NodeId, f64)>>,
}

impl Default for OriginTimeEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl OriginTimeEstimator {
    pub fn new() -> Self {
        Self { estimates: lru::LruCache::new(std::num::NonZeroUsize::new(10_000).unwrap()) }
    }

    pub fn record(&mut self, order_id: [u8; 32], witnessing_hop: NodeId, estimate_ms: f64) {
        if let Some(v) = self.estimates.get_mut(&order_id) {
            v.push((witnessing_hop, estimate_ms));
        } else {
            self.estimates.put(order_id, vec![(witnessing_hop, estimate_ms)]);
        }
    }

    // The earliest (minimum) estimate recorded for this order -- any
    // additional hop or delay can only push an estimate LATER than the
    // truth (see this module's docs on under-correction), never earlier,
    // so the minimum across however many independent witnesses this node
    // has seen is the best available estimate, not an arbitrary pick.
    pub fn earliest_estimate_ms(&mut self, order_id: &[u8; 32]) -> Option<f64> {
        self.estimates
            .get(order_id)
            .and_then(|v| v.iter().map(|(_, t)| *t).fold(None, |acc, t| Some(acc.map_or(t, |a: f64| a.min(t)))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_recorded_estimate_returns_none() {
        let mut est = OriginTimeEstimator::new();
        assert_eq!(est.earliest_estimate_ms(&[1u8; 32]), None);
    }

    #[test]
    fn test_single_estimate_is_returned() {
        let mut est = OriginTimeEstimator::new();
        est.record([1u8; 32], NodeId(1), 1000.0);
        assert_eq!(est.earliest_estimate_ms(&[1u8; 32]), Some(1000.0));
    }

    #[test]
    fn test_earliest_among_multiple_witnesses_wins() {
        let mut est = OriginTimeEstimator::new();
        est.record([1u8; 32], NodeId(1), 1000.0);
        est.record([1u8; 32], NodeId(2), 950.0);
        est.record([1u8; 32], NodeId(3), 1200.0);
        assert_eq!(est.earliest_estimate_ms(&[1u8; 32]), Some(950.0));
    }

    #[test]
    fn test_estimates_for_distinct_orders_do_not_mix() {
        let mut est = OriginTimeEstimator::new();
        est.record([1u8; 32], NodeId(1), 1000.0);
        est.record([2u8; 32], NodeId(1), 500.0);
        assert_eq!(est.earliest_estimate_ms(&[1u8; 32]), Some(1000.0));
        assert_eq!(est.earliest_estimate_ms(&[2u8; 32]), Some(500.0));
    }
}
