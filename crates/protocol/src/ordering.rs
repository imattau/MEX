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
//
// Stage O2: compare_orders below turns two orders' estimates into an
// actual ranking. Two estimates within AMBIGUITY_WINDOW_MS of each other
// are, honestly, not distinguishable by this mechanism's own precision
// (see this module's docs on jitter) -- picking the numerically-smaller
// one anyway would let ordinary network noise decide priority, which is
// exactly the kind of exploitable non-determinism a real ordering scheme
// can't have. Falling back to a HASH-based tie-break at that point is
// deterministic (every honest observer computes the same answer from the
// same inputs) without being decided by raw timing noise.
//
// The tie-break input is order_id -- but NOT order_id alone. order_id is
// trader-chosen (trader_pubkey + nonce), so a trader who can predict
// "hash(order_id) low wins" can just grind through nonce values until
// they find one that wins every tie they care about, for free. Folding
// in the EARLIEST witnessing hop's NodeId defeats pure grinding, since a
// trader submitting through a relay they don't control can't choose that
// value. This is NOT a complete fix: a trader who IS the operator of
// their own entry-point relay still controls both inputs. Closing that
// gap needs relay identity to cost something to acquire or forge --
// which is exactly what Stage 4's NodeRegistry/stake work already
// exists for, just not connected to this yet. Documented as a real,
// acknowledged limit, not solved here.
//
// Also inherits this whole module's single-shared-witnessing-hop scope:
// the tie-break is only guaranteed IDENTICAL across independent
// observers when they all see the order via the same immediate hop (this
// stage's test topology, same as O1's) -- a node that saw an order via a
// DIFFERENT immediate hop than another observer could compute a
// different tie-break input entirely. Reconciling that needs the same
// witness-chain-back-to-true-origin work O1's docs already flag as
// deferred.

use common::NodeId;
use sha2::{Digest, Sha256};
use std::cmp::Ordering as CmpOrdering;

// How close two orders' estimated origin times need to be before this
// node treats them as too close to trust a raw timestamp compare --
// deliberately the same order of magnitude as latency::MIN_TOLERANCE_MS,
// not a tighter number that would let ordinary jitter decide order.
pub const AMBIGUITY_WINDOW_MS: f64 = 25.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderingDecision {
    // The two estimates differed by at least AMBIGUITY_WINDOW_MS --
    // decided by which was numerically earlier.
    ByTimestamp(CmpOrdering),
    // The two estimates were within AMBIGUITY_WINDOW_MS of each other --
    // decided by the deterministic hash tie-break instead (see this
    // module's docs above on why, and its real limits).
    TieBroken(CmpOrdering),
}

fn tie_break_key(order_id: &[u8; 32], witnessing_hop: NodeId) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(order_id);
    hasher.update(witnessing_hop.0.to_be_bytes());
    hasher.finalize().into()
}

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

    // Same as earliest_estimate_ms, but also returns WHICH hop produced
    // it -- compare_orders needs the hop identity for its tie-break
    // input, not just the timestamp.
    fn earliest_witness(&mut self, order_id: &[u8; 32]) -> Option<(NodeId, f64)> {
        self.estimates
            .get(order_id)?
            .iter()
            .copied()
            .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
    }

    // Stage O2: ranks two orders using this node's own recorded
    // estimates -- None if this node hasn't seen enough evidence for
    // EITHER order to have an estimate at all (can't rank what you
    // haven't observed). See OrderingDecision's docs for what
    // ByTimestamp vs TieBroken means and why.
    pub fn compare_orders(&mut self, order_a: &[u8; 32], order_b: &[u8; 32]) -> Option<OrderingDecision> {
        let (hop_a, t_a) = self.earliest_witness(order_a)?;
        let (hop_b, t_b) = self.earliest_witness(order_b)?;

        if (t_a - t_b).abs() >= AMBIGUITY_WINDOW_MS {
            return Some(OrderingDecision::ByTimestamp(t_a.partial_cmp(&t_b).unwrap()));
        }

        let key_a = tie_break_key(order_a, hop_a);
        let key_b = tie_break_key(order_b, hop_b);
        Some(OrderingDecision::TieBroken(key_a.cmp(&key_b)))
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

    #[test]
    fn test_compare_orders_none_without_evidence_for_both() {
        let mut est = OriginTimeEstimator::new();
        est.record([1u8; 32], NodeId(1), 1000.0);
        assert_eq!(est.compare_orders(&[1u8; 32], &[2u8; 32]), None);
    }

    #[test]
    fn test_compare_orders_by_timestamp_when_clearly_separated() {
        let mut est = OriginTimeEstimator::new();
        est.record([1u8; 32], NodeId(1), 1000.0);
        est.record([2u8; 32], NodeId(1), 1000.0 + AMBIGUITY_WINDOW_MS + 1.0);
        assert_eq!(est.compare_orders(&[1u8; 32], &[2u8; 32]), Some(OrderingDecision::ByTimestamp(CmpOrdering::Less)));
        assert_eq!(est.compare_orders(&[2u8; 32], &[1u8; 32]), Some(OrderingDecision::ByTimestamp(CmpOrdering::Greater)));
    }

    #[test]
    fn test_compare_orders_tie_broken_when_within_ambiguity_window() {
        let mut est = OriginTimeEstimator::new();
        est.record([1u8; 32], NodeId(1), 1000.0);
        est.record([2u8; 32], NodeId(1), 1000.0 + AMBIGUITY_WINDOW_MS - 1.0);
        let result = est.compare_orders(&[1u8; 32], &[2u8; 32]);
        assert!(matches!(result, Some(OrderingDecision::TieBroken(_))), "expected a tie-break, got {result:?}");
    }

    #[test]
    fn test_tie_break_is_deterministic_and_not_solely_based_on_raw_order_id_bytes() {
        let mut est = OriginTimeEstimator::new();
        // [1u8; 32] < [2u8; 32] as raw bytes -- if the tie-break were
        // just comparing order_id directly, order 1 would always win.
        // Witnessed by a DIFFERENT hop each, so the actual decision
        // depends on the hashed (order_id, hop) pair, not raw byte order.
        est.record([1u8; 32], NodeId(99), 1000.0);
        est.record([2u8; 32], NodeId(1), 1000.0);
        let first = est.compare_orders(&[1u8; 32], &[2u8; 32]);
        let second = est.compare_orders(&[1u8; 32], &[2u8; 32]);
        assert_eq!(first, second, "tie-break must be deterministic across repeated calls with the same evidence");
        assert!(matches!(first, Some(OrderingDecision::TieBroken(_))));
    }

    #[test]
    fn test_tie_break_is_antisymmetric() {
        let mut est = OriginTimeEstimator::new();
        est.record([1u8; 32], NodeId(5), 1000.0);
        est.record([2u8; 32], NodeId(7), 1000.0);
        let a_vs_b = est.compare_orders(&[1u8; 32], &[2u8; 32]);
        let b_vs_a = est.compare_orders(&[2u8; 32], &[1u8; 32]);
        match (a_vs_b, b_vs_a) {
            (Some(OrderingDecision::TieBroken(o1)), Some(OrderingDecision::TieBroken(o2))) => {
                assert_eq!(o1, o2.reverse(), "comparing A-then-B must be the exact reverse of B-then-A");
            }
            other => panic!("expected both directions to be tie-broken, got {other:?}"),
        }
    }
}
