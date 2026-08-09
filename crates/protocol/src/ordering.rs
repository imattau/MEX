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
// Stage O3: a withholding relay delaying its forward would, on its own,
// just produce a later, uncorrected estimate for whichever order it sat
// on -- indistinguishable at this layer from ordinary jitter, UNLESS
// something else is available to prefer over it. That something is
// HopLatencyMonitor's existing anomaly verdicts (Stage 1-3): every
// recorded estimate here can be retroactively flagged anomalous (see
// mark_anomalous) once the matching HopWitness confirms this specific
// hop's observed transit time blew past its own established baseline.
// earliest_witness/earliest_estimate_ms/compare_orders then prefer
// non-anomalous witnesses whenever at least one is available for that
// order, falling back to whatever's recorded (even if flagged) only when
// NOTHING non-anomalous has been seen yet -- a single, uncorroborated
// observation is still real evidence (same reasoning Stage 1 already
// established for misconduct detection), just the last resort here.
//
// This is exactly the payoff of the whole earlier misconduct-detection
// arc for ORDERING, not just policing: a node with genuine topological
// redundancy (an honest second path for the same order, Stage 2's
// diamond-topology case) will have that honest path's estimate win over
// a manipulated one automatically, with no separate reconciliation step.
//
// Real, acknowledged limit: classification is asynchronous and NOT
// guaranteed complete by the time a query runs. `anomalous` defaults to
// false at record time (assumed honest until proven otherwise) -- a
// witness whose matching HopWitness simply hasn't arrived yet, or whose
// verdict hasn't been computed yet, looks identical to a genuinely
// honest one at query time. This mechanism reflects the best evidence
// available AT THE MOMENT OF QUERY, not a promise that manipulation
// in-flight has already been caught.
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

pub(crate) fn tie_break_key(order_id: &[u8; 32], witnessing_hop: NodeId) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(order_id);
    hasher.update(witnessing_hop.0.to_be_bytes());
    hasher.finalize().into()
}

// The pure comparison logic behind compare_orders, factored out so
// sequencer::OrderSequencer can rank a whole BATCH of orders using the
// exact same rule against a pre-fetched evidence snapshot, instead of
// duplicating it. `evidence_a`/`evidence_b` are each (witnessing_hop,
// estimated_origin_time_ms), already resolved by the caller.
pub(crate) fn compare_by_evidence(
    order_a: &[u8; 32],
    evidence_a: (NodeId, f64),
    order_b: &[u8; 32],
    evidence_b: (NodeId, f64),
) -> OrderingDecision {
    let (hop_a, t_a) = evidence_a;
    let (hop_b, t_b) = evidence_b;

    if (t_a - t_b).abs() >= AMBIGUITY_WINDOW_MS {
        return OrderingDecision::ByTimestamp(t_a.partial_cmp(&t_b).unwrap());
    }

    let key_a = tie_break_key(order_a, hop_a);
    let key_b = tie_break_key(order_b, hop_b);
    OrderingDecision::TieBroken(key_a.cmp(&key_b))
}

pub struct OriginTimeEstimator {
    // order_id -> every (witnessing_hop, estimated_origin_time_ms,
    // anomalous) this node has independently derived for it so far --
    // kept as a Vec, not just the running minimum, since Stage O2's
    // tie-break needs to distinguish estimates by which hop produced
    // them, and Stage O3's anomaly-preference needs all of them, not
    // just the best one. `anomalous` starts false at record() time
    // (nothing known yet) and can be flipped later by mark_anomalous --
    // see this module's docs on why classification is asynchronous.
    estimates: lru::LruCache<[u8; 32], Vec<(NodeId, f64, bool)>>,
}

impl Default for OriginTimeEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl OriginTimeEstimator {
    pub fn new() -> Self {
        Self {
            estimates: lru::LruCache::new(std::num::NonZeroUsize::new(10_000).unwrap()),
        }
    }

    pub fn record(&mut self, order_id: [u8; 32], witnessing_hop: NodeId, estimate_ms: f64) {
        if let Some(v) = self.estimates.get_mut(&order_id) {
            v.push((witnessing_hop, estimate_ms, false));
        } else {
            self.estimates
                .put(order_id, vec![(witnessing_hop, estimate_ms, false)]);
        }
    }

    // Stage O3: retroactively flags the estimate recorded for
    // (order_id, witnessing_hop) as anomalous, once HopLatencyMonitor's
    // matching verdict says this specific hop's observed transit time
    // blew past its own established baseline. A no-op if no such
    // estimate was recorded (e.g. this node had no latency baseline yet
    // for that hop at arrival time, so record() never ran for it).
    pub fn mark_anomalous(&mut self, order_id: [u8; 32], witnessing_hop: NodeId) {
        if let Some(v) = self.estimates.get_mut(&order_id) {
            for entry in v.iter_mut() {
                if entry.0 == witnessing_hop {
                    entry.2 = true;
                }
            }
        }
    }

    // The earliest (minimum) estimate recorded for this order, preferring
    // non-anomalous witnesses whenever at least one exists for this
    // order (see this module's docs on why) -- any additional hop or
    // delay can only push an honest estimate LATER than the truth, never
    // earlier, so the minimum among the preferred pool is the best
    // available estimate, not an arbitrary pick.
    pub fn earliest_estimate_ms(&mut self, order_id: &[u8; 32]) -> Option<f64> {
        self.earliest_witness(order_id).map(|(_, t)| t)
    }

    // Same as earliest_estimate_ms, but also returns WHICH hop produced
    // it -- compare_orders needs the hop identity for its tie-break
    // input, not just the timestamp. pub(crate), not private: Stage P1's
    // sequencer module needs a (hop, estimate) snapshot for a whole
    // batch of orders, fetched once up front -- see its own docs.
    pub(crate) fn earliest_witness(&mut self, order_id: &[u8; 32]) -> Option<(NodeId, f64)> {
        let entries = self.estimates.get(order_id)?;
        let has_honest = entries.iter().any(|(_, _, anomalous)| !anomalous);
        entries
            .iter()
            .filter(|(_, _, anomalous)| !has_honest || !anomalous)
            .map(|(hop, t, _)| (*hop, *t))
            .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
    }

    // Stage O2: ranks two orders using this node's own recorded
    // estimates -- None if this node hasn't seen enough evidence for
    // EITHER order to have an estimate at all (can't rank what you
    // haven't observed). See OrderingDecision's docs for what
    // ByTimestamp vs TieBroken means and why.
    pub fn compare_orders(
        &mut self,
        order_a: &[u8; 32],
        order_b: &[u8; 32],
    ) -> Option<OrderingDecision> {
        let wa = self.earliest_witness(order_a)?;
        let wb = self.earliest_witness(order_b)?;
        Some(compare_by_evidence(order_a, wa, order_b, wb))
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
        assert_eq!(
            est.compare_orders(&[1u8; 32], &[2u8; 32]),
            Some(OrderingDecision::ByTimestamp(CmpOrdering::Less))
        );
        assert_eq!(
            est.compare_orders(&[2u8; 32], &[1u8; 32]),
            Some(OrderingDecision::ByTimestamp(CmpOrdering::Greater))
        );
    }

    #[test]
    fn test_compare_orders_tie_broken_when_within_ambiguity_window() {
        let mut est = OriginTimeEstimator::new();
        est.record([1u8; 32], NodeId(1), 1000.0);
        est.record([2u8; 32], NodeId(1), 1000.0 + AMBIGUITY_WINDOW_MS - 1.0);
        let result = est.compare_orders(&[1u8; 32], &[2u8; 32]);
        assert!(
            matches!(result, Some(OrderingDecision::TieBroken(_))),
            "expected a tie-break, got {result:?}"
        );
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
        assert_eq!(
            first, second,
            "tie-break must be deterministic across repeated calls with the same evidence"
        );
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
                assert_eq!(
                    o1,
                    o2.reverse(),
                    "comparing A-then-B must be the exact reverse of B-then-A"
                );
            }
            other => panic!("expected both directions to be tie-broken, got {other:?}"),
        }
    }

    #[test]
    fn test_anomalous_witness_ignored_when_honest_alternative_exists() {
        let mut est = OriginTimeEstimator::new();
        // A manipulated relay's estimate: numerically EARLIER than the
        // honest one (it made the order look like it arrived sooner than
        // it really did, e.g. by backdating) -- if anomaly-preference
        // weren't applied, the smaller (manipulated) value would win
        // purely on being numerically smaller.
        est.record([1u8; 32], NodeId(1), 500.0);
        est.record([1u8; 32], NodeId(2), 900.0);
        est.mark_anomalous([1u8; 32], NodeId(1));

        assert_eq!(est.earliest_estimate_ms(&[1u8; 32]), Some(900.0), "the anomalous (and numerically smaller) witness must be ignored in favor of the honest one");
    }

    #[test]
    fn test_anomalous_witness_used_as_fallback_when_no_honest_alternative() {
        let mut est = OriginTimeEstimator::new();
        est.record([1u8; 32], NodeId(1), 500.0);
        est.mark_anomalous([1u8; 32], NodeId(1));

        // No corroborating honest path exists -- a single, even flagged,
        // observation is still the best (only) evidence available, same
        // reasoning HopLatencyMonitor's has_corroborating_non_anomalous_hop
        // already uses for misconduct detection.
        assert_eq!(
            est.earliest_estimate_ms(&[1u8; 32]),
            Some(500.0),
            "with no honest alternative, the flagged witness should still be used as a fallback"
        );
    }

    #[test]
    fn test_mark_anomalous_is_a_noop_for_unknown_order_or_hop() {
        let mut est = OriginTimeEstimator::new();
        est.record([1u8; 32], NodeId(1), 500.0);
        est.mark_anomalous([1u8; 32], NodeId(99)); // different hop, never recorded
        est.mark_anomalous([2u8; 32], NodeId(1)); // different order, never recorded
        assert_eq!(
            est.earliest_estimate_ms(&[1u8; 32]),
            Some(500.0),
            "marking an unrelated (order, hop) pair must not affect an unrelated recorded estimate"
        );
    }

    #[test]
    fn test_compare_orders_prefers_honest_witness_over_manipulated_one() {
        let mut est = OriginTimeEstimator::new();
        // Order A: a withholding relay tries to make A look like it
        // arrived AFTER order B by backdating a large delay onto its own
        // witness -- but an honest second path for A also exists and
        // wasn't manipulated.
        est.record([1u8; 32], NodeId(1), 2000.0); // manipulated, late
        est.record([1u8; 32], NodeId(2), 500.0); // honest, early
        est.mark_anomalous([1u8; 32], NodeId(1));

        est.record([2u8; 32], NodeId(3), 900.0);

        // With the manipulated witness discarded, A's honest estimate
        // (500.0) is clearly before B's (900.0) -- correct despite the
        // manipulation attempt.
        assert_eq!(
            est.compare_orders(&[1u8; 32], &[2u8; 32]),
            Some(OrderingDecision::ByTimestamp(CmpOrdering::Less))
        );
    }
}
