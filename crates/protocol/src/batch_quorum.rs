// Stage P3a: lets multiple INDEPENDENT nodes -- each resolving the same
// set of orders via its own OriginTimeEstimator evidence (see
// sequencer::OrderSequencer) -- confirm they actually agree on the
// result, instead of each unilaterally treating its own local resolution
// as canonical. Deliberately reuses the exact shape MisconductQuorum
// (node.rs) already validated for the same underlying problem
// ("multiple distinct voices must independently agree before this is
// treated as confirmed"), just applied to order-batch proposals instead
// of misconduct accusations.
//
// This is "vote by computation," not "vote by opinion": a proposal is
// just a node reporting the sha256 hash of what ITS OWN evidence-driven
// resolution already produced (see sequencer::OrderSequencer::flush) --
// nothing here lets a node vote for an arbitrary preferred order it
// didn't actually derive from evidence. Quorum is reached once
// min_reporters DISTINCT reporters report the SAME hash for the SAME
// batch_key; if honest nodes' evidence has genuinely converged (O1's
// live tests showed independently-positioned nodes agreeing within
// ~10-30ms), their proposals should naturally match without any
// out-of-band coordination.
//
// Real, acknowledged limits, same as MisconductQuorum's: no Sybil
// resistance on its own (a reporter is just a NodeId with no cost --
// Stage 4's chain-gating/stake-weighting work applies here exactly the
// same way it did there, just not wired in at this stage). No shared
// ledger either -- different nodes can reach quorum on the same
// batch_key at different times, or never, depending on which proposals
// each happens to receive; there's still no consensus layer underneath
// this.
//
// What this stage does NOT do: decide what happens when reporters
// genuinely DISAGREE (multiple distinct hashes accumulate for the same
// batch_key without any single one reaching threshold) -- that's a real
// divergence signal (see distinct_hash_count), surfaced but not resolved
// here. Reconciling a genuine disagreement, and actually gating
// order_log commitment on reaching quorum, is Stage P3b's job.

use common::NodeId;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// Identifies WHICH set of order_ids a proposal is about -- order-
// INsensitive (sorted first), so any node that has heard of the same
// set of order_ids computes the same batch_key regardless of what order
// it currently believes they belong in. Two nodes with genuinely
// different subsets of orders (e.g. one hasn't heard of an order yet)
// will compute DIFFERENT batch_keys entirely and simply never reach
// quorum with each other on either -- a real limitation of this stage,
// not silently papered over (see this module's docs on P3b).
pub fn compute_batch_key(order_ids: &[[u8; 32]]) -> [u8; 32] {
    let mut sorted: Vec<[u8; 32]> = order_ids.to_vec();
    sorted.sort();
    let mut hasher = Sha256::new();
    for id in &sorted {
        hasher.update(id);
    }
    hasher.finalize().into()
}

// The actual claim being voted on for a batch_key -- order-SENSITIVE
// (unlike compute_batch_key above), since this is a commitment to a
// specific RESOLVED SEQUENCE (see sequencer::OrderSequencer::flush's
// output), not just to which orders are involved.
pub fn compute_proposal_hash(resolved_order_ids: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for id in resolved_order_ids {
        hasher.update(id);
    }
    hasher.finalize().into()
}

pub struct OrderBatchQuorum {
    // batch_key -> proposed_hash -> (reporter -> last_seen)
    proposals: HashMap<[u8; 32], HashMap<[u8; 32], HashMap<NodeId, f64>>>,
    min_reporters: usize,
    window_secs: f64,
}

impl OrderBatchQuorum {
    pub fn new(min_reporters: usize, window_secs: f64) -> Self {
        Self {
            proposals: HashMap::new(),
            min_reporters,
            window_secs,
        }
    }

    // Records `reporter`'s claim that `batch_key` resolves to
    // `proposed_hash`, expiring stale entries (across every hash bucket
    // for this batch_key, not just the one being voted on) first. A
    // repeat proposal from the same reporter for the same hash just
    // refreshes its timestamp, same non-accumulating-vote-spam property
    // MisconductQuorum's own docs describe. Returns Some(proposed_hash)
    // once min_reporters distinct reporters agree on THIS hash; None
    // otherwise (not enough agreement yet -- including when reporters
    // are actively disagreeing, see distinct_hash_count).
    pub fn record(
        &mut self,
        batch_key: [u8; 32],
        reporter: NodeId,
        proposed_hash: [u8; 32],
        now: f64,
    ) -> Option<[u8; 32]> {
        let by_hash = self.proposals.entry(batch_key).or_default();
        for reporters in by_hash.values_mut() {
            reporters.retain(|_, last_seen| now - *last_seen < self.window_secs);
        }
        by_hash.retain(|_, reporters| !reporters.is_empty());

        let reporters = by_hash.entry(proposed_hash).or_default();
        reporters.insert(reporter, now);
        if reporters.len() >= self.min_reporters {
            Some(proposed_hash)
        } else {
            None
        }
    }

    // How many DISTINCT hash values are currently proposed for this
    // batch_key -- more than 1 means real, live disagreement among
    // reporters (their evidence hasn't converged, or one of them is
    // wrong/dishonest), not just "not enough votes yet" (which shows up
    // as exactly 1 hash with too few reporters).
    pub fn distinct_hash_count(&self, batch_key: &[u8; 32]) -> usize {
        self.proposals.get(batch_key).map(|m| m.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_batch_key_is_order_insensitive() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(
            compute_batch_key(&[a, b]),
            compute_batch_key(&[b, a]),
            "batch_key must be the same regardless of the order order_ids are passed in"
        );
    }

    #[test]
    fn test_compute_proposal_hash_is_order_sensitive() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(
            compute_proposal_hash(&[a, b]),
            compute_proposal_hash(&[b, a]),
            "proposal hash must differ when the resolved SEQUENCE differs"
        );
    }

    #[test]
    fn test_single_proposal_never_reaches_quorum() {
        let mut q = OrderBatchQuorum::new(2, 60.0);
        assert_eq!(q.record([1u8; 32], NodeId(1), [9u8; 32], 0.0), None);
    }

    #[test]
    fn test_two_distinct_reporters_on_same_hash_reach_quorum() {
        let mut q = OrderBatchQuorum::new(2, 60.0);
        assert_eq!(q.record([1u8; 32], NodeId(1), [9u8; 32], 0.0), None);
        assert_eq!(
            q.record([1u8; 32], NodeId(2), [9u8; 32], 0.0),
            Some([9u8; 32])
        );
    }

    #[test]
    fn test_repeated_proposal_from_same_reporter_does_not_manufacture_quorum() {
        let mut q = OrderBatchQuorum::new(2, 60.0);
        assert_eq!(q.record([1u8; 32], NodeId(1), [9u8; 32], 0.0), None);
        assert_eq!(q.record([1u8; 32], NodeId(1), [9u8; 32], 1.0), None);
        assert_eq!(q.record([1u8; 32], NodeId(1), [9u8; 32], 2.0), None);
    }

    #[test]
    fn test_disagreeing_reporters_never_reach_quorum_on_either_hash() {
        let mut q = OrderBatchQuorum::new(2, 60.0);
        assert_eq!(q.record([1u8; 32], NodeId(1), [9u8; 32], 0.0), None);
        assert_eq!(
            q.record([1u8; 32], NodeId(2), [8u8; 32], 0.0),
            None,
            "a different reporter proposing a DIFFERENT hash must not confirm the first one"
        );
        assert_eq!(
            q.distinct_hash_count(&[1u8; 32]),
            2,
            "genuine disagreement should be visible as more than one distinct hash"
        );
    }

    #[test]
    fn test_distinct_batch_keys_do_not_mix() {
        let mut q = OrderBatchQuorum::new(2, 60.0);
        q.record([1u8; 32], NodeId(1), [9u8; 32], 0.0);
        q.record([2u8; 32], NodeId(1), [9u8; 32], 0.0);
        assert_eq!(q.distinct_hash_count(&[1u8; 32]), 1);
        assert_eq!(q.distinct_hash_count(&[2u8; 32]), 1);
        // Same reporter, same hash, but DIFFERENT batch_key -- must not
        // count toward the other batch_key's quorum.
        assert_eq!(
            q.record([2u8; 32], NodeId(2), [9u8; 32], 0.0),
            Some([9u8; 32])
        );
        assert_eq!(q.distinct_hash_count(&[1u8; 32]), 1, "batch_key [1u8;32] must still only have 1 reporter -- unaffected by votes on a different batch_key");
    }

    #[test]
    fn test_stale_proposals_expire_out_of_the_window() {
        let mut q = OrderBatchQuorum::new(2, 10.0);
        assert_eq!(q.record([1u8; 32], NodeId(1), [9u8; 32], 0.0), None);
        // Reporter 2 votes long after reporter 1's vote has expired.
        assert_eq!(
            q.record([1u8; 32], NodeId(2), [9u8; 32], 100.0),
            None,
            "reporter 1's stale vote must not still count toward quorum"
        );
    }
}
