// Stage P1: buffers order_ids as they arrive (HTTP/local receipt order,
// which the whole O1-O3 arc exists precisely because it can't be trusted
// on its own) for a window, then flushes them in an order derived from
// OriginTimeEstimator's evidence instead. Standalone: this module does
// not touch orderlog::HashChainLog or api::server -- wiring the actual
// api submit_order path to buffer-then-flush, with all the response-
// timing and fallback-behavior decisions that entails, is a separate,
// later step (see this stage's own scoping notes). This only proves the
// mechanism produces a correctly-ordered batch from the same evidence
// O1-O3 already validate live.
//
// Evidence is a pre-fetched SNAPSHOT, not a live query made during the
// sort: flush() takes a HashMap<order_id, (witnessing_hop, estimate_ms)>
// the caller resolves once, up front (e.g. via
// MeshNode::earliest_witness over its query channel, for every order_id
// currently pending), rather than this module querying
// OriginTimeEstimator per-comparison mid-sort. Sorting against a live,
// async, potentially-mutating data source risks an inconsistent
// comparator -- Rust's sort_by doesn't require a strict total order to
// avoid panicking, but silently produces a wrong result if the
// comparator isn't stable across the whole sort. Freezing a snapshot
// first avoids that, at the cost of not reflecting evidence that arrives
// DURING the sort itself -- negligible in practice, since sorting a
// batch is fast, synchronous, in-memory work.
//
// Deliberate design choice, not an oversight: an order with NO recorded
// evidence at all is placed AFTER every order that has some, regardless
// of local arrival order. The alternative -- falling back to arrival
// order (call add() first, rank first) whenever evidence is missing --
// would hand back exactly the manipulation surface this whole mechanism
// exists to close: a trader could just skip mesh participation, or race
// the flush window, to get placed by raw arrival order instead of real
// evidence, undermining the entire point of using it. Evidence-lacking
// orders are still ordered SOMEHOW (by arrival order relative to each
// OTHER evidence-lacking order, not dropped), just never ahead of an
// evidence-backed one.

use crate::ordering::{compare_by_evidence, OrderingDecision};
use common::NodeId;
use std::cmp::Ordering as CmpOrdering;
use std::collections::HashMap;

pub struct OrderSequencer {
    pending: Vec<PendingOrder>,
    next_arrival_seq: u64,
}

struct PendingOrder {
    order_id: [u8; 32],
    // Purely a local tie-break for orders with NO network evidence at
    // all -- never compared against, or mixed with,
    // estimated_origin_time_ms values (different units, not meaningfully
    // comparable). See this module's docs on why evidence-lacking orders
    // never outrank evidence-backed ones regardless of this value.
    arrival_seq: u64,
}

impl Default for OrderSequencer {
    fn default() -> Self {
        Self::new()
    }
}

impl OrderSequencer {
    pub fn new() -> Self {
        Self { pending: Vec::new(), next_arrival_seq: 0 }
    }

    pub fn add(&mut self, order_id: [u8; 32]) {
        self.pending.push(PendingOrder { order_id, arrival_seq: self.next_arrival_seq });
        self.next_arrival_seq += 1;
    }

    pub fn pending_order_ids(&self) -> Vec<[u8; 32]> {
        self.pending.iter().map(|p| p.order_id).collect()
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    // Resolves canonical order for every currently pending order_id
    // using `evidence` (see this module's docs on why it's a
    // pre-fetched snapshot, not a live query) and clears the pending
    // batch. Orders not present in `evidence` at all are treated as
    // having no evidence (see this module's docs on the fallback rule).
    pub fn flush(&mut self, evidence: &HashMap<[u8; 32], (NodeId, f64)>) -> Vec<[u8; 32]> {
        let mut batch = std::mem::take(&mut self.pending);
        batch.sort_by(|a, b| compare(a, b, evidence));
        batch.into_iter().map(|p| p.order_id).collect()
    }
}

fn compare(a: &PendingOrder, b: &PendingOrder, evidence: &HashMap<[u8; 32], (NodeId, f64)>) -> CmpOrdering {
    match (evidence.get(&a.order_id).copied(), evidence.get(&b.order_id).copied()) {
        (Some(ea), Some(eb)) => match compare_by_evidence(&a.order_id, ea, &b.order_id, eb) {
            OrderingDecision::ByTimestamp(o) | OrderingDecision::TieBroken(o) => o,
        },
        (Some(_), None) => CmpOrdering::Less,
        (None, Some(_)) => CmpOrdering::Greater,
        (None, None) => a.arrival_seq.cmp(&b.arrival_seq),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence_map(entries: &[([u8; 32], NodeId, f64)]) -> HashMap<[u8; 32], (NodeId, f64)> {
        entries.iter().map(|&(id, hop, t)| (id, (hop, t))).collect()
    }

    #[test]
    fn test_flush_empty_sequencer_returns_empty() {
        let mut seq = OrderSequencer::new();
        assert_eq!(seq.flush(&HashMap::new()), Vec::<[u8; 32]>::new());
    }

    #[test]
    fn test_flush_sorts_by_evidence_not_arrival_order() {
        let mut seq = OrderSequencer::new();
        // Added out of true order: C, then A, then B.
        seq.add([3u8; 32]);
        seq.add([1u8; 32]);
        seq.add([2u8; 32]);

        let evidence = evidence_map(&[
            ([1u8; 32], NodeId(1), 100.0),
            ([2u8; 32], NodeId(1), 200.0),
            ([3u8; 32], NodeId(1), 300.0),
        ]);

        assert_eq!(seq.flush(&evidence), vec![[1u8; 32], [2u8; 32], [3u8; 32]], "flush must resolve TRUE evidence order, not raw arrival order");
    }

    #[test]
    fn test_flush_clears_pending_batch() {
        let mut seq = OrderSequencer::new();
        seq.add([1u8; 32]);
        let evidence = evidence_map(&[([1u8; 32], NodeId(1), 100.0)]);
        seq.flush(&evidence);
        assert_eq!(seq.pending_len(), 0);
        assert_eq!(seq.flush(&HashMap::new()), Vec::<[u8; 32]>::new());
    }

    #[test]
    fn test_orders_without_evidence_never_outrank_orders_with_evidence() {
        let mut seq = OrderSequencer::new();
        // [2u8;32] added FIRST (would win by raw arrival order) but has
        // NO evidence; [1u8;32] added second but DOES have evidence.
        seq.add([2u8; 32]);
        seq.add([1u8; 32]);

        let evidence = evidence_map(&[([1u8; 32], NodeId(1), 500.0)]);

        assert_eq!(seq.flush(&evidence), vec![[1u8; 32], [2u8; 32]], "the evidence-backed order must rank first regardless of arrival order");
    }

    #[test]
    fn test_orders_without_any_evidence_fall_back_to_arrival_order_among_themselves() {
        let mut seq = OrderSequencer::new();
        seq.add([2u8; 32]);
        seq.add([1u8; 32]);
        // Neither has any evidence at all.
        assert_eq!(seq.flush(&HashMap::new()), vec![[2u8; 32], [1u8; 32]], "with no evidence for either, arrival order should be preserved");
    }

    #[test]
    fn test_evidence_within_ambiguity_window_still_produces_a_stable_total_order() {
        let mut seq = OrderSequencer::new();
        seq.add([1u8; 32]);
        seq.add([2u8; 32]);
        // Estimates within the ambiguity window -- must fall through to
        // the deterministic tie-break, not panic or produce an
        // arbitrary/unstable result.
        let evidence = evidence_map(&[
            ([1u8; 32], NodeId(1), 1000.0),
            ([2u8; 32], NodeId(1), 1005.0),
        ]);
        let first = seq.flush(&evidence);
        seq.add([1u8; 32]);
        seq.add([2u8; 32]);
        let second = seq.flush(&evidence);
        assert_eq!(first, second, "the tie-break must be deterministic across repeated flushes with the same evidence");
    }
}
