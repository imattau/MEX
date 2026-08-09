// Stage P2: the periodic flush loop that turns Stage P1's standalone
// protocol::OrderSequencer into something actually driving this server's
// real order_log/order_book -- draining whatever submit_order queued
// (see server.rs's docs on why submit_order no longer applies orders
// immediately once this is enabled), resolving true order from real
// network-time evidence, and applying each order via
// server::apply_accepted_order in THAT order instead of raw HTTP
// arrival order.
//
// Response-timing decision, made explicitly rather than defaulted into:
// submit_order acks immediately once an order is queued here (receipt
// signed, success=true, pending=true, matches empty) rather than
// blocking the HTTP response for the whole flush window -- blocking
// would add real latency (the full window) to EVERY order, not an
// acceptable default for a trading API. Actual match results arrive
// asynchronously over the existing ws_broadcast websocket once this loop
// applies the order. This is a real API-shape difference from the
// non-sequenced path (which still returns matches synchronously,
// unchanged) -- SubmitOrderResponse.pending tells a caller which mode a
// given response came from.
//
// Stage P3b: a resolved batch is no longer applied the instant this
// node's own window closes -- it's PROPOSED to mesh peers (see
// protocol::batch_quorum) and only applied once cross-node quorum
// confirms it, or a bounded timeout expires. Three outcomes per batch:
//
//   1. Quorum confirms THIS node's own proposed hash -- apply with real
//      cross-node confirmation, the strongest guarantee this stage
//      offers.
//   2. Quorum confirms a DIFFERENT hash than this node proposed -- a
//      genuine divergence (this node's evidence didn't match its peers').
//      There's no mechanism yet to fetch/adopt the winning resolution's
//      actual DATA (only its hash is exchanged, see batch_quorum's
//      docs) -- so this node can't correctly apply anything for this
//      batch. The order_ids are re-queued into OrderSequencer for a
//      future flush (fresh evidence might resolve the divergence) rather
//      than dropped or force-applied.
//   3. No quorum reached before the timeout -- FAILS OPEN: applies this
//      node's own local resolution anyway, loudly logged as unconfirmed.
//      Blocking indefinitely for peers that may not exist (a lone
//      sequencer with no other nodes running order-sequencing) would be
//      a liveness bug, not a safety win -- a solo node timing out on
//      every batch and always falling back here reproduces Stage P2's
//      exact behavior, which is the correct degrade path, not a failure.

use crate::server::{apply_accepted_order, AppState};
use common::NodeId;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

// Drains confirmed_batch_rx until either `batch_key`'s confirmation
// arrives (returns Some(agreed_hash)) or `timeout` elapses (returns
// None). Confirmations for a DIFFERENT batch_key are neither ours nor
// stale garbage -- they're another concurrent flush's business (or a
// leftover from a batch this node already gave up waiting on) -- so
// they're simply skipped, not treated as an error.
async fn wait_for_batch_confirmation(
    confirmed_batch_rx: &mut mpsc::Receiver<([u8; 32], [u8; 32])>,
    batch_key: [u8; 32],
    timeout: Duration,
) -> Option<[u8; 32]> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, confirmed_batch_rx.recv()).await {
            Ok(Some((k, h))) if k == batch_key => return Some(h),
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => return None,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_order_sequencing_loop(
    state: Arc<RwLock<AppState>>,
    window: Duration,
    witness_query_tx: mpsc::Sender<([u8; 32], oneshot::Sender<Option<(NodeId, f64)>>)>,
    propose_batch_tx: mpsc::Sender<([u8; 32], Vec<[u8; 32]>)>,
    mut confirmed_batch_rx: mpsc::Receiver<([u8; 32], [u8; 32])>,
    quorum_timeout: Duration,
) {
    tracing::info!(?window, ?quorum_timeout, "order sequencing loop started");

    loop {
        tokio::time::sleep(window).await;

        let pending_ids = {
            let guard = state.read().unwrap();
            match &guard.order_sequencer {
                Some(seq) => seq.pending_order_ids(),
                None => Vec::new(),
            }
        };
        if pending_ids.is_empty() {
            continue;
        }

        // Evidence is fetched OUTSIDE the lock -- these are async
        // queries to the mesh node, and a std::sync RwLock must never be
        // held across an .await (see apply_accepted_order's own docs on
        // this same invariant).
        let mut evidence = HashMap::new();
        for order_id in &pending_ids {
            let (tx, rx) = oneshot::channel();
            if witness_query_tx.send((*order_id, tx)).await.is_err() {
                tracing::warn!(
                    "order sequencing loop: mesh witness query channel closed, stopping"
                );
                return;
            }
            match rx.await {
                Ok(Some(w)) => {
                    evidence.insert(*order_id, w);
                }
                Ok(None) => {
                    // No evidence yet for this order (e.g. propagation
                    // still in flight, or it never went through the mesh
                    // at all) -- left out of the map entirely, which
                    // OrderSequencer::flush treats as evidence-lacking:
                    // ranked after every order in THIS SAME batch that
                    // does have evidence, but still resolved now, not
                    // deferred to a later flush (flush() drains
                    // everything currently pending unconditionally --
                    // there's no "hold back for next round" mechanism on
                    // ITS side; only the quorum step below can cause a
                    // re-queue, and only on genuine divergence). Sizing
                    // `window` comfortably larger than typical
                    // propagation/convergence time (O1's live tests
                    // showed ~20-30ms) is what keeps this the rare case
                    // rather than the common one.
                    tracing::debug!(
                        ?order_id,
                        "order sequencing loop: no evidence yet, will be ranked last in this batch"
                    );
                }
                Err(_) => {
                    tracing::warn!(
                        "order sequencing loop: mesh witness reply channel closed, stopping"
                    );
                    return;
                }
            }
        }

        let resolved = {
            let mut guard = state.write().unwrap();
            match guard.order_sequencer.as_mut() {
                Some(seq) => seq.flush(&evidence),
                None => continue,
            }
        };

        let batch_key = protocol::batch_quorum::compute_batch_key(&resolved);
        let my_hash = protocol::batch_quorum::compute_proposal_hash(&resolved);

        if propose_batch_tx
            .send((batch_key, resolved.clone()))
            .await
            .is_err()
        {
            tracing::warn!(
                ?batch_key,
                "order sequencing loop: propose_batch channel closed, stopping"
            );
            return;
        }

        let confirmed =
            wait_for_batch_confirmation(&mut confirmed_batch_rx, batch_key, quorum_timeout).await;

        let mut guard = state.write().unwrap();
        match confirmed {
            Some(agreed_hash) if agreed_hash == my_hash => {
                metrics::counter!("api.sequencing.batch_confirmed_by_quorum").increment(1);
                tracing::info!(
                    ?batch_key,
                    orders = resolved.len(),
                    "order batch confirmed by cross-node quorum, applying"
                );
                apply_resolved_batch(&mut guard, resolved, &evidence);
            }
            Some(_other_hash) => {
                // Real divergence -- see this file's docs on why we
                // can't apply anything here. Re-queue for a future
                // flush rather than dropping the orders.
                metrics::counter!("api.sequencing.batch_diverged").increment(1);
                tracing::warn!(?batch_key, orders = resolved.len(), "order batch quorum confirmed a DIFFERENT hash than this node proposed -- re-queueing for a future flush");
                if let Some(seq) = guard.order_sequencer.as_mut() {
                    for order_id in resolved {
                        seq.add(order_id);
                    }
                }
            }
            None => {
                metrics::counter!("api.sequencing.batch_applied_after_timeout").increment(1);
                tracing::warn!(?batch_key, orders = resolved.len(), ?quorum_timeout, "order batch quorum not reached in time -- applying this node's own resolution unconfirmed");
                apply_resolved_batch(&mut guard, resolved, &evidence);
            }
        }
    }
}

// Stage P3c-1: `evidence` is the SAME (witnessing_hop, estimated_origin_
// time_ms) snapshot the caller already fetched to resolve this batch's
// order -- reused here as the source of the SHARED match timestamp (see
// server::apply_accepted_order's docs on why that's what makes
// independent replicas able to converge). An order with no evidence
// entry (the rare fallback case -- see this file's docs earlier) gets
// None, falling back to this node's own wall clock for just that order,
// same as the non-sequenced path always has.
fn apply_resolved_batch(
    guard: &mut AppState,
    resolved: Vec<[u8; 32]>,
    evidence: &HashMap<[u8; 32], (NodeId, f64)>,
) {
    for order_id in resolved {
        let Some((order, receipt)) = guard.pending_order_data.remove(&order_id) else {
            // Genuinely shouldn't happen -- every order_id here came
            // from add(), and add() is only ever called alongside
            // inserting into pending_order_data (see server.rs's
            // submit_order). Logged, not panicked: an ordering bug here
            // shouldn't take the whole server down.
            tracing::warn!(
                ?order_id,
                "order sequencing loop: resolved order_id had no pending data"
            );
            continue;
        };
        let match_timestamp_us = evidence
            .get(&order_id)
            .map(|(_, estimate_ms)| (estimate_ms * 1000.0) as u64);
        let start = Instant::now();
        let matches = match apply_accepted_order(guard, order, receipt, match_timestamp_us) {
            Ok(m) => m,
            Err(e) => {
                // Stage P4-1: a durable-write failure here means this
                // order is dropped from this flush -- it was already
                // removed from pending_order_data above, and isn't
                // durably recorded, so it's genuinely lost from this
                // node's perspective. Not retried: a WAL that's failing
                // (e.g. disk full) is an operational emergency this loop
                // can't fix by itself, and blocking the whole batch on
                // one order would stall every other order in it too.
                tracing::error!(error = %e, ?order_id, "failed to durably persist sequenced order -- dropped, not applied");
                continue;
            }
        };
        metrics::counter!("api.orders.matched").increment(matches.len() as u64);
        metrics::histogram!("api.orders.match_latency_us")
            .record(start.elapsed().as_micros() as f64);
        if matches.is_empty() {
            tracing::debug!(?order_id, "sequenced order added to book with no matches");
        } else {
            tracing::info!(
                ?order_id,
                matches = matches.len(),
                "sequenced order matched successfully"
            );
        }
    }
}
