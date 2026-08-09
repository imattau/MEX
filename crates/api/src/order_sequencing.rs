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

use crate::server::{apply_accepted_order, AppState};
use common::NodeId;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

pub async fn run_order_sequencing_loop(
    state: Arc<RwLock<AppState>>,
    window: Duration,
    witness_query_tx: mpsc::Sender<([u8; 32], oneshot::Sender<Option<(NodeId, f64)>>)>,
) {
    tracing::info!(?window, "order sequencing loop started");

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
                tracing::warn!("order sequencing loop: mesh witness query channel closed, stopping");
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
                    // does have evidence, but still resolved and applied
                    // now, not deferred to a later flush (flush() drains
                    // everything currently pending unconditionally --
                    // there's no "hold back for next round" mechanism).
                    // Sizing `window` comfortably larger than typical
                    // propagation/convergence time (O1's live tests
                    // showed ~20-30ms) is what keeps this the rare case
                    // rather than the common one.
                    tracing::debug!(?order_id, "order sequencing loop: no evidence yet, will be ranked last in this batch");
                }
                Err(_) => {
                    tracing::warn!("order sequencing loop: mesh witness reply channel closed, stopping");
                    return;
                }
            }
        }

        let mut guard = state.write().unwrap();
        let resolved = match guard.order_sequencer.as_mut() {
            Some(seq) => seq.flush(&evidence),
            None => continue,
        };

        for order_id in resolved {
            let Some((order, receipt)) = guard.pending_order_data.remove(&order_id) else {
                // Genuinely shouldn't happen -- every order_id flush()
                // returns came from add(), and add() is only ever called
                // alongside inserting into pending_order_data (see
                // server.rs's submit_order). Logged, not panicked: an
                // ordering bug here shouldn't take the whole server down.
                tracing::warn!(?order_id, "order sequencing loop: resolved order_id had no pending data");
                continue;
            };
            let start = Instant::now();
            let matches = apply_accepted_order(&mut guard, order, receipt);
            metrics::counter!("api.orders.matched").increment(matches.len() as u64);
            metrics::histogram!("api.orders.match_latency_us").record(start.elapsed().as_micros() as f64);
            if matches.is_empty() {
                tracing::debug!(?order_id, "sequenced order added to book with no matches");
            } else {
                tracing::info!(?order_id, matches = matches.len(), "sequenced order matched successfully");
            }
        }
    }
}
