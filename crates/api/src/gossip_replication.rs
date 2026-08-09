// Stage P3c-2: feeds orders this node only learned about via mesh gossip
// (not its own HTTP submissions) into its own order-sequencing pipeline,
// so this node can independently apply/match them too, not just witness
// their timing for other nodes' quorum purposes. Without this, "order-
// sequencing enabled" only ever sequenced this node's OWN submissions --
// a peer that received the same order purely via Flood gossip had no way
// to queue it for its own local application at all.
//
// FloodMessage already carries the complete common::Order (nothing new
// needed on the wire) -- the gap was purely that nothing consumed an
// arriving Flood for this purpose. protocol::MeshNode::flood_receiver
// (new alongside this) exposes every genuinely peer-received arrival
// (self-injected ones, i.e. this node's own submissions, are excluded at
// the source -- see its own docs).
//
// Deliberately tied to order_sequencer being enabled already, not a
// separate opt-in flag: a node with order-sequencing on has already
// opted into "apply orders via network-time-resolved batches instead of
// raw arrival order," and a gossip-sourced order is exactly the kind of
// input that pipeline exists to handle. A witness-only node (mesh
// enabled, order-sequencing NOT enabled) simply has nothing for this
// loop to do -- it still contributes network-time evidence and quorum
// votes via the existing mesh machinery, just never applies orders
// itself.

use crate::server::AppState;
use common::{FloodMessage, NodeId};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;

pub async fn run_gossip_replication_loop(
    state: Arc<RwLock<AppState>>,
    mut flood_rx: mpsc::Receiver<(NodeId, FloodMessage)>,
) {
    tracing::info!("gossip replication loop started");

    while let Some((from_node, flood_msg)) = flood_rx.recv().await {
        let order = flood_msg.order;
        let order_id = order.id;

        let mut guard = state.write().unwrap();

        let Some(_) = guard.order_sequencer.as_ref() else {
            // Order-sequencing isn't enabled on this node -- nothing to
            // do with a gossiped order (see this module's docs on why
            // this isn't a separate opt-in).
            continue;
        };

        // Idempotency: skip an order this node has already queued (a
        // redundant arrival via a different mesh path -- legitimate,
        // see flood.rs's Stage 1 docs on why duplicates are expected)
        // or already fully applied (this exact order gossiped again
        // after this node already committed it, e.g. another peer
        // replaying old traffic). Re-queueing either would re-apply the
        // same order twice.
        if guard.pending_order_data.contains_key(&order_id)
            || guard.applied_order_ids.contains(&order_id)
        {
            continue;
        }

        // Don't trust gossip blindly -- verify the signature exactly as
        // submit_order does for a direct HTTP submission. A malicious or
        // buggy peer could otherwise gossip a fabricated order and have
        // it silently queued for real matching.
        if !guard.validator.validate_order(&order) {
            tracing::warn!(
                ?order_id,
                ?from_node,
                "gossip replication loop: received an order with an invalid signature, discarding"
            );
            continue;
        }

        let receipt = orderlog::sign_receipt(
            &guard.receipt_signing_key,
            order.id,
            order.trader,
            &order.symbol,
            order.side,
            order.price,
            order.amount,
            order.nonce,
            order.expiry,
            order.settlement_preference,
            order.settlement_requester,
        );

        guard.order_sequencer.as_mut().unwrap().add(order_id);
        guard.pending_order_data.insert(order_id, (order, receipt));
        metrics::counter!("api.orders.queued_from_gossip").increment(1);
        tracing::debug!(
            ?order_id,
            ?from_node,
            "order queued for network-time sequencing from mesh gossip"
        );
    }

    tracing::warn!("gossip replication loop: flood channel closed, stopping");
}
