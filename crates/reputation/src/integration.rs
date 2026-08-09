use crate::composite::ReputationEngine;
use crate::metrics::ReputationMetrics;
use crate::p2p_score::P2PScoreUpdate;
use crate::stake::SlashReason;
use crate::types::*;
use common::NodeId;
use engine::Match;

pub fn on_node_join(engine: &mut ReputationEngine, node_id: NodeId, stake: u64) -> TrustLevel {
    engine.register_node(node_id, stake);
    engine.update_reputation(node_id);
    engine.get_trust_level(&node_id)
}

pub fn on_node_leave(engine: &mut ReputationEngine, node_id: NodeId, downtime_secs: f64) {
    engine.record_downtime(node_id, downtime_secs);

    let state = engine.get_state(&node_id).cloned();
    if let Some(state) = state {
        let has_disputes_lost = state
            .dispute_history
            .iter()
            .any(|d| d.resolved_in_favor_of != node_id);
        let stake_mgr = engine.stake_manager_mut();
        let forfeited =
            stake_mgr.check_bond_conditions(&node_id, state.uptime_percentage, has_disputes_lost);
        for bond_type in forfeited {
            let _ = stake_mgr.forfeit_bond(node_id, bond_type);
        }
    }

    ReputationMetrics::record_node_left(node_id);
}

pub fn on_heartbeat_received(engine: &mut ReputationEngine, node_id: NodeId) {
    engine.record_heartbeat_ok(node_id);
}

pub fn on_censorship_flag(engine: &mut ReputationEngine, node_id: NodeId) {
    engine.update_p2p_metrics(
        node_id,
        P2PScoreUpdate {
            censorship_flag: true,
            ..Default::default()
        },
    );
}

// A peer other than this node independently detected and broadcast
// misconduct (see protocol::WireMessage::MisconductReport) -- an invalid
// settlement proof, a broken order-log chain, or the same kind of
// censorship on_censorship_flag already covers, just witnessed by
// someone else instead of by this node's own EchoRequest/EchoResponse
// probe. Kept as its own function (not just a call site for
// on_censorship_flag) so it stays possible to give externally-reported
// evidence a different weight later -- reuses the same underlying P2P
// penalty for now, since this codebase doesn't yet have a severity model
// that distinguishes "suspected of dropping one echo" from "caught with
// an invalid ZK proof."
pub fn on_misconduct_reported(
    engine: &mut ReputationEngine,
    subject: NodeId,
    reporter: NodeId,
    reason: &str,
) {
    tracing::warn!(?subject, ?reporter, reason, "misconduct reported by a peer");
    engine.update_p2p_metrics(
        subject,
        P2PScoreUpdate {
            censorship_flag: true,
            ..Default::default()
        },
    );
}

pub fn on_echo_response(engine: &mut ReputationEngine, node_id: NodeId, rtt_ms: f64) {
    engine.update_p2p_metrics(
        node_id,
        P2PScoreUpdate {
            echo_rtt_ms: Some(rtt_ms),
            ..Default::default()
        },
    );
}

pub fn on_flood_relayed(engine: &mut ReputationEngine, node_id: NodeId) {
    engine.update_p2p_metrics(
        node_id,
        P2PScoreUpdate {
            flood_relayed: true,
            ..Default::default()
        },
    );
}

pub fn on_flood_dropped(engine: &mut ReputationEngine, node_id: NodeId) {
    engine.update_p2p_metrics(
        node_id,
        P2PScoreUpdate {
            flood_dropped: true,
            ..Default::default()
        },
    );
}

pub fn on_order_matched(
    engine: &mut ReputationEngine,
    node_id: NodeId,
    trade: &Match,
    timestamp: f64,
) {
    let client_engine = engine.client_engine_mut();
    client_engine.update_trader_reputation(trade.maker_trader, 0.01);
    client_engine.record_match_success(node_id, trade, timestamp);
    engine.update_reputation(node_id);
    ReputationMetrics::record_good_trade();
}

pub fn on_settlement_complete(
    engine: &mut ReputationEngine,
    node_id: NodeId,
    trade_id: [u8; 32],
    actual_latency_secs: f64,
    expected_latency_secs: f64,
    timestamp: f64,
) {
    let client_engine = engine.client_engine_mut();
    client_engine.record_settlement_complete(
        node_id,
        trade_id,
        actual_latency_secs,
        expected_latency_secs,
        timestamp,
    );
    engine.update_reputation(node_id);
}

pub fn on_dispute_resolved(engine: &mut ReputationEngine, dispute: DisputeRecord) {
    let subject = dispute.subject;
    let penalty_amount = dispute.penalty_applied;
    let reason = dispute.reason.clone();
    let resolved_in_favor_of = dispute.resolved_in_favor_of;
    let now = engine.now();

    engine.resolve_dispute(dispute);

    if resolved_in_favor_of != subject {
        let penalty = PenaltyRecord {
            penalty_type: PenaltyType::StakePenalty(penalty_amount),
            amount: penalty_amount,
            applied_at: now,
            expires_at: f64::MAX,
            reason,
        };
        engine.apply_penalty(subject, penalty);

        let _ = engine
            .stake_manager_mut()
            .slash(subject, penalty_amount, SlashReason::DisputeLost);
    } else {
        ReputationMetrics::record_bad_trade();
    }

    engine.update_reputation(subject);
}

pub fn on_trade_disputed(
    engine: &mut ReputationEngine,
    node_id: NodeId,
    trade_id: [u8; 32],
    slippage_bps: f64,
    timestamp: f64,
) {
    let client_engine = engine.client_engine_mut();
    client_engine.record_dispute(node_id, trade_id, slippage_bps, timestamp);
    engine.update_reputation(node_id);
    ReputationMetrics::record_bad_trade();
}

pub fn periodic_reputation_update(engine: &mut ReputationEngine, node_ids: &[NodeId]) {
    for &node_id in node_ids {
        engine.update_reputation(node_id);
    }
}
