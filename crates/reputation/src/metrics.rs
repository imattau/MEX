use crate::types::TrustLevel;
use common::NodeId;
use metrics::{counter, gauge};

pub struct ReputationMetrics;

impl ReputationMetrics {
    pub fn record_reputation_score(node_id: NodeId, score: f64) {
        gauge!("reputation.score", "node_id" => node_id.0.to_string()).set(score);
    }

    pub fn record_trust_level(node_id: NodeId, level: TrustLevel) {
        let level_label = match level {
            TrustLevel::Newcomer => "newcomer",
            TrustLevel::Contributor => "contributor",
            TrustLevel::Trusted => "trusted",
            TrustLevel::Elite => "elite",
            TrustLevel::Banned => "banned",
        };
        gauge!("reputation.trust_level", "node_id" => node_id.0.to_string(), "level" => level_label.to_string()).set(1.0);
    }

    pub fn record_p2p_score(node_id: NodeId, score: f64) {
        gauge!("reputation.p2p_score", "node_id" => node_id.0.to_string()).set(score);
    }

    pub fn record_client_score(node_id: NodeId, score: f64) {
        gauge!("reputation.client_score", "node_id" => node_id.0.to_string()).set(score);
    }

    pub fn record_effective_stake(node_id: NodeId, stake: u64) {
        gauge!("reputation.stake_effective", "node_id" => node_id.0.to_string()).set(stake as f64);
    }

    pub fn record_penalty_applied() {
        counter!("reputation.penalties.applied").increment(1);
    }

    pub fn record_dispute_resolved() {
        counter!("reputation.disputes.resolved").increment(1);
    }

    pub fn record_good_trade() {
        counter!("reputation.good_trades").increment(1);
    }

    pub fn record_bad_trade() {
        counter!("reputation.bad_trades").increment(1);
    }

    pub fn record_bond_active(bond_type_label: &str) {
        gauge!("reputation.bonds.active", "bond_type" => bond_type_label.to_string())
            .increment(1.0);
    }

    pub fn record_bond_forfeited(bond_type_label: &str) {
        gauge!("reputation.bonds.active", "bond_type" => bond_type_label.to_string())
            .decrement(1.0);
    }

    pub fn record_node_joined(_node_id: NodeId) {
        counter!("reputation.nodes.joined").increment(1);
        gauge!("reputation.nodes.total").increment(1.0);
    }

    pub fn record_node_left(_node_id: NodeId) {
        gauge!("reputation.nodes.total").decrement(1.0);
    }
}
