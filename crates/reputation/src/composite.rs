use common::NodeId;
use std::collections::HashMap;
use tracing::{info, warn};

use crate::client_score::ClientScoreAggregator;
use crate::metrics::ReputationMetrics;
use crate::p2p_score::{P2PScoreEngine, P2PScoreUpdate};
use crate::stake::StakeManager;
use crate::types::*;

const SCORE_P2P_WEIGHT: f64 = 0.6;
const SCORE_CLIENT_WEIGHT: f64 = 0.4;
const LOYALTY_AGE_SCALE: f64 = 86_400.0;
const RECOVERY_RATE_PER_SECOND: f64 = 0.0001;

pub struct ReputationEngine {
    p2p_engine: P2PScoreEngine,
    client_engine: ClientScoreAggregator,
    stake_manager: StakeManager,
    states: HashMap<NodeId, ReputationState>,
    p2p_metrics: HashMap<NodeId, P2PMetrics>,
}

impl ReputationEngine {
    pub fn new() -> Self {
        Self {
            p2p_engine: P2PScoreEngine::new(),
            client_engine: ClientScoreAggregator::new(),
            stake_manager: StakeManager::new(),
            states: HashMap::new(),
            p2p_metrics: HashMap::new(),
        }
    }

    pub fn now(&self) -> f64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64()
    }

    pub fn register_node(&mut self, node_id: NodeId, stake: u64) -> &ReputationState {
        let now = self.now();
        let state = ReputationState::new(node_id, now);

        if stake > 0 {
            self.stake_manager.stake(node_id, stake, now);
        }

        self.states.insert(node_id, state);
        self.p2p_metrics.insert(node_id, P2PMetrics::default());
        ReputationMetrics::record_node_joined(node_id);

        info!(node = ?node_id, stake, "Node registered for reputation tracking");

        self.states.get(&node_id).unwrap()
    }

    pub fn update_p2p_metrics(&mut self, node_id: NodeId, update: P2PScoreUpdate) {
        let now = self.now();
        let metrics = self.p2p_metrics.entry(node_id).or_default();

        if let Some(rtt) = update.echo_rtt_ms {
            metrics.echo_rtt_ms = rtt;
        }
        if update.heartbeat_miss {
            metrics.heartbeat_miss_count += 1;
        }
        if update.censorship_flag {
            metrics.censorship_flags += 1;
        }
        if update.flood_relayed {
            metrics.flood_relay_count += 1;
        }
        if update.flood_dropped {
            metrics.flood_drop_count += 1;
        }

        metrics.last_heartbeat_time = now;
    }

    pub fn record_heartbeat_ok(&mut self, node_id: NodeId) {
        let now = self.now();
        let metrics = self.p2p_metrics.entry(node_id).or_default();
        metrics.heartbeat_miss_count = 0;
        metrics.last_heartbeat_time = now;
    }

    pub fn update_reputation(&mut self, node_id: NodeId) -> f64 {
        let now = self.now();

        {
            let state = match self.states.get_mut(&node_id) {
                Some(s) => s,
                None => {
                    self.register_node(node_id, 0);
                    self.states.get_mut(&node_id).unwrap()
                }
            };

            let metrics = self.p2p_metrics.entry(node_id).or_default();
            let raw_p2p = self.p2p_engine.compute_p2p_score(node_id, metrics);
            let p2p_score = self.p2p_engine.update_and_smooth(node_id, raw_p2p);
            state.p2p_score = p2p_score;

            let client_score = self.client_engine.recompute_score(node_id);
            state.client_score = client_score;

            let composite_score =
                (p2p_score * SCORE_P2P_WEIGHT) + (client_score * SCORE_CLIENT_WEIGHT);
            state.composite_score = composite_score.clamp(0.0, 1.0);

            let vesting_progress = self.stake_manager.calculate_vesting_progress(node_id, now);
            let effective_stake =
                self.stake_manager.get_effective_stake(&node_id) as f64 * vesting_progress;

            let loyalty_mult = calculate_loyalty_multiplier(state, now);
            let id_penalty = calculate_id_penalty(state, now);
            let base_score =
                state.composite_score * (effective_stake / 1000.0).clamp(0.0, 10.0).max(0.5);

            let mut reputation = (base_score * loyalty_mult * id_penalty).clamp(0.0, 100.0);

            let recovery_mult = calculate_recovery_multiplier(state, now);
            reputation *= recovery_mult;

            state.reputation_score = reputation;
            state.trust_level = determine_trust_level(state, now, &self.stake_manager);
            state.last_seen = now;
            state.total_uptime_secs += 0.1;

            let total_time = state.total_uptime_secs + state.total_downtime_secs;
            if total_time > 0.0 {
                state.uptime_percentage = state.total_uptime_secs / total_time;
            }

            ReputationMetrics::record_reputation_score(node_id, state.reputation_score);
            ReputationMetrics::record_trust_level(node_id, state.trust_level);
            ReputationMetrics::record_p2p_score(node_id, state.p2p_score);
            ReputationMetrics::record_client_score(node_id, state.client_score);
            ReputationMetrics::record_effective_stake(node_id, effective_stake as u64);

            state.reputation_score
        }
    }

    pub fn record_downtime(&mut self, node_id: NodeId, duration_secs: f64) {
        if let Some(state) = self.states.get_mut(&node_id) {
            state.total_downtime_secs += duration_secs;
            let total = state.total_uptime_secs + state.total_downtime_secs;
            if total > 0.0 {
                state.uptime_percentage = state.total_uptime_secs / total;
            }
        }
    }

    pub fn record_id_change(&mut self, node_id: NodeId) {
        let now = self.now();
        if let Some(state) = self.states.get_mut(&node_id) {
            state.id_change_count += 1;
            state.last_id_change = now;
            warn!(node = ?node_id, change_count = state.id_change_count, "Node ID change recorded");
        }
    }

    pub fn apply_penalty(&mut self, node_id: NodeId, penalty: PenaltyRecord) {
        let now = self.now();
        if let Some(state) = self.states.get_mut(&node_id) {
            state.penalty_history.push(penalty.clone());

            match &penalty.penalty_type {
                PenaltyType::ReputationPenalty(amount) => {
                    state.reputation_score = (state.reputation_score - *amount).max(0.0);
                }
                PenaltyType::StakePenalty(amount) => {
                    state.staked_amount = state.staked_amount.saturating_sub(*amount);
                }
                PenaltyType::BondForfeiture(bond_type) => {
                    let _ = self.stake_manager.forfeit_bond(node_id, bond_type.clone());
                    state
                        .bonds
                        .retain(|b| b.bond_type != *bond_type || !b.forfeited);
                }
                PenaltyType::Downgrade => {
                    state.trust_level = TrustLevel::Newcomer;
                }
                PenaltyType::TemporaryBan(_) | PenaltyType::PermanentBan => {
                    state.trust_level = TrustLevel::Banned;
                }
            }

            state.recovery_start = Some(now);
            ReputationMetrics::record_penalty_applied();
        }
    }

    pub fn resolve_dispute(&mut self, record: DisputeRecord) {
        let now = self.now();
        if let Some(state) = self.states.get_mut(&record.subject) {
            state.dispute_history.push(record.clone());

            if record.resolved_in_favor_of != record.subject {
                let penalty = PenaltyRecord {
                    penalty_type: PenaltyType::ReputationPenalty(0.5),
                    amount: record.penalty_applied,
                    applied_at: now,
                    expires_at: f64::MAX,
                    reason: record.reason.clone(),
                };
                state.penalty_history.push(penalty);
                state.recovery_start = Some(now);
            }

            ReputationMetrics::record_dispute_resolved();
        }
    }

    pub fn get_state(&self, node_id: &NodeId) -> Option<&ReputationState> {
        self.states.get(node_id)
    }

    pub fn get_state_mut(&mut self, node_id: &NodeId) -> Option<&mut ReputationState> {
        self.states.get_mut(node_id)
    }

    pub fn get_trust_level(&self, node_id: &NodeId) -> TrustLevel {
        self.states
            .get(node_id)
            .map(|s| s.trust_level)
            .unwrap_or(TrustLevel::Newcomer)
    }

    pub fn client_engine_mut(&mut self) -> &mut ClientScoreAggregator {
        &mut self.client_engine
    }

    pub fn stake_manager_mut(&mut self) -> &mut StakeManager {
        &mut self.stake_manager
    }
}

impl Default for ReputationEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn calculate_loyalty_multiplier(state: &ReputationState, now: f64) -> f64 {
    let age_secs = now - state.first_seen;
    let age_factor = (age_secs / LOYALTY_AGE_SCALE).clamp(0.0, 10.0);
    let uptime_factor = state.uptime_percentage;
    1.0 + (age_factor * uptime_factor * 0.1)
}

fn calculate_id_penalty(state: &ReputationState, now: f64) -> f64 {
    if state.id_change_count == 0 {
        return 1.0;
    }

    let base_penalty = 0.5;
    let max_penalty = 0.9;
    let penalty = (base_penalty + (state.id_change_count as f64 * 0.1)).min(max_penalty);

    let time_since_change = now - state.last_id_change;
    let decay = (time_since_change / LOYALTY_AGE_SCALE).clamp(0.0, 1.0);
    let effective_penalty = penalty * (1.0 - decay * 0.5);

    1.0 - effective_penalty.clamp(0.0, 1.0)
}

fn calculate_recovery_multiplier(state: &ReputationState, now: f64) -> f64 {
    if state.penalty_history.is_empty() || state.reputation_score >= 50.0 {
        return 1.0;
    }

    let recovery_start = state.recovery_start.unwrap_or(now);
    let elapsed = now - recovery_start;
    let recovery = elapsed * RECOVERY_RATE_PER_SECOND;
    let capped_recovery = recovery.min(0.5);

    if state.reputation_score < 10.0 {
        1.0 + capped_recovery
    } else {
        1.0
    }
}

fn determine_trust_level(
    state: &ReputationState,
    now: f64,
    _stake_mgr: &StakeManager,
) -> TrustLevel {
    for penalty in &state.penalty_history {
        match &penalty.penalty_type {
            PenaltyType::PermanentBan => return TrustLevel::Banned,
            PenaltyType::TemporaryBan(expires) => {
                if now < *expires {
                    return TrustLevel::Banned;
                }
            }
            _ => {}
        }
    }

    let has_tss_bond = state
        .bonds
        .iter()
        .any(|b| b.bond_type == BondType::TSS && !b.forfeited);
    let has_watchtower_bond = state
        .bonds
        .iter()
        .any(|b| b.bond_type == BondType::Watchtower && !b.forfeited);

    match state.reputation_score {
        s if s < 0.1 => TrustLevel::Banned,
        s if s < 0.5 => TrustLevel::Newcomer,
        s if s < 10.0 => {
            if has_watchtower_bond {
                TrustLevel::Contributor
            } else {
                TrustLevel::Newcomer
            }
        }
        s if s < 50.0 => {
            if has_tss_bond {
                TrustLevel::Trusted
            } else {
                TrustLevel::Contributor
            }
        }
        _ => {
            if has_tss_bond && state.staked_amount > 100_000 {
                TrustLevel::Elite
            } else {
                TrustLevel::Trusted
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_node_initial_score() {
        let mut engine = ReputationEngine::new();
        let score = engine.update_reputation(NodeId(1));
        assert!(score >= 0.0);
        let state = engine.get_state(&NodeId(1)).unwrap();
        assert_eq!(state.trust_level, TrustLevel::Newcomer);
    }

    #[test]
    fn test_id_change_penalty() {
        let mut engine = ReputationEngine::new();
        engine.register_node(NodeId(1), 1000);
        engine.update_reputation(NodeId(1));
        engine.record_id_change(NodeId(1));
        let state = engine.get_state(&NodeId(1)).unwrap();
        assert_eq!(state.id_change_count, 1);
    }

    #[test]
    fn test_penalty_reduces_score() {
        let mut engine = ReputationEngine::new();
        engine.register_node(NodeId(1), 5000);
        engine.update_reputation(NodeId(1));

        engine.apply_penalty(
            NodeId(1),
            PenaltyRecord {
                penalty_type: PenaltyType::ReputationPenalty(20.0),
                amount: 0,
                applied_at: engine.now(),
                expires_at: f64::MAX,
                reason: "test".to_string(),
            },
        );

        let state = engine.get_state(&NodeId(1)).unwrap();
        assert!(state.reputation_score < 50.0);
    }
}
