use common::NodeId;
use std::collections::HashMap;
use tracing::{info, warn};

use crate::metrics::ReputationMetrics;
use crate::types::*;

pub struct StakeManager {
    stakes: HashMap<NodeId, u64>,
    vesting_schedules: HashMap<NodeId, VestingSchedule>,
    bonds: HashMap<NodeId, Vec<ReputationBond>>,
    slashing_pool: u64,
}

#[derive(Debug, Clone)]
pub struct VestingSchedule {
    pub start_time: f64,
    pub total_amount: u64,
    pub unlocked_amount: u64,
    pub period_secs: f64,
}

#[derive(Debug)]
pub enum SlashReason {
    DisputeLost,
    MissedDeadline,
    CensorshipDetected,
    BondViolation,
    Custom(String),
}

impl StakeManager {
    pub fn new() -> Self {
        Self {
            stakes: HashMap::new(),
            vesting_schedules: HashMap::new(),
            bonds: HashMap::new(),
            slashing_pool: 0,
        }
    }

    pub fn stake(&mut self, node_id: NodeId, amount: u64, now: f64) {
        let vesting = VestingSchedule {
            start_time: now,
            total_amount: amount,
            unlocked_amount: 0,
            period_secs: 30.0 * 24.0 * 3600.0,
        };

        self.stakes.insert(node_id, amount);
        self.vesting_schedules.insert(node_id, vesting);

        info!(node = ?node_id, amount, "Stake registered");
    }

    pub fn add_stake(&mut self, node_id: NodeId, amount: u64) {
        let entry = self.stakes.entry(node_id).or_insert(0);
        *entry += amount;
    }

    pub fn calculate_vesting_progress(&self, node_id: NodeId, now: f64) -> f64 {
        let vesting = match self.vesting_schedules.get(&node_id) {
            Some(v) => v,
            None => return 0.0,
        };

        let elapsed = now - vesting.start_time;
        (elapsed / vesting.period_secs).clamp(0.0, 1.0)
    }

    pub fn get_effective_stake(&self, node_id: &NodeId) -> u64 {
        let staked = self.stakes.get(node_id).copied().unwrap_or(0);
        let vesting = self.vesting_schedules.get(node_id);
        let progress = if let Some(v) = vesting {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64();
            let elapsed = now - v.start_time;
            (elapsed / v.period_secs).clamp(0.0, 1.0)
        } else {
            0.0
        };

        (staked as f64 * progress) as u64
    }

    pub fn lock_bond(&mut self, node_id: NodeId, bond: ReputationBond) -> Result<(), String> {
        let staked = self.stakes.get(&node_id).copied().unwrap_or(0);
        if staked < bond.amount {
            return Err("Insufficient stake for bond".to_string());
        }

        let bond_type_label = match bond.bond_type {
            BondType::Watchtower => "watchtower",
            BondType::TSS => "tss",
            BondType::Settlement => "settlement",
            BondType::Validator => "validator",
        };

        let entry = self.bonds.entry(node_id).or_insert_with(Vec::new);
        entry.push(bond);

        ReputationMetrics::record_bond_active(bond_type_label);

        Ok(())
    }

    pub fn slash(
        &mut self,
        node_id: NodeId,
        amount: u64,
        reason: SlashReason,
    ) -> Result<u64, String> {
        let staked = self.stakes.get_mut(&node_id).ok_or("Node not found")?;
        let slash_amount = amount.min(*staked);
        *staked -= slash_amount;

        self.slashing_pool += slash_amount * 2 / 3;

        warn!(node = ?node_id, amount = slash_amount, ?reason, "Node slashed");

        Ok(slash_amount)
    }

    pub fn forfeit_bond(&mut self, node_id: NodeId, bond_type: BondType) -> Result<u64, String> {
        let bonds = self.bonds.get_mut(&node_id).ok_or("Node not found")?;

        if let Some(bond) = bonds
            .iter_mut()
            .find(|b| b.bond_type == bond_type && !b.forfeited)
        {
            bond.forfeited = true;
            bond.forfeited_at = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs_f64(),
            );
            bond.forfeit_reason = Some("Bond condition violated".to_string());

            let forfeit_amount = bond.amount / 2;
            let staked = self.stakes.get_mut(&node_id).ok_or("Node not found")?;
            *staked = staked.saturating_sub(forfeit_amount);
            self.slashing_pool += forfeit_amount;

            let bond_type_label = match bond_type {
                BondType::Watchtower => "watchtower",
                BondType::TSS => "tss",
                BondType::Settlement => "settlement",
                BondType::Validator => "validator",
            };
            ReputationMetrics::record_bond_forfeited(bond_type_label);

            warn!(node = ?node_id, amount = forfeit_amount, ?bond_type, "Bond forfeited");

            return Ok(forfeit_amount);
        }

        Err("Bond not found or already forfeited".to_string())
    }

    pub fn get_bonds(&self, node_id: &NodeId) -> &[ReputationBond] {
        static EMPTY: Vec<ReputationBond> = Vec::new();
        self.bonds
            .get(node_id)
            .map(|v| v.as_slice())
            .unwrap_or(&EMPTY)
    }

    pub fn check_bond_conditions(
        &self,
        node_id: &NodeId,
        uptime_percentage: f64,
        has_disputes_lost: bool,
    ) -> Vec<BondType> {
        let mut forfeited = Vec::new();
        let bonds = self.get_bonds(node_id);

        for bond in bonds {
            if bond.forfeited {
                continue;
            }
            for condition in &bond.conditions {
                let should_forfeit = match condition {
                    BondCondition::Uptime90Percent => uptime_percentage < 0.9,
                    BondCondition::NoDisputesLost => has_disputes_lost,
                    _ => false,
                };
                if should_forfeit {
                    forfeited.push(bond.bond_type.clone());
                    break;
                }
            }
        }

        forfeited
    }

    pub fn total_staked(&self) -> u64 {
        self.stakes.values().sum()
    }

    pub fn slashing_pool_balance(&self) -> u64 {
        self.slashing_pool
    }
}

impl Default for StakeManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stake_tracking() {
        let mut manager = StakeManager::new();
        manager.stake(NodeId(1), 1000, 0.0);
        assert_eq!(manager.stakes[&NodeId(1)], 1000);
    }

    #[test]
    fn test_slash_reduces_stake() {
        let mut manager = StakeManager::new();
        manager.stake(NodeId(1), 1000, 0.0);
        let result = manager.slash(NodeId(1), 500, SlashReason::Custom("test".into()));
        assert!(result.is_ok());
        assert_eq!(manager.stakes[&NodeId(1)], 500);
    }

    #[test]
    fn test_bond_lock_and_forfeit() {
        let mut manager = StakeManager::new();
        manager.stake(NodeId(1), 1000, 0.0);

        let bond = ReputationBond {
            bond_type: BondType::Watchtower,
            amount: 500,
            locked_until: f64::MAX,
            conditions: vec![BondCondition::Uptime90Percent],
            forfeited: false,
            forfeited_at: None,
            forfeit_reason: None,
        };

        manager.lock_bond(NodeId(1), bond).unwrap();
        assert_eq!(manager.get_bonds(&NodeId(1)).len(), 1);

        let result = manager.forfeit_bond(NodeId(1), BondType::Watchtower);
        assert!(result.is_ok());
        assert!(manager.stakes[&NodeId(1)] < 1000);
    }
}
