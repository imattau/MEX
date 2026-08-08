use crate::types::{AgentConfig, AgentStateSnapshot, OrderSnapshot, order_id_to_hex};
use common::Order;
use std::collections::HashMap;

pub struct AgentTracker {
    agents: HashMap<String, AgentRecord>,
}

struct AgentRecord {
    config: AgentConfig,
    balance: u64,
    position: u64,
    position_avg_price: u64,
    open_orders: Vec<Order>,
    realized_pnl: i64,
    trade_count: u64,
    last_action: String,
}

impl AgentTracker {
    pub fn new() -> Self {
        Self {
            agents: HashMap::new(),
        }
    }

    pub fn register(&mut self, config: AgentConfig) {
        self.agents.insert(
            config.id.clone(),
            AgentRecord {
                balance: config.initial_capital,
                position: 0,
                position_avg_price: 0,
                open_orders: Vec::new(),
                realized_pnl: 0,
                trade_count: 0,
                last_action: "none".to_string(),
                config,
            },
        );
    }

    pub fn get_trader_bytes(&self, agent_id: &str) -> Option<[u8; 32]> {
        self.agents.get(agent_id).map(|a| {
            let mut bytes = [0u8; 32];
            let id_bytes = a.config.id.as_bytes();
            let len = id_bytes.len().min(32);
            bytes[..len].copy_from_slice(&id_bytes[..len]);
            bytes
        })
    }

    pub fn get_balance(&self, agent_id: &str) -> Option<u64> {
        self.agents.get(agent_id).map(|a| a.balance)
    }

    pub fn get_position(&self, agent_id: &str) -> Option<u64> {
        self.agents.get(agent_id).map(|a| a.position)
    }

    pub fn add_order(&mut self, agent_id: &str, order: Order) {
        if let Some(agent) = self.agents.get_mut(agent_id) {
            agent.open_orders.push(order);
            agent.last_action = "place_order".to_string();
        }
    }

    pub fn cancel_order(&mut self, agent_id: &str, order_id: &[u8; 32]) -> bool {
        if let Some(agent) = self.agents.get_mut(agent_id) {
            if let Some(pos) = agent.open_orders.iter().position(|o| o.id == *order_id) {
                agent.open_orders.remove(pos);
                agent.last_action = "cancel_order".to_string();
                return true;
            }
        }
        false
    }

    pub fn record_trade_buy(
        &mut self,
        agent_id: &str,
        amount: u64,
        price: u64,
        order_id: &[u8; 32],
    ) {
        if let Some(agent) = self.agents.get_mut(agent_id) {
            let total_cost = amount as u128 * price as u128;
            agent.balance = agent.balance.saturating_sub(total_cost as u64);
            let old_value = agent.position as u128 * agent.position_avg_price as u128;
            let new_value = amount as u128 * price as u128;
            let new_total = agent.position as u128 + amount as u128;
            agent.position_avg_price = if new_total > 0 {
                ((old_value + new_value) / new_total) as u64
            } else {
                0
            };
            agent.position += amount;
            agent.trade_count += 1;
            agent.open_orders.retain(|o| o.id != *order_id);
            agent.last_action = "trade_executed".to_string();
        }
    }

    pub fn record_trade_sell(
        &mut self,
        agent_id: &str,
        amount: u64,
        price: u64,
        order_id: &[u8; 32],
    ) {
        if let Some(agent) = self.agents.get_mut(agent_id) {
            let revenue = amount as u128 * price as u128;
            let cost_basis = if agent.position > 0 {
                amount as u128 * agent.position_avg_price as u128
            } else {
                0
            };
            agent.balance = agent.balance.saturating_add(revenue as u64);
            agent.position = agent.position.saturating_sub(amount);
            agent.realized_pnl += revenue as i64 - cost_basis as i64;
            agent.trade_count += 1;
            agent.open_orders.retain(|o| o.id != *order_id);
            agent.last_action = "trade_executed".to_string();
        }
    }

    pub fn snapshot(&self, agent_id: &str) -> Option<AgentStateSnapshot> {
        self.agents.get(agent_id).map(|agent| {
            AgentStateSnapshot {
                id: agent.config.id.clone(),
                balance: agent.balance,
                position: agent.position,
                open_orders: agent
                    .open_orders
                    .iter()
                    .map(|o| OrderSnapshot {
                        order_id: order_id_to_hex(&o.id),
                        symbol: o.symbol.clone(),
                        side: format!("{:?}", o.side).to_lowercase(),
                        price: o.price,
                        amount: o.amount,
                        status: "open".to_string(),
                    })
                    .collect(),
                pnl: agent.realized_pnl,
                trade_count: agent.trade_count,
                last_action: agent.last_action.clone(),
            }
        })
    }

    pub fn all_snapshots(&self) -> Vec<AgentStateSnapshot> {
        self.agents
            .keys()
            .filter_map(|id| self.snapshot(id))
            .collect()
    }

    pub fn agent_ids(&self) -> Vec<String> {
        self.agents.keys().cloned().collect()
    }
}
