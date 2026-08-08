use common::{FeeCalculator, Order, SettlementPreference};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Match {
    pub maker_order_id: [u8; 32],
    pub taker_order_id: [u8; 32],
    pub maker_trader: [u8; 32],
    pub taker_trader: [u8; 32],
    pub price: u64,
    pub amount: u64,
    pub timestamp_us: u64,
    pub settlement_tier: SettlementPreference,
    pub fee_basis_points: u32,
    pub seller: [u8; 32],
    pub fee_payer: [u8; 32],
    pub settlement_deadline: u64,
    pub symbol: String,
    pub assigned_node: [u8; 32],
}

pub struct OrderBook {
    pub symbol: String,
    pub bids: BTreeMap<u64, Vec<Order>>,
    pub asks: BTreeMap<u64, Vec<Order>>,
    pub node_rewards: u64,
    pub(crate) active_nodes: Vec<[u8; 32]>,
    pub(crate) next_node_index: usize,
    // Defaults (via FeeCalculator::default()) to exactly the old fixed
    // 5/15/50 bps schedule -- see set_fee_calculator to make fees actually
    // respond to real gas price / expected batch efficiency.
    pub fee_calculator: FeeCalculator,
}
