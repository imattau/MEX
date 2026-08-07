use common::Order;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Match {
    pub maker_order_id: [u8; 32],
    pub taker_order_id: [u8; 32],
    pub price: u64,
    pub amount: u64,
    pub timestamp_us: u64,
}

pub struct OrderBook {
    pub symbol: String,
    pub bids: BTreeMap<u64, Vec<Order>>,
    pub asks: BTreeMap<u64, Vec<Order>>,
}
