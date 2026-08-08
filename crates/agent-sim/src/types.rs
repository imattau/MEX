use common::OrderSide;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub id: String,
    pub name: String,
    pub persona: String,
    pub initial_capital: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStateSnapshot {
    pub id: String,
    pub balance: u64,
    pub position: u64,
    pub open_orders: Vec<OrderSnapshot>,
    pub pnl: i64,
    pub trade_count: u64,
    pub last_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderSnapshot {
    pub order_id: String,
    pub symbol: String,
    pub side: String,
    pub price: u64,
    pub amount: u64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TradeRecord {
    pub id: String,
    pub symbol: String,
    pub price: u64,
    pub amount: u64,
    pub seller: String,
    pub buyer: String,
    pub timestamp: f64,
    pub node_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookDepth {
    pub symbol: String,
    pub node_id: u32,
    pub region: String,
    pub bids: Vec<BidAskLevel>,
    pub asks: Vec<BidAskLevel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BidAskLevel {
    pub price: u64,
    pub total_amount: u64,
    pub order_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricePoint {
    pub timestamp: f64,
    pub mid_price: f64,
    pub last_trade_price: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSnapshot {
    pub id: u32,
    pub region: String,
    pub online: bool,
    pub order_count: usize,
    pub matches_this_step: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationStateSnapshot {
    pub virtual_time: f64,
    pub step_number: u64,
    pub symbol: String,
    pub nodes: Vec<NodeSnapshot>,
    pub book: BookDepth,
    pub agents: Vec<AgentStateSnapshot>,
    pub recent_trades: Vec<TradeRecord>,
    pub price_history: Vec<PricePoint>,
    pub total_volume: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRequest {
    pub agent_id: String,
    pub action: String,
    pub symbol: String,
    pub node_id: Option<u32>,
    pub side: Option<String>,
    pub price: Option<u64>,
    pub amount: Option<u64>,
    pub order_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResponse {
    pub status: String,
    pub message: String,
    pub order_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResponse {
    pub virtual_time: f64,
    pub step_number: u64,
    pub matches_this_step: Vec<TradeRecord>,
    pub state: SimulationStateSnapshot,
}

pub fn parse_order_side(s: &str) -> OrderSide {
    match s.to_lowercase().as_str() {
        "buy" => OrderSide::Buy,
        _ => OrderSide::Sell,
    }
}

pub fn order_id_to_hex(id: &[u8; 32]) -> String {
    id.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn hex_to_order_id(hex: &str) -> Option<[u8; 32]> {
    let hex = hex.trim_start_matches("0x");
    if hex.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        let byte_str = &hex[i * 2..i * 2 + 2];
        bytes[i] = u8::from_str_radix(byte_str, 16).ok()?;
    }
    Some(bytes)
}

pub fn trader_id_to_hex(id: &[u8; 32]) -> String {
    order_id_to_hex(id)
}

pub fn hex_to_trader_id(hex: &str) -> Option<[u8; 32]> {
    hex_to_order_id(hex)
}
