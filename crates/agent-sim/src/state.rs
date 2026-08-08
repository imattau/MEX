use crate::agent_state::AgentTracker;
use crate::types::{
    AgentConfig, BidAskLevel, BookDepth, PricePoint, SimulationStateSnapshot,
    TradeRecord, order_id_to_hex, trader_id_to_hex,
};
use engine::{Match, OrderBook};

pub struct SimulationState {
    pub book: OrderBook,
    pub agents: AgentTracker,
    pub virtual_time: f64,
    pub step_number: u64,
    pub recent_trades: Vec<TradeRecord>,
    pub price_history: Vec<PricePoint>,
    pub total_volume: u64,
    pub matches_buffer: Vec<Match>,
}

impl SimulationState {
    pub fn new(symbol: String) -> Self {
        Self {
            book: OrderBook::new(symbol),
            agents: AgentTracker::new(),
            virtual_time: 0.0,
            step_number: 0,
            recent_trades: Vec::new(),
            price_history: Vec::new(),
            total_volume: 0,
            matches_buffer: Vec::new(),
        }
    }

    pub fn register_agent(&mut self, config: AgentConfig) {
        self.agents.register(config);
    }

    pub fn get_book_depth(&self) -> BookDepth {
        let symbol = self.book.symbol.clone();
        let bids: Vec<BidAskLevel> = self
            .book
            .bids
            .iter()
            .rev()
            .take(50)
            .map(|(price, orders)| {
                let total: u64 = orders.iter().map(|o| o.amount).sum();
                BidAskLevel {
                    price: *price,
                    total_amount: total,
                    order_count: orders.len(),
                }
            })
            .collect();

        let asks: Vec<BidAskLevel> = self
            .book
            .asks
            .iter()
            .take(50)
            .map(|(price, orders)| {
                let total: u64 = orders.iter().map(|o| o.amount).sum();
                BidAskLevel {
                    price: *price,
                    total_amount: total,
                    order_count: orders.len(),
                }
            })
            .collect();

        BookDepth {
            symbol,
            bids,
            asks,
        }
    }

    pub fn mid_price(&self) -> Option<f64> {
        let best_bid = self.book.bids.keys().rev().next().copied();
        let best_ask = self.book.asks.keys().next().copied();
        match (best_bid, best_ask) {
            (Some(bid), Some(ask)) => Some((bid as f64 + ask as f64) / 2.0),
            (Some(bid), None) => Some(bid as f64),
            (None, Some(ask)) => Some(ask as f64),
            (None, None) => None,
        }
    }

    pub fn snapshot(&mut self) -> SimulationStateSnapshot {
        let mp = self.mid_price();
        let last_trade_price = self.recent_trades.last().map(|t| t.price);

        let pp = PricePoint {
            timestamp: self.virtual_time,
            mid_price: mp.unwrap_or(0.0),
            last_trade_price,
        };
        self.price_history.push(pp.clone());

        SimulationStateSnapshot {
            virtual_time: self.virtual_time,
            step_number: self.step_number,
            symbol: self.book.symbol.clone(),
            book: self.get_book_depth(),
            agents: self.agents.all_snapshots(&self.book.symbol),
            recent_trades: self.recent_trades.clone(),
            price_history: self.price_history.clone(),
            total_volume: self.total_volume,
        }
    }

    pub fn drain_matches_for_trader(&mut self, agent_trader_bytes: &[u8; 32]) -> Vec<TradeRecord> {
        let mut relevant = Vec::new();
        let mut remaining = Vec::new();

        for m in self.matches_buffer.drain(..) {
            if m.maker_trader == *agent_trader_bytes || m.taker_trader == *agent_trader_bytes {
                let record = TradeRecord {
                    id: order_id_to_hex(&m.maker_order_id),
                    symbol: m.symbol.clone(),
                    price: m.price,
                    amount: m.amount,
                    seller: trader_id_to_hex(&m.seller),
                    buyer: trader_id_to_hex(&m.fee_payer),
                    timestamp: self.virtual_time,
                };
                relevant.push(record);
            } else {
                remaining.push(m);
            }
        }
        self.matches_buffer = remaining;
        relevant
    }
}
