mod ledger;

pub use ledger::BalanceLedger;

use common::{NodeId, SettlementPreference};
use engine::Match;
use prover::{TradeBatch, BACKEND, ProverBackend};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub struct SettlementBatcher {
    standard_queue: VecDeque<Match>,
    express_queue: VecDeque<Match>,
    instant_queue: VecDeque<Match>,
    standard_timer: Instant,
    express_timer: Instant,
    standard_batch_size: usize,
    express_batch_size: usize,
    standard_interval: Duration,
    express_interval: Duration,
    prover: &'static dyn ProverBackend,
    node_id: NodeId,
    reputation: Option<reputation::ReputationEngine>,
    ledger: BalanceLedger,
}

impl SettlementBatcher {
    pub fn new() -> Self {
        Self {
            standard_queue: VecDeque::new(),
            express_queue: VecDeque::new(),
            instant_queue: VecDeque::new(),
            standard_timer: Instant::now(),
            express_timer: Instant::now(),
            standard_batch_size: 1000,
            express_batch_size: 100,
            standard_interval: Duration::from_secs(10),
            express_interval: Duration::from_secs(60),
            prover: &BACKEND,
            node_id: NodeId(0),
            reputation: None,
            ledger: BalanceLedger::new(),
        }
    }

    // Records a balance for a trader in the simulated ledger (e.g. standing in for an
    // on-chain deposit until real chain event listening exists). Without a deposit, a
    // trader's balance is 0 and any trade against it is treated as insolvent.
    pub fn deposit(&mut self, trader: [u8; 32], symbol: &str, amount: u64) {
        self.ledger.deposit(trader, symbol, amount);
    }

    pub fn balance_of(&self, trader: [u8; 32], symbol: &str) -> u64 {
        self.ledger.balance_of(trader, symbol)
    }

    pub fn with_reputation(mut self, node_id: NodeId, engine: reputation::ReputationEngine) -> Self {
        self.node_id = node_id;
        self.reputation = Some(engine);
        self
    }

    pub fn enqueue(&mut self, trade: Match) {
        match trade.settlement_tier {
            SettlementPreference::Instant => {
                tracing::debug!(trade_id = ?trade.maker_order_id, "Enqueued for instant settlement");
                self.instant_queue.push_back(trade);
            }
            SettlementPreference::Express => {
                self.express_queue.push_back(trade);
            }
            SettlementPreference::Standard => {
                self.standard_queue.push_back(trade);
            }
        }
    }

    pub fn process_batches(&mut self) -> Vec<SettlementBatch> {
        let mut batches = Vec::new();

        if let Some(batch) = self.try_flush_instant() {
            batches.push(batch);
        }

        if let Some(batch) = self.try_flush_express() {
            batches.push(batch);
        }

        if let Some(batch) = self.try_flush_standard() {
            batches.push(batch);
        }

        if let Some(ref mut engine) = self.reputation {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64();
            for batch in &batches {
                for trade in &batch.trades {
                    let expected = trade.settlement_tier.deadline_seconds() as f64;
                    reputation::integration::on_settlement_complete(
                        engine,
                        self.node_id,
                        trade.maker_order_id,
                        0.0,
                        expected,
                        now,
                    );
                }
            }
        }

        batches
    }

    fn try_flush_instant(&mut self) -> Option<SettlementBatch> {
        if let Some(trade) = self.instant_queue.pop_front() {
            tracing::info!(
                trade_id = ?trade.maker_order_id,
                "Processing instant settlement (single trade)"
            );
            let batch = self.build_batch(vec![trade], SettlementPreference::Instant);
            Some(batch)
        } else {
            None
        }
    }

    fn try_flush_express(&mut self) -> Option<SettlementBatch> {
        let should_flush = self.express_queue.len() >= self.express_batch_size
            || self.express_timer.elapsed() >= self.express_interval;

        if should_flush && !self.express_queue.is_empty() {
            let trades: Vec<Match> = self.express_queue.drain(..).collect();
            tracing::info!(
                count = trades.len(),
                "Processing express settlement batch"
            );
            self.express_timer = Instant::now();
            let batch = self.build_batch(trades, SettlementPreference::Express);
            Some(batch)
        } else {
            None
        }
    }

    fn try_flush_standard(&mut self) -> Option<SettlementBatch> {
        let should_flush = self.standard_queue.len() >= self.standard_batch_size
            || self.standard_timer.elapsed() >= self.standard_interval;

        if should_flush && !self.standard_queue.is_empty() {
            let trades: Vec<Match> = self.standard_queue.drain(..).collect();
            tracing::info!(
                count = trades.len(),
                "Processing standard settlement batch"
            );
            self.standard_timer = Instant::now();
            let batch = self.build_batch(trades, SettlementPreference::Standard);
            Some(batch)
        } else {
            None
        }
    }

    // The circuit backing prove_batch only supports one trade per proof (see
    // crates/prover/src/bn254.rs), so batching here means proving each trade
    // individually against its traders' real (simulated) balances, rather than
    // amortizing a single proof over the whole batch. A trade that would be
    // insolvent against the ledger is dropped from the batch with a warning
    // instead of silently shipping an empty/invalid proof for it.
    fn build_batch(&mut self, trades: Vec<Match>, _tier: SettlementPreference) -> SettlementBatch {
        let mut proven_trades = Vec::with_capacity(trades.len());
        let mut proofs = Vec::with_capacity(trades.len());
        let mut total_value: u64 = 0;

        for trade in trades {
            let trade_value = trade.price as u64 * trade.amount as u64;
            let maker_balance = self.ledger.balance_of(trade.maker_trader, &trade.symbol);
            let taker_balance = self.ledger.balance_of(trade.taker_trader, &trade.symbol);

            let single_trade_batch = TradeBatch {
                trades: vec![trade.clone()],
                maker_balance,
                taker_balance,
                pre_state_root: [0u8; 32],
                post_state_root: [0u8; 32],
            };

            match self.prover.prove_batch(&single_trade_batch) {
                Ok(proof) => {
                    // prove_batch already checked trade_value <= taker_balance, so
                    // these ledger updates cannot fail.
                    self.ledger.credit(trade.maker_trader, &trade.symbol, trade_value);
                    self.ledger
                        .debit(trade.taker_trader, &trade.symbol, trade_value)
                        .expect("prove_batch already verified sufficient taker balance");

                    total_value += trade_value;
                    proven_trades.push(trade);
                    proofs.push(proof);
                }
                Err(reason) => {
                    tracing::warn!(
                        trade_id = ?trade.maker_order_id,
                        reason,
                        "Dropping trade from settlement batch: proof generation failed"
                    );
                }
            }
        }

        SettlementBatch {
            trades: proven_trades,
            total_value,
            proofs,
        }
    }
}

impl Default for SettlementBatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct SettlementBatch {
    pub trades: Vec<Match>,
    pub total_value: u64,
    // One proof per entry in `trades`, aligned by index. Trades that failed
    // to prove (e.g. insolvent against the ledger) are omitted from both.
    pub proofs: Vec<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{OrderSide, SettlementRequester};

    fn make_match(tier: SettlementPreference, id_seed: u8) -> Match {
        Match {
            maker_order_id: [id_seed; 32],
            taker_order_id: [id_seed + 1; 32],
            maker_trader: [1u8; 32],
            taker_trader: [2u8; 32],
            price: 100,
            amount: 10,
            timestamp_us: 0,
            settlement_tier: tier,
            fee_basis_points: tier.fee_basis_points(),
            seller: [2u8; 32],
            fee_payer: [2u8; 32],
            symbol: "BTC-USD".to_string(),
            settlement_deadline: 0,
        }
    }

    #[test]
    fn test_instant_trade_flushes_immediately() {
        let mut batcher = SettlementBatcher::new();
        batcher.deposit([2u8; 32], "BTC-USD", 1_000_000);
        batcher.enqueue(make_match(SettlementPreference::Instant, 1));

        let batches = batcher.process_batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].trades.len(), 1);
        assert_eq!(batches[0].proofs.len(), 1);
        assert!(!batches[0].proofs[0].is_empty());
    }

    #[test]
    fn test_insolvent_trade_is_dropped_not_faked() {
        let mut batcher = SettlementBatcher::new();
        // No deposit -- taker has a 0 balance, trade value is 1000.
        batcher.enqueue(make_match(SettlementPreference::Instant, 1));

        let batches = batcher.process_batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].trades.len(), 0, "insolvent trade must be dropped, not proven with a fake balance");
        assert_eq!(batches[0].proofs.len(), 0);
    }

    #[test]
    fn test_standard_batch_waits_for_size() {
        let mut batcher = SettlementBatcher::new();
        batcher.deposit([2u8; 32], "BTC-USD", 1_000_000);
        batcher.standard_batch_size = 3;

        batcher.enqueue(make_match(SettlementPreference::Standard, 1));
        batcher.enqueue(make_match(SettlementPreference::Standard, 2));

        let batches = batcher.process_batches();
        assert_eq!(batches.len(), 0);

        batcher.enqueue(make_match(SettlementPreference::Standard, 3));

        let batches = batcher.process_batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].trades.len(), 3);
    }

    #[test]
    fn test_mixed_tiers_flush_correctly() {
        let mut batcher = SettlementBatcher::new();
        batcher.deposit([2u8; 32], "BTC-USD", 1_000_000);
        batcher.express_batch_size = 2;

        batcher.enqueue(make_match(SettlementPreference::Standard, 1));
        batcher.enqueue(make_match(SettlementPreference::Instant, 2));
        batcher.enqueue(make_match(SettlementPreference::Express, 3));
        batcher.enqueue(make_match(SettlementPreference::Express, 4));

        let batches = batcher.process_batches();
        assert_eq!(batches.len(), 2); // instant + express

        let has_instant = batches.iter().any(|b| b.trades.len() == 1);
        let has_express = batches.iter().any(|b| b.trades.len() == 2);
        assert!(has_instant);
        assert!(has_express);
    }

    #[test]
    fn test_express_timer_flush() {
        let mut batcher = SettlementBatcher::new();
        batcher.express_batch_size = 1000; // large so only timer matters
        batcher.express_interval = Duration::from_millis(1);

        batcher.enqueue(make_match(SettlementPreference::Express, 1));
        std::thread::sleep(Duration::from_millis(5));

        let batches = batcher.process_batches();
        assert_eq!(batches.len(), 1);
    }
}
