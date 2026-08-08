mod ledger;

pub use ledger::BalanceLedger;

use common::{NodeId, SettlementPreference};
use engine::Match;
use prover::{TradeBatch, BACKEND, ProverBackend, MAX_BATCH_TRADES};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn u64_to_bytes32(val: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&val.to_be_bytes());
    out
}

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
    ledger: Arc<Mutex<BalanceLedger>>,
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
            ledger: Arc::new(Mutex::new(BalanceLedger::new())),
        }
    }

    // Shares an externally-owned ledger (e.g. one a chain-sync service is
    // keeping up to date with real deposits/withdrawals) instead of the
    // private, purely-simulated one `new()` creates. The batcher and
    // whoever else holds a clone of `ledger` see and mutate the same state.
    pub fn with_ledger(mut self, ledger: Arc<Mutex<BalanceLedger>>) -> Self {
        self.ledger = ledger;
        self
    }

    pub fn ledger(&self) -> Arc<Mutex<BalanceLedger>> {
        self.ledger.clone()
    }

    // Records a balance for a trader in the ledger directly (e.g. for tests, or to
    // stand in for a real deposit before chain-sync is wired up). Without a deposit,
    // a trader's balance is 0 and any trade against it is treated as insolvent.
    pub fn deposit(&mut self, trader: [u8; 32], symbol: &str, amount: u64) {
        self.ledger
            .lock()
            .expect("ledger mutex poisoned")
            .deposit(trader, symbol, amount);
    }

    pub fn balance_of(&self, trader: [u8; 32], symbol: &str) -> u64 {
        self.ledger
            .lock()
            .expect("ledger mutex poisoned")
            .balance_of(trader, symbol)
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

    // The circuit backing prove_batch supports up to MAX_BATCH_TRADES trades
    // per proof, each with its own independent maker/taker pair (see
    // crates/prover's DEXBatchCircuit docs) -- so trades here are grouped
    // into chunks of that size and proven together, amortizing one proof's
    // verification cost across every trade in the chunk instead of paying
    // it per trade. A trade that would be insolvent against the ledger is
    // dropped before proving, with a warning, instead of silently proving
    // over a fabricated balance.
    //
    // The ledger may be shared with a concurrently-running chain-sync
    // service (see SettlementBatcher::with_ledger), so the balance read
    // here and the debit below aren't atomic with each other -- a real
    // withdrawal could land in between and make a debit fail even though
    // prove_batch's own solvency check passed. Because one proof now covers
    // a whole chunk at once, a single trade's debit failing after the
    // chunk's proof was already generated can't be handled by just
    // dropping that one trade (the proof's arithmetic already accounts for
    // it) -- the entire chunk is rolled back and dropped instead, so the
    // proof and the trades actually reported as settled never diverge.
    fn build_batch(&mut self, trades: Vec<Match>, _tier: SettlementPreference) -> SettlementBatch {
        let mut proven_trades = Vec::with_capacity(trades.len());
        let mut proofs = Vec::new();
        let mut proof_trade_counts = Vec::new();
        let mut trade_batches = Vec::new();
        let mut total_value: u64 = 0;

        for chunk in trades.chunks(MAX_BATCH_TRADES) {
            let mut chunk_trades = Vec::with_capacity(chunk.len());
            let mut chunk_maker_balances = Vec::with_capacity(chunk.len());
            let mut chunk_taker_balances = Vec::with_capacity(chunk.len());

            for trade in chunk {
                let trade_value = trade.price as u64 * trade.amount as u64;
                let (maker_balance, taker_balance) = {
                    let ledger = self.ledger.lock().expect("ledger mutex poisoned");
                    (
                        ledger.balance_of(trade.maker_trader, &trade.symbol),
                        ledger.balance_of(trade.taker_trader, &trade.symbol),
                    )
                };

                if trade_value > taker_balance {
                    tracing::warn!(
                        trade_id = ?trade.maker_order_id,
                        "Dropping trade from settlement batch: insolvent against the ledger"
                    );
                    continue;
                }

                chunk_trades.push(trade.clone());
                chunk_maker_balances.push(maker_balance);
                chunk_taker_balances.push(taker_balance);
            }

            if chunk_trades.is_empty() {
                continue;
            }

            // prove_batch ignores this field entirely -- it computes the
            // real post_state_root itself from the circuit witness (see
            // padded_witness) and only USES pre_state_root as an input,
            // so setting this wrong never affected the proof this crate
            // actually produces or what settleBatchWithFees accepts
            // on-chain. It matters for anyone independently re-verifying
            // the proof afterward: verify_proof recomputes its own
            // expected post_state_root from pre_state_root + the trades
            // and rejects the batch if this field doesn't match that --
            // a placeholder [0u8; 32] here made every batch this
            // produced fail that check, undetected until something
            // actually called verify_proof against a real batch (see
            // watchtower_node, added in the same change as this fix).
            let chunk_total_value: u64 = chunk_trades.iter().map(|t| t.price as u64 * t.amount as u64).sum();
            let batch = TradeBatch {
                trades: chunk_trades.clone(),
                maker_balances: chunk_maker_balances,
                taker_balances: chunk_taker_balances,
                pre_state_root: [0u8; 32],
                post_state_root: u64_to_bytes32(chunk_total_value),
            };

            match self.prover.prove_batch(&batch) {
                Ok(proof) => {
                    // Two-phase: attempt every debit in the chunk before
                    // crediting any of them, so a mid-chunk failure can be
                    // fully undone rather than leaving a partially-applied
                    // chunk whose proof no longer matches what actually
                    // got settled.
                    let mut debited_so_far: Vec<(&Match, u64)> = Vec::with_capacity(chunk_trades.len());
                    let mut chunk_failed = false;

                    for trade in &chunk_trades {
                        let trade_value = trade.price as u64 * trade.amount as u64;
                        let debited = self
                            .ledger
                            .lock()
                            .expect("ledger mutex poisoned")
                            .debit(trade.taker_trader, &trade.symbol, trade_value);

                        match debited {
                            Ok(()) => debited_so_far.push((trade, trade_value)),
                            Err(reason) => {
                                tracing::warn!(
                                    trade_id = ?trade.maker_order_id,
                                    reason,
                                    "Dropping settlement chunk: taker balance changed concurrently between proving and settling"
                                );
                                chunk_failed = true;
                                break;
                            }
                        }
                    }

                    if chunk_failed {
                        let mut ledger = self.ledger.lock().expect("ledger mutex poisoned");
                        for (trade, trade_value) in &debited_so_far {
                            ledger.credit(trade.taker_trader, &trade.symbol, *trade_value);
                        }
                        continue;
                    }

                    let mut ledger = self.ledger.lock().expect("ledger mutex poisoned");
                    for (trade, trade_value) in &debited_so_far {
                        ledger.credit(trade.maker_trader, &trade.symbol, *trade_value);
                        total_value += trade_value;
                    }
                    drop(ledger);

                    proof_trade_counts.push(chunk_trades.len());
                    proven_trades.extend(chunk_trades);
                    proofs.push(proof);
                    trade_batches.push(batch);
                }
                Err(reason) => {
                    tracing::warn!(
                        count = chunk_trades.len(),
                        reason,
                        "Dropping settlement chunk: proof generation failed"
                    );
                }
            }
        }

        SettlementBatch {
            trades: proven_trades,
            total_value,
            proofs,
            proof_trade_counts,
            trade_batches,
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
    // Trades that were successfully proven and settled, grouped by which
    // proof covers them: proof_trade_counts[i] is how many consecutive
    // entries of `trades`, starting right after the previous group, belong
    // to proofs[i]. E.g. proof_trade_counts = [3, 2] means trades[0..3]
    // belong to proofs[0] and trades[3..5] belong to proofs[1]. Trades that
    // failed to prove or settle (e.g. insolvent against the ledger, or part
    // of a chunk whose proof generation failed) are omitted entirely --
    // there is no placeholder entry for them.
    pub trades: Vec<Match>,
    pub total_value: u64,
    pub proofs: Vec<Vec<u8>>,
    pub proof_trade_counts: Vec<usize>,
    // The exact TradeBatch (trades + balances + roots) used to generate
    // each proofs[i] -- same length/order as proofs. Needed by anything
    // independently re-verifying a proof (see
    // watchtower::WatchtowerClient::monitor_batch), since verify_proof
    // needs the same batch data the proof was generated against, not
    // just the trades that ended up settled.
    pub trade_batches: Vec<TradeBatch>,
}

#[cfg(test)]
mod tests {
    use super::*;

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
            assigned_node: [0u8; 32],
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

    // The actual point of the batching rewrite: a batch bigger than
    // MAX_BATCH_TRADES, made of trades between many different, unrelated
    // trader pairs (not the same two parties repeatedly), must still all
    // get proven and settled -- split across multiple proofs, each
    // covering up to MAX_BATCH_TRADES trades, not one proof per trade.
    #[test]
    fn test_standard_batch_spans_multiple_proof_chunks() {
        let mut batcher = SettlementBatcher::new();
        // Deliberately not a clean multiple of MAX_BATCH_TRADES, to also
        // exercise a final, partially-filled chunk.
        let n = MAX_BATCH_TRADES * 2 + 3;
        batcher.standard_batch_size = n;

        for i in 0..n {
            let maker = [(i * 2) as u8; 32];
            let taker = [(i * 2 + 1) as u8; 32];
            batcher.deposit(taker, "BTC-USD", 1_000_000);
            batcher.enqueue(Match {
                maker_order_id: [i as u8; 32],
                taker_order_id: [(i + 200) as u8; 32],
                maker_trader: maker,
                taker_trader: taker,
                price: 100,
                amount: 10,
                timestamp_us: 0,
                settlement_tier: SettlementPreference::Standard,
                fee_basis_points: SettlementPreference::Standard.fee_basis_points(),
                seller: taker,
                fee_payer: taker,
                symbol: "BTC-USD".to_string(),
                assigned_node: [0u8; 32],
                settlement_deadline: 0,
            });
        }

        let batches = batcher.process_batches();
        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        assert_eq!(batch.trades.len(), n, "every solvent trade across every pair must be settled");

        let expected_proof_count = n.div_ceil(MAX_BATCH_TRADES);
        assert_eq!(batch.proofs.len(), expected_proof_count);
        assert_eq!(batch.proof_trade_counts.len(), expected_proof_count);
        assert_eq!(
            batch.proof_trade_counts.iter().sum::<usize>(),
            n,
            "proof_trade_counts must account for every settled trade exactly once"
        );
        for &count in &batch.proof_trade_counts {
            assert!(count > 0 && count <= MAX_BATCH_TRADES);
        }

        // Every maker actually got credited -- confirms the multi-pair
        // per-chunk debit/credit logic, not just the proof-generation side.
        for i in 0..n {
            let maker = [(i * 2) as u8; 32];
            assert_eq!(batcher.balance_of(maker, "BTC-USD"), 1000, "maker {i} should have been credited 100*10");
        }
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

    // Regression test for a real bug: build_batch used to hardcode
    // post_state_root to [0u8; 32] on every TradeBatch it produced.
    // prove_batch never noticed (it computes the real root itself and
    // ignores this field) so every proof this crate ever generated was
    // still valid -- but ANYONE independently re-verifying a real
    // batcher-produced batch via ProverBackend::verify_proof would always
    // get `false`, since verify_proof recomputes its own expected root
    // from pre_state_root + the trades and compares it against this
    // field. Caught live by Stage C's watchtower_node reporting every
    // real settlement as fraudulent when it wasn't.
    #[test]
    fn test_produced_batch_passes_independent_verification() {
        let mut batcher = SettlementBatcher::new();
        batcher.deposit([2u8; 32], "BTC-USD", 1_000_000);
        batcher.enqueue(make_match(SettlementPreference::Instant, 1));

        let batches = batcher.process_batches();
        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        assert_eq!(batch.trade_batches.len(), 1, "one proof chunk should produce one TradeBatch");

        let trade_batch = &batch.trade_batches[0];
        let proof = &batch.proofs[0];
        assert!(
            BACKEND.verify_proof(proof, trade_batch),
            "a batch this crate just produced and proved must pass independent re-verification against itself"
        );
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
