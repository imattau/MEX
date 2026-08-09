use chain::{ChainAdapter, OnChainAccount, SettlementFeeConfig, SettlementTrade};
use prover::{ProverBackend, TradeBatch, BACKEND};
use std::collections::HashSet;

pub trait OnChainClient: ChainAdapter {
    fn slash_signer(&mut self, signer: [u8; 32]);
    fn raise_dispute(&mut self, batch_hash: [u8; 32]);
    fn is_batch_settled(&self, batch_hash: [u8; 32]) -> bool;
    fn disputes_raised(&self) -> usize;
    fn is_rolled_back(&self) -> bool;
    fn record_missed_deadline(&mut self, node_pubkey: [u8; 32]);
    fn missed_deadlines(&self) -> usize;
}

pub struct MockOnChainState {
    pub slashed_signers: Vec<[u8; 32]>,
    pub disputes_raised: usize,
    pub rolled_back: bool,
    pub settled_batches: std::collections::HashSet<[u8; 32]>,
    pub missed_deadlines: HashSet<[u8; 32]>,
    pub fee_violations: HashSet<[u8; 32]>,
    // Stage P4-4b: (trader, trade_hash) pairs a test wants is_trade_settled
    // to report as already-settled -- everything else reports false,
    // matching a trader who genuinely never committed/settled that trade.
    // Populated directly by tests (see Stage P4-4c's reconciliation
    // tests), never mutated by this mock itself.
    pub settled_trades: HashSet<(OnChainAccount, [u8; 32])>,
}

impl MockOnChainState {
    pub fn new() -> Self {
        Self {
            slashed_signers: Vec::new(),
            disputes_raised: 0,
            rolled_back: false,
            settled_batches: std::collections::HashSet::new(),
            missed_deadlines: HashSet::new(),
            fee_violations: HashSet::new(),
            settled_trades: HashSet::new(),
        }
    }
}

impl ChainAdapter for MockOnChainState {
    fn chain_id(&self) -> &'static str {
        "mock"
    }
    fn native_denomination(&self) -> &'static str {
        "MOCK"
    }
    async fn submit_settlement_batch(
        &self,
        _trades: &[SettlementTrade],
        _proof: &[u8],
        _fee_config: SettlementFeeConfig,
    ) -> Result<String, String> {
        Ok("mock_tx_hash".into())
    }
    async fn submit_missed_deadline_report(&self, _pubkey: OnChainAccount) -> Result<(), String> {
        Ok(())
    }
    async fn register_node(
        &self,
        _pubkey: OnChainAccount,
        _geo: &str,
        _stake: u64,
    ) -> Result<(), String> {
        Ok(())
    }
    async fn get_node_stake(&self, _pubkey: OnChainAccount) -> Result<u64, String> {
        Ok(0)
    }
    async fn is_node_active(&self, _pubkey: OnChainAccount) -> Result<bool, String> {
        Ok(false)
    }
    async fn get_node_reputation(&self, _pubkey: OnChainAccount) -> Result<(u32, u8, u64), String> {
        Ok((5000, 0, 0))
    }
    async fn is_trade_settled(
        &self,
        trader: OnChainAccount,
        trade_hash: [u8; 32],
    ) -> Result<bool, String> {
        Ok(self.settled_trades.contains(&(trader, trade_hash)))
    }
    fn prover(&self) -> &dyn ProverBackend {
        &BACKEND
    }
}

impl OnChainClient for MockOnChainState {
    fn slash_signer(&mut self, signer: [u8; 32]) {
        self.slashed_signers.push(signer);
    }

    fn raise_dispute(&mut self, _batch_hash: [u8; 32]) {
        self.disputes_raised += 1;
        self.rolled_back = true;
    }

    fn is_batch_settled(&self, batch_hash: [u8; 32]) -> bool {
        self.settled_batches.contains(&batch_hash)
    }

    fn disputes_raised(&self) -> usize {
        self.disputes_raised
    }

    fn is_rolled_back(&self) -> bool {
        self.rolled_back
    }

    fn record_missed_deadline(&mut self, node_pubkey: [u8; 32]) {
        self.missed_deadlines.insert(node_pubkey);
    }

    fn missed_deadlines(&self) -> usize {
        self.missed_deadlines.len()
    }
}

pub struct WatchtowerClient;

impl WatchtowerClient {
    pub fn monitor_batch(
        &self,
        batch: &TradeBatch,
        proof: &[u8],
        prover: &dyn ProverBackend,
        on_chain: &mut impl OnChainClient,
    ) -> bool {
        let is_valid = prover.verify_proof(proof, batch);

        if !is_valid {
            on_chain.raise_dispute(batch.pre_state_root);

            for trade in &batch.trades {
                on_chain.slash_signer(trade.maker_trader);
                on_chain.slash_signer(trade.taker_trader);
            }
            return false;
        }

        self.check_fee_compliance(batch, on_chain);

        true
    }

    pub fn check_fee_compliance(&self, batch: &TradeBatch, on_chain: &mut impl OnChainClient) {
        for trade in &batch.trades {
            let expected_bps = trade.settlement_tier.fee_basis_points();
            if trade.fee_basis_points != expected_bps {
                on_chain.raise_dispute(trade.maker_order_id);
                on_chain.slash_signer(trade.fee_payer);
            }
        }
    }

    pub fn check_deadline_compliance(
        &self,
        batch: &TradeBatch,
        current_time: u64,
        on_chain: &mut impl OnChainClient,
    ) {
        for trade in &batch.trades {
            if current_time > trade.settlement_deadline {
                on_chain.record_missed_deadline(trade.maker_trader);
                on_chain.record_missed_deadline(trade.taker_trader);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::SettlementPreference;
    use engine::Match;

    fn u64_to_bytes32(val: u64) -> [u8; 32] {
        let mut result = [0u8; 32];
        result[24..32].copy_from_slice(&val.to_be_bytes());
        result
    }

    fn test_batch() -> TradeBatch {
        let maker_balance = 1_000_000u64;
        let taker_balance = 1_000_000u64;
        let price = 3000u64;
        let amount = 5u64;
        let total_value = price * amount;
        // Root = sum of each trade's (amount * price), not maker_post +
        // taker_post -- see prover::DEXBatchCircuit's docs.
        let post_root_val = total_value;

        TradeBatch {
            trades: vec![Match {
                maker_order_id: [1u8; 32],
                taker_order_id: [2u8; 32],
                maker_trader: [3u8; 32],
                taker_trader: [4u8; 32],
                price,
                amount,
                timestamp_us: 1700000000,
                settlement_tier: SettlementPreference::Standard,
                fee_basis_points: 5,
                seller: [4u8; 32],
                fee_payer: [4u8; 32],
                symbol: "BTC-USD".to_string(),
                assigned_node: [0u8; 32],
                settlement_deadline: 0,
            }],
            pre_state_root: [0u8; 32],
            post_state_root: u64_to_bytes32(post_root_val),
            maker_balances: vec![maker_balance],
            taker_balances: vec![taker_balance],
        }
    }

    #[test]
    fn test_watchtower_valid_batch() {
        let batch = test_batch();
        let proof = BACKEND.prove_batch(&batch).unwrap();
        let mut on_chain = MockOnChainState::new();

        let client = WatchtowerClient;
        let success = client.monitor_batch(&batch, &proof, &BACKEND, &mut on_chain);

        assert!(success);
        assert_eq!(on_chain.disputes_raised, 0);
        assert_eq!(on_chain.slashed_signers.len(), 0);
    }

    #[test]
    fn test_watchtower_fraud_dispute_and_slash() {
        let batch = test_batch();
        let proof = BACKEND.prove_batch(&batch).unwrap();

        let mut tampered_batch = batch.clone();
        tampered_batch.post_state_root[0] ^= 0xFF;

        let mut on_chain = MockOnChainState::new();
        let client = WatchtowerClient;

        let success = client.monitor_batch(&tampered_batch, &proof, &BACKEND, &mut on_chain);

        assert!(!success);
        assert_eq!(on_chain.disputes_raised, 1);
        assert_eq!(on_chain.slashed_signers.len(), 2);
    }

    #[test]
    fn test_watchtower_tampered_trade_fails() {
        let batch = test_batch();
        let proof = BACKEND.prove_batch(&batch).unwrap();

        let mut tampered_batch = batch.clone();
        tampered_batch.trades[0].amount = 99;

        let mut on_chain = MockOnChainState::new();
        let client = WatchtowerClient;

        let success = client.monitor_batch(&tampered_batch, &proof, &BACKEND, &mut on_chain);

        assert!(!success);
        assert_eq!(on_chain.disputes_raised, 1);
    }

    #[test]
    fn test_fee_compliance_detects_wrong_bps() {
        let mut batch = test_batch();
        batch.trades[0].fee_basis_points = 999; // Wrong!

        let mut on_chain = MockOnChainState::new();
        let client = WatchtowerClient;

        client.check_fee_compliance(&batch, &mut on_chain);

        assert_eq!(on_chain.disputes_raised, 1);
        assert_eq!(on_chain.slashed_signers.len(), 1);
    }

    #[test]
    fn test_deadline_compliance_records_missed() {
        let mut batch = test_batch();
        batch.trades[0].settlement_deadline = 100;

        let mut on_chain = MockOnChainState::new();
        let client = WatchtowerClient;

        client.check_deadline_compliance(&batch, 200, &mut on_chain);

        assert!(on_chain.missed_deadlines() > 0);
    }

    // Stage P4-4b: the mock must distinguish real (trader, trade_hash)
    // pairs from everything else -- a reconciliation check must never
    // report "settled" for a trade that was never marked as such, and
    // must never confuse two different traders' otherwise-identical
    // trade_hash.
    #[tokio::test]
    async fn test_mock_is_trade_settled_only_matches_recorded_pairs() {
        let mut on_chain = MockOnChainState::new();
        let trader_a: OnChainAccount = [1u8; 32];
        let trader_b: OnChainAccount = [2u8; 32];
        let trade_hash = [0xABu8; 32];
        on_chain.settled_trades.insert((trader_a, trade_hash));

        assert!(on_chain
            .is_trade_settled(trader_a, trade_hash)
            .await
            .unwrap());
        assert!(
            !on_chain
                .is_trade_settled(trader_b, trade_hash)
                .await
                .unwrap(),
            "a different trader with the same trade_hash must not read as settled"
        );
        assert!(
            !on_chain
                .is_trade_settled(trader_a, [0xCDu8; 32])
                .await
                .unwrap(),
            "an unrecorded trade_hash for the same trader must not read as settled"
        );
    }
}
