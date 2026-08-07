use chain::{ChainAdapter, Token};
use common::SettlementPreference;
use prover::{TradeBatch, ProverBackend, BACKEND};
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
        }
    }
}

impl ChainAdapter for MockOnChainState {
    fn chain_id(&self) -> &'static str { "mock" }
    fn native_denomination(&self) -> &'static str { "MOCK" }
    fn submit_settlement_batch(
        &self, _b: &TradeBatch, _p: &[u8], _s: &[([u8; 32], Vec<u8>)],
        _tier: SettlementPreference, _fee_recipient: [u8; 32], _deadlines: &[u64],
    ) -> Result<String, String> {
        Ok("mock_tx_hash".into())
    }
    fn lock_funds(&self, _t: [u8; 32], _tk: Token, _a: u64) -> Result<(), String> { Ok(()) }
    fn settle_funds(&self, _f: [u8; 32], _t: [u8; 32], _tk: Token, _a: u64) -> Result<(), String> { Ok(()) }
    fn release_funds(&self, _t: [u8; 32], _tk: Token, _a: u64) -> Result<(), String> { Ok(()) }
    fn register_node(&self, _p: [u8; 32], _o: [u8; 32], _g: &str, _s: u64) -> Result<(), String> { Ok(()) }
    fn slash_node(&self, _p: [u8; 32], _a: u64) -> Result<(), String> { Ok(()) }
    fn get_node_stake(&self, _p: [u8; 32]) -> Result<u64, String> { Ok(0) }
    fn is_node_active(&self, _p: [u8; 32]) -> Result<bool, String> { Ok(false) }
    fn update_node_reputation(&self, _p: [u8; 32], _s: u32, _l: u8) -> Result<(), String> { Ok(()) }
    fn get_node_reputation(&self, _p: [u8; 32]) -> Result<(u32, u8, u64), String> { Ok((5000, 0, 0)) }
    fn prover(&self) -> &dyn ProverBackend { &BACKEND }
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

    pub fn check_fee_compliance(
        &self,
        batch: &TradeBatch,
        on_chain: &mut impl OnChainClient,
    ) {
        for trade in &batch.trades {
            let expected_bps = trade.settlement_tier.fee_basis_points();
            if trade.fee_basis_points != expected_bps {
                on_chain.raise_dispute(trade.maker_order_id);
                on_chain.slash_signer(trade.seller);
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
    use engine::Match;
    use common::SettlementRequester;

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
        let maker_post = maker_balance + total_value;
        let taker_post = taker_balance - total_value;
        let post_root_val = maker_post + taker_post;

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
                settlement_deadline: 0,
            }],
            pre_state_root: [0u8; 32],
            post_state_root: u64_to_bytes32(post_root_val),
            maker_balance,
            taker_balance,
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
}
