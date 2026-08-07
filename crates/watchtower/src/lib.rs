use prover::{TradeBatch, ZKProver};

pub struct MockOnChainState {
    pub slashed_signers: Vec<[u8; 32]>,
    pub disputes_raised: usize,
    pub rolled_back: bool,
}

impl MockOnChainState {
    pub fn new() -> Self {
        Self {
            slashed_signers: Vec::new(),
            disputes_raised: 0,
            rolled_back: false,
        }
    }

    pub fn slash_signer(&mut self, signer: [u8; 32]) {
        self.slashed_signers.push(signer);
    }

    pub fn raise_dispute(&mut self) {
        self.disputes_raised += 1;
        self.rolled_back = true;
    }
}

pub struct WatchtowerClient;

impl WatchtowerClient {
    pub fn monitor_batch(
        &self,
        batch: &TradeBatch,
        proof: &[u8],
        on_chain: &mut MockOnChainState,
    ) -> bool {
        // 1. Verify ZK proof off-chain
        let is_valid = ZKProver::verify_proof(proof, batch);

        if !is_valid {
            // 2. Fraud detected! Trigger dispute and slash signers on-chain
            on_chain.raise_dispute();

            // Slash signers associated with the invalid trade transitions
            for trade in &batch.trades {
                on_chain.slash_signer(trade.maker_order_id);
            }
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine::Match;

    #[test]
    fn test_watchtower_valid_batch() {
        let batch = TradeBatch {
            trades: vec![Match {
                maker_order_id: [1u8; 32],
                taker_order_id: [2u8; 32],
                price: 3000,
                amount: 5,
                timestamp_us: 1700000000,
            }],
            pre_state_root: [10u8; 32],
            post_state_root: [20u8; 32],
        };

        let proof = ZKProver::prove_batch(&batch).unwrap();
        let mut on_chain = MockOnChainState::new();

        let client = WatchtowerClient;
        let success = client.monitor_batch(&batch, &proof, &mut on_chain);

        assert!(success);
        assert_eq!(on_chain.disputes_raised, 0);
        assert_eq!(on_chain.slashed_signers.len(), 0);
    }

    #[test]
    fn test_watchtower_fraud_dispute_and_slash() {
        let batch = TradeBatch {
            trades: vec![Match {
                maker_order_id: [1u8; 32],
                taker_order_id: [2u8; 32],
                price: 3000,
                amount: 5,
                timestamp_us: 1700000000,
            }],
            pre_state_root: [10u8; 32],
            post_state_root: [20u8; 32],
        };

        let proof = ZKProver::prove_batch(&batch).unwrap();

        // Tamper with batch to simulate fraud
        let mut tampered_batch = batch.clone();
        tampered_batch.post_state_root[0] ^= 0xFF;

        let mut on_chain = MockOnChainState::new();
        let client = WatchtowerClient;

        let success = client.monitor_batch(&tampered_batch, &proof, &mut on_chain);

        assert!(!success);
        assert_eq!(on_chain.disputes_raised, 1);
        assert!(on_chain.rolled_back);
        assert_eq!(on_chain.slashed_signers.len(), 1);
    }
}
