use engine::Match;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TradeBatch {
    pub trades: Vec<Match>,
    pub pre_state_root: [u8; 32],
    pub post_state_root: [u8; 32],
}

pub struct ZKProver;

impl ZKProver {
    pub fn prove_batch(batch: &TradeBatch) -> Result<Vec<u8>, String> {
        let mut hasher = Sha256::new();
        hasher.update(&batch.pre_state_root);

        let trades_bytes = serde_json::to_vec(&batch.trades).map_err(|e| e.to_string())?;
        hasher.update(&trades_bytes);

        hasher.update(&batch.post_state_root);

        let proof = hasher.finalize().to_vec();
        Ok(proof)
    }

    pub fn verify_proof(proof: &[u8], batch: &TradeBatch) -> bool {
        let expected_proof = match Self::prove_batch(batch) {
            Ok(p) => p,
            Err(_) => return false,
        };
        proof == expected_proof
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prove_and_verify_success() {
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
        assert_eq!(proof.len(), 32);

        assert!(ZKProver::verify_proof(&proof, &batch));
    }

    #[test]
    fn test_verify_tampered_batch_fails() {
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

        // Tamper with the post state root in the batch
        let mut tampered_batch = batch.clone();
        tampered_batch.post_state_root[0] ^= 0xFF;

        assert!(!ZKProver::verify_proof(&proof, &tampered_batch));
    }
}
