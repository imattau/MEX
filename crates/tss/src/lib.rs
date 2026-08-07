use sha2::{Digest, Sha256};

pub struct TssSigner {
    pub threshold: usize,
    pub total: usize,
}

impl TssSigner {
    pub fn new(threshold: usize, total: usize) -> Self {
        Self { threshold, total }
    }

    pub fn keygen(&self) -> Vec<Vec<u8>> {
        // In a real GG18 MPC protocol, this executes distributed key generation (DKG)
        // producing public key and private polynomial shares.
        // For the mock, we generate deterministic secret shares based on index.
        (0..self.total)
            .map(|i| {
                let mut share = vec![0u8; 32];
                share[0..8].copy_from_slice(&(i as u64).to_be_bytes());
                share
            })
            .collect()
    }

    pub fn sign_message(&self, shares: &[Vec<u8>], message: &[u8]) -> Result<Vec<u8>, String> {
        if shares.len() < self.threshold {
            return Err(format!(
                "Insufficient shares: got {}, threshold is {}",
                shares.len(),
                self.threshold
            ));
        }

        // Aggregate threshold signature by combining shares and hashing message
        let mut hasher = Sha256::new();
        hasher.update(message);

        // Sort shares to ensure deterministic ordering of aggregation
        let mut sorted_shares = shares.to_vec();
        sorted_shares.sort();

        for share in sorted_shares {
            hasher.update(&share);
        }

        let signature = hasher.finalize().to_vec();
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tss_keygen_and_sign_success() {
        let tss = TssSigner::new(2, 3); // 2-of-3 threshold
        let shares = tss.keygen();
        assert_eq!(shares.len(), 3);

        let message = b"Settle cross-chain trade block #159";

        // Provide 2 shares (meets threshold)
        let active_shares = vec![shares[0].clone(), shares[2].clone()];
        let signature = tss.sign_message(&active_shares, message).unwrap();
        assert_eq!(signature.len(), 32);
    }

    #[test]
    fn test_tss_insufficient_shares_fails() {
        let tss = TssSigner::new(3, 5); // 3-of-5 threshold
        let shares = tss.keygen();

        let message = b"Lock escrow block #160";

        // Provide only 2 shares (fails threshold)
        let active_shares = vec![shares[0].clone(), shares[1].clone()];
        let result = tss.sign_message(&active_shares, message);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Insufficient shares"));
    }
}
