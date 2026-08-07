use frost_ed25519::{
    self as frost,
    keys::{KeyPackage, PublicKeyPackage, IdentifierList},
};
use std::collections::BTreeMap;

pub struct TssSigner {
    pub threshold: usize,
    pub total: usize,
    public_key_pkg: Option<Vec<u8>>,
}

impl TssSigner {
    pub fn new(threshold: usize, total: usize) -> Self {
        assert!(threshold >= 2, "Threshold must be at least 2");
        assert!(total >= threshold, "Total must be >= threshold");
        Self {
            threshold,
            total,
            public_key_pkg: None,
        }
    }

    pub fn keygen(&mut self) -> Vec<Vec<u8>> {
        let mut rng = rand::thread_rng();
        let ids = IdentifierList::Default;

        let (secret_shares_map, pubkey_pkg) = frost::keys::generate_with_dealer(
            self.total as u16,
            self.threshold as u16,
            ids,
            &mut rng,
        )
        .expect("Key generation failed");

        self.public_key_pkg =
            Some(serde_json::to_vec(&pubkey_pkg).expect("Pubkey serialization failed"));

        secret_shares_map
            .into_values()
            .map(|ss| {
                let kp: KeyPackage = KeyPackage::try_from(ss)
                    .expect("SecretShare to KeyPackage conversion failed");
                serde_json::to_vec(&kp).expect("KeyPackage serialization failed")
            })
            .collect()
    }

    pub fn sign_message(
        &self,
        shares: &[Vec<u8>],
        message: &[u8],
    ) -> Result<Vec<u8>, String> {
        if shares.len() < self.threshold {
            return Err(format!(
                "Insufficient shares: got {}, threshold is {}",
                shares.len(),
                self.threshold
            ));
        }

        let pubkey_pkg_bytes = self
            .public_key_pkg
            .as_ref()
            .ok_or("Must call keygen before signing")?;
        let pubkey_pkg: PublicKeyPackage = serde_json::from_slice(pubkey_pkg_bytes)
            .map_err(|e| format!("Pubkey deserialization failed: {}", e))?;

        let key_packages: Vec<KeyPackage> = shares
            .iter()
            .take(self.threshold)
            .map(|s| {
                serde_json::from_slice(s)
                    .map_err(|e| format!("Share deserialization failed: {}", e))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut rng = rand::thread_rng();

        let mut nonces_map = BTreeMap::new();
        let mut commitments_map = BTreeMap::new();

        for kp in &key_packages {
            let (nonces, commitments) = frost::round1::commit(kp.signing_share(), &mut rng);
            let id = *kp.identifier();
            commitments_map.insert(id, commitments);
            nonces_map.insert(id, nonces);
        }

        let signing_package = frost::SigningPackage::new(commitments_map, message);

        let mut signature_shares = BTreeMap::new();
        for kp in &key_packages {
            let id = *kp.identifier();
            let nonces = nonces_map.get(&id).unwrap();
            let share = frost::round2::sign(&signing_package, nonces, kp).unwrap();
            signature_shares.insert(id, share);
        }

        let sig = frost::aggregate(&signing_package, &signature_shares, &pubkey_pkg)
            .map_err(|e| format!("Aggregation failed: {}", e))?;

        Ok(sig.serialize().to_vec())
    }

    pub fn verify_signature(
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, String> {
        let vk = frost::VerifyingKey::deserialize(
            public_key
                .try_into()
                .map_err(|_| "Invalid pubkey length")?,
        )
        .map_err(|e| format!("Invalid verifying key: {}", e))?;

        let sig = frost::Signature::deserialize(
            signature
                .try_into()
                .map_err(|_| "Invalid signature length")?,
        )
        .map_err(|e| format!("Invalid signature: {}", e))?;

        Ok(vk.verify(message, &sig).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(threshold: usize, total: usize) -> (TssSigner, Vec<Vec<u8>>) {
        let mut tss = TssSigner::new(threshold, total);
        let shares = tss.keygen();
        (tss, shares)
    }

    #[test]
    fn test_tss_keygen_and_sign_success() {
        let (tss, shares) = setup(2, 3);
        assert_eq!(shares.len(), 3);

        let message = b"Settle cross-chain trade block #159";

        let active_shares = vec![shares[0].clone(), shares[2].clone()];
        let signature = tss.sign_message(&active_shares, message).unwrap();
        assert!(signature.len() > 32);
    }

    #[test]
    fn test_tss_insufficient_shares_fails() {
        let (tss, shares) = setup(3, 5);

        let message = b"Lock escrow block #160";

        let active_shares = vec![shares[0].clone(), shares[1].clone()];
        let result = tss.sign_message(&active_shares, message);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Insufficient shares"));
    }

    #[test]
    fn test_tss_different_messages_produce_different_signatures() {
        let (tss, shares) = setup(2, 3);

        let sig1 = tss
            .sign_message(&shares[..2], b"Message A")
            .unwrap();
        let sig2 = tss
            .sign_message(&shares[..2], b"Message B")
            .unwrap();

        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_tss_sign_with_exact_threshold() {
        let (tss, shares) = setup(2, 2);
        assert_eq!(shares.len(), 2);

        let signature = tss
            .sign_message(&[shares[0].clone(), shares[1].clone()], b"test")
            .unwrap();
        assert!(!signature.is_empty());
    }

    #[test]
    fn test_tss_more_shares_than_threshold_works() {
        let (tss, shares) = setup(2, 5);
        assert_eq!(shares.len(), 5);

        let sig = tss
            .sign_message(&shares[2..4], b"test")
            .unwrap();
        assert!(!sig.is_empty());
    }
}
