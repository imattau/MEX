pub mod backend;
pub mod bn254;

use ark_ff::PrimeField;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable, LinearCombination,
};
use engine::Match;
use serde::{Deserialize, Serialize};

pub use backend::ProverBackend;
pub use bn254::{
    decode_proof_calldata, export_verifying_key_calldata, Bn254Groth16Backend, ProofCalldata,
    VerifyingKeyCalldata,
};

pub static BACKEND: Bn254Groth16Backend = Bn254Groth16Backend;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TradeBatch {
    pub trades: Vec<Match>,
    pub maker_balance: u64,
    pub taker_balance: u64,
    pub pre_state_root: [u8; 32],
    pub post_state_root: [u8; 32],
}

pub struct DEXTradeCircuit<F: PrimeField> {
    pub maker_balance_pre: Option<F>,
    pub taker_balance_pre: Option<F>,
    pub amount: Option<F>,
    pub price: Option<F>,
    pub maker_balance_post: Option<F>,
    pub taker_balance_post: Option<F>,
    pub pre_state_root: Option<F>,
    pub post_state_root: Option<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for DEXTradeCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let maker_pre =
            cs.new_witness_variable(|| self.maker_balance_pre.ok_or(SynthesisError::AssignmentMissing))?;
        let taker_pre =
            cs.new_witness_variable(|| self.taker_balance_pre.ok_or(SynthesisError::AssignmentMissing))?;
        let amt = cs.new_witness_variable(|| self.amount.ok_or(SynthesisError::AssignmentMissing))?;
        let prc = cs.new_witness_variable(|| self.price.ok_or(SynthesisError::AssignmentMissing))?;

        let maker_post =
            cs.new_input_variable(|| self.maker_balance_post.ok_or(SynthesisError::AssignmentMissing))?;
        let taker_post =
            cs.new_input_variable(|| self.taker_balance_post.ok_or(SynthesisError::AssignmentMissing))?;

        let pre_root =
            cs.new_input_variable(|| self.pre_state_root.ok_or(SynthesisError::AssignmentMissing))?;
        let post_root =
            cs.new_input_variable(|| self.post_state_root.ok_or(SynthesisError::AssignmentMissing))?;

        let val = cs.new_witness_variable(|| {
            let a = self.amount.ok_or(SynthesisError::AssignmentMissing)?;
            let p = self.price.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(a * p)
        })?;

        cs.enforce_constraint(
            LinearCombination::from(amt),
            LinearCombination::from(prc),
            LinearCombination::from(val),
        )?;

        let mut lc_maker = LinearCombination::zero();
        lc_maker = lc_maker + (F::one(), maker_pre) + (F::one(), val);
        cs.enforce_constraint(
            lc_maker,
            LinearCombination::from(Variable::One),
            LinearCombination::from(maker_post),
        )?;

        let mut lc_taker = LinearCombination::zero();
        lc_taker = lc_taker + (F::one(), taker_pre) - (F::one(), val);
        cs.enforce_constraint(
            lc_taker,
            LinearCombination::from(Variable::One),
            LinearCombination::from(taker_post),
        )?;

        let mut lc_post = LinearCombination::zero();
        lc_post = lc_post + (F::one(), pre_root) + (F::one(), maker_post) + (F::one(), taker_post);
        cs.enforce_constraint(
            lc_post,
            LinearCombination::from(Variable::One),
            LinearCombination::from(post_root),
        )?;

        Ok(())
    }
}

pub struct BatchSigner;

impl BatchSigner {
    pub fn sign_batch(batch: &TradeBatch, node_seed: &[u8; 32]) -> Vec<u8> {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(node_seed);
        let msg = Self::batch_message(batch);
        sk.sign(&msg).to_vec()
    }

    pub fn verify_node_sig(
        batch: &TradeBatch,
        node_pubkey: &[u8; 32],
        signature: &[u8],
    ) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let vk = match VerifyingKey::from_bytes(node_pubkey) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let sig = match Signature::from_slice(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let msg = Self::batch_message(batch);
        vk.verify(&msg, &sig).is_ok()
    }

    pub fn verify_threshold(
        batch: &TradeBatch,
        signatures: &[([u8; 32], Vec<u8>)],
        threshold: usize,
    ) -> bool {
        let mut valid_count = 0;
        for (pubkey, sig) in signatures {
            if Self::verify_node_sig(batch, pubkey, sig) {
                valid_count += 1;
            }
        }
        valid_count >= threshold
    }

    fn batch_message(batch: &TradeBatch) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&batch.pre_state_root);
        msg.extend_from_slice(&batch.post_state_root);
        msg.extend_from_slice(&batch.maker_balance.to_be_bytes());
        msg.extend_from_slice(&batch.taker_balance.to_be_bytes());
        for trade in &batch.trades {
            msg.extend_from_slice(&trade.maker_order_id);
            msg.extend_from_slice(&trade.taker_order_id);
            msg.extend_from_slice(&trade.price.to_be_bytes());
            msg.extend_from_slice(&trade.amount.to_be_bytes());
        }
        msg
    }
}

pub struct MultiWatchtower {
    pub threshold: usize,
    pub watchtower_keys: Vec<[u8; 32]>,
}

impl MultiWatchtower {
    pub fn new(threshold: usize, keys: Vec<[u8; 32]>) -> Self {
        Self { threshold, watchtower_keys: keys }
    }

    pub fn approve_batch(
        &self,
        batch: &TradeBatch,
        proof: &[u8],
        signatures: &[([u8; 32], Vec<u8>)],
        prover: &dyn ProverBackend,
    ) -> bool {
        if !prover.verify_proof(proof, batch) {
            return false;
        }

        let mut unique_signers = std::collections::HashSet::new();
        let mut valid_count = 0;

        for (pubkey, sig) in signatures {
            if !self.watchtower_keys.contains(pubkey) {
                continue;
            }
            if unique_signers.contains(pubkey) {
                continue;
            }
            if BatchSigner::verify_node_sig(batch, pubkey, sig) {
                unique_signers.insert(*pubkey);
                valid_count += 1;
            }
        }

        valid_count >= self.threshold
    }
}

// ark_ff_macros' MontConfig derive (used below) expands to an impl the
// `non_local_definitions` lint flags when the struct lives inside this `mod`;
// it's an upstream macro-hygiene quirk, not an issue with this code.
#[allow(non_local_definitions)]
#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_ff::fields::{Fp64, MontBackend, MontConfig};
    use common::SettlementPreference;

    #[derive(MontConfig)]
    #[modulus = "17"]
    #[generator = "3"]
    pub struct FqConfig;

    pub type Fq = Fp64<MontBackend<FqConfig, 1>>;

    #[test]
    fn test_zk_circuit_satisfied() {
        let circuit = DEXTradeCircuit::<Fq> {
            maker_balance_pre: Some(Fq::from(5u64)),
            taker_balance_pre: Some(Fq::from(10u64)),
            amount: Some(Fq::from(2u64)),
            price: Some(Fq::from(3u64)),
            maker_balance_post: Some(Fq::from(11u64)),
            taker_balance_post: Some(Fq::from(4u64)),
            pre_state_root: Some(Fq::from(0u64)),
            post_state_root: Some(Fq::from(15u64)),
        };

        let cs = ark_relations::r1cs::ConstraintSystem::new();
        let cs_ref = ConstraintSystemRef::new(cs);
        assert!(circuit.generate_constraints(cs_ref.clone()).is_ok());
        assert!(cs_ref.is_satisfied().unwrap_or(false));
    }

    #[test]
    fn test_zk_circuit_unsatisfied_tampered_post_balance() {
        let circuit = DEXTradeCircuit::<Fq> {
            maker_balance_pre: Some(Fq::from(5u64)),
            taker_balance_pre: Some(Fq::from(10u64)),
            amount: Some(Fq::from(2u64)),
            price: Some(Fq::from(3u64)),
            maker_balance_post: Some(Fq::from(99u64)),
            taker_balance_post: Some(Fq::from(4u64)),
            pre_state_root: Some(Fq::from(0u64)),
            post_state_root: Some(Fq::from(0u64)),
        };

        let cs = ark_relations::r1cs::ConstraintSystem::new();
        let cs_ref = ConstraintSystemRef::new(cs);
        assert!(circuit.generate_constraints(cs_ref.clone()).is_ok());
        assert!(!cs_ref.is_satisfied().unwrap_or(true));
    }

    #[test]
    fn test_batch_signer_and_multi_watchtower() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        fn u64_to_bytes32(val: u64) -> [u8; 32] {
            let mut result = [0u8; 32];
            result[24..32].copy_from_slice(&val.to_be_bytes());
            result
        }

        let batch = TradeBatch {
            trades: vec![Match {
                maker_order_id: [1u8; 32],
                taker_order_id: [2u8; 32],
                maker_trader: [0u8; 32],
                taker_trader: [0u8; 32],
                price: 3000,
                amount: 5,
                timestamp_us: 0,
                settlement_tier: SettlementPreference::Standard,
                fee_basis_points: 5,
                seller: [0u8; 32],
                fee_payer: [0u8; 32],
                symbol: "BTC-USD".to_string(),
                assigned_node: [0u8; 32],
                settlement_deadline: 0,
            }],
            maker_balance: 1_000_000,
            taker_balance: 1_000_000,
            pre_state_root: [0u8; 32],
            post_state_root: u64_to_bytes32(2_000_000),
        };

        let backend = Bn254Groth16Backend;
        let proof = backend.prove_batch(&batch).unwrap();

        let mut rng = OsRng;
        let keys: Vec<_> = (0..5)
            .map(|_| {
                let sk = SigningKey::generate(&mut rng);
                let pk = sk.verifying_key().to_bytes();
                (sk.to_bytes(), pk)
            })
            .collect();

        let sigs: Vec<_> = keys
            .iter()
            .map(|(seed, pk)| (*pk, BatchSigner::sign_batch(&batch, seed)))
            .collect();

        for (pk, sig) in &sigs {
            assert!(BatchSigner::verify_node_sig(&batch, pk, sig));
        }

        assert!(BatchSigner::verify_threshold(&batch, &sigs, 3));
        assert!(!BatchSigner::verify_threshold(&batch, &sigs, 10));

        let pks: Vec<_> = keys.iter().map(|(_, pk)| *pk).collect();
        let wt = MultiWatchtower::new(3, pks);
        assert!(wt.approve_batch(&batch, &proof, &sigs, &backend));
        assert!(!wt.approve_batch(&batch, &proof, &sigs[..2], &backend));
    }
}
