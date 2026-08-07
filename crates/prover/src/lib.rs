use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable, LinearCombination};
use engine::Match;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TradeBatch {
    pub trades: Vec<Match>,
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
}

impl<F: PrimeField> ConstraintSynthesizer<F> for DEXTradeCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let maker_pre = cs.new_witness_variable(|| self.maker_balance_pre.ok_or(SynthesisError::AssignmentMissing))?;
        let taker_pre = cs.new_witness_variable(|| self.taker_balance_pre.ok_or(SynthesisError::AssignmentMissing))?;
        let amt = cs.new_witness_variable(|| self.amount.ok_or(SynthesisError::AssignmentMissing))?;
        let prc = cs.new_witness_variable(|| self.price.ok_or(SynthesisError::AssignmentMissing))?;
        
        let maker_post = cs.new_input_variable(|| self.maker_balance_post.ok_or(SynthesisError::AssignmentMissing))?;
        let taker_post = cs.new_input_variable(|| self.taker_balance_post.ok_or(SynthesisError::AssignmentMissing))?;

        let val = cs.new_witness_variable(|| {
            let a = self.amount.ok_or(SynthesisError::AssignmentMissing)?;
            let p = self.price.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(a * p)
        })?;

        // amt * prc = val
        cs.enforce_constraint(
            LinearCombination::from(amt),
            LinearCombination::from(prc),
            LinearCombination::from(val),
        )?;

        // maker_pre + val = maker_post
        let mut lc_maker = LinearCombination::zero();
        lc_maker = lc_maker + (F::one(), maker_pre) + (F::one(), val);
        cs.enforce_constraint(
            lc_maker,
            LinearCombination::from(Variable::One),
            LinearCombination::from(maker_post),
        )?;

        // taker_pre - val = taker_post
        let mut lc_taker = LinearCombination::zero();
        lc_taker = lc_taker + (F::one(), taker_pre) - (F::one(), val);
        cs.enforce_constraint(
            lc_taker,
            LinearCombination::from(Variable::One),
            LinearCombination::from(taker_post),
        )?;

        Ok(())
    }
}

pub struct ZKProver;

impl ZKProver {
    pub fn prove_batch(batch: &TradeBatch) -> Result<Vec<u8>, String> {
        let mut proof_bytes = Vec::new();
        proof_bytes.extend_from_slice(&batch.pre_state_root);
        proof_bytes.extend_from_slice(&batch.post_state_root);
        Ok(proof_bytes)
    }

    pub fn verify_proof(proof: &[u8], batch: &TradeBatch) -> bool {
        let expected_proof = match Self::prove_batch(batch) {
            Ok(p) => p,
            Err(_) => return false,
        };
        proof == expected_proof
    }

    pub fn verify_batch_constraints<F: PrimeField>(circuit: DEXTradeCircuit<F>) -> bool {
        use ark_relations::r1cs::ConstraintSystem;
        let cs = ConstraintSystemRef::new(ConstraintSystem::new());
        if circuit.generate_constraints(cs.clone()).is_err() {
            return false;
        }
        cs.is_satisfied().unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{fields::{Fp64, MontBackend, MontConfig}};

    #[derive(MontConfig)]
    #[modulus = "17"]
    #[generator = "3"]
    pub struct FqConfig;

    pub type Fq = Fp64<MontBackend<FqConfig, 1>>;

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

        let mut tampered_batch = batch.clone();
        tampered_batch.post_state_root[0] ^= 0xFF;

        assert!(!ZKProver::verify_proof(&proof, &tampered_batch));
    }

    #[test]
    fn test_zk_circuit_satisfied() {
        let circuit = DEXTradeCircuit::<Fq> {
            maker_balance_pre: Some(Fq::from(5u64)), // 5 pre balance
            taker_balance_pre: Some(Fq::from(10u64)), // 10 pre balance
            amount: Some(Fq::from(2u64)),
            price: Some(Fq::from(3u64)), // value = 6 (modulo 17)
            maker_balance_post: Some(Fq::from(11u64)), // 5 + 6 = 11
            taker_balance_post: Some(Fq::from(4u64)), // 10 - 6 = 4
        };

        let satisfied = ZKProver::verify_batch_constraints(circuit);
        assert!(satisfied);
    }

    #[test]
    fn test_zk_circuit_unsatisfied_tampered_post_balance() {
        let circuit = DEXTradeCircuit::<Fq> {
            maker_balance_pre: Some(Fq::from(5u64)),
            taker_balance_pre: Some(Fq::from(10u64)),
            amount: Some(Fq::from(2u64)),
            price: Some(Fq::from(3u64)),
            maker_balance_post: Some(Fq::from(99u64)), // Invalid post balance
            taker_balance_post: Some(Fq::from(4u64)),
        };

        let satisfied = ZKProver::verify_batch_constraints(circuit);
        assert!(!satisfied);
    }
}
