pub mod backend;
pub mod bn254;

use ark_ff::PrimeField;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
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
    // One entry per trade in `trades`, same length, same order -- each
    // trade has its own independent maker/taker balance pair, so a batch
    // can cover any number of unrelated trader pairs, not just one pair
    // trading repeatedly. See DEXBatchCircuit's docs.
    pub maker_balances: Vec<u64>,
    pub taker_balances: Vec<u64>,
    pub pre_state_root: [u8; 32],
    pub post_state_root: [u8; 32],
}

// Fixed at circuit/trusted-setup time -- Groth16 can't prove a
// variably-shaped circuit, so a batch always has exactly this many trade
// "slots". A real batch with fewer trades is padded with no-op trades
// (amount = price = 0, contributing nothing to any balance), which is why
// prove_batch accepts anywhere from 1 to MAX_BATCH_TRADES trades. Changing
// this constant changes the circuit's shape, which requires a fresh
// trusted setup (see bn254::trusted_setup_path) and therefore a fresh
// verifying key / BatchVerifier redeployment -- it is not a
// backwards-compatible change.
pub const MAX_BATCH_TRADES: usize = 8;

// Proves balance conservation across a batch of up to MAX_BATCH_TRADES
// sequential trades between one maker/taker pair: starting from
// maker_balance_pre/taker_balance_pre (external to the circuit, folded
// into pre_state_root by the caller), each trade in turn updates both
// balances by its (amount * price) value and folds that traded value
// (not the resulting balances -- see below) into a running root, ending
// at post_state_root.
//
// The root accumulates each trade's `amount * price`, not its resulting
// balances. That's deliberate: a zero-amount padding trade (used to fill
// unused slots in a batch smaller than MAX_BATCH_TRADES) must be a true
// no-op for the root, contributing nothing, regardless of how many
// padding slots exist. Accumulating balances instead would make even a
// no-op trade add its (unchanged) balances to the root again on every
// padding step, so the root would depend on how much padding a batch
// happened to need rather than only on its real trades -- breaking the
// off-chain replay verify_proof uses to independently recompute the
// expected root from just the real trade list.
//
// Only pre_state_root and post_state_root are public inputs -- every
// per-trade balance and the roots between trades are private witnesses.
// This keeps the public input count constant (2) regardless of batch
// size, unlike an earlier single-trade version of this circuit that
// exposed each trade's post-balances as public inputs directly; that
// doesn't generalize cleanly to a batch (it would leak every intermediate
// balance on-chain, once per trade, in every batch's calldata) and isn't
// needed for the conservation property the circuit actually proves.
pub struct DEXBatchCircuit<F: PrimeField> {
    pub maker_balance_pre: Vec<Option<F>>,
    pub taker_balance_pre: Vec<Option<F>>,
    pub amount: Vec<Option<F>>,
    pub price: Vec<Option<F>>,
    pub maker_balance_post: Vec<Option<F>>,
    pub taker_balance_post: Vec<Option<F>>,
    // Root after each trade except the last (whose resulting root IS
    // post_state_root) -- length MAX_BATCH_TRADES - 1.
    pub intermediate_roots: Vec<Option<F>>,
    pub pre_state_root: Option<F>,
    pub post_state_root: Option<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for DEXBatchCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let pre_root_var =
            cs.new_input_variable(|| self.pre_state_root.ok_or(SynthesisError::AssignmentMissing))?;
        let post_root_var = cs.new_input_variable(|| {
            self.post_state_root
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let mut running_root = pre_root_var;

        for i in 0..MAX_BATCH_TRADES {
            let maker_pre = cs.new_witness_variable(|| {
                self.maker_balance_pre
                    .get(i)
                    .copied()
                    .flatten()
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            let taker_pre = cs.new_witness_variable(|| {
                self.taker_balance_pre
                    .get(i)
                    .copied()
                    .flatten()
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            let amt = cs.new_witness_variable(|| {
                self.amount
                    .get(i)
                    .copied()
                    .flatten()
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            let prc = cs.new_witness_variable(|| {
                self.price
                    .get(i)
                    .copied()
                    .flatten()
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            let val = cs.new_witness_variable(|| {
                let a = self
                    .amount
                    .get(i)
                    .copied()
                    .flatten()
                    .ok_or(SynthesisError::AssignmentMissing)?;
                let p = self
                    .price
                    .get(i)
                    .copied()
                    .flatten()
                    .ok_or(SynthesisError::AssignmentMissing)?;
                Ok(a * p)
            })?;

            cs.enforce_constraint(
                LinearCombination::from(amt),
                LinearCombination::from(prc),
                LinearCombination::from(val),
            )?;

            let maker_post = cs.new_witness_variable(|| {
                self.maker_balance_post
                    .get(i)
                    .copied()
                    .flatten()
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            let mut lc_maker = LinearCombination::zero();
            lc_maker = lc_maker + (F::one(), maker_pre) + (F::one(), val);
            cs.enforce_constraint(
                lc_maker,
                LinearCombination::from(Variable::One),
                LinearCombination::from(maker_post),
            )?;

            let taker_post = cs.new_witness_variable(|| {
                self.taker_balance_post
                    .get(i)
                    .copied()
                    .flatten()
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            let mut lc_taker = LinearCombination::zero();
            lc_taker = lc_taker + (F::one(), taker_pre) - (F::one(), val);
            cs.enforce_constraint(
                lc_taker,
                LinearCombination::from(Variable::One),
                LinearCombination::from(taker_post),
            )?;

            let next_root = if i == MAX_BATCH_TRADES - 1 {
                post_root_var
            } else {
                cs.new_witness_variable(|| {
                    self.intermediate_roots
                        .get(i)
                        .copied()
                        .flatten()
                        .ok_or(SynthesisError::AssignmentMissing)
                })?
            };
            // Accumulates val (the traded amount * price), not maker_post +
            // taker_post -- see this struct's docs for why that matters for
            // padding trades.
            let mut lc_root = LinearCombination::zero();
            lc_root = lc_root + (F::one(), running_root) + (F::one(), val);
            cs.enforce_constraint(
                lc_root,
                LinearCombination::from(Variable::One),
                LinearCombination::from(next_root),
            )?;

            running_root = next_root;
        }

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

    pub fn verify_node_sig(batch: &TradeBatch, node_pubkey: &[u8; 32], signature: &[u8]) -> bool {
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
        for &b in &batch.maker_balances {
            msg.extend_from_slice(&b.to_be_bytes());
        }
        for &b in &batch.taker_balances {
            msg.extend_from_slice(&b.to_be_bytes());
        }
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
        Self {
            threshold,
            watchtower_keys: keys,
        }
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

    // Builds a MAX_BATCH_TRADES-slot circuit with one real trade (pre=5,10
    // amount=2 price=3 -> post=11,4, matching the old single-trade test's
    // values) followed by (MAX_BATCH_TRADES - 1) zero-amount padding
    // trades, which must be true no-ops for the root (see
    // DEXBatchCircuit's docs) -- so the final root equals the real trade's
    // val (2*3=6) added to pre_state_root (0), i.e. 6, regardless of how
    // many padding slots follow it.
    fn batch_circuit_one_real_trade(tamper_maker_post: bool) -> DEXBatchCircuit<Fq> {
        let real_maker_post = if tamper_maker_post {
            Fq::from(99u64)
        } else {
            Fq::from(11u64)
        };

        let mut maker_pre = vec![Some(Fq::from(5u64))];
        let mut taker_pre = vec![Some(Fq::from(10u64))];
        let mut amount = vec![Some(Fq::from(2u64))];
        let mut price = vec![Some(Fq::from(3u64))];
        let mut maker_post = vec![Some(real_maker_post)];
        let mut taker_post = vec![Some(Fq::from(4u64))];

        for _ in 1..MAX_BATCH_TRADES {
            maker_pre.push(Some(Fq::from(0u64)));
            taker_pre.push(Some(Fq::from(0u64)));
            amount.push(Some(Fq::from(0u64)));
            price.push(Some(Fq::from(0u64)));
            maker_post.push(Some(Fq::from(0u64)));
            taker_post.push(Some(Fq::from(0u64)));
        }

        // val for every padding trade is 0, so the root never moves past
        // the first trade's contribution -- every intermediate root is 6.
        let intermediate_roots = vec![Some(Fq::from(6u64)); MAX_BATCH_TRADES - 1];

        DEXBatchCircuit::<Fq> {
            maker_balance_pre: maker_pre,
            taker_balance_pre: taker_pre,
            amount,
            price,
            maker_balance_post: maker_post,
            taker_balance_post: taker_post,
            intermediate_roots,
            pre_state_root: Some(Fq::from(0u64)),
            post_state_root: Some(Fq::from(6u64)),
        }
    }

    #[test]
    fn test_zk_circuit_satisfied() {
        let circuit = batch_circuit_one_real_trade(false);

        let cs = ark_relations::r1cs::ConstraintSystem::new();
        let cs_ref = ConstraintSystemRef::new(cs);
        assert!(circuit.generate_constraints(cs_ref.clone()).is_ok());
        assert!(cs_ref.is_satisfied().unwrap_or(false));
    }

    // Stage P6-1b-2: structural equivalence with circuit/circom/
    // dex_batch.circom -- the arkworks circuit's own constraint/
    // variable counts must match what `circom --r1cs` reports for the
    // ported circuit. This alone isn't sufficient proof of equivalence
    // (two DIFFERENT constraint systems could coincidentally have the
    // same counts), but a mismatch would be conclusive proof of
    // INEQUIVALENCE, so it's a cheap, meaningful first check -- see
    // circuit/circom/EQUIVALENCE.md for the full reasoning and the
    // witness-level cross-check that complements it.
    //
    // Expected counts, and why:
    //   num_constraints = 32        (circom: 8 non-linear + 24 linear)
    //   num_instance_variables = 3  (circom: 2 public inputs, +1 for
    //                                 the implicit constant-one wire
    //                                 every R1CS system has)
    //   num_witness_variables = 63  (circom: 55 declared private
    //                                 inputs -- 6 arrays of 8 slots
    //                                 (makerPre/takerPre/amount/price/
    //                                 makerPost/takerPost) + 7
    //                                 intermediateRoots -- plus 8
    //                                 internal `val` signals circom
    //                                 doesn't count as "inputs" but
    //                                 arkworks' flat witness-variable
    //                                 model does: 55 + 8 = 63)
    #[test]
    fn test_constraint_counts_match_the_circom_port() {
        let circuit = batch_circuit_one_real_trade(false);
        let cs = ark_relations::r1cs::ConstraintSystem::new();
        let cs_ref = ConstraintSystemRef::new(cs);
        circuit.generate_constraints(cs_ref.clone()).unwrap();
        assert_eq!(
            cs_ref.num_constraints(),
            32,
            "must match circom's reported 8 non-linear + 24 linear = 32 constraints"
        );
        assert_eq!(
            cs_ref.num_instance_variables(),
            3,
            "must match circom's 2 public inputs (+1 for the implicit constant-one wire)"
        );
        assert_eq!(
            cs_ref.num_witness_variables(),
            63,
            "must match circom's 55 declared private inputs + 8 internal `val` signals"
        );
    }

    #[test]
    fn test_zk_circuit_unsatisfied_tampered_post_balance() {
        let circuit = batch_circuit_one_real_trade(true);

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
            maker_balances: vec![1_000_000],
            taker_balances: vec![1_000_000],
            pre_state_root: [0u8; 32],
            // Root = sum of each trade's (amount * price), not maker_post +
            // taker_post -- see DEXBatchCircuit's docs. One trade of
            // 3000 * 5.
            post_state_root: u64_to_bytes32(3000 * 5),
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
