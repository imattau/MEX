use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey, Proof, prepare_verifying_key};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_snark::SNARK;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

use crate::{DEXTradeCircuit, TradeBatch};
use crate::backend::ProverBackend;

fn bytes_to_fe(data: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(data)
}

fn g1_to_xy(point: &G1Affine) -> Option<(Vec<u8>, Vec<u8>)> {
    if let Some((x, y)) = point.xy() {
        let mut xb = Vec::new();
        let mut yb = Vec::new();
        x.serialize_compressed(&mut xb).ok()?;
        y.serialize_compressed(&mut yb).ok()?;
        Some((xb, yb))
    } else {
        None
    }
}

fn group_to_hex(point: &G1Affine) -> serde_json::Value {
    if let Some((x, y)) = g1_to_xy(point) {
        serde_json::json!([hex::encode(x), hex::encode(y)])
    } else {
        serde_json::json!(["0", "0"])
    }
}

fn g2_to_tuple(point: &G2Affine) -> serde_json::Value {
    let (x, y) = match point.xy() {
        Some(p) => p,
        None => return serde_json::json!([["0", "0"], ["0", "0"]]),
    };
    let mut x_c0 = Vec::new();
    let mut x_c1 = Vec::new();
    let mut y_c0 = Vec::new();
    let mut y_c1 = Vec::new();
    x.c0.serialize_compressed(&mut x_c0).unwrap_or_default();
    x.c1.serialize_compressed(&mut x_c1).unwrap_or_default();
    y.c0.serialize_compressed(&mut y_c0).unwrap_or_default();
    y.c1.serialize_compressed(&mut y_c1).unwrap_or_default();
    serde_json::json!([
        [hex::encode(x_c0), hex::encode(x_c1)],
        [hex::encode(y_c0), hex::encode(y_c1)],
    ])
}

fn setup_circuit() -> DEXTradeCircuit<Fr> {
    DEXTradeCircuit {
        maker_balance_pre: Some(Fr::from(1u64)),
        taker_balance_pre: Some(Fr::from(1u64)),
        amount: Some(Fr::from(1u64)),
        price: Some(Fr::from(1u64)),
        maker_balance_post: Some(Fr::from(2u64)),
        taker_balance_post: Some(Fr::from(0u64)),
        pre_state_root: Some(Fr::from(0u64)),
        post_state_root: Some(Fr::from(0u64)),
    }
}

struct SetupParams {
    pk: ProvingKey<Bn254>,
    vk: VerifyingKey<Bn254>,
}

fn setup_params() -> &'static SetupParams {
    static PARAMS: OnceLock<SetupParams> = OnceLock::new();
    PARAMS.get_or_init(|| {
        let circuit = setup_circuit();
        let mut rng = OsRng;
        let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng)
            .expect("Groth16 setup failed");
        let vk = pk.vk.clone();
        SetupParams { pk, vk }
    })
}

fn proving_key() -> &'static ProvingKey<Bn254> {
    &setup_params().pk
}

fn prepared_vk() -> &'static VerifyingKey<Bn254> {
    &setup_params().vk
}

#[derive(Serialize, Deserialize)]
struct ProofData {
    proof: Vec<u8>,
    public_inputs: Vec<Vec<u8>>,
}

pub struct Bn254Groth16Backend;

impl ProverBackend for Bn254Groth16Backend {
    fn name(&self) -> &'static str {
        "BN254-Groth16 (Ethereum alt_bn128)"
    }

    fn prove_batch(&self, batch: &TradeBatch) -> Result<Vec<u8>, String> {
        if batch.trades.is_empty() {
            return Err("Empty batch".to_string());
        }
        // The circuit's trusted setup is fixed to a single (amount, price) witness pair,
        // so it can only bind the witness to real trade data for a single trade. Batches
        // with more than one trade would have to fall back to a placeholder witness (as
        // before), which proves nothing about the individual trades -- reject them instead
        // of silently proving over fake data.
        if batch.trades.len() != 1 {
            return Err(format!(
                "Circuit only supports single-trade batches, got {} trades",
                batch.trades.len()
            ));
        }
        let trade = &batch.trades[0];

        let total_value_u128 = trade.amount as u128 * trade.price as u128;
        if total_value_u128 > batch.taker_balance as u128 {
            return Err(format!(
                "Insolvent trade: value {} exceeds taker balance {}",
                total_value_u128, batch.taker_balance
            ));
        }

        let pre_balance = Fr::from(batch.maker_balance);
        let taker_pre_balance = Fr::from(batch.taker_balance);

        let amount = Fr::from(trade.amount as u64);
        let price = Fr::from(trade.price as u64);
        let total_value = amount * price;

        let maker_post = pre_balance + total_value;
        let taker_post = taker_pre_balance - total_value;
        let pre_root = bytes_to_fe(&batch.pre_state_root);
        let post_root = pre_root + maker_post + taker_post;

        let circuit = DEXTradeCircuit::<Fr> {
            maker_balance_pre: Some(pre_balance),
            taker_balance_pre: Some(taker_pre_balance),
            amount: Some(amount),
            price: Some(price),
            maker_balance_post: Some(maker_post),
            taker_balance_post: Some(taker_post),
            pre_state_root: Some(pre_root),
            post_state_root: Some(post_root),
        };

        let pk = proving_key();
        let mut rng = OsRng;
        let proof = Groth16::<Bn254>::prove(pk, circuit, &mut rng)
            .map_err(|e| format!("Proving failed: {:?}", e))?;

        let mut proof_bytes = Vec::new();
        proof
            .serialize_compressed(&mut proof_bytes)
            .map_err(|e| format!("Proof serialization failed: {:?}", e))?;

        let public_inputs = vec![maker_post, taker_post, pre_root, post_root];
        let mut public_bytes = Vec::new();
        for input in &public_inputs {
            let mut buf = Vec::new();
            input
                .serialize_compressed(&mut buf)
                .map_err(|e| format!("Input serialization failed: {:?}", e))?;
            public_bytes.push(buf);
        }

        let data = ProofData {
            proof: proof_bytes,
            public_inputs: public_bytes,
        };

        serde_json::to_vec(&data).map_err(|e| format!("JSON encode failed: {}", e))
    }

    fn verify_proof(&self, proof_data: &[u8], batch: &TradeBatch) -> bool {
        let data: ProofData = match serde_json::from_slice(proof_data) {
            Ok(d) => d,
            Err(_) => return false,
        };

        let proof = match Proof::<Bn254>::deserialize_compressed(data.proof.as_slice()) {
            Ok(p) => p,
            Err(_) => return false,
        };

        if batch.trades.is_empty() {
            return false;
        }

        let mut total_value_u128 = 0u128;
        for trade in &batch.trades {
            total_value_u128 += trade.amount as u128 * trade.price as u128;
        }
        if total_value_u128 > batch.taker_balance as u128 {
            // Insolvent trade: taker_balance - total_value would wrap around the
            // BN254 scalar field instead of underflowing, silently producing a
            // huge-but-"valid" post-balance. Reject before that can happen.
            return false;
        }

        let pre_balance = Fr::from(batch.maker_balance);
        let taker_pre_balance = Fr::from(batch.taker_balance);

        let mut total_value = Fr::from(0u64);
        for trade in &batch.trades {
            let amount = Fr::from(trade.amount as u64);
            let price = Fr::from(trade.price as u64);
            total_value += amount * price;
        }

        let expected_maker_post = pre_balance + total_value;
        let expected_taker_post = taker_pre_balance - total_value;
        let expected_pre_root = bytes_to_fe(&batch.pre_state_root);
        let expected_post_root = expected_pre_root + expected_maker_post + expected_taker_post;

        if bytes_to_fe(&batch.post_state_root) != expected_post_root {
            return false;
        }

        let expected_inputs = vec![
            expected_maker_post,
            expected_taker_post,
            expected_pre_root,
            expected_post_root,
        ];

        if data.public_inputs.len() != expected_inputs.len() {
            return false;
        }

        let mut deserialized_inputs = Vec::new();
        for (i, input_bytes) in data.public_inputs.iter().enumerate() {
            match Fr::deserialize_compressed(input_bytes.as_slice()) {
                Ok(v) => {
                    if v != expected_inputs[i] {
                        return false;
                    }
                    deserialized_inputs.push(v);
                }
                Err(_) => return false,
            }
        }

        let vk = prepared_vk();
        let pvk = prepare_verifying_key(vk);
        Groth16::<Bn254>::verify_proof(&pvk, &proof, &deserialized_inputs)
            .unwrap_or(false)
    }

    fn export_verifying_key(&self) -> serde_json::Value {
        let vk = prepared_vk();
        serde_json::json!({
            "alpha": group_to_hex(&vk.alpha_g1),
            "beta": g2_to_tuple(&vk.beta_g2),
            "gamma": g2_to_tuple(&vk.gamma_g2),
            "delta": g2_to_tuple(&vk.delta_g2),
            "ic": vk.gamma_abc_g1.iter().map(group_to_hex).collect::<Vec<_>>(),
        })
    }
}

// The raw (a, b, c, public_inputs) shape an on-chain Groth16 verifier expects
// as calldata: each field element as a big-endian uint256. This is distinct
// from the JSON `ProofData` prove_batch returns, which wraps ark-serialize's
// *compressed* (and little-endian) encoding -- fine for passing the proof
// bytes back into verify_proof, but not directly usable as EVM calldata.
pub struct ProofCalldata {
    pub a: [[u8; 32]; 2],
    pub b: [[[u8; 32]; 2]; 2],
    pub c: [[u8; 32]; 2],
    pub public_inputs: Vec<[u8; 32]>,
}

// BN254's base and scalar fields are both 254 bits, so to_bytes_be() never
// exceeds 32 bytes; left-pad with zeros to the fixed-width uint256 encoding
// EVM calldata expects.
fn field_to_be_bytes<F: PrimeField>(f: &F) -> [u8; 32] {
    let bytes = f.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let start = out.len() - bytes.len();
    out[start..].copy_from_slice(&bytes);
    out
}

fn g1_to_be_bytes(point: &G1Affine) -> Result<[[u8; 32]; 2], String> {
    let (x, y) = point.xy().ok_or("G1 point is the point at infinity")?;
    Ok([field_to_be_bytes(x), field_to_be_bytes(y)])
}

fn g2_to_be_bytes(point: &G2Affine) -> Result<[[[u8; 32]; 2]; 2], String> {
    let (x, y) = point.xy().ok_or("G2 point is the point at infinity")?;
    Ok([
        [field_to_be_bytes(&x.c0), field_to_be_bytes(&x.c1)],
        [field_to_be_bytes(&y.c0), field_to_be_bytes(&y.c1)],
    ])
}

// Decodes prove_batch's output into the raw calldata shape a Groth16
// verifier's verifyProof(a, b, c, input) expects. Field-element byte order
// here is big-endian (standard uint256 encoding) -- NOT the little-endian
// order ark-serialize's compressed format uses internally, so this cannot
// just re-slice the JSON bytes; it fully deserializes the proof and public
// inputs and re-encodes each field element from scratch.
pub fn decode_proof_calldata(proof_bytes: &[u8]) -> Result<ProofCalldata, String> {
    let data: ProofData =
        serde_json::from_slice(proof_bytes).map_err(|e| format!("JSON decode failed: {e}"))?;

    let proof = Proof::<Bn254>::deserialize_compressed(data.proof.as_slice())
        .map_err(|e| format!("Proof deserialization failed: {e:?}"))?;

    let a = g1_to_be_bytes(&proof.a)?;
    let b = g2_to_be_bytes(&proof.b)?;
    let c = g1_to_be_bytes(&proof.c)?;

    let mut public_inputs = Vec::with_capacity(data.public_inputs.len());
    for input_bytes in &data.public_inputs {
        let fr = Fr::deserialize_compressed(input_bytes.as_slice())
            .map_err(|e| format!("Public input deserialization failed: {e:?}"))?;
        public_inputs.push(field_to_be_bytes(&fr));
    }

    Ok(ProofCalldata { a, b, c, public_inputs })
}

// The verifying key in the same raw big-endian uint256 shape as
// ProofCalldata, suitable as BatchVerifier.sol constructor arguments --
// unlike export_verifying_key()'s hex-encoded *compressed* point encoding
// (fine for display/debugging, not usable as calldata/constructor args).
pub struct VerifyingKeyCalldata {
    pub alpha: [[u8; 32]; 2],
    pub beta: [[[u8; 32]; 2]; 2],
    pub gamma: [[[u8; 32]; 2]; 2],
    pub delta: [[[u8; 32]; 2]; 2],
    pub ic: Vec<[[u8; 32]; 2]>,
}

pub fn export_verifying_key_calldata() -> Result<VerifyingKeyCalldata, String> {
    let vk = prepared_vk();
    let alpha = g1_to_be_bytes(&vk.alpha_g1)?;
    let beta = g2_to_be_bytes(&vk.beta_g2)?;
    let gamma = g2_to_be_bytes(&vk.gamma_g2)?;
    let delta = g2_to_be_bytes(&vk.delta_g2)?;
    let ic = vk
        .gamma_abc_g1
        .iter()
        .map(g1_to_be_bytes)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(VerifyingKeyCalldata { alpha, beta, gamma, delta, ic })
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

    #[test]
    fn test_bn254_prove_and_verify() {
        let maker_balance = 1_000_000u64;
        let taker_balance = 1_000_000u64;
        let price = 3000u64;
        let amount = 5u64;
        let total_value = price * amount;
        let maker_post = maker_balance + total_value;
        let taker_post = taker_balance - total_value;
        let post_root_val = maker_post + taker_post;

        let batch = TradeBatch {
            trades: vec![Match {
                maker_order_id: [1u8; 32],
                taker_order_id: [2u8; 32],
                maker_trader: [0u8; 32],
                taker_trader: [0u8; 32],
                price,
                amount,
                timestamp_us: 1700000000,
                settlement_tier: SettlementPreference::Standard,
                fee_basis_points: 5,
                seller: [0u8; 32],
                fee_payer: [0u8; 32],
                symbol: "BTC-USD".to_string(),
                settlement_deadline: 0,
            }],
            maker_balance,
            taker_balance,
            pre_state_root: [0u8; 32],
            post_state_root: u64_to_bytes32(post_root_val),
        };

        let backend = Bn254Groth16Backend;
        let proof = backend.prove_batch(&batch).unwrap();
        assert!(backend.verify_proof(&proof, &batch));
    }

    #[test]
    fn test_decode_proof_calldata_matches_public_inputs() {
        let maker_balance = 1_000_000u64;
        let taker_balance = 1_000_000u64;
        let price = 3000u64;
        let amount = 5u64;
        let total_value = price * amount;
        let maker_post = maker_balance + total_value;
        let taker_post = taker_balance - total_value;
        let pre_root = 0u64;
        let post_root_val = maker_post + taker_post;

        let batch = TradeBatch {
            trades: vec![Match {
                maker_order_id: [1u8; 32],
                taker_order_id: [2u8; 32],
                maker_trader: [0u8; 32],
                taker_trader: [0u8; 32],
                price,
                amount,
                timestamp_us: 1700000000,
                settlement_tier: SettlementPreference::Standard,
                fee_basis_points: 5,
                seller: [0u8; 32],
                fee_payer: [0u8; 32],
                symbol: "BTC-USD".to_string(),
                settlement_deadline: 0,
            }],
            maker_balance,
            taker_balance,
            pre_state_root: [0u8; 32],
            post_state_root: u64_to_bytes32(post_root_val),
        };

        let backend = Bn254Groth16Backend;
        let proof = backend.prove_batch(&batch).unwrap();
        let calldata = decode_proof_calldata(&proof).unwrap();

        // 4 public inputs: maker_post, taker_post, pre_root, post_root (see
        // prove_batch's `public_inputs` vec) -- each a big-endian uint256
        // matching the plaintext u64 values used to build this batch, since
        // none of them come close to wrapping the scalar field here.
        assert_eq!(calldata.public_inputs.len(), 4);
        assert_eq!(calldata.public_inputs[0], u64_to_bytes32(maker_post));
        assert_eq!(calldata.public_inputs[1], u64_to_bytes32(taker_post));
        assert_eq!(calldata.public_inputs[2], u64_to_bytes32(pre_root));
        assert_eq!(calldata.public_inputs[3], u64_to_bytes32(post_root_val));

        // a/c are G1 points (non-infinity for a real proof); b is G2. Just
        // assert they're non-zero -- an actual pairing-check round trip
        // against BatchVerifier.sol needs a real chain, exercised in the
        // chain-ethereum crate's live tests instead of here.
        assert_ne!(calldata.a, [[0u8; 32]; 2]);
        assert_ne!(calldata.c, [[0u8; 32]; 2]);
        assert_ne!(calldata.b, [[[0u8; 32]; 2]; 2]);
    }
}
