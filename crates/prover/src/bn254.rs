use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey, Proof, prepare_verifying_key};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_snark::SNARK;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::{DEXBatchCircuit, TradeBatch, MAX_BATCH_TRADES};
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

// Builds a full, self-consistent MAX_BATCH_TRADES-slot circuit instance
// from a (possibly shorter) list of (amount, price) trades, a starting
// maker/taker balance, and a starting root. Trades beyond `trades.len()`
// are padded with (0, 0) -- true no-ops for both balances and the root
// (see DEXBatchCircuit's docs). Used by both setup_circuit (an arbitrary
// but internally consistent dummy instance, needed only to fix the
// circuit's shape for the one-time trusted setup) and prove_batch (the
// real thing).
fn padded_witness(trades: &[(u64, u64)], maker_balance: u64, taker_balance: u64, pre_root: Fr) -> DEXBatchCircuit<Fr> {
    assert!(trades.len() <= MAX_BATCH_TRADES, "padded_witness caller must enforce the batch-size limit itself");

    let mut maker_pre = Vec::with_capacity(MAX_BATCH_TRADES);
    let mut taker_pre = Vec::with_capacity(MAX_BATCH_TRADES);
    let mut amount = Vec::with_capacity(MAX_BATCH_TRADES);
    let mut price = Vec::with_capacity(MAX_BATCH_TRADES);
    let mut maker_post = Vec::with_capacity(MAX_BATCH_TRADES);
    let mut taker_post = Vec::with_capacity(MAX_BATCH_TRADES);
    let mut intermediate_roots = Vec::with_capacity(MAX_BATCH_TRADES.saturating_sub(1));

    let mut maker_bal = Fr::from(maker_balance);
    let mut taker_bal = Fr::from(taker_balance);
    let mut root = pre_root;

    for i in 0..MAX_BATCH_TRADES {
        let (amt_u64, prc_u64) = trades.get(i).copied().unwrap_or((0, 0));
        let amt = Fr::from(amt_u64);
        let prc = Fr::from(prc_u64);
        let val = amt * prc;
        let m_post = maker_bal + val;
        let t_post = taker_bal - val;

        maker_pre.push(Some(maker_bal));
        taker_pre.push(Some(taker_bal));
        amount.push(Some(amt));
        price.push(Some(prc));
        maker_post.push(Some(m_post));
        taker_post.push(Some(t_post));

        root += val;
        if i < MAX_BATCH_TRADES - 1 {
            intermediate_roots.push(Some(root));
        }

        maker_bal = m_post;
        taker_bal = t_post;
    }

    DEXBatchCircuit {
        maker_balance_pre: maker_pre,
        taker_balance_pre: taker_pre,
        amount,
        price,
        maker_balance_post: maker_post,
        taker_balance_post: taker_post,
        intermediate_roots,
        pre_state_root: Some(pre_root),
        post_state_root: Some(root),
    }
}

fn setup_circuit() -> DEXBatchCircuit<Fr> {
    let dummy_trades = vec![(1u64, 1u64); MAX_BATCH_TRADES];
    padded_witness(&dummy_trades, 10, 10, Fr::from(0u64))
}

struct SetupParams {
    pk: ProvingKey<Bn254>,
    vk: VerifyingKey<Bn254>,
}

// Where the persisted trusted setup (the Groth16 proving key, which embeds
// the verifying key) lives. Overridable via MEX_TRUSTED_SETUP_PATH -- e.g.
// to point multiple test processes at a shared temp file, or to isolate a
// test's own setup from the checked-in default. Defaults to a fixed path
// under this crate's own directory (via CARGO_MANIFEST_DIR, resolved at
// compile time) rather than the current working directory, so it resolves
// the same way regardless of where the binary is run from.
fn trusted_setup_path() -> PathBuf {
    if let Ok(path) = std::env::var("MEX_TRUSTED_SETUP_PATH") {
        return PathBuf::from(path);
    }
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/trusted_setup.bin"))
}

// Loads the proving key from disk if present, otherwise runs the (one-time,
// insecure-toxic-waste, dev-only) setup and persists it so every later
// process -- not just this one -- reuses the exact same key. Without this,
// every process restart silently generated a fresh, incompatible key: a
// verifying key exported (or a BatchVerifier deployed) from one run could
// never validate a proof produced by a different run.
fn load_or_generate_pk(path: &Path) -> ProvingKey<Bn254> {
    if let Ok(bytes) = std::fs::read(path) {
        if let Ok(pk) = ProvingKey::<Bn254>::deserialize_compressed(bytes.as_slice()) {
            return pk;
        }
        // Corrupt or incompatible file (e.g. from a different arkworks
        // version) -- fall through and regenerate rather than fail closed.
    }

    let circuit = setup_circuit();
    let mut rng = OsRng;
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng)
        .expect("Groth16 setup failed");

    let mut bytes = Vec::new();
    if pk.serialize_compressed(&mut bytes).is_ok() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // Write-then-rename so a crash or a concurrent second process
        // generating its own key at the same time can't leave a partially
        // written, corrupt file behind for the next reader.
        let tmp_path = path.with_extension("bin.tmp");
        if std::fs::write(&tmp_path, &bytes).is_ok() {
            let _ = std::fs::rename(&tmp_path, path);
        }
    }

    pk
}

fn setup_params() -> &'static SetupParams {
    static PARAMS: OnceLock<SetupParams> = OnceLock::new();
    PARAMS.get_or_init(|| {
        let pk = load_or_generate_pk(&trusted_setup_path());
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
        if batch.trades.len() > MAX_BATCH_TRADES {
            return Err(format!(
                "Batch of {} trades exceeds the circuit's max of {MAX_BATCH_TRADES}",
                batch.trades.len()
            ));
        }

        let mut total_value_u128 = 0u128;
        for trade in &batch.trades {
            total_value_u128 += trade.amount as u128 * trade.price as u128;
        }
        if total_value_u128 > batch.taker_balance as u128 {
            return Err(format!(
                "Insolvent batch: total value {} exceeds taker balance {}",
                total_value_u128, batch.taker_balance
            ));
        }

        let trade_pairs: Vec<(u64, u64)> = batch.trades.iter().map(|t| (t.amount, t.price)).collect();
        let pre_root = bytes_to_fe(&batch.pre_state_root);
        let circuit = padded_witness(&trade_pairs, batch.maker_balance, batch.taker_balance, pre_root);
        let post_root = circuit.post_state_root.expect("padded_witness always sets post_state_root");

        let pk = proving_key();
        let mut rng = OsRng;
        let proof = Groth16::<Bn254>::prove(pk, circuit, &mut rng)
            .map_err(|e| format!("Proving failed: {:?}", e))?;

        let mut proof_bytes = Vec::new();
        proof
            .serialize_compressed(&mut proof_bytes)
            .map_err(|e| format!("Proof serialization failed: {:?}", e))?;

        let public_inputs = vec![pre_root, post_root];
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

        if batch.trades.is_empty() || batch.trades.len() > MAX_BATCH_TRADES {
            return false;
        }

        let mut total_value_u128 = 0u128;
        for trade in &batch.trades {
            total_value_u128 += trade.amount as u128 * trade.price as u128;
        }
        if total_value_u128 > batch.taker_balance as u128 {
            // Insolvent batch: taker_balance - total_value would wrap around the
            // BN254 scalar field instead of underflowing, silently producing a
            // huge-but-"valid" post-balance. Reject before that can happen.
            return false;
        }

        // Padding trades contribute 0 to the root (see DEXBatchCircuit's
        // docs), so replaying only the real trades here -- without needing
        // to know or reproduce how many padding slots the prover used --
        // gives exactly the same root the circuit computed.
        let mut total_value = Fr::from(0u64);
        for trade in &batch.trades {
            let amount = Fr::from(trade.amount as u64);
            let price = Fr::from(trade.price as u64);
            total_value += amount * price;
        }

        let expected_pre_root = bytes_to_fe(&batch.pre_state_root);
        let expected_post_root = expected_pre_root + total_value;

        if bytes_to_fe(&batch.post_state_root) != expected_post_root {
            return false;
        }

        let expected_inputs = vec![
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

    fn make_match(price: u64, amount: u64) -> Match {
        Match {
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
            assigned_node: [0u8; 32],
            settlement_deadline: 0,
        }
    }

    #[test]
    fn test_bn254_prove_and_verify_single_trade() {
        let maker_balance = 1_000_000u64;
        let taker_balance = 1_000_000u64;
        let total_value = 3000u64 * 5u64;
        let post_root_val = total_value;

        let batch = TradeBatch {
            trades: vec![make_match(3000, 5)],
            maker_balance,
            taker_balance,
            pre_state_root: [0u8; 32],
            post_state_root: u64_to_bytes32(post_root_val),
        };

        let backend = Bn254Groth16Backend;
        let proof = backend.prove_batch(&batch).unwrap();
        assert!(backend.verify_proof(&proof, &batch));
    }

    // The actual point of this whole rewrite: a batch of several distinct
    // trades, proven under a single proof, must verify -- and the root
    // must reflect the SUM of all real trades' values (not just the
    // first, and not inflated by the padding slots the circuit uses
    // internally to reach MAX_BATCH_TRADES).
    #[test]
    fn test_bn254_prove_and_verify_multi_trade_batch() {
        let maker_balance = 1_000_000u64;
        let taker_balance = 1_000_000u64;

        let trades = vec![
            make_match(3000, 5),
            make_match(2950, 3),
            make_match(3010, 7),
        ];
        let total_value: u64 = trades.iter().map(|t| t.price * t.amount).sum();

        let batch = TradeBatch {
            trades,
            maker_balance,
            taker_balance,
            pre_state_root: [0u8; 32],
            post_state_root: u64_to_bytes32(total_value),
        };

        let backend = Bn254Groth16Backend;
        let proof = backend.prove_batch(&batch).unwrap();
        assert!(backend.verify_proof(&proof, &batch), "a real multi-trade batch's proof must verify");

        // Same proof, but checked against a batch missing one trade (a
        // different, smaller total_value/post_state_root) -- must fail,
        // proving the batch's root really is bound to ALL of its trades,
        // not just however many the verifier happens to be told about.
        let mut short_batch = batch.clone();
        short_batch.trades.pop();
        let short_total: u64 = short_batch.trades.iter().map(|t| t.price * t.amount).sum();
        short_batch.post_state_root = u64_to_bytes32(short_total);
        assert!(
            !backend.verify_proof(&proof, &short_batch),
            "a proof for 3 trades must not verify against a claimed 2-trade batch"
        );
    }

    #[test]
    fn test_bn254_batch_over_max_size_rejected() {
        let maker_balance = 10_000_000u64;
        let taker_balance = 10_000_000u64;
        let trades: Vec<Match> = (0..(MAX_BATCH_TRADES + 1)).map(|_| make_match(10, 1)).collect();

        let batch = TradeBatch {
            trades,
            maker_balance,
            taker_balance,
            pre_state_root: [0u8; 32],
            post_state_root: [0u8; 32],
        };

        let backend = Bn254Groth16Backend;
        assert!(backend.prove_batch(&batch).is_err());
    }

    #[test]
    fn test_decode_proof_calldata_matches_public_inputs() {
        let maker_balance = 1_000_000u64;
        let taker_balance = 1_000_000u64;
        let pre_root = 0u64;
        let post_root_val = 3000u64 * 5u64;

        let batch = TradeBatch {
            trades: vec![make_match(3000, 5)],
            maker_balance,
            taker_balance,
            pre_state_root: [0u8; 32],
            post_state_root: u64_to_bytes32(post_root_val),
        };

        let backend = Bn254Groth16Backend;
        let proof = backend.prove_batch(&batch).unwrap();
        let calldata = decode_proof_calldata(&proof).unwrap();

        // 2 public inputs: pre_root, post_root (see prove_batch's
        // `public_inputs` vec and DEXBatchCircuit's docs for why
        // per-trade balances are no longer public).
        assert_eq!(calldata.public_inputs.len(), 2);
        assert_eq!(calldata.public_inputs[0], u64_to_bytes32(pre_root));
        assert_eq!(calldata.public_inputs[1], u64_to_bytes32(post_root_val));

        // a/c are G1 points (non-infinity for a real proof); b is G2. Just
        // assert they're non-zero -- an actual pairing-check round trip
        // against BatchVerifier.sol needs a real chain, exercised in the
        // chain-ethereum crate's live tests instead of here.
        assert_ne!(calldata.a, [[0u8; 32]; 2]);
        assert_ne!(calldata.c, [[0u8; 32]; 2]);
        assert_ne!(calldata.b, [[[0u8; 32]; 2]; 2]);
    }
}

#[cfg(test)]
mod persistence_tests {
    use super::*;

    fn pk_bytes(pk: &ProvingKey<Bn254>) -> Vec<u8> {
        let mut bytes = Vec::new();
        pk.serialize_compressed(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn test_load_or_generate_persists_across_calls() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("setup.bin");
        assert!(!path.exists());

        let first = load_or_generate_pk(&path);
        assert!(path.exists(), "first call must persist the generated key to disk");

        let second = load_or_generate_pk(&path);
        assert_eq!(
            pk_bytes(&first),
            pk_bytes(&second),
            "a second call against the same path must load the identical key, not generate a new one"
        );
    }

    #[test]
    fn test_different_paths_get_independent_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path_a = dir.path().join("a.bin");
        let path_b = dir.path().join("b.bin");

        let a = load_or_generate_pk(&path_a);
        let b = load_or_generate_pk(&path_b);

        assert_ne!(
            pk_bytes(&a),
            pk_bytes(&b),
            "two never-before-seen paths should each get their own freshly generated key"
        );
    }

    #[test]
    fn test_corrupt_file_falls_back_to_regeneration_instead_of_failing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corrupt.bin");
        std::fs::write(&path, b"not a valid proving key").unwrap();

        // Must not panic -- a corrupt/incompatible file is recoverable by
        // regenerating, not a fatal condition.
        let _pk = load_or_generate_pk(&path);
    }
}
