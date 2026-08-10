//! Calldata parsing and Groth16 verification math for the settlement
//! contract, independent of FRG's host-function ABI (see `src/lib.rs` for
//! the wasm32 entrypoints that call into this module).
//!
//! # Calldata format (the bytes after the 4-byte function selector)
//!
//! ```text
//! [0..32)    pre_root, big-endian Fr  (the proof's 1st public input)
//! [32..64)   post_root, big-endian Fr (the proof's 2nd public input)
//! [64]       trade_count, 1..=MAX_TRADES
//! [65..)     trade_count trade_hash entries, 32 bytes each
//! [..+256)   Groth16 proof: a.x(32) a.y(32) | b.x.c0(32) b.x.c1(32) b.y.c0(32) b.y.c1(32) | c.x(32) c.y(32)
//! ```
//!
//! `a`/`c` are G1 in plain (x, y) order; `b` is G2 in arkworks' natural
//! (c0, c1) order -- the same layout `prover::decode_proof_calldata`
//! produces. This deliberately matches `ProofCalldata`/`VerifyingKeyCalldata`
//! rather than a wasm/FRG-specific format, so a future caller can build this
//! calldata directly from `prover`'s existing output with no extra
//! reordering of its own; `build_pairing_input` below does the (c0,c1) ->
//! (c1,c0) reorder into the host precompile's format itself, the same way
//! `BatchVerifier.sol`'s `_verifyGroth16` reorders before calling the EVM's
//! 0x08 precompile (see that function's comment for the EIP-197 rationale,
//! confirmed here against `golang.org/x/crypto/bn256`'s actual `G2.Marshal`
//! source, since that's what FRG's `bn254_pairing_check` unmarshals with).
//!
//! `pre_root`/`post_root` are trusted directly as the proof's public
//! inputs, not independently recomputed from the trades here -- mirroring
//! `BatchVerifier.sol`, whose `verifyProof` also just checks the proof
//! against whatever `input` it's given, with no on-chain recomputation from
//! `TradeEntry[]` amounts. `chain::SettlementTrade` (what
//! `ChainAdapter::submit_settlement_batch` actually receives) has no
//! `price` field to recompute a root from in the first place; the
//! trade-hash list here exists only to pick which trades get flagged
//! settled after a successful proof check, same role `TradeEntry[]` plays
//! in `SettlementFactory.settleBatchWithFees`.

use crate::encoding::{fq_from_be, fq_to_be, fr_from_be};
use crate::vk;
use alloc::vec::Vec;
use ark_bn254::{Fq2, G1Affine, G1Projective, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;

pub const PROOF_LEN: usize = 256;
pub const MAX_TRADES: usize = 8;
const HEADER_LEN: usize = 65;
pub const MAX_CALLDATA_LEN: usize = HEADER_LEN + 32 * MAX_TRADES + PROOF_LEN;

pub struct ParsedBatch {
    pub pre_root: [u8; 32],
    pub post_root: [u8; 32],
    pub trade_hashes: Vec<[u8; 32]>,
    pub proof: [u8; PROOF_LEN],
}

/// Parses calldata into a batch, or `None` if it's the wrong length for its
/// own declared `trade_count`, or `trade_count` is out of `1..=MAX_TRADES`.
/// Does not touch curve/field validity yet -- that happens lazily in
/// `build_pairing_input`, where a bad point is indistinguishable from a bad
/// proof (both just fail verification).
pub fn parse_calldata(data: &[u8]) -> Option<ParsedBatch> {
    if data.len() < HEADER_LEN {
        return None;
    }
    let pre_root: [u8; 32] = data[0..32].try_into().ok()?;
    let post_root: [u8; 32] = data[32..64].try_into().ok()?;
    let trade_count = data[64] as usize;
    if trade_count == 0 || trade_count > MAX_TRADES {
        return None;
    }
    let trades_end = HEADER_LEN + trade_count * 32;
    let proof_end = trades_end + PROOF_LEN;
    if data.len() != proof_end {
        return None;
    }

    let mut trade_hashes = Vec::with_capacity(trade_count);
    for i in 0..trade_count {
        let base = HEADER_LEN + i * 32;
        let hash: [u8; 32] = data[base..base + 32].try_into().ok()?;
        trade_hashes.push(hash);
    }

    let mut proof = [0u8; PROOF_LEN];
    proof.copy_from_slice(&data[trades_end..proof_end]);

    Some(ParsedBatch {
        pre_root,
        post_root,
        trade_hashes,
        proof,
    })
}

fn g1_from_be(bytes: &[u8]) -> Option<G1Affine> {
    let x = fq_from_be(bytes[0..32].try_into().ok()?);
    let y = fq_from_be(bytes[32..64].try_into().ok()?);
    let p = G1Affine::new_unchecked(x, y);
    (p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve()).then_some(p)
}

fn g2_from_be(bytes: &[u8]) -> Option<G2Affine> {
    let x0 = fq_from_be(bytes[0..32].try_into().ok()?);
    let x1 = fq_from_be(bytes[32..64].try_into().ok()?);
    let y0 = fq_from_be(bytes[64..96].try_into().ok()?);
    let y1 = fq_from_be(bytes[96..128].try_into().ok()?);
    let p = G2Affine::new_unchecked(Fq2::new(x0, x1), Fq2::new(y0, y1));
    (p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve()).then_some(p)
}

fn write_g1(buf: &mut [u8], p: &G1Affine) -> Option<()> {
    let (x, y) = p.xy()?;
    buf[0..32].copy_from_slice(&fq_to_be(x));
    buf[32..64].copy_from_slice(&fq_to_be(y));
    Some(())
}

// Reorders arkworks' native (c0, c1) into (c1, c0) -- imaginary component
// first -- matching golang.org/x/crypto/bn256's G2.Marshal (see module
// docs). This is the only place that reorder happens; everywhere else in
// this crate uses arkworks' natural component order.
fn write_g2(buf: &mut [u8], p: &G2Affine) -> Option<()> {
    let (x, y) = p.xy()?;
    buf[0..32].copy_from_slice(&fq_to_be(&x.c1));
    buf[32..64].copy_from_slice(&fq_to_be(&x.c0));
    buf[64..96].copy_from_slice(&fq_to_be(&y.c1));
    buf[96..96 + 32].copy_from_slice(&fq_to_be(&y.c0));
    Some(())
}

fn negate_g1(p: &G1Affine) -> Option<G1Affine> {
    let (x, y) = p.xy()?;
    Some(G1Affine::new_unchecked(*x, -*y))
}

/// Builds the 768-byte (4-pair) multi-pairing input for
/// `frg::bn254_pairing_check`: `e(A,B) * e(-alpha,beta) * e(-vk_x,gamma) *
/// e(-C,delta)`, which is 1 iff the Groth16 proof is valid for this
/// contract's hardcoded verifying key (`vk.rs`) and the batch's
/// `(pre_root, post_root)` public inputs. Returns `None` if the proof
/// doesn't decode to valid, correct-subgroup curve points -- "this proof is
/// invalid" and "this proof is malformed" are indistinguishable to the
/// caller by design, same as a failed `require` in Solidity.
pub fn build_pairing_input(batch: &ParsedBatch) -> Option<[u8; 768]> {
    let pre_root = fr_from_be(&batch.pre_root);
    let post_root = fr_from_be(&batch.post_root);

    let a = g1_from_be(&batch.proof[0..64])?;
    let b = g2_from_be(&batch.proof[64..192])?;
    let c = g1_from_be(&batch.proof[192..256])?;

    let vk_x: G1Projective = vk::ic(0).into_group()
        + vk::ic(1).mul_bigint(pre_root.into_bigint())
        + vk::ic(2).mul_bigint(post_root.into_bigint());
    let vk_x = vk_x.into_affine();

    let neg_vk_x = negate_g1(&vk_x)?;
    let neg_alpha = negate_g1(&vk::alpha())?;
    let neg_c = negate_g1(&c)?;

    let mut buf = [0u8; 768];
    write_g1(&mut buf[0..64], &a)?;
    write_g2(&mut buf[64..192], &b)?;
    write_g1(&mut buf[192..256], &neg_alpha)?;
    write_g2(&mut buf[256..384], &vk::beta())?;
    write_g1(&mut buf[384..448], &neg_vk_x)?;
    write_g2(&mut buf[448..576], &vk::gamma())?;
    write_g1(&mut buf[576..640], &neg_c)?;
    write_g2(&mut buf[640..768], &vk::delta())?;

    Some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Bn254;
    use ark_ec::pairing::Pairing;
    use common::SettlementPreference;
    use engine::Match;
    use prover::{decode_proof_calldata, Bn254Groth16Backend, ProverBackend, TradeBatch};

    // Independent re-implementation of what `frg::bn254_pairing_check`
    // does host-side (core/contract/bn254.go's Bn254PairingCheck): unmarshal
    // each 192-byte chunk back into (G1, G2) -- exercising write_g1/write_g2's
    // encoding round-trip -- and check the accumulated product is the GT
    // identity. This is the closest check possible without a live FRG node.
    fn pairing_input_is_identity(input: &[u8; 768]) -> bool {
        let mut g1s = Vec::new();
        let mut g2s = Vec::new();
        for chunk in input.chunks_exact(192) {
            let g1x = fq_from_be(chunk[0..32].try_into().unwrap());
            let g1y = fq_from_be(chunk[32..64].try_into().unwrap());
            // Undo write_g2's (c1,c0) reorder to recover arkworks' native
            // (c0,c1), the same way a real Unmarshal-then-use would.
            let x1 = fq_from_be(chunk[64..96].try_into().unwrap());
            let x0 = fq_from_be(chunk[96..128].try_into().unwrap());
            let y1 = fq_from_be(chunk[128..160].try_into().unwrap());
            let y0 = fq_from_be(chunk[160..192].try_into().unwrap());
            g1s.push(G1Affine::new_unchecked(g1x, g1y));
            g2s.push(G2Affine::new_unchecked(Fq2::new(x0, x1), Fq2::new(y0, y1)));
        }
        let product = Bn254::multi_pairing(&g1s, &g2s);
        product.0 == <Bn254 as Pairing>::TargetField::from(1u64)
    }

    fn make_match(seed: u8, price: u64, amount: u64) -> Match {
        Match {
            maker_order_id: [1u8; 32],
            taker_order_id: [2u8; 32],
            maker_trader: [seed; 32],
            taker_trader: [seed.wrapping_add(1); 32],
            price,
            amount,
            timestamp_us: 0,
            settlement_tier: SettlementPreference::Standard,
            fee_basis_points: 5,
            seller: [0u8; 32],
            fee_payer: [0u8; 32],
            symbol: "BTC-USD".into(),
            assigned_node: [0u8; 32],
            settlement_deadline: 0,
        }
    }

    fn u64_to_bytes32(v: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[24..].copy_from_slice(&v.to_be_bytes());
        out
    }

    // Builds real calldata (the same shape `parse_calldata` expects) from a
    // freshly generated proof against the checked-in trusted setup.
    // `trade_hashes` are arbitrary stand-ins -- build_pairing_input never
    // reads them; only the caller (chain-frg, eventually) derives real ones.
    fn build_calldata(trades: &[(u8, u64, u64)]) -> Vec<u8> {
        let matches: Vec<Match> = trades
            .iter()
            .map(|&(seed, price, amount)| make_match(seed, price, amount))
            .collect();
        let total_value: u64 = matches.iter().map(|m| m.price * m.amount).sum();
        let balances = vec![10_000_000u64; matches.len()];

        let batch = TradeBatch {
            trades: matches.clone(),
            maker_balances: balances.clone(),
            taker_balances: balances,
            pre_state_root: [0u8; 32],
            post_state_root: u64_to_bytes32(total_value),
        };

        let backend = Bn254Groth16Backend;
        let proof_bytes = backend.prove_batch(&batch).unwrap();
        assert!(backend.verify_proof(&proof_bytes, &batch));
        let calldata = decode_proof_calldata(&proof_bytes).unwrap();

        let mut out = Vec::new();
        out.extend_from_slice(&batch.pre_state_root);
        out.extend_from_slice(&batch.post_state_root);
        out.push(matches.len() as u8);
        for m in &matches {
            out.extend_from_slice(&[m.maker_trader[0]; 32]);
        }
        out.extend_from_slice(&calldata.a[0]);
        out.extend_from_slice(&calldata.a[1]);
        out.extend_from_slice(&calldata.b[0][0]);
        out.extend_from_slice(&calldata.b[0][1]);
        out.extend_from_slice(&calldata.b[1][0]);
        out.extend_from_slice(&calldata.b[1][1]);
        out.extend_from_slice(&calldata.c[0]);
        out.extend_from_slice(&calldata.c[1]);
        out
    }

    #[test]
    fn vk_constants_are_valid_points() {
        assert!(vk::alpha().is_on_curve() && vk::alpha().is_in_correct_subgroup_assuming_on_curve());
        assert!(vk::beta().is_on_curve() && vk::beta().is_in_correct_subgroup_assuming_on_curve());
        assert!(vk::gamma().is_on_curve() && vk::gamma().is_in_correct_subgroup_assuming_on_curve());
        assert!(vk::delta().is_on_curve() && vk::delta().is_in_correct_subgroup_assuming_on_curve());
        for i in 0..3 {
            assert!(vk::ic(i).is_on_curve() && vk::ic(i).is_in_correct_subgroup_assuming_on_curve());
        }
    }

    #[test]
    fn real_proof_round_trips_through_calldata_and_verifies() {
        let calldata = build_calldata(&[(1, 3000, 5)]);
        let batch = parse_calldata(&calldata).expect("well-formed calldata must parse");
        let input = build_pairing_input(&batch)
            .expect("a real proof against the real vk must build a pairing input");
        assert!(pairing_input_is_identity(&input), "a real proof must verify");
    }

    #[test]
    fn multi_trade_batch_verifies() {
        let calldata = build_calldata(&[(1, 3000, 5), (10, 2950, 3), (20, 3010, 7)]);
        let batch = parse_calldata(&calldata).unwrap();
        let input = build_pairing_input(&batch).unwrap();
        assert!(pairing_input_is_identity(&input));
    }

    #[test]
    fn tampered_post_root_fails_the_pairing_check() {
        let mut calldata = build_calldata(&[(1, 3000, 5)]);
        calldata[63] ^= 0x01; // flip a low bit of post_root
        let batch = parse_calldata(&calldata).unwrap();
        // A tampered public input still builds *a* pairing input (nothing
        // here recomputes post_root from the trades to catch it early --
        // see module docs), but it must no longer be the one a genuine
        // proof for the real inputs would produce.
        let input = build_pairing_input(&batch).unwrap();
        assert!(!pairing_input_is_identity(&input));
    }

    #[test]
    fn tampered_proof_fails_the_pairing_check() {
        let mut calldata = build_calldata(&[(1, 3000, 5)]);
        let proof_start = calldata.len() - PROOF_LEN;
        calldata[proof_start] ^= 0x01; // flip a bit of a.x
        let batch = parse_calldata(&calldata).unwrap();
        // Still parses and may even still decode to on-curve points, but
        // the pairing product must no longer be the identity.
        if let Some(input) = build_pairing_input(&batch) {
            assert!(!pairing_input_is_identity(&input));
        }
    }

    #[test]
    fn wrong_trade_count_length_is_rejected() {
        let mut calldata = build_calldata(&[(1, 3000, 5)]);
        calldata.pop();
        assert!(parse_calldata(&calldata).is_none());
    }

    #[test]
    fn zero_trades_is_rejected() {
        let mut calldata = build_calldata(&[(1, 3000, 5)]);
        calldata[64] = 0;
        assert!(parse_calldata(&calldata).is_none());
    }

    #[test]
    fn too_many_trades_is_rejected() {
        let mut calldata = build_calldata(&[(1, 3000, 5)]);
        calldata[64] = (MAX_TRADES + 1) as u8;
        assert!(parse_calldata(&calldata).is_none());
    }
}
