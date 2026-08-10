//! Big-endian field-element <-> byte conversions shared by `groth16.rs` and
//! `vk.rs`. Deliberately big-endian throughout (not ark-serialize's native
//! little-endian compressed format): this crate's calldata format and the
//! host `bn254_pairing_check` precompile's input both use big-endian
//! uint256-style words, matching `prover::decode_proof_calldata`'s output
//! and Ethereum's alt_bn128 precompile convention (see FRG's own
//! `core/contract/bn254.go`, backed by `golang.org/x/crypto/bn256`, whose
//! `G1`/`G2` `Marshal` are big-endian for the same reason).

use ark_bn254::{Fq, Fr};
use ark_ff::{BigInteger, PrimeField};

pub fn fr_from_be(b: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(b)
}

pub fn fq_from_be(b: &[u8; 32]) -> Fq {
    Fq::from_be_bytes_mod_order(b)
}

pub fn fq_to_be(f: &Fq) -> [u8; 32] {
    let bytes = f.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}
