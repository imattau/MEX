//! Hardcoded Groth16 verifying key for `DEXBatchCircuit`, baked into the
//! deployed WASM rather than supplied at deploy time -- FRG's `init` export
//! runs with no calldata (see `core/contract/contract.go`'s `Deploy`, which
//! never sets `RuntimeConfig.CallData`), so there is no way to pass
//! constructor-style arguments the way `BatchVerifier.sol`'s constructor
//! takes the VK on Ethereum. A new VK (e.g. after a new trusted setup)
//! means recompiling and redeploying this contract, not reconfiguring it.
//!
//! Values dumped from `crates/prover`'s checked-in `trusted_setup.bin` via
//! `prover::export_verifying_key_calldata()` -- see that function and
//! `BatchVerifier.sol`'s constructor args for where these numbers come
//! from. `crates/frg-settlement/tests` (this crate's own test suite) checks
//! proofs made against that same trusted setup verify against these
//! constants, so a mismatch between this file and the live setup wouldn't
//! go unnoticed as long as the setup file doesn't change without rerunning
//! this crate's tests.

use crate::encoding::fq_from_be;
use ark_bn254::{Fq2, G1Affine, G2Affine};

const ALPHA_X: [u8; 32] = [
    28, 87, 64, 178, 148, 212, 121, 49, 241, 203, 219, 188, 132, 161, 172, 221, 253, 133, 45, 70,
    43, 222, 194, 184, 230, 6, 225, 13, 202, 66, 247, 163,
];
const ALPHA_Y: [u8; 32] = [
    0, 220, 73, 123, 36, 200, 48, 129, 63, 18, 92, 13, 10, 18, 133, 21, 242, 161, 233, 60, 120,
    79, 26, 152, 233, 88, 243, 103, 97, 213, 45, 148,
];

const BETA_X0: [u8; 32] = [
    10, 98, 208, 77, 246, 113, 202, 7, 63, 192, 104, 188, 31, 200, 63, 103, 161, 170, 110, 60, 55,
    158, 9, 247, 37, 195, 124, 87, 50, 253, 69, 170,
];
const BETA_X1: [u8; 32] = [
    7, 179, 173, 149, 147, 238, 112, 21, 167, 192, 54, 251, 23, 49, 186, 85, 9, 160, 225, 152,
    162, 90, 217, 174, 222, 49, 169, 163, 157, 172, 102, 69,
];
const BETA_Y0: [u8; 32] = [
    27, 236, 160, 68, 79, 219, 146, 79, 33, 149, 57, 111, 222, 205, 113, 244, 239, 94, 220, 155,
    208, 72, 185, 138, 93, 28, 55, 251, 91, 2, 75, 253,
];
const BETA_Y1: [u8; 32] = [
    47, 31, 7, 107, 59, 109, 132, 182, 234, 12, 40, 202, 30, 158, 25, 40, 173, 169, 52, 214, 170,
    4, 144, 226, 122, 128, 135, 13, 21, 134, 136, 95,
];

const GAMMA_X0: [u8; 32] = [
    39, 51, 36, 185, 58, 202, 141, 116, 7, 230, 19, 19, 38, 107, 135, 146, 93, 96, 103, 55, 96,
    184, 182, 59, 107, 70, 214, 176, 11, 17, 229, 79,
];
const GAMMA_X1: [u8; 32] = [
    5, 99, 117, 185, 108, 130, 99, 5, 79, 193, 168, 90, 126, 248, 52, 61, 91, 129, 173, 195, 176,
    100, 122, 129, 88, 106, 25, 150, 224, 5, 90, 210,
];
const GAMMA_Y0: [u8; 32] = [
    15, 149, 181, 236, 91, 169, 50, 203, 195, 106, 69, 197, 145, 85, 177, 71, 255, 20, 240, 249,
    39, 147, 64, 59, 212, 198, 153, 169, 240, 135, 149, 99,
];
const GAMMA_Y1: [u8; 32] = [
    43, 24, 41, 15, 82, 208, 223, 236, 45, 205, 11, 114, 57, 8, 99, 27, 199, 214, 240, 35, 114,
    247, 8, 74, 21, 190, 206, 22, 199, 224, 80, 87,
];

const DELTA_X0: [u8; 32] = [
    25, 153, 173, 101, 169, 28, 117, 217, 85, 226, 46, 6, 179, 218, 202, 37, 229, 29, 244, 117,
    181, 37, 248, 243, 6, 170, 89, 195, 226, 29, 54, 111,
];
const DELTA_X1: [u8; 32] = [
    39, 6, 235, 115, 228, 225, 105, 147, 251, 225, 108, 242, 251, 168, 73, 148, 134, 44, 10, 155,
    80, 248, 100, 121, 208, 91, 206, 145, 254, 110, 161, 97,
];
const DELTA_Y0: [u8; 32] = [
    1, 41, 50, 20, 72, 199, 35, 45, 94, 116, 170, 104, 58, 158, 231, 68, 16, 224, 71, 51, 245, 77,
    128, 203, 18, 99, 114, 156, 129, 165, 119, 55,
];
const DELTA_Y1: [u8; 32] = [
    37, 177, 210, 38, 81, 36, 148, 122, 199, 2, 190, 205, 231, 210, 169, 105, 37, 30, 40, 134,
    109, 75, 100, 238, 114, 213, 76, 93, 84, 59, 53, 106,
];

// IC[0] (the constant term) and IC[1..3] (one per public input: pre_root,
// post_root -- DEXBatchCircuit always has exactly these 2, see
// crates/prover/src/bn254.rs's `prove_batch`).
const IC0_X: [u8; 32] = [
    25, 216, 56, 70, 43, 66, 69, 143, 46, 103, 199, 173, 183, 205, 76, 29, 94, 150, 47, 152, 244,
    219, 148, 123, 13, 125, 32, 28, 5, 191, 66, 182,
];
const IC0_Y: [u8; 32] = [
    41, 198, 204, 24, 122, 204, 241, 78, 254, 202, 122, 92, 51, 143, 176, 251, 253, 101, 18, 203,
    110, 235, 231, 192, 47, 64, 11, 87, 244, 204, 78, 5,
];
const IC1_X: [u8; 32] = [
    15, 219, 8, 55, 203, 95, 204, 112, 200, 201, 4, 94, 194, 52, 176, 213, 254, 88, 213, 143, 37,
    50, 203, 69, 130, 246, 51, 255, 108, 74, 88, 174,
];
const IC1_Y: [u8; 32] = [
    45, 104, 7, 72, 242, 32, 27, 143, 53, 0, 48, 40, 94, 187, 90, 54, 53, 23, 114, 82, 124, 85,
    128, 210, 130, 246, 52, 191, 220, 204, 166, 235,
];
const IC2_X: [u8; 32] = [
    3, 208, 107, 49, 5, 45, 96, 28, 180, 187, 50, 7, 172, 199, 11, 73, 140, 54, 141, 181, 207, 39,
    29, 148, 229, 85, 179, 155, 61, 111, 48, 236,
];
const IC2_Y: [u8; 32] = [
    8, 107, 169, 236, 98, 144, 212, 214, 29, 14, 194, 161, 231, 108, 36, 156, 219, 47, 110, 67,
    23, 36, 237, 7, 209, 94, 192, 196, 183, 71, 146, 2,
];

fn g1(x: &[u8; 32], y: &[u8; 32]) -> G1Affine {
    G1Affine::new_unchecked(fq_from_be(x), fq_from_be(y))
}

fn g2(x0: &[u8; 32], x1: &[u8; 32], y0: &[u8; 32], y1: &[u8; 32]) -> G2Affine {
    G2Affine::new_unchecked(
        Fq2::new(fq_from_be(x0), fq_from_be(x1)),
        Fq2::new(fq_from_be(y0), fq_from_be(y1)),
    )
}

pub fn alpha() -> G1Affine {
    g1(&ALPHA_X, &ALPHA_Y)
}

pub fn beta() -> G2Affine {
    g2(&BETA_X0, &BETA_X1, &BETA_Y0, &BETA_Y1)
}

pub fn gamma() -> G2Affine {
    g2(&GAMMA_X0, &GAMMA_X1, &GAMMA_Y0, &GAMMA_Y1)
}

pub fn delta() -> G2Affine {
    g2(&DELTA_X0, &DELTA_X1, &DELTA_Y0, &DELTA_Y1)
}

/// `i` in `0..=2` (IC[0] is the constant term; IC[1], IC[2] pair with the
/// circuit's 2 public inputs, pre_root and post_root, in that order).
pub fn ic(i: usize) -> G1Affine {
    match i {
        0 => g1(&IC0_X, &IC0_Y),
        1 => g1(&IC1_X, &IC1_Y),
        2 => g1(&IC2_X, &IC2_Y),
        _ => unreachable!("DEXBatchCircuit has exactly 2 public inputs, so only IC[0..=2] exist"),
    }
}
