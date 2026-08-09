// Exports the real Groth16 verifying key (derived from the persisted
// trusted setup -- see bn254::trusted_setup_path) as the JSON shape
// scripts/deploy.js's VERIFYING_KEY_PATH expects: { alpha, beta, gamma,
// delta, ic }, each uint256/uint256[2]/uint256[2][2] entry a 0x-prefixed
// hex string BatchVerifier's constructor can consume directly.
//
// Usage: cargo run -p prover --bin export_vk -- <output_path.json>
// Respects MEX_TRUSTED_SETUP_PATH the same way the rest of this crate does.

use prover::export_verifying_key_calldata;

fn hex32(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn g1(point: &[[u8; 32]; 2]) -> serde_json::Value {
    serde_json::json!([hex32(&point[0]), hex32(&point[1])])
}

fn g2(point: &[[[u8; 32]; 2]; 2]) -> serde_json::Value {
    serde_json::json!([
        [hex32(&point[0][0]), hex32(&point[0][1])],
        [hex32(&point[1][0]), hex32(&point[1][1])],
    ])
}

fn main() {
    let output_path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: export_vk <output_path.json>");
        std::process::exit(1);
    });

    let vk = export_verifying_key_calldata().unwrap_or_else(|e| {
        eprintln!("failed to export verifying key: {e}");
        std::process::exit(1);
    });

    let json = serde_json::json!({
        "alpha": g1(&vk.alpha),
        "beta": g2(&vk.beta),
        "gamma": g2(&vk.gamma),
        "delta": g2(&vk.delta),
        "ic": vk.ic.iter().map(g1).collect::<Vec<_>>(),
    });

    std::fs::write(&output_path, serde_json::to_string_pretty(&json).unwrap()).unwrap_or_else(
        |e| {
            eprintln!("failed to write {output_path}: {e}");
            std::process::exit(1);
        },
    );

    println!("wrote real verifying key to {output_path}");
}
