use crate::TradeBatch;

pub trait ProverBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn prove_batch(&self, batch: &TradeBatch) -> Result<Vec<u8>, String>;
    fn verify_proof(&self, proof: &[u8], batch: &TradeBatch) -> bool;
    fn export_verifying_key(&self) -> serde_json::Value;
}

use ark_ff::PrimeField;
use crate::DEXBatchCircuit;

pub trait CircuitVerifier {
    fn verify_constraints<F: PrimeField>(circuit: DEXBatchCircuit<F>) -> bool;
}
