use chain::{ChainAdapter, Token, SettlementPreference};
use prover::{TradeBatch, ProverBackend, Bn254Groth16Backend};

pub struct SolanaAdapter;

impl ChainAdapter for SolanaAdapter {
    fn chain_id(&self) -> &'static str { "solana" }
    fn native_denomination(&self) -> &'static str { "SOL" }

    fn submit_settlement_batch(
        &self, _b: &TradeBatch, _p: &[u8], _s: &[([u8; 32], Vec<u8>)],
        _tier: SettlementPreference, _fee_recipient: [u8; 32], _deadlines: &[u64],
    ) -> Result<String, String> {
        Err("Solana settlement not yet implemented".into())
    }
    fn lock_funds(&self, _t: [u8; 32], _tk: Token, _a: u64) -> Result<(), String> {
        Err("Solana escrow not yet implemented".into())
    }
    fn settle_funds(&self, _f: [u8; 32], _t: [u8; 32], _tk: Token, _a: u64) -> Result<(), String> {
        Err("Solana settlement not yet implemented".into())
    }
    fn release_funds(&self, _t: [u8; 32], _tk: Token, _a: u64) -> Result<(), String> {
        Err("Solana escrow not yet implemented".into())
    }
    fn register_node(&self, _p: [u8; 32], _o: [u8; 32], _g: &str, _s: u64) -> Result<(), String> {
        Err("Solana registry not yet implemented".into())
    }
    fn slash_node(&self, _p: [u8; 32], _a: u64) -> Result<(), String> {
        Err("Solana slashing not yet implemented".into())
    }
    fn get_node_stake(&self, _p: [u8; 32]) -> Result<u64, String> { Ok(0) }
    fn is_node_active(&self, _p: [u8; 32]) -> Result<bool, String> { Ok(false) }
    fn update_node_reputation(&self, _p: [u8; 32], _s: u32, _l: u8) -> Result<(), String> { Ok(()) }
    fn get_node_reputation(&self, _p: [u8; 32]) -> Result<(u32, u8, u64), String> { Ok((5000, 0, 0)) }
    fn prover(&self) -> &dyn ProverBackend { &Bn254Groth16Backend }
}
