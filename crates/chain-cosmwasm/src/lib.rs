use chain::{ChainAdapter, OnChainAccount, SettlementFeeConfig, SettlementTrade};
use prover::{ProverBackend, Bn254Groth16Backend};

pub struct CosmosAdapter;

impl ChainAdapter for CosmosAdapter {
    fn chain_id(&self) -> &'static str { "cosmos" }
    fn native_denomination(&self) -> &'static str { "ATOM" }

    async fn submit_settlement_batch(
        &self, _trades: &[SettlementTrade], _proof: &[u8], _fee_config: SettlementFeeConfig,
    ) -> Result<String, String> {
        Err("Cosmos settlement not yet implemented".into())
    }
    async fn submit_missed_deadline_report(&self, _pubkey: OnChainAccount) -> Result<(), String> {
        Err("Cosmos registry not yet implemented".into())
    }
    async fn register_node(&self, _pubkey: OnChainAccount, _geo: &str, _stake: u64) -> Result<(), String> {
        Err("Cosmos registry not yet implemented".into())
    }
    async fn get_node_stake(&self, _pubkey: OnChainAccount) -> Result<u64, String> { Ok(0) }
    async fn is_node_active(&self, _pubkey: OnChainAccount) -> Result<bool, String> { Ok(false) }
    async fn get_node_reputation(&self, _pubkey: OnChainAccount) -> Result<(u32, u8, u64), String> { Ok((5000, 0, 0)) }
    fn prover(&self) -> &dyn ProverBackend { &Bn254Groth16Backend }
}
