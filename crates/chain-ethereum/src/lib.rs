mod listener;
mod persist;
mod registry;
mod service;
mod sync;

pub use listener::{http_provider, ChainEvent, ChainSync};
pub use persist::SyncStore;
pub use registry::{EscrowRegistry, EthAddress, TokenRegistry};
pub use service::SyncService;
pub use sync::apply_event;

use chain::{ChainAdapter, Token, SettlementPreference};
use prover::{TradeBatch, ProverBackend, Bn254Groth16Backend};

pub struct EthereumAdapter {
    pub rpc_url: String,
    pub verifier_address: String,
    pub factory_address: String,
    pub registry_address: String,
    pub chain_identifier: &'static str,
    pub native_denom: &'static str,
}

impl EthereumAdapter {
    pub fn new(
        rpc_url: &str,
        verifier: &str,
        factory: &str,
        registry: &str,
    ) -> Self {
        Self {
            rpc_url: rpc_url.to_string(),
            verifier_address: verifier.to_string(),
            factory_address: factory.to_string(),
            registry_address: registry.to_string(),
            chain_identifier: "ethereum",
            native_denom: "ETH",
        }
    }
}

impl ChainAdapter for EthereumAdapter {
    fn chain_id(&self) -> &'static str { self.chain_identifier }

    fn native_denomination(&self) -> &'static str { self.native_denom }

    fn submit_settlement_batch(
        &self,
        batch: &TradeBatch,
        proof: &[u8],
        _node_sigs: &[([u8; 32], Vec<u8>)],
        _tier: SettlementPreference,
        _fee_recipient: [u8; 32],
        _deadlines: &[u64],
    ) -> Result<String, String> {
        let _ = (batch, proof);
        Ok(format!("0x{}", hex::encode(&proof[..16])))
    }

    fn lock_funds(
        &self, _trader: [u8; 32], _token: Token, _amount: u64,
    ) -> Result<(), String> {
        Ok(())
    }

    fn settle_funds(
        &self, _from: [u8; 32], _to: [u8; 32], _token: Token, _amount: u64,
    ) -> Result<(), String> {
        Ok(())
    }

    fn release_funds(
        &self, _trader: [u8; 32], _token: Token, _amount: u64,
    ) -> Result<(), String> {
        Ok(())
    }

    fn register_node(
        &self, _pubkey: [u8; 32], _operator: [u8; 32], _geo: &str, _stake: u64,
    ) -> Result<(), String> {
        Ok(())
    }

    fn slash_node(&self, _pubkey: [u8; 32], _amount: u64) -> Result<(), String> {
        Ok(())
    }

    fn get_node_stake(&self, _pubkey: [u8; 32]) -> Result<u64, String> {
        Ok(10_000_000_000_000_000_000)
    }

    fn is_node_active(&self, _pubkey: [u8; 32]) -> Result<bool, String> {
        Ok(true)
    }

    fn update_node_reputation(
        &self, _pubkey: [u8; 32], _score: u32, _level: u8,
    ) -> Result<(), String> {
        Ok(())
    }

    fn get_node_reputation(
        &self, _pubkey: [u8; 32],
    ) -> Result<(u32, u8, u64), String> {
        Ok((5000, 0, 0))
    }

    fn prover(&self) -> &dyn ProverBackend {
        &Bn254Groth16Backend
    }
}
