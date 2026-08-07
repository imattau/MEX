pub use common::SettlementPreference;
use prover::{TradeBatch, ProverBackend};

#[derive(Debug, Clone)]
pub enum Token {
    Native,
    Erc20(String),
    Spl(String),
    Cw20(String),
}

pub trait ChainAdapter: Send + Sync {
    fn chain_id(&self) -> &'static str;
    fn native_denomination(&self) -> &'static str;

    fn submit_settlement_batch(
        &self,
        batch: &TradeBatch,
        proof: &[u8],
        node_sigs: &[([u8; 32], Vec<u8>)],
        tier: SettlementPreference,
        fee_recipient: [u8; 32],
        deadlines: &[u64],
    ) -> Result<String, String>;

    fn lock_funds(
        &self, trader: [u8; 32], token: Token, amount: u64,
    ) -> Result<(), String>;

    fn settle_funds(
        &self, from: [u8; 32], to: [u8; 32], token: Token, amount: u64,
    ) -> Result<(), String>;

    fn release_funds(
        &self, trader: [u8; 32], token: Token, amount: u64,
    ) -> Result<(), String>;

    fn register_node(
        &self, pubkey: [u8; 32], operator: [u8; 32], geo: &str, stake: u64,
    ) -> Result<(), String>;

    fn slash_node(&self, pubkey: [u8; 32], amount: u64) -> Result<(), String>;

    fn get_node_stake(&self, pubkey: [u8; 32]) -> Result<u64, String>;
    fn is_node_active(&self, pubkey: [u8; 32]) -> Result<bool, String>;

    fn update_node_reputation(
        &self, pubkey: [u8; 32], score: u32, level: u8,
    ) -> Result<(), String>;
    fn get_node_reputation(
        &self, pubkey: [u8; 32],
    ) -> Result<(u32, u8, u64), String>;

    fn prover(&self) -> &dyn ProverBackend;
}
