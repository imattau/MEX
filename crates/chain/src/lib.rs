pub use common::SettlementPreference;
use prover::ProverBackend;
use std::future::Future;

// A chain-specific account/pubkey encoding, left-zero-padded to 32 bytes for
// chains with shorter native addresses (e.g. a 20-byte EVM address becomes
// 12 zero bytes + the address). Kept generic across chains rather than
// picking one chain's native address type, consistent with how node pubkeys
// are already represented as [u8; 32] throughout this codebase.
pub type OnChainAccount = [u8; 32];

#[derive(Debug, Clone)]
pub enum Token {
    Native,
    Erc20(String),
    Spl(String),
    Cw20(String),
}

// One trade being settled on-chain. Mirrors SettlementFactory.TradeEntry on
// Ethereum as closely as a chain-agnostic shape reasonably can.
//
// maker_order_id/taker_order_id trace back to the off-chain engine::Match
// that produced this trade, and (together with the other fields) feed
// trade_hash's derivation -- see chain-ethereum::compute_trade_hash. Nothing
// on-chain currently recomputes/validates trade_hash (TraderEscrow just
// stores whatever bytes32 the trader supplies), but binding it to these
// specific terms is still the point: trade_hash is a commitment to exactly
// this trade, not just an arbitrary unique ID, so it stays meaningful if
// on-chain verification is ever added later.
#[derive(Debug, Clone)]
pub struct SettlementTrade {
    pub maker_order_id: [u8; 32],
    pub taker_order_id: [u8; 32],
    pub trader: OnChainAccount,
    pub counterparty: OnChainAccount,
    pub token: Token,
    pub amount: u64,
    pub fee: u64,
    pub deadline: u64,
    pub trade_hash: [u8; 32],
    pub assigned_node: OnChainAccount,
}

#[derive(Debug, Clone)]
pub struct SettlementFeeConfig {
    pub fee_recipient: OnChainAccount,
    pub tier: u8,
}

// Write actions a node's own on-chain key can legitimately sign and submit.
//
// Deliberately excludes actions that require the end trader's own wallet --
// committing to a trade (SettlementFactory.commitTrade) and claiming a slash
// for a missed deadline (SettlementFactory.claimSlash) are both restricted
// on-chain to `msg.sender == trader`. Node/relay infrastructure should never
// hold a trader's private key, so those don't belong on this trait; they're
// a wallet-integration concern, not a ChainAdapter concern. Similarly,
// slashing a node's stake and updating a node's reputation are not exposed
// here: NodeRegistry.slashNode/updateReputation are gated to the contract's
// own slashingAuthority (SettlementFactory), not directly callable by an
// arbitrary off-chain adapter.
pub trait ChainAdapter: Send + Sync {
    fn chain_id(&self) -> &'static str;
    fn native_denomination(&self) -> &'static str;

    // Submits a batch of already-committed trades (via commitTrade, by each
    // trader themselves) for settlement, alongside their ZK proof. Maps to
    // SettlementFactory.settleBatchWithFees, which requires msg.sender to
    // be the registered operator of every trade's assignedNode -- callers
    // must use the same key that registered as that node in NodeRegistry,
    // not an arbitrary key.
    fn submit_settlement_batch(
        &self,
        trades: &[SettlementTrade],
        proof: &[u8],
        fee_config: SettlementFeeConfig,
    ) -> impl Future<Output = Result<String, String>> + Send;

    // Reports that a node missed its settlement deadline for a trade. Maps
    // to NodeRegistry.recordMissedDeadline, open to any caller.
    //
    // Named `submit_` rather than `record_` to avoid colliding with
    // OnChainClient::record_missed_deadline (crates/watchtower) -- that's a
    // separate, synchronous, in-memory bookkeeping method already used by
    // existing watchtower call sites; MockOnChainState implements both
    // traits, so a same-named async method here would make those calls
    // ambiguous.
    fn submit_missed_deadline_report(
        &self,
        node_pubkey: OnChainAccount,
    ) -> impl Future<Output = Result<(), String>> + Send;

    // Registers the caller's own node, staking with the adapter's own key.
    // Maps to NodeRegistry.registerNode.
    fn register_node(
        &self,
        pubkey: OnChainAccount,
        geo: &str,
        stake: u64,
    ) -> impl Future<Output = Result<(), String>> + Send;

    fn get_node_stake(&self, pubkey: OnChainAccount) -> impl Future<Output = Result<u64, String>> + Send;
    fn is_node_active(&self, pubkey: OnChainAccount) -> impl Future<Output = Result<bool, String>> + Send;
    fn get_node_reputation(
        &self,
        pubkey: OnChainAccount,
    ) -> impl Future<Output = Result<(u32, u8, u64), String>> + Send;

    fn prover(&self) -> &dyn ProverBackend;
}
