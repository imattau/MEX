//! [`chain::ChainAdapter`] for FRG (https://github.com/imattau/FRG), a
//! separate Go L1 with its own consensus/staking/WASM-contract stack, spoken
//! to here purely over its gRPC admin API (`proto/frg.proto`, vendored in
//! this crate -- see that file's header).
//!
//! FRG's proto only exposes reads (`GetAccount`, `ListValidators`, ...) and
//! one opaque write, `SubmitTx(RawBytes)`, where `RawBytes` is a
//! FRG-encoded, Ed25519-signed transaction. That encoding lives in the Go
//! repo's `core/tx` package and isn't part of the proto or documented
//! anywhere reimplementable from outside Go, so every write-path method
//! below is a real stub, not a placeholder for something already working.
//! Read-path methods (`get_node_stake`, `is_node_active`) are implemented
//! for real against `ListValidators`.
//!
//! Settlement itself needs a second piece that doesn't exist yet: an FRG
//! WASM contract playing the role of `SettlementFactory.sol` /
//! `BatchVerifier.sol` (commit-then-settle, fee split, slashing, Groth16
//! verification), deployed via `CONTRACT_DEPLOY` and invoked via
//! `CONTRACT_CALL`. `submit_settlement_batch` has nothing to call until
//! that contract exists.

mod client;

pub use client::FrgClient;

use chain::{ChainAdapter, OnChainAccount, SettlementFeeConfig, SettlementTrade};
use prover::{Bn254Groth16Backend, ProverBackend};

pub struct FrgAdapter {
    client: FrgClient,
}

impl FrgAdapter {
    pub async fn connect(endpoint: impl Into<String>) -> Result<Self, String> {
        Ok(Self {
            client: FrgClient::connect(endpoint).await?,
        })
    }
}

impl ChainAdapter for FrgAdapter {
    fn chain_id(&self) -> &'static str {
        "frg"
    }

    fn native_denomination(&self) -> &'static str {
        "FRG"
    }

    // Needs a settlement contract deployed on FRG (none exists yet, see
    // module docs) plus the signed-tx encoding to invoke it.
    async fn submit_settlement_batch(
        &self,
        _trades: &[SettlementTrade],
        _proof: &[u8],
        _fee_config: SettlementFeeConfig,
    ) -> Result<String, String> {
        Err(
            "chain-frg: no settlement contract deployed on FRG yet, and FRG's \
             signed-tx encoding (core/tx in the Go repo) isn't reimplemented here"
                .into(),
        )
    }

    // Maps to a signed MISS_EVIDENCE (Type=2) tx -- same signed-tx-encoding
    // gap as submit_settlement_batch.
    async fn submit_missed_deadline_report(
        &self,
        _node_pubkey: OnChainAccount,
    ) -> Result<(), String> {
        Err(
            "chain-frg: MISS_EVIDENCE submission needs FRG's signed-tx encoding, not implemented"
                .into(),
        )
    }

    // Maps to a signed BOND (Type=5) tx -- same gap.
    async fn register_node(
        &self,
        _pubkey: OnChainAccount,
        _geo: &str,
        _stake: u64,
    ) -> Result<(), String> {
        Err("chain-frg: BOND submission needs FRG's signed-tx encoding, not implemented".into())
    }

    // FRG pubkeys are already 32 bytes (Ed25519), so unlike the 20-byte EVM
    // address, OnChainAccount needs no padding/unpadding here.
    async fn get_node_stake(&self, pubkey: OnChainAccount) -> Result<u64, String> {
        self.client.validator_bond(pubkey).await
    }

    async fn is_node_active(&self, pubkey: OnChainAccount) -> Result<bool, String> {
        self.client.is_validator(pubkey).await
    }

    // FRG has no on-chain reputation concept (see core/staking: bond,
    // unbond, slash, liveness misses -- no reputation score). Mirrors the
    // chain-solana/chain-cosmwasm stubs' neutral default rather than
    // inventing a number FRG doesn't track.
    async fn get_node_reputation(&self, _pubkey: OnChainAccount) -> Result<(u32, u8, u64), String> {
        Ok((5000, 0, 0))
    }

    // No settlement contract exists on FRG yet (see module docs), so there
    // is nothing to query.
    async fn is_trade_settled(
        &self,
        _trader: OnChainAccount,
        _trade_hash: [u8; 32],
    ) -> Result<bool, String> {
        Err("chain-frg: no settlement contract deployed on FRG yet".into())
    }

    fn prover(&self) -> &dyn ProverBackend {
        &Bn254Groth16Backend
    }
}
