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
//! Writes that don't need a settlement contract (bonding a validator,
//! submitting FRG's own MISS_EVIDENCE) go through [`wallet::FrgWalletClient`]
//! instead: `frg-wallet`'s local HTTP API signs and submits on the caller's
//! behalf, so this crate still never has to reimplement FRG's tx encoding
//! itself. Note FRG's MISS_EVIDENCE (validator consensus-liveness) is a
//! different concept from `ChainAdapter::submit_missed_deadline_report`
//! (MEX settlement-node liveness) -- see that method's doc comment below.
//!
//! Settlement itself needed a second piece FRG had no equivalent of: a WASM
//! contract playing the role of `SettlementFactory.sol`/`BatchVerifier.sol`
//! (commit-then-settle, fee split, slashing, Groth16 verification),
//! deployed via `CONTRACT_DEPLOY` and invoked via `CONTRACT_CALL`. That now
//! exists as `contracts/frg/settlement` (a standalone crate, not a MEX
//! workspace member -- it's a deploy artifact, not linked into any MEX
//! binary), scoped to exactly what `submit_settlement_batch`/
//! `is_trade_settled` need: verify a Groth16 batch proof and record which
//! trades it covers as settled. It does NOT implement trader escrow
//! deposits, fee-tier transfers, or missed-deadline slashing -- see that
//! crate's README for why those are deliberately out of scope here.
//! `FrgAdapter::with_settlement_contract` points this adapter at a deployed
//! instance; both methods below build calldata matching that contract's
//! `sett` entrypoint (see `contracts/frg/settlement/src/groth16.rs`'s
//! module docs for the exact format) and drive it through
//! `FrgWalletClient::call_contract`/`::contract_state`.

mod client;
mod wallet;

pub use client::FrgClient;
pub use wallet::FrgWalletClient;

use chain::{ChainAdapter, OnChainAccount, SettlementFeeConfig, SettlementTrade};
use prover::{decode_proof_calldata, Bn254Groth16Backend, ProverBackend};

// The `sett` entrypoint selector: contracts/frg/settlement/src/lib.rs
// exports it under this literal 4-byte ASCII name (FRG picks the WASM
// export to run from the calldata's first 4 bytes -- see
// core/contract/contract.go's `Call`).
const SETTLE_FUNCTION: &str = "sett";
const MAX_SETTLEMENT_TRADES: usize = 8;

pub struct FrgAdapter {
    client: FrgClient,
    wallet: Option<FrgWalletClient>,
    settlement_contract: Option<OnChainAccount>,
}

impl FrgAdapter {
    pub async fn connect(endpoint: impl Into<String>) -> Result<Self, String> {
        Ok(Self {
            client: FrgClient::connect(endpoint).await?,
            wallet: None,
            settlement_contract: None,
        })
    }

    /// Attaches an `frg-wallet` HTTP endpoint, enabling the write-path
    /// methods that only need a bare signed tx (`register_node` via
    /// `POST /bond`, and -- once `with_settlement_contract` is also set --
    /// `submit_settlement_batch`/`is_trade_settled` via `/contracts/call`
    /// and `/contracts/state`). See module docs for why
    /// `submit_missed_deadline_report` still can't go through the wallet.
    pub fn with_wallet(mut self, wallet_base_url: impl Into<String>) -> Self {
        self.wallet = Some(FrgWalletClient::new(wallet_base_url));
        self
    }

    /// Points this adapter at a deployed `contracts/frg/settlement`
    /// instance, enabling `submit_settlement_batch`/`is_trade_settled`.
    pub fn with_settlement_contract(mut self, contract_address: OnChainAccount) -> Self {
        self.settlement_contract = Some(contract_address);
        self
    }

    fn wallet(&self) -> Result<&FrgWalletClient, String> {
        self.wallet.as_ref().ok_or_else(|| {
            "chain-frg: no frg-wallet endpoint configured (see FrgAdapter::with_wallet)".into()
        })
    }

    fn settlement_contract(&self) -> Result<OnChainAccount, String> {
        self.settlement_contract.ok_or_else(|| {
            "chain-frg: no settlement contract configured (see FrgAdapter::with_settlement_contract)"
                .into()
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

    // Builds calldata for contracts/frg/settlement's `sett` entrypoint and
    // submits it via frg-wallet's POST /contracts/call. `fee_config` is
    // unused: this contract doesn't implement fee-tier transfers (see its
    // README's Scope section), unlike SettlementFactory.settleBatchWithFees
    // on Ethereum, which does.
    async fn submit_settlement_batch(
        &self,
        trades: &[SettlementTrade],
        proof: &[u8],
        _fee_config: SettlementFeeConfig,
    ) -> Result<String, String> {
        if trades.is_empty() {
            return Err("chain-frg: no trades to settle".into());
        }
        if trades.len() > MAX_SETTLEMENT_TRADES {
            return Err(format!(
                "chain-frg: batch of {} trades exceeds the settlement contract's max of {MAX_SETTLEMENT_TRADES}",
                trades.len()
            ));
        }

        let calldata = decode_proof_calldata(proof)?;
        if calldata.public_inputs.len() != 2 {
            return Err(format!(
                "chain-frg: expected 2 public inputs (pre_root, post_root), got {}",
                calldata.public_inputs.len()
            ));
        }

        // The selector must be the first 4 bytes of the raw calldata
        // itself, not passed as FrgWalletClient::call_contract's separate
        // `function` param -- frg-wallet's /contracts/call prioritizes
        // call_data_hex over function whenever both are set (see
        // cmd/frg-wallet/main.go's contractCallData), so passing both (as
        // an earlier version of this function did) silently discarded the
        // selector and sent this payload as raw calldata, corrupting
        // contract.go's own 4-byte selector/payload split on the other
        // end. Confirmed against a live FRG devnet.
        let mut body = Vec::with_capacity(4 + 65 + 32 * trades.len() + 256);
        body.extend_from_slice(SETTLE_FUNCTION.as_bytes());
        body.extend_from_slice(&calldata.public_inputs[0]);
        body.extend_from_slice(&calldata.public_inputs[1]);
        body.push(trades.len() as u8);
        for trade in trades {
            body.extend_from_slice(&trade.trade_hash);
        }
        body.extend_from_slice(&calldata.a[0]);
        body.extend_from_slice(&calldata.a[1]);
        body.extend_from_slice(&calldata.b[0][0]);
        body.extend_from_slice(&calldata.b[0][1]);
        body.extend_from_slice(&calldata.b[1][0]);
        body.extend_from_slice(&calldata.b[1][1]);
        body.extend_from_slice(&calldata.c[0]);
        body.extend_from_slice(&calldata.c[1]);

        self.wallet()?
            .call_contract(self.settlement_contract()?, None, Some(&body), "0")
            .await
    }

    // NOT the same "missed deadline" as FRG's MISS_EVIDENCE, despite the
    // name -- this trait method reports a *settlement node* missing a
    // *trade settlement deadline* (NodeRegistry.recordMissedDeadline on
    // Ethereum). FRG's MISS_EVIDENCE (frg-wallet's now-live POST
    // /miss-evidence, wrapped by FrgWalletClient::submit_missed_deadline_report)
    // reports an *FRG validator* missing its *consensus block-proposal
    // slot* -- FRG's own chain-liveness bookkeeping, unrelated to MEX
    // trades. There is no FRG-side registry tracking MEX settlement nodes
    // at all yet; that still needs the settlement contract (see module
    // docs), so this stays unimplemented until that exists.
    async fn submit_missed_deadline_report(
        &self,
        _node_pubkey: OnChainAccount,
    ) -> Result<(), String> {
        Err(
            "chain-frg: no settlement contract deployed on FRG yet to record this against \
             (FRG's own MISS_EVIDENCE is a different, validator-liveness concept -- see \
             FrgWalletClient::submit_missed_deadline_report)"
                .into(),
        )
    }

    // Maps to a signed BOND (Type=5) tx, via frg-wallet's POST /bond. FRG
    // bonding has no geo/metadata field (unlike NodeRegistry.registerNode),
    // so `_geo` is dropped, and it always bonds the wallet's own key --
    // `_pubkey` is trusted to be that key rather than verified against it,
    // consistent with this trait's doc comment ("staking with the
    // adapter's own key").
    async fn register_node(
        &self,
        _pubkey: OnChainAccount,
        _geo: &str,
        stake: u64,
    ) -> Result<(), String> {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or("chain-frg: no frg-wallet endpoint configured (see FrgAdapter::with_wallet)")?;
        wallet.bond(&stake.to_string()).await.map(|_txid| ())
    }

    // FRG pubkeys are already 32 bytes (Ed25519), so unlike the 20-byte EVM
    // address, OnChainAccount needs no padding/unpadding here.
    //
    // Saturates u128 quanta down to u64: ChainAdapter::get_node_stake's
    // return type is a shared trait signature (used by every chain
    // adapter), not something to widen unilaterally from here, but a real
    // FRG bond routinely exceeds u64::MAX (see FrgClient::validator_bond's
    // docs) -- saturating avoids a hard error for every real validator,
    // at the cost of precision above ~18.4 quintillion quanta (~18.4 FRG,
    // well past the point where relative differences between large bonds
    // still matter for whatever compares this value). Callers that need
    // the exact figure should go through FrgClient::validator_bond
    // (u128) or FrgWalletClient::validators() (decimal string) directly
    // instead of this trait method.
    async fn get_node_stake(&self, pubkey: OnChainAccount) -> Result<u64, String> {
        let quanta = self.client.validator_bond(pubkey).await?;
        Ok(quanta.min(u64::MAX as u128) as u64)
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

    // contracts/frg/settlement's `sett` stores `state_set(trade_hash, [1])`
    // on success, so this is a plain state read -- no WASM call needed.
    // `_trader` is unused: unlike Ethereum's per-trader TraderEscrow
    // contracts, there is one shared FRG settlement contract, and
    // trade_hash alone is already a unique commitment (see
    // chain::SettlementTrade's docs on trade_hash).
    async fn is_trade_settled(
        &self,
        _trader: OnChainAccount,
        trade_hash: [u8; 32],
    ) -> Result<bool, String> {
        let state = self
            .wallet()?
            .contract_state(self.settlement_contract()?, Some(&trade_hash))
            .await?;
        Ok(state.found)
    }

    fn prover(&self) -> &dyn ProverBackend {
        &Bn254Groth16Backend
    }
}
