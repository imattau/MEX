//! Client for `frg-wallet`'s local HTTP API (see FRG's `docs/wallet-api.md`
//! and `cmd/frg-wallet/main.go`), the intended way for non-Go callers to
//! submit signed FRG transactions: the wallet process holds the Ed25519
//! key, tracks the account nonce, signs, and submits over gRPC itself, so
//! callers here never touch FRG's tx wire format (`core/tx`, Go-only).
//!
//! Request/response shapes below are copied from `frg-wallet`'s Go structs,
//! not inferred from the prose docs -- in particular `/status` serializes
//! the raw `frgpb.StatusResponse` Go struct via `encoding/json`, whose
//! `[]byte` fields (`state_root`) come out **base64**, unlike every hex-
//! encoded `[]byte` field elsewhere in this API (`/validators`, contract
//! endpoints), where `main.go` hex-encodes by hand before serializing.
//!
//! FRG's "Standardize FRG denominations" change repurposed the plain
//! `amount`/`value` request fields to mean whole FRG (decimal), adding
//! sibling `amount_quanta`/`value_quanta` fields (mutually exclusive with
//! the FRG ones) for raw-integer callers. Every quantity this client deals
//! in is already quanta, so it always sends the `_quanta` fields and never
//! the decimal ones -- silently sending quanta under the old `amount` key
//! post-upgrade would have been off by 10^18.
//!
//! `frg-wallet` is a local developer/operator API, not a hosted custody
//! service: anyone who can reach it can spend through it (`/transfer`,
//! `/bond`, `/contracts/deploy`, `/contracts/call`, ...). Point this client
//! only at an instance you trust, ideally loopback-bound.

use chain::OnChainAccount;
use serde::{Deserialize, Serialize};

pub struct FrgWalletClient {
    http: reqwest::Client,
    base_url: String,
}

#[derive(Debug, Clone)]
pub struct WalletAccount {
    pub pubkey: OnChainAccount,
    /// Raw quanta, as a decimal string: FRG amounts are arbitrary-precision
    /// (Go `big.Int`) and can exceed `u64`.
    pub balance: String,
    /// The same balance formatted as whole FRG (1 FRG = 10^18 quanta).
    pub balance_frg: String,
    pub nonce: u64,
}

#[derive(Debug, Clone, Default)]
pub struct WalletStatus {
    pub height: u64,
    pub state_root: Vec<u8>,
    pub peer_count: u64,
    pub mempool_len: u64,
    pub validator_count: u64,
    pub consensus_round: u32,
    pub consensus_phase: String,
    pub grpc_only: bool,
}

#[derive(Debug, Clone)]
pub struct WalletValidator {
    pub pubkey: OnChainAccount,
    /// Raw quanta, as a decimal string.
    pub bond: String,
    /// The same bond formatted as whole FRG.
    pub bond_frg: String,
}

#[derive(Debug, Clone)]
pub struct ContractState {
    pub contract_address: OnChainAccount,
    pub exists: bool,
    pub state_root: Vec<u8>,
    pub key: Vec<u8>,
    pub found: bool,
    pub value: Vec<u8>,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Deserialize)]
struct PubkeyResponse {
    pubkey: String,
    chain_id: String,
}

#[derive(Deserialize)]
struct AccountResponseWire {
    pubkey: String,
    balance: String,
    balance_frg: String,
    nonce: u64,
}

// Mirrors frgpb.StatusResponse exactly (field-for-field, including
// `omitempty`), because /status serializes that struct directly.
#[derive(Deserialize, Default)]
struct StatusResponseWire {
    #[serde(default)]
    height: u64,
    #[serde(default)]
    state_root: String,
    #[serde(default)]
    peer_count: u64,
    #[serde(default)]
    mempool_len: u64,
    #[serde(default)]
    validator_count: u64,
    #[serde(default)]
    consensus_round: u32,
    #[serde(default)]
    consensus_phase: String,
    #[serde(default)]
    grpc_only: bool,
}

#[derive(Deserialize)]
struct ValidatorEntryWire {
    pubkey: String,
    bond: String,
    bond_frg: String,
}

#[derive(Deserialize)]
struct ValidatorsResponseWire {
    #[serde(default)]
    validators: Vec<ValidatorEntryWire>,
}

// `amount`/`value` on the wire mean whole FRG (decimal) as of FRG's
// "Standardize FRG denominations" change; `_quanta` siblings were added
// alongside them for raw-integer callers and must be used exclusively
// (the server rejects a request setting both). Every quantity in
// ChainAdapter is already quanta (u64), so this client always uses the
// `_quanta` fields and never the human-decimal ones.
#[derive(Serialize)]
struct TransferRequest<'a> {
    to: &'a str,
    amount_quanta: &'a str,
}

#[derive(Serialize)]
struct BondRequest<'a> {
    amount_quanta: &'a str,
}

#[derive(Deserialize)]
struct TransferResult {
    txid: String,
}

#[derive(Serialize)]
struct ContractDeployRequest<'a> {
    wasm_hex: &'a str,
    value_quanta: &'a str,
}

#[derive(Deserialize)]
struct DeployResult {
    txid: String,
    contract_address: String,
}

#[derive(Serialize, Default)]
struct ContractCallRequest<'a> {
    contract_address: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    call_data_hex: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    function: Option<&'a str>,
    value_quanta: &'a str,
}

#[derive(Deserialize)]
struct ContractAddressResponse {
    contract_address: String,
}

#[derive(Deserialize)]
struct ContractStateResponseWire {
    contract_address: String,
    exists: bool,
    #[serde(default)]
    state_root: String,
    #[serde(default)]
    key: String,
    found: bool,
    #[serde(default)]
    value: String,
}

#[derive(Serialize)]
struct MissedDeadlineReportRequest<'a> {
    missed_height: u64,
    missed_proposer: &'a str,
    skip_index: u32,
}

#[derive(Serialize, Default)]
struct FaucetRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pubkey: Option<&'a str>,
}

#[derive(Deserialize)]
struct FaucetResult {
    #[serde(default)]
    txid: Option<String>,
}

fn encode_pubkey(pubkey: OnChainAccount) -> String {
    hex::encode(pubkey)
}

fn decode_pubkey(field: &str, s: &str) -> Result<OnChainAccount, String> {
    let bytes = hex::decode(s).map_err(|e| format!("frg-wallet: {field} {s:?} is not hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|b: Vec<u8>| format!("frg-wallet: {field} must be 32 bytes, got {}", b.len()))
}

impl FrgWalletClient {
    /// `base_url` is e.g. `http://127.0.0.1:8090` (no trailing slash).
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.into(),
        }
    }

    pub async fn health(&self) -> Result<(), String> {
        self.get::<serde_json::Value>("/health").await.map(|_| ())
    }

    pub async fn pubkey(&self) -> Result<(OnChainAccount, String), String> {
        let resp: PubkeyResponse = self.get("/pubkey").await?;
        Ok((decode_pubkey("pubkey", &resp.pubkey)?, resp.chain_id))
    }

    /// `pubkey = None` queries the wallet's own account.
    pub async fn account(&self, pubkey: Option<OnChainAccount>) -> Result<WalletAccount, String> {
        let path = match pubkey {
            Some(pk) => format!("/account?pubkey={}", encode_pubkey(pk)),
            None => "/account".to_string(),
        };
        let resp: AccountResponseWire = self.get(&path).await?;
        Ok(WalletAccount {
            pubkey: decode_pubkey("pubkey", &resp.pubkey)?,
            balance: resp.balance,
            balance_frg: resp.balance_frg,
            nonce: resp.nonce,
        })
    }

    pub async fn status(&self) -> Result<WalletStatus, String> {
        let resp: StatusResponseWire = self.get("/status").await?;
        let state_root = if resp.state_root.is_empty() {
            Vec::new()
        } else {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(&resp.state_root)
                .map_err(|e| format!("frg-wallet: state_root is not base64: {e}"))?
        };
        Ok(WalletStatus {
            height: resp.height,
            state_root,
            peer_count: resp.peer_count,
            mempool_len: resp.mempool_len,
            validator_count: resp.validator_count,
            consensus_round: resp.consensus_round,
            consensus_phase: resp.consensus_phase,
            grpc_only: resp.grpc_only,
        })
    }

    pub async fn validators(&self) -> Result<Vec<WalletValidator>, String> {
        let resp: ValidatorsResponseWire = self.get("/validators").await?;
        resp.validators
            .into_iter()
            .map(|v| {
                Ok(WalletValidator {
                    pubkey: decode_pubkey("validator pubkey", &v.pubkey)?,
                    bond: v.bond,
                    bond_frg: v.bond_frg,
                })
            })
            .collect()
    }

    /// `amount_quanta` is a positive base-10 quanta string (1 FRG =
    /// 10^18 quanta).
    pub async fn transfer(
        &self,
        to: OnChainAccount,
        amount_quanta: &str,
    ) -> Result<String, String> {
        let to = encode_pubkey(to);
        let body = TransferRequest {
            to: &to,
            amount_quanta,
        };
        let resp: TransferResult = self.post("/transfer", &body).await?;
        Ok(resp.txid)
    }

    /// Bonds the wallet's own key as a validator. FRG has no separate
    /// geo/metadata field on bonding, unlike `ChainAdapter::register_node`.
    /// `amount_quanta` is a positive base-10 quanta string.
    pub async fn bond(&self, amount_quanta: &str) -> Result<String, String> {
        let resp: TransferResult = self.post("/bond", &BondRequest { amount_quanta }).await?;
        Ok(resp.txid)
    }

    pub async fn unbond(&self) -> Result<String, String> {
        let resp: TransferResult = self.post_empty("/unbond").await?;
        Ok(resp.txid)
    }

    pub async fn finalize_unbond(&self) -> Result<String, String> {
        let resp: TransferResult = self.post_empty("/finalize-unbond").await?;
        Ok(resp.txid)
    }

    pub async fn claim_rewards(&self) -> Result<String, String> {
        let resp: TransferResult = self.post_empty("/claim-rewards").await?;
        Ok(resp.txid)
    }

    /// Submits MISS_EVIDENCE for `missed_proposer` missing its slot at
    /// `missed_height`. The wallet's own key must be the validator
    /// scheduled to report that miss (the next in skip rotation) --
    /// the node rejects the tx otherwise.
    pub async fn submit_missed_deadline_report(
        &self,
        missed_height: u64,
        missed_proposer: OnChainAccount,
        skip_index: u32,
    ) -> Result<String, String> {
        let missed_proposer = encode_pubkey(missed_proposer);
        let body = MissedDeadlineReportRequest {
            missed_height,
            missed_proposer: &missed_proposer,
            skip_index,
        };
        let resp: TransferResult = self.post("/miss-evidence", &body).await?;
        Ok(resp.txid)
    }

    /// `nonce = None` asks the server to predict the wallet's *next*
    /// deploy address (its current nonce + 1).
    pub async fn contract_address(&self, nonce: Option<u64>) -> Result<OnChainAccount, String> {
        let path = match nonce {
            Some(n) => format!("/contracts/address?nonce={n}"),
            None => "/contracts/address".to_string(),
        };
        let resp: ContractAddressResponse = self.get(&path).await?;
        decode_pubkey("contract_address", &resp.contract_address)
    }

    /// `value_quanta` is a non-negative base-10 quanta string (defaults to
    /// "0" server-side, but always sent explicitly here).
    pub async fn deploy_contract(
        &self,
        wasm: &[u8],
        value_quanta: &str,
    ) -> Result<(String, OnChainAccount), String> {
        let wasm_hex = hex::encode(wasm);
        let body = ContractDeployRequest {
            wasm_hex: &wasm_hex,
            value_quanta,
        };
        let resp: DeployResult = self.post("/contracts/deploy", &body).await?;
        Ok((
            resp.txid,
            decode_pubkey("contract_address", &resp.contract_address)?,
        ))
    }

    /// Exactly one of `function` (a 4-byte selector) or `call_data` should
    /// be set; if both are `None` the server defaults to the literal
    /// selector `"call"`.
    pub async fn call_contract(
        &self,
        contract_address: OnChainAccount,
        function: Option<&str>,
        call_data: Option<&[u8]>,
        value_quanta: &str,
    ) -> Result<String, String> {
        let addr = encode_pubkey(contract_address);
        let call_data_hex = call_data.map(hex::encode);
        let body = ContractCallRequest {
            contract_address: &addr,
            call_data_hex: call_data_hex.as_deref(),
            function,
            value_quanta,
        };
        let resp: TransferResult = self.post("/contracts/call", &body).await?;
        Ok(resp.txid)
    }

    /// `key = None` only queries existence/state root, not a specific
    /// state entry.
    pub async fn contract_state(
        &self,
        contract_address: OnChainAccount,
        key: Option<&[u8]>,
    ) -> Result<ContractState, String> {
        let mut path = format!(
            "/contracts/state?contract_address={}",
            encode_pubkey(contract_address)
        );
        if let Some(key) = key {
            path.push_str(&format!("&key_hex={}", hex::encode(key)));
        }
        let resp: ContractStateResponseWire = self.get(&path).await?;
        Ok(ContractState {
            contract_address: decode_pubkey("contract_address", &resp.contract_address)?,
            exists: resp.exists,
            state_root: hex::decode(&resp.state_root)
                .map_err(|e| format!("frg-wallet: state_root is not hex: {e}"))?,
            key: hex::decode(&resp.key).map_err(|e| format!("frg-wallet: key is not hex: {e}"))?,
            found: resp.found,
            value: hex::decode(&resp.value)
                .map_err(|e| format!("frg-wallet: value is not hex: {e}"))?,
        })
    }

    /// Requires the wallet to have been started with `--faucet-url`.
    /// `pubkey = None` funds the wallet's own key. Returns the funding
    /// txid, if the faucet reports one.
    pub async fn faucet(&self, pubkey: Option<OnChainAccount>) -> Result<Option<String>, String> {
        let encoded = pubkey.map(encode_pubkey);
        let body = FaucetRequest {
            pubkey: encoded.as_deref(),
        };
        let resp: FaucetResult = self.post("/faucet", &body).await?;
        Ok(resp.txid)
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, String> {
        let resp = self
            .http
            .get(format!("{}{path}", self.base_url))
            .send()
            .await
            .map_err(|e| format!("frg-wallet: GET {path} failed: {e}"))?;
        Self::parse(resp).await
    }

    async fn post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<T, String> {
        let resp = self
            .http
            .post(format!("{}{path}", self.base_url))
            .json(body)
            .send()
            .await
            .map_err(|e| format!("frg-wallet: POST {path} failed: {e}"))?;
        Self::parse(resp).await
    }

    async fn post_empty<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, String> {
        let resp = self
            .http
            .post(format!("{}{path}", self.base_url))
            .send()
            .await
            .map_err(|e| format!("frg-wallet: POST {path} failed: {e}"))?;
        Self::parse(resp).await
    }

    async fn parse<T: serde::de::DeserializeOwned>(resp: reqwest::Response) -> Result<T, String> {
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| format!("frg-wallet: reading response body failed: {e}"))?;
        if !status.is_success() {
            let message = serde_json::from_str::<ErrorResponse>(&body)
                .map(|e| e.error)
                .unwrap_or(body);
            return Err(format!("frg-wallet: {status}: {message}"));
        }
        serde_json::from_str(&body)
            .map_err(|e| format!("frg-wallet: unexpected response body ({body:?}): {e}"))
    }
}
