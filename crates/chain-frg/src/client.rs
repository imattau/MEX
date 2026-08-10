//! Thin wrapper over the tonic client generated from `proto/frg.proto`.

mod pb {
    tonic::include_proto!("frg");
}

use chain::OnChainAccount;
use pb::frg_client::FrgClient as GrpcClient;
use pb::{AccountRequest, Empty, RawBytes};
use tonic::transport::Channel;

pub struct FrgClient {
    inner: GrpcClient<Channel>,
}

impl FrgClient {
    pub async fn connect(endpoint: impl Into<String>) -> Result<Self, String> {
        let inner = GrpcClient::connect(endpoint.into())
            .await
            .map_err(|e| format!("chain-frg: failed to connect: {e}"))?;
        Ok(Self { inner })
    }

    // u128, not u64: FRG bonds are quanta (1 FRG = 10^18 quanta), and the
    // protocol minimum bond alone is 1,000 FRG = 10^21 quanta -- already
    // ~54x past u64::MAX (~1.8*10^19, i.e. ~18.4 FRG). u64 can't represent
    // any real validator's bond. Confirmed live against a real devnet:
    // parsing this as u64 failed outright for the genesis validator's
    // bond. u128 covers the full range with room to spare.
    pub async fn validator_bond(&self, pubkey: OnChainAccount) -> Result<u128, String> {
        let entry = self.find_validator(pubkey).await?;
        match entry {
            Some(v) => v
                .bond
                .parse::<u128>()
                .map_err(|e| format!("chain-frg: unparsable bond {:?}: {e}", v.bond)),
            None => Ok(0),
        }
    }

    pub async fn is_validator(&self, pubkey: OnChainAccount) -> Result<bool, String> {
        Ok(self.find_validator(pubkey).await?.is_some())
    }

    async fn find_validator(
        &self,
        pubkey: OnChainAccount,
    ) -> Result<Option<pb::ValidatorEntry>, String> {
        let mut client = self.inner.clone();
        let resp = client
            .list_validators(Empty {})
            .await
            .map_err(|e| format!("chain-frg: ListValidators failed: {e}"))?
            .into_inner();
        Ok(resp
            .validators
            .into_iter()
            .find(|v| v.pubkey.as_slice() == pubkey.as_slice()))
    }

    pub async fn account_balance(&self, pubkey: OnChainAccount) -> Result<(String, u64), String> {
        let mut client = self.inner.clone();
        let resp = client
            .get_account(AccountRequest {
                pubkey: pubkey.to_vec(),
            })
            .await
            .map_err(|e| format!("chain-frg: GetAccount failed: {e}"))?
            .into_inner();
        Ok((resp.balance, resp.nonce))
    }

    /// Submits an already-encoded, already-signed FRG transaction. FRG's
    /// tx wire format (`core/tx` in the Go repo) isn't reimplemented in
    /// this crate, so callers must produce `raw` themselves for now -- see
    /// the module docs in `lib.rs`.
    pub async fn submit_raw_tx(&self, raw: Vec<u8>) -> Result<(), String> {
        let mut client = self.inner.clone();
        let resp = client
            .submit_tx(RawBytes { data: raw })
            .await
            .map_err(|e| format!("chain-frg: SubmitTx failed: {e}"))?
            .into_inner();
        if resp.ok {
            Ok(())
        } else {
            Err(format!("chain-frg: SubmitTx rejected: {}", resp.error))
        }
    }
}
