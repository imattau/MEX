// Connects the two halves of settlement that, until now, only existed as
// separately-tested pieces: SettlementBatcher (proves batches of confirmed
// matches) and ChainAdapter::submit_settlement_batch (submits a proven
// batch on-chain). Runs as a background loop: periodically drains ready
// batches from AppState's batcher, resolves each trade's off-chain pubkeys
// to real Ethereum addresses (via a live ChainSync), and submits each
// proof chunk with settleBatchWithFees.
//
// This is infra-signed, not trader-signed -- it uses the settlement
// node's own key (see chain::ChainAdapter's docs for why commitTrade and
// claimSlash are deliberately NOT part of this path).

use crate::server::AppState;
use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};
use chain::{ChainAdapter, SettlementFeeConfig, SettlementTrade, Token};
use chain_ethereum::{address_to_account, ChainSync, EthereumAdapter, TokenRegistry};
use std::sync::{Arc, RwLock};
use std::time::Duration;

pub struct SettlementConfig {
    pub rpc_url: String,
    pub node_private_key: String,
    pub factory_address: String,
    pub registry_address: String,
    pub fee_recipient: Address,
    pub poll_interval: Duration,
}

pub async fn run_settlement_loop(state: Arc<RwLock<AppState>>, config: SettlementConfig) {
    let chain_adapter = match EthereumAdapter::new(
        &config.rpc_url,
        &config.node_private_key,
        &config.factory_address,
        &config.registry_address,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, "settlement loop: failed to construct EthereumAdapter, not starting");
            return;
        }
    };

    let url = match config.rpc_url.parse() {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "settlement loop: invalid RPC URL, not starting");
            return;
        }
    };
    let sync_provider = ProviderBuilder::new().connect_http(url).erased();
    let factory_addr: Address = match config.factory_address.parse() {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, "settlement loop: invalid factory address, not starting");
            return;
        }
    };
    let mut chain_sync = ChainSync::new(sync_provider, *factory_addr.as_ref(), TokenRegistry::new(), 0, 0);

    tracing::info!("settlement loop started");

    loop {
        tokio::time::sleep(config.poll_interval).await;

        if let Err(e) = chain_sync.poll_once().await {
            tracing::warn!(error = %e, "settlement loop: chain sync poll failed, will retry next tick");
        }

        let batches = {
            let mut guard = state.write().unwrap();
            guard.batcher.process_batches()
        };

        for batch in batches {
            let mut idx = 0;
            for (proof, &count) in batch.proofs.iter().zip(&batch.proof_trade_counts) {
                let chunk = &batch.trades[idx..idx + count];
                idx += count;

                match build_settlement_trades(&state, &chain_sync, chunk) {
                    Some(settlement_trades) => {
                        let fee_config = SettlementFeeConfig {
                            fee_recipient: address_to_account(config.fee_recipient),
                            tier: 0,
                        };
                        match chain_adapter
                            .submit_settlement_batch(&settlement_trades, proof, fee_config)
                            .await
                        {
                            Ok(tx) => tracing::info!(tx, trades = settlement_trades.len(), "settled a batch chunk on-chain"),
                            Err(e) => tracing::error!(error = %e, "settleBatchWithFees failed for a chunk"),
                        }
                    }
                    None => {
                        tracing::warn!("skipping a batch chunk: missing trade_hash or unresolvable trader address for at least one trade in it");
                    }
                }
            }
        }
    }
}

// Builds the on-chain TradeEntry-equivalent for every trade in a chunk, or
// None if any single trade in it can't be resolved yet (missing
// confirmed_trade_hash, or a trader whose escrow hasn't been observed by
// chain_sync yet) -- the whole chunk shares one proof, so it's all-or-
// nothing, same as the proof itself.
fn build_settlement_trades(
    state: &Arc<RwLock<AppState>>,
    chain_sync: &ChainSync<impl Provider>,
    chunk: &[engine::Match],
) -> Option<Vec<SettlementTrade>> {
    let mut out = Vec::with_capacity(chunk.len());

    for m in chunk {
        let trade_hash = {
            let mut guard = state.write().unwrap();
            guard.confirmed_trade_hashes.remove(&(m.maker_order_id, m.taker_order_id))?
        };

        let (payer_pubkey, counterparty_pubkey) = if m.fee_payer == m.maker_trader {
            (m.maker_trader, m.taker_trader)
        } else {
            (m.taker_trader, m.maker_trader)
        };

        let payer_addr = resolve_address(chain_sync, payer_pubkey)?;
        let counterparty_addr = resolve_address(chain_sync, counterparty_pubkey)?;

        let notional = m.price * m.amount;
        let fee = notional * m.fee_basis_points as u64 / 10_000;

        out.push(SettlementTrade {
            maker_order_id: m.maker_order_id,
            taker_order_id: m.taker_order_id,
            trader: address_to_account(payer_addr),
            counterparty: address_to_account(counterparty_addr),
            token: Token::Native,
            amount: notional,
            fee,
            deadline: m.settlement_deadline,
            trade_hash,
            assigned_node: m.assigned_node,
        });
    }

    Some(out)
}

fn resolve_address(chain_sync: &ChainSync<impl Provider>, pubkey: [u8; 32]) -> Option<Address> {
    chain_sync.escrows().known_escrows().find_map(|escrow| {
        let owner = chain_sync.escrows().owner_of(*escrow)?;
        (owner.offchain_pubkey == pubkey).then_some(Address::from(owner.trader))
    })
}
