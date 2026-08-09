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
    // This node's own settlement pubkey (matches OrderBook::assign_node's
    // entries, see main.rs's MEX_SETTLEMENT_NODE_PUBKEY /
    // MEX_SETTLEMENT_ACTIVE_NODES docs). A chunk is only submitted here if
    // every trade in it -- SettlementBatcher::build_batch now guarantees
    // this is homogeneous per chunk, see its own docs -- is assigned to
    // this pubkey; chunks assigned to another active node are silently
    // skipped, not errored, since submitting them is that OTHER node's job.
    pub own_settlement_pubkey: [u8; 32],
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
    let mut chain_sync = ChainSync::new(
        sync_provider,
        *factory_addr.as_ref(),
        TokenRegistry::new(),
        0,
        0,
    );

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
            for ((proof, &count), trade_batch) in batch
                .proofs
                .iter()
                .zip(&batch.proof_trade_counts)
                .zip(&batch.trade_batches)
            {
                let chunk = &batch.trades[idx..idx + count];
                idx += count;

                // build_batch groups trades by assigned_node before
                // chunking, so every trade in a chunk shares the same
                // assigned_node -- checking the first is checking all of
                // them. An empty chunk can't reach here (build_batch skips
                // those), so this is always Some.
                let chunk_assigned_node = chunk[0].assigned_node;
                if chunk_assigned_node != config.own_settlement_pubkey {
                    tracing::debug!(
                        assigned_node = %hex::encode(chunk_assigned_node),
                        own = %hex::encode(config.own_settlement_pubkey),
                        count,
                        "skipping settlement chunk assigned to a different node"
                    );
                    continue;
                }

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
                            Ok(tx) => {
                                tracing::info!(
                                    tx,
                                    trades = settlement_trades.len(),
                                    "settled a batch chunk on-chain"
                                );
                                // Stage P4-2: checkpoint every trade in
                                // this chunk as fully settled BEFORE
                                // broadcasting the proof -- so a crash
                                // right after a real on-chain submission
                                // doesn't leave replay believing these
                                // are still awaiting settlement (which
                                // would attempt a duplicate submission
                                // next restart). Doesn't need AppState's
                                // write lock: PersistenceLog::append does
                                // its own I/O, and the causal ordering
                                // this relies on (a CommitConfirmed entry
                                // always precedes the BatchSubmitted
                                // checkpoint for the same key) is already
                                // guaranteed by AppState's lock
                                // serializing confirm_committed against
                                // this loop's own batcher.process_batches
                                // call above. A checkpoint-write failure
                                // is logged, not retried here -- see
                                // MEX_PERSISTENCE_PATH's own docs on the
                                // remaining crash window this can't close
                                // alone.
                                let persistence_log = state.read().unwrap().persistence.clone();
                                if let Some(log) = persistence_log {
                                    let keys: Vec<([u8; 32], [u8; 32])> = settlement_trades
                                        .iter()
                                        .map(|t| (t.maker_order_id, t.taker_order_id))
                                        .collect();
                                    if let Err(e) = log.append_batch_submitted(keys) {
                                        tracing::error!(error = %e, "failed to durably checkpoint a successful settlement submission -- a crash before this recovers could attempt a duplicate on-chain submission next restart");
                                    }
                                }
                                broadcast_settlement_proof(&state, trade_batch, proof).await;
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "settleBatchWithFees failed for a chunk")
                            }
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

// Broadcasts the exact TradeBatch + proof just submitted on-chain to
// every configured mesh peer, so each can independently re-verify it
// (watchtower::WatchtowerClient::monitor_batch) instead of trusting this
// node's own self-report. Only broadcast AFTER a successful on-chain
// submission -- a failed submission never happened as far as settlement
// is concerned, so there's nothing real to verify yet.
async fn broadcast_settlement_proof(
    state: &Arc<RwLock<AppState>>,
    trade_batch: &prover::TradeBatch,
    proof: &[u8],
) {
    let mesh = {
        let guard = state.read().unwrap();
        match &guard.mesh {
            Some(m) => (m.transport.clone(), m.peer_ids.clone()),
            None => return,
        }
    };
    let (transport, peer_ids) = mesh;
    for peer_id in peer_ids {
        let msg = protocol::WireMessage::SettlementProof {
            batch: trade_batch.clone(),
            proof: proof.to_vec(),
        };
        if let Err(e) = transport.send(peer_id, msg).await {
            tracing::warn!(?peer_id, error = %e, "failed to broadcast settlement proof to peer");
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
            guard
                .confirmed_trade_hashes
                .remove(&(m.maker_order_id, m.taker_order_id))?
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
