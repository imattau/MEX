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
                                tracing::error!(error = %e, trades = settlement_trades.len(), "settleBatchWithFees failed for a chunk -- re-queueing every trade in it for retry next interval");
                                let mut guard = state.write().unwrap();
                                restore_failed_chunk(&mut guard, chunk, &settlement_trades);
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

// Stage P4-4a: undoes what build_settlement_trades (below) and
// batcher.process_batches (in run_settlement_loop, above) already did to
// this chunk's trades BEFORE the just-failed submit_settlement_batch
// call was even made -- confirmed_trade_hashes' entries were already
// consumed, and the trades were already drained out of the batcher's
// queue. Without this, a failed submission (a network hiccup, an
// out-of-gas, or Stage P4-4c's future "already settled on-chain"
// reconciliation case) would silently drop every trade in the chunk from
// all local bookkeeping, forever, with no retry -- a real, pre-existing
// bug independent of persistence, found while scoping P4-4.
//
// `chunk` and `settlement_trades` are the same length, in the same
// order (build_settlement_trades only ever returns Some(..) once every
// trade in `chunk` succeeded, pushing exactly one SettlementTrade per
// input Match in iteration order) -- zip is safe. No new durable WAL
// entry is needed for this alone: these trades' CommitConfirmed entries
// are still on disk, and no BatchSubmitted checkpoint was ever written
// for them (that only happens after a successful submission) -- the WAL
// already correctly reflects "still pending"; only this in-memory state
// had drifted from it.
fn restore_failed_chunk(
    guard: &mut AppState,
    chunk: &[engine::Match],
    settlement_trades: &[SettlementTrade],
) {
    for (m, st) in chunk.iter().zip(settlement_trades) {
        guard
            .confirmed_trade_hashes
            .insert((m.maker_order_id, m.taker_order_id), st.trade_hash);
        guard.batcher.enqueue(m.clone());
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

#[cfg(test)]
mod tests {
    use super::*;
    use chain::Token;
    use ed25519_dalek::SigningKey;
    use engine::Match;
    use rand::rngs::OsRng;

    fn make_match(seed: u8) -> Match {
        Match {
            maker_order_id: [seed; 32],
            taker_order_id: [seed + 1; 32],
            maker_trader: [seed + 2; 32],
            taker_trader: [seed + 3; 32],
            price: 100,
            amount: 10,
            timestamp_us: 0,
            // Instant tier flushes immediately on process_batches(), no
            // batch-size/timer gate to fight with in a test.
            settlement_tier: common::SettlementPreference::Instant,
            fee_basis_points: 5,
            seller: [seed + 3; 32],
            fee_payer: [seed + 3; 32],
            symbol: "ETH-USD".to_string(),
            assigned_node: [0u8; 32],
            settlement_deadline: 0,
        }
    }

    fn make_settlement_trade(m: &Match, trade_hash: [u8; 32]) -> SettlementTrade {
        SettlementTrade {
            maker_order_id: m.maker_order_id,
            taker_order_id: m.taker_order_id,
            trader: m.taker_trader,
            counterparty: m.maker_trader,
            token: Token::Native,
            amount: m.price * m.amount,
            fee: 0,
            deadline: m.settlement_deadline,
            trade_hash,
            assigned_node: m.assigned_node,
        }
    }

    fn test_state() -> AppState {
        let (tx, _) = tokio::sync::broadcast::channel(100);
        AppState {
            node_id: common::NodeId(0),
            order_book: engine::OrderBook::new("ETH-USD".to_string()),
            validator: validation::OrderValidator::new(100),
            ws_broadcast: tx,
            reputation: reputation::ReputationEngine::new(),
            pending_commits: std::collections::HashMap::new(),
            confirmed_trade_hashes: std::collections::HashMap::new(),
            batcher: batcher::SettlementBatcher::new(),
            receipt_signing_key: SigningKey::generate(&mut OsRng),
            order_log: orderlog::HashChainLog::new(),
            match_log: orderlog::HashChainLog::new(),
            mesh: None,
            order_sequencer: None,
            pending_order_data: std::collections::HashMap::new(),
            applied_order_ids: std::collections::HashSet::new(),
            persistence: None,
        }
    }

    // Stage P4-4a: the actual bug being fixed -- before this,
    // build_settlement_trades and process_batches had already drained
    // these trades out of confirmed_trade_hashes and the batcher's
    // queue BEFORE a submission was even attempted, so a failed
    // submission dropped them forever. restore_failed_chunk must put
    // both back exactly as they stood before that draining.
    #[test]
    fn test_restore_failed_chunk_reinstates_confirmed_hashes_and_batcher_queue() {
        let mut state = test_state();

        let m1 = make_match(1);
        let m2 = make_match(10);
        let hash1 = [0xAAu8; 32];
        let hash2 = [0xBBu8; 32];
        let chunk = vec![m1.clone(), m2.clone()];
        let settlement_trades = vec![
            make_settlement_trade(&m1, hash1),
            make_settlement_trade(&m2, hash2),
        ];

        // Simulate what build_settlement_trades + process_batches already
        // did before the failed submission: both trades are gone from
        // confirmed_trade_hashes and would already have been drained out
        // of the batcher's internal queues (nothing to simulate there --
        // an empty batcher already reflects "drained").
        assert!(state.confirmed_trade_hashes.is_empty());
        state
            .batcher
            .deposit(m1.taker_trader, &m1.symbol, u64::MAX / 2);
        state
            .batcher
            .deposit(m2.taker_trader, &m2.symbol, u64::MAX / 2);

        restore_failed_chunk(&mut state, &chunk, &settlement_trades);

        assert_eq!(
            state
                .confirmed_trade_hashes
                .get(&(m1.maker_order_id, m1.taker_order_id)),
            Some(&hash1),
            "trade 1's confirmed_trade_hashes entry must be restored with its original trade_hash"
        );
        assert_eq!(
            state
                .confirmed_trade_hashes
                .get(&(m2.maker_order_id, m2.taker_order_id)),
            Some(&hash2),
            "trade 2's confirmed_trade_hashes entry must be restored with its original trade_hash"
        );

        // Both trades must be back in the batcher's queue, ready to be
        // picked up and retried on the next process_batches() call(s) --
        // try_flush_instant only pops one trade per call, so two calls
        // are needed to drain both.
        let mut settled_ids: Vec<[u8; 32]> = Vec::new();
        for _ in 0..2 {
            let batches = state.batcher.process_batches();
            settled_ids.extend(
                batches
                    .iter()
                    .flat_map(|b| b.trades.iter().map(|t| t.maker_order_id)),
            );
        }
        assert!(
            settled_ids.contains(&m1.maker_order_id),
            "trade 1 must be back in the batcher's queue after restore_failed_chunk"
        );
        assert!(
            settled_ids.contains(&m2.maker_order_id),
            "trade 2 must be back in the batcher's queue after restore_failed_chunk"
        );
    }
}
