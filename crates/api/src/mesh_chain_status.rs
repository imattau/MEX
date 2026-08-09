// Stage 4c: the periodic NodeRegistry poll that feeds
// protocol::MeshNode::chain_status_sender -- the piece Stage 4b's
// require_staked_reporters gate needed but didn't build, since protocol
// deliberately doesn't depend on chain/chain-ethereum (see node.rs's
// ChainNodeStatus docs). Mirrors settlement.rs::run_settlement_loop's
// shape: construct one EthereumAdapter, loop on an interval, push
// results back into the mesh via a channel rather than holding the
// MeshNode directly (run() already owns it by the time this is spawned).

use chain::ChainAdapter;
use chain_ethereum::EthereumAdapter;
use protocol::ChainNodeStatus;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;

pub struct MeshChainStatusConfig {
    pub rpc_url: String,
    pub node_private_key: String,
    pub factory_address: String,
    pub registry_address: String,
    // Every mesh peer's real (non-placeholder) pubkey -- see
    // main.rs's MEX_MESH_PEERS parsing. Static for this process's
    // lifetime, matching how MEX_MESH_PEERS itself is only read once at
    // startup; a peer added later via some future dynamic-membership
    // mechanism wouldn't be picked up without a restart.
    pub peer_pubkeys: Vec<[u8; 32]>,
    pub poll_interval: Duration,
    pub chain_status_tx: mpsc::Sender<HashMap<[u8; 32], ChainNodeStatus>>,
}

pub async fn run_mesh_chain_status_loop(config: MeshChainStatusConfig) {
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
            tracing::error!(error = %e, "mesh chain-status loop: failed to construct EthereumAdapter, not starting");
            return;
        }
    };

    if config.peer_pubkeys.is_empty() {
        tracing::warn!("mesh chain-status loop: MEX_MESH_REQUIRE_STAKE is set but no MEX_MESH_PEERS entry carries a real pubkey (id@host:port@pubkeyhex) -- no reporter will ever resolve to an eligible on-chain identity");
    }

    tracing::info!(peers = config.peer_pubkeys.len(), poll_interval = ?config.poll_interval, "mesh chain-status loop started");

    loop {
        tokio::time::sleep(config.poll_interval).await;

        let mut snapshot = HashMap::new();
        for pubkey in &config.peer_pubkeys {
            let active = match chain_adapter.is_node_active(*pubkey).await {
                Ok(active) => active,
                Err(e) => {
                    tracing::warn!(error = %e, pubkey = %hex::encode(pubkey), "mesh chain-status loop: is_node_active failed, leaving this peer out of this round's snapshot");
                    continue;
                }
            };
            let stake = chain_adapter.get_node_stake(*pubkey).await.unwrap_or_else(|e| {
                tracing::warn!(error = %e, pubkey = %hex::encode(pubkey), "mesh chain-status loop: get_node_stake failed, recording stake as 0 for this round");
                0
            });
            snapshot.insert(*pubkey, ChainNodeStatus { active, stake });
        }

        tracing::debug!(
            entries = snapshot.len(),
            "mesh chain-status loop: pushing fresh snapshot"
        );
        if config.chain_status_tx.send(snapshot).await.is_err() {
            tracing::warn!(
                "mesh chain-status loop: mesh node's chain_status channel closed, stopping"
            );
            return;
        }
    }
}
