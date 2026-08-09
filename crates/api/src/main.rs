// The first actual runnable entry point for this DEX's matching API --
// previously AppState/app() existed and were unit-tested, but nothing
// anywhere constructed a real AppState and served it as a live process.
//
// Env vars:
//   MEX_API_KEY              Required by check_auth (server.rs); a dev
//                             default is used with a loud warning if unset.
//   MEX_API_PORT              Defaults to 8080.
//   MEX_API_SYMBOL            Defaults to "ETH-USD".
//   MEX_RPC_URL               Required. Ethereum JSON-RPC endpoint.
//   MEX_NODE_PRIVATE_KEY      Required. This settlement node's own key --
//                             must already be registered in NodeRegistry
//                             (see scripts/deploy.js / register_node).
//   MEX_FACTORY_ADDRESS       Required. SettlementFactory address.
//   MEX_REGISTRY_ADDRESS      Required. NodeRegistry address.
//   MEX_SETTLEMENT_NODE_PUBKEY  Required, hex. This node's own 32-byte
//                             pubkey as registered in NodeRegistry -- used
//                             to configure the OrderBook's active-node set
//                             so matches actually get assigned to a real,
//                             active node instead of the zero sentinel.
//   MEX_SETTLEMENT_POLL_SECS Defaults to 5.
//   MEX_FEE_BASE_GAS_PRICE   Optional, gwei. Feeds FeeCalculator's gas-price
//                            term. Unset means FeeCalculator::default(),
//                            which reproduces the old fixed 5/15/50 bps
//                            schedule exactly -- see common::fees' own
//                            test_default_calculator_matches_static_schedule.
//                            This is a static value set at startup, not
//                            live-polled; see FeeCalculator's own docs for
//                            why (this crate is chain-agnostic).
//   MEX_FEE_BATCH_UTILIZATION Optional, 0.0-1.0. Feeds FeeCalculator's
//                            batching-discount term -- the operator's
//                            expected typical_batch_size / MAX_BATCH_TRADES,
//                            not a live value (see FeeCalculator's docs).
//   MEX_FEE_VOLATILITY_INDEX Optional, >= 0.0. Feeds FeeCalculator's
//                            volatility-premium term.
//   MEX_RECEIPT_SIGNING_KEY  Optional, hex-encoded 32-byte ed25519 seed.
//                            Signs order receipts (see receipts.rs) --
//                            deliberately separate from
//                            MEX_NODE_PRIVATE_KEY, since this key never
//                            authorizes moving funds. If unset, a fresh
//                            key is generated at startup with a loud
//                            warning: receipts still work within that
//                            process's lifetime, but a trader who wants to
//                            hold this node accountable across restarts
//                            needs the pubkey to stay stable, so this
//                            should be set for any real deployment.
//   MEX_MESH_NODE_ID         Optional, u32. Presence of this var is what
//                            enables the gossip mesh (protocol crate) --
//                            unset means no mesh, matching every other
//                            optional feature in this file: no behavior
//                            change from before it existed.
//   MEX_MESH_LISTEN_ADDR     Required if MEX_MESH_NODE_ID is set. UDP
//                            address this node's mesh listens on, e.g.
//                            0.0.0.0:9001.
//   MEX_MESH_REGION          Optional if mesh enabled. One of us-east-1 /
//                            eu-west-1 / ap-southeast-1. Defaults to
//                            us-east-1.
//   MEX_MESH_PEERS           Optional if mesh enabled. Comma-separated
//                            entries, each either id@host:port (pubkey
//                            defaults to the zero placeholder --
//                            unauthenticated, matches SignedHeartbeat
//                            verification off and Stage 4b/4c chain
//                            gating never resolving this peer) or
//                            id@host:port@pubkeyhex (this peer's real
//                            32-byte ed25519 pubkey, hex-encoded -- the
//                            SAME identity NodeRegistry tracks on-chain,
//                            see protocol::MeshNode::peer_pubkey's docs).
//                            e.g. "1@127.0.0.1:9002@aa..,2@127.0.0.1:9003".
//   MEX_MESH_REQUIRE_STAKE   Optional bool ("1"/"true"), defaults false.
//                            When set, a misconduct reporter's vote only
//                            counts toward this node's MisconductQuorum
//                            if it resolves (via the pubkey above) to an
//                            active entry in a periodically-polled
//                            NodeRegistry snapshot -- see
//                            api::mesh_chain_status. Off reproduces the
//                            old any-NodeId-counts behavior exactly.
//   MEX_MESH_CHAIN_STATUS_POLL_SECS  Optional, only used if
//                            MEX_MESH_REQUIRE_STAKE is set. Defaults 30.
//   MEX_MESH_STAKE_QUORUM_THRESHOLD  Required if MEX_MESH_REQUIRE_STAKE
//                            is set (ignored otherwise). Minimum COMBINED
//                            on-chain stake, across at least 2 distinct
//                            eligible reporters, before a misconduct
//                            accusation is confirmed -- see
//                            protocol::MeshNode's MisconductQuorum docs.
//                            No default: an unset value here would
//                            silently fall back to a 0 threshold, which
//                            reproduces Stage 4b/4c's plain active/
//                            inactive gate rather than real stake
//                            weighting, so this fails loud instead.

use api::server::{AppState, MeshHandle};
use api::settlement::SettlementConfig;
use common::FeeCalculator;
use ed25519_dalek::SigningKey;
use engine::OrderBook;
use std::sync::{Arc, RwLock};
use std::time::Duration;

fn require_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        eprintln!("required environment variable {name} not set");
        std::process::exit(1);
    })
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let port: u16 = std::env::var("MEX_API_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let symbol = std::env::var("MEX_API_SYMBOL").unwrap_or_else(|_| "ETH-USD".to_string());

    let rpc_url = require_env("MEX_RPC_URL");
    let node_private_key = require_env("MEX_NODE_PRIVATE_KEY");
    let factory_address = require_env("MEX_FACTORY_ADDRESS");
    let registry_address = require_env("MEX_REGISTRY_ADDRESS");
    let node_pubkey_hex = require_env("MEX_SETTLEMENT_NODE_PUBKEY");
    let node_pubkey_bytes = hex::decode(node_pubkey_hex.trim_start_matches("0x"))
        .unwrap_or_else(|e| {
            eprintln!("MEX_SETTLEMENT_NODE_PUBKEY is not valid hex: {e}");
            std::process::exit(1);
        });
    let node_pubkey: [u8; 32] = node_pubkey_bytes.try_into().unwrap_or_else(|v: Vec<u8>| {
        eprintln!("MEX_SETTLEMENT_NODE_PUBKEY must be exactly 32 bytes, got {}", v.len());
        std::process::exit(1);
    });

    let poll_secs: u64 = std::env::var("MEX_SETTLEMENT_POLL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);

    let deployer_signer: alloy::signers::local::PrivateKeySigner = node_private_key
        .trim_start_matches("0x")
        .parse()
        .unwrap_or_else(|e| {
            eprintln!("MEX_NODE_PRIVATE_KEY is not a valid private key: {e}");
            std::process::exit(1);
        });
    let fee_recipient = deployer_signer.address();

    let fee_base_gas_price: u64 = std::env::var("MEX_FEE_BASE_GAS_PRICE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50); // matches FeeCalculator::default()'s BASELINE_GAS_GWEI
    let fee_batch_utilization: f64 = std::env::var("MEX_FEE_BATCH_UTILIZATION")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);
    let fee_volatility_index: f64 = std::env::var("MEX_FEE_VOLATILITY_INDEX")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);
    let fee_calculator = FeeCalculator::new(fee_base_gas_price, fee_batch_utilization, fee_volatility_index);

    let receipt_signing_key: SigningKey = match std::env::var("MEX_RECEIPT_SIGNING_KEY") {
        Ok(hex_seed) => {
            let seed_bytes = hex::decode(hex_seed.trim_start_matches("0x")).unwrap_or_else(|e| {
                eprintln!("MEX_RECEIPT_SIGNING_KEY is not valid hex: {e}");
                std::process::exit(1);
            });
            let seed: [u8; 32] = seed_bytes.try_into().unwrap_or_else(|v: Vec<u8>| {
                eprintln!("MEX_RECEIPT_SIGNING_KEY must be exactly 32 bytes, got {}", v.len());
                std::process::exit(1);
            });
            SigningKey::from_bytes(&seed)
        }
        Err(_) => {
            eprintln!("WARNING: MEX_RECEIPT_SIGNING_KEY not set -- generating an ephemeral receipt-signing key for this process only. Order receipts won't be verifiable against a stable pubkey across restarts.");
            SigningKey::generate(&mut rand::rngs::OsRng)
        }
    };
    let receipt_pubkey_hex = hex::encode(receipt_signing_key.verifying_key().to_bytes());

    let mut order_book = OrderBook::new(symbol.clone());
    order_book.set_active_nodes(vec![node_pubkey]);
    order_book.set_fee_calculator(fee_calculator);

    let mesh = match std::env::var("MEX_MESH_NODE_ID") {
        Ok(id_str) => {
            let mesh_node_id: u32 = id_str.parse().unwrap_or_else(|e| {
                eprintln!("MEX_MESH_NODE_ID is not a valid u32: {e}");
                std::process::exit(1);
            });
            let listen_addr: std::net::SocketAddr = require_env("MEX_MESH_LISTEN_ADDR")
                .parse()
                .unwrap_or_else(|e| {
                    eprintln!("MEX_MESH_LISTEN_ADDR is not a valid socket address: {e}");
                    std::process::exit(1);
                });
            let region = match std::env::var("MEX_MESH_REGION").as_deref() {
                Ok("eu-west-1") => common::Region::EuWest1,
                Ok("ap-southeast-1") => common::Region::ApSoutheast1,
                Ok("us-east-1") | Err(_) => common::Region::UsEast1,
                Ok(other) => {
                    eprintln!("MEX_MESH_REGION must be one of us-east-1/eu-west-1/ap-southeast-1, got {other}");
                    std::process::exit(1);
                }
            };
            let peers: Vec<(common::NodeId, std::net::SocketAddr, [u8; 32])> =
                std::env::var("MEX_MESH_PEERS").unwrap_or_default()
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|entry| {
                        let mut parts = entry.splitn(3, '@');
                        let id_part = parts.next().filter(|s| !s.is_empty()).unwrap_or_else(|| {
                            eprintln!("MEX_MESH_PEERS entry '{entry}' must be of the form id@host:port[@pubkeyhex]");
                            std::process::exit(1);
                        });
                        let addr_part = parts.next().unwrap_or_else(|| {
                            eprintln!("MEX_MESH_PEERS entry '{entry}' must be of the form id@host:port[@pubkeyhex]");
                            std::process::exit(1);
                        });
                        let peer_id: u32 = id_part.parse().unwrap_or_else(|e| {
                            eprintln!("MEX_MESH_PEERS entry '{entry}' has an invalid id: {e}");
                            std::process::exit(1);
                        });
                        let peer_addr: std::net::SocketAddr = addr_part.parse().unwrap_or_else(|e| {
                            eprintln!("MEX_MESH_PEERS entry '{entry}' has an invalid address: {e}");
                            std::process::exit(1);
                        });
                        // Real pubkey if the entry carried a third @-separated
                        // segment; otherwise the [0u8; 32] no-key placeholder
                        // (unauthenticated -- see MEX_MESH_PEERS's own docs).
                        let pubkey = match parts.next() {
                            Some(hex_str) => {
                                let bytes = hex::decode(hex_str.trim_start_matches("0x")).unwrap_or_else(|e| {
                                    eprintln!("MEX_MESH_PEERS entry '{entry}' has invalid pubkey hex: {e}");
                                    std::process::exit(1);
                                });
                                bytes.try_into().unwrap_or_else(|v: Vec<u8>| {
                                    eprintln!("MEX_MESH_PEERS entry '{entry}' pubkey must be exactly 32 bytes, got {}", v.len());
                                    std::process::exit(1);
                                })
                            }
                            None => [0u8; 32],
                        };
                        (common::NodeId(peer_id), peer_addr, pubkey)
                    })
                    .collect();

            let require_staked_reporters = std::env::var("MEX_MESH_REQUIRE_STAKE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            // Stage 4d: required, not defaulted, whenever chain gating is
            // on -- an unset/weak default here would silently reproduce
            // Stage 4b/4c's plain pass/fail gate (any two staked-above-
            // dust identities reach quorum) while looking like real
            // stake-weighting is in effect. Fail loud instead.
            let misconduct_stake_threshold: u64 = if require_staked_reporters {
                require_env("MEX_MESH_STAKE_QUORUM_THRESHOLD").parse().unwrap_or_else(|e| {
                    eprintln!("MEX_MESH_STAKE_QUORUM_THRESHOLD is not a valid u64: {e}");
                    std::process::exit(1);
                })
            } else {
                0
            };
            // Computed before `peers` is moved into MeshConfig below.
            let chain_peer_pubkeys: Vec<[u8; 32]> = peers.iter()
                .map(|(_, _, pk)| *pk)
                .filter(|pk| *pk != [0u8; 32])
                .collect();

            let mesh_node = protocol::MeshNode::new(protocol::MeshConfig {
                node_id: common::NodeId(mesh_node_id),
                region,
                listen_addr,
                peers,
                node_key: None,
                mesh_encryption_key: None,
                heartbeat_interval_ms: 1000.0,
                max_missed_heartbeats: 10,
                schedule: None,
                artificial_forward_delay_ms: None,
                require_staked_reporters,
                misconduct_stake_threshold,
            })
            .await
            .unwrap_or_else(|e| {
                eprintln!("failed to bind mesh listener on {listen_addr}: {e}");
                std::process::exit(1);
            });
            let sender = mesh_node.sender();
            let transport = mesh_node.transport();
            let peer_ids = mesh_node.peer_ids();
            let chain_status_tx = mesh_node.chain_status_sender();

            if require_staked_reporters {
                let chain_status_poll_secs: u64 = std::env::var("MEX_MESH_CHAIN_STATUS_POLL_SECS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(30);
                tokio::spawn(api::run_mesh_chain_status_loop(api::MeshChainStatusConfig {
                    rpc_url: rpc_url.clone(),
                    node_private_key: node_private_key.clone(),
                    factory_address: factory_address.clone(),
                    registry_address: registry_address.clone(),
                    peer_pubkeys: chain_peer_pubkeys,
                    poll_interval: Duration::from_secs(chain_status_poll_secs),
                    chain_status_tx: chain_status_tx.clone(),
                }));
            }

            tokio::spawn(mesh_node.run());
            tracing::info!(mesh_node_id, %listen_addr, require_staked_reporters, "gossip mesh enabled");
            Some(MeshHandle { node_id: common::NodeId(mesh_node_id), region, sender, transport, peer_ids, chain_status_tx })
        }
        Err(_) => None,
    };

    let (ws_broadcast, _) = tokio::sync::broadcast::channel(1024);
    let state = Arc::new(RwLock::new(AppState {
        node_id: common::NodeId(0),
        order_book,
        validator: validation::OrderValidator::new(10_000),
        ws_broadcast,
        reputation: reputation::ReputationEngine::new(),
        pending_commits: std::collections::HashMap::new(),
        confirmed_trade_hashes: std::collections::HashMap::new(),
        batcher: batcher::SettlementBatcher::new(),
        receipt_signing_key,
        order_log: orderlog::HashChainLog::new(),
        match_log: orderlog::HashChainLog::new(),
        mesh,
    }));

    let settlement_config = SettlementConfig {
        rpc_url: rpc_url.clone(),
        node_private_key,
        factory_address,
        registry_address,
        fee_recipient,
        poll_interval: Duration::from_secs(poll_secs),
    };
    tokio::spawn(api::run_settlement_loop(Arc::clone(&state), settlement_config));

    let router = api::app(state);
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    tracing::info!(%addr, %symbol, fee_base_gas_price, fee_batch_utilization, fee_volatility_index, %receipt_pubkey_hex, "MEX API server starting");
    axum::serve(listener, router).await.unwrap();
}
