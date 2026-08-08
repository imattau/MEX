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

use api::server::AppState;
use api::settlement::SettlementConfig;
use common::FeeCalculator;
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

    let mut order_book = OrderBook::new(symbol.clone());
    order_book.set_active_nodes(vec![node_pubkey]);
    order_book.set_fee_calculator(fee_calculator);

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

    tracing::info!(%addr, %symbol, fee_base_gas_price, fee_batch_utilization, fee_volatility_index, "MEX API server starting");
    axum::serve(listener, router).await.unwrap();
}
