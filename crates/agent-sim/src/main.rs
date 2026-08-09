use agent_sim::chain_setup::OnChainConfig;
use agent_sim::mesh_state::MultiNodeSimulation;
use agent_sim::server::{create_router, SharedState};
use agent_sim::types::AgentConfig;
use common::Region;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let port: u16 = args
        .iter()
        .position(|a| a == "--port")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(9876);

    let symbol = args
        .iter()
        .position(|a| a == "--symbol")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "ETH-USD".to_string());

    let step_duration_ms: f64 = args
        .iter()
        .position(|a| a == "--step-duration")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(60000.0);

    let noise_amplitude: f64 = args
        .iter()
        .position(|a| a == "--noise")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.005);

    let use_local = args.contains(&"--local".to_string());

    let node_config = vec![
        (Region::UsEast1, 3),
        (Region::EuWest1, 2),
        (Region::ApSoutheast1, 5),
    ];

    let mut sim = MultiNodeSimulation::new(symbol.clone(), &node_config, use_local);

    sim.register_agent(AgentConfig {
        id: "market_maker_1".to_string(),
        name: "Athena MM".to_string(),
        persona: "market_maker".to_string(),
        initial_capital: 1_000_000,
    });

    sim.register_agent(AgentConfig {
        id: "market_maker_2".to_string(),
        name: "Hermes MM".to_string(),
        persona: "market_maker".to_string(),
        initial_capital: 1_000_000,
    });

    sim.register_agent(AgentConfig {
        id: "momentum_1".to_string(),
        name: "Zeus Momentum".to_string(),
        persona: "momentum_trader".to_string(),
        initial_capital: 500_000,
    });

    sim.register_agent(AgentConfig {
        id: "momentum_2".to_string(),
        name: "Ares Momentum".to_string(),
        persona: "momentum_trader".to_string(),
        initial_capital: 500_000,
    });

    sim.register_agent(AgentConfig {
        id: "mean_reversion_1".to_string(),
        name: "Hades Reversion".to_string(),
        persona: "mean_reversion".to_string(),
        initial_capital: 500_000,
    });

    sim.register_agent(AgentConfig {
        id: "mean_reversion_2".to_string(),
        name: "Demeter Reversion".to_string(),
        persona: "mean_reversion".to_string(),
        initial_capital: 500_000,
    });

    // agent-sim always requires a live devnet: matches are gated on a real
    // on-chain commitTrade (see MultiNodeSimulation::propagate_and_match),
    // so there is no meaningful degraded/offline mode to fall back to.
    // Fail fast here rather than starting a server that would silently
    // reject every trade later.
    let onchain_config = OnChainConfig::from_env().unwrap_or_else(|e| {
        eprintln!("agent-sim requires a live devnet and refuses to start without it: {e}");
        eprintln!(
            "Set AGENT_SIM_RPC_URL, AGENT_SIM_DEPLOYER_KEY, AGENT_SIM_FACTORY_ADDRESS, \
             AGENT_SIM_REGISTRY_ADDRESS (e.g. from `npx hardhat run scripts/deploy.js`)."
        );
        std::process::exit(1);
    });

    tracing::info!("Bootstrapping on-chain wallets/escrows for all registered agents...");
    if let Err(e) = sim.bootstrap_onchain(&onchain_config).await {
        eprintln!("On-chain bootstrap failed, refusing to start: {e}");
        std::process::exit(1);
    }
    tracing::info!(
        "On-chain bootstrap complete -- {} agents ready",
        sim.onchain_agents.len()
    );

    let shared = Arc::new(Mutex::new(SharedState {
        sim,
        step_duration_ms,
        noise_amplitude,
    }));

    let router = create_router(shared);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    tracing::info!("Agent mesh simulation starting on {}", addr);
    tracing::info!(
        "Nodes: 10 (3 US-East, 2 EU-West, 5 AP-Southeast) | Symbol: {} | Step: {}ms | Noise: {:.3}% | Profile: {}",
        symbol, step_duration_ms, noise_amplitude * 100.0,
        if use_local { "local" } else { "global" }
    );

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, router).await.unwrap();
}
