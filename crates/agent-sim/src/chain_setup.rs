use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use chain::{ChainAdapter, OnChainAccount};
use chain_ethereum::{EthereumAdapter, TokenRegistry};
use std::collections::HashMap;
use trader_client::TraderClient;

// Devnet-only amounts. Real values would come from real config; these exist
// purely so agent wallets/escrows have enough to actually commit trades
// during a simulation run without tuning per-scenario.
const AGENT_FUNDING_ETH: &str = "20"; // sent to each agent's own EOA (gas + deposit)
const AGENT_DEPOSIT_ETH: &str = "10"; // deposited into each agent's TraderEscrow
const NODE_STAKE_ETH: &str = "10"; // exactly NodeRegistry.MIN_STAKE

pub struct OnChainConfig {
    pub rpc_url: String,
    pub deployer_private_key: String,
    pub factory_address: String,
    pub registry_address: String,
}

impl OnChainConfig {
    // Reads required on-chain config from environment variables. Returns
    // Err (rather than silently falling back to an in-memory-only mode) if
    // anything is missing -- agent-sim always requires a live devnet.
    pub fn from_env() -> Result<Self, String> {
        let get = |name: &str| {
            std::env::var(name).map_err(|_| format!("required environment variable {name} not set"))
        };
        Ok(Self {
            rpc_url: get("AGENT_SIM_RPC_URL")?,
            deployer_private_key: get("AGENT_SIM_DEPLOYER_KEY")?,
            factory_address: get("AGENT_SIM_FACTORY_ADDRESS")?,
            registry_address: get("AGENT_SIM_REGISTRY_ADDRESS")?,
        })
    }
}

pub struct OnChainAgent {
    pub client: TraderClient,
    pub offchain_pubkey: [u8; 32],
}

pub struct OnChainSetup {
    pub agents: HashMap<String, OnChainAgent>,
    pub assigned_node: OnChainAccount,
}

// Registers one settlement node (used as `assigned_node` for every match in
// this simulation -- a real deployment would have many independently
// operated nodes; this simulation only needs one to exercise the real
// commitTrade/claimSlash path) and bootstraps a real, funded on-chain
// wallet + escrow for each already-registered simulated agent:
//   1. Generate a fresh ephemeral keypair per agent (devnet-only; nothing
//      here is meant to be reused outside a single simulation run).
//   2. Fund it from the deployer account (plain ETH transfer).
//   3. Bind its escrow to the SAME off-chain pubkey the simulation already
//      derives from the agent's ID (AgentTracker::get_trader_bytes) --
//      this is what makes engine::Match.fee_payer/maker_trader/taker_trader
//      resolvable back to a real TraderClient later.
//   4. Deposit devnet ETH into the escrow so commitTrade's lock() has
//      something to lock.
pub async fn bootstrap(
    config: &OnChainConfig,
    agent_offchain_pubkeys: &HashMap<String, [u8; 32]>,
) -> Result<OnChainSetup, String> {
    let deployer_signer: PrivateKeySigner = config
        .deployer_private_key
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .parse()
        .map_err(|e| format!("invalid deployer private key: {e}"))?;
    let deployer_wallet = EthereumWallet::from(deployer_signer.clone());
    let url = config
        .rpc_url
        .parse()
        .map_err(|e| format!("invalid RPC URL: {e}"))?;
    let deployer_provider = ProviderBuilder::new()
        .wallet(deployer_wallet)
        .connect_http(url)
        .erased();

    let assigned_node = register_settlement_node(config).await?;

    let mut tokens = TokenRegistry::new();
    tokens.register([0u8; 20], "ETH-USD");

    let mut agents = HashMap::new();
    for (agent_id, &offchain_pubkey) in agent_offchain_pubkeys {
        let agent_signer = PrivateKeySigner::random();
        let agent_address = agent_signer.address();

        fund_address(&deployer_provider, agent_address, AGENT_FUNDING_ETH).await?;

        let agent_private_key = hex::encode(agent_signer.to_bytes());
        let client = TraderClient::new(
            &config.rpc_url,
            &agent_private_key,
            &config.factory_address,
            offchain_pubkey,
            tokens.clone(),
            0,
        )
        .await?;

        client.ensure_escrow().await?;
        deposit_native(
            &config.rpc_url,
            &agent_private_key,
            &config.factory_address,
            AGENT_DEPOSIT_ETH,
        )
        .await?;

        tracing::info!(
            agent_id,
            address = %agent_address,
            "bootstrapped on-chain wallet + funded escrow"
        );

        agents.insert(
            agent_id.clone(),
            OnChainAgent {
                client,
                offchain_pubkey,
            },
        );
    }

    Ok(OnChainSetup {
        agents,
        assigned_node,
    })
}

async fn register_settlement_node(config: &OnChainConfig) -> Result<OnChainAccount, String> {
    let node_pubkey: OnChainAccount = {
        let mut b = [0u8; 32];
        b[0] = b'S';
        b[1] = b'I';
        b[2] = b'M';
        b
    };

    let adapter = EthereumAdapter::new(
        &config.rpc_url,
        &config.deployer_private_key,
        &config.factory_address,
        &config.registry_address,
    )
    .await?;

    if !adapter.is_node_active(node_pubkey).await? {
        let stake = u64::try_from(parse_eth(NODE_STAKE_ETH))
            .map_err(|_| "NODE_STAKE_ETH exceeds u64 range".to_string())?;
        adapter
            .register_node(node_pubkey, "sim-devnet", stake)
            .await?;
    }

    Ok(node_pubkey)
}

async fn fund_address<P: Provider>(
    provider: &P,
    to: Address,
    eth_amount: &str,
) -> Result<(), String> {
    let tx = TransactionRequest::default()
        .with_to(to)
        .with_value(U256::from(parse_eth(eth_amount)));
    provider
        .send_transaction(tx)
        .await
        .map_err(|e| format!("funding transfer to {to} failed: {e}"))?
        .get_receipt()
        .await
        .map_err(|e| format!("funding transfer receipt failed: {e}"))?;
    Ok(())
}

async fn deposit_native(
    rpc_url: &str,
    private_key: &str,
    factory_address: &str,
    eth_amount: &str,
) -> Result<(), String> {
    // Depositing is a TraderEscrow action, not exposed on TraderClient
    // (which only covers commitTrade/claimSlash -- see its docs). Do it
    // directly here with the same signer, mirroring how the live tests
    // built while developing trader-client funded escrows.
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface ISettlementFactoryLookup {
            function getEscrow(address trader) external view returns (address);
        }
        #[sol(rpc)]
        interface ITraderEscrowDeposit {
            function deposit(address token, uint256 amount) external payable;
        }
    }

    let signer: PrivateKeySigner = private_key
        .parse()
        .map_err(|e| format!("invalid private key: {e}"))?;
    let own_address = signer.address();
    let wallet = EthereumWallet::from(signer);
    let url = rpc_url.parse().map_err(|e| format!("invalid RPC URL: {e}"))?;
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(url).erased();

    let factory: Address = factory_address
        .parse()
        .map_err(|e| format!("invalid factory address: {e}"))?;
    let factory_contract = ISettlementFactoryLookup::new(factory, &provider);
    let escrow_address = factory_contract
        .getEscrow(own_address)
        .call()
        .await
        .map_err(|e| format!("getEscrow failed: {e}"))?;

    let amount = U256::from(parse_eth(eth_amount));
    let escrow = ITraderEscrowDeposit::new(escrow_address, &provider);
    escrow
        .deposit(Address::ZERO, amount)
        .value(amount)
        .send()
        .await
        .map_err(|e| format!("deposit send failed: {e}"))?
        .get_receipt()
        .await
        .map_err(|e| format!("deposit receipt failed: {e}"))?;
    Ok(())
}

fn parse_eth(amount: &str) -> u128 {
    let whole: u128 = amount.parse().expect("hardcoded ETH amount constant must parse");
    whole * 1_000_000_000_000_000_000u128
}
