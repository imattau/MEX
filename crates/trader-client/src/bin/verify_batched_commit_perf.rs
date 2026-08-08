// Measures the real gas savings from batching commitTrade via EIP-712
// signatures (commitTradeBatch) instead of each trader submitting their
// own commitTrade transaction -- the concrete answer to "how much would
// batching the commit side actually save," not just the direction.
//
// Runs N independent trader pairs (different maker/taker each) through
// both paths on the SAME devnet in the SAME run, so the comparison is
// apples-to-apples: N individual commitTrade transactions, then N fresh
// trades committed together in one commitTradeBatch call.
//
// Usage:
//   cargo run -p trader-client --release --bin verify_batched_commit_perf -- \
//     <rpc_url> <deployer_private_key> <factory_address> <registry_address> [n]

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, FixedBytes, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::network::TransactionBuilder;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use chain::OnChainAccount;
use common::SettlementPreference;
use engine::Match;
use trader_client::TraderClient;

sol! {
    #[sol(rpc)]
    interface INodeRegistryPerf {
        function registerNode(bytes32 nodePubkey, string calldata geoRegion) external payable;
        function isActiveNode(bytes32 nodePubkey) external view returns (bool);
    }

    #[sol(rpc)]
    interface ISettlementFactoryPerf {
        struct TradeEntry {
            address trader;
            address counterparty;
            address token;
            uint256 amount;
            uint256 fee;
            uint256 deadline;
            bytes32 tradeHash;
            bytes32 assignedNode;
        }
        function commitTrade(TradeEntry calldata trade) external;
        function commitTradeBatch(TradeEntry[] calldata trades, bytes[] calldata signatures) external;
    }
}

async fn fund(provider: &impl Provider, to: Address, eth: &str) {
    let wei: u128 = eth.parse::<u128>().unwrap() * 1_000_000_000_000_000_000u128;
    let tx = TransactionRequest::default().with_to(to).with_value(U256::from(wei));
    provider.send_transaction(tx).await.unwrap().get_receipt().await.unwrap();
}

fn u64_to_bytes32(val: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&val.to_be_bytes());
    out
}

struct TraderPair {
    maker_client: TraderClient,
    maker_pubkey: [u8; 32],
    taker_pubkey: [u8; 32],
}

async fn setup_pair(
    rpc_url: &str,
    deployer_provider: &impl Provider,
    factory_address: &str,
    seed: u8,
) -> TraderPair {
    let maker_eth = PrivateKeySigner::random();
    let taker_eth = PrivateKeySigner::random();
    fund(deployer_provider, maker_eth.address(), "5").await;
    fund(deployer_provider, taker_eth.address(), "5").await;

    let maker_pubkey: [u8; 32] = { let mut b = [0u8; 32]; b[0] = seed; b[1..5].copy_from_slice(b"MAKR"); b };
    let taker_pubkey: [u8; 32] = { let mut b = [0u8; 32]; b[0] = seed; b[1..5].copy_from_slice(b"TAKR"); b };

    let mut tokens = chain_ethereum::TokenRegistry::new();
    tokens.register([0u8; 20], "ETH-USD");
    let maker_client = TraderClient::new(rpc_url, &hex::encode(maker_eth.to_bytes()), factory_address, maker_pubkey, tokens.clone(), 0).await.unwrap();
    let taker_client = TraderClient::new(rpc_url, &hex::encode(taker_eth.to_bytes()), factory_address, taker_pubkey, tokens, 0).await.unwrap();
    maker_client.ensure_escrow().await.unwrap();
    taker_client.ensure_escrow().await.unwrap();
    maker_client.deposit_native(U256::from(2_000_000_000_000_000_000u128)).await.unwrap();

    TraderPair { maker_client, maker_pubkey, taker_pubkey }
}

fn build_match(maker_pubkey: [u8; 32], taker_pubkey: [u8; 32], node_pubkey: OnChainAccount, seed: u64, deadline: u64) -> Match {
    Match {
        maker_order_id: u64_to_bytes32(seed * 2),
        taker_order_id: u64_to_bytes32(seed * 2 + 1),
        maker_trader: maker_pubkey,
        taker_trader: taker_pubkey,
        price: 3000,
        amount: 1,
        timestamp_us: 0,
        settlement_tier: SettlementPreference::Standard,
        fee_basis_points: 5,
        seller: maker_pubkey,
        fee_payer: maker_pubkey,
        settlement_deadline: deadline,
        symbol: "ETH-USD".to_string(),
        assigned_node: node_pubkey,
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rpc_url = args.get(1).expect("usage: verify_batched_commit_perf <rpc_url> <deployer_key> <factory_address> <registry_address> [n]").clone();
    let deployer_key = args.get(2).expect("missing deployer_key").clone();
    let factory_address = args.get(3).expect("missing factory_address").clone();
    let registry_address = args.get(4).expect("missing registry_address").clone();
    let n: usize = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(8);

    let factory_addr: Address = factory_address.parse().unwrap();
    let registry_addr: Address = registry_address.parse().unwrap();

    let deployer_signer: PrivateKeySigner = deployer_key.trim_start_matches("0x").parse().unwrap();
    let deployer_wallet = EthereumWallet::from(deployer_signer);
    let deployer_provider = ProviderBuilder::new().wallet(deployer_wallet).connect_http(rpc_url.parse().unwrap());
    let read_provider = ProviderBuilder::new().connect_http(rpc_url.parse().unwrap());

    let node_pubkey: OnChainAccount = { let mut b = [0u8; 32]; b[0..4].copy_from_slice(b"BCOM"); b };
    let registry_contract = INodeRegistryPerf::new(registry_addr, &deployer_provider);
    if !registry_contract.isActiveNode(FixedBytes::from(node_pubkey)).call().await.unwrap() {
        registry_contract
            .registerNode(FixedBytes::from(node_pubkey), "batched-commit-test".to_string())
            .value(U256::from(10_000_000_000_000_000_000u128))
            .send().await.unwrap().get_receipt().await.unwrap();
    }
    println!("settlement node registered: OK\n");

    let deadline = read_provider.get_block_by_number(alloy::eips::BlockNumberOrTag::Latest).await.unwrap().unwrap().header.timestamp + 3600;

    // === Baseline: N individual commitTrade transactions ===
    println!("=== Baseline: {n} individual commitTrade transactions ===");
    let factory_as_deployer = ISettlementFactoryPerf::new(factory_addr, &deployer_provider);

    let mut baseline_gas_total = 0u64;
    for i in 0..n {
        let mut pair = setup_pair(&rpc_url, &deployer_provider, &factory_address, i as u8).await;
        let m = build_match(pair.maker_pubkey, pair.taker_pubkey, node_pubkey, i as u64, deadline);
        pair.maker_client.commit_trade(&m).await.expect("baseline commitTrade failed");
        let block = read_provider.get_block_by_number(alloy::eips::BlockNumberOrTag::Latest).await.unwrap().unwrap();
        baseline_gas_total += block.header.gas_used;
        print!(".");
        use std::io::Write;
        std::io::stdout().flush().ok();
    }
    println!(" done");
    let baseline_gas_per_trade = baseline_gas_total / n as u64;
    println!("baseline: {baseline_gas_total} total gas / {n} trades = {baseline_gas_per_trade} gas/trade\n");

    // === Batched: N traders sign off-chain, one commitTradeBatch call ===
    println!("=== Batched: {n} traders sign off-chain (zero gas each), one commitTradeBatch call ===");
    let mut entries = Vec::with_capacity(n);
    let mut signatures = Vec::with_capacity(n);
    for i in 0..n {
        let mut pair = setup_pair(&rpc_url, &deployer_provider, &factory_address, (100 + i) as u8).await;
        let m = build_match(pair.maker_pubkey, pair.taker_pubkey, node_pubkey, (1000 + i) as u64, deadline);
        let (entry, sig) = pair.maker_client.sign_commit_authorization(&m).await.expect("sign_commit_authorization failed");
        entries.push(ISettlementFactoryPerf::TradeEntry {
            trader: entry.trader,
            counterparty: entry.counterparty,
            token: entry.token,
            amount: entry.amount,
            fee: entry.fee,
            deadline: entry.deadline,
            tradeHash: entry.tradeHash,
            assignedNode: entry.assignedNode,
        });
        signatures.push(sig.into());
        print!(".");
        use std::io::Write;
        std::io::stdout().flush().ok();
    }
    println!(" done, all signed off-chain with zero gas cost to any trader");

    let receipt = factory_as_deployer
        .commitTradeBatch(entries, signatures)
        .send()
        .await
        .expect("commitTradeBatch send failed")
        .get_receipt()
        .await
        .expect("commitTradeBatch receipt failed");
    assert!(receipt.status(), "commitTradeBatch must succeed");
    let batched_gas_total = receipt.gas_used;
    let batched_gas_per_trade = batched_gas_total / n as u64;
    println!("batched: {batched_gas_total} total gas / {n} trades = {batched_gas_per_trade} gas/trade\n");

    println!("=== Result ===");
    println!("commitTrade (individual):    ~{baseline_gas_per_trade} gas/trade");
    println!("commitTradeBatch (batched):  ~{batched_gas_per_trade} gas/trade");
    let reduction = baseline_gas_per_trade as f64 / batched_gas_per_trade as f64;
    println!("reduction: {reduction:.2}x");
    println!("\nBATCHED COMMIT PERF TEST PASSED: {n} trades committed via one transaction with real signature verification.");
}
