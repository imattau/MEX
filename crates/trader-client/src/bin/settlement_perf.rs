// Measures the thing crates/benchmarks doesn't: real on-chain settlement
// performance, not in-memory matching-engine performance. The matching
// engine does ~195k ops/sec in memory (see crates/benchmarks); that number
// is irrelevant if settlement -- the part that actually touches a
// blockchain -- is the bottleneck. This measures the real, current,
// two-transaction settlement pipeline end to end against a live chain:
//
//   1. commitTrade   (trader-signed, locks funds)      -- TraderClient
//   2. prove_batch   (off-chain Groth16 proving)        -- prover
//   3. settleBatchWithFees (infra-signed, moves funds)  -- EthereumAdapter
//
// Reports wall-clock latency and gas cost for each stage, a combined
// per-trade total, and from the measured gas cost, a computed (not
// measured -- there is no real network access here) throughput ceiling for
// a couple of reference chains, so the gas number means something concrete.
//
// Usage:
//   cargo run -p trader-client --release --bin settlement_perf -- \
//     <rpc_url> <deployer_private_key> <factory_address> <registry_address> [iterations]

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
use prover::{Bn254Groth16Backend, ProverBackend, TradeBatch, MAX_BATCH_TRADES};
use std::time::{Duration, Instant};
use trader_client::TraderClient;

// Raw bindings for the two deployer-signed actions this script needs
// (registerNode, settleBatchWithFees), used instead of
// chain_ethereum::EthereumAdapter deliberately: EthereumAdapter::new()
// always constructs its own fresh provider internally, and this script
// needs the deployer to sign several different kinds of calls
// (registerNode, settleBatchWithFees, plain ETH transfers for funding) all
// through the SAME provider instance. Two independent alloy providers
// signing for the same account desync their local nonce caches from each
// other's sends -- this is exactly the bug fixed in chain_setup.rs earlier
// (see that file's deposit_native docs); constructing a second/third
// EthereumAdapter here for the same deployer key would silently
// reintroduce it.
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
        struct FeeConfig {
            address feeRecipient;
            uint8 tier;
        }
        function settleBatchWithFees(
            TradeEntry[] calldata trades,
            uint256[2] calldata a,
            uint256[2][2] calldata b,
            uint256[2] calldata c,
            uint256[] calldata input,
            FeeConfig calldata feeConfig
        ) external;
    }
}

const FUND_ETH: &str = "5";
const DEPOSIT_ETH: &str = "2";
const NODE_STAKE_ETH: &str = "10";

struct StageTiming {
    commit_latency: Duration,
    commit_gas: u64,
    prove_latency: Duration,
    settle_latency: Duration,
    settle_gas: u64,
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx]
}

fn u64_to_bytes32(val: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&val.to_be_bytes());
    out
}

async fn fund(provider: &impl Provider, to: Address, eth: &str) {
    let wei: u128 = eth.parse::<u128>().unwrap() * 1_000_000_000_000_000_000u128;
    let tx = TransactionRequest::default().with_to(to).with_value(U256::from(wei));
    provider.send_transaction(tx).await.unwrap().get_receipt().await.unwrap();
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rpc_url = args.get(1).expect("usage: settlement_perf <rpc_url> <deployer_key> <factory_address> <registry_address> [iterations]").clone();
    let deployer_key = args.get(2).expect("missing deployer_key").clone();
    let factory_address = args.get(3).expect("missing factory_address").clone();
    let registry_address = args.get(4).expect("missing registry_address").clone();
    let iterations: usize = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(10);

    println!("=== MEX Settlement Performance ===");
    println!("iterations: {iterations}\n");

    // Plain read-only provider, used only to look up gas_used on receipts --
    // TraderClient/EthereumAdapter deliberately don't expose that, they're
    // scoped to what a real caller needs (a trade hash / tx hash).
    let read_provider = ProviderBuilder::new().connect_http(rpc_url.parse().unwrap());

    let deployer_signer: PrivateKeySigner = deployer_key.trim_start_matches("0x").parse().unwrap();
    let deployer_address = deployer_signer.address();
    let deployer_wallet = EthereumWallet::from(deployer_signer);
    let deployer_provider = ProviderBuilder::new()
        .wallet(deployer_wallet)
        .connect_http(rpc_url.parse().unwrap());

    let registry_addr: Address = registry_address.parse().unwrap();
    let factory_addr: Address = factory_address.parse().unwrap();

    // Register one settlement node (reusing the deployer key as node
    // operator -- irrelevant to what's being measured). Signed through
    // deployer_provider, same as every other deployer action below.
    let node_pubkey: OnChainAccount = { let mut b = [0u8; 32]; b[0..4].copy_from_slice(b"PERF"); b };
    let registry_contract = INodeRegistryPerf::new(registry_addr, &deployer_provider);
    if !registry_contract.isActiveNode(FixedBytes::from(node_pubkey)).call().await.unwrap() {
        let stake_wei: u128 = NODE_STAKE_ETH.parse::<u128>().unwrap() * 1_000_000_000_000_000_000u128;
        registry_contract
            .registerNode(FixedBytes::from(node_pubkey), "perf-test".to_string())
            .value(U256::from(stake_wei))
            .send()
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap();
    }
    println!("settlement node registered: OK");

    // Maker (the trader who commits + gets settled) and taker (counterparty).
    let maker_signer = PrivateKeySigner::random();
    let taker_signer = PrivateKeySigner::random();
    fund(&deployer_provider, maker_signer.address(), FUND_ETH).await;
    fund(&deployer_provider, taker_signer.address(), FUND_ETH).await;

    let maker_pubkey: [u8; 32] = { let mut b = [0u8; 32]; b[0..5].copy_from_slice(b"MAKER"); b };
    let taker_pubkey: [u8; 32] = { let mut b = [0u8; 32]; b[0..5].copy_from_slice(b"TAKER"); b };

    let mut tokens = chain_ethereum::TokenRegistry::new();
    tokens.register([0u8; 20], "ETH-USD");
    let mut maker_client = TraderClient::new(
        &rpc_url,
        &hex::encode(maker_signer.to_bytes()),
        &factory_address,
        maker_pubkey,
        tokens.clone(),
        0,
    )
    .await
    .unwrap();
    let taker_client = TraderClient::new(
        &rpc_url,
        &hex::encode(taker_signer.to_bytes()),
        &factory_address,
        taker_pubkey,
        tokens,
        0,
    )
    .await
    .unwrap();

    maker_client.ensure_escrow().await.unwrap();
    taker_client.ensure_escrow().await.unwrap();
    let deposit_wei = U256::from(DEPOSIT_ETH.parse::<u128>().unwrap() * 1_000_000_000_000_000_000u128);
    maker_client.deposit_native(deposit_wei).await.unwrap();
    println!("two trader escrows created + funded: OK\n");

    let factory_contract = ISettlementFactoryPerf::new(factory_addr, &deployer_provider);

    let mut timings = Vec::with_capacity(iterations);

    println!("running {iterations} sequential full settlement cycles (commitTrade -> prove -> settleBatchWithFees)...");
    for i in 0..iterations {
        let deadline = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        let m = Match {
            maker_order_id: u64_to_bytes32(i as u64 * 2),
            taker_order_id: u64_to_bytes32(i as u64 * 2 + 1),
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
        };

        let t0 = Instant::now();
        let trade_hash_hex_hash = maker_client.commit_trade(&m).await.unwrap();
        let commit_latency = t0.elapsed();

        // commit_trade only returns the trade hash, not the tx hash (by
        // design -- see TraderClient's docs), so there's no direct receipt
        // to query. This relies on Hardhat's default automine putting each
        // transaction in its own block immediately: since calls here run
        // strictly sequentially with nothing else submitting transactions
        // concurrently, "gas used by the latest block" and "gas used by
        // the commitTrade call that just landed" are the same number on
        // this specific setup. Not a general-purpose technique.
        let commit_gas = latest_block_gas(&read_provider).await;

        let batch = TradeBatch {
            trades: vec![m.clone()],
            maker_balances: vec![1_000_000],
            taker_balances: vec![1_000_000],
            pre_state_root: [0u8; 32],
            post_state_root: u64_to_bytes32(m.price * m.amount),
        };
        let backend = Bn254Groth16Backend;
        let t1 = Instant::now();
        let proof = backend.prove_batch(&batch).unwrap();
        let prove_latency = t1.elapsed();

        let entry = ISettlementFactoryPerf::TradeEntry {
            trader: maker_signer.address(),
            counterparty: taker_signer.address(),
            token: Address::ZERO,
            amount: U256::from(m.price * m.amount),
            fee: U256::from((m.price * m.amount) * m.fee_basis_points as u64 / 10_000),
            deadline: U256::from(deadline),
            tradeHash: FixedBytes::from(trade_hash_hex_hash),
            assignedNode: FixedBytes::from(node_pubkey),
        };
        let fee_config = ISettlementFactoryPerf::FeeConfig {
            feeRecipient: deployer_address,
            tier: 0,
        };
        let calldata = prover::decode_proof_calldata(&proof).unwrap();
        let a = [U256::from_be_bytes(calldata.a[0]), U256::from_be_bytes(calldata.a[1])];
        let b = [
            [U256::from_be_bytes(calldata.b[0][0]), U256::from_be_bytes(calldata.b[0][1])],
            [U256::from_be_bytes(calldata.b[1][0]), U256::from_be_bytes(calldata.b[1][1])],
        ];
        let c = [U256::from_be_bytes(calldata.c[0]), U256::from_be_bytes(calldata.c[1])];
        let input: Vec<U256> = calldata.public_inputs.iter().map(|bytes| U256::from_be_bytes(*bytes)).collect();

        let t2 = Instant::now();
        let settle_receipt = factory_contract
            .settleBatchWithFees(vec![entry], a, b, c, input, fee_config)
            .send()
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap();
        let settle_latency = t2.elapsed();
        let settle_gas = settle_receipt.gas_used;

        timings.push(StageTiming {
            commit_latency,
            commit_gas,
            prove_latency,
            settle_latency,
            settle_gas,
        });

        print!(".");
        use std::io::Write;
        std::io::stdout().flush().ok();
    }
    println!(" done\n");

    let baseline_settle_gas = timings.iter().map(|t| t.settle_gas).sum::<u64>() / timings.len() as u64;
    let baseline_commit_gas = timings.iter().map(|t| t.commit_gas).sum::<u64>() / timings.len() as u64;
    report(&timings);

    println!("\nrunning a batched settlement: {MAX_BATCH_TRADES} trades, one proof, one settleBatchWithFees call...");
    run_batched_settlement(
        &mut maker_client,
        &factory_contract,
        maker_pubkey,
        taker_pubkey,
        maker_signer.address(),
        taker_signer.address(),
        node_pubkey,
        baseline_commit_gas,
        baseline_settle_gas,
    )
    .await;

    println!("\nrunning a concurrent burst: 10 independent commitTrade calls fired in parallel...");
    concurrent_burst(&rpc_url, &factory_address, &deployer_provider, node_pubkey).await;
}

// The actual payoff being measured: MAX_BATCH_TRADES trades between the
// same maker/taker pair, each individually commitTrade'd (that part is
// inherently per-trade -- commitTrade is trader-signed, there is no way
// to batch a different trader's signature into someone else's
// transaction), but proven under ONE Groth16 proof and settled in ONE
// settleBatchWithFees call instead of MAX_BATCH_TRADES separate ones.
#[allow(clippy::too_many_arguments)]
async fn run_batched_settlement(
    maker_client: &mut TraderClient,
    factory_contract: &ISettlementFactoryPerf::ISettlementFactoryPerfInstance<&impl Provider>,
    maker_pubkey: [u8; 32],
    taker_pubkey: [u8; 32],
    maker_address: Address,
    taker_address: Address,
    node_pubkey: OnChainAccount,
    baseline_commit_gas: u64,
    baseline_settle_gas: u64,
) {
    let mut matches = Vec::with_capacity(MAX_BATCH_TRADES);
    let mut commit_total = Duration::ZERO;

    for i in 0..MAX_BATCH_TRADES {
        let deadline = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600;
        let m = Match {
            maker_order_id: u64_to_bytes32(20_000 + i as u64 * 2),
            taker_order_id: u64_to_bytes32(20_000 + i as u64 * 2 + 1),
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
        };
        let t0 = Instant::now();
        let trade_hash = maker_client.commit_trade(&m).await.unwrap();
        commit_total += t0.elapsed();

        matches.push((m, trade_hash));
    }

    let trades: Vec<Match> = matches.iter().map(|(m, _)| m.clone()).collect();
    let total_value: u64 = trades.iter().map(|t| t.price * t.amount).sum();
    let batch = TradeBatch {
        maker_balances: vec![1_000_000; trades.len()],
        taker_balances: vec![1_000_000; trades.len()],
        trades: trades.clone(),
        pre_state_root: [0u8; 32],
        post_state_root: u64_to_bytes32(total_value),
    };

    let backend = Bn254Groth16Backend;
    let t1 = Instant::now();
    let proof = backend.prove_batch(&batch).unwrap();
    let prove_latency = t1.elapsed();

    let entries: Vec<ISettlementFactoryPerf::TradeEntry> = matches
        .iter()
        .map(|(m, trade_hash)| ISettlementFactoryPerf::TradeEntry {
            trader: maker_address,
            counterparty: taker_address,
            token: Address::ZERO,
            amount: U256::from(m.price * m.amount),
            fee: U256::from((m.price * m.amount) * m.fee_basis_points as u64 / 10_000),
            deadline: U256::from(m.settlement_deadline),
            tradeHash: FixedBytes::from(*trade_hash),
            assignedNode: FixedBytes::from(node_pubkey),
        })
        .collect();
    let fee_config = ISettlementFactoryPerf::FeeConfig { feeRecipient: maker_address, tier: 0 };
    let calldata = prover::decode_proof_calldata(&proof).unwrap();
    let a = [U256::from_be_bytes(calldata.a[0]), U256::from_be_bytes(calldata.a[1])];
    let b = [
        [U256::from_be_bytes(calldata.b[0][0]), U256::from_be_bytes(calldata.b[0][1])],
        [U256::from_be_bytes(calldata.b[1][0]), U256::from_be_bytes(calldata.b[1][1])],
    ];
    let c = [U256::from_be_bytes(calldata.c[0]), U256::from_be_bytes(calldata.c[1])];
    let input: Vec<U256> = calldata.public_inputs.iter().map(|bytes| U256::from_be_bytes(*bytes)).collect();

    let t2 = Instant::now();
    let receipt = factory_contract
        .settleBatchWithFees(entries, a, b, c, input, fee_config)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    let settle_latency = t2.elapsed();
    let settle_gas = receipt.gas_used;

    println!("commitTrade x{MAX_BATCH_TRADES} total wall clock: {commit_total:?} (still one tx per trade -- inherent, trader-signed)");
    println!("prove_batch (one proof for all {MAX_BATCH_TRADES} trades): {prove_latency:?}");
    println!("settleBatchWithFees (one call, {MAX_BATCH_TRADES}-entry array): {settle_latency:?}, gas: {settle_gas}");

    let batched_settle_gas_per_trade = settle_gas / MAX_BATCH_TRADES as u64;
    let batched_total_gas_per_trade = baseline_commit_gas + batched_settle_gas_per_trade;
    let baseline_total_gas_per_trade = baseline_commit_gas + baseline_settle_gas;

    println!("\n=== Per-trade gas: single-trade-per-proof baseline vs {MAX_BATCH_TRADES}-trade batch ===");
    println!("settleBatchWithFees gas/trade: baseline ~{baseline_settle_gas}  ->  batched ~{batched_settle_gas_per_trade}  ({:.1}x reduction)", baseline_settle_gas as f64 / batched_settle_gas_per_trade as f64);
    println!("TOTAL gas/trade (commit unavoidable, settle amortized): baseline ~{baseline_total_gas_per_trade}  ->  batched ~{batched_total_gas_per_trade}  ({:.1}x reduction)", baseline_total_gas_per_trade as f64 / batched_total_gas_per_trade as f64);

    println!("\n=== Updated computed throughput ceiling using batched gas/trade ===");
    print_ceiling("Ethereum L1", 30_000_000, 12.0, batched_total_gas_per_trade);
    print_ceiling("A representative L2 (e.g. Base)", 200_000_000, 2.0, batched_total_gas_per_trade);
}

async fn latest_block_gas(provider: &impl Provider) -> u64 {
    let block = provider
        .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
        .await
        .unwrap()
        .unwrap();
    block.header.gas_used
}

fn report(timings: &[StageTiming]) {
    let mut commit_lat: Vec<Duration> = timings.iter().map(|t| t.commit_latency).collect();
    let mut prove_lat: Vec<Duration> = timings.iter().map(|t| t.prove_latency).collect();
    let mut settle_lat: Vec<Duration> = timings.iter().map(|t| t.settle_latency).collect();
    let mut total_lat: Vec<Duration> = timings
        .iter()
        .map(|t| t.commit_latency + t.prove_latency + t.settle_latency)
        .collect();
    commit_lat.sort();
    prove_lat.sort();
    settle_lat.sort();
    total_lat.sort();

    let avg_commit_gas = timings.iter().map(|t| t.commit_gas).sum::<u64>() / timings.len() as u64;
    let avg_settle_gas = timings.iter().map(|t| t.settle_gas).sum::<u64>() / timings.len() as u64;
    let total_gas_per_trade = avg_commit_gas + avg_settle_gas;

    println!("=== Per-stage latency (n={}) ===", timings.len());
    println!(
        "commitTrade:            p50 {:?}  p90 {:?}  p99 {:?}",
        percentile(&commit_lat, 0.5), percentile(&commit_lat, 0.9), percentile(&commit_lat, 0.99)
    );
    println!(
        "prove_batch (off-chain): p50 {:?}  p90 {:?}  p99 {:?}",
        percentile(&prove_lat, 0.5), percentile(&prove_lat, 0.9), percentile(&prove_lat, 0.99)
    );
    println!(
        "settleBatchWithFees:    p50 {:?}  p90 {:?}  p99 {:?}",
        percentile(&settle_lat, 0.5), percentile(&settle_lat, 0.9), percentile(&settle_lat, 0.99)
    );
    println!(
        "TOTAL end-to-end:        p50 {:?}  p90 {:?}  p99 {:?}",
        percentile(&total_lat, 0.5), percentile(&total_lat, 0.9), percentile(&total_lat, 0.99)
    );

    println!("\n=== Gas cost per trade, single-trade-per-proof baseline (this section) ===");
    println!("commitTrade gas:         ~{avg_commit_gas}");
    println!("settleBatchWithFees gas: ~{avg_settle_gas}");
    println!("TOTAL gas per trade:     ~{total_gas_per_trade}");
    println!("(see the batched settlement section below for the amortized comparison)\n");

    println!("=== Computed throughput ceiling (not measured -- extrapolated from the gas ===");
    println!("    number above against real network block gas limits/times; local devnet");
    println!("    has neither a real gas limit nor a real block time) ===");
    print_ceiling("Ethereum L1", 30_000_000, 12.0, total_gas_per_trade);
    print_ceiling("A representative L2 (e.g. Base)", 200_000_000, 2.0, total_gas_per_trade);
}

fn print_ceiling(name: &str, block_gas_limit: u64, block_time_secs: f64, gas_per_trade: u64) {
    let trades_per_block = block_gas_limit / gas_per_trade;
    let trades_per_sec = trades_per_block as f64 / block_time_secs;
    println!(
        "  {name}: {trades_per_block} trades/block @ {block_time_secs}s blocks => ~{trades_per_sec:.1} trades/sec ceiling"
    );
}

async fn concurrent_burst(
    rpc_url: &str,
    factory_address: &str,
    deployer_provider: &impl Provider,
    node_pubkey: OnChainAccount,
) {
    const N: usize = 10;
    let mut handles = Vec::new();

    for i in 0..N {
        let rpc_url = rpc_url.to_string();
        let factory_address = factory_address.to_string();

        let maker_signer = PrivateKeySigner::random();
        let taker_signer = PrivateKeySigner::random();
        fund(deployer_provider, maker_signer.address(), FUND_ETH).await;
        fund(deployer_provider, taker_signer.address(), FUND_ETH).await;

        let maker_pubkey: [u8; 32] = { let mut b = [0u8; 32]; b[0..4].copy_from_slice(b"BURM"); b[4] = i as u8; b };
        let taker_pubkey: [u8; 32] = { let mut b = [0u8; 32]; b[0..4].copy_from_slice(b"BURT"); b[4] = i as u8; b };

        let handle = tokio::spawn(async move {
            let mut tokens = chain_ethereum::TokenRegistry::new();
    tokens.register([0u8; 20], "ETH-USD");
            let mut maker_client = TraderClient::new(
                &rpc_url,
                &hex::encode(maker_signer.to_bytes()),
                &factory_address,
                maker_pubkey,
                tokens.clone(),
                0,
            )
            .await
            .unwrap();
            let taker_client = TraderClient::new(&rpc_url, &hex::encode(taker_signer.to_bytes()), &factory_address, taker_pubkey, tokens, 0)
                .await
                .unwrap();
            maker_client.ensure_escrow().await.unwrap();
            taker_client.ensure_escrow().await.unwrap();
            maker_client
                .deposit_native(U256::from(DEPOSIT_ETH.parse::<u128>().unwrap() * 1_000_000_000_000_000_000u128))
                .await
                .unwrap();

            let deadline = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600;
            let m = Match {
                maker_order_id: u64_to_bytes32(9000 + i as u64),
                taker_order_id: u64_to_bytes32(9500 + i as u64),
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
            };

            let t0 = Instant::now();
            let result = maker_client.commit_trade(&m).await;
            (result.is_ok(), t0.elapsed())
        });
        handles.push(handle);
    }

    let burst_start = Instant::now();
    let mut results = Vec::new();
    for h in handles {
        results.push(h.await.unwrap());
    }
    let burst_wall = burst_start.elapsed();

    let ok_count = results.iter().filter(|(ok, _)| *ok).count();
    let mut lats: Vec<Duration> = results.iter().map(|(_, d)| *d).collect();
    lats.sort();

    println!("{ok_count}/{N} concurrent commitTrade calls succeeded (nonce handling under real parallelism)");
    println!("wall clock for all {N} in parallel: {burst_wall:?}");
    println!(
        "per-call latency under contention: p50 {:?}  max {:?}",
        percentile(&lats, 0.5),
        lats.last().unwrap()
    );
}
