// Live regression check for a real gap: NodeRegistry.slashNode used to
// only decrement bookkeeping (node.stake -= amount) and never actually
// transfer the slashed ETH anywhere -- it just stayed stuck in the
// contract's balance forever, benefiting no one, not even the trader who
// was actually harmed by the missed deadline.
//
// This registers a node, has a trader commit a trade with a very short
// deadline, lets the deadline pass (via evm_increaseTime), calls
// claimSlash, and confirms the trader's own ETH balance actually
// increased by the slashed amount -- not just that the node's stake
// bookkeeping went down.
//
// Usage:
//   cargo run -p trader-client --release --bin verify_slash_compensation -- \
//     <rpc_url> <deployer_private_key> <factory_address> <registry_address>

use alloy::network::EthereumWallet;
use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, FixedBytes, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use chain::OnChainAccount;
use common::SettlementPreference;
use engine::Match;
use trader_client::TraderClient;

sol! {
    #[sol(rpc)]
    interface INodeRegistrySlash {
        struct NodeInfo {
            bytes32 nodePubkey;
            address operator;
            uint256 stake;
            uint256 registeredAt;
            bool active;
            uint256 slashCount;
            uint256 missedDeadlines;
            string geoRegion;
            uint32 reputationScore;
            uint8 trustLevel;
            uint64 lastRepUpdate;
        }
        function registerNode(bytes32 nodePubkey, string calldata geoRegion) external payable;
        function isActiveNode(bytes32 nodePubkey) external view returns (bool);
        function getNode(bytes32 nodePubkey) external view returns (NodeInfo memory);
    }
}

async fn fund(provider: &impl Provider, to: Address, eth: &str) {
    let wei: u128 = eth.parse::<u128>().unwrap() * 1_000_000_000_000_000_000u128;
    let tx = TransactionRequest::default()
        .with_to(to)
        .with_value(U256::from(wei));
    provider
        .send_transaction(tx)
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
}

fn u64_to_bytes32(val: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&val.to_be_bytes());
    out
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rpc_url = args.get(1).expect("usage: verify_slash_compensation <rpc_url> <deployer_key> <factory_address> <registry_address>").clone();
    let deployer_key = args.get(2).expect("missing deployer_key").clone();
    let factory_address = args.get(3).expect("missing factory_address").clone();
    let registry_address = args.get(4).expect("missing registry_address").clone();

    let registry_addr: Address = registry_address.parse().unwrap();

    let deployer_signer: PrivateKeySigner = deployer_key.trim_start_matches("0x").parse().unwrap();
    let deployer_wallet = EthereumWallet::from(deployer_signer);
    let deployer_provider = ProviderBuilder::new()
        .wallet(deployer_wallet)
        .connect_http(rpc_url.parse().unwrap());

    // Register a node with a known 10 ETH stake -- claimSlash takes half
    // of whatever the node's current stake is, so the expected payout here
    // is exactly 5 ETH.
    let node_pubkey: OnChainAccount = {
        let mut b = [0u8; 32];
        b[0..4].copy_from_slice(b"SLSH");
        b
    };
    let stake_wei: u128 = 10_000_000_000_000_000_000u128;
    let registry_contract = INodeRegistrySlash::new(registry_addr, &deployer_provider);
    registry_contract
        .registerNode(FixedBytes::from(node_pubkey), "slash-test".to_string())
        .value(U256::from(stake_wei))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    println!("node registered with 10 ETH stake: OK");

    // Maker (will commit, then claim the slash) and taker.
    let maker_signer = PrivateKeySigner::random();
    let taker_signer = PrivateKeySigner::random();
    fund(&deployer_provider, maker_signer.address(), "5").await;
    fund(&deployer_provider, taker_signer.address(), "5").await;

    let maker_pubkey: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0..5].copy_from_slice(b"MAKER");
        b
    };
    let taker_pubkey: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0..5].copy_from_slice(b"TAKER");
        b
    };
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
    maker_client
        .deposit_native(U256::from(2_000_000_000_000_000_000u128))
        .await
        .unwrap();
    println!("maker + taker escrows created + funded: OK");

    // A trade with a deadline just 3 seconds out -- short enough to blow
    // past with a small time-travel, not the usual +1h used elsewhere.
    let read_provider = ProviderBuilder::new().connect_http(rpc_url.parse().unwrap());
    let chain_now = read_provider
        .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
        .await
        .unwrap()
        .unwrap()
        .header
        .timestamp;
    let deadline = chain_now + 3;

    let m = Match {
        maker_order_id: u64_to_bytes32(1),
        taker_order_id: u64_to_bytes32(2),
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
    let trade_hash = maker_client.commit_trade(&m).await.unwrap();
    println!(
        "commitTrade succeeded (deadline in 3s), trade_hash = {}",
        hex::encode(trade_hash)
    );

    // Time-travel past the deadline without ever settling the trade.
    let _: serde_json::Value = read_provider
        .client()
        .request("evm_increaseTime", (10,))
        .await
        .expect("evm_increaseTime failed");
    let _: serde_json::Value = read_provider
        .client()
        .request("evm_mine", ())
        .await
        .expect("evm_mine failed");
    println!("advanced chain time past the deadline: OK");

    let maker_balance_before = read_provider
        .get_balance(maker_signer.address())
        .await
        .unwrap();

    let claim_tx = maker_client
        .claim_slash(&[trade_hash])
        .await
        .expect("claimSlash failed");
    println!("claimSlash succeeded, tx = {claim_tx}");

    let maker_balance_after = read_provider
        .get_balance(maker_signer.address())
        .await
        .unwrap();
    let received = maker_balance_after - maker_balance_before;

    // received will be slightly under 5 ETH (gas spent on the claimSlash
    // tx itself comes out of the same balance) -- assert it's close to,
    // not stuck at, the expected 5 ETH slash payout.
    let expected = U256::from(5_000_000_000_000_000_000u128);
    let tolerance = U256::from(1_000_000_000_000_000u128); // 0.001 ETH, well above any reasonable gas cost
    println!(
        "maker balance change from claimSlash: {received} wei (expected ~{expected} wei minus gas)"
    );
    assert!(
        received + tolerance >= expected,
        "trader received {received} wei, expected close to {expected} wei -- slashed stake did not reach the wronged trader"
    );

    // Slashing halves a 10 ETH stake to 5 ETH, which is below MIN_STAKE
    // (10 ETH) -- NodeRegistry.slashNode deletes the node entirely in that
    // case rather than leaving it active-but-under-minimum, so getNode
    // correctly returns a zeroed-out struct here, not "5 ETH, inactive".
    let node_info = registry_contract
        .getNode(FixedBytes::from(node_pubkey))
        .call()
        .await
        .unwrap();
    assert_eq!(
        node_info.stake,
        U256::ZERO,
        "a node slashed below MIN_STAKE should be fully deleted, not left partially staked"
    );
    assert!(
        !node_info.active,
        "a slashed (and deleted) node must not read as active"
    );

    println!("\nSLASH COMPENSATION REGRESSION TEST PASSED: wronged trader actually received the slashed stake, node correctly deactivated with reduced stake.");
}
