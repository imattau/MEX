// Live regression check for a real fund-theft vulnerability that used to
// exist in SettlementFactory.settleBatchWithFees: the function had no
// caller restriction, and never cross-checked the caller-supplied
// TradeEntry's token/counterparty/amount against what commitTrade actually
// recorded -- so anyone could take any trader's real, publicly-observable
// tradeHash and settle it with an arbitrary amount/counterparty/token of
// their own choosing, as long as they attached *some* internally-
// consistent ZK proof (the proof's content was never bound to the specific
// trades[] array being settled either).
//
// This sets up one real, honestly-committed trade, then attempts the
// exploit four ways: wrong caller, wrong counterparty, wrong amount, wrong
// token -- each must revert -- before finally confirming the honest,
// correctly-formed settlement still succeeds.
//
// Usage:
//   cargo run -p trader-client --release --bin verify_settlement_authorization -- \
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
use prover::{decode_proof_calldata, Bn254Groth16Backend, ProverBackend, TradeBatch};
use trader_client::TraderClient;

sol! {
    #[sol(rpc)]
    interface INodeRegistryAuth {
        function registerNode(bytes32 nodePubkey, string calldata geoRegion) external payable;
        function isActiveNode(bytes32 nodePubkey) external view returns (bool);
    }

    #[sol(rpc)]
    interface ISettlementFactoryAuth {
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
    let rpc_url = args.get(1).expect("usage: verify_settlement_authorization <rpc_url> <deployer_key> <factory_address> <registry_address>").clone();
    let deployer_key = args.get(2).expect("missing deployer_key").clone();
    let factory_address = args.get(3).expect("missing factory_address").clone();
    let registry_address = args.get(4).expect("missing registry_address").clone();

    let factory_addr: Address = factory_address.parse().unwrap();
    let registry_addr: Address = registry_address.parse().unwrap();

    let deployer_signer: PrivateKeySigner = deployer_key.trim_start_matches("0x").parse().unwrap();
    let deployer_address = deployer_signer.address();
    let deployer_wallet = EthereumWallet::from(deployer_signer);
    let deployer_provider = ProviderBuilder::new()
        .wallet(deployer_wallet)
        .connect_http(rpc_url.parse().unwrap());

    // Register one settlement node, operated by the deployer key.
    let node_pubkey: OnChainAccount = {
        let mut b = [0u8; 32];
        b[0..4].copy_from_slice(b"AUTH");
        b
    };
    let registry_contract = INodeRegistryAuth::new(registry_addr, &deployer_provider);
    if !registry_contract
        .isActiveNode(FixedBytes::from(node_pubkey))
        .call()
        .await
        .unwrap()
    {
        registry_contract
            .registerNode(FixedBytes::from(node_pubkey), "auth-test".to_string())
            .value(U256::from(10_000_000_000_000_000_000u128))
            .send()
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap();
    }
    println!("settlement node registered (operator = deployer): OK");

    // Maker (real committer) and taker (real counterparty), plus a third,
    // completely unrelated address the attacker will try to redirect
    // funds to.
    let maker_signer = PrivateKeySigner::random();
    let taker_signer = PrivateKeySigner::random();
    let attacker_signer = PrivateKeySigner::random();
    fund(&deployer_provider, maker_signer.address(), "5").await;
    fund(&deployer_provider, taker_signer.address(), "5").await;
    fund(&deployer_provider, attacker_signer.address(), "5").await;

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

    // One real, honest commitTrade.
    let deadline = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
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
        "real commitTrade succeeded, trade_hash = {}",
        hex::encode(trade_hash)
    );

    let real_amount = U256::from(m.price * m.amount);
    let real_fee = U256::from((m.price * m.amount) * m.fee_basis_points as u64 / 10_000);

    let batch = TradeBatch {
        trades: vec![m.clone()],
        maker_balances: vec![1_000_000],
        taker_balances: vec![1_000_000],
        pre_state_root: [0u8; 32],
        post_state_root: u64_to_bytes32(m.price * m.amount),
    };
    let proof = Bn254Groth16Backend.prove_batch(&batch).unwrap();
    let calldata = decode_proof_calldata(&proof).unwrap();
    let a = [
        U256::from_be_bytes(calldata.a[0]),
        U256::from_be_bytes(calldata.a[1]),
    ];
    let b = [
        [
            U256::from_be_bytes(calldata.b[0][0]),
            U256::from_be_bytes(calldata.b[0][1]),
        ],
        [
            U256::from_be_bytes(calldata.b[1][0]),
            U256::from_be_bytes(calldata.b[1][1]),
        ],
    ];
    let c = [
        U256::from_be_bytes(calldata.c[0]),
        U256::from_be_bytes(calldata.c[1]),
    ];
    let input: Vec<U256> = calldata
        .public_inputs
        .iter()
        .map(|bytes| U256::from_be_bytes(*bytes))
        .collect();

    let honest_entry = ISettlementFactoryAuth::TradeEntry {
        trader: maker_signer.address(),
        counterparty: taker_signer.address(),
        token: Address::ZERO,
        amount: real_amount,
        fee: real_fee,
        deadline: U256::from(deadline),
        tradeHash: FixedBytes::from(trade_hash),
        assignedNode: FixedBytes::from(node_pubkey),
    };
    let fee_config = ISettlementFactoryAuth::FeeConfig {
        feeRecipient: deployer_address,
        tier: 0,
    };

    println!("\n=== Attempting the exploit, each must be rejected ===");

    // 1. Wrong caller: attacker's own key, not the node operator.
    let attacker_wallet = EthereumWallet::from(attacker_signer.clone());
    let attacker_provider = ProviderBuilder::new()
        .wallet(attacker_wallet)
        .connect_http(rpc_url.parse().unwrap());
    let factory_as_attacker = ISettlementFactoryAuth::new(factory_addr, &attacker_provider);
    let result = factory_as_attacker
        .settleBatchWithFees(
            vec![honest_entry.clone()],
            a,
            b,
            c,
            input.clone(),
            fee_config.clone(),
        )
        .send()
        .await;
    assert!(
        result.is_err(),
        "EXPLOIT SUCCEEDED: an unauthorized caller settled someone else's trade"
    );
    println!("1. Unauthorized caller (not the assigned node operator): correctly REJECTED");

    let factory_as_deployer = ISettlementFactoryAuth::new(factory_addr, &deployer_provider);

    // 2. Correct caller, but redirect funds to the attacker instead of the real counterparty.
    let mut tampered_counterparty = honest_entry.clone();
    tampered_counterparty.counterparty = attacker_signer.address();
    let result = factory_as_deployer
        .settleBatchWithFees(
            vec![tampered_counterparty],
            a,
            b,
            c,
            input.clone(),
            fee_config.clone(),
        )
        .send()
        .await;
    assert!(
        result.is_err(),
        "EXPLOIT SUCCEEDED: funds were redirected to an unrecorded counterparty"
    );
    println!("2. Tampered counterparty (redirect to attacker): correctly REJECTED");

    // 3. Correct caller, but inflate the amount beyond what was actually locked.
    let mut tampered_amount = honest_entry.clone();
    tampered_amount.amount = real_amount * U256::from(1000);
    let result = factory_as_deployer
        .settleBatchWithFees(
            vec![tampered_amount],
            a,
            b,
            c,
            input.clone(),
            fee_config.clone(),
        )
        .send()
        .await;
    assert!(
        result.is_err(),
        "EXPLOIT SUCCEEDED: settled for far more than was actually locked"
    );
    println!("3. Tampered amount (1000x inflation): correctly REJECTED");

    // 4. Correct caller, but claim a different token than was actually locked.
    let mut tampered_token = honest_entry.clone();
    tampered_token.token = Address::from([0x42u8; 20]);
    let result = factory_as_deployer
        .settleBatchWithFees(
            vec![tampered_token],
            a,
            b,
            c,
            input.clone(),
            fee_config.clone(),
        )
        .send()
        .await;
    assert!(
        result.is_err(),
        "EXPLOIT SUCCEEDED: settled against an unrecorded token"
    );
    println!("4. Tampered token: correctly REJECTED");

    // 5. The real thing, unmodified, from the correct operator: must succeed.
    //
    // The 4 rejected attempts above each failed during client-side gas
    // estimation (before ever being broadcast), but alloy's nonce filler
    // still optimistically advances its local cache per .send() call
    // regardless of whether the call is ultimately broadcast -- so that
    // cache is now ahead of the real on-chain nonce. Re-sync explicitly
    // from the chain rather than trusting the filler here.
    let real_nonce = deployer_provider
        .get_transaction_count(deployer_address)
        .await
        .unwrap();
    let receipt = factory_as_deployer
        .settleBatchWithFees(vec![honest_entry], a, b, c, input, fee_config)
        .nonce(real_nonce)
        .send()
        .await
        .expect("honest settlement send failed")
        .get_receipt()
        .await
        .expect("honest settlement receipt failed");
    assert!(
        receipt.status(),
        "the honest, correctly-formed settlement should have succeeded"
    );
    println!("5. Honest settlement (correct caller, untampered data): correctly ACCEPTED");

    println!("\nSETTLEMENT AUTHORIZATION REGRESSION TEST PASSED: all 4 exploit attempts rejected, honest path still works.");
}
