// The capstone live validation: drives a REAL, running crates/api server
// process (started separately, pointed at the same devnet) through the
// entire pipeline for the first time as one connected system --
//   HTTP order submission -> off-chain match -> trader's own commitTrade
//   -> commit confirmation back to the API -> the API's own background
//   settlement loop batching, proving, and calling settleBatchWithFees --
// and confirms the trade actually settled on-chain, driven entirely by
// the live server, not by any code in this binary calling settlement
// directly.
//
// Usage:
//   cargo run -p trader-client --release --bin verify_live_api_settlement -- \
//     <api_base_url> <rpc_url> <deployer_private_key> <factory_address> <registry_address>
//
// Expects a live `api` server (crates/api/src/main.rs) already running
// against the same devnet/contracts, with its own settlement node already
// registered and its MEX_SETTLEMENT_NODE_PUBKEY matching what this script
// uses as `assigned_node`.

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::network::TransactionBuilder;
use alloy::signers::local::PrivateKeySigner;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use trader_client::TraderClient;

async fn fund(provider: &impl Provider, to: Address, eth: &str) {
    let wei: u128 = eth.parse::<u128>().unwrap() * 1_000_000_000_000_000_000u128;
    let tx = TransactionRequest::default().with_to(to).with_value(U256::from(wei));
    provider.send_transaction(tx).await.unwrap().get_receipt().await.unwrap();
}

// Mirrors OrderValidator::serialize_order_message exactly (id, trader,
// symbol, price, amount, nonce, expiry -- side is NOT covered) -- an
// order's signature covers this same byte layout, computed independently
// here since this binary has no direct dependency on the `validation`
// crate.
fn serialize_order_message(order: &serde_json::Value) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(order["id"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap() as u8).collect::<Vec<u8>>().as_slice());
    msg.extend_from_slice(order["trader"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap() as u8).collect::<Vec<u8>>().as_slice());
    msg.extend_from_slice(order["symbol"].as_str().unwrap().as_bytes());
    msg.extend_from_slice(&order["price"].as_u64().unwrap().to_be_bytes());
    msg.extend_from_slice(&order["amount"].as_u64().unwrap().to_be_bytes());
    msg.extend_from_slice(&order["nonce"].as_u64().unwrap().to_be_bytes());
    msg.extend_from_slice(&order["expiry"].as_u64().unwrap().to_be_bytes());
    msg
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let api_base = args.get(1).expect("usage: verify_live_api_settlement <api_base_url> <rpc_url> <deployer_key> <factory_address> <registry_address>").trim_end_matches('/').to_string();
    let rpc_url = args.get(2).expect("missing rpc_url").clone();
    let deployer_key = args.get(3).expect("missing deployer_key").clone();
    let factory_address = args.get(4).expect("missing factory_address").clone();

    let deployer_signer: PrivateKeySigner = deployer_key.trim_start_matches("0x").parse().unwrap();
    let deployer_wallet = EthereumWallet::from(deployer_signer);
    let deployer_provider = ProviderBuilder::new().wallet(deployer_wallet).connect_http(rpc_url.parse().unwrap());
    let read_provider = ProviderBuilder::new().connect_http(rpc_url.parse().unwrap());

    // Real Ethereum keys (on-chain escrow custody) for a seller and buyer.
    let seller_eth = PrivateKeySigner::random();
    let buyer_eth = PrivateKeySigner::random();
    fund(&deployer_provider, seller_eth.address(), "5").await;
    fund(&deployer_provider, buyer_eth.address(), "5").await;

    // Real ed25519 keys -- the SAME identity used both for off-chain order
    // signing (Order.trader) and for the on-chain escrow binding
    // (TraderClient's own_pubkey), exactly like every other real trader in
    // this system.
    let mut csprng = OsRng;
    let seller_offchain = SigningKey::generate(&mut csprng);
    let seller_pubkey = seller_offchain.verifying_key().to_bytes();
    let buyer_offchain = SigningKey::generate(&mut csprng);
    let buyer_pubkey = buyer_offchain.verifying_key().to_bytes();

    let mut tokens = chain_ethereum::TokenRegistry::new();
    tokens.register([0u8; 20], "ETH-USD");
    let mut seller_client = TraderClient::new(&rpc_url, &hex::encode(seller_eth.to_bytes()), &factory_address, seller_pubkey, tokens.clone(), 0).await.unwrap();
    let buyer_client = TraderClient::new(&rpc_url, &hex::encode(buyer_eth.to_bytes()), &factory_address, buyer_pubkey, tokens, 0).await.unwrap();
    seller_client.ensure_escrow().await.unwrap();
    buyer_client.ensure_escrow().await.unwrap();
    seller_client.deposit_native(U256::from(2_000_000_000_000_000_000u128)).await.unwrap();
    println!("seller + buyer real on-chain escrows created + funded: OK");

    let http = reqwest::Client::new();
    let api_key = std::env::var("MEX_API_KEY").unwrap_or_else(|_| "dev-default-key".to_string());

    let build_and_sign = |sk: &SigningKey, trader: [u8; 32], side: &str, price: u64, amount: u64, nonce: u64| -> serde_json::Value {
        let mut order_id = [0u8; 32];
        order_id[0..16].copy_from_slice(&trader[0..16]);
        order_id[16..24].copy_from_slice(&nonce.to_be_bytes());
        let unsigned = serde_json::json!({
            "id": order_id, "trader": trader, "symbol": "ETH-USD", "side": side,
            "price": price, "amount": amount, "nonce": nonce, "expiry": 0,
        });
        let msg = serialize_order_message(&unsigned);
        let signature = sk.sign(&msg).to_vec();
        serde_json::json!({
            "trader": trader, "symbol": "ETH-USD", "side": side,
            "price": price, "amount": amount, "signature": signature,
            "nonce": nonce, "expiry": 0,
        })
    };

    // Seller rests first (as maker); buyer's order crosses it (as taker).
    // Default settlement_requester (Seller) makes the SELLER the fee_payer
    // -- see engine::book::resolve_settlement_params -- so the seller is
    // who needs to commitTrade.
    let sell_req = build_and_sign(&seller_offchain, seller_pubkey, "Sell", 3000, 1, 1);
    let sell_resp: serde_json::Value = http.post(format!("{api_base}/api/v1/order"))
        .header("X-API-Key", &api_key).json(&sell_req).send().await.unwrap().json().await.unwrap();
    assert_eq!(sell_resp["success"], true, "sell order rejected: {sell_resp:?}");
    println!("sell order submitted to the LIVE api server: OK");

    let buy_req = build_and_sign(&buyer_offchain, buyer_pubkey, "Buy", 3000, 1, 1);
    let buy_resp: serde_json::Value = http.post(format!("{api_base}/api/v1/order"))
        .header("X-API-Key", &api_key).json(&buy_req).send().await.unwrap().json().await.unwrap();
    assert_eq!(buy_resp["success"], true, "buy order rejected: {buy_resp:?}");
    let matches = buy_resp["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 1, "expected exactly one real match from the live matching engine");
    let m = &matches[0];
    println!("buy order matched by the LIVE matching engine: OK");

    let maker_order_id: [u8; 32] = serde_json::from_value(m["maker_order_id"].clone()).unwrap();
    let taker_order_id: [u8; 32] = serde_json::from_value(m["taker_order_id"].clone()).unwrap();
    let price: u64 = serde_json::from_value(m["price"].clone()).unwrap();
    let amount: u64 = serde_json::from_value(m["amount"].clone()).unwrap();
    let fee_basis_points: u32 = serde_json::from_value(m["fee_basis_points"].clone()).unwrap();
    let settlement_deadline: u64 = serde_json::from_value(m["settlement_deadline"].clone()).unwrap();
    let assigned_node: [u8; 32] = serde_json::from_value(m["assigned_node"].clone()).unwrap();
    let maker_trader: [u8; 32] = serde_json::from_value(m["maker_trader"].clone()).unwrap();
    let taker_trader: [u8; 32] = serde_json::from_value(m["taker_trader"].clone()).unwrap();
    let seller_pk: [u8; 32] = serde_json::from_value(m["seller"].clone()).unwrap();
    let fee_payer_pk: [u8; 32] = serde_json::from_value(m["fee_payer"].clone()).unwrap();
    assert_eq!(seller_pk, seller_pubkey, "seller should be the fee_payer's counterpart as recorded");
    assert_eq!(fee_payer_pk, seller_pubkey, "the seller must be the fee_payer for this test's assumptions to hold");

    let engine_match = engine::Match {
        maker_order_id,
        taker_order_id,
        maker_trader,
        taker_trader,
        price,
        amount,
        timestamp_us: 0,
        settlement_tier: common::SettlementPreference::Standard,
        fee_basis_points,
        seller: seller_pk,
        fee_payer: fee_payer_pk,
        settlement_deadline,
        symbol: "ETH-USD".to_string(),
        assigned_node,
    };

    // The seller (fee_payer) commits on-chain themselves -- this binary
    // stands in for what would be the seller's own trading client.
    let trade_hash = seller_client.commit_trade(&engine_match).await.expect("seller's own commitTrade failed");
    println!("seller committed the trade on-chain themselves: OK, trade_hash = {}", hex::encode(trade_hash));

    let confirm_body = serde_json::json!({
        "maker_order_id": maker_order_id,
        "taker_order_id": taker_order_id,
        "trade_hash": trade_hash,
    });
    let confirm_resp: serde_json::Value = http.post(format!("{api_base}/api/v1/trade/committed"))
        .header("X-API-Key", &api_key).json(&confirm_body).send().await.unwrap().json().await.unwrap();
    assert_eq!(confirm_resp["success"], true, "commit confirmation rejected: {confirm_resp:?}");
    println!("commit confirmed to the live api server, now eligible for settlement: OK");

    // The live server's own background settlement loop must now pick this
    // up, prove it, and settle it on-chain -- entirely on its own.
    println!("waiting for the live server's own settlement loop to settle this on-chain...");
    let escrow_addr = seller_client.own_address();
    // A thin, purely-read-only settlement lookup, to confirm the loop
    // running inside the OTHER process actually did its job -- not
    // something this binary computes or drives itself.
    sol_settlement_check(&read_provider, &factory_address, escrow_addr, trade_hash).await;
}

// Minimal read-only check that a trade actually got marked settled --
// deliberately independent of any state this binary itself touched.
async fn sol_settlement_check(provider: &impl Provider, factory_address: &str, trader: Address, trade_hash: [u8; 32]) {
    use alloy::primitives::FixedBytes;
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface ISettlementFactoryCheck {
            function getEscrow(address trader) external view returns (address);
        }
        #[sol(rpc)]
        interface ITraderEscrowCheck {
            struct Settlement {
                uint256 deadline;
                bool refunded;
                bool settled;
                bool slashed;
                bytes32 assignedNode;
                address token;
                uint256 lockedAmount;
                address counterparty;
            }
            function getSettlement(bytes32 tradeHash) external view returns (Settlement memory);
        }
    }

    let factory_addr: Address = factory_address.parse().unwrap();
    let factory = ISettlementFactoryCheck::new(factory_addr, provider);
    let escrow_addr = factory.getEscrow(trader).call().await.unwrap();

    let escrow = ITraderEscrowCheck::new(escrow_addr, provider);

    let deadline_secs = 90u64;
    let start = std::time::Instant::now();
    loop {
        let settlement = escrow.getSettlement(FixedBytes::from(trade_hash)).call().await.unwrap();
        if settlement.settled {
            println!("\nLIVE API END-TO-END SETTLEMENT TEST PASSED: the trade was settled on-chain entirely by the live server's own background loop.");
            return;
        }
        if start.elapsed().as_secs() > deadline_secs {
            panic!(
                "trade was not settled by the live server within {deadline_secs}s -- settlement.settled = {}, refunded = {}",
                settlement.settled, settlement.refunded
            );
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}
