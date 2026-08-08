use alloy::network::EthereumWallet;
use alloy::primitives::{Address, FixedBytes, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use chain::{ChainAdapter, OnChainAccount, SettlementFeeConfig, SettlementTrade, Token};
use prover::{decode_proof_calldata, Bn254Groth16Backend, ProverBackend};

sol! {
    #[sol(rpc)]
    interface ISettlementFactory {
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

    // NodeRegistry.getNode returns a single NodeInfo struct (one tuple-typed
    // ABI output), not N flattened top-level outputs -- declaring it as a
    // real struct here (matching the contract's actual ABI shape, confirmed
    // against the compiled artifact's `outputs: [{type: "tuple", ...}]`) is
    // required for correct decoding. Because NodeInfo contains a dynamic
    // `string` field, the whole struct is a dynamic ABI type, so the return
    // data has an extra leading offset word wrapping it; declaring the
    // fields as flat top-level returns instead (an earlier attempt) omits
    // that wrapping and silently decodes every field shifted by one word.
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

    #[sol(rpc)]
    interface INodeRegistry {
        function recordMissedDeadline(bytes32 nodePubkey) external;
        function registerNode(bytes32 nodePubkey, string calldata geoRegion) external payable;
        function isActiveNode(bytes32 nodePubkey) external view returns (bool);
        function getReputation(bytes32 nodePubkey)
            external
            view
            returns (uint32 score, uint8 level, uint64 lastUpdate);
        function getNode(bytes32 nodePubkey) external view returns (NodeInfo memory);
    }
}

// Left-zero-padded 20-byte-address <-> chain::OnChainAccount ([u8; 32])
// conversion. See OnChainAccount's docs: this is the convention every
// generic account field in the `chain` crate uses for EVM chains.
fn account_to_address(account: OnChainAccount) -> Result<Address, String> {
    if account[..12] != [0u8; 12] {
        return Err(format!(
            "OnChainAccount {} is not a valid left-zero-padded Ethereum address",
            hex::encode(account)
        ));
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&account[12..]);
    Ok(Address::from(addr))
}

fn token_to_address(token: &Token) -> Result<Address, String> {
    match token {
        Token::Native => Ok(Address::ZERO),
        Token::Erc20(addr) => addr
            .parse()
            .map_err(|e| format!("invalid ERC20 address {addr}: {e}")),
        other => Err(format!("{other:?} is not an Ethereum token type")),
    }
}

fn trade_to_entry(trade: &SettlementTrade) -> Result<ISettlementFactory::TradeEntry, String> {
    Ok(ISettlementFactory::TradeEntry {
        trader: account_to_address(trade.trader)?,
        counterparty: account_to_address(trade.counterparty)?,
        token: token_to_address(&trade.token)?,
        amount: U256::from(trade.amount),
        fee: U256::from(trade.fee),
        deadline: U256::from(trade.deadline),
        tradeHash: FixedBytes::from(trade.trade_hash),
        assignedNode: FixedBytes::from(trade.assigned_node),
    })
}

// A real, signing EthereumAdapter: submits transactions using its own key
// (via alloy's wallet-filled provider, which handles nonce/gas/chain-id
// automatically), for the write actions a node's own key can legitimately
// sign -- see ChainAdapter's docs for why lock/settle/release/slash aren't
// part of this adapter's surface at all.
//
// Holds a type-erased DynProvider rather than the concrete filler-stack type
// ProviderBuilder produces, so this struct doesn't need to name (or track,
// across alloy versions) that internal type.
pub struct EthereumAdapter {
    provider: DynProvider,
    factory_address: Address,
    registry_address: Address,
    chain_identifier: &'static str,
    native_denom: &'static str,
}

impl EthereumAdapter {
    pub async fn new(
        rpc_url: &str,
        private_key: &str,
        factory_address: &str,
        registry_address: &str,
    ) -> Result<Self, String> {
        let signer: PrivateKeySigner = private_key
            .trim_start_matches("0x")
            .trim_start_matches("0X")
            .parse()
            .map_err(|e| format!("invalid private key: {e}"))?;
        let wallet = EthereumWallet::from(signer);
        let url = rpc_url
            .parse()
            .map_err(|e| format!("invalid RPC URL: {e}"))?;
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(url)
            .erased();

        Ok(Self {
            provider,
            factory_address: factory_address
                .parse()
                .map_err(|e| format!("invalid factory address: {e}"))?,
            registry_address: registry_address
                .parse()
                .map_err(|e| format!("invalid registry address: {e}"))?,
            chain_identifier: "ethereum",
            native_denom: "ETH",
        })
    }
}

impl ChainAdapter for EthereumAdapter {
    fn chain_id(&self) -> &'static str {
        self.chain_identifier
    }

    fn native_denomination(&self) -> &'static str {
        self.native_denom
    }

    async fn submit_settlement_batch(
        &self,
        trades: &[SettlementTrade],
        proof: &[u8],
        fee_config: SettlementFeeConfig,
    ) -> Result<String, String> {
        if trades.is_empty() {
            return Err("no trades to settle".to_string());
        }

        let calldata = decode_proof_calldata(proof)?;

        let entries: Vec<ISettlementFactory::TradeEntry> =
            trades.iter().map(trade_to_entry).collect::<Result<_, _>>()?;

        let a = [U256::from_be_bytes(calldata.a[0]), U256::from_be_bytes(calldata.a[1])];
        let b = [
            [U256::from_be_bytes(calldata.b[0][0]), U256::from_be_bytes(calldata.b[0][1])],
            [U256::from_be_bytes(calldata.b[1][0]), U256::from_be_bytes(calldata.b[1][1])],
        ];
        let c = [U256::from_be_bytes(calldata.c[0]), U256::from_be_bytes(calldata.c[1])];
        let input: Vec<U256> = calldata
            .public_inputs
            .iter()
            .map(|bytes| U256::from_be_bytes(*bytes))
            .collect();

        let fee_config_sol = ISettlementFactory::FeeConfig {
            feeRecipient: account_to_address(fee_config.fee_recipient)?,
            tier: fee_config.tier,
        };

        let factory = ISettlementFactory::new(self.factory_address, &self.provider);
        let pending = factory
            .settleBatchWithFees(entries, a, b, c, input, fee_config_sol)
            .send()
            .await
            .map_err(|e| format!("settleBatchWithFees send failed: {e}"))?;

        let receipt = pending
            .get_receipt()
            .await
            .map_err(|e| format!("settleBatchWithFees receipt failed: {e}"))?;

        Ok(format!("0x{:x}", receipt.transaction_hash))
    }

    async fn submit_missed_deadline_report(
        &self,
        node_pubkey: OnChainAccount,
    ) -> Result<(), String> {
        let registry = INodeRegistry::new(self.registry_address, &self.provider);
        let pending = registry
            .recordMissedDeadline(FixedBytes::from(node_pubkey))
            .send()
            .await
            .map_err(|e| format!("recordMissedDeadline send failed: {e}"))?;
        pending
            .get_receipt()
            .await
            .map_err(|e| format!("recordMissedDeadline receipt failed: {e}"))?;
        Ok(())
    }

    async fn register_node(
        &self,
        pubkey: OnChainAccount,
        geo: &str,
        stake: u64,
    ) -> Result<(), String> {
        let registry = INodeRegistry::new(self.registry_address, &self.provider);
        let pending = registry
            .registerNode(FixedBytes::from(pubkey), geo.to_string())
            .value(U256::from(stake))
            .send()
            .await
            .map_err(|e| format!("registerNode send failed: {e}"))?;
        pending
            .get_receipt()
            .await
            .map_err(|e| format!("registerNode receipt failed: {e}"))?;
        Ok(())
    }

    async fn get_node_stake(&self, pubkey: OnChainAccount) -> Result<u64, String> {
        let registry = INodeRegistry::new(self.registry_address, &self.provider);
        let node = registry
            .getNode(FixedBytes::from(pubkey))
            .call()
            .await
            .map_err(|e| format!("getNode call failed: {e}"))?;
        u64::try_from(node.stake).map_err(|_| format!("stake {} exceeds u64 range", node.stake))
    }

    async fn is_node_active(&self, pubkey: OnChainAccount) -> Result<bool, String> {
        let registry = INodeRegistry::new(self.registry_address, &self.provider);
        registry
            .isActiveNode(FixedBytes::from(pubkey))
            .call()
            .await
            .map_err(|e| format!("isActiveNode call failed: {e}"))
    }

    async fn get_node_reputation(
        &self,
        pubkey: OnChainAccount,
    ) -> Result<(u32, u8, u64), String> {
        let registry = INodeRegistry::new(self.registry_address, &self.provider);
        let result = registry
            .getReputation(FixedBytes::from(pubkey))
            .call()
            .await
            .map_err(|e| format!("getReputation call failed: {e}"))?;
        Ok((result.score, result.level, result.lastUpdate))
    }

    fn prover(&self) -> &dyn ProverBackend {
        &Bn254Groth16Backend
    }
}
