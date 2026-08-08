use alloy::network::EthereumWallet;
use alloy::primitives::{Address, FixedBytes, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use chain::{SettlementTrade, Token};
use chain_ethereum::{account_to_address, address_to_account, compute_trade_hash, token_to_address, ChainSync, TokenRegistry};
use engine::Match;

sol! {
    #[sol(rpc)]
    interface ISettlementFactoryTrader {
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
        function createEscrow(address trader, bytes32 offchainPubkey) external returns (address);
        function getEscrow(address trader) external view returns (address);
        function commitTrade(TradeEntry calldata trade) external;
        function claimSlash(bytes32[] calldata tradeHashes) external;
    }

    #[sol(rpc)]
    interface ITraderEscrowDeposit {
        function deposit(address token, uint256 amount) external payable;
    }
}

// A trader's own signing client: holds the trader's own Ethereum key and
// off-chain pubkey, and submits exactly the two on-chain actions that are
// restricted to `msg.sender == trader` and therefore can never be performed
// by node/infra (see chain::ChainAdapter's docs for why those are excluded
// there) -- commitTrade and claimSlash.
pub struct TraderClient {
    provider: DynProvider,
    factory_address: Address,
    own_address: Address,
    own_pubkey: [u8; 32],
    tokens: TokenRegistry,
    // Lazily kept warm by resolve_counterparty rather than run as a
    // continuous background service -- see resolve_counterparty's docs.
    sync: ChainSync<DynProvider>,
}

impl TraderClient {
    pub async fn new(
        rpc_url: &str,
        private_key: &str,
        factory_address: &str,
        own_pubkey: [u8; 32],
        tokens: TokenRegistry,
        sync_start_block: u64,
    ) -> Result<Self, String> {
        let signer: PrivateKeySigner = private_key
            .trim_start_matches("0x")
            .trim_start_matches("0X")
            .parse()
            .map_err(|e| format!("invalid private key: {e}"))?;
        let own_address = signer.address();
        let wallet = EthereumWallet::from(signer);
        let url = rpc_url
            .parse()
            .map_err(|e| format!("invalid RPC URL: {e}"))?;
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(url)
            .erased();

        let factory_address: Address = factory_address
            .parse()
            .map_err(|e| format!("invalid factory address: {e}"))?;

        let sync = ChainSync::new(
            provider.clone(),
            factory_address.into_array(),
            tokens.clone(),
            0,
            sync_start_block,
        );

        Ok(Self {
            provider,
            factory_address,
            own_address,
            own_pubkey,
            tokens,
            sync,
        })
    }

    pub fn own_address(&self) -> Address {
        self.own_address
    }

    // Registers this trader's own escrow if it doesn't already have one,
    // binding it to their own off-chain pubkey. Required before commitTrade
    // will accept anything from this trader -- SettlementFactory.commitTrade
    // requires both trader's and counterparty's escrows to already exist.
    pub async fn ensure_escrow(&self) -> Result<Address, String> {
        let factory = ISettlementFactoryTrader::new(self.factory_address, &self.provider);
        let existing = factory
            .getEscrow(self.own_address)
            .call()
            .await
            .map_err(|e| format!("getEscrow call failed: {e}"))?;
        if existing != Address::ZERO {
            return Ok(existing);
        }

        let pending = factory
            .createEscrow(self.own_address, FixedBytes::from(self.own_pubkey))
            .send()
            .await
            .map_err(|e| format!("createEscrow send failed: {e}"))?;
        pending
            .get_receipt()
            .await
            .map_err(|e| format!("createEscrow receipt failed: {e}"))?;

        factory
            .getEscrow(self.own_address)
            .call()
            .await
            .map_err(|e| format!("getEscrow call failed: {e}"))
    }

    // Deposits native ETH into this trader's own escrow (ensure_escrow must
    // have already been called -- this fails if no escrow exists yet).
    //
    // Deliberately sends through this client's own `self.provider` rather
    // than a freshly constructed one. alloy's nonce filler resolves an
    // account's next nonce once per provider instance (via
    // eth_getTransactionCount) and then tracks it locally from there; a
    // second, independent provider signing for the same account desyncs
    // that local count from actual chain state as soon as either provider
    // sends a transaction the other doesn't know about. A caller that
    // built its own throwaway provider to deposit, separate from the
    // provider a TraderClient goes on to reuse for every later
    // commitTrade/claimSlash, was hitting exactly that: the first
    // commitTrade after such a deposit would reuse a stale cached nonce
    // and get rejected with "nonce too low". Routing every transaction for
    // this trader through the one provider avoids the desync entirely.
    pub async fn deposit_native(&self, amount_wei: U256) -> Result<(), String> {
        let factory = ISettlementFactoryTrader::new(self.factory_address, &self.provider);
        let escrow_address = factory
            .getEscrow(self.own_address)
            .call()
            .await
            .map_err(|e| format!("getEscrow call failed: {e}"))?;
        if escrow_address == Address::ZERO {
            return Err("no escrow exists for this trader yet -- call ensure_escrow first".to_string());
        }

        let escrow = ITraderEscrowDeposit::new(escrow_address, &self.provider);
        escrow
            .deposit(Address::ZERO, amount_wei)
            .value(amount_wei)
            .send()
            .await
            .map_err(|e| format!("deposit send failed: {e}"))?
            .get_receipt()
            .await
            .map_err(|e| format!("deposit receipt failed: {e}"))?;
        Ok(())
    }

    // Resolves a counterparty's Ethereum address from their off-chain
    // pubkey by scanning SettlementFactory's EscrowCreated events. There is
    // no on-chain reverse lookup (pubkey -> address) to call directly --
    // EscrowCreated is the only place that association exists (see
    // chain_ethereum::EscrowRegistry's docs) -- so this polls ChainSync a
    // few times rather than running it as a continuous background service,
    // since a trader-client only needs this resolved right before
    // committing a trade, not kept warm continuously.
    pub async fn resolve_counterparty(&mut self, counterparty_pubkey: [u8; 32]) -> Result<Address, String> {
        for _ in 0..10 {
            if let Some(owner) = self
                .sync
                .escrows()
                .known_escrows()
                .find_map(|escrow| {
                    let owner = self.sync.escrows().owner_of(*escrow)?;
                    (owner.offchain_pubkey == counterparty_pubkey).then_some(owner)
                })
            {
                return Ok(Address::from(owner.trader));
            }
            self.sync.poll_once().await?;
        }

        self.sync
            .escrows()
            .known_escrows()
            .find_map(|escrow| {
                let owner = self.sync.escrows().owner_of(*escrow)?;
                (owner.offchain_pubkey == counterparty_pubkey).then_some(owner)
            })
            .map(|owner| Address::from(owner.trader))
            .ok_or_else(|| {
                format!(
                    "counterparty pubkey {} has no known escrow on-chain yet",
                    hex::encode(counterparty_pubkey)
                )
            })
    }

    // Commits this trader to a trade produced by the off-chain matching
    // engine (delivered e.g. via GET /ws/trades/:trader). Only proceeds if
    // this client's own pubkey is actually the trade's fee_payer -- a Match
    // is broadcast to BOTH participants, but only the fee-paying side is
    // the `trader` in SettlementFactory.TradeEntry (commitTrade locks and
    // pays from `trader`'s escrow to `counterparty`; the other side isn't
    // the one calling commitTrade for this particular trade at all).
    pub async fn commit_trade(&mut self, m: &Match) -> Result<[u8; 32], String> {
        if m.fee_payer != self.own_pubkey {
            return Err(format!(
                "this client ({}) is not the fee_payer ({}) for this match -- nothing to commit",
                hex::encode(self.own_pubkey),
                hex::encode(m.fee_payer)
            ));
        }

        let counterparty_pubkey = if m.maker_trader == self.own_pubkey {
            m.taker_trader
        } else {
            m.maker_trader
        };
        let counterparty_address = self.resolve_counterparty(counterparty_pubkey).await?;

        let notional = m.price as u128 * m.amount as u128;
        let fee = notional * m.fee_basis_points as u128 / 10_000;
        let amount = u64::try_from(notional).map_err(|_| "trade notional exceeds u64 range".to_string())?;
        let fee = u64::try_from(fee).map_err(|_| "trade fee exceeds u64 range".to_string())?;

        let token = self
            .tokens
            .address_of(&m.symbol)
            .ok_or_else(|| format!("no token address registered for symbol {}", m.symbol))?;

        let trade = SettlementTrade {
            maker_order_id: m.maker_order_id,
            taker_order_id: m.taker_order_id,
            trader: address_to_account(self.own_address),
            counterparty: address_to_account(counterparty_address),
            token: Token::Erc20(format!("0x{}", hex::encode(token))),
            amount,
            fee,
            deadline: m.settlement_deadline,
            trade_hash: [0u8; 32],
            assigned_node: m.assigned_node,
        };
        let trade_hash = compute_trade_hash(&trade)?;

        let entry = ISettlementFactoryTrader::TradeEntry {
            trader: account_to_address(trade.trader)?,
            counterparty: account_to_address(trade.counterparty)?,
            token: token_to_address(&trade.token)?,
            amount: U256::from(trade.amount),
            fee: U256::from(trade.fee),
            deadline: U256::from(trade.deadline),
            tradeHash: FixedBytes::from(trade_hash),
            assignedNode: FixedBytes::from(trade.assigned_node),
        };

        let factory = ISettlementFactoryTrader::new(self.factory_address, &self.provider);
        let pending = factory
            .commitTrade(entry)
            .send()
            .await
            .map_err(|e| format!("commitTrade send failed: {e}"))?;
        pending
            .get_receipt()
            .await
            .map_err(|e| format!("commitTrade receipt failed: {e}"))?;

        Ok(trade_hash)
    }

    // Claims a slash against node(s) that missed their settlement deadline
    // for trades this trader committed. Only the trader who committed a
    // trade can claim against it (SettlementFactory.claimSlash operates on
    // `msg.sender`'s own escrow).
    pub async fn claim_slash(&self, trade_hashes: &[[u8; 32]]) -> Result<String, String> {
        let factory = ISettlementFactoryTrader::new(self.factory_address, &self.provider);
        let hashes: Vec<FixedBytes<32>> = trade_hashes.iter().map(|h| FixedBytes::from(*h)).collect();
        let pending = factory
            .claimSlash(hashes)
            .send()
            .await
            .map_err(|e| format!("claimSlash send failed: {e}"))?;
        let receipt = pending
            .get_receipt()
            .await
            .map_err(|e| format!("claimSlash receipt failed: {e}"))?;
        Ok(format!("0x{:x}", receipt.transaction_hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Both of these validate before any network I/O (key parsing and URL
    // parsing are both local), so they don't need a live RPC endpoint --
    // unlike commit_trade/claim_slash/ensure_escrow, which are only
    // exercised live (see the trader-client live validation used while
    // building this).
    #[tokio::test]
    async fn test_new_rejects_invalid_private_key() {
        let result = TraderClient::new(
            "http://127.0.0.1:8545",
            "not-a-valid-key",
            "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0",
            [0u8; 32],
            TokenRegistry::new(),
            0,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_new_rejects_invalid_factory_address() {
        let result = TraderClient::new(
            "http://127.0.0.1:8545",
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
            "not-an-address",
            [0u8; 32],
            TokenRegistry::new(),
            0,
        )
        .await;
        assert!(result.is_err());
    }
}
