use crate::registry::{EscrowRegistry, EthAddress, TokenRegistry};
use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::Filter;
use alloy::sol;
use alloy::sol_types::SolEvent;
use serde::{Deserialize, Serialize};

sol! {
    event EscrowCreated(address indexed trader, address escrowAddress, bytes32 offchainPubkey);
    event Deposited(address indexed token, uint256 amount);
    event Withdrawn(address indexed token, uint256 amount);
}

// A deposit or withdrawal observed on-chain, resolved as far as the current
// registries allow. `trader` is the on-chain Ethereum account that owns the
// escrow the event came from; `offchain_pubkey` is the ed25519 pubkey it was
// bound to at creation (see EscrowRegistry/TraderEscrow.offchainPubkey) --
// that's the identity engine::Match/BalanceLedger actually key traders by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainEvent {
    EscrowCreated {
        trader: EthAddress,
        escrow: EthAddress,
        offchain_pubkey: [u8; 32],
    },
    Deposited {
        escrow: EthAddress,
        trader: EthAddress,
        offchain_pubkey: [u8; 32],
        token: EthAddress,
        symbol: Option<String>,
        amount: u128,
        block_number: u64,
    },
    Withdrawn {
        escrow: EthAddress,
        trader: EthAddress,
        offchain_pubkey: [u8; 32],
        token: EthAddress,
        symbol: Option<String>,
        amount: u128,
        block_number: u64,
    },
}

fn to_eth_address(addr: Address) -> EthAddress {
    addr.into_array()
}

// Polls a factory + its known escrows for new events via eth_getLogs, rather
// than subscribing over a websocket -- this keeps the transport to plain
// HTTP, which is all a local Anvil devnet or most public RPC providers need,
// at the cost of a polling delay instead of push notifications.
pub struct ChainSync<P: Provider> {
    provider: P,
    factory_address: Address,
    // Number of blocks to stay behind the chain head before treating a log
    // as final, to avoid crediting a deposit that a reorg later erases.
    confirmations: u64,
    // Highest block number already scanned; the next poll starts after it.
    last_synced_block: u64,
    escrows: EscrowRegistry,
    tokens: TokenRegistry,
}

impl<P: Provider> ChainSync<P> {
    pub fn new(
        provider: P,
        factory_address: EthAddress,
        tokens: TokenRegistry,
        confirmations: u64,
        start_block: u64,
    ) -> Self {
        Self {
            provider,
            factory_address: Address::from(factory_address),
            confirmations,
            last_synced_block: start_block,
            escrows: EscrowRegistry::new(),
            tokens,
        }
    }

    pub fn escrows(&self) -> &EscrowRegistry {
        &self.escrows
    }

    pub fn last_synced_block(&self) -> u64 {
        self.last_synced_block
    }

    // Feeds a previously-observed event back into ChainSync's internal state
    // (currently: EscrowRegistry) without fetching it from chain again. Used
    // to reconstruct that state from a persisted event log on startup,
    // instead of rescanning from genesis -- pair with constructing this
    // ChainSync with `start_block` set to the persisted last_synced_block so
    // poll_once resumes exactly where the previous run left off.
    pub fn replay(&mut self, event: &ChainEvent) {
        if let ChainEvent::EscrowCreated {
            trader,
            escrow,
            offchain_pubkey,
        } = event
        {
            self.escrows
                .record_escrow_created(*trader, *escrow, *offchain_pubkey);
        }
    }

    // Scans [last_synced_block + 1, latest - confirmations] for new events,
    // advances last_synced_block, and returns everything found in that range,
    // in block order. Returns an empty vec (without erroring) if there's
    // nothing new to scan yet, e.g. because the chain hasn't produced enough
    // confirmations since the last poll.
    pub async fn poll_once(&mut self) -> Result<Vec<ChainEvent>, String> {
        let latest = self
            .provider
            .get_block_number()
            .await
            .map_err(|e| format!("get_block_number failed: {e}"))?;

        let Some(safe_head) = latest.checked_sub(self.confirmations) else {
            return Ok(Vec::new());
        };
        if safe_head <= self.last_synced_block {
            return Ok(Vec::new());
        }

        let from_block = self.last_synced_block + 1;
        let to_block = safe_head;

        let mut events = Vec::new();

        // Pass 1: new escrows created by the factory since the last scan.
        let factory_filter = Filter::new()
            .address(self.factory_address)
            .event_signature(EscrowCreated::SIGNATURE_HASH)
            .from_block(from_block)
            .to_block(to_block);

        let factory_logs = self
            .provider
            .get_logs(&factory_filter)
            .await
            .map_err(|e| format!("get_logs (factory) failed: {e}"))?;

        for log in &factory_logs {
            let decoded = log
                .log_decode::<EscrowCreated>()
                .map_err(|e| format!("decode EscrowCreated failed: {e}"))?;
            let trader = to_eth_address(decoded.inner.data.trader);
            let escrow = to_eth_address(decoded.inner.data.escrowAddress);
            let offchain_pubkey: [u8; 32] = decoded.inner.data.offchainPubkey.into();
            self.escrows
                .record_escrow_created(trader, escrow, offchain_pubkey);
            events.push(ChainEvent::EscrowCreated {
                trader,
                escrow,
                offchain_pubkey,
            });
        }

        // Pass 2: deposits/withdrawals on every escrow known so far (including
        // ones just discovered above), filtered to this scan's block range.
        let escrow_addresses: Vec<Address> = self
            .escrows
            .known_escrows()
            .map(|e| Address::from(*e))
            .collect();

        if !escrow_addresses.is_empty() {
            let escrow_filter = Filter::new()
                .address(escrow_addresses)
                .events([Deposited::SIGNATURE, Withdrawn::SIGNATURE])
                .from_block(from_block)
                .to_block(to_block);

            let escrow_logs = self
                .provider
                .get_logs(&escrow_filter)
                .await
                .map_err(|e| format!("get_logs (escrows) failed: {e}"))?;

            for log in &escrow_logs {
                let escrow = to_eth_address(log.address());
                let Some(owner) = self.escrows.owner_of(escrow) else {
                    // Shouldn't happen: escrow_addresses came from the registry
                    // itself, but skip defensively rather than panic on a log
                    // from an address we don't actually recognize.
                    continue;
                };
                let block_number = log.block_number.unwrap_or(to_block);

                if let Ok(decoded) = log.log_decode::<Deposited>() {
                    let token = to_eth_address(decoded.inner.data.token);
                    let amount = decoded.inner.data.amount.to::<u128>();
                    events.push(ChainEvent::Deposited {
                        escrow,
                        trader: owner.trader,
                        offchain_pubkey: owner.offchain_pubkey,
                        token,
                        symbol: self.tokens.symbol_of(token).map(|s| s.to_string()),
                        amount,
                        block_number,
                    });
                } else if let Ok(decoded) = log.log_decode::<Withdrawn>() {
                    let token = to_eth_address(decoded.inner.data.token);
                    let amount = decoded.inner.data.amount.to::<u128>();
                    events.push(ChainEvent::Withdrawn {
                        escrow,
                        trader: owner.trader,
                        offchain_pubkey: owner.offchain_pubkey,
                        token,
                        symbol: self.tokens.symbol_of(token).map(|s| s.to_string()),
                        amount,
                        block_number,
                    });
                }
            }
        }

        self.last_synced_block = to_block;
        Ok(events)
    }
}

pub async fn http_provider(rpc_url: &str) -> Result<impl Provider + Clone, String> {
    let url = rpc_url
        .parse()
        .map_err(|e| format!("invalid RPC URL: {e}"))?;
    Ok(ProviderBuilder::new().connect_http(url))
}
