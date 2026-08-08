use std::collections::HashMap;

// Ethereum account/contract address (20 bytes). Not to be confused with the
// [u8; 32] ed25519 pubkey used to identify traders in the off-chain matching
// engine/ledger -- there is currently no mapping between the two anywhere in
// this codebase. See EscrowRegistry's docs for why that matters.
pub type EthAddress = [u8; 20];

// Maps ERC20 token contract addresses to the symbol used by the off-chain
// ledger/matching engine (e.g. "BTC-USD"). There is no on-chain registry of
// this mapping -- TraderEscrow just tracks balances per raw token address --
// so it has to be populated from static config wherever this is wired up.
#[derive(Debug, Default, Clone)]
pub struct TokenRegistry {
    by_address: HashMap<EthAddress, String>,
}

impl TokenRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, token: EthAddress, symbol: &str) {
        self.by_address.insert(token, symbol.to_string());
    }

    pub fn symbol_of(&self, token: EthAddress) -> Option<&str> {
        self.by_address.get(&token).map(|s| s.as_str())
    }
}

// The owner of a TraderEscrow: its Ethereum account, and the off-chain
// ed25519 pubkey it was bound to at creation time (see
// SettlementFactory.createEscrow / TraderEscrow.offchainPubkey in the
// Solidity contracts). Binding happens once, self-service, at escrow
// creation -- there is no separate registration step or rebind path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EscrowOwner {
    pub trader: EthAddress,
    pub offchain_pubkey: [u8; 32],
}

// Maps each trader's per-trader TraderEscrow contract address to its owner,
// built from SettlementFactory's
// EscrowCreated(trader, escrowAddress, offchainPubkey) events -- that's the
// only place this association exists; TraderEscrow's own Deposited/Withdrawn
// events don't carry the trader's address at all (each trader gets a
// distinct escrow contract instance, so the trader is identified by which
// contract emitted the event, not by an event field).
#[derive(Debug, Default, Clone)]
pub struct EscrowRegistry {
    owner_of_escrow: HashMap<EthAddress, EscrowOwner>,
}

impl EscrowRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_escrow_created(
        &mut self,
        trader: EthAddress,
        escrow: EthAddress,
        offchain_pubkey: [u8; 32],
    ) {
        self.owner_of_escrow.insert(
            escrow,
            EscrowOwner {
                trader,
                offchain_pubkey,
            },
        );
    }

    pub fn owner_of(&self, escrow: EthAddress) -> Option<EscrowOwner> {
        self.owner_of_escrow.get(&escrow).copied()
    }

    pub fn known_escrows(&self) -> impl Iterator<Item = &EthAddress> {
        self.owner_of_escrow.keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> EthAddress {
        [byte; 20]
    }

    #[test]
    fn test_token_registry_round_trip() {
        let mut reg = TokenRegistry::new();
        let token = addr(1);
        assert_eq!(reg.symbol_of(token), None);
        reg.register(token, "BTC-USD");
        assert_eq!(reg.symbol_of(token), Some("BTC-USD"));
    }

    #[test]
    fn test_token_registry_unknown_address() {
        let reg = TokenRegistry::new();
        assert_eq!(reg.symbol_of(addr(99)), None);
    }

    fn pubkey(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn test_escrow_registry_records_and_resolves() {
        let mut reg = EscrowRegistry::new();
        let trader = addr(1);
        let escrow = addr(2);
        let pk = pubkey(0xAA);
        assert_eq!(reg.owner_of(escrow), None);
        reg.record_escrow_created(trader, escrow, pk);
        assert_eq!(
            reg.owner_of(escrow),
            Some(EscrowOwner {
                trader,
                offchain_pubkey: pk
            })
        );
    }

    #[test]
    fn test_escrow_registry_known_escrows() {
        let mut reg = EscrowRegistry::new();
        reg.record_escrow_created(addr(1), addr(10), pubkey(1));
        reg.record_escrow_created(addr(2), addr(20), pubkey(2));

        let mut escrows: Vec<EthAddress> = reg.known_escrows().copied().collect();
        escrows.sort();
        assert_eq!(escrows, vec![addr(10), addr(20)]);
    }

    #[test]
    fn test_escrow_registry_distinct_traders_distinct_escrows() {
        let mut reg = EscrowRegistry::new();
        let escrow_a = addr(10);
        let escrow_b = addr(11);
        reg.record_escrow_created(addr(1), escrow_a, pubkey(1));
        reg.record_escrow_created(addr(2), escrow_b, pubkey(2));

        assert_eq!(reg.owner_of(escrow_a).unwrap().trader, addr(1));
        assert_eq!(reg.owner_of(escrow_b).unwrap().trader, addr(2));
    }
}
