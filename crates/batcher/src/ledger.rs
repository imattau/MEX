use std::collections::HashMap;

// A self-contained, in-memory balance ledger keyed by (trader, symbol). This
// is NOT synced with real on-chain state -- there is currently no on-chain
// event listening or RPC connectivity anywhere in this codebase for it to
// sync against. Balances here only reflect deposits explicitly recorded via
// `deposit()` and trades settled through `SettlementBatcher`. Real balance
// enforcement for actual funds happens on-chain in TraderEscrow.
#[derive(Debug, Default)]
pub struct BalanceLedger {
    balances: HashMap<([u8; 32], String), u64>,
}

impl BalanceLedger {
    pub fn new() -> Self {
        Self {
            balances: HashMap::new(),
        }
    }

    pub fn balance_of(&self, trader: [u8; 32], symbol: &str) -> u64 {
        self.balances
            .get(&(trader, symbol.to_string()))
            .copied()
            .unwrap_or(0)
    }

    pub fn deposit(&mut self, trader: [u8; 32], symbol: &str, amount: u64) {
        *self.balances.entry((trader, symbol.to_string())).or_insert(0) += amount;
    }

    pub fn credit(&mut self, trader: [u8; 32], symbol: &str, amount: u64) {
        self.deposit(trader, symbol, amount);
    }

    pub fn debit(&mut self, trader: [u8; 32], symbol: &str, amount: u64) -> Result<(), String> {
        let key = (trader, symbol.to_string());
        let balance = self.balances.get(&key).copied().unwrap_or(0);
        if balance < amount {
            return Err(format!(
                "insufficient balance: have {}, need {}",
                balance, amount
            ));
        }
        self.balances.insert(key, balance - amount);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deposit_and_balance_of() {
        let mut ledger = BalanceLedger::new();
        let trader = [1u8; 32];
        assert_eq!(ledger.balance_of(trader, "BTC-USD"), 0);
        ledger.deposit(trader, "BTC-USD", 100);
        assert_eq!(ledger.balance_of(trader, "BTC-USD"), 100);
    }

    #[test]
    fn test_debit_insufficient_balance_fails() {
        let mut ledger = BalanceLedger::new();
        let trader = [1u8; 32];
        ledger.deposit(trader, "BTC-USD", 50);
        assert!(ledger.debit(trader, "BTC-USD", 100).is_err());
        assert_eq!(ledger.balance_of(trader, "BTC-USD"), 50);
    }

    #[test]
    fn test_debit_success_reduces_balance() {
        let mut ledger = BalanceLedger::new();
        let trader = [1u8; 32];
        ledger.deposit(trader, "BTC-USD", 100);
        assert!(ledger.debit(trader, "BTC-USD", 40).is_ok());
        assert_eq!(ledger.balance_of(trader, "BTC-USD"), 60);
    }

    #[test]
    fn test_balances_are_per_symbol() {
        let mut ledger = BalanceLedger::new();
        let trader = [1u8; 32];
        ledger.deposit(trader, "BTC-USD", 100);
        assert_eq!(ledger.balance_of(trader, "ETH-USD"), 0);
    }
}
