use crate::listener::ChainEvent;
use batcher::BalanceLedger;

// Applies a chain event observed by ChainSync to the off-chain BalanceLedger.
//
// Two things can stop an event from being applied, and both are logged
// rather than silently dropped or (worse) silently misapplied:
//   - The token has no known symbol (see TokenRegistry) -- the ledger has no
//     way to credit/debit an asset it can't name.
//   - The amount doesn't fit in the ledger's u64 balance. On-chain amounts
//     are u128 (e.g. wei, 18 decimals: anything above ~18.4 ETH already
//     overflows u64), so this is a real, expected limitation of the current
//     ledger model, not an edge case -- truncating instead of rejecting
//     would silently misrepresent real funds.
pub fn apply_event(ledger: &mut BalanceLedger, event: &ChainEvent) {
    match event {
        ChainEvent::EscrowCreated { .. } => {
            // No ledger effect -- EscrowRegistry already tracked this in
            // ChainSync itself.
        }
        ChainEvent::Deposited {
            offchain_pubkey,
            symbol,
            amount,
            ..
        } => {
            apply_credit(ledger, *offchain_pubkey, symbol.as_deref(), *amount);
        }
        ChainEvent::Withdrawn {
            offchain_pubkey,
            symbol,
            amount,
            ..
        } => {
            apply_debit(ledger, *offchain_pubkey, symbol.as_deref(), *amount);
        }
    }
}

fn resolve_amount(symbol: Option<&str>, amount: u128, kind: &str) -> Option<(String, u64)> {
    let Some(symbol) = symbol else {
        tracing::warn!(kind, "chain event for unknown token, skipping (not in TokenRegistry)");
        return None;
    };
    let Ok(amount_u64) = u64::try_from(amount) else {
        tracing::warn!(
            kind,
            amount,
            "chain event amount does not fit in ledger's u64 balance, skipping"
        );
        return None;
    };
    Some((symbol.to_string(), amount_u64))
}

fn apply_credit(ledger: &mut BalanceLedger, trader: [u8; 32], symbol: Option<&str>, amount: u128) {
    let Some((symbol, amount)) = resolve_amount(symbol, amount, "deposit") else {
        return;
    };
    ledger.credit(trader, &symbol, amount);
}

fn apply_debit(ledger: &mut BalanceLedger, trader: [u8; 32], symbol: Option<&str>, amount: u128) {
    let Some((symbol, amount)) = resolve_amount(symbol, amount, "withdrawal") else {
        return;
    };
    if let Err(error) = ledger.debit(trader, &symbol, amount) {
        // The chain says this withdrawal happened; if the ledger doesn't
        // have enough balance to match, the ledger has desynced from real
        // on-chain state (e.g. it missed an earlier deposit). Debit floors
        // at 0 rather than going negative or panicking -- see BalanceLedger.
        tracing::warn!(error, "ledger desynced from chain: withdrawal debit failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn test_deposit_credits_ledger() {
        let mut ledger = BalanceLedger::new();
        let trader = pk(1);
        apply_event(
            &mut ledger,
            &ChainEvent::Deposited {
                escrow: [0u8; 20],
                trader: [0u8; 20],
                offchain_pubkey: trader,
                token: [0u8; 20],
                symbol: Some("ETH-USD".to_string()),
                amount: 1_000,
                block_number: 1,
            },
        );
        assert_eq!(ledger.balance_of(trader, "ETH-USD"), 1_000);
    }

    #[test]
    fn test_withdrawal_debits_ledger() {
        let mut ledger = BalanceLedger::new();
        let trader = pk(1);
        ledger.deposit(trader, "ETH-USD", 1_000);

        apply_event(
            &mut ledger,
            &ChainEvent::Withdrawn {
                escrow: [0u8; 20],
                trader: [0u8; 20],
                offchain_pubkey: trader,
                token: [0u8; 20],
                symbol: Some("ETH-USD".to_string()),
                amount: 400,
                block_number: 2,
            },
        );
        assert_eq!(ledger.balance_of(trader, "ETH-USD"), 600);
    }

    #[test]
    fn test_deposit_with_unknown_symbol_is_skipped() {
        let mut ledger = BalanceLedger::new();
        let trader = pk(1);
        apply_event(
            &mut ledger,
            &ChainEvent::Deposited {
                escrow: [0u8; 20],
                trader: [0u8; 20],
                offchain_pubkey: trader,
                token: [0u8; 20],
                symbol: None,
                amount: 1_000,
                block_number: 1,
            },
        );
        assert_eq!(ledger.balance_of(trader, "ETH-USD"), 0);
    }

    #[test]
    fn test_deposit_amount_too_large_for_u64_is_skipped() {
        let mut ledger = BalanceLedger::new();
        let trader = pk(1);
        apply_event(
            &mut ledger,
            &ChainEvent::Deposited {
                escrow: [0u8; 20],
                trader: [0u8; 20],
                offchain_pubkey: trader,
                token: [0u8; 20],
                symbol: Some("ETH-USD".to_string()),
                amount: u128::from(u64::MAX) + 1,
                block_number: 1,
            },
        );
        assert_eq!(ledger.balance_of(trader, "ETH-USD"), 0);
    }

    #[test]
    fn test_withdrawal_exceeding_balance_does_not_panic_or_underflow() {
        let mut ledger = BalanceLedger::new();
        let trader = pk(1);
        ledger.deposit(trader, "ETH-USD", 100);

        apply_event(
            &mut ledger,
            &ChainEvent::Withdrawn {
                escrow: [0u8; 20],
                trader: [0u8; 20],
                offchain_pubkey: trader,
                token: [0u8; 20],
                symbol: Some("ETH-USD".to_string()),
                amount: 500,
                block_number: 2,
            },
        );
        // Debit fails internally (insufficient balance) and is logged as a
        // desync rather than applied -- balance is left untouched.
        assert_eq!(ledger.balance_of(trader, "ETH-USD"), 100);
    }

    #[test]
    fn test_escrow_created_has_no_ledger_effect() {
        let mut ledger = BalanceLedger::new();
        let trader = pk(1);
        apply_event(
            &mut ledger,
            &ChainEvent::EscrowCreated {
                trader: [0u8; 20],
                escrow: [0u8; 20],
                offchain_pubkey: trader,
            },
        );
        assert_eq!(ledger.balance_of(trader, "ETH-USD"), 0);
    }
}
