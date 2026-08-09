use crate::adapter::{account_to_address, token_to_address};
use alloy::primitives::{keccak256, FixedBytes, U256};
use alloy::sol;
use alloy::sol_types::SolValue;
use chain::SettlementTrade;

sol! {
    // Not a real on-chain type -- nothing currently recomputes/validates
    // trade_hash against this (TraderEscrow just stores whatever bytes32
    // the trader supplies). Declaring it via sol! anyway, and hashing its
    // abi_encode() output, gives a standard, canonical, ABI-compatible
    // commitment that could be reproduced by a Solidity keccak256(abi.encode(...))
    // call later if on-chain verification is ever added, without needing a
    // new hashing scheme at that point.
    struct TradeCommitment {
        bytes32 makerOrderId;
        bytes32 takerOrderId;
        address trader;
        address counterparty;
        address token;
        uint256 amount;
        uint256 fee;
        uint256 deadline;
        bytes32 assignedNode;
    }
}

// Derives the canonical tradeHash for a trade's commit-time terms. Both the
// trader (calling commitTrade) and infra (later matching it up for
// settleBatchWithFees/claimSlash) must derive the exact same hash from the
// exact same terms -- this is the single shared implementation both sides
// call, rather than each independently reinventing a packing scheme that
// could subtly disagree.
//
// Binds every field that defines what was actually agreed (not just enough
// fields to make the hash unique): maker_order_id/taker_order_id trace it
// back to the specific off-chain match; trader/counterparty/token/amount/
// fee/deadline/assigned_node are exactly what commitTrade records. Changing
// any one of them changes the hash, so it functions as a real commitment,
// not just a dedup key.
pub fn compute_trade_hash(trade: &SettlementTrade) -> Result<[u8; 32], String> {
    let commitment = TradeCommitment {
        makerOrderId: FixedBytes::from(trade.maker_order_id),
        takerOrderId: FixedBytes::from(trade.taker_order_id),
        trader: account_to_address(trade.trader)?,
        counterparty: account_to_address(trade.counterparty)?,
        token: token_to_address(&trade.token)?,
        amount: U256::from(trade.amount),
        fee: U256::from(trade.fee),
        deadline: U256::from(trade.deadline),
        assignedNode: FixedBytes::from(trade.assigned_node),
    };
    Ok(keccak256(commitment.abi_encode()).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_trade() -> SettlementTrade {
        SettlementTrade {
            maker_order_id: [1u8; 32],
            taker_order_id: [2u8; 32],
            trader: {
                let mut a = [0u8; 32];
                a[12..].copy_from_slice(&[0xAAu8; 20]);
                a
            },
            counterparty: {
                let mut a = [0u8; 32];
                a[12..].copy_from_slice(&[0xBBu8; 20]);
                a
            },
            token: chain::Token::Native,
            amount: 1_000_000_000_000_000_000,
            fee: 1_000,
            deadline: 1_800_000_000,
            trade_hash: [0u8; 32],
            assigned_node: [0xCCu8; 32],
        }
    }

    #[test]
    fn test_deterministic_same_input_same_hash() {
        let trade = sample_trade();
        let h1 = compute_trade_hash(&trade).unwrap();
        let h2 = compute_trade_hash(&trade).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_sensitive_to_every_field() {
        let base = sample_trade();
        let base_hash = compute_trade_hash(&base).unwrap();

        let mut t = base.clone();
        t.maker_order_id = [9u8; 32];
        assert_ne!(compute_trade_hash(&t).unwrap(), base_hash, "maker_order_id");

        let mut t = base.clone();
        t.taker_order_id = [9u8; 32];
        assert_ne!(compute_trade_hash(&t).unwrap(), base_hash, "taker_order_id");

        let mut t = base.clone();
        t.trader[31] ^= 0xFF;
        assert_ne!(compute_trade_hash(&t).unwrap(), base_hash, "trader");

        let mut t = base.clone();
        t.counterparty[31] ^= 0xFF;
        assert_ne!(compute_trade_hash(&t).unwrap(), base_hash, "counterparty");

        let mut t = base.clone();
        t.amount += 1;
        assert_ne!(compute_trade_hash(&t).unwrap(), base_hash, "amount");

        let mut t = base.clone();
        t.fee += 1;
        assert_ne!(compute_trade_hash(&t).unwrap(), base_hash, "fee");

        let mut t = base.clone();
        t.deadline += 1;
        assert_ne!(compute_trade_hash(&t).unwrap(), base_hash, "deadline");

        let mut t = base.clone();
        t.assigned_node[31] ^= 0xFF;
        assert_ne!(compute_trade_hash(&t).unwrap(), base_hash, "assigned_node");

        // trade_hash itself is the output, not an input -- changing it must
        // NOT change what compute_trade_hash derives from the same terms.
        let mut t = base.clone();
        t.trade_hash = [0xFFu8; 32];
        assert_eq!(
            compute_trade_hash(&t).unwrap(),
            base_hash,
            "trade_hash field itself must not affect derivation"
        );
    }

    #[test]
    fn test_rejects_invalid_account_encoding() {
        let mut trade = sample_trade();
        // Not left-zero-padded -- account_to_address must reject this
        // rather than silently truncating to a wrong address.
        trade.trader = [0xAAu8; 32];
        assert!(compute_trade_hash(&trade).is_err());
    }
}
