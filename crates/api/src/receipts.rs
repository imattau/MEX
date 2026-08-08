// Independent, trader-verifiable proof of when this server received a
// given order -- signed BEFORE matching happens, so the operator can't
// choose a timestamp to fit whatever match order it already produced.
// This alone doesn't stop front-running (see server.rs's docs on
// submit_order for the full picture); it turns an unfalsifiable dispute
// ("you delayed my order") into an auditable one, and is the timestamped
// unit crates/orderlog's hash chain will be built from.
use common::OrderSide;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderReceipt {
    pub order_id: [u8; 32],
    pub trader: [u8; 32],
    pub symbol: String,
    pub side: OrderSide,
    pub price: u64,
    pub amount: u64,
    pub nonce: u64,
    pub expiry: u64,
    // Wall-clock microseconds when this server received the order, set by
    // sign_receipt itself (never caller-supplied) -- see this module's
    // top docs for why the ordering (sign before match) matters.
    pub received_at_us: u64,
    pub node_pubkey: [u8; 32],
    pub signature: Vec<u8>,
}

// Canonical byte layout signed over -- fixed-width fields plus order_id/
// trader (both already 32 bytes) give unambiguous field boundaries without
// needing a length prefix on `symbol`, matching the convention already
// used for off-chain order signatures elsewhere in this codebase (see
// trader-client's serialize_order_message).
fn receipt_message(
    order_id: [u8; 32],
    trader: [u8; 32],
    symbol: &str,
    side: OrderSide,
    price: u64,
    amount: u64,
    nonce: u64,
    expiry: u64,
    received_at_us: u64,
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&order_id);
    msg.extend_from_slice(&trader);
    msg.extend_from_slice(symbol.as_bytes());
    msg.push(match side {
        OrderSide::Buy => 0u8,
        OrderSide::Sell => 1u8,
    });
    msg.extend_from_slice(&price.to_be_bytes());
    msg.extend_from_slice(&amount.to_be_bytes());
    msg.extend_from_slice(&nonce.to_be_bytes());
    msg.extend_from_slice(&expiry.to_be_bytes());
    msg.extend_from_slice(&received_at_us.to_be_bytes());
    msg
}

#[allow(clippy::too_many_arguments)]
pub fn sign_receipt(
    signing_key: &SigningKey,
    order_id: [u8; 32],
    trader: [u8; 32],
    symbol: &str,
    side: OrderSide,
    price: u64,
    amount: u64,
    nonce: u64,
    expiry: u64,
) -> OrderReceipt {
    let received_at_us = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64;

    let msg = receipt_message(order_id, trader, symbol, side, price, amount, nonce, expiry, received_at_us);
    let signature = signing_key.sign(&msg);

    OrderReceipt {
        order_id,
        trader,
        symbol: symbol.to_string(),
        side,
        price,
        amount,
        nonce,
        expiry,
        received_at_us,
        node_pubkey: signing_key.verifying_key().to_bytes(),
        signature: signature.to_bytes().to_vec(),
    }
}

// Independent of this server -- a trader (or third-party auditor) verifies
// a receipt entirely from its own fields plus the node's known pubkey,
// with no need to trust or query this server again.
pub fn verify_receipt(receipt: &OrderReceipt) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(&receipt.node_pubkey) else {
        return false;
    };
    let Ok(sig_bytes) = <[u8; 64]>::try_from(receipt.signature.as_slice()) else {
        return false;
    };
    let signature = Signature::from_bytes(&sig_bytes);
    let msg = receipt_message(
        receipt.order_id,
        receipt.trader,
        &receipt.symbol,
        receipt.side,
        receipt.price,
        receipt.amount,
        receipt.nonce,
        receipt.expiry,
        receipt.received_at_us,
    );
    verifying_key.verify(&msg, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let receipt = sign_receipt(
            &signing_key,
            [1u8; 32],
            [2u8; 32],
            "ETH-USD",
            OrderSide::Buy,
            3000,
            1,
            42,
            9999,
        );
        assert!(verify_receipt(&receipt));
    }

    #[test]
    fn test_tampered_receipt_fails_verification() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let mut receipt = sign_receipt(
            &signing_key,
            [1u8; 32],
            [2u8; 32],
            "ETH-USD",
            OrderSide::Buy,
            3000,
            1,
            42,
            9999,
        );
        receipt.price = 4000; // operator tries to rewrite the receipt after the fact
        assert!(!verify_receipt(&receipt));
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let other_key = SigningKey::generate(&mut OsRng);
        let mut receipt = sign_receipt(
            &signing_key,
            [1u8; 32],
            [2u8; 32],
            "ETH-USD",
            OrderSide::Buy,
            3000,
            1,
            42,
            9999,
        );
        receipt.node_pubkey = other_key.verifying_key().to_bytes(); // operator claims a different signer
        assert!(!verify_receipt(&receipt));
    }
}
