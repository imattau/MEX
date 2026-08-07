#[cfg(test)]
mod tests {
    use crate::types::OrderValidator;
    use common::{Order, OrderSide, SettlementPreference, SettlementRequester};
    use ed25519_dalek::Signer;
    use rand::rngs::OsRng;

    #[test]
    fn test_signature_verification_and_cache() {
        let mut csprng = OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let trader_bytes = verifying_key.to_bytes();

        let mut order = Order {
            id: [0u8; 32],
            trader: trader_bytes,
            symbol: "ETH-USD".to_string(),
            side: OrderSide::Buy,
            price: 3000,
            amount: 5,
            signature: Vec::new(),
            nonce: 42,
            expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };

        let msg = OrderValidator::serialize_order_message(&order);
        let signature = signing_key.sign(&msg);
        order.signature = signature.to_vec();

        let mut validator = OrderValidator::new(100);

        assert!(validator.validate_order(&order));

        let mut order2 = order.clone();
        order2.nonce = 43;
        let msg2 = OrderValidator::serialize_order_message(&order2);
        order2.signature = signing_key.sign(&msg2).to_vec();

        assert!(validator.validate_order(&order2));

        let mut tampered_order = order.clone();
        tampered_order.price = 3001;
        assert!(!validator.validate_order(&tampered_order));

        let mut low_nonce = order.clone();
        low_nonce.nonce = 41;
        let msg3 = OrderValidator::serialize_order_message(&low_nonce);
        low_nonce.signature = signing_key.sign(&msg3).to_vec();
        assert!(!validator.validate_order(&low_nonce),
            "Nonce sequencing blocks lower nonces");
    }

    #[test]
    fn test_zero_verification() {
        use ed25519_dalek::Verifier;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&[0u8; 32]);
        println!("VERIFYING KEY: {:?}", verifying_key);
        if let Ok(key) = verifying_key {
            let sig = ed25519_dalek::Signature::from_slice(&[0u8; 64]).unwrap();
            let res = key.verify(b"hello", &sig);
            println!("RESULT: {:?}", res);
        }
    }

    #[test]
    fn test_serialized_zero_verification() {
        use crate::types::OrderValidator;
        use common::OrderSide;
        use ed25519_dalek::Verifier;

        let order = Order {
            id: [0u8; 32],
            trader: [0u8; 32],
            symbol: "ETH-USD".to_string(),
            side: OrderSide::Buy,
            price: 3000,
            amount: 5,
            signature: vec![0u8; 64],
            nonce: 999,
            expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };

        let msg = OrderValidator::serialize_order_message(&order);
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&order.trader).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&order.signature).unwrap();
        let res = verifying_key.verify(&msg, &sig);
        println!("SERIALIZED ZERO VERIFY RESULT: {:?}", res);
    }
}
