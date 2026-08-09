#[cfg(test)]
mod tests {
    use common::{Order, OrderSide, SettlementPreference, SettlementRequester};
    use ed25519_dalek::Signer;
    use rand::rngs::OsRng;
    use sandbox::WasmSandbox;
    use security::{decrypt_packet, encrypt_packet};
    use validation::OrderValidator;

    #[test]
    fn test_signature_tampering_and_cache_bypass() {
        let mut csprng = OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let trader_bytes = signing_key.verifying_key().to_bytes();

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
        order.signature = signing_key.sign(&msg).to_vec();

        let mut validator = OrderValidator::new(100);

        // 1. Valid order passes
        assert!(validator.validate_order(&order));

        // 2. Tampering a parameter fails validation
        let mut tampered_price = order.clone();
        tampered_price.price = 3001;
        assert!(!validator.validate_order(&tampered_price));

        // 3. Re-using the signature with a modified nonce fails validation (Replay check)
        let mut replayed_nonce = order.clone();
        replayed_nonce.nonce = 43;
        assert!(!validator.validate_order(&replayed_nonce));
    }

    #[test]
    fn test_identity_keys_rejected() {
        let order = Order {
            id: [0u8; 32],
            trader: [0u8; 32], // Zero public key
            symbol: "ETH-USD".to_string(),
            side: OrderSide::Buy,
            price: 3000,
            amount: 5,
            signature: vec![0u8; 64], // Zero signature
            nonce: 999,
            expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };

        let mut validator = OrderValidator::new(100);
        // Explicitly rejected
        assert!(!validator.validate_order(&order));
    }

    #[test]
    fn test_ciphertext_tampering_fails() {
        let key = [0xAAu8; 32];
        let payload = b"Sensitive matching engine trace details";

        let encrypted = encrypt_packet(&key, payload).unwrap();

        // Tamper with a single byte in the ciphertext payload
        let mut tampered_encrypted = encrypted.clone();
        if let Some(byte) = tampered_encrypted.get_mut(12) {
            *byte ^= 0x01; // flip a bit
        }

        // Decryption must fail due to AEAD tag verification failure
        let decrypt_result = decrypt_packet(&key, &tampered_encrypted);
        assert!(decrypt_result.is_err());
    }

    #[test]
    fn test_sandbox_runaway_fuel_limit() {
        // Simple WAT strategy attempting a runaway infinite loop
        let wat = r#"
            (module
                (func (export "on_tick") (result i32)
                    (loop
                        (br 0)
                    )
                    (i32.const 0)
                )
            )
        "#;

        let sandbox = WasmSandbox::new().unwrap();
        let result = sandbox.execute_strategy(wat, 1000);

        // Runaway execution must be aborted cleanly
        assert!(result.is_err());
    }
}
