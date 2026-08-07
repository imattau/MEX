use crate::types::{OrderValidator, ValidationKey};
use common::Order;
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::time::{SystemTime, UNIX_EPOCH};
use lru::LruCache;

impl OrderValidator {
    pub fn new(cache_size: usize) -> Self {
        let cap = NonZeroUsize::new(cache_size).unwrap_or(NonZeroUsize::new(1000).unwrap());
        Self {
            cache: LruCache::new(cap),
            nonces: HashMap::new(),
        }
    }

    pub fn serialize_order_message(order: &Order) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&order.id);
        msg.extend_from_slice(&order.trader);
        msg.extend_from_slice(order.symbol.as_bytes());
        msg.extend_from_slice(&order.price.to_be_bytes());
        msg.extend_from_slice(&order.amount.to_be_bytes());
        msg.extend_from_slice(&order.nonce.to_be_bytes());
        msg.extend_from_slice(&order.expiry.to_be_bytes());
        msg
    }

    pub fn validate_order(&mut self, order: &Order) -> bool {
        if order.amount == 0 {
            return false;
        }

        let max_value = order.amount as u128 * order.price as u128;
        if max_value > u64::MAX as u128 {
            return false;
        }

        if order.expiry > 0 {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now > order.expiry {
                return false;
            }
        }

        if let Some(&last_nonce) = self.nonces.get(&order.trader) {
            if order.nonce <= last_nonce {
                return false;
            }
        }

        if order.signature.is_empty() || order.trader == [0u8; 32] {
            return false;
        }

        let msg = Self::serialize_order_message(order);
        let key = ValidationKey {
            message: msg.clone(),
            signature: order.signature.clone(),
        };

        if self.cache.contains(&key) {
            return false;
        }

        let verifying_key = match VerifyingKey::from_bytes(&order.trader) {
            Ok(key) => key,
            Err(_) => return false,
        };

        let signature = match Signature::from_slice(&order.signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        let is_valid = verifying_key.verify(&msg, &signature).is_ok();

        if is_valid {
            self.cache.put(key, false);
            self.nonces.insert(order.trader, order.nonce);
        }

        is_valid
    }
}
