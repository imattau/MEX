use lru::LruCache;
use std::collections::HashMap;

#[derive(Hash, PartialEq, Eq, Clone)]
pub struct ValidationKey {
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}

pub struct OrderValidator {
    pub cache: LruCache<ValidationKey, bool>,
    pub nonces: HashMap<[u8; 32], u64>,
}
