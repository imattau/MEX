use lru::LruCache;

#[derive(Hash, PartialEq, Eq, Clone)]
pub struct ValidationKey {
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}

pub struct OrderValidator {
    pub cache: LruCache<ValidationKey, bool>,
}
