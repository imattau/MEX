use crate::listener::ChainEvent;
use sled::{Batch, Db};
use std::path::Path;

const LAST_SYNCED_BLOCK_KEY: &[u8] = b"__last_synced_block__";
const EVENT_SEQ_KEY: &[u8] = b"__event_seq__";
const EVENT_PREFIX: &[u8] = b"event:";

// Persists ChainSync's progress so a restart can resume from where it left
// off instead of rescanning the whole chain from genesis: the watermark
// (last_synced_block) and every event observed so far, which on startup gets
// replayed to reconstruct BalanceLedger and ChainSync's EscrowRegistry.
pub struct SyncStore {
    db: Db,
}

impl SyncStore {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let db = sled::open(path).map_err(|e| format!("sled open failed: {e}"))?;
        Ok(Self { db })
    }

    pub fn last_synced_block(&self) -> Result<Option<u64>, String> {
        let value = self
            .db
            .get(LAST_SYNCED_BLOCK_KEY)
            .map_err(|e| format!("get failed: {e}"))?;
        Ok(value
            .and_then(|v| <[u8; 8]>::try_from(v.as_ref()).ok())
            .map(u64::from_be_bytes))
    }

    // Persists `events` and advances the watermark to `synced_through` in a
    // single atomic sled batch, so a crash between polls can never leave the
    // event log and the watermark disagreeing with each other -- either both
    // land, or neither does and the next run just re-polls (and re-persists)
    // the same, deterministic on-chain range.
    pub fn record_batch(&self, events: &[ChainEvent], synced_through: u64) -> Result<(), String> {
        if events.is_empty() {
            self.db
                .insert(LAST_SYNCED_BLOCK_KEY, &synced_through.to_be_bytes())
                .map_err(|e| format!("insert failed: {e}"))?;
            self.db.flush().map_err(|e| format!("flush failed: {e}"))?;
            return Ok(());
        }

        let mut next_seq = self.next_event_seq()?;
        let mut batch = Batch::default();

        for event in events {
            let value =
                serde_json::to_vec(event).map_err(|e| format!("serialize failed: {e}"))?;
            let mut key = EVENT_PREFIX.to_vec();
            key.extend_from_slice(&next_seq.to_be_bytes());
            batch.insert(key, value);
            next_seq += 1;
        }
        batch.insert(EVENT_SEQ_KEY, &next_seq.to_be_bytes());
        batch.insert(LAST_SYNCED_BLOCK_KEY, &synced_through.to_be_bytes());

        self.db
            .apply_batch(batch)
            .map_err(|e| format!("apply_batch failed: {e}"))?;
        self.db.flush().map_err(|e| format!("flush failed: {e}"))?;
        Ok(())
    }

    fn next_event_seq(&self) -> Result<u64, String> {
        let value = self
            .db
            .get(EVENT_SEQ_KEY)
            .map_err(|e| format!("get failed: {e}"))?;
        Ok(value
            .and_then(|v| <[u8; 8]>::try_from(v.as_ref()).ok())
            .map(u64::from_be_bytes)
            .unwrap_or(0))
    }

    // Every persisted event, in the order they were recorded.
    pub fn all_events(&self) -> Result<Vec<ChainEvent>, String> {
        self.db
            .scan_prefix(EVENT_PREFIX)
            .map(|item| {
                let (_key, value) = item.map_err(|e| format!("scan failed: {e}"))?;
                serde_json::from_slice::<ChainEvent>(&value)
                    .map_err(|e| format!("deserialize failed: {e}"))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deposit_event(seed: u8, amount: u128) -> ChainEvent {
        ChainEvent::Deposited {
            escrow: [seed; 20],
            trader: [seed; 20],
            offchain_pubkey: [seed; 32],
            token: [0u8; 20],
            symbol: Some("ETH-USD".to_string()),
            amount,
            block_number: seed as u64,
        }
    }

    #[test]
    fn test_last_synced_block_defaults_to_none() {
        let dir = tempfile::tempdir().unwrap();
        let store = SyncStore::open(dir.path()).unwrap();
        assert_eq!(store.last_synced_block().unwrap(), None);
    }

    #[test]
    fn test_record_batch_persists_watermark_and_events() {
        let dir = tempfile::tempdir().unwrap();
        let store = SyncStore::open(dir.path()).unwrap();

        let events = vec![deposit_event(1, 100), deposit_event(2, 200)];
        store.record_batch(&events, 42).unwrap();

        assert_eq!(store.last_synced_block().unwrap(), Some(42));
        assert_eq!(store.all_events().unwrap(), events);
    }

    #[test]
    fn test_record_batch_appends_across_calls() {
        let dir = tempfile::tempdir().unwrap();
        let store = SyncStore::open(dir.path()).unwrap();

        store.record_batch(&[deposit_event(1, 100)], 10).unwrap();
        store.record_batch(&[deposit_event(2, 200)], 20).unwrap();

        assert_eq!(store.last_synced_block().unwrap(), Some(20));
        assert_eq!(
            store.all_events().unwrap(),
            vec![deposit_event(1, 100), deposit_event(2, 200)]
        );
    }

    #[test]
    fn test_empty_batch_still_advances_watermark() {
        let dir = tempfile::tempdir().unwrap();
        let store = SyncStore::open(dir.path()).unwrap();

        store.record_batch(&[], 5).unwrap();

        assert_eq!(store.last_synced_block().unwrap(), Some(5));
        assert_eq!(store.all_events().unwrap(), Vec::new());
    }

    #[test]
    fn test_reopen_recovers_persisted_state() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = SyncStore::open(dir.path()).unwrap();
            store.record_batch(&[deposit_event(1, 100)], 7).unwrap();
        }
        let reopened = SyncStore::open(dir.path()).unwrap();
        assert_eq!(reopened.last_synced_block().unwrap(), Some(7));
        assert_eq!(reopened.all_events().unwrap(), vec![deposit_event(1, 100)]);
    }
}
