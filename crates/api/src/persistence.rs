// Stage P4-1: a durable write-ahead log for the accept -> apply/match
// stage of the pipeline (order_book, order_log, match_log,
// pending_commits, applied_order_ids -- see server::apply_accepted_order,
// the single choke point all of that state flows through today).
//
// Design: rather than snapshotting derived state (order_book's resting
// orders, the hash-chain logs, etc.) in some new format, this persists
// only the INPUTS apply_accepted_order was originally called with --
// (order, receipt, match_timestamp_us) -- in the exact order they were
// durably recorded. On boot, replaying those inputs back through the same
// deterministic core (engine::OrderBook::add_order_at is proven
// deterministic given identical order + timestamp, see Stage P3c-1's own
// tests) reproduces byte-identical order_book/order_log/match_log/
// pending_commits state with no separate snapshot format to keep in sync.
//
// A WAL entry is appended and fsynced (Tree::flush, blocking) BEFORE the
// order is applied to in-memory state -- see server::apply_accepted_order
// -- so a crash can never leave an order that was actually matched (and
// whose result a trader may already be relying on) unrecoverable. This
// does mean order throughput is bounded by disk fsync latency, since the
// write happens while the caller holds AppState's write lock; batching
// multiple orders per fsync is a real future optimization, out of scope
// here.

use common::Order;
use orderlog::OrderReceipt;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WalEntry {
    order: Order,
    receipt: OrderReceipt,
    match_timestamp_us: Option<u64>,
}

pub struct PersistenceLog {
    // sled::Db itself also holds the monotonic id-generator state
    // (see append's use of generate_id) that entries's own keys are
    // derived from -- kept alongside the named entries tree rather than
    // used directly as a tree, so a future stage (e.g. P4-2's batch-
    // submitted checkpoints) can add more named trees to the same
    // on-disk database without colliding with this one's keyspace.
    db: sled::Db,
    entries: sled::Tree,
}

impl PersistenceLog {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let db = sled::open(path).map_err(|e| e.to_string())?;
        let entries = db.open_tree("wal_entries").map_err(|e| e.to_string())?;
        Ok(Self { db, entries })
    }

    // Durably records that apply_accepted_order is about to run with
    // exactly these inputs. Blocks on fsync (Tree::flush) before
    // returning Ok -- the caller must not apply the order to in-memory
    // state until this returns Ok, or a crash between the two could
    // leave a real match unrecoverable.
    pub fn append(
        &self,
        order: &Order,
        receipt: &OrderReceipt,
        match_timestamp_us: Option<u64>,
    ) -> Result<(), String> {
        let seq = self.db.generate_id().map_err(|e| e.to_string())?;
        let entry = WalEntry {
            order: order.clone(),
            receipt: receipt.clone(),
            match_timestamp_us,
        };
        let bytes = serde_json::to_vec(&entry).map_err(|e| e.to_string())?;
        self.entries
            .insert(seq.to_be_bytes(), bytes)
            .map_err(|e| e.to_string())?;
        self.entries.flush().map_err(|e| e.to_string())?;
        Ok(())
    }

    // Every durably-recorded entry, in the exact order they were
    // originally appended (big-endian u64 keys from generate_id sort
    // correctly as bytes, and sled::Tree::iter walks keys in order).
    pub fn replay(&self) -> Result<Vec<(Order, OrderReceipt, Option<u64>)>, String> {
        let mut out = Vec::new();
        for kv in self.entries.iter() {
            let (_, v) = kv.map_err(|e| e.to_string())?;
            let entry: WalEntry = serde_json::from_slice(&v).map_err(|e| e.to_string())?;
            out.push((entry.order, entry.receipt, entry.match_timestamp_us));
        }
        Ok(out)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{OrderSide, SettlementPreference, SettlementRequester};

    fn make_order(seed: u8) -> Order {
        Order {
            id: [seed; 32],
            trader: [seed; 32],
            symbol: "ETH-USD".to_string(),
            side: OrderSide::Buy,
            price: 3000,
            amount: 10,
            signature: vec![],
            nonce: seed as u64,
            expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        }
    }

    fn make_receipt(order: &Order) -> OrderReceipt {
        OrderReceipt {
            order_id: order.id,
            trader: order.trader,
            symbol: order.symbol.clone(),
            side: order.side,
            price: order.price,
            amount: order.amount,
            nonce: order.nonce,
            expiry: order.expiry,
            settlement_preference: order.settlement_preference,
            settlement_requester: order.settlement_requester,
            received_at_us: 0,
            node_pubkey: [0u8; 32],
            signature: vec![],
        }
    }

    #[test]
    fn test_replay_returns_entries_in_append_order() {
        let dir = tempfile::tempdir().unwrap();
        let log = PersistenceLog::open(dir.path()).unwrap();

        for seed in 1..=5u8 {
            let order = make_order(seed);
            let receipt = make_receipt(&order);
            log.append(&order, &receipt, Some(seed as u64 * 100))
                .unwrap();
        }

        let replayed = log.replay().unwrap();
        assert_eq!(replayed.len(), 5);
        for (i, (order, _receipt, ts)) in replayed.iter().enumerate() {
            let seed = (i + 1) as u8;
            assert_eq!(
                order.id, [seed; 32],
                "replay must preserve original append order"
            );
            assert_eq!(*ts, Some(seed as u64 * 100));
        }
    }

    #[test]
    fn test_replay_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let log = PersistenceLog::open(dir.path()).unwrap();
            let order = make_order(9);
            let receipt = make_receipt(&order);
            log.append(&order, &receipt, None).unwrap();
        }
        // Reopen fresh, as a real restart would.
        let log = PersistenceLog::open(dir.path()).unwrap();
        let replayed = log.replay().unwrap();
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].0.id, [9u8; 32]);
    }
}
