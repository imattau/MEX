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
// Stage P4-2 extends the same log to the confirm -> batch -> settle
// stage (pending_commits exiting, confirmed_trade_hashes, the batcher's
// internal queues). That stage has a real state machine with an
// IRREVERSIBLE external side effect in the middle -- the on-chain
// submit_settlement_batch call -- so it can't just replay inputs through
// a pure function the way Stage P4-1's does; it also needs to know which
// confirmations were already fully settled before a crash, so replay
// doesn't attempt a duplicate on-chain submission. WalEntry::
// BatchSubmitted is that checkpoint. See server::replay_persistence_log
// for how the two entry kinds are reconciled during replay.
//
// A WAL entry is appended and fsynced (Tree::flush, blocking) BEFORE the
// corresponding state transition is applied -- see
// server::apply_accepted_order and server::confirm_committed -- so a
// crash can never leave an order or a confirmation that already took
// effect (and that a trader may already be relying on) unrecoverable.
// This does mean throughput on those paths is bounded by disk fsync
// latency; batching multiple entries per fsync is a real future
// optimization, out of scope here.

use common::Order;
use engine::Match;
use orderlog::OrderReceipt;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalEntry {
    // Stage P4-1: exactly the inputs apply_accepted_order was called
    // with.
    OrderAccepted {
        order: Order,
        receipt: OrderReceipt,
        match_timestamp_us: Option<u64>,
    },
    // Stage P4-2: a trader confirmed this match's commitTrade landed
    // on-chain. Carries the full Match (not just its order ids) so
    // replay can re-enqueue it into the batcher without needing to
    // cross-reference match_log.
    CommitConfirmed {
        m: Match,
        trade_hash: [u8; 32],
    },
    // Stage P4-2: checkpoint written AFTER a settlement chunk's
    // submit_settlement_batch call succeeded on-chain -- every
    // (maker_order_id, taker_order_id) key in that chunk is now fully
    // settled. Replay uses this to recognize a CommitConfirmed entry
    // that's already done, instead of re-enqueueing (and attempting to
    // resubmit) something already settled.
    BatchSubmitted {
        keys: Vec<([u8; 32], [u8; 32])>,
    },
    // Stage P4-3: an order entered order-sequencing's intake (either
    // submit_order's own HTTP path or gossip_replication's mesh-gossip
    // path -- see server::queue_for_sequencing, shared by both) but
    // hasn't been resolved/applied yet. Unlike CommitConfirmed, this
    // needs no separate checkpoint entry: replay already knows whether
    // an order was later actually applied via applied_order_ids (built
    // from OrderAccepted entries during the same replay), so that's
    // sufficient to tell "still buffered at crash time" apart from
    // "already flushed" -- see server::replay_persistence_log's final
    // pass.
    OrderQueued {
        order: Order,
        receipt: OrderReceipt,
    },
}

// sled::Db and sled::Tree are cheap, Arc-backed handles -- Clone gives
// callers (e.g. settlement.rs, which needs its own handle without
// holding AppState's lock across an I/O + fsync) an easy way to get one
// without any extra wrapping.
#[derive(Clone)]
pub struct PersistenceLog {
    // Also holds the monotonic id-generator state (see append_entry's
    // use of generate_id) every entry's key is derived from.
    db: sled::Db,
    entries: sled::Tree,
}

impl PersistenceLog {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let db = sled::open(path).map_err(|e| e.to_string())?;
        let entries = db.open_tree("wal_entries").map_err(|e| e.to_string())?;
        Ok(Self { db, entries })
    }

    // Durably records `entry`. Blocks on fsync (Tree::flush) before
    // returning Ok -- the caller must not apply the corresponding state
    // transition until this returns Ok, or a crash between the two
    // could leave it unrecoverable.
    fn append_entry(&self, entry: &WalEntry) -> Result<(), String> {
        let seq = self.db.generate_id().map_err(|e| e.to_string())?;
        let bytes = serde_json::to_vec(entry).map_err(|e| e.to_string())?;
        self.entries
            .insert(seq.to_be_bytes(), bytes)
            .map_err(|e| e.to_string())?;
        self.entries.flush().map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn append_order_accepted(
        &self,
        order: &Order,
        receipt: &OrderReceipt,
        match_timestamp_us: Option<u64>,
    ) -> Result<(), String> {
        self.append_entry(&WalEntry::OrderAccepted {
            order: order.clone(),
            receipt: receipt.clone(),
            match_timestamp_us,
        })
    }

    pub fn append_commit_confirmed(&self, m: &Match, trade_hash: [u8; 32]) -> Result<(), String> {
        self.append_entry(&WalEntry::CommitConfirmed {
            m: m.clone(),
            trade_hash,
        })
    }

    pub fn append_batch_submitted(&self, keys: Vec<([u8; 32], [u8; 32])>) -> Result<(), String> {
        self.append_entry(&WalEntry::BatchSubmitted { keys })
    }

    pub fn append_order_queued(&self, order: &Order, receipt: &OrderReceipt) -> Result<(), String> {
        self.append_entry(&WalEntry::OrderQueued {
            order: order.clone(),
            receipt: receipt.clone(),
        })
    }

    // Every durably-recorded entry, in the exact order they were
    // originally appended (big-endian u64 keys from generate_id sort
    // correctly as bytes, and sled::Tree::iter walks keys in order).
    pub fn replay(&self) -> Result<Vec<WalEntry>, String> {
        let mut out = Vec::new();
        for kv in self.entries.iter() {
            let (_, v) = kv.map_err(|e| e.to_string())?;
            let entry: WalEntry = serde_json::from_slice(&v).map_err(|e| e.to_string())?;
            out.push(entry);
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
            log.append_order_accepted(&order, &receipt, Some(seed as u64 * 100))
                .unwrap();
        }

        let replayed = log.replay().unwrap();
        assert_eq!(replayed.len(), 5);
        for (i, entry) in replayed.iter().enumerate() {
            let seed = (i + 1) as u8;
            let WalEntry::OrderAccepted {
                order,
                match_timestamp_us,
                ..
            } = entry
            else {
                panic!("expected OrderAccepted, got {entry:?}");
            };
            assert_eq!(
                order.id, [seed; 32],
                "replay must preserve original append order"
            );
            assert_eq!(*match_timestamp_us, Some(seed as u64 * 100));
        }
    }

    #[test]
    fn test_replay_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let log = PersistenceLog::open(dir.path()).unwrap();
            let order = make_order(9);
            let receipt = make_receipt(&order);
            log.append_order_accepted(&order, &receipt, None).unwrap();
        }
        // Reopen fresh, as a real restart would.
        let log = PersistenceLog::open(dir.path()).unwrap();
        let replayed = log.replay().unwrap();
        assert_eq!(replayed.len(), 1);
        let WalEntry::OrderAccepted { order, .. } = &replayed[0] else {
            panic!("expected OrderAccepted");
        };
        assert_eq!(order.id, [9u8; 32]);
    }

    // Stage P4-2: the three entry kinds must interleave correctly in a
    // single ordered log -- not just each kind independently roundtrip.
    #[test]
    fn test_mixed_entry_kinds_replay_in_append_order() {
        let dir = tempfile::tempdir().unwrap();
        let log = PersistenceLog::open(dir.path()).unwrap();

        let order = make_order(1);
        let receipt = make_receipt(&order);
        log.append_order_accepted(&order, &receipt, None).unwrap();

        let m = Match {
            maker_order_id: [1u8; 32],
            taker_order_id: [2u8; 32],
            maker_trader: [3u8; 32],
            taker_trader: [4u8; 32],
            price: 100,
            amount: 5,
            timestamp_us: 0,
            settlement_tier: SettlementPreference::Standard,
            fee_basis_points: 5,
            seller: [4u8; 32],
            fee_payer: [4u8; 32],
            symbol: "ETH-USD".to_string(),
            assigned_node: [0u8; 32],
            settlement_deadline: 0,
        };
        log.append_commit_confirmed(&m, [0x42u8; 32]).unwrap();
        log.append_batch_submitted(vec![([1u8; 32], [2u8; 32])])
            .unwrap();

        let replayed = log.replay().unwrap();
        assert_eq!(replayed.len(), 3);
        assert!(matches!(replayed[0], WalEntry::OrderAccepted { .. }));
        assert!(matches!(replayed[1], WalEntry::CommitConfirmed { .. }));
        assert!(matches!(replayed[2], WalEntry::BatchSubmitted { .. }));
    }

    #[test]
    fn test_order_queued_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let log = PersistenceLog::open(dir.path()).unwrap();

        let order = make_order(3);
        let receipt = make_receipt(&order);
        log.append_order_queued(&order, &receipt).unwrap();

        let replayed = log.replay().unwrap();
        assert_eq!(replayed.len(), 1);
        let WalEntry::OrderQueued {
            order: replayed_order,
            ..
        } = &replayed[0]
        else {
            panic!("expected OrderQueued");
        };
        assert_eq!(replayed_order.id, [3u8; 32]);
    }
}
