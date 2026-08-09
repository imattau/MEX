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
use orderlog::{HashChainLog, LogEntry as OrderlogEntry, OrderReceipt};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
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

// Stage P4-5: a wholesale copy of every piece of state
// replay_persistence_log otherwise has to re-derive by replaying the
// ENTIRE WAL history on every single boot -- order_log/match_log
// included, in full, verbatim (not summarized: their whole reason to
// exist is being a COMPLETE auditable record, see orderlog's own docs,
// so a snapshot that dropped old entries from them would silently break
// that guarantee for anyone restarting this node). Since every field
// here is already just data these structures already hold (nothing
// derived or recomputed), saving/loading a snapshot needs no expensive
// replay logic of its own -- unlike the WAL, which HAS to re-run
// engine::OrderBook::add_order_at et al. to reconstruct anything.
//
// HashMap<([u8;32],[u8;32]), V> fields are represented as Vec<(key,
// value)> rather than a real HashMap: this is serialized with
// serde_json elsewhere in this module, and JSON object keys must be
// strings -- a tuple key has no defined string representation. A Vec of
// pairs sidesteps that entirely and is just as cheap to convert back to
// a HashMap on load.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub order_book_bids: BTreeMap<u64, Vec<Order>>,
    pub order_book_asks: BTreeMap<u64, Vec<Order>>,
    // See engine::OrderBook::active_nodes_cursor's own docs on why this
    // specifically (not just resetting to 0) must be preserved across a
    // restart -- it's load-bearing for Stage P3c-4's cross-replica
    // assign_node determinism guarantee.
    pub active_nodes_cursor: usize,
    pub order_log: HashChainLog<OrderReceipt>,
    pub match_log: HashChainLog<Match>,
    pub pending_commits: Vec<(([u8; 32], [u8; 32]), Match)>,
    pub confirmed_trade_hashes: Vec<(([u8; 32], [u8; 32]), [u8; 32])>,
    pub applied_order_ids: HashSet<[u8; 32]>,
    // Every trade still sitting in the settlement batcher's queue,
    // across all tiers -- see batcher::SettlementBatcher::queued_trades'
    // own docs on why tier information doesn't need to be carried
    // separately.
    pub queued_trades: Vec<Match>,
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

    // Every durably-recorded entry with seq > `after_seq` (None means
    // every entry, from the very start), in the order they were
    // originally appended (big-endian u64 keys from generate_id sort
    // correctly as bytes, so a plain range scan is enough -- no need to
    // decode every entry just to filter by seq). Stage P4-5's snapshot
    // load path uses Some(snapshot's covered seq) to replay only the
    // tail after a snapshot instead of the entire history; every other
    // caller still wants the full history, via None.
    pub fn replay(&self, after_seq: Option<u64>) -> Result<Vec<WalEntry>, String> {
        let mut out = Vec::new();
        match after_seq {
            Some(seq) => {
                for kv in self.entries.range((seq + 1).to_be_bytes().to_vec()..) {
                    let (_, v) = kv.map_err(|e| e.to_string())?;
                    let entry: WalEntry = serde_json::from_slice(&v).map_err(|e| e.to_string())?;
                    out.push(entry);
                }
            }
            None => {
                for kv in self.entries.iter() {
                    let (_, v) = kv.map_err(|e| e.to_string())?;
                    let entry: WalEntry = serde_json::from_slice(&v).map_err(|e| e.to_string())?;
                    out.push(entry);
                }
            }
        }
        Ok(out)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    // The seq of the most recently appended entry, or None if the WAL
    // is empty -- what a fresh snapshot should record as "covers up to."
    pub fn latest_seq(&self) -> Result<Option<u64>, String> {
        match self.entries.last().map_err(|e| e.to_string())? {
            Some((k, _)) => {
                let bytes: [u8; 8] = k
                    .as_ref()
                    .try_into()
                    .map_err(|_| "corrupt WAL key: wrong length".to_string())?;
                Ok(Some(u64::from_be_bytes(bytes)))
            }
            None => Ok(None),
        }
    }

    // Stage P4-5: durably records `snapshot` as the latest one, tagged
    // with the WAL seq it covers up to. A single always-overwritten slot
    // -- only the most recent snapshot is ever useful for booting (an
    // older one would just mean replaying a longer tail, never
    // incorrect, just slower), so there's no reason to keep a history of
    // them.
    pub fn save_snapshot(&self, snapshot: &Snapshot, covers_up_to_seq: u64) -> Result<(), String> {
        let tree = self.db.open_tree("snapshot").map_err(|e| e.to_string())?;
        let bytes = serde_json::to_vec(&(snapshot, covers_up_to_seq)).map_err(|e| e.to_string())?;
        tree.insert(b"latest", bytes).map_err(|e| e.to_string())?;
        tree.flush().map_err(|e| e.to_string())?;
        Ok(())
    }

    // None if no snapshot has ever been saved (a fresh WAL, or one from
    // before Stage P4-5 existed) -- callers fall back to replaying the
    // entire WAL from scratch in that case, exactly as before this
    // stage existed.
    pub fn load_snapshot(&self) -> Result<Option<(Snapshot, u64)>, String> {
        let tree = self.db.open_tree("snapshot").map_err(|e| e.to_string())?;
        match tree.get(b"latest").map_err(|e| e.to_string())? {
            Some(bytes) => {
                let (snapshot, covers_up_to_seq) =
                    serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                Ok(Some((snapshot, covers_up_to_seq)))
            }
            None => Ok(None),
        }
    }

    // Stage P4-5: deletes every WAL entry with seq <= `up_to_seq` -- the
    // ones a snapshot covering up to that seq has already made
    // redundant for replay purposes. Deliberately safe to call at any
    // time, or not at all, or to crash partway through: boot-time
    // correctness only ever depends on comparing an entry's seq against
    // a snapshot's recorded covers_up_to_seq (see replay/load_snapshot),
    // never on whether stale entries were actually physically removed
    // yet -- so this is pure, best-effort disk-space cleanup, not a step
    // that needs crash-atomicity with the snapshot write it follows.
    pub fn truncate_up_to(&self, up_to_seq: u64) -> Result<usize, String> {
        let mut removed = 0;
        for kv in self.entries.range(..=up_to_seq.to_be_bytes().to_vec()) {
            let (k, _) = kv.map_err(|e| e.to_string())?;
            self.entries.remove(k).map_err(|e| e.to_string())?;
            removed += 1;
        }
        self.entries.flush().map_err(|e| e.to_string())?;
        Ok(removed)
    }

    // Stage P4-6c: durable, never-deleted cold storage for order_log/
    // match_log entries a snapshot no longer carries in its "hot
    // window" (see orderlog::HashChainLog::split_off_archived and
    // snapshot_loop's own docs on how this fits into the periodic
    // snapshot cycle). Separate trees per log, keyed by each entry's
    // own absolute seq -- entries within a tree are always contiguous
    // (nothing is ever archived out of order), so a plain big-endian-key
    // range scan is enough to fetch a given range back, same pattern as
    // the WAL's own `entries` tree.
    pub fn archive_order_log_entries(
        &self,
        entries: &[OrderlogEntry<OrderReceipt>],
    ) -> Result<(), String> {
        let tree = self
            .db
            .open_tree("order_log_archive")
            .map_err(|e| e.to_string())?;
        for entry in entries {
            let bytes = serde_json::to_vec(entry).map_err(|e| e.to_string())?;
            tree.insert(entry.seq.to_be_bytes(), bytes)
                .map_err(|e| e.to_string())?;
        }
        tree.flush().map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn archive_match_log_entries(
        &self,
        entries: &[OrderlogEntry<Match>],
    ) -> Result<(), String> {
        let tree = self
            .db
            .open_tree("match_log_archive")
            .map_err(|e| e.to_string())?;
        for entry in entries {
            let bytes = serde_json::to_vec(entry).map_err(|e| e.to_string())?;
            tree.insert(entry.seq.to_be_bytes(), bytes)
                .map_err(|e| e.to_string())?;
        }
        tree.flush().map_err(|e| e.to_string())?;
        Ok(())
    }

    // Every archived order_log entry with seq >= `since` -- an external
    // auditor (or this node's own fetch API, see Stage P4-6d) combines
    // this with the live hot window's own entries_since to reconstruct
    // any range spanning the archive/hot boundary.
    pub fn archived_order_log_entries_since(
        &self,
        since: u64,
    ) -> Result<Vec<OrderlogEntry<OrderReceipt>>, String> {
        let tree = self
            .db
            .open_tree("order_log_archive")
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for kv in tree.range(since.to_be_bytes().to_vec()..) {
            let (_, v) = kv.map_err(|e| e.to_string())?;
            out.push(serde_json::from_slice(&v).map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    pub fn archived_match_log_entries_since(
        &self,
        since: u64,
    ) -> Result<Vec<OrderlogEntry<Match>>, String> {
        let tree = self
            .db
            .open_tree("match_log_archive")
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for kv in tree.range(since.to_be_bytes().to_vec()..) {
            let (_, v) = kv.map_err(|e| e.to_string())?;
            out.push(serde_json::from_slice(&v).map_err(|e| e.to_string())?);
        }
        Ok(out)
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

        let replayed = log.replay(None).unwrap();
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
        let replayed = log.replay(None).unwrap();
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

        let replayed = log.replay(None).unwrap();
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

        let replayed = log.replay(None).unwrap();
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

    #[test]
    fn test_replay_with_after_seq_returns_only_the_tail() {
        let dir = tempfile::tempdir().unwrap();
        let log = PersistenceLog::open(dir.path()).unwrap();

        for seed in 1..=5u8 {
            let order = make_order(seed);
            let receipt = make_receipt(&order);
            log.append_order_accepted(&order, &receipt, None).unwrap();
        }
        // First 3 entries' seqs -- replaying strictly after the 3rd
        // must return only entries 4 and 5.
        let all = log.replay(None).unwrap();
        assert_eq!(all.len(), 5);

        let cutoff = log.latest_seq().unwrap().unwrap() - 2; // seq of the 3rd entry
        let tail = log.replay(Some(cutoff)).unwrap();
        assert_eq!(
            tail.len(),
            2,
            "only entries after the cutoff seq must be returned"
        );
        for entry in &tail {
            let WalEntry::OrderAccepted { order, .. } = entry else {
                panic!("expected OrderAccepted");
            };
            assert!(
                order.id == [4u8; 32] || order.id == [5u8; 32],
                "unexpected order in tail: {:?}",
                order.id
            );
        }
    }

    #[test]
    fn test_latest_seq_is_none_for_an_empty_log() {
        let dir = tempfile::tempdir().unwrap();
        let log = PersistenceLog::open(dir.path()).unwrap();
        assert_eq!(log.latest_seq().unwrap(), None);
    }

    fn empty_snapshot() -> Snapshot {
        Snapshot {
            order_book_bids: std::collections::BTreeMap::new(),
            order_book_asks: std::collections::BTreeMap::new(),
            active_nodes_cursor: 3,
            order_log: orderlog::HashChainLog::new(),
            match_log: orderlog::HashChainLog::new(),
            pending_commits: Vec::new(),
            confirmed_trade_hashes: Vec::new(),
            applied_order_ids: std::collections::HashSet::new(),
            queued_trades: Vec::new(),
        }
    }

    #[test]
    fn test_load_snapshot_returns_none_when_none_was_ever_saved() {
        let dir = tempfile::tempdir().unwrap();
        let log = PersistenceLog::open(dir.path()).unwrap();
        assert!(log.load_snapshot().unwrap().is_none());
    }

    #[test]
    fn test_save_and_load_snapshot_roundtrips_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let log = PersistenceLog::open(dir.path()).unwrap();
            let mut snapshot = empty_snapshot();
            snapshot.order_book_bids.insert(3000, vec![]);
            log.save_snapshot(&snapshot, 42).unwrap();
        }

        let log = PersistenceLog::open(dir.path()).unwrap();
        let (snapshot, covers_up_to_seq) = log.load_snapshot().unwrap().unwrap();
        assert_eq!(covers_up_to_seq, 42);
        assert_eq!(snapshot.active_nodes_cursor, 3);
        assert!(snapshot.order_book_bids.contains_key(&3000));
    }

    #[test]
    fn test_truncate_up_to_removes_only_covered_entries() {
        let dir = tempfile::tempdir().unwrap();
        let log = PersistenceLog::open(dir.path()).unwrap();

        for seed in 1..=5u8 {
            let order = make_order(seed);
            let receipt = make_receipt(&order);
            log.append_order_accepted(&order, &receipt, None).unwrap();
        }
        let cutoff = log.latest_seq().unwrap().unwrap() - 2; // covers entries 1-3

        let removed = log.truncate_up_to(cutoff).unwrap();
        assert_eq!(removed, 3);
        assert_eq!(log.len(), 2, "only entries 4 and 5 should remain");

        let remaining = log.replay(None).unwrap();
        for entry in &remaining {
            let WalEntry::OrderAccepted { order, .. } = entry else {
                panic!("expected OrderAccepted");
            };
            assert!(order.id == [4u8; 32] || order.id == [5u8; 32]);
        }
    }

    fn make_match(seed: u8) -> Match {
        Match {
            maker_order_id: [seed; 32],
            taker_order_id: [seed + 1; 32],
            maker_trader: [seed + 2; 32],
            taker_trader: [seed + 3; 32],
            price: 100,
            amount: 10,
            timestamp_us: 0,
            settlement_tier: SettlementPreference::Standard,
            fee_basis_points: 5,
            seller: [seed + 3; 32],
            fee_payer: [seed + 3; 32],
            symbol: "ETH-USD".to_string(),
            assigned_node: [0u8; 32],
            settlement_deadline: 0,
        }
    }

    #[test]
    fn test_archive_and_fetch_order_log_entries_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let log = PersistenceLog::open(dir.path()).unwrap();

        let mut order_log: HashChainLog<OrderReceipt> = HashChainLog::new();
        for seed in 1..=4u8 {
            let order = make_order(seed);
            order_log.append(make_receipt(&order));
        }
        let entries = order_log.entries().to_vec();

        log.archive_order_log_entries(&entries).unwrap();
        let fetched = log.archived_order_log_entries_since(0).unwrap();
        assert_eq!(fetched.len(), 4);
        for (original, fetched) in entries.iter().zip(&fetched) {
            assert_eq!(original.seq, fetched.seq);
            assert_eq!(original.entry_hash, fetched.entry_hash);
            assert_eq!(original.payload.order_id, fetched.payload.order_id);
        }
    }

    #[test]
    fn test_archive_and_fetch_match_log_entries_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let log = PersistenceLog::open(dir.path()).unwrap();

        let mut match_log: HashChainLog<Match> = HashChainLog::new();
        for seed in 1..=4u8 {
            match_log.append(make_match(seed));
        }
        let entries = match_log.entries().to_vec();

        log.archive_match_log_entries(&entries).unwrap();
        let fetched = log.archived_match_log_entries_since(0).unwrap();
        assert_eq!(fetched.len(), 4);
        for (original, fetched) in entries.iter().zip(&fetched) {
            assert_eq!(original.entry_hash, fetched.entry_hash);
            assert_eq!(
                original.payload.maker_order_id,
                fetched.payload.maker_order_id
            );
        }
    }

    #[test]
    fn test_archived_entries_since_only_returns_entries_at_or_after_seq() {
        let dir = tempfile::tempdir().unwrap();
        let log = PersistenceLog::open(dir.path()).unwrap();

        let mut order_log: HashChainLog<OrderReceipt> = HashChainLog::new();
        for seed in 1..=5u8 {
            let order = make_order(seed);
            order_log.append(make_receipt(&order));
        }
        log.archive_order_log_entries(order_log.entries()).unwrap();

        let all = log.archived_order_log_entries_since(0).unwrap();
        assert_eq!(all.len(), 5);
        let from_third = log.archived_order_log_entries_since(2).unwrap();
        assert_eq!(
            from_third.len(),
            3,
            "seqs 2, 3, 4 -- everything from the third entry onward"
        );
        let none = log.archived_order_log_entries_since(100).unwrap();
        assert!(none.is_empty());
    }

    // Stage P4-6c's whole point, proven end to end at the persistence
    // layer: split a log via split_off_archived, archive the prefix,
    // and confirm the archived prefix plus the resumed hot window's own
    // entries still verify as one unbroken chain from genesis -- the
    // same guarantee orderlog's own tests prove in memory, now proven
    // to survive an actual durable round trip through sled.
    #[test]
    fn test_archived_prefix_and_resumed_hot_window_still_verify_as_one_chain() {
        let dir = tempfile::tempdir().unwrap();
        let log = PersistenceLog::open(dir.path()).unwrap();

        let mut order_log: HashChainLog<OrderReceipt> = HashChainLog::new();
        for seed in 1..=6u8 {
            let order = make_order(seed);
            order_log.append(make_receipt(&order));
        }

        let (archived, hot) = order_log.split_off_archived(3);
        log.archive_order_log_entries(&archived).unwrap();

        let fetched_archive = log.archived_order_log_entries_since(0).unwrap();
        assert_eq!(fetched_archive.len(), 3);
        assert!(orderlog::verify_chain_segment(
            0,
            [0u8; 32],
            &fetched_archive
        ));
        assert!(orderlog::verify_chain_segment(
            3,
            fetched_archive.last().unwrap().entry_hash,
            hot.entries()
        ));
    }
}
