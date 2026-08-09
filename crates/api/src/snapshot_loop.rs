// Stage P4-5: periodically snapshots derived state and truncates the WAL
// up to what the snapshot covers, so a restart doesn't have to replay
// (and re-derive, via engine::OrderBook::add_order_at et al.) this
// node's ENTIRE history on every single boot -- see persistence.rs's
// Snapshot docs for why this is a wholesale, lossless copy (order_log/
// match_log included in full) rather than a summary that would silently
// break their audit-completeness guarantee.
//
// Runs on a fixed interval, not only on clean shutdown: the whole point
// is bounding boot time after a CRASH, and a process that crashes
// doesn't get a chance to snapshot on its way out.
//
// Stage P4-6c: "included in full" above is true of every snapshot's
// CONTENT, but not of where that content physically lives forever --
// order_log/match_log entries older than `hot_window_size` are moved
// out of AppState's own in-memory copy and into durable, never-deleted
// cold storage (see PersistenceLog::archive_order_log_entries/
// archive_match_log_entries) before each snapshot is built, so neither
// live memory nor the snapshot itself keeps re-growing forever. Nothing
// is lost: HashChainLog::split_off_archived + resume_from (Stage
// P4-6b) keep the live "hot window" a valid continuation of the
// archived prefix, verifiable via orderlog::verify_chain_segment
// without ever needing the archive and the hot window in memory at the
// same time.

use crate::server::AppState;
use std::sync::{Arc, RwLock};
use std::time::Duration;

pub async fn run_snapshot_loop(
    state: Arc<RwLock<AppState>>,
    interval: Duration,
    hot_window_size: usize,
) {
    tracing::info!(
        interval_secs = interval.as_secs(),
        hot_window_size,
        "snapshot loop started"
    );

    loop {
        tokio::time::sleep(interval).await;

        // A single write-lock hold for archiving + capturing the
        // snapshot content + the WAL seq it covers up to, so all of it
        // is always a consistent triple: every WAL append happens while
        // a caller (apply_accepted_order, confirm_committed,
        // queue_for_sequencing) holds this same write lock for the
        // whole append+mutate, so holding it here too excludes any new
        // append -- or any of THIS loop's own archiving mutations --
        // from racing with what gets captured.
        let captured = {
            let mut guard = state.write().unwrap();
            let Some(log) = guard.persistence.clone() else {
                continue;
            };
            archive_and_trim_order_log(&mut guard, &log, hot_window_size);
            archive_and_trim_match_log(&mut guard, &log, hot_window_size);

            match log.latest_seq() {
                Ok(Some(seq)) => Some((log, crate::server::build_snapshot(&guard), seq)),
                // An empty WAL means nothing has happened yet -- nothing
                // new to snapshot this cycle.
                Ok(None) => None,
                Err(e) => {
                    tracing::warn!(error = %e, "snapshot loop: failed to read latest WAL seq, skipping this cycle");
                    None
                }
            }
        };

        let Some((log, snapshot, seq)) = captured else {
            continue;
        };

        match log.save_snapshot(&snapshot, seq) {
            Ok(()) => {
                tracing::info!(covers_up_to_seq = seq, "wrote a new persistence snapshot");
                // Best-effort, not crash-atomic with the snapshot write
                // above -- see PersistenceLog::truncate_up_to's own docs
                // on why that's safe (boot-time correctness only ever
                // depends on the snapshot's recorded seq, never on
                // whether old entries were actually deleted yet).
                match log.truncate_up_to(seq) {
                    Ok(removed) => {
                        tracing::info!(
                            removed,
                            "truncated WAL entries already covered by the new snapshot"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "snapshot loop: failed to truncate WAL after a successful snapshot -- safe to retry next cycle");
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "snapshot loop: failed to durably save snapshot, will retry next cycle");
            }
        }
    }
}

// Stage P4-6c: if order_log holds more than `hot_window_size` entries,
// moves everything beyond the most recent `hot_window_size` to durable
// archival storage and replaces guard.order_log with a resumed hot
// window covering just the rest -- see orderlog::HashChainLog::
// split_off_archived's own docs on why this is safe to retry: nothing
// is committed to `guard` until the archive write itself has already
// succeeded, so a failure here just means retrying with the log
// completely unchanged, never partial data loss.
pub(crate) fn archive_and_trim_order_log(
    guard: &mut AppState,
    log: &crate::persistence::PersistenceLog,
    hot_window_size: usize,
) {
    if guard.order_log.len() <= hot_window_size {
        return;
    }
    let keep_from_seq = guard.order_log.next_seq() - hot_window_size as u64;
    let (archived, hot) = guard.order_log.split_off_archived(keep_from_seq);
    match log.archive_order_log_entries(&archived) {
        Ok(()) => {
            tracing::info!(
                archived = archived.len(),
                remaining_hot = hot.len(),
                "archived old order_log entries to cold storage"
            );
            guard.order_log = hot;
        }
        Err(e) => {
            tracing::error!(error = %e, "snapshot loop: failed to durably archive old order_log entries, leaving them in memory and retrying next cycle");
        }
    }
}

pub(crate) fn archive_and_trim_match_log(
    guard: &mut AppState,
    log: &crate::persistence::PersistenceLog,
    hot_window_size: usize,
) {
    if guard.match_log.len() <= hot_window_size {
        return;
    }
    let keep_from_seq = guard.match_log.next_seq() - hot_window_size as u64;
    let (archived, hot) = guard.match_log.split_off_archived(keep_from_seq);
    match log.archive_match_log_entries(&archived) {
        Ok(()) => {
            tracing::info!(
                archived = archived.len(),
                remaining_hot = hot.len(),
                "archived old match_log entries to cold storage"
            );
            guard.match_log = hot;
        }
        Err(e) => {
            tracing::error!(error = %e, "snapshot loop: failed to durably archive old match_log entries, leaving them in memory and retrying next cycle");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::PersistenceLog;
    use common::{OrderSide, SettlementPreference, SettlementRequester};
    use ed25519_dalek::SigningKey;
    use engine::{Match, OrderBook};
    use rand::rngs::OsRng;
    use validation::OrderValidator;

    fn make_receipt(seed: u8) -> orderlog::OrderReceipt {
        orderlog::OrderReceipt {
            order_id: [seed; 32],
            trader: [seed; 32],
            symbol: "ETH-USD".to_string(),
            side: OrderSide::Buy,
            price: 3000,
            amount: 10,
            nonce: seed as u64,
            expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
            received_at_us: 0,
            node_pubkey: [0u8; 32],
            signature: vec![],
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

    fn test_state() -> AppState {
        let (tx, _) = tokio::sync::broadcast::channel(100);
        AppState {
            node_id: common::NodeId(0),
            order_book: OrderBook::new("ETH-USD".to_string()),
            validator: OrderValidator::new(100),
            ws_broadcast: tx,
            reputation: reputation::ReputationEngine::new(),
            pending_commits: std::collections::HashMap::new(),
            confirmed_trade_hashes: std::collections::HashMap::new(),
            batcher: batcher::SettlementBatcher::new(),
            receipt_signing_key: SigningKey::generate(&mut OsRng),
            order_log: orderlog::HashChainLog::new(),
            match_log: orderlog::HashChainLog::new(),
            mesh: None,
            order_sequencer: None,
            pending_order_data: std::collections::HashMap::new(),
            applied_order_ids: std::collections::HashSet::new(),
            persistence: None,
        }
    }

    // Stage P4-6c's whole point, exercised through the actual loop
    // helper: an order_log bigger than the hot window gets trimmed down
    // to exactly the window, the trimmed-off prefix lands durably in
    // the archive, and the archive plus the remaining hot window still
    // verify as one unbroken chain.
    #[test]
    fn test_archive_and_trim_order_log_moves_old_entries_to_cold_storage() {
        let dir = tempfile::tempdir().unwrap();
        let log = PersistenceLog::open(dir.path()).unwrap();
        let mut state = test_state();
        for seed in 1..=6u8 {
            state.order_log.append(make_receipt(seed));
        }
        let original_root = state.order_log.root();

        archive_and_trim_order_log(&mut state, &log, 3);

        assert_eq!(
            state.order_log.len(),
            3,
            "only the hot window should remain in memory"
        );
        assert_eq!(
            state.order_log.next_seq(),
            6,
            "seq numbering must continue correctly, not reset"
        );
        assert_eq!(
            state.order_log.root(),
            original_root,
            "trimming must not change the log's current root"
        );

        let archived = log.archived_order_log_entries_since(0).unwrap();
        assert_eq!(archived.len(), 3);
        assert!(orderlog::verify_chain_segment(0, [0u8; 32], &archived));
        assert!(orderlog::verify_chain_segment(
            3,
            archived.last().unwrap().entry_hash,
            state.order_log.entries()
        ));
    }

    #[test]
    fn test_archive_and_trim_match_log_moves_old_entries_to_cold_storage() {
        let dir = tempfile::tempdir().unwrap();
        let log = PersistenceLog::open(dir.path()).unwrap();
        let mut state = test_state();
        for seed in 1..=6u8 {
            state.match_log.append(make_match(seed));
        }

        archive_and_trim_match_log(&mut state, &log, 3);

        assert_eq!(state.match_log.len(), 3);
        assert_eq!(state.match_log.next_seq(), 6);
        let archived = log.archived_match_log_entries_since(0).unwrap();
        assert_eq!(archived.len(), 3);
        assert!(orderlog::verify_chain_segment(
            3,
            archived.last().unwrap().entry_hash,
            state.match_log.entries()
        ));
    }

    #[test]
    fn test_archive_and_trim_is_a_no_op_below_the_hot_window() {
        let dir = tempfile::tempdir().unwrap();
        let log = PersistenceLog::open(dir.path()).unwrap();
        let mut state = test_state();
        for seed in 1..=3u8 {
            state.order_log.append(make_receipt(seed));
        }

        archive_and_trim_order_log(&mut state, &log, 10);

        assert_eq!(
            state.order_log.len(),
            3,
            "nothing should be trimmed when under the hot window size"
        );
        assert!(log.archived_order_log_entries_since(0).unwrap().is_empty());
    }
}
