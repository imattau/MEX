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

use crate::server::AppState;
use std::sync::{Arc, RwLock};
use std::time::Duration;

pub async fn run_snapshot_loop(state: Arc<RwLock<AppState>>, interval: Duration) {
    tracing::info!(interval_secs = interval.as_secs(), "snapshot loop started");

    loop {
        tokio::time::sleep(interval).await;

        // Snapshot content and the WAL seq it covers up to are captured
        // together, under the SAME read-lock hold, so they're always a
        // consistent pair: every WAL append happens while a caller
        // (apply_accepted_order, confirm_committed, queue_for_sequencing)
        // holds AppState's WRITE lock for the whole append+mutate, so
        // holding this READ lock across both reads here excludes any
        // new append from landing in between them.
        let captured = {
            let guard = state.read().unwrap();
            guard.persistence.as_ref().and_then(|log| match log.latest_seq() {
                Ok(Some(seq)) => Some((log.clone(), crate::server::build_snapshot(&guard), seq)),
                // An empty WAL means nothing has happened yet -- nothing
                // new to snapshot this cycle.
                Ok(None) => None,
                Err(e) => {
                    tracing::warn!(error = %e, "snapshot loop: failed to read latest WAL seq, skipping this cycle");
                    None
                }
            })
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
