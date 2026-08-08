use crate::listener::ChainSync;
use crate::persist::SyncStore;
use crate::sync::apply_event;
use alloy::providers::Provider;
use batcher::BalanceLedger;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;

// Runs ChainSync::poll_once on an interval as a long-lived background
// service: each tick, persist whatever's new (atomically, via SyncStore) and
// apply it to a shared BalanceLedger that other parts of the system can read
// concurrently.
pub struct SyncService<P: Provider> {
    sync: ChainSync<P>,
    store: SyncStore,
    ledger: Arc<Mutex<BalanceLedger>>,
    poll_interval: Duration,
}

impl<P: Provider> SyncService<P> {
    // `sync` must already be constructed with `start_block` set to
    // `store.last_synced_block()` (or the configured genesis block if that's
    // None) -- this type doesn't second-guess that, since ChainSync doesn't
    // expose a way to change it after construction.
    pub fn new(sync: ChainSync<P>, store: SyncStore, poll_interval: Duration) -> Self {
        Self {
            sync,
            store,
            ledger: Arc::new(Mutex::new(BalanceLedger::new())),
            poll_interval,
        }
    }

    // A cloneable handle to the ledger this service keeps updated, for
    // callers that want to read balances while the service runs.
    pub fn ledger(&self) -> Arc<Mutex<BalanceLedger>> {
        self.ledger.clone()
    }

    // Replays whatever SyncStore already had on disk (e.g. from a prior run)
    // into the ledger and ChainSync's registries before the loop starts
    // polling forward. Call once, before `run`.
    pub fn replay_persisted(&mut self) -> Result<usize, String> {
        let events = self.store.all_events()?;
        let mut ledger = self.ledger.lock().expect("ledger mutex poisoned");
        for event in &events {
            self.sync.replay(event);
            apply_event(&mut ledger, event);
        }
        Ok(events.len())
    }

    // Polls, persists, and applies exactly once. Exposed separately from
    // `run` so callers (and tests) can drive individual ticks without
    // spinning up the interval loop.
    pub async fn tick(&mut self) -> Result<usize, String> {
        let events = self.sync.poll_once().await?;
        if events.is_empty() {
            return Ok(0);
        }

        self.store
            .record_batch(&events, self.sync.last_synced_block())?;

        let mut ledger = self.ledger.lock().expect("ledger mutex poisoned");
        for event in &events {
            apply_event(&mut ledger, event);
        }

        Ok(events.len())
    }

    // Ticks on an interval until `shutdown` is set to true. A failed tick
    // (e.g. a dropped RPC connection) is logged and retried on the next
    // interval rather than ending the loop -- a long-lived sync service
    // shouldn't die because of one bad poll.
    pub async fn run(&mut self, mut shutdown: watch::Receiver<bool>) {
        let mut ticker = tokio::time::interval(self.poll_interval);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    match self.tick().await {
                        Ok(count) if count > 0 => {
                            tracing::info!(
                                count,
                                block = self.sync.last_synced_block(),
                                "chain sync applied new events"
                            );
                        }
                        Ok(_) => {}
                        Err(error) => {
                            tracing::warn!(%error, "chain sync poll failed, will retry next tick");
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("chain sync service shutting down");
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::TokenRegistry;
    use crate::listener::http_provider;

    // A minimal liveness check for the run/shutdown mechanics themselves --
    // not a real chain poll (see chain-ethereum's live tests, run manually
    // against a local devnet, for that). This just proves `run` actually
    // ticks and actually stops when told to, without hanging the test suite.
    #[tokio::test]
    async fn test_run_stops_on_shutdown_signal() {
        // A provider pointed at an address nothing is listening on: every
        // tick's poll_once will fail and be logged, which is exactly the
        // "don't die on a bad poll" behavior this test wants to exercise
        // alongside the shutdown path.
        let provider = http_provider("http://127.0.0.1:1").await.unwrap();
        let tokens = TokenRegistry::new();
        let sync = ChainSync::new(provider, [0u8; 20], tokens, 0, 0);
        let store = SyncStore::open(
            tempfile::tempdir().unwrap().keep(),
        )
        .unwrap();

        let mut service = SyncService::new(sync, store, Duration::from_millis(10));
        let (tx, rx) = watch::channel(false);

        let handle = tokio::spawn(async move {
            service.run(rx).await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        tx.send(true).unwrap();

        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("run() did not stop within timeout after shutdown signal")
            .expect("run() task panicked");
    }
}
