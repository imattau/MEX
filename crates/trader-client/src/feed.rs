use crate::client::TraderClient;
use engine::Match;
use futures_util::StreamExt;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

// Connects to a per-trader trade feed (api's GET /ws/trades/:trader) and
// auto-commits every Match this client is the fee_payer for as it arrives.
// Runs until the connection closes or errors -- a caller wanting to run
// this continuously should reconnect/retry around it; this function itself
// makes no retry attempt, matching the "simplest first" scope of the rest
// of this pipeline (SyncService's poll-and-retry loop is the pattern to
// follow if/when this needs to become a long-lived, crash-resilient
// service).
pub async fn watch_trades(ws_url: &str, mut client: TraderClient) -> Result<(), String> {
    let (ws_stream, _) = connect_async(ws_url)
        .await
        .map_err(|e| format!("WS connect to {ws_url} failed: {e}"))?;
    let (_, mut read) = ws_stream.split();

    while let Some(msg) = read.next().await {
        let msg = msg.map_err(|e| format!("WS read failed: {e}"))?;
        let text = match msg {
            Message::Text(t) => t,
            Message::Close(_) => break,
            _ => continue,
        };

        let m: Match = match serde_json::from_str(&text) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, "failed to decode match from trade feed, skipping");
                continue;
            }
        };

        match client.commit_trade(&m).await {
            Ok(trade_hash) => {
                tracing::info!(trade_hash = %hex::encode(trade_hash), "committed trade");
            }
            Err(e) => {
                // Expected, not just tolerated: a Match is broadcast to both
                // participants, but only the fee_payer actually commits it
                // -- see TraderClient::commit_trade's docs. The other
                // participant is expected to hit this error for every match
                // they didn't initiate payment for.
                tracing::debug!(error = %e, "did not commit match (not this client's trade to commit, or a real failure)");
            }
        }
    }

    Ok(())
}
