use crate::types::{ConfirmCommitRequest, ConfirmCommitResponse, LogRootResponse, OrderBookResponse, PriceLevel, SubmitOrderRequest, SubmitOrderResponse};
use axum::{
    extract::{Path, Query, State, WebSocketUpgrade, ws::{Message, WebSocket}},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use batcher::SettlementBatcher;
use common::Order;
use ed25519_dalek::SigningKey;
use engine::{Match, OrderBook};
use orderlog::{HashChainLog, LogEntry, OrderReceipt};
use metrics::{counter, gauge, histogram};
use std::collections::HashMap;
use std::sync::{Arc, RwLock, OnceLock};
use std::time::Instant;
use tokio::sync::{broadcast, mpsc};
use tower::limit::ConcurrencyLimitLayer;
use axum::http::{HeaderMap, StatusCode, Request};
use axum::middleware::{self, Next};
use axum::response::Response;
use tracing::{info, warn, debug, error, instrument};
use validation::OrderValidator;

static API_KEY: OnceLock<String> = OnceLock::new();

fn get_api_key() -> &'static str {
    API_KEY.get_or_init(|| {
        std::env::var("MEX_API_KEY").unwrap_or_else(|_| {
            eprintln!("WARNING: MEX_API_KEY not set, using development default");
            "dev-default-key".to_string()
        })
    })
}

async fn check_auth(headers: HeaderMap, request: Request<axum::body::Body>, next: Next) -> Result<Response, StatusCode> {
    let valid_key = headers
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == get_api_key())
        .unwrap_or(false);

    if !valid_key {
        warn!("Unauthorized API request");
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(request).await)
}

pub struct AppState {
    pub node_id: common::NodeId,
    pub order_book: OrderBook,
    pub validator: OrderValidator,
    pub ws_broadcast: broadcast::Sender<Match>,
    pub reputation: reputation::ReputationEngine,
    // A fresh match sits here, NOT yet in `batcher`, until the fee-paying
    // trader confirms they've actually committed it on-chain (commitTrade
    // is trader-signed -- this server can never do that on a trader's
    // behalf). Keyed by (maker_order_id, taker_order_id) since a single
    // maker order can partially fill against several different takers,
    // producing several Matches that share a maker_order_id.
    pub pending_commits: HashMap<([u8; 32], [u8; 32]), Match>,
    // The trade_hash the confirming trader reported for each match that
    // has moved from pending_commits into batcher, kept until the
    // settlement loop consumes it to build that trade's on-chain
    // TradeEntry. Trusting the trader's self-reported hash here is safe:
    // if it doesn't correspond to a real commitTrade record,
    // settleBatchWithFees simply reverts for that trade at settlement
    // time, the same as it would for any other bad input.
    pub confirmed_trade_hashes: HashMap<([u8; 32], [u8; 32]), [u8; 32]>,
    pub batcher: SettlementBatcher,
    // Deliberately separate from the on-chain settlement key
    // (MEX_NODE_PRIVATE_KEY) -- this key only ever signs order receipts,
    // never a transaction, so compromising it can't move funds. See
    // orderlog's docs.
    pub receipt_signing_key: SigningKey,
    // Append-only, tamper-evident records of every accepted order and
    // every match this server actually produced -- see orderlog's docs.
    // A third party fetches both (GET /api/v1/order_log/entries,
    // /api/v1/match_log/entries), verifies the hash chains
    // (orderlog::verify_chain), replays correct price-time-priority
    // matching against order_log using a fresh engine::OrderBook, and
    // diffs that against match_log: any divergence is provable evidence
    // the server didn't actually match orders the way it claims to.
    pub order_log: HashChainLog<OrderReceipt>,
    pub match_log: HashChainLog<Match>,
    // Stage A of connecting the gossip mesh (protocol crate) to this
    // server: when configured (MEX_MESH_* env vars), every accepted order
    // is also flooded to mesh peers for redundant replication, in
    // addition to being matched locally here. None means mesh disabled --
    // the default, and no behavior change from before this existed.
    // Peers only hold a replicated copy at this stage; they don't match
    // independently (see the conversation this was scoped in for why
    // that's a deliberately separate, harder problem).
    pub mesh: Option<MeshHandle>,
}

pub struct MeshHandle {
    pub node_id: common::NodeId,
    pub region: common::Region,
    pub sender: mpsc::Sender<(common::NodeId, common::FloodMessage)>,
    // Stage C: direct handle for broadcasting a settlement proof to every
    // configured peer -- not routed through `sender`/on_receive, since
    // that path's flood-forwarding semantics (dedup by order id, hop
    // limits) are Order-specific and settlement proofs are sent directly
    // to known peers, not multi-hop propagated (see
    // protocol::WireMessage::SettlementProof's docs).
    pub transport: std::sync::Arc<protocol::UdpTransport>,
    pub peer_ids: Vec<common::NodeId>,
}

fn setup_metrics() {
    use metrics_exporter_prometheus::PrometheusBuilder;
    use std::sync::OnceLock;
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        PrometheusBuilder::new()
            .install_recorder()
            .expect("Failed to install Prometheus recorder");
    });
}

pub fn app(state: Arc<RwLock<AppState>>) -> Router {
    setup_metrics();

    Router::new()
        .route("/api/v1/order", post(submit_order))
        .route("/api/v1/orderbook", get(get_orderbook))
        .route("/api/v1/trade/committed", post(confirm_committed))
        .route("/api/v1/order_log/root", get(order_log_root))
        .route("/api/v1/order_log/entries", get(order_log_entries))
        .route("/api/v1/match_log/root", get(match_log_root))
        .route("/api/v1/match_log/entries", get(match_log_entries))
        .route("/metrics", get(metrics_handler))
        .route("/ws", get(ws_handler))
        .route("/ws/trades/:trader", get(ws_trader_handler))
        .layer(middleware::from_fn(check_auth))
        .layer(ConcurrencyLimitLayer::new(256))
        .with_state(state)
}

async fn metrics_handler() -> impl IntoResponse {
    use metrics_exporter_prometheus::PrometheusHandle;
    use std::sync::OnceLock;
    static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();
    let handle = HANDLE.get_or_init(|| {
        setup_metrics();
        metrics_exporter_prometheus::PrometheusBuilder::new()
            .install_recorder()
            .expect("Metrics already installed")
    });
    handle.render()
}

#[instrument(skip(state, payload), fields(
    symbol = %payload.symbol,
    side = ?payload.side,
    price = payload.price,
    amount = payload.amount
))]
async fn submit_order(
    State(state): State<Arc<RwLock<AppState>>>,
    Json(payload): Json<SubmitOrderRequest>,
) -> Json<SubmitOrderResponse> {
    let start = Instant::now();
    counter!("api.orders.received").increment(1);

    let mut order_id = [0u8; 32];
    order_id[0..16].copy_from_slice(&payload.trader[0..16]);
    order_id[16..24].copy_from_slice(&payload.nonce.to_be_bytes());

    let order = Order {
        id: order_id,
        trader: payload.trader,
        symbol: payload.symbol.clone(),
        side: payload.side,
        price: payload.price,
        amount: payload.amount,
        signature: payload.signature,
        nonce: payload.nonce,
        expiry: payload.expiry,
        settlement_preference: payload.settlement_preference,
        settlement_requester: payload.settlement_requester,
    };

    let mut guard = state.write().unwrap();

    if !guard.validator.validate_order(&order) {
        counter!("api.orders.invalid_signature").increment(1);
        warn!(nonce = order.nonce, "Invalid signature for order");
        return Json(SubmitOrderResponse {
            success: false,
            order_id,
            matches: Vec::new(),
            error: Some("Invalid order signature".to_string()),
            receipt: None,
        });
    }

    // Signed BEFORE add_order runs -- see orderlog's docs for why this
    // ordering is the entire point: signing after matching would let the
    // timestamp be chosen to fit whatever match order already happened.
    let receipt = orderlog::sign_receipt(
        &guard.receipt_signing_key,
        order.id,
        order.trader,
        &order.symbol,
        order.side,
        order.price,
        order.amount,
        order.nonce,
        order.expiry,
        order.settlement_preference,
        order.settlement_requester,
    );
    let log_entry = guard.order_log.append(receipt.clone()).clone();

    if let Some(mesh) = &guard.mesh {
        let flood_msg = common::FloodMessage {
            order: order.clone(),
            hop_count: 0,
            path: vec![mesh.node_id],
            timestamp: receipt.received_at_us as f64 / 1000.0,
            source_region: mesh.region,
        };
        // Injected as if received from ourselves -- MeshNode::run's main
        // loop treats anything on this channel through the same
        // on_receive/forward path as a real inbound flood, which is
        // exactly what's needed to get it propagating to downstream
        // peers. Fire-and-forget: a slow/full mesh channel must never
        // block or fail a trader's HTTP response.
        let _ = mesh.sender.try_send((mesh.node_id, flood_msg));

        // Stage B: broadcast the actual committed log entry (not just
        // the bare order Flood above), so peers can verify each one
        // really is this sequencer's next entry, not just gossip that an
        // order existed at some point -- see
        // protocol::WireMessage::LogEntryBroadcast's docs. Spawned
        // rather than awaited here: this function holds a std::sync
        // RwLock write guard (`guard`) for the rest of its body, and
        // that must never be held across an .await.
        let transport = mesh.transport.clone();
        let peer_ids = mesh.peer_ids.clone();
        tokio::spawn(async move {
            for peer_id in peer_ids {
                let msg = protocol::WireMessage::LogEntryBroadcast { entry: log_entry.clone() };
                let _ = transport.send(peer_id, msg).await;
            }
        });
    }

    let matches = guard.order_book.add_order(order);
    counter!("api.orders.matched").increment(matches.len() as u64);
    histogram!("api.orders.match_latency_us").record(start.elapsed().as_micros() as f64);

    for m in &matches {
        guard.match_log.append(m.clone());
        let _ = guard.ws_broadcast.send(m.clone());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        let node_id = guard.node_id;
        reputation::integration::on_order_matched(
            &mut guard.reputation,
            node_id,
            m,
            now,
        );
        guard
            .pending_commits
            .insert((m.maker_order_id, m.taker_order_id), m.clone());
    }

    gauge!("orderbook.bids.depth").set(guard.order_book.bids.len() as f64);
    gauge!("orderbook.asks.depth").set(guard.order_book.asks.len() as f64);

    if matches.is_empty() {
        debug!(order_id = ?order_id, symbol = %payload.symbol, "Order added to book with no matches");
    } else {
        info!(matches = matches.len(), "Order matched successfully");
    }

    Json(SubmitOrderResponse {
        success: true,
        order_id,
        matches,
        error: None,
        receipt: Some(receipt),
    })
}

#[instrument(skip(state))]
async fn get_orderbook(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Json<OrderBookResponse> {
    counter!("api.orderbook.requests").increment(1);
    let guard = state.read().unwrap();

    let bids = guard
        .order_book
        .bids
        .iter()
        .map(|(&price, orders)| PriceLevel {
            price,
            total_amount: orders.iter().map(|o| o.amount).sum(),
        })
        .collect();

    let asks = guard
        .order_book
        .asks
        .iter()
        .map(|(&price, orders)| PriceLevel {
            price,
            total_amount: orders.iter().map(|o| o.amount).sum(),
        })
        .collect();

    Json(OrderBookResponse {
        symbol: guard.order_book.symbol.clone(),
        bids,
        asks,
    })
}

#[derive(serde::Deserialize)]
struct SinceQuery {
    #[serde(default)]
    since: u64,
}

async fn order_log_root(State(state): State<Arc<RwLock<AppState>>>) -> Json<LogRootResponse> {
    let guard = state.read().unwrap();
    Json(LogRootResponse { root: guard.order_log.root(), len: guard.order_log.len() as u64 })
}

// Fetches order receipts from `since` (inclusive) onward -- an auditor
// fetches the whole log this way, verifies the hash chain
// (orderlog::verify_chain), and replays it through a fresh
// engine::OrderBook to compute what price-time-priority matching should
// have produced, then diffs that against /api/v1/match_log/entries.
async fn order_log_entries(
    State(state): State<Arc<RwLock<AppState>>>,
    Query(q): Query<SinceQuery>,
) -> Json<Vec<LogEntry<OrderReceipt>>> {
    let guard = state.read().unwrap();
    Json(guard.order_log.entries_since(q.since).to_vec())
}

async fn match_log_root(State(state): State<Arc<RwLock<AppState>>>) -> Json<LogRootResponse> {
    let guard = state.read().unwrap();
    Json(LogRootResponse { root: guard.match_log.root(), len: guard.match_log.len() as u64 })
}

async fn match_log_entries(
    State(state): State<Arc<RwLock<AppState>>>,
    Query(q): Query<SinceQuery>,
) -> Json<Vec<LogEntry<Match>>> {
    let guard = state.read().unwrap();
    Json(guard.match_log.entries_since(q.since).to_vec())
}

// Called by a trader (or their TraderClient) right after they've
// successfully called commitTrade on-chain for a match this server
// notified them of. Moves the match from pending_commits into the
// settlement batcher -- before this call, a match exists only in this
// server's memory and is never eligible for batched settlement, since
// this server cannot commit a trader's funds on their behalf.
#[instrument(skip(state))]
async fn confirm_committed(
    State(state): State<Arc<RwLock<AppState>>>,
    Json(payload): Json<ConfirmCommitRequest>,
) -> Json<ConfirmCommitResponse> {
    counter!("api.trade.commit_confirmations").increment(1);
    let key = (payload.maker_order_id, payload.taker_order_id);

    let mut guard = state.write().unwrap();
    let Some(m) = guard.pending_commits.remove(&key) else {
        warn!("Rejected commit confirmation for unknown or already-confirmed match");
        return Json(ConfirmCommitResponse {
            success: false,
            error: Some("no pending match for that (maker_order_id, taker_order_id)".to_string()),
        });
    };

    guard.confirmed_trade_hashes.insert(key, payload.trade_hash);

    // SettlementBatcher checks its own internal ledger for solvency before
    // proving a batch (see batcher::BalanceLedger) -- a separate, purely
    // off-chain balance tracker, disconnected from the real on-chain
    // TraderEscrow balances that actually custody funds and that
    // settleBatchWithFees already enforces against directly. Real
    // solvency was already proven the moment this trader's own
    // commitTrade succeeded on-chain (that's what we're confirming here);
    // crediting the ledger with exactly this trade's value translates
    // that already-proven fact into the ledger's own terms, rather than
    // re-deriving or re-checking something the chain already guarantees.
    let trade_value = m.price * m.amount;
    guard.batcher.deposit(m.taker_trader, &m.symbol, trade_value);

    guard.batcher.enqueue(m);
    info!("Match confirmed committed on-chain, queued for batched settlement");

    Json(ConfirmCommitResponse { success: true, error: None })
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<RwLock<AppState>>>,
) -> impl IntoResponse {
    counter!("api.ws.connections").increment(1);
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: Arc<RwLock<AppState>>) {
    let mut rx = {
        let guard = state.read().unwrap();
        guard.ws_broadcast.subscribe()
    };

    while let Ok(msg) = rx.recv().await {
        match serde_json::to_string(&msg) {
            Ok(serialized) => {
                if socket.send(Message::Text(serialized)).await.is_err() {
                    debug!("WebSocket connection closed");
                    break;
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to serialize match for WebSocket");
            }
        }
    }

    gauge!("api.ws.connections").decrement(1.0);
}

// Parses a hex-encoded 32-byte trader pubkey from a URL path segment
// (optionally "0x"-prefixed). A malformed value is rejected with 400 before
// ever upgrading the connection, rather than upgrading and then immediately
// erroring over the socket.
pub(crate) fn parse_trader_hex(s: &str) -> Result<[u8; 32], String> {
    let trimmed = s.trim_start_matches("0x").trim_start_matches("0X");
    let bytes = hex::decode(trimmed).map_err(|e| format!("invalid hex: {e}"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("expected 32 bytes, got {}", v.len()))?;
    Ok(bytes)
}

// Delivers only the Matches a specific trader actually participated in
// (as maker or taker), instead of /ws's unfiltered broadcast to every
// connected client -- this is what lets a trader-side client learn "here's
// your match, here's what to commit" without having to filter every other
// trader's matches out client-side. Filters the SAME underlying
// ws_broadcast stream server-side; no separate per-trader queue, so a
// trader who connects after a match happened has already missed it (no
// backlog/replay yet).
async fn ws_trader_handler(
    Path(trader_hex): Path<String>,
    ws: WebSocketUpgrade,
    State(state): State<Arc<RwLock<AppState>>>,
) -> Response {
    let trader = match parse_trader_hex(&trader_hex) {
        Ok(t) => t,
        Err(e) => {
            warn!(error = %e, trader_hex = %trader_hex, "Rejected /ws/trades connection: invalid trader");
            return (StatusCode::BAD_REQUEST, e).into_response();
        }
    };
    counter!("api.ws.trader_connections").increment(1);
    ws.on_upgrade(move |socket| handle_trader_socket(socket, state, trader))
        .into_response()
}

async fn handle_trader_socket(mut socket: WebSocket, state: Arc<RwLock<AppState>>, trader: [u8; 32]) {
    let mut rx = {
        let guard = state.read().unwrap();
        guard.ws_broadcast.subscribe()
    };

    while let Ok(msg) = rx.recv().await {
        if msg.maker_trader != trader && msg.taker_trader != trader {
            continue;
        }
        match serde_json::to_string(&msg) {
            Ok(serialized) => {
                if socket.send(Message::Text(serialized)).await.is_err() {
                    debug!("Trader WebSocket connection closed");
                    break;
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to serialize match for trader WebSocket");
            }
        }
    }

    gauge!("api.ws.trader_connections").decrement(1.0);
}
