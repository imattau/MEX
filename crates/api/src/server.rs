use crate::types::{OrderBookResponse, PriceLevel, SubmitOrderRequest, SubmitOrderResponse};
use axum::{
    extract::{State, WebSocketUpgrade, ws::{Message, WebSocket}},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use common::Order;
use engine::{Match, OrderBook};
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use validation::OrderValidator;

pub struct AppState {
    pub order_book: OrderBook,
    pub validator: OrderValidator,
    pub ws_broadcast: broadcast::Sender<Match>,
}

pub fn app(state: Arc<Mutex<AppState>>) -> Router {
    Router::new()
        .route("/api/v1/order", post(submit_order))
        .route("/api/v1/orderbook", get(get_orderbook))
        .route("/ws", get(ws_handler))
        .with_state(state)
}

async fn submit_order(
    State(state): State<Arc<Mutex<AppState>>>,
    Json(payload): Json<SubmitOrderRequest>,
) -> Json<SubmitOrderResponse> {
    // Generate order ID from nonce and details
    let mut order_id = [0u8; 32];
    order_id[0..8].copy_from_slice(&payload.nonce.to_be_bytes());

    let order = Order {
        id: order_id,
        trader: payload.trader,
        symbol: payload.symbol,
        side: payload.side,
        price: payload.price,
        amount: payload.amount,
        signature: payload.signature,
        nonce: payload.nonce,
        expiry: payload.expiry,
    };
    let mut guard = state.lock().unwrap();

    // 1. Validate signature using validation cache
    if !guard.validator.validate_order(&order) {
        return Json(SubmitOrderResponse {
            success: false,
            order_id,
            matches: Vec::new(),
            error: Some("Invalid order signature".to_string()),
        });
    }

    // 2. Insert order into matching engine book
    let matches = guard.order_book.add_order(order);

    // 3. Broadcast matches via WebSocket
    for m in &matches {
        let _ = guard.ws_broadcast.send(m.clone());
    }

    Json(SubmitOrderResponse {
        success: true,
        order_id,
        matches,
        error: None,
    })
}

async fn get_orderbook(
    State(state): State<Arc<Mutex<AppState>>>,
) -> Json<OrderBookResponse> {
    let guard = state.lock().unwrap();

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

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<Mutex<AppState>>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: Arc<Mutex<AppState>>) {
    let mut rx = {
        let guard = state.lock().unwrap();
        guard.ws_broadcast.subscribe()
    };

    while let Ok(msg) = rx.recv().await {
        if let Ok(serialized) = serde_json::to_string(&msg) {
            if socket.send(Message::Text(serialized)).await.is_err() {
                break; // Connection closed
            }
        }
    }
}
