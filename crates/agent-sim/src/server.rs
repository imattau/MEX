use crate::mesh_state::MultiNodeSimulation;
use crate::types::{ActionRequest, ActionResponse, StepResponse};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use rand::SeedableRng;
use std::sync::Arc;
use tokio::sync::Mutex;

pub type AppState = Arc<Mutex<SharedState>>;

pub struct SharedState {
    pub sim: MultiNodeSimulation,
    pub step_duration_ms: f64,
    pub noise_amplitude: f64,
}

pub fn create_router(shared: AppState) -> Router {
    Router::new()
        .route("/state", get(get_state))
        .route("/state/agent/:id", get(get_agent_state))
        .route("/action", post(post_action))
        .route("/step", post(post_step))
        .route("/health", get(health))
        .with_state(shared)
}

async fn health() -> &'static str {
    "ok"
}

async fn get_state(State(state): State<AppState>) -> Json<serde_json::Value> {
    let mut sim = state.lock().await;
    let snapshot = sim.sim.snapshot();
    Json(serde_json::to_value(snapshot).unwrap())
}

async fn get_agent_state(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let sim = state.lock().await;
    match sim.sim.agents.snapshot(&agent_id) {
        Some(snapshot) => Ok(Json(serde_json::to_value(snapshot).unwrap())),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn post_action(
    State(state): State<AppState>,
    Json(req): Json<ActionRequest>,
) -> Result<Json<ActionResponse>, StatusCode> {
    let mut sim = state.lock().await;

    match req.action.as_str() {
        "place_order" => {
            let side_str = req.side.as_deref().unwrap_or("buy");
            let price = req.price.unwrap_or(3000);
            let amount = req.amount.unwrap_or(1);
            let symbol = req.symbol.clone();
            let node_id = req.node_id.unwrap_or(0);

            if price == 0 || amount == 0 {
                return Ok(Json(ActionResponse {
                    status: "error".to_string(),
                    message: "Invalid price or amount".to_string(),
                    order_id: None,
                }));
            }

            let agent_bytes = sim.sim.agents.get_trader_bytes(&req.agent_id);
            if agent_bytes.is_none() {
                return Ok(Json(ActionResponse {
                    status: "error".to_string(),
                    message: format!("Unknown agent: {}", req.agent_id),
                    order_id: None,
                }));
            }
            let trader = agent_bytes.unwrap();

            let side = crate::types::parse_order_side(side_str);
            match side {
                common::OrderSide::Buy => {
                    let balance = sim.sim.agents.get_balance(&req.agent_id).unwrap_or(0);
                    let cost = amount as u128 * price as u128;
                    if cost > balance as u128 {
                        return Ok(Json(ActionResponse {
                            status: "error".to_string(),
                            message: format!("Insufficient balance: need {}, have {}", cost, balance),
                            order_id: None,
                        }));
                    }
                }
                common::OrderSide::Sell => {
                    let position = sim.sim.agents.get_position(&req.agent_id).unwrap_or(0);
                    if amount > position {
                        return Ok(Json(ActionResponse {
                            status: "error".to_string(),
                            message: format!("Insufficient position: need {}, have {}", amount, position),
                            order_id: None,
                        }));
                    }
                }
            }

            let mut order_id_bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut order_id_bytes);

            let order = common::Order {
                id: order_id_bytes,
                trader,
                symbol,
                side,
                price,
                amount,
                signature: Vec::new(),
                nonce: sim.sim.step_number * 1000 + sim.sim.recent_trades.len() as u64,
                expiry: 1000000,
                settlement_preference: common::SettlementPreference::Standard,
                settlement_requester: common::SettlementRequester::Seller,
            };

            let order_id_hex = crate::types::order_id_to_hex(&order_id_bytes);

            sim.sim.agents.add_order(&req.agent_id, order.clone());
            sim.sim.queue_order(order, node_id);

            Ok(Json(ActionResponse {
                status: "success".to_string(),
                message: format!("Order placed at node {}", node_id),
                order_id: Some(order_id_hex),
            }))
        }

        "cancel_order" => {
            let oid_hex = req.order_id.as_deref().unwrap_or("");
            let oid = crate::types::hex_to_order_id(oid_hex);

            match oid {
                Some(bytes) => {
                    let mut cancelled = false;
                    for node in &mut sim.sim.nodes {
                        if node.orderbook.cancel_order(bytes) {
                            cancelled = true;
                        }
                    }
                    let agent_cancelled = sim.sim.agents.cancel_order(&req.agent_id, &bytes);

                    if cancelled || agent_cancelled {
                        Ok(Json(ActionResponse {
                            status: "success".to_string(),
                            message: "Order cancelled".to_string(),
                            order_id: Some(oid_hex.to_string()),
                        }))
                    } else {
                        Ok(Json(ActionResponse {
                            status: "error".to_string(),
                            message: "Order not found".to_string(),
                            order_id: None,
                        }))
                    }
                }
                None => Ok(Json(ActionResponse {
                    status: "error".to_string(),
                    message: "Invalid order ID format".to_string(),
                    order_id: None,
                })),
            }
        }

        "hold" => Ok(Json(ActionResponse {
            status: "success".to_string(),
            message: "Holding position".to_string(),
            order_id: None,
        })),

        _ => Ok(Json(ActionResponse {
            status: "error".to_string(),
            message: format!("Unknown action: {}", req.action),
            order_id: None,
        })),
    }
}

async fn post_step(
    State(state): State<AppState>,
) -> Json<StepResponse> {
    let mut sim = state.lock().await;

    sim.sim.step_matches.clear();
    for node in &mut sim.sim.nodes {
        node.matches_this_step = 0;
    }

    sim.sim.virtual_time += sim.step_duration_ms;
    sim.sim.step_number += 1;

    // ThreadRng (rand::thread_rng()) is !Send and can't be held across the
    // .await inside propagate_and_match (needed now that it gates matches
    // on a real on-chain commitTrade); StdRng is a Send-able equivalent.
    let mut rng = rand::rngs::StdRng::from_entropy();
    let noise_amp = sim.noise_amplitude;
    sim.sim.inject_noise(&mut rng, noise_amp);
    sim.sim.propagate_and_match(&mut rng).await;

    let step_trades = sim.sim.step_matches_to_trades();

    let snapshot = sim.sim.snapshot();

    Json(StepResponse {
        virtual_time: sim.sim.virtual_time,
        step_number: sim.sim.step_number,
        matches_this_step: step_trades,
        state: snapshot,
    })
}
