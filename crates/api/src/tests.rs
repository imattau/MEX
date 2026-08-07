#[cfg(test)]
mod tests {
    use crate::server::{app, AppState};
    use crate::types::{OrderBookResponse, SubmitOrderRequest, SubmitOrderResponse};
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use common::OrderSide;
    use engine::OrderBook;
    use std::sync::{Arc, RwLock};
    use tokio::sync::broadcast;
    use tower::ServiceExt;
    use validation::OrderValidator;

    fn test_state() -> Arc<RwLock<AppState>> {
        let (tx, _) = broadcast::channel(100);
        Arc::new(RwLock::new(AppState {
            node_id: common::NodeId(0),
            order_book: OrderBook::new("ETH-USD".to_string()),
            validator: OrderValidator::new(100),
            ws_broadcast: tx,
            reputation: reputation::ReputationEngine::new(),
        }))
    }

    #[tokio::test]
    async fn test_get_orderbook_empty() {
        let state = test_state();
        let app = app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/orderbook")
                    .header("X-API-Key", "dev-default-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let book_resp: OrderBookResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(book_resp.symbol, "ETH-USD");
        assert!(book_resp.bids.is_empty());
        assert!(book_resp.asks.is_empty());
    }

    #[tokio::test]
    async fn test_submit_invalid_signature_order() {
        let state = test_state();
        let app = app(state);

        let req = SubmitOrderRequest {
            trader: [0u8; 32],
            symbol: "ETH-USD".to_string(),
            side: OrderSide::Buy,
            price: 3000,
            amount: 5,
            signature: vec![0u8; 64], // Invalid signature
            nonce: 999,
            expiry: 0,
            settlement_preference: Default::default(),
            settlement_requester: Default::default(),
        };

        let body = serde_json::to_vec(&req).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/order")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .header("X-API-Key", "dev-default-key")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let submit_resp: SubmitOrderResponse = serde_json::from_slice(&body).unwrap();
        assert!(!submit_resp.success);
        assert!(submit_resp.error.unwrap().contains("signature"));
    }
}
