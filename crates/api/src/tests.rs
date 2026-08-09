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
            pending_commits: std::collections::HashMap::new(),
            confirmed_trade_hashes: std::collections::HashMap::new(),
            batcher: batcher::SettlementBatcher::new(),
            receipt_signing_key: ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            order_log: orderlog::HashChainLog::new(),
            match_log: orderlog::HashChainLog::new(),
            mesh: None,
            order_sequencer: None,
            pending_order_data: std::collections::HashMap::new(),
            applied_order_ids: std::collections::HashSet::new(),
            persistence: None,
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
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
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
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let submit_resp: SubmitOrderResponse = serde_json::from_slice(&body).unwrap();
        assert!(!submit_resp.success);
        assert!(submit_resp.error.unwrap().contains("signature"));
    }

    // parse_trader_hex is a pure function -- unit-testing it directly is
    // more precise than routing malformed input through the HTTP/WS layer.
    // (An earlier version of these tests tried the latter via `oneshot`;
    // axum's WebSocketUpgrade extractor itself fails on a synthetic
    // non-connection request regardless of parameter order, since all of a
    // handler's parameters are extracted up front before the handler body
    // ever runs, so that approach can't actually exercise this validation
    // path at all.)
    #[test]
    fn test_parse_trader_hex_rejects_non_hex() {
        assert!(crate::server::parse_trader_hex("not-hex").is_err());
    }

    #[test]
    fn test_parse_trader_hex_rejects_wrong_length() {
        // Valid hex, but only 16 bytes -- must be rejected as the wrong
        // length, not silently truncated/padded into a real trader ID.
        assert!(crate::server::parse_trader_hex(&"ab".repeat(16)).is_err());
    }

    #[test]
    fn test_parse_trader_hex_accepts_valid_32_bytes_with_or_without_prefix() {
        let hex64 = "ab".repeat(32);
        assert_eq!(
            crate::server::parse_trader_hex(&hex64).unwrap(),
            [0xABu8; 32]
        );
        assert_eq!(
            crate::server::parse_trader_hex(&format!("0x{hex64}")).unwrap(),
            [0xABu8; 32]
        );
    }

    // Real, live round trip: binds the app to a real TCP socket, connects
    // TWO real WebSocket clients scoped to two different traders, submits
    // orders that produce a match between them, and confirms each trader's
    // /ws/trades/:trader socket receives ONLY the match(es) they actually
    // participated in -- not an unfiltered firehose of every match on the
    // book, and not the other trader's stream leaking in.
    #[tokio::test]
    async fn test_ws_trades_filters_to_only_the_named_traders_matches() {
        use ed25519_dalek::{Signer, SigningKey};
        use engine::OrderBook;
        use futures_util::StreamExt;
        use rand::rngs::OsRng;
        use tokio_tungstenite::connect_async;
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        use validation::OrderValidator;

        let (tx, _) = broadcast::channel(100);
        let state = Arc::new(RwLock::new(AppState {
            node_id: common::NodeId(0),
            order_book: OrderBook::new("ETH-USD".to_string()),
            validator: OrderValidator::new(100),
            ws_broadcast: tx,
            reputation: reputation::ReputationEngine::new(),
            pending_commits: std::collections::HashMap::new(),
            confirmed_trade_hashes: std::collections::HashMap::new(),
            batcher: batcher::SettlementBatcher::new(),
            receipt_signing_key: ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            order_log: orderlog::HashChainLog::new(),
            match_log: orderlog::HashChainLog::new(),
            mesh: None,
            order_sequencer: None,
            pending_order_data: std::collections::HashMap::new(),
            applied_order_ids: std::collections::HashSet::new(),
            persistence: None,
        }));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = app(state);
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut csprng = OsRng;
        let sk_buyer = SigningKey::generate(&mut csprng);
        let pk_buyer = sk_buyer.verifying_key().to_bytes();
        let sk_seller = SigningKey::generate(&mut csprng);
        let pk_seller = sk_seller.verifying_key().to_bytes();
        let sk_bystander = SigningKey::generate(&mut csprng);
        let pk_bystander = sk_bystander.verifying_key().to_bytes();

        async fn connect_trader(
            addr: std::net::SocketAddr,
            trader: [u8; 32],
        ) -> tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        > {
            let url = format!("ws://{addr}/ws/trades/{}", hex::encode(trader));
            let mut req = url.into_client_request().unwrap();
            req.headers_mut()
                .insert("X-API-Key", "dev-default-key".parse().unwrap());
            let (ws, _) = connect_async(req).await.unwrap();
            ws
        }

        let mut buyer_ws = connect_trader(addr, pk_buyer).await;
        let mut bystander_ws = connect_trader(addr, pk_bystander).await;

        // Give both sockets a moment to actually subscribe before the match
        // fires -- ws_broadcast is a live channel with no replay/backlog,
        // so a subscription that lands after the send would simply miss it.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = reqwest::Client::new();
        let base = format!("http://{addr}");

        // submit_order (server.rs) derives order.id from trader/nonce, and
        // the signature covers that derived id -- so signing correctly here
        // means replicating the exact same derivation the server uses,
        // not just picking arbitrary bytes to sign.
        fn build_and_sign(
            sk: &SigningKey,
            trader: [u8; 32],
            side: common::OrderSide,
            price: u64,
            amount: u64,
            nonce: u64,
        ) -> serde_json::Value {
            let mut order_id = [0u8; 32];
            order_id[0..16].copy_from_slice(&trader[0..16]);
            order_id[16..24].copy_from_slice(&nonce.to_be_bytes());

            let unsigned = common::Order {
                id: order_id,
                trader,
                symbol: "ETH-USD".to_string(),
                side,
                price,
                amount,
                signature: Vec::new(),
                nonce,
                expiry: 0,
                settlement_preference: common::SettlementPreference::Standard,
                settlement_requester: common::SettlementRequester::Seller,
            };
            let msg = OrderValidator::serialize_order_message(&unsigned);
            let signature = sk.sign(&msg).to_vec();

            serde_json::json!({
                "trader": trader, "symbol": "ETH-USD", "side": side,
                "price": price, "amount": amount,
                "signature": signature,
                "nonce": nonce, "expiry": 0,
            })
        }

        let sell_req = build_and_sign(&sk_seller, pk_seller, common::OrderSide::Sell, 3000, 5, 1);
        let sell_resp: SubmitOrderResponse = client
            .post(format!("{base}/api/v1/order"))
            .header("X-API-Key", "dev-default-key")
            .json(&sell_req)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(
            sell_resp.success,
            "sell order rejected: {:?}",
            sell_resp.error
        );

        let buy_req = build_and_sign(&sk_buyer, pk_buyer, common::OrderSide::Buy, 3000, 5, 1);
        let buy_resp: SubmitOrderResponse = client
            .post(format!("{base}/api/v1/order"))
            .header("X-API-Key", "dev-default-key")
            .json(&buy_req)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(buy_resp.success, "buy order rejected: {:?}", buy_resp.error);
        assert_eq!(
            buy_resp.matches.len(),
            1,
            "buy order should have matched the resting sell"
        );

        let buyer_msg = tokio::time::timeout(std::time::Duration::from_secs(2), buyer_ws.next())
            .await
            .expect("buyer socket must receive its own match")
            .unwrap()
            .unwrap();
        let received: engine::Match = match buyer_msg {
            tokio_tungstenite::tungstenite::Message::Text(t) => serde_json::from_str(&t).unwrap(),
            other => panic!("unexpected message type: {other:?}"),
        };
        assert!(received.maker_trader == pk_buyer || received.taker_trader == pk_buyer);

        // The bystander (unrelated trader) must NOT receive this match.
        let bystander_result =
            tokio::time::timeout(std::time::Duration::from_millis(300), bystander_ws.next()).await;
        assert!(
            bystander_result.is_err(),
            "an unrelated trader's socket must not receive someone else's match"
        );

        let _ = buyer_ws.close(None).await;
        let _ = bystander_ws.close(None).await;
    }

    // A fresh match must sit in pending_commits, invisible to the
    // settlement batcher, until the fee-paying trader confirms they've
    // actually committed it on-chain -- this server never holds a
    // trader's key and can't do that on their behalf. Confirming moves it
    // into the batcher and records the trader-reported trade_hash.
    #[tokio::test]
    async fn test_confirm_committed_moves_match_from_pending_to_batcher() {
        use ed25519_dalek::{Signer, SigningKey};
        use engine::OrderBook;
        use rand::rngs::OsRng;

        let (tx, _) = broadcast::channel(100);
        let state = Arc::new(RwLock::new(AppState {
            node_id: common::NodeId(0),
            order_book: OrderBook::new("ETH-USD".to_string()),
            validator: OrderValidator::new(100),
            ws_broadcast: tx,
            reputation: reputation::ReputationEngine::new(),
            pending_commits: std::collections::HashMap::new(),
            confirmed_trade_hashes: std::collections::HashMap::new(),
            batcher: batcher::SettlementBatcher::new(),
            receipt_signing_key: ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            order_log: orderlog::HashChainLog::new(),
            match_log: orderlog::HashChainLog::new(),
            mesh: None,
            order_sequencer: None,
            pending_order_data: std::collections::HashMap::new(),
            applied_order_ids: std::collections::HashSet::new(),
            persistence: None,
        }));
        let state_for_inspection = Arc::clone(&state);
        let app = app(state);

        let mut csprng = OsRng;
        let sk_seller = SigningKey::generate(&mut csprng);
        let pk_seller = sk_seller.verifying_key().to_bytes();
        let sk_buyer = SigningKey::generate(&mut csprng);
        let pk_buyer = sk_buyer.verifying_key().to_bytes();

        fn build_and_sign(
            sk: &SigningKey,
            trader: [u8; 32],
            side: common::OrderSide,
            price: u64,
            amount: u64,
            nonce: u64,
        ) -> serde_json::Value {
            let mut order_id = [0u8; 32];
            order_id[0..16].copy_from_slice(&trader[0..16]);
            order_id[16..24].copy_from_slice(&nonce.to_be_bytes());
            let unsigned = common::Order {
                id: order_id,
                trader,
                symbol: "ETH-USD".to_string(),
                side,
                price,
                amount,
                signature: Vec::new(),
                nonce,
                expiry: 0,
                settlement_preference: common::SettlementPreference::Standard,
                settlement_requester: common::SettlementRequester::Seller,
            };
            let msg = OrderValidator::serialize_order_message(&unsigned);
            let signature = sk.sign(&msg).to_vec();
            serde_json::json!({
                "trader": trader, "symbol": "ETH-USD", "side": side,
                "price": price, "amount": amount, "signature": signature,
                "nonce": nonce, "expiry": 0,
            })
        }

        async fn post_order(app: &axum::Router, body: &serde_json::Value) -> SubmitOrderResponse {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(http::Method::POST)
                        .uri("/api/v1/order")
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .header("X-API-Key", "dev-default-key")
                        .body(Body::from(serde_json::to_vec(body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice(&body).unwrap()
        }

        let sell_req = build_and_sign(&sk_seller, pk_seller, common::OrderSide::Sell, 3000, 5, 1);
        let sell_resp = post_order(&app, &sell_req).await;
        assert!(sell_resp.success);

        let buy_req = build_and_sign(&sk_buyer, pk_buyer, common::OrderSide::Buy, 3000, 5, 1);
        let buy_resp = post_order(&app, &buy_req).await;
        assert!(buy_resp.success);
        assert_eq!(buy_resp.matches.len(), 1);
        let m = &buy_resp.matches[0];

        {
            let guard = state_for_inspection.read().unwrap();
            assert!(
                guard
                    .pending_commits
                    .contains_key(&(m.maker_order_id, m.taker_order_id)),
                "a fresh match must sit in pending_commits before commit confirmation"
            );
        }

        let fake_trade_hash = [0x42u8; 32];
        let confirm_body = serde_json::json!({
            "maker_order_id": m.maker_order_id,
            "taker_order_id": m.taker_order_id,
            "trade_hash": fake_trade_hash,
        });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/trade/committed")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .header("X-API-Key", "dev-default-key")
                    .body(Body::from(serde_json::to_vec(&confirm_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let confirm_resp: crate::types::ConfirmCommitResponse =
            serde_json::from_slice(&body).unwrap();
        assert!(
            confirm_resp.success,
            "confirm_committed rejected a real pending match: {:?}",
            confirm_resp.error
        );

        {
            let guard = state_for_inspection.read().unwrap();
            assert!(
                !guard
                    .pending_commits
                    .contains_key(&(m.maker_order_id, m.taker_order_id)),
                "confirmed match must be removed from pending_commits"
            );
            assert_eq!(
                guard
                    .confirmed_trade_hashes
                    .get(&(m.maker_order_id, m.taker_order_id)),
                Some(&fake_trade_hash),
                "the trader-reported trade_hash must be recorded"
            );
        }

        // Confirming the same match twice must not succeed the second
        // time -- it's already been removed from pending_commits.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/trade/committed")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .header("X-API-Key", "dev-default-key")
                    .body(Body::from(serde_json::to_vec(&confirm_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let confirm_resp2: crate::types::ConfirmCommitResponse =
            serde_json::from_slice(&body).unwrap();
        assert!(
            !confirm_resp2.success,
            "confirming an already-confirmed match must not succeed again"
        );
    }

    // Stage P4-1 live validation: the actual point of persistence -- a
    // crossing order pair is submitted and matched on one AppState
    // (standing in for a real process), then a SECOND, freshly-
    // constructed AppState (standing in for that process restarting,
    // with no in-memory state carried over) replays the same on-disk WAL
    // and must end up with the identical resting-order-book state and
    // the identical match recorded in pending_commits, with no new HTTP
    // submissions. Uses immediate (non-sequenced, order_sequencer: None)
    // apply so match_timestamp_us is None for both -- add_order_at's
    // cross-replica determinism (Stage P3c-1) doesn't need re-proving
    // here, only that replay actually reproduces what apply_accepted_order
    // originally did.
    #[tokio::test]
    async fn test_persisted_orders_are_recovered_after_a_simulated_restart() {
        use ed25519_dalek::{Signer, SigningKey};
        use engine::OrderBook;
        use rand::rngs::OsRng;

        let dir = tempfile::tempdir().unwrap();

        fn build_and_sign(
            sk: &SigningKey,
            trader: [u8; 32],
            side: common::OrderSide,
            price: u64,
            amount: u64,
            nonce: u64,
        ) -> serde_json::Value {
            let mut order_id = [0u8; 32];
            order_id[0..16].copy_from_slice(&trader[0..16]);
            order_id[16..24].copy_from_slice(&nonce.to_be_bytes());
            let unsigned = common::Order {
                id: order_id,
                trader,
                symbol: "ETH-USD".to_string(),
                side,
                price,
                amount,
                signature: Vec::new(),
                nonce,
                expiry: 0,
                settlement_preference: common::SettlementPreference::Standard,
                settlement_requester: common::SettlementRequester::Seller,
            };
            let msg = OrderValidator::serialize_order_message(&unsigned);
            let signature = sk.sign(&msg).to_vec();
            serde_json::json!({
                "trader": trader, "symbol": "ETH-USD", "side": side,
                "price": price, "amount": amount, "signature": signature,
                "nonce": nonce, "expiry": 0,
            })
        }

        async fn post_order(app: &axum::Router, body: &serde_json::Value) -> SubmitOrderResponse {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(http::Method::POST)
                        .uri("/api/v1/order")
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .header("X-API-Key", "dev-default-key")
                        .body(Body::from(serde_json::to_vec(body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice(&body).unwrap()
        }

        let mut csprng = OsRng;
        let sk_seller = SigningKey::generate(&mut csprng);
        let pk_seller = sk_seller.verifying_key().to_bytes();
        let sk_buyer = SigningKey::generate(&mut csprng);
        let pk_buyer = sk_buyer.verifying_key().to_bytes();

        let expected_match = {
            let log = crate::persistence::PersistenceLog::open(dir.path()).unwrap();
            let (tx, _) = broadcast::channel(100);
            let state = Arc::new(RwLock::new(AppState {
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
                persistence: Some(log),
            }));
            let app = app(Arc::clone(&state));

            let sell_req =
                build_and_sign(&sk_seller, pk_seller, common::OrderSide::Sell, 3000, 5, 1);
            let sell_resp = post_order(&app, &sell_req).await;
            assert!(sell_resp.success);

            let buy_req = build_and_sign(&sk_buyer, pk_buyer, common::OrderSide::Buy, 3000, 5, 1);
            let buy_resp = post_order(&app, &buy_req).await;
            assert!(buy_resp.success);
            assert_eq!(
                buy_resp.matches.len(),
                1,
                "a crossing buy/sell must match immediately in non-sequenced mode"
            );

            let guard = state.read().unwrap();
            assert_eq!(
                guard.order_log.len(),
                2,
                "both orders must have durably-backed order_log entries before 'crashing'"
            );
            buy_resp.matches[0].clone()
            // `state` (and the sled Db it holds a PersistenceLog handle
            // to) is dropped here, at scope end -- standing in for the
            // process exiting/crashing with nothing else surviving.
        };

        // "Restart": a brand new AppState, sharing nothing with the one
        // above except the same on-disk path, reopened fresh.
        let log = crate::persistence::PersistenceLog::open(dir.path()).unwrap();
        let mut recovered_state = AppState {
            node_id: common::NodeId(0),
            order_book: OrderBook::new("ETH-USD".to_string()),
            validator: OrderValidator::new(100),
            ws_broadcast: broadcast::channel(100).0,
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
        };

        let summary = crate::server::replay_persistence_log(&mut recovered_state, &log).unwrap();
        assert_eq!(
            summary.entries_replayed, 2,
            "both durably-recorded orders must be replayed"
        );

        assert!(
            recovered_state
                .applied_order_ids
                .contains(&expected_match.maker_order_id)
                || recovered_state
                    .applied_order_ids
                    .contains(&expected_match.taker_order_id),
            "replay must mark both original order ids as applied"
        );
        assert_eq!(
            recovered_state.match_log.len(),
            1,
            "replay must reproduce exactly the one match that originally occurred"
        );
        assert!(
            recovered_state.pending_commits.contains_key(&(expected_match.maker_order_id, expected_match.taker_order_id)),
            "replay must reconstruct pending_commits exactly as it stood before the simulated crash -- this match was never confirmed, so it must still be pending"
        );
        // Resting book state: since both orders matched fully (amount 5
        // vs 5), nothing should be left resting on either side.
        assert_eq!(recovered_state.order_book.bids.len(), 0);
        assert_eq!(recovered_state.order_book.asks.len(), 0);
    }

    // Stage P4-2 live validation: the actual point of extending the WAL
    // past P4-1 -- two matches are both confirmed committed (moved out
    // of pending_commits, into the batcher), but only ONE of them ever
    // gets a BatchSubmitted checkpoint (standing in for the settlement
    // loop having actually gotten it on-chain before the simulated
    // crash). Replay must tell these apart: the unsettled one comes back
    // exactly as confirm_committed originally left it (in the batcher's
    // queue, credited in the ledger, in confirmed_trade_hashes); the
    // settled one must NOT be re-enqueued (that would risk a duplicate
    // on-chain submission) but must still be gone from pending_commits.
    #[tokio::test]
    async fn test_settled_confirmations_are_not_replayed_but_unsettled_ones_are() {
        use ed25519_dalek::{Signer, SigningKey};
        use engine::OrderBook;
        use rand::rngs::OsRng;

        let dir = tempfile::tempdir().unwrap();

        fn build_and_sign(
            sk: &SigningKey,
            trader: [u8; 32],
            side: common::OrderSide,
            price: u64,
            amount: u64,
            nonce: u64,
        ) -> serde_json::Value {
            let mut order_id = [0u8; 32];
            order_id[0..16].copy_from_slice(&trader[0..16]);
            order_id[16..24].copy_from_slice(&nonce.to_be_bytes());
            // Instant tier: SettlementBatcher::try_flush_instant pops
            // and proves a trade the moment process_batches() is called,
            // with no batch-size/timer gate to fight with in a test.
            let unsigned = common::Order {
                id: order_id,
                trader,
                symbol: "ETH-USD".to_string(),
                side,
                price,
                amount,
                signature: Vec::new(),
                nonce,
                expiry: 0,
                settlement_preference: common::SettlementPreference::Instant,
                settlement_requester: common::SettlementRequester::Seller,
            };
            let msg = OrderValidator::serialize_order_message(&unsigned);
            let signature = sk.sign(&msg).to_vec();
            serde_json::json!({
                "trader": trader, "symbol": "ETH-USD", "side": side,
                "price": price, "amount": amount, "signature": signature,
                "nonce": nonce, "expiry": 0,
                "settlement_preference": "Instant",
            })
        }

        async fn post_order(app: &axum::Router, body: &serde_json::Value) -> SubmitOrderResponse {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(http::Method::POST)
                        .uri("/api/v1/order")
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .header("X-API-Key", "dev-default-key")
                        .body(Body::from(serde_json::to_vec(body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice(&body).unwrap()
        }

        async fn confirm(
            app: &axum::Router,
            m: &engine::Match,
        ) -> crate::types::ConfirmCommitResponse {
            let trade_hash = [0x42u8; 32];
            let body = serde_json::json!({
                "maker_order_id": m.maker_order_id,
                "taker_order_id": m.taker_order_id,
                "trade_hash": trade_hash,
            });
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(http::Method::POST)
                        .uri("/api/v1/trade/committed")
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .header("X-API-Key", "dev-default-key")
                        .body(Body::from(serde_json::to_vec(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice(&body).unwrap()
        }

        let mut csprng = OsRng;
        let sk1 = SigningKey::generate(&mut csprng);
        let pk1 = sk1.verifying_key().to_bytes();
        let sk2 = SigningKey::generate(&mut csprng);
        let pk2 = sk2.verifying_key().to_bytes();
        let sk3 = SigningKey::generate(&mut csprng);
        let pk3 = sk3.verifying_key().to_bytes();
        let sk4 = SigningKey::generate(&mut csprng);
        let pk4 = sk4.verifying_key().to_bytes();

        let (unsettled_match, settled_match) = {
            let log = crate::persistence::PersistenceLog::open(dir.path()).unwrap();
            let (tx, _) = broadcast::channel(100);
            let state = Arc::new(RwLock::new(AppState {
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
                persistence: Some(log.clone()),
            }));
            let app = app(Arc::clone(&state));

            // Match 1: will be confirmed but NOT checkpointed as settled
            // -- must survive replay as still-pending.
            let sell1 = build_and_sign(&sk1, pk1, common::OrderSide::Sell, 3000, 5, 1);
            post_order(&app, &sell1).await;
            let buy1_resp = post_order(
                &app,
                &build_and_sign(&sk2, pk2, common::OrderSide::Buy, 3000, 5, 1),
            )
            .await;
            assert_eq!(buy1_resp.matches.len(), 1);
            let unsettled_match = buy1_resp.matches[0].clone();

            // Match 2: will be confirmed AND checkpointed as settled --
            // must NOT survive replay as pending.
            let sell2 = build_and_sign(&sk3, pk3, common::OrderSide::Sell, 3100, 4, 1);
            post_order(&app, &sell2).await;
            let buy2_resp = post_order(
                &app,
                &build_and_sign(&sk4, pk4, common::OrderSide::Buy, 3100, 4, 1),
            )
            .await;
            assert_eq!(buy2_resp.matches.len(), 1);
            let settled_match = buy2_resp.matches[0].clone();

            let confirm1 = confirm(&app, &unsettled_match).await;
            assert!(confirm1.success, "{:?}", confirm1.error);
            let confirm2 = confirm(&app, &settled_match).await;
            assert!(confirm2.success, "{:?}", confirm2.error);

            // Stand in for the settlement loop having actually gotten
            // match 2 on-chain before the simulated crash -- match 1
            // never got this checkpoint.
            log.append_batch_submitted(vec![(
                settled_match.maker_order_id,
                settled_match.taker_order_id,
            )])
            .unwrap();

            (unsettled_match, settled_match)
            // `state` drops here, simulating a crash with nothing else
            // surviving.
        };

        let log = crate::persistence::PersistenceLog::open(dir.path()).unwrap();
        let mut recovered_state = AppState {
            node_id: common::NodeId(0),
            order_book: OrderBook::new("ETH-USD".to_string()),
            validator: OrderValidator::new(100),
            ws_broadcast: broadcast::channel(100).0,
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
        };
        let summary = crate::server::replay_persistence_log(&mut recovered_state, &log).unwrap();

        // Stage P4-4c: reconciliation_candidates must contain exactly
        // the unsettled match -- the settled one has a BatchSubmitted
        // checkpoint, so its true status was never ambiguous and it has
        // nothing left to reconcile.
        let candidate_ids: Vec<[u8; 32]> = summary
            .reconciliation_candidates
            .iter()
            .map(|(m, _)| m.maker_order_id)
            .collect();
        assert_eq!(
            candidate_ids,
            vec![unsettled_match.maker_order_id],
            "only the unsettled match should be a reconciliation candidate"
        );

        // Neither match should still be "pending confirmation" -- both
        // were genuinely confirmed before the crash.
        assert!(!recovered_state.pending_commits.contains_key(&(
            unsettled_match.maker_order_id,
            unsettled_match.taker_order_id
        )));
        assert!(!recovered_state
            .pending_commits
            .contains_key(&(settled_match.maker_order_id, settled_match.taker_order_id)));

        // The unsettled match must have its confirmation fully
        // reconstructed: still in confirmed_trade_hashes, and still
        // sitting in the batcher's queue awaiting settlement.
        assert!(
            recovered_state.confirmed_trade_hashes.contains_key(&(
                unsettled_match.maker_order_id,
                unsettled_match.taker_order_id
            )),
            "the unsettled match's confirmation must be reconstructed"
        );
        assert!(
            !recovered_state
                .confirmed_trade_hashes
                .contains_key(&(settled_match.maker_order_id, settled_match.taker_order_id)),
            "the settled match's confirmed_trade_hashes entry was already consumed live -- replay must not resurrect it"
        );

        let batches = recovered_state.batcher.process_batches();
        let all_settled_ids: Vec<[u8; 32]> = batches
            .iter()
            .flat_map(|b| b.trades.iter().map(|t| t.maker_order_id))
            .collect();
        assert!(
            all_settled_ids.contains(&unsettled_match.maker_order_id),
            "the unsettled match must still be in the batcher's queue after replay, ready to actually settle"
        );
        assert!(
            !all_settled_ids.contains(&settled_match.maker_order_id),
            "the already-settled match must NOT be re-enqueued -- that would risk a duplicate on-chain submission"
        );
    }

    // Stage P4-3 live validation: with order-sequencing enabled, two
    // orders are queued (both durably recorded via queue_for_sequencing
    // -- see server.rs). One is then manually flushed/applied (standing
    // in for run_order_sequencing_loop having processed it before the
    // crash); the other is left sitting in the buffer, unresolved --
    // standing in for a crash mid-window. Replay must put the still-
    // buffered order back into a fresh OrderSequencer/pending_order_data
    // exactly as it stood, and must NOT re-queue the one that was
    // already flushed (applied_order_ids already accounts for it).
    #[tokio::test]
    async fn test_unflushed_queued_orders_are_recovered_but_flushed_ones_are_not() {
        use ed25519_dalek::{Signer, SigningKey};
        use engine::OrderBook;
        use protocol::OrderSequencer;
        use rand::rngs::OsRng;

        let dir = tempfile::tempdir().unwrap();

        fn build_and_sign(
            sk: &SigningKey,
            trader: [u8; 32],
            side: common::OrderSide,
            price: u64,
            amount: u64,
            nonce: u64,
        ) -> serde_json::Value {
            let mut order_id = [0u8; 32];
            order_id[0..16].copy_from_slice(&trader[0..16]);
            order_id[16..24].copy_from_slice(&nonce.to_be_bytes());
            let unsigned = common::Order {
                id: order_id,
                trader,
                symbol: "ETH-USD".to_string(),
                side,
                price,
                amount,
                signature: Vec::new(),
                nonce,
                expiry: 0,
                settlement_preference: common::SettlementPreference::Standard,
                settlement_requester: common::SettlementRequester::Seller,
            };
            let msg = OrderValidator::serialize_order_message(&unsigned);
            let signature = sk.sign(&msg).to_vec();
            serde_json::json!({
                "trader": trader, "symbol": "ETH-USD", "side": side,
                "price": price, "amount": amount, "signature": signature,
                "nonce": nonce, "expiry": 0,
            })
        }

        async fn post_order(app: &axum::Router, body: &serde_json::Value) -> SubmitOrderResponse {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(http::Method::POST)
                        .uri("/api/v1/order")
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .header("X-API-Key", "dev-default-key")
                        .body(Body::from(serde_json::to_vec(body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice(&body).unwrap()
        }

        let mut csprng = OsRng;
        let sk_still_buffered = SigningKey::generate(&mut csprng);
        let pk_still_buffered = sk_still_buffered.verifying_key().to_bytes();
        let sk_flushed = SigningKey::generate(&mut csprng);
        let pk_flushed = sk_flushed.verifying_key().to_bytes();

        let (still_buffered_id, flushed_id) = {
            let log = crate::persistence::PersistenceLog::open(dir.path()).unwrap();
            let (tx, _) = broadcast::channel(100);
            let state = Arc::new(RwLock::new(AppState {
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
                order_sequencer: Some(OrderSequencer::new()),
                pending_order_data: std::collections::HashMap::new(),
                applied_order_ids: std::collections::HashSet::new(),
                persistence: Some(log),
            }));
            let app = app(Arc::clone(&state));

            let still_buffered_req = build_and_sign(
                &sk_still_buffered,
                pk_still_buffered,
                common::OrderSide::Buy,
                3000,
                5,
                1,
            );
            let resp1 = post_order(&app, &still_buffered_req).await;
            assert!(resp1.success && resp1.pending);
            let still_buffered_id = resp1.order_id;

            let flushed_req =
                build_and_sign(&sk_flushed, pk_flushed, common::OrderSide::Buy, 3100, 3, 1);
            let resp2 = post_order(&app, &flushed_req).await;
            assert!(resp2.success && resp2.pending);
            let flushed_id = resp2.order_id;

            // Stand in for run_order_sequencing_loop having flushed and
            // applied the second order before the simulated crash --
            // the first order is deliberately left untouched, still
            // sitting in the buffer.
            {
                let mut guard = state.write().unwrap();
                let (order, receipt) = guard.pending_order_data.remove(&flushed_id).unwrap();
                crate::server::apply_accepted_order(&mut guard, order, receipt, None).unwrap();
            }

            (still_buffered_id, flushed_id)
            // `state` drops here, simulating a crash with nothing else
            // surviving.
        };

        let log = crate::persistence::PersistenceLog::open(dir.path()).unwrap();
        let mut recovered_state = AppState {
            node_id: common::NodeId(0),
            order_book: OrderBook::new("ETH-USD".to_string()),
            validator: OrderValidator::new(100),
            ws_broadcast: broadcast::channel(100).0,
            reputation: reputation::ReputationEngine::new(),
            pending_commits: std::collections::HashMap::new(),
            confirmed_trade_hashes: std::collections::HashMap::new(),
            batcher: batcher::SettlementBatcher::new(),
            receipt_signing_key: SigningKey::generate(&mut OsRng),
            order_log: orderlog::HashChainLog::new(),
            match_log: orderlog::HashChainLog::new(),
            mesh: None,
            order_sequencer: Some(OrderSequencer::new()),
            pending_order_data: std::collections::HashMap::new(),
            applied_order_ids: std::collections::HashSet::new(),
            persistence: None,
        };
        crate::server::replay_persistence_log(&mut recovered_state, &log).unwrap();

        assert!(
            recovered_state.applied_order_ids.contains(&flushed_id),
            "the flushed order must be marked applied by replay"
        );
        assert!(
            !recovered_state
                .applied_order_ids
                .contains(&still_buffered_id),
            "the still-buffered order was never actually applied before the crash"
        );

        let sequencer = recovered_state.order_sequencer.as_ref().unwrap();
        assert!(
            sequencer.pending_order_ids().contains(&still_buffered_id),
            "replay must re-queue the order that was still buffered at crash time"
        );
        assert!(
            !sequencer.pending_order_ids().contains(&flushed_id),
            "replay must NOT re-queue an order that was already flushed before the crash"
        );
        assert!(recovered_state
            .pending_order_data
            .contains_key(&still_buffered_id));
        assert!(!recovered_state.pending_order_data.contains_key(&flushed_id));
    }
}
