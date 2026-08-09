// Stage P2 live validation: does the REAL api server -- a real AppState,
// a real MeshNode, a real order_sequencing::run_order_sequencing_loop,
// served over a real axum::serve HTTP+WebSocket listener -- actually ack
// submit_order immediately with `pending: true` and empty matches, then
// deliver the real match asynchronously over the existing ws_broadcast
// websocket once the flush window resolves true order and applies it?
// This assembles the exact same pieces api::main.rs wires together
// (rather than spawning the real `api` binary as a subprocess, which
// crates/trader-client's verify_mesh_flood_live expects to already be
// running externally), so it's a faithful integration test, not just
// exercising OrderSequencer in isolation (see protocol's
// order_sequencer_test.rs for that, Stage P1).
//
// Real subtlety this test has to work around: submit_order injects a
// submitted order's Flood "as if received from ourselves" (see
// server.rs's apply_accepted_order), meaning from_node == the server's
// OWN mesh node_id for that arrival -- and MeshNode never Pings itself,
// so it has no latency baseline to correct that specific arrival by
// (protocol::ordering::OriginTimeEstimator's whole mechanism depends on
// one). Self-injection ALONE can never produce real network-time
// evidence for an order. This test's "external peer" (a bare
// UdpTransport, standing in for a genuinely independent second mesh
// participant) relays the SAME order directly to the server's mesh
// listen address too, giving OriginTimeEstimator a witnessed hop it DOES
// have an established baseline for -- exactly the kind of independent
// corroboration the whole O1-O3 arc is built around.

use api::server::{app, AppState, MeshHandle};
use api::types::SubmitOrderResponse;
use common::{FloodMessage, NodeId, Region};
use ed25519_dalek::{Signer, SigningKey};
use engine::OrderBook;
use futures_util::StreamExt;
use protocol::{MeshConfig, MeshNode, OrderSequencer, UdpTransport, WireMessage};
use rand::rngs::OsRng;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use validation::OrderValidator;

fn addr(port: u16) -> std::net::SocketAddr {
    format!("127.0.0.1:{}", port).parse().unwrap()
}

fn build_order(trader: [u8; 32], side: common::OrderSide, price: u64, amount: u64, nonce: u64) -> common::Order {
    let mut order_id = [0u8; 32];
    order_id[0..16].copy_from_slice(&trader[0..16]);
    order_id[16..24].copy_from_slice(&nonce.to_be_bytes());
    common::Order {
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
    }
}

fn sign_and_jsonify(sk: &SigningKey, order: &common::Order) -> serde_json::Value {
    let msg = OrderValidator::serialize_order_message(order);
    let signature = sk.sign(&msg).to_vec();
    serde_json::json!({
        "trader": order.trader, "symbol": order.symbol, "side": order.side,
        "price": order.price, "amount": order.amount,
        "signature": signature,
        "nonce": order.nonce, "expiry": order.expiry,
    })
}

fn now_ms() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
        * 1000.0
}

#[tokio::test]
async fn test_sequenced_submission_acks_immediately_and_match_arrives_async_over_websocket() {
    let external_peer_addr = addr(17000);
    let mesh_listen_addr = addr(17001);
    const MESH_NODE_ID: u32 = 5;
    const EXTERNAL_PEER_ID: u32 = 10;
    const WINDOW_MS: u64 = 200;
    // This test has no OTHER mesh node running order-sequencing to
    // propose a corroborating batch hash -- it exercises Stage P3b's
    // fail-open path (no quorum reached in time -> apply this node's own
    // resolution anyway, loudly logged as unconfirmed), same as a lone
    // sequencer with no peers would in a real deployment. Kept short so
    // this test doesn't spend long sitting in that wait.
    const QUORUM_TIMEOUT_MS: u64 = 150;

    // The external peer: answers Pings (so the server's mesh node
    // establishes a real latency baseline to it) and, later, relays each
    // submitted order's Flood directly -- see this file's docs on why
    // that's needed for any real evidence to exist at all.
    let mut external_bind = UdpTransport::bind(external_peer_addr, None).await.unwrap();
    external_bind.register_peer(NodeId(MESH_NODE_ID), mesh_listen_addr, [0u8; 32]);
    let external_peer = Arc::new(external_bind);
    {
        let external_peer = external_peer.clone();
        tokio::spawn(async move {
            loop {
                if let Ok((from, WireMessage::Ping { nonce, .. })) = external_peer.recv().await {
                    let _ = external_peer.send(from, WireMessage::Pong { nonce }).await;
                }
            }
        });
    }

    let mut mesh_node = MeshNode::new(MeshConfig {
        node_id: NodeId(MESH_NODE_ID),
        region: Region::UsEast1,
        listen_addr: mesh_listen_addr,
        peers: vec![(NodeId(EXTERNAL_PEER_ID), external_peer_addr, [0u8; 32])],
        node_key: None,
        mesh_encryption_key: None,
        heartbeat_interval_ms: 5000.0,
        max_missed_heartbeats: 100,
        schedule: None,
        artificial_forward_delay_ms: None,
        require_staked_reporters: false,
        misconduct_stake_threshold: 0,
    }).await.unwrap();

    let mesh_handle = MeshHandle {
        node_id: NodeId(MESH_NODE_ID),
        region: Region::UsEast1,
        sender: mesh_node.sender(),
        transport: mesh_node.transport(),
        peer_ids: mesh_node.peer_ids(),
        chain_status_tx: mesh_node.chain_status_sender(),
        earliest_witness_query_tx: mesh_node.earliest_witness_query_sender(),
        propose_batch_tx: mesh_node.propose_batch_sender(),
    };
    let witness_query_tx = mesh_handle.earliest_witness_query_tx.clone();
    let propose_batch_tx = mesh_handle.propose_batch_tx.clone();
    let confirmed_batch_rx = mesh_node.confirmed_batch_receiver();

    tokio::spawn(mesh_node.run());

    let (tx, _) = broadcast::channel(100);
    let state = Arc::new(RwLock::new(AppState {
        node_id: NodeId(MESH_NODE_ID),
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
        mesh: Some(mesh_handle),
        order_sequencer: Some(OrderSequencer::new()),
        pending_order_data: std::collections::HashMap::new(),
    }));

    tokio::spawn(api::run_order_sequencing_loop(
        Arc::clone(&state),
        Duration::from_millis(WINDOW_MS),
        witness_query_tx,
        propose_batch_tx,
        confirmed_batch_rx,
        Duration::from_millis(QUORUM_TIMEOUT_MS),
    ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = listener.local_addr().unwrap();
    let axum_app = app(state);
    tokio::spawn(async move {
        axum::serve(listener, axum_app).await.unwrap();
    });

    // Let real Ping/Pong establish the server mesh node's baseline to
    // the external peer before anything is measured against it.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let mut csprng = OsRng;
    let sk_seller = SigningKey::generate(&mut csprng);
    let pk_seller = sk_seller.verifying_key().to_bytes();
    let sk_buyer = SigningKey::generate(&mut csprng);
    let pk_buyer = sk_buyer.verifying_key().to_bytes();

    let mut buyer_ws = {
        let url = format!("ws://{http_addr}/ws/trades/{}", hex::encode(pk_buyer));
        let mut req = url.into_client_request().unwrap();
        req.headers_mut().insert("X-API-Key", "dev-default-key".parse().unwrap());
        let (ws, _) = connect_async(req).await.unwrap();
        ws
    };
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = reqwest::Client::new();
    let base = format!("http://{http_addr}");

    let sell_order = build_order(pk_seller, common::OrderSide::Sell, 3000, 5, 1);
    let buy_order = build_order(pk_buyer, common::OrderSide::Buy, 3000, 5, 1);

    let sell_req = sign_and_jsonify(&sk_seller, &sell_order);
    let sell_resp: SubmitOrderResponse = client.post(format!("{base}/api/v1/order"))
        .header("X-API-Key", "dev-default-key")
        .json(&sell_req)
        .send().await.unwrap()
        .json().await.unwrap();
    assert!(sell_resp.success, "sell order rejected: {:?}", sell_resp.error);
    assert!(sell_resp.pending, "with order-sequencing enabled, submit_order must ack with pending=true");
    assert!(sell_resp.matches.is_empty(), "a pending response must never carry matches -- they haven't been resolved yet");

    let buy_req = sign_and_jsonify(&sk_buyer, &buy_order);
    let buy_resp: SubmitOrderResponse = client.post(format!("{base}/api/v1/order"))
        .header("X-API-Key", "dev-default-key")
        .json(&buy_req)
        .send().await.unwrap()
        .json().await.unwrap();
    assert!(buy_resp.success, "buy order rejected: {:?}", buy_resp.error);
    assert!(buy_resp.pending, "with order-sequencing enabled, submit_order must ack with pending=true");
    assert!(buy_resp.matches.is_empty(), "a pending response must never carry matches -- they haven't been resolved yet");

    // Give the server's own self-injected Flood a moment's head start,
    // then relay the SAME two orders from the external peer -- the
    // witnessed hop that actually lets OriginTimeEstimator produce a
    // real estimate (see this file's docs).
    for order in [&sell_order, &buy_order] {
        let msg = FloodMessage { order: order.clone(), hop_count: 0, path: vec![NodeId(EXTERNAL_PEER_ID)], timestamp: now_ms(), source_region: Region::UsEast1 };
        external_peer.send(NodeId(MESH_NODE_ID), WireMessage::Flood(msg)).await.unwrap();
    }

    // Past the flush window -- the loop should have resolved and applied
    // both orders by now, producing a match.
    let match_msg = tokio::time::timeout(Duration::from_millis(WINDOW_MS + QUORUM_TIMEOUT_MS + 500), buyer_ws.next())
        .await
        .expect("buyer socket must eventually receive the match once the sequencing loop applies both orders")
        .unwrap()
        .unwrap();
    let received: engine::Match = match match_msg {
        tokio_tungstenite::tungstenite::Message::Text(t) => serde_json::from_str(&t).unwrap(),
        other => panic!("unexpected message type: {other:?}"),
    };
    assert!(received.maker_trader == pk_buyer || received.taker_trader == pk_buyer, "the async match must actually involve the buyer who submitted it");

    println!("PASS: submit_order acked immediately with pending=true/empty matches; the real match arrived asynchronously over the websocket after the sequencing loop applied both orders in resolved order.");

    let _ = buyer_ws.close(None).await;
}
