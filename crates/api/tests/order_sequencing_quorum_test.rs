// Stage P3b live validation of the actual value-add over Stage P2: does
// the sequencing flush loop's cross-node quorum gating make a REAL,
// live-observable difference, not just exist as inert plumbing? Proven
// via TIMING, not a log/metrics scrape: crates/api/tests/
// order_sequencing_live_test.rs (no witness peer) already demonstrates
// the fail-open path, where the match only arrives after
// window + quorum_timeout has elapsed. THIS test adds a genuinely
// independent witness node that proposes a corroborating batch hash
// promptly -- if quorum gating is real, the match should arrive shortly
// after the flush window closes, nowhere close to the (deliberately
// long) quorum_timeout, proving real cross-node confirmation actually
// happened rather than the loop just falling back to unconfirmed
// application.
//
// Witness design: a plain protocol::MeshNode, no AppState/order_book/
// axum server at all -- proposing a batch hash only needs
// OriginTimeEstimator evidence (accumulated automatically from ordinary
// Flood gossip) and OrderSequencer's pure resolution logic, neither of
// which needs a full sequencer/matcher stack. This is a real, useful
// architectural property: a node can serve as a network-time WITNESS
// for quorum purposes without running redundant matching at all.

use api::server::{app, AppState, MeshHandle};
use api::types::SubmitOrderResponse;
use common::{FloodMessage, NodeId, Region};
use ed25519_dalek::{Signer, SigningKey};
use engine::OrderBook;
use futures_util::StreamExt;
use protocol::{batch_quorum, MeshConfig, MeshNode, OrderSequencer, UdpTransport, WireMessage};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
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

async fn query_witness_evidence(
    sender: &tokio::sync::mpsc::Sender<([u8; 32], tokio::sync::oneshot::Sender<Option<(NodeId, f64)>>)>,
    order_id: [u8; 32],
) -> Option<(NodeId, f64)> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    sender.send((order_id, tx)).await.unwrap();
    rx.await.unwrap()
}

#[tokio::test]
async fn test_witness_corroboration_gets_batch_applied_well_before_quorum_timeout() {
    let external_peer_addr = addr(17010);
    let mesh_listen_addr = addr(17011);
    let witness_addr = addr(17012);
    const SERVER_MESH_ID: u32 = 5;
    const WITNESS_ID: u32 = 6;
    const EXTERNAL_PEER_ID: u32 = 10;
    const WINDOW_MS: u64 = 300;
    // Deliberately long -- if the match arrives in anywhere close to
    // this, that's evidence the loop fell back to unconfirmed
    // application rather than being genuinely quorum-confirmed.
    const QUORUM_TIMEOUT_MS: u64 = 5000;

    let mut external_bind = UdpTransport::bind(external_peer_addr, None).await.unwrap();
    external_bind.register_peer(NodeId(SERVER_MESH_ID), mesh_listen_addr, [0u8; 32]);
    external_bind.register_peer(NodeId(WITNESS_ID), witness_addr, [0u8; 32]);
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

    let mut server_mesh_node = MeshNode::new(MeshConfig {
        node_id: NodeId(SERVER_MESH_ID),
        region: Region::UsEast1,
        listen_addr: mesh_listen_addr,
        peers: vec![(NodeId(EXTERNAL_PEER_ID), external_peer_addr, [0u8; 32]), (NodeId(WITNESS_ID), witness_addr, [0u8; 32])],
        node_key: None,
        mesh_encryption_key: None,
        heartbeat_interval_ms: 5000.0,
        max_missed_heartbeats: 100,
        schedule: None,
        artificial_forward_delay_ms: None,
        require_staked_reporters: false,
        misconduct_stake_threshold: 0,
    }).await.unwrap();

    let witness = MeshNode::new(MeshConfig {
        node_id: NodeId(WITNESS_ID),
        region: Region::UsEast1,
        listen_addr: witness_addr,
        peers: vec![(NodeId(EXTERNAL_PEER_ID), external_peer_addr, [0u8; 32]), (NodeId(SERVER_MESH_ID), mesh_listen_addr, [0u8; 32])],
        node_key: None,
        mesh_encryption_key: None,
        heartbeat_interval_ms: 5000.0,
        max_missed_heartbeats: 100,
        schedule: None,
        artificial_forward_delay_ms: None,
        require_staked_reporters: false,
        misconduct_stake_threshold: 0,
    }).await.unwrap();
    let witness_evidence_query = witness.earliest_witness_query_sender();
    let witness_propose = witness.propose_batch_sender();

    let mesh_handle = MeshHandle {
        node_id: NodeId(SERVER_MESH_ID),
        region: Region::UsEast1,
        sender: server_mesh_node.sender(),
        transport: server_mesh_node.transport(),
        peer_ids: server_mesh_node.peer_ids(),
        chain_status_tx: server_mesh_node.chain_status_sender(),
        earliest_witness_query_tx: server_mesh_node.earliest_witness_query_sender(),
        propose_batch_tx: server_mesh_node.propose_batch_sender(),
    };
    let server_witness_query = mesh_handle.earliest_witness_query_tx.clone();
    let server_propose = mesh_handle.propose_batch_tx.clone();
    let server_confirmed_batch_rx = server_mesh_node.confirmed_batch_receiver();

    tokio::spawn(server_mesh_node.run());
    tokio::spawn(witness.run());

    let (tx, _) = broadcast::channel(100);
    let state = Arc::new(RwLock::new(AppState {
        node_id: NodeId(SERVER_MESH_ID),
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
        applied_order_ids: std::collections::HashSet::new(),
    }));

    tokio::spawn(api::run_order_sequencing_loop(
        Arc::clone(&state),
        Duration::from_millis(WINDOW_MS),
        server_witness_query,
        server_propose,
        server_confirmed_batch_rx,
        Duration::from_millis(QUORUM_TIMEOUT_MS),
    ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = listener.local_addr().unwrap();
    let axum_app = app(state);
    tokio::spawn(async move {
        axum::serve(listener, axum_app).await.unwrap();
    });

    // Let real Ping/Pong establish latency baselines (server<->external,
    // witness<->external) before anything is measured against them.
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

    let submit_start = Instant::now();

    let sell_req = sign_and_jsonify(&sk_seller, &sell_order);
    let sell_resp: SubmitOrderResponse = client.post(format!("{base}/api/v1/order"))
        .header("X-API-Key", "dev-default-key")
        .json(&sell_req)
        .send().await.unwrap()
        .json().await.unwrap();
    assert!(sell_resp.success && sell_resp.pending && sell_resp.matches.is_empty());

    let buy_req = sign_and_jsonify(&sk_buyer, &buy_order);
    let buy_resp: SubmitOrderResponse = client.post(format!("{base}/api/v1/order"))
        .header("X-API-Key", "dev-default-key")
        .json(&buy_req)
        .send().await.unwrap()
        .json().await.unwrap();
    assert!(buy_resp.success && buy_resp.pending && buy_resp.matches.is_empty());

    // Relay both orders to BOTH the server's mesh node AND the witness --
    // both need to observe the same Flood traffic to accumulate matching
    // network-time evidence.
    for order in [&sell_order, &buy_order] {
        let t = now_ms();
        let msg_to_server = FloodMessage { order: order.clone(), hop_count: 0, path: vec![NodeId(EXTERNAL_PEER_ID)], timestamp: t, source_region: Region::UsEast1 };
        let msg_to_witness = msg_to_server.clone();
        external_peer.send(NodeId(SERVER_MESH_ID), WireMessage::Flood(msg_to_server)).await.unwrap();
        external_peer.send(NodeId(WITNESS_ID), WireMessage::Flood(msg_to_witness)).await.unwrap();
    }

    // Give evidence a moment to land, then have the witness independently
    // resolve and propose -- well before the server's own flush window
    // closes, so its proposal is already available when the server asks
    // for quorum.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let order_ids = vec![sell_order.id, buy_order.id];
    let mut witness_sequencer = OrderSequencer::new();
    for &id in &order_ids {
        witness_sequencer.add(id);
    }
    let mut witness_evidence = HashMap::new();
    for &id in &order_ids {
        if let Some(w) = query_witness_evidence(&witness_evidence_query, id).await {
            witness_evidence.insert(id, w);
        }
    }
    let witness_resolved = witness_sequencer.flush(&witness_evidence);
    let witness_batch_key = batch_quorum::compute_batch_key(&witness_resolved);
    witness_propose.send((witness_batch_key, witness_resolved)).await.unwrap();

    // The match must arrive comfortably before QUORUM_TIMEOUT_MS would
    // even matter -- proving real quorum confirmation, not the fail-open
    // path (see order_sequencing_live_test.rs for that path's timing).
    let match_msg = tokio::time::timeout(Duration::from_millis(QUORUM_TIMEOUT_MS), buyer_ws.next())
        .await
        .expect("buyer socket must receive the match")
        .unwrap()
        .unwrap();
    let elapsed = submit_start.elapsed();

    let received: engine::Match = match match_msg {
        tokio_tungstenite::tungstenite::Message::Text(t) => serde_json::from_str(&t).unwrap(),
        other => panic!("unexpected message type: {other:?}"),
    };
    assert!(received.maker_trader == pk_buyer || received.taker_trader == pk_buyer);

    println!("match arrived {elapsed:?} after submission (window={WINDOW_MS}ms, quorum_timeout={QUORUM_TIMEOUT_MS}ms)");
    assert!(
        elapsed < Duration::from_millis(WINDOW_MS + 1500),
        "match should arrive shortly after the flush window closes when a witness corroborates promptly -- took {elapsed:?}, which is close to or past the {QUORUM_TIMEOUT_MS}ms fail-open timeout, suggesting quorum was NOT actually reached"
    );

    println!("PASS: witness corroboration let the batch be applied via real cross-node quorum confirmation, well before the fail-open timeout.");

    let _ = buyer_ws.close(None).await;
}
