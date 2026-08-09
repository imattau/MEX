// Stage P3c-2 live validation: does a peer that NEVER receives an order
// over HTTP still end up independently applying and matching it, purely
// because it observed the Flood gossip? This is the actual point of
// this stage -- before it, order-sequencing only ever sequenced a node's
// OWN HTTP submissions; a peer only ever WITNESSED timing for other
// nodes' quorum purposes (Stage P3a/b), never applied anything itself.
//
// Two FULL replicas (own AppState, order_book, order_log, order_
// sequencer, axum server -- everything main.rs wires up), configured as
// mutual mesh peers. Both orders (a crossing sell + buy) are submitted
// via HTTP to Replica A ONLY. Replica A's own order-sequencing flush
// loop applies them and self-injects the resulting Flood into its own
// mesh node, which forwards it directly to Replica B (B is A's
// configured downstream peer, per protocol::MeshNode's NodeId-ordering
// routing rule). Replica B's gossip_replication loop picks up that
// arrival, queues both orders into ITS OWN order_sequencer, and its own
// flush loop independently resolves and applies them -- producing the
// SAME match, entirely from evidence B derived from its own Ping/Pong
// baseline to A and the gossiped Flood arrivals, with zero HTTP
// submissions to B at all.

use api::server::{app, AppState, MeshHandle};
use api::types::SubmitOrderResponse;
use common::{NodeId, Region};
use ed25519_dalek::{Signer, SigningKey};
use engine::OrderBook;
use futures_util::StreamExt;
use protocol::{MeshConfig, MeshNode, OrderSequencer};
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

fn build_order(
    trader: [u8; 32],
    side: common::OrderSide,
    price: u64,
    amount: u64,
    nonce: u64,
) -> common::Order {
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

// Spins up one full replica: mesh node, AppState (order-sequencing
// enabled), the sequencing flush loop, the gossip replication loop, and
// a real axum HTTP+WebSocket server. Returns its HTTP address.
async fn spawn_replica(
    node_id: u32,
    mesh_addr: std::net::SocketAddr,
    peers: Vec<(NodeId, std::net::SocketAddr)>,
    window_ms: u64,
    quorum_timeout_ms: u64,
) -> std::net::SocketAddr {
    let mut mesh_node = MeshNode::new(MeshConfig {
        node_id: NodeId(node_id),
        region: Region::UsEast1,
        listen_addr: mesh_addr,
        peers: peers
            .into_iter()
            .map(|(id, addr)| (id, addr, [0u8; 32]))
            .collect(),
        node_key: None,
        mesh_encryption_key: None,
        heartbeat_interval_ms: 5000.0,
        max_missed_heartbeats: 100,
        schedule: None,
        artificial_forward_delay_ms: None,
        require_staked_reporters: false,
        misconduct_stake_threshold: 0,
    })
    .await
    .unwrap();

    let mesh_handle = MeshHandle {
        node_id: NodeId(node_id),
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
    let flood_rx = mesh_node.flood_receiver();

    tokio::spawn(mesh_node.run());

    let (tx, _) = broadcast::channel(100);
    let state = Arc::new(RwLock::new(AppState {
        node_id: NodeId(node_id),
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
        persistence: None,
    }));

    tokio::spawn(api::run_order_sequencing_loop(
        Arc::clone(&state),
        Duration::from_millis(window_ms),
        witness_query_tx,
        propose_batch_tx,
        confirmed_batch_rx,
        Duration::from_millis(quorum_timeout_ms),
    ));
    tokio::spawn(api::run_gossip_replication_loop(
        Arc::clone(&state),
        flood_rx,
    ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = listener.local_addr().unwrap();
    let axum_app = app(state);
    tokio::spawn(async move {
        axum::serve(
            listener,
            axum_app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    http_addr
}

#[tokio::test]
async fn test_replica_never_submitted_to_still_applies_orders_via_gossip_alone() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .try_init();
    const REPLICA_A_ID: u32 = 5;
    const REPLICA_B_ID: u32 = 6; // > A, so A's mesh treats B as downstream and forwards to it
    let a_mesh_addr = addr(17020);
    let b_mesh_addr = addr(17021);
    const WINDOW_MS: u64 = 300;
    // Long enough that a quorum-confirmed application (the expected
    // path here, since A and B corroborate each other) is clearly
    // distinguishable from a fail-open timeout.
    // With only 2 replicas and one-directional information flow (B only
    // learns about an order AFTER A applies and gossips it), NEITHER
    // leg of this test can ever get real quorum corroboration: A has no
    // one to corroborate its first proposal (B doesn't know about the
    // order yet), and B has no one to corroborate its later one (A
    // isn't proposing again for the same batch). Both legs necessarily
    // fall through the fail-open timeout -- SEQUENTIALLY, since B's
    // whole pipeline only starts after A's completes -- so the real
    // wait is roughly 2x this value. Kept short since this test is about
    // whether gossip-sourced replication works AT ALL, not about
    // quorum-confirmation timing (see order_sequencing_quorum_test.rs
    // for that).
    const QUORUM_TIMEOUT_MS: u64 = 200;

    let a_http = spawn_replica(
        REPLICA_A_ID,
        a_mesh_addr,
        vec![(NodeId(REPLICA_B_ID), b_mesh_addr)],
        WINDOW_MS,
        QUORUM_TIMEOUT_MS,
    )
    .await;
    let b_http = spawn_replica(
        REPLICA_B_ID,
        b_mesh_addr,
        vec![(NodeId(REPLICA_A_ID), a_mesh_addr)],
        WINDOW_MS,
        QUORUM_TIMEOUT_MS,
    )
    .await;

    // Let real Ping/Pong establish A<->B's mutual latency baseline
    // before anything is measured against it.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let mut csprng = OsRng;
    let sk_seller = SigningKey::generate(&mut csprng);
    let pk_seller = sk_seller.verifying_key().to_bytes();
    let sk_buyer = SigningKey::generate(&mut csprng);
    let pk_buyer = sk_buyer.verifying_key().to_bytes();

    // Subscribed on REPLICA B -- the node that will NEVER receive either
    // order over HTTP.
    let mut buyer_ws_on_b = {
        let url = format!("ws://{b_http}/ws/trades/{}", hex::encode(pk_buyer));
        let mut req = url.into_client_request().unwrap();
        req.headers_mut()
            .insert("X-API-Key", "dev-default-key".parse().unwrap());
        let (ws, _) = connect_async(req).await.unwrap();
        ws
    };
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = reqwest::Client::new();

    let sell_order = build_order(pk_seller, common::OrderSide::Sell, 3000, 5, 1);
    let buy_order = build_order(pk_buyer, common::OrderSide::Buy, 3000, 5, 1);

    // BOTH submitted to A ONLY.
    let sell_req = sign_and_jsonify(&sk_seller, &sell_order);
    let sell_resp: SubmitOrderResponse = client
        .post(format!("http://{a_http}/api/v1/order"))
        .header("X-API-Key", "dev-default-key")
        .json(&sell_req)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        sell_resp.success && sell_resp.pending,
        "sell order rejected by replica A: {:?}",
        sell_resp.error
    );

    let buy_req = sign_and_jsonify(&sk_buyer, &buy_order);
    let buy_resp: SubmitOrderResponse = client
        .post(format!("http://{a_http}/api/v1/order"))
        .header("X-API-Key", "dev-default-key")
        .json(&buy_req)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        buy_resp.success && buy_resp.pending,
        "buy order rejected by replica A: {:?}",
        buy_resp.error
    );

    // Replica B's websocket must receive the match -- it can only have
    // learned about either order via gossip from A, applied them through
    // its OWN order_sequencer/gossip_replication pipeline, and matched
    // them in its OWN order_book.
    let match_msg = tokio::time::timeout(
        Duration::from_millis(2 * (WINDOW_MS + QUORUM_TIMEOUT_MS) + 1000),
        buyer_ws_on_b.next(),
    )
    .await
    .expect("replica B must eventually apply and match both orders via gossip alone")
    .unwrap()
    .unwrap();
    let received: engine::Match = match match_msg {
        tokio_tungstenite::tungstenite::Message::Text(t) => serde_json::from_str(&t).unwrap(),
        other => panic!("unexpected message type: {other:?}"),
    };
    assert!(received.maker_trader == pk_buyer || received.taker_trader == pk_buyer);

    println!("PASS: replica B independently applied and matched both orders via gossip alone -- it never received either one over HTTP.");

    let _ = buyer_ws_on_b.close(None).await;
}
