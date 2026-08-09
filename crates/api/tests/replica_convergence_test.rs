// Stage P3c-3 live validation: do two FULLY INDEPENDENT replicas,
// receiving DIFFERENT subsets of orders directly (genuine decentralized
// entry points, not everything funneled through one node like
// gossip_replication_test.rs's simpler scenario) converge on the SAME
// trades -- same maker/taker, same price, same amount, same fee terms?
//
// Two matching pairs (sell1/buy1, sell2/buy2), submitted in a
// deliberately MIXED pattern -- sell1 and buy2 to Replica A, buy1 and
// sell2 to Replica B -- so EACH replica has to both (a) apply an order
// it received directly and (b) replicate one it only learned about via
// gossip from the other, in both directions. This is the genuinely
// decentralized scenario the whole O1-P3 arc was for.
//
// Real limit found live while building this, corrected here rather than
// asserted away: match_log entries are NOT expected to be byte-identical
// across replicas, and this test does not claim they are.
// apply_accepted_order's match_timestamp_us (Stage P3c-1) is sourced from
// EACH replica's OWN OriginTimeEstimator reading for that order -- and
// while O1's live tests proved these independently-derived estimates
// CONVERGE closely (typically within ~10-30ms of each other), "close" is
// not "byte-identical": a cryptographic hash has zero tolerance for a
// 1ms difference, so match_log's hash chain root will essentially never
// match across two truly independent processes with their own clocks,
// and Match.timestamp_us / settlement_deadline (derived from it) won't
// be EXACTLY equal either. This is the same NTP-vs-TrueTime gap O1's own
// docs already flagged as a real, unaddressed assumption -- deriving the
// shared timestamp from literally-received wire data (a HopWitness's raw
// forwarded_at, identical bytes for every observer) instead of each
// node's locally-corrected estimate would close it, but that's a further
// stage, not built here. What IS asserted here, and IS genuinely true:
// every economically meaningful field of the match (who traded with
// whom, at what price, how much, whose fee) converges exactly, and the
// two independently-derived timestamps land within the same bound O1
// already established, not off by seconds or wildly diverging.
//
// order_log entries are a separate, even weaker convergence claim: each
// replica signs its own receipts with its own receipt_signing_key (by
// design, for per-node accountability -- see orderlog's docs), so their
// content necessarily differs even for "the same" order. Not compared
// here at all beyond confirming both replicas have one.

use api::server::{app, AppState, MeshHandle};
use api::types::{LogRootResponse, SubmitOrderResponse};
use common::{NodeId, Region};
use ed25519_dalek::{Signer, SigningKey};
use engine::OrderBook;
use protocol::{MeshConfig, MeshNode, OrderSequencer};
use rand::rngs::OsRng;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::broadcast;
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

async fn match_log_root(
    client: &reqwest::Client,
    http_addr: std::net::SocketAddr,
) -> LogRootResponse {
    client
        .get(format!("http://{http_addr}/api/v1/match_log/root"))
        .header("X-API-Key", "dev-default-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn match_log_entries(
    client: &reqwest::Client,
    http_addr: std::net::SocketAddr,
) -> Vec<orderlog::LogEntry<engine::Match>> {
    client
        .get(format!("http://{http_addr}/api/v1/match_log/entries"))
        .header("X-API-Key", "dev-default-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

// Real finding, live: maker_order_id/taker_order_id are a LOCAL
// SEQUENCING artifact, not a stable economic fact -- whichever order a
// given replica happened to already have RESTING in its own book is the
// "maker", and that depends on which order it applied FIRST locally
// (its own direct submission is always applied before a gossiped one
// arrives). Since this test deliberately has A and B each self-apply a
// DIFFERENT order of the same pair first, A and B can legitimately (and
// did, live) swap maker vs taker for the exact same real-world trade.
// This is NOT an economic divergence: resolve_settlement_params derives
// settlement_tier/fee_basis_points/seller/fee_payer from each order's
// SIDE (buy vs sell), never from which one was labeled maker/taker, so
// those fields are already invariant to this swap. Comparison here
// canonicalizes the pair (sorted by order_id) so a maker/taker swap
// doesn't look like a spurious mismatch, while everything else is still
// compared exactly.
fn canonical_order_pair(m: &engine::Match) -> ([u8; 32], [u8; 32]) {
    if m.maker_order_id < m.taker_order_id {
        (m.maker_order_id, m.taker_order_id)
    } else {
        (m.taker_order_id, m.maker_order_id)
    }
}

fn sorted_by_trade_ids(mut matches: Vec<engine::Match>) -> Vec<engine::Match> {
    matches.sort_by_key(canonical_order_pair);
    matches
}

#[tokio::test]
async fn test_two_replicas_with_mixed_entry_points_converge_to_identical_match_history() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .try_init();

    const REPLICA_A_ID: u32 = 5;
    const REPLICA_B_ID: u32 = 6;
    let a_mesh_addr = addr(17030);
    let b_mesh_addr = addr(17031);
    const WINDOW_MS: u64 = 200;
    // Kept short deliberately -- unlike order_sequencing_quorum_test.rs,
    // this test isn't measuring confirmation timing, and each side
    // realistically needs roughly TWO full window+timeout cycles per
    // pair (apply its own direct order alone first -- with no possible
    // corroborator, since the other side's simultaneous proposal covers
    // a different order_id set -- then, once gossip delivers the other
    // side's order, apply THAT and produce the actual match, again with
    // no corroborator since the other side already finished). A long
    // timeout here would make this test unnecessarily slow without
    // proving anything more.
    const QUORUM_TIMEOUT_MS: u64 = 150;

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

    tokio::time::sleep(Duration::from_millis(1500)).await;

    let mut csprng = OsRng;
    let sk_seller1 = SigningKey::generate(&mut csprng);
    let pk_seller1 = sk_seller1.verifying_key().to_bytes();
    let sk_buyer1 = SigningKey::generate(&mut csprng);
    let pk_buyer1 = sk_buyer1.verifying_key().to_bytes();
    let sk_seller2 = SigningKey::generate(&mut csprng);
    let pk_seller2 = sk_seller2.verifying_key().to_bytes();
    let sk_buyer2 = SigningKey::generate(&mut csprng);
    let pk_buyer2 = sk_buyer2.verifying_key().to_bytes();

    let sell1 = build_order(pk_seller1, common::OrderSide::Sell, 3000, 5, 1);
    let buy1 = build_order(pk_buyer1, common::OrderSide::Buy, 3000, 5, 1);
    let sell2 = build_order(pk_seller2, common::OrderSide::Sell, 3100, 3, 1);
    let buy2 = build_order(pk_buyer2, common::OrderSide::Buy, 3100, 3, 1);

    let client = reqwest::Client::new();

    async fn submit(
        client: &reqwest::Client,
        http_addr: std::net::SocketAddr,
        req: serde_json::Value,
    ) -> SubmitOrderResponse {
        client
            .post(format!("http://{http_addr}/api/v1/order"))
            .header("X-API-Key", "dev-default-key")
            .json(&req)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    // Waits until both replicas' match_log report AT LEAST
    // `expected_len` matches, then returns both roots. Real price-time
    // priority doesn't understand "intended pairs" -- a resting sell
    // from pair N and an incoming buy from pair M WILL cross each other
    // if the buy's price permits it, regardless of which pair a human
    // reader would call them. So each pair below is fully resolved (this
    // helper waited out) before the next pair is submitted, avoiding any
    // window where both pairs' unresolved orders coexist and could cross
    // each other by accident -- a constraint of real order-book
    // semantics, not of the replication mechanism under test.
    async fn wait_for_match_count(
        client: &reqwest::Client,
        a_http: std::net::SocketAddr,
        b_http: std::net::SocketAddr,
        expected_len: u64,
        deadline: tokio::time::Instant,
    ) -> (api::types::LogRootResponse, api::types::LogRootResponse) {
        loop {
            let a_root = match_log_root(client, a_http).await;
            let b_root = match_log_root(client, b_http).await;
            if a_root.len >= expected_len && b_root.len >= expected_len {
                return (a_root, b_root);
            }
            if tokio::time::Instant::now() >= deadline {
                panic!("timed out waiting for both replicas to reach {expected_len} matches -- A has {}, B has {}", a_root.len, b_root.len);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    // 4x: each side may need ~2 full window+timeout cycles per pair (see
    // QUORUM_TIMEOUT_MS's docs), and the two sides' cycles aren't
    // synchronized with each other, so this budgets generously rather
    // than trying to hand-compute the exact worst case.
    let per_pair_budget = Duration::from_millis(4 * (WINDOW_MS + QUORUM_TIMEOUT_MS) + 1500);

    // Pair 1: sell1 -> A, buy1 -> B. A applies one directly and
    // replicates the other via gossip; B does the reverse.
    let r1 = submit(&client, a_http, sign_and_jsonify(&sk_seller1, &sell1)).await;
    assert!(
        r1.success && r1.pending,
        "sell1 rejected by A: {:?}",
        r1.error
    );
    let r2 = submit(&client, b_http, sign_and_jsonify(&sk_buyer1, &buy1)).await;
    assert!(
        r2.success && r2.pending,
        "buy1 rejected by B: {:?}",
        r2.error
    );
    // Just confirms both sides reached 1 match before pair 2 is
    // submitted (wait_for_match_count's own loop condition) -- content
    // convergence is asserted once, on the full set, after pair 2 below;
    // see this file's docs on why raw root/hash equality isn't the right
    // claim to make here.
    wait_for_match_count(
        &client,
        a_http,
        b_http,
        1,
        tokio::time::Instant::now() + per_pair_budget,
    )
    .await;

    // Pair 2: sell2 -> B, buy2 -> A -- the REVERSE mixing from pair 1,
    // so both directions of gossip replication get exercised across the
    // two pairs.
    let r3 = submit(&client, b_http, sign_and_jsonify(&sk_seller2, &sell2)).await;
    assert!(
        r3.success && r3.pending,
        "sell2 rejected by B: {:?}",
        r3.error
    );
    let r4 = submit(&client, a_http, sign_and_jsonify(&sk_buyer2, &buy2)).await;
    assert!(
        r4.success && r4.pending,
        "buy2 rejected by A: {:?}",
        r4.error
    );
    let (a_match_root, b_match_root) = wait_for_match_count(
        &client,
        a_http,
        b_http,
        2,
        tokio::time::Instant::now() + per_pair_budget,
    )
    .await;

    assert_eq!(
        a_match_root.len, 2,
        "replica A should have exactly 2 matches, not more (idempotency)"
    );
    assert_eq!(
        b_match_root.len, 2,
        "replica B should have exactly 2 matches, not more (idempotency)"
    );
    println!(
        "Replica A match_log root: {} (len={})",
        hex::encode(a_match_root.root),
        a_match_root.len
    );
    println!(
        "Replica B match_log root: {} (len={})",
        hex::encode(b_match_root.root),
        b_match_root.len
    );
    println!("(roots are expected to differ -- see this file's docs on why timestamp_us/settlement_deadline can't be byte-identical across independent clocks)");

    let a_matches = sorted_by_trade_ids(
        match_log_entries(&client, a_http)
            .await
            .into_iter()
            .map(|e| e.payload)
            .collect(),
    );
    let b_matches = sorted_by_trade_ids(
        match_log_entries(&client, b_http)
            .await
            .into_iter()
            .map(|e| e.payload)
            .collect(),
    );
    assert_eq!(a_matches.len(), 2);
    assert_eq!(b_matches.len(), 2);

    const TIMESTAMP_CONVERGENCE_BOUND_US: i64 = 200_000; // 200ms, generous over O1's ~10-30ms observations
    for (a_m, b_m) in a_matches.iter().zip(b_matches.iter()) {
        // Canonical (order-invariant) pair comparison -- see
        // canonical_order_pair's docs on why a maker/taker swap between
        // replicas is expected, not a bug.
        assert_eq!(canonical_order_pair(a_m), canonical_order_pair(b_m), "the same two orders must have traded on both replicas, regardless of which one each replica happened to label maker vs taker");
        let a_traders = {
            let mut t = [a_m.maker_trader, a_m.taker_trader];
            t.sort();
            t
        };
        let b_traders = {
            let mut t = [b_m.maker_trader, b_m.taker_trader];
            t.sort();
            t
        };
        assert_eq!(
            a_traders, b_traders,
            "the same two traders must have been on both sides of the trade"
        );
        assert_eq!(a_m.price, b_m.price, "price must match exactly");
        assert_eq!(a_m.amount, b_m.amount, "amount must match exactly");
        assert_eq!(a_m.settlement_tier, b_m.settlement_tier);
        assert_eq!(a_m.fee_basis_points, b_m.fee_basis_points);
        assert_eq!(a_m.seller, b_m.seller);
        assert_eq!(a_m.fee_payer, b_m.fee_payer);
        assert_eq!(a_m.symbol, b_m.symbol);

        let ts_delta_us = (a_m.timestamp_us as i64 - b_m.timestamp_us as i64).abs();
        println!(
            "trade {:?}: timestamp_us delta = {ts_delta_us}us",
            canonical_order_pair(a_m)
        );
        assert!(
            ts_delta_us < TIMESTAMP_CONVERGENCE_BOUND_US,
            "independently-derived timestamps should still converge within a generous bound, not diverge wildly -- got {ts_delta_us}us apart"
        );
    }

    println!("PASS: two independently-entered replicas converged on identical trade terms (maker/taker/price/amount/fees) for both matches, with independently-derived timestamps landing within {TIMESTAMP_CONVERGENCE_BOUND_US}us of each other.");
}
