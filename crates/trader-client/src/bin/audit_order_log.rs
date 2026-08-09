// Standalone fairness auditor for a live `api` server: fetches its
// order_log and match_log over HTTP, verifies both hash chains and every
// receipt signature independently (no trust in the server needed for
// that part), then replays strict price-time-priority matching against
// the order log using the REAL engine::OrderBook -- the same matching
// code the server itself runs -- and diffs the replayed matches against
// what the server actually reported in match_log. Divergence is provable
// evidence the server didn't match orders the way it claims to.
//
// Scope: this compares the fields fully determined by the order sequence
// itself (maker/taker order ids and traders, price, amount, seller,
// fee_payer) -- NOT fee_basis_points or settlement_deadline, which also
// depend on the server's live FeeCalculator config and wall-clock time at
// match, neither of which is captured in the log. A real mismatch in fee
// or deadline isn't itself proof of unfair MATCHING (it could just be a
// fee-schedule question), so it's out of scope for this specific check.
//
// Usage:
//   cargo run -p trader-client --bin audit_order_log -- <api_base_url>

use common::Order;
use engine::{Match, OrderBook};
use orderlog::{verify_chain, verify_receipt, LogEntry, OrderReceipt};

#[derive(serde::Deserialize)]
struct LogRootResponse {
    root: [u8; 32],
    len: u64,
}

fn hex32(b: &[u8; 32]) -> String {
    hex::encode(b)
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let api_base = args
        .get(1)
        .expect("usage: audit_order_log <api_base_url>")
        .trim_end_matches('/')
        .to_string();

    let http = reqwest::Client::new();
    let api_key = std::env::var("MEX_API_KEY").unwrap_or_else(|_| "dev-default-key".to_string());

    println!("=== Fetching order log and match log from {api_base} ===\n");

    let order_root: LogRootResponse = http
        .get(format!("{api_base}/api/v1/order_log/root"))
        .header("X-API-Key", &api_key)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let order_entries: Vec<LogEntry<OrderReceipt>> = http
        .get(format!("{api_base}/api/v1/order_log/entries"))
        .header("X-API-Key", &api_key)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let match_root: LogRootResponse = http
        .get(format!("{api_base}/api/v1/match_log/root"))
        .header("X-API-Key", &api_key)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let match_entries: Vec<LogEntry<Match>> = http
        .get(format!("{api_base}/api/v1/match_log/entries"))
        .header("X-API-Key", &api_key)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    println!(
        "order_log: {} entries, published root {}",
        order_root.len,
        hex32(&order_root.root)
    );
    println!(
        "match_log: {} entries, published root {}\n",
        match_root.len,
        hex32(&match_root.root)
    );

    assert_eq!(
        order_entries.len() as u64,
        order_root.len,
        "order_log entry count doesn't match published root's len"
    );
    assert_eq!(
        match_entries.len() as u64,
        match_root.len,
        "match_log entry count doesn't match published root's len"
    );

    // Step 1: hash-chain integrity -- proves nothing was inserted,
    // deleted, or reordered after being logged, independent of trusting
    // the server that served this data right now.
    assert!(
        verify_chain(&order_entries),
        "order_log hash chain is broken -- log has been tampered with"
    );
    assert!(
        verify_chain(&match_entries),
        "match_log hash chain is broken -- log has been tampered with"
    );
    println!("order_log hash chain: internally consistent (untampered)");
    println!("match_log hash chain: internally consistent (untampered)\n");

    if order_entries.last().map(|e| e.entry_hash) != Some(order_root.root) {
        panic!("order_log's last entry_hash doesn't match the published root");
    }
    if match_entries.last().map(|e| e.entry_hash) != Some(match_root.root) {
        panic!("match_log's last entry_hash doesn't match the published root");
    }
    println!("both logs' last entry matches their published root: OK\n");

    // Step 2: every receipt's signature -- proves each receipt really was
    // signed by the node key it claims, not fabricated after the fact.
    for entry in &order_entries {
        assert!(
            verify_receipt(&entry.payload),
            "order_log entry seq={} has an invalid signature",
            entry.seq
        );
    }
    println!(
        "all {} order receipts independently verified against their claimed node_pubkey: OK\n",
        order_entries.len()
    );

    // Step 3: replay strict price-time-priority matching against the
    // order log using the REAL engine::OrderBook, and diff against what
    // the server actually reported.
    //
    // Single-symbol assumption matches this system's actual design --
    // one running `api` server (crates/api/src/main.rs) only ever serves
    // one symbol (MEX_API_SYMBOL), so there is no cross-symbol ordering
    // question to resolve here.
    let symbol = order_entries
        .first()
        .map(|e| e.payload.symbol.clone())
        .unwrap_or_default();
    let mut book = OrderBook::new(symbol);
    let mut replayed_matches: Vec<Match> = Vec::new();

    for entry in &order_entries {
        let r = &entry.payload;
        let order = Order {
            id: r.order_id,
            trader: r.trader,
            symbol: r.symbol.clone(),
            side: r.side,
            price: r.price,
            amount: r.amount,
            signature: Vec::new(), // not needed for matching logic itself
            nonce: r.nonce,
            expiry: r.expiry,
            settlement_preference: r.settlement_preference,
            settlement_requester: r.settlement_requester,
        };
        replayed_matches.extend(book.add_order(order));
    }

    println!(
        "replayed {} orders through a fresh, independent OrderBook -> {} matches produced\n",
        order_entries.len(),
        replayed_matches.len()
    );

    if replayed_matches.len() != match_entries.len() {
        println!(
            "MISMATCH: server reported {} matches, replay produced {} -- FAIRNESS VIOLATION",
            match_entries.len(),
            replayed_matches.len()
        );
        std::process::exit(1);
    }

    let mut mismatches = 0;
    for (i, (replayed, reported)) in replayed_matches
        .iter()
        .zip(match_entries.iter().map(|e| &e.payload))
        .enumerate()
    {
        let core_matches = replayed.maker_order_id == reported.maker_order_id
            && replayed.taker_order_id == reported.taker_order_id
            && replayed.maker_trader == reported.maker_trader
            && replayed.taker_trader == reported.taker_trader
            && replayed.price == reported.price
            && replayed.amount == reported.amount
            && replayed.seller == reported.seller
            && replayed.fee_payer == reported.fee_payer;

        if !core_matches {
            mismatches += 1;
            println!("MISMATCH at match #{i}:");
            println!(
                "  replayed: maker={} taker={} price={} amount={} seller={}",
                hex::encode(replayed.maker_order_id),
                hex::encode(replayed.taker_order_id),
                replayed.price,
                replayed.amount,
                hex::encode(replayed.seller)
            );
            println!(
                "  reported: maker={} taker={} price={} amount={} seller={}",
                hex::encode(reported.maker_order_id),
                hex::encode(reported.taker_order_id),
                reported.price,
                reported.amount,
                hex::encode(reported.seller)
            );
        }
    }

    if mismatches > 0 {
        println!("\n{mismatches} FAIRNESS VIOLATION(S) DETECTED -- server's reported matches diverge from correct price-time-priority replay");
        std::process::exit(1);
    }

    println!("all {} matches verified: server's reported matches exactly match correct price-time-priority replay", replayed_matches.len());
    println!("\nAUDIT PASSED: order log and match log are both untampered, every receipt is authentically signed, and every reported match is exactly what fair price-time-priority matching would have produced.");
}
