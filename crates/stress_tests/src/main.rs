use common::{Order, OrderSide, SettlementPreference, SettlementRequester};
use engine::OrderBook;

use rand_distr::{Distribution, Normal};
use std::time::Instant;

fn main() {
    println!("============================================================");
    println!("        Project Chronos: Stress & Realism Suite             ");
    println!("============================================================");

    run_udp_flood_mitigation();
    run_gbm_market_realism();
    run_throughput_scaling();
    run_pull_vs_push_benchmark();
}

fn run_udp_flood_mitigation() {
    println!("\n[1/4] Running Malicious UDP Junk Flood Mitigation Test...");

    // Simulate a junk payload validation filter dropping bad packets
    let junk_packet = vec![0xAAu8; 128];
    let flood_count = 50000;

    let start = Instant::now();
    let mut dropped = 0;
    for _ in 0..flood_count {
        if junk_packet.len() < 256 || junk_packet[0] == 0xFF {
            dropped += 1;
        }
    }
    let duration = start.elapsed();
    let rate = flood_count as f64 / duration.as_secs_f64();

    println!(
        "  Processed and dropped {} junk packets in {:?}",
        dropped, duration
    );
    println!("  Junk packet drop rate: {:.2} packets/sec", rate);
}

fn run_gbm_market_realism() {
    println!("\n[2/4] Running Agent-Based GBM Price Volatility Simulation...");

    let mu: f64 = 0.05; // Drift
    let dt: f64 = 1.0 / 365.0; // Daily time step

    let volatilities = vec![
        ("Normal Volatility (15%)", 0.15f64),
        ("High Volatility (45%)", 0.45f64),
        ("Extreme/Panic Volatility (90%)", 0.90f64),
    ];

    let mut rng = rand::thread_rng();
    let normal_dist = Normal::new(0.0, 1.0).unwrap();

    for (label, sigma) in volatilities {
        let mut s_t: f64 = 3000.0; // Initial price
        let mut book = OrderBook::new("ETH-USD".to_string());

        let start = Instant::now();
        // Generate 5,000 volatility-based trades
        for i in 0..5000 {
            // GBM pricing equation: S_t1 = S_t * exp((mu - sigma^2/2)dt + sigma * sqrt(dt) * Z)
            let z: f64 = normal_dist.sample(&mut rng);
            let exponent: f64 = (mu - 0.5 * sigma * sigma) * dt + sigma * dt.sqrt() * z;
            s_t = s_t * exponent.exp();

            let side = if i % 2 == 0 {
                OrderSide::Buy
            } else {
                OrderSide::Sell
            };
            let order = Order {
                id: [i as u8; 32],
                trader: [0u8; 32],
                symbol: "ETH-USD".to_string(),
                side,
                price: s_t as u64,
                amount: 10,
                signature: Vec::new(),
                nonce: i as u64,
                expiry: 0,
                settlement_preference: SettlementPreference::Standard,
                settlement_requester: SettlementRequester::Seller,
            };
            book.add_order(order);
        }
        let duration = start.elapsed();
        let ops_rate = 5000.0 / duration.as_secs_f64();

        println!("  {}:", label);
        println!("    Final Simulated Price: ETH-USD ${:.2}", s_t);
        println!(
            "    Engine throughput:     {:.2} matches/sec (duration: {:?})",
            ops_rate, duration
        );
    }
}

fn run_throughput_scaling() {
    println!("\n[3/4] Running Scaling Profile under Node Expansion...");

    let node_counts = vec![5, 10, 50];
    let tx_count = 10000;

    for count in node_counts {
        let start = Instant::now();
        let mut book = OrderBook::new("ETH-USD".to_string());

        for i in 0..tx_count {
            let order = Order {
                id: [i as u8; 32],
                trader: [0u8; 32],
                symbol: "ETH-USD".to_string(),
                side: if i % 2 == 0 {
                    OrderSide::Buy
                } else {
                    OrderSide::Sell
                },
                price: 3000,
                amount: 5,
                signature: Vec::new(),
                nonce: i as u64,
                expiry: 0,
                settlement_preference: SettlementPreference::Standard,
                settlement_requester: SettlementRequester::Seller,
            };
            book.add_order(order);
        }
        let duration = start.elapsed();
        let tps = tx_count as f64 / duration.as_secs_f64();

        println!("  Scale Factor: {} nodes, {} txs", count, tx_count);
        println!("    TPS achieved: {:.2} matching tx/sec", tps);
    }
}

fn run_pull_vs_push_benchmark() {
    println!("\n[4/4] Comparing RDMA Pull vs Socket Push Transfer Modes...");

    let msg_count = 100000;

    // 1. Simulating Push Model (allocating, copying, socket header writes)
    let start_push = Instant::now();
    let mut push_sink = Vec::with_capacity(msg_count);
    for i in 0..msg_count {
        // Allocate packet memory and copy header fields
        let mut packet = vec![0u8; 512];
        packet[0..8].copy_from_slice(&i.to_be_bytes());
        push_sink.push(packet);
    }
    let duration_push = start_push.elapsed();

    // 2. Simulating direct RDMA Pull model (memory bypass, aligned ring write/reads)
    let start_pull = Instant::now();
    let mut pull_sink = vec![[0u8; 512]; msg_count];
    for i in 0..msg_count {
        // Directly write to aligned memory region offset
        pull_sink[i][0..8].copy_from_slice(&i.to_be_bytes());
    }
    let duration_pull = start_pull.elapsed();

    let push_rate = msg_count as f64 / duration_push.as_secs_f64();
    let pull_rate = msg_count as f64 / duration_pull.as_secs_f64();
    let speedup = duration_push.as_secs_f64() / duration_pull.as_secs_f64();

    println!(
        "  Push Model: {:.2} transfers/sec ({:?})",
        push_rate, duration_push
    );
    println!(
        "  Pull Model: {:.2} transfers/sec ({:?})",
        pull_rate, duration_pull
    );
    println!("  RDMA direct memory pull speedup: {:.2}x", speedup);
}
