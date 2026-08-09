use common::{Order, OrderSide, SettlementPreference, SettlementRequester};
use engine::OrderBook;
use rdma::{PullScheduler, TraderMemoryRegionManager};
use security::{decrypt_packet, encrypt_packet};
use validation::OrderValidator;

use ed25519_dalek::Signer;
use rand::rngs::OsRng;
use std::time::Instant;

fn main() {
    println!("============================================================");
    println!("        Project Chronos: Performance & Stress Suite         ");
    println!("============================================================");

    benchmark_matching_engine();
    benchmark_signature_cache();
    benchmark_rdma_scheduler();
    benchmark_aead_encryption();
}

fn benchmark_matching_engine() {
    println!("\n[1/4] Benchmarking Price-Time OrderBook Matching...");
    let mut book = OrderBook::new("ETH-USD".to_string());
    let mut latencies = Vec::new();

    // Create 10,000 resting orders
    for i in 0..10000 {
        let order = Order {
            id: [i as u8; 32],
            trader: [0u8; 32],
            symbol: "ETH-USD".to_string(),
            side: OrderSide::Buy,
            price: 3000 - (i % 100),
            amount: 10,
            signature: Vec::new(),
            nonce: i as u64,
            expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };
        book.add_order(order);
    }

    // Measure matching latency for 10,000 cross orders
    let start_time = Instant::now();
    for i in 0..10000 {
        let order = Order {
            id: [(i + 10000) as u8; 32],
            trader: [0u8; 32],
            symbol: "ETH-USD".to_string(),
            side: OrderSide::Sell,
            price: 3000 - (i % 100),
            amount: 10,
            signature: Vec::new(),
            nonce: (i + 10000) as u64,
            expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };
        let tick = Instant::now();
        book.add_order(order);
        latencies.push(tick.elapsed());
    }
    let duration = start_time.elapsed();
    latencies.sort();

    let matches_sec = 10000.0 / duration.as_secs_f64();
    let p50 = latencies[5000];
    let p90 = latencies[9000];
    let p99 = latencies[9900];

    println!("  Throughput: {:.2} matching ops/sec", matches_sec);
    println!("  Latency distribution:");
    println!("    p50: {:?}", p50);
    println!("    p90: {:?}", p90);
    println!("    p99: {:?}", p99);
}

fn benchmark_signature_cache() {
    println!("\n[2/4] Benchmarking Signature Verification Cache...");
    let mut csprng = OsRng;
    let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
    let trader_bytes = signing_key.verifying_key().to_bytes();

    let mut order = Order {
        id: [1u8; 32],
        trader: trader_bytes,
        symbol: "ETH-USD".to_string(),
        side: OrderSide::Buy,
        price: 3000,
        amount: 5,
        signature: Vec::new(),
        nonce: 42,
        expiry: 0,
        settlement_preference: SettlementPreference::Standard,
        settlement_requester: SettlementRequester::Seller,
    };

    let msg = OrderValidator::serialize_order_message(&order);
    order.signature = signing_key.sign(&msg).to_vec();

    let mut validator = OrderValidator::new(1000);

    // Uncached verification run
    let start_uncached = Instant::now();
    assert!(validator.validate_order(&order));
    let uncached_dur = start_uncached.elapsed();

    // Cache hit verification run (100,000 iterations)
    let start_cached = Instant::now();
    for _ in 0..100000 {
        validator.validate_order(&order);
    }
    let cached_dur = start_cached.elapsed();

    let cached_ops_sec = 100000.0 / cached_dur.as_secs_f64();
    let speedup = uncached_dur.as_secs_f64() / (cached_dur.as_secs_f64() / 100000.0);

    println!("  Uncached verification: {:?}", uncached_dur);
    println!(
        "  Cached verification throughput: {:.2} checks/sec",
        cached_ops_sec
    );
    println!("  Cache validation speedup factor: {:.2}x", speedup);
}

fn benchmark_rdma_scheduler() {
    println!("\n[3/4] Benchmarking RDMA Round-Robin Scheduler Poll Latency...");
    let mut mr_manager = TraderMemoryRegionManager::new();
    let trader_a = [1u8; 32];
    let trader_b = [2u8; 32];

    mr_manager.register(trader_a, 4096, 0x1111);
    mr_manager.register(trader_b, 4096, 0x2222);

    let mut scheduler = PullScheduler::new(100);
    scheduler.add_trader(trader_a);
    scheduler.add_trader(trader_b);

    let start = Instant::now();
    let iterations = 200000;
    for _ in 0..iterations {
        let _ = scheduler.perform_pull(&mr_manager);
    }
    let duration = start.elapsed();
    let avg_poll = duration / iterations;
    let poll_rate = (iterations as f64) / duration.as_secs_f64();

    println!("  Polled {} iterations in {:?}", iterations, duration);
    println!("  Avg poll latency: {:?}", avg_poll);
    println!("  Scheduler poll rate: {:.2} polls/sec", poll_rate);
}

fn benchmark_aead_encryption() {
    println!("\n[4/4] Benchmarking ChaCha20-Poly1305 Security Throughput...");
    let key = [0x55u8; 32];
    let packet_size = 1024; // 1 KB packet size
    let payload = vec![0xAAu8; packet_size];
    let iterations = 20000; // 20 MB total load

    let start = Instant::now();
    for _ in 0..iterations {
        let encrypted = encrypt_packet(&key, &payload).unwrap();
        let decrypted = decrypt_packet(&key, &encrypted).unwrap();
        assert_eq!(decrypted.len(), packet_size);
    }
    let duration = start.elapsed();
    let total_mb = (iterations * packet_size) as f64 / (1024.0 * 1024.0);
    let throughput = total_mb / duration.as_secs_f64();

    println!("  Processed {:.2} MB in {:?}", total_mb, duration);
    println!("  Cipher execution throughput: {:.2} MB/s", throughput);
}
