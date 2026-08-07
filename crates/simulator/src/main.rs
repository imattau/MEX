use common::{FloodMessage, NodeId, Order, OrderSide, Region, SettlementPreference, SettlementRequester};
use protocol::{DeterministicFlood, FloodSchedule, Peer, RoutingTable, HeartbeatTracker};
use rand::Rng;
use simulator::types::{Event, ScheduledEvent, NodeInfo, Measurement, SimulationResultJson};
use simulator::latency::LatencyModel;
use std::collections::{BinaryHeap, HashMap};
use std::fs::File;
use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let use_local_profile = args.contains(&"--profile".to_string()) && args.contains(&"local".to_string());
    
    let test_scenario = if let Some(idx) = args.iter().position(|r| r == "--test") {
        args.get(idx + 1).map(|s| s.as_str()).unwrap_or("default")
    } else {
        "default"
    };

    println!("Initializing Project Chronos Protocol Simulator...");
    println!("  Scenario configuration: {}", test_scenario.to_uppercase());
    if use_local_profile {
        println!("  Profile active: LOCAL MULTI-ZONE MESH");
    } else {
        println!("  Profile active: GLOBAL MULTI-REGION MESH");
    }

    // 1. Setup Nodes based on scenario
    let mut nodes = Vec::new();
    let regions = match test_scenario {
        "p2p" => vec![
            (Region::UsEast1, 1),
            (Region::EuWest1, 1),
        ],
        _ => vec![
            (Region::UsEast1, 3),      // Nodes 0, 1, 2
            (Region::EuWest1, 2),      // Nodes 3, 4
            (Region::ApSoutheast1, 5), // Nodes 5, 6, 7, 8, 9
        ],
    };

    let mut current_id = 0;
    for (region, count) in regions {
        for _ in 0..count {
            nodes.push(NodeInfo {
                id: NodeId(current_id),
                region,
                online: true,
            });
            current_id += 1;
        }
    }

    let node_count = nodes.len();
    println!("Provisioned {} virtual nodes.", node_count);

    // 2. Setup Routing Tables for Deterministic Flooding
    let mut flood_nodes = HashMap::new();
    let latency_model = if use_local_profile {
        LatencyModel::local()
    } else {
        LatencyModel::new()
    };
    let schedule = FloodSchedule::default();

    for i in 0..node_count {
        let node_id = NodeId(i as u32);
        let node_region = nodes[i].region;

        let mut zone_peers = Vec::new();
        let mut upstream_peers = Vec::new();
        let mut downstream_peers = Vec::new();

        for j in 0..node_count {
            if i == j {
                continue;
            }
            let peer_id = NodeId(j as u32);
            let peer_region = nodes[j].region;
            let latency = latency_model.get_latency(node_region, peer_region);

            let peer = Peer {
                id: peer_id,
                latency_ms: latency,
                last_heartbeat: 0.0,
                health_score: 1.0,
            };

            if node_region == peer_region {
                zone_peers.push(peer.clone());
                downstream_peers.push(peer.clone());
                upstream_peers.push(peer.clone());
            } else {
                let is_this_bridge = (node_region == Region::UsEast1 && i == 0)
                    || (node_region == Region::EuWest1 && (i == 3 || test_scenario == "p2p"))
                    || (node_region == Region::ApSoutheast1 && i == 5);

                let is_peer_bridge = (peer_region == Region::UsEast1 && j == 0)
                    || (peer_region == Region::EuWest1 && (j == 3 || test_scenario == "p2p"))
                    || (peer_region == Region::ApSoutheast1 && j == 5);

                if is_this_bridge && is_peer_bridge {
                    downstream_peers.push(peer.clone());
                }
            }
        }

        let routing_table = RoutingTable {
            upstream_peers,
            downstream_peers,
            zone_peers,
        };

        let flood_state = DeterministicFlood::new(node_id, node_region, routing_table, schedule.clone());
        flood_nodes.insert(node_id, flood_state);
    }

    // 3. Event Queue Initialization
    let mut event_queue = BinaryHeap::new();
    let mut rng = rand::thread_rng();
    let mut injected_orders = HashMap::new();

    let order_count = match test_scenario {
        "cold_start" => 1,
        "p2p" => 10,
        _ => 1000,
    };

    for o in 0..order_count {
        let mut order_id = [0u8; 32];
        order_id[0..8].copy_from_slice(&(o as u64).to_be_bytes());
        let mut trader_id = [0u8; 32];
        rng.fill(&mut trader_id);
        
        let order = Order {
            id: order_id,
            trader: trader_id,
            symbol: "ETH-USD".to_string(),
            side: if rng.gen_bool(0.5) { OrderSide::Buy } else { OrderSide::Sell },
            price: rng.gen_range(3000..3200),
            amount: rng.gen_range(1..10),
            signature: Vec::new(),
            nonce: o as u64,
            expiry: 100000,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };

        let source_node = match test_scenario {
            "cold_start" | "churn" => NodeId(0),
            _ => NodeId(rng.gen_range(0..node_count as u32)),
        };
        let generation_time = rng.gen_range(0.0..1000.0);

        injected_orders.insert(order_id, (generation_time, source_node));

        event_queue.push(ScheduledEvent {
            time: generation_time,
            event: Event::OrderGenerated { order, source_node },
        });
    }

    if test_scenario == "churn" {
        event_queue.push(ScheduledEvent {
            time: 200.0,
            event: Event::NodeStatusChange {
                node_id: NodeId(2),
                online: false,
            },
        });
    } else if test_scenario == "default" {
        event_queue.push(ScheduledEvent {
            time: 2000.0,
            event: Event::NodeStatusChange {
                node_id: NodeId(2),
                online: false,
            },
        });
        event_queue.push(ScheduledEvent {
            time: 5000.0,
            event: Event::NodeStatusChange {
                node_id: NodeId(2),
                online: true,
            },
        });
    }

    // 4. Run Virtual Time Simulation Loop
    let mut current_virtual_time = 0.0;
    let mut measurements = Vec::new();
    let mut total_deliveries = 0;
    let mut heartbeat_tracker = HeartbeatTracker::new(100.0, 3);

    let bandwidth_kbps = match test_scenario {
        "bandwidth" => 5000.0,
        _ => 100000.0,
    };
    let message_size_kb = 500.0;

    println!("Simulation started...");
    while let Some(scheduled_event) = event_queue.pop() {
        current_virtual_time = scheduled_event.time;

        let dead_nodes = heartbeat_tracker.check_health(current_virtual_time);
        for dead_node in dead_nodes {
            if flood_nodes.contains_key(&dead_node) {
                for state in flood_nodes.values_mut() {
                    state.routing_table.downstream_peers.retain(|p| p.id != dead_node);
                }
            }
        }

        match scheduled_event.event {
            Event::OrderGenerated { order, source_node } => {
                let node_region = nodes[source_node.0 as usize].region;
                let flood_msg = FloodMessage {
                    order,
                    hop_count: 0,
                    path: vec![source_node],
                    timestamp: current_virtual_time,
                    source_region: node_region,
                };

                heartbeat_tracker.on_heartbeat(source_node, current_virtual_time);

                if let Some(flood_state) = flood_nodes.get_mut(&source_node) {
                    if let Ok(forwards) = flood_state.on_receive(flood_msg, current_virtual_time) {
                        for (to_peer, next_msg) in forwards {
                            let to_region = nodes[to_peer.0 as usize].region;
                            let base_lat = latency_model.get_latency(node_region, to_region);
                            let tx_delay = (message_size_kb / bandwidth_kbps) * 1000.0;
                            let jitter = rng.gen_range(-0.5..0.5);
                            let delay = base_lat + tx_delay + jitter;

                            event_queue.push(ScheduledEvent {
                                time: current_virtual_time + delay,
                                event: Event::PacketDeliver { to_node: to_peer, msg: next_msg },
                            });
                        }
                    }
                }
            }
            Event::PacketDeliver { to_node, msg } => {
                if !nodes[to_node.0 as usize].online {
                    continue;
                }

                let order_id = msg.order.id;
                let hop_count = msg.hop_count;
                let source_region = msg.source_region;
                let to_region = nodes[to_node.0 as usize].region;

                if let Some(&source) = msg.path.first() {
                    heartbeat_tracker.on_heartbeat(source, current_virtual_time);
                }

                if let Some(flood_state) = flood_nodes.get_mut(&to_node) {
                    let rx_time = current_virtual_time;
                    match flood_state.on_receive(msg, rx_time) {
                        Ok(forwards) => {
                            total_deliveries += 1;

                            if let Some(&(gen_time, _)) = injected_orders.get(&order_id) {
                                measurements.push(Measurement {
                                    order_id: format!("{:?}", order_id),
                                    latency_ms: rx_time - gen_time,
                                    hops: hop_count,
                                    source_region: format!("{:?}", source_region),
                                    dest_region: format!("{:?}", to_region),
                                });
                            }

                            for (to_peer, next_msg) in forwards {
                                let base_lat = latency_model.get_latency(to_region, nodes[to_peer.0 as usize].region);
                                let tx_delay = (message_size_kb / bandwidth_kbps) * 1000.0;
                                let jitter = rng.gen_range(-0.5..0.5);
                                let delay = base_lat + tx_delay + jitter;

                                event_queue.push(ScheduledEvent {
                                    time: current_virtual_time + delay,
                                    event: Event::PacketDeliver { to_node: to_peer, msg: next_msg },
                                });
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
            Event::NodeStatusChange { node_id, online } => {
                nodes[node_id.0 as usize].online = online;
                println!(
                    "[{:.1}ms] Node {} status changed to: {}",
                    current_virtual_time,
                    node_id.0,
                    if online { "ONLINE" } else { "OFFLINE" }
                );
            }
        }
    }

    println!("Simulation finished at virtual time {:.2}ms.", current_virtual_time);

    if measurements.is_empty() {
        println!("No successful deliveries recorded.");
        return;
    }

    let mut latencies: Vec<f64> = measurements.iter().map(|m| m.latency_ms).collect();
    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let p50 = latencies[latencies.len() / 2];
    let p95 = latencies[(latencies.len() as f64 * 0.95) as usize];
    let p999 = latencies[(latencies.len() as f64 * 0.999) as usize];
    let worst_case = latencies.last().copied().unwrap_or(0.0);

    let target_global_propagation_limit = 85.0;
    let verified = p999 < target_global_propagation_limit;

    println!("\n=== Chronos Simulator Execution Report ===");
    println!("Total Orders Injected: {}", injected_orders.len());
    println!("Total Deliveries Completed: {}", total_deliveries);
    println!("Propagation Latency Metrics:");
    println!("  p50:   {:.2}ms", p50);
    println!("  p95:   {:.2}ms", p95);
    println!("  p99.9: {:.2}ms (Target: <{}ms)", p999, target_global_propagation_limit);
    println!("  Max:   {:.2}ms", worst_case);
    println!("Verification Result: {}", if verified { "SUCCESS (Go to Phase 2)" } else { "FAILED (Pivot to Gossip)" });

    let sim_result = SimulationResultJson {
        scenario: test_scenario.to_string(),
        total_orders_injected: injected_orders.len(),
        total_deliveries,
        p50_latency_ms: p50,
        p95_latency_ms: p95,
        p99_9_latency_ms: p999,
        t_max_ms: worst_case,
        verified,
    };

    if let Ok(serialized) = serde_json::to_string_pretty(&sim_result) {
        let output_path = args.iter()
            .position(|r| r == "--output")
            .and_then(|i| args.get(i + 1))
            .map(|s| s.as_str())
            .unwrap_or("latency_matrix.json");

        if let Ok(mut file) = File::create(output_path) {
            let _ = file.write_all(serialized.as_bytes());
            println!("Simulation report saved to {}", output_path);
        }
    }
}
