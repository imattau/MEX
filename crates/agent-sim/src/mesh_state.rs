use crate::agent_state::AgentTracker;
use crate::chain_setup::{self, OnChainAgent, OnChainConfig};
use crate::simple_flood::SimpleFlood;
use crate::types::{
    AgentConfig, BidAskLevel, BookDepth, NodeSnapshot, PricePoint, SimulationStateSnapshot,
    TradeRecord, order_id_to_hex, trader_id_to_hex,
};
use common::{FloodMessage, NodeId, Order, OrderSide, Region, SettlementPreference, SettlementRequester};
use engine::{Match, OrderBook};
use protocol::{FloodSchedule, Peer, RoutingTable};
use rand::Rng;
use std::collections::HashMap;

pub struct MeshNode {
    pub id: NodeId,
    pub region: Region,
    pub online: bool,
    pub flood: SimpleFlood,
    pub routing: RoutingTable,
    pub schedule: FloodSchedule,
    pub orderbook: OrderBook,
    pub pending_messages: Vec<(f64, FloodMessage)>,
    pub matches_this_step: usize,
}

pub struct LatencyModel {
    latencies: HashMap<(Region, Region), f64>,
}

impl LatencyModel {
    pub fn new() -> Self {
        let mut latencies = HashMap::new();
        latencies.insert((Region::UsEast1, Region::UsEast1), 5.0);
        latencies.insert((Region::EuWest1, Region::EuWest1), 5.0);
        latencies.insert((Region::ApSoutheast1, Region::ApSoutheast1), 5.0);
        latencies.insert((Region::UsEast1, Region::EuWest1), 75.0);
        latencies.insert((Region::EuWest1, Region::UsEast1), 75.0);
        latencies.insert((Region::UsEast1, Region::ApSoutheast1), 150.0);
        latencies.insert((Region::ApSoutheast1, Region::UsEast1), 150.0);
        latencies.insert((Region::EuWest1, Region::ApSoutheast1), 220.0);
        latencies.insert((Region::ApSoutheast1, Region::EuWest1), 220.0);
        Self { latencies }
    }

    pub fn local() -> Self {
        let mut latencies = HashMap::new();
        latencies.insert((Region::UsEast1, Region::UsEast1), 2.0);
        latencies.insert((Region::EuWest1, Region::EuWest1), 2.0);
        latencies.insert((Region::ApSoutheast1, Region::ApSoutheast1), 2.0);
        latencies.insert((Region::UsEast1, Region::EuWest1), 25.0);
        latencies.insert((Region::EuWest1, Region::UsEast1), 25.0);
        latencies.insert((Region::UsEast1, Region::ApSoutheast1), 15.0);
        latencies.insert((Region::ApSoutheast1, Region::UsEast1), 15.0);
        latencies.insert((Region::EuWest1, Region::ApSoutheast1), 35.0);
        latencies.insert((Region::ApSoutheast1, Region::EuWest1), 35.0);
        Self { latencies }
    }

    pub fn get_latency(&self, from: Region, to: Region) -> f64 {
        *self.latencies.get(&(from, to)).unwrap_or(&100.0)
    }
}

pub struct MultiNodeSimulation {
    pub nodes: Vec<MeshNode>,
    pub latency_model: LatencyModel,
    pub agents: AgentTracker,
    pub virtual_time: f64,
    pub step_number: u64,
    pub symbol: String,
    pub recent_trades: Vec<TradeRecord>,
    pub price_history: Vec<PricePoint>,
    pub total_volume: u64,
    pub step_matches: Vec<Match>,
    // Real on-chain wallets/escrows, keyed by agent id -- populated by
    // bootstrap_onchain, which must run (and succeed) before any match can
    // be gated on a real commitTrade. Empty until then.
    pub onchain_agents: HashMap<String, OnChainAgent>,
}

impl MultiNodeSimulation {
    pub fn new(symbol: String, node_config: &[(Region, u32)], use_local_profile: bool) -> Self {
        let latency_model = if use_local_profile {
            LatencyModel::local()
        } else {
            LatencyModel::new()
        };

        let mut nodes = Vec::new();
        let mut node_regions = Vec::new();

        for &(region, count) in node_config {
            for _ in 0..count {
                node_regions.push(region);
            }
        }

        let total_nodes = node_regions.len();
        let schedule = FloodSchedule::default();

        for i in 0..total_nodes {
            let node_id = NodeId(i as u32);
            let node_region = node_regions[i];

            let mut zone_peers = Vec::new();
            let mut downstream_peers = Vec::new();
            let mut upstream_peers = Vec::new();

            for j in 0..total_nodes {
                if i == j {
                    continue;
                }
                let peer_id = NodeId(j as u32);
                let peer_region = node_regions[j];
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
                        || (node_region == Region::EuWest1 && i == node_regions.iter().position(|&r| r == Region::EuWest1).unwrap_or(0))
                        || (node_region == Region::ApSoutheast1 && i == node_regions.iter().position(|&r| r == Region::ApSoutheast1).unwrap_or(0));

                    let is_peer_bridge = (peer_region == Region::UsEast1 && j == 0)
                        || (peer_region == Region::EuWest1 && j == node_regions.iter().position(|&r| r == Region::EuWest1).unwrap_or(0))
                        || (peer_region == Region::ApSoutheast1 && j == node_regions.iter().position(|&r| r == Region::ApSoutheast1).unwrap_or(0));

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

            nodes.push(MeshNode {
                id: node_id,
                region: node_region,
                online: true,
                flood: SimpleFlood::new(),
                routing: routing_table,
                schedule: schedule.clone(),
                orderbook: OrderBook::new(symbol.clone()),
                pending_messages: Vec::new(),
                matches_this_step: 0,
            });
        }

        Self {
            nodes,
            latency_model,
            agents: AgentTracker::new(),
            virtual_time: 0.0,
            step_number: 0,
            symbol,
            recent_trades: Vec::new(),
            price_history: Vec::new(),
            total_volume: 0,
            step_matches: Vec::new(),
            onchain_agents: HashMap::new(),
        }
    }

    pub fn register_agent(&mut self, config: AgentConfig) {
        self.agents.register(config);
    }

    // Registers a real settlement node and a real, funded on-chain
    // wallet/escrow for every agent already registered via register_agent,
    // then points every mesh node's OrderBook at that settlement node so
    // engine::Match.assigned_node is populated correctly (see
    // OrderBook::set_active_nodes). Must be called after all
    // register_agent calls and before the simulation is driven -- matches
    // produced before this succeeds have no on-chain wallet to gate a
    // commit against and cannot settle for real.
    pub async fn bootstrap_onchain(&mut self, config: &OnChainConfig) -> Result<(), String> {
        let agent_pubkeys: HashMap<String, [u8; 32]> = self
            .agents
            .agent_ids()
            .into_iter()
            .filter_map(|id| {
                let bytes = self.agents.get_trader_bytes(&id)?;
                Some((id, bytes))
            })
            .collect();

        let setup = chain_setup::bootstrap(config, &agent_pubkeys).await?;

        for node in &mut self.nodes {
            node.orderbook.set_active_nodes(vec![setup.assigned_node]);
        }

        self.onchain_agents = setup.agents;
        Ok(())
    }

    pub fn queue_order(&mut self, order: Order, source_node_id: u32) {
        let idx = source_node_id as usize;
        if idx >= self.nodes.len() || !self.nodes[idx].online {
            return;
        }

        let node = &self.nodes[idx];
        let flood_msg = FloodMessage {
            order,
            hop_count: 0,
            path: vec![node.id],
            timestamp: self.virtual_time,
            source_region: node.region,
        };

        self.nodes[idx].pending_messages.push((self.virtual_time, flood_msg));
    }

    pub async fn propagate_and_match(&mut self, rng: &mut impl Rng) {
        let new_time = self.virtual_time;
        let node_count = self.nodes.len();

        let mut pending_per_node: Vec<Vec<(f64, FloodMessage)>> =
            (0..node_count).map(|_| Vec::new()).collect();
        std::mem::swap(&mut pending_per_node[0], &mut self.nodes[0].pending_messages);
        for i in 1..node_count {
            let (left, right) = self.nodes.split_at_mut(i);
            std::mem::swap(&mut pending_per_node[i], &mut right[0].pending_messages);
            let _ = left;
        }

        let mut new_outbound: Vec<(usize, f64, FloodMessage)> = Vec::new();
        let mut all_matches: Vec<(Match, u32)> = Vec::new();
        let node_regions: Vec<Region> = self.nodes.iter().map(|n| n.region).collect();

        for i in 0..node_count {
            let node = &mut self.nodes[i];

            if !node.online {
                pending_per_node[i].clear();
                continue;
            }

            let region = node.region;

            pending_per_node[i].retain(|(arrival_time, _)| *arrival_time <= new_time);

            let arrived_msgs: Vec<FloodMessage> = pending_per_node[i]
                .drain(..)
                .map(|(_, msg)| msg)
                .collect();

            for msg in arrived_msgs {
                let node_id = node.id;
                let schedule = node.schedule.clone();
                match node.flood.on_receive(msg, node_id, &node.routing.clone(), &schedule) {
                    Ok(forwards) => {
                        if let Some(order) = node.flood.order_book_orders.last().cloned() {
                            let matches = node.orderbook.add_order(order);
                            node.matches_this_step += matches.len();
                            for m in matches {
                                all_matches.push((m, node.id.0));
                            }
                        }

                        for (target_id, fwd_msg) in forwards {
                            let target_idx = target_id.0 as usize;
                            if target_idx < node_count {
                                let latency = self.latency_model.get_latency(
                                    region,
                                    node_regions[target_idx],
                                );
                                let jitter = rng.gen_range(-0.5..0.5);
                                let delay = latency + 0.5 + jitter;
                                new_outbound.push((target_idx, new_time + delay, fwd_msg));
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
        }

        for (target_idx, arrival_time, fwd_msg) in new_outbound {
            self.nodes[target_idx]
                .pending_messages
                .push((arrival_time, fwd_msg));
        }

        for node in &mut self.nodes {
            node.flood.order_book_orders.clear();
        }

        for (m, node_id) in all_matches {
            // A match's fee_payer resolves to a real on-chain wallet only
            // when it's one of this simulation's configured agents. Noise
            // trades (see inject_noise) use a freshly-randomized synthetic
            // trader as a counterparty every time -- there is no real key
            // for that identity and never will be, so there's nothing to
            // commit or gate: apply them exactly as before. A real
            // agent-vs-agent (or agent-vs-noise, with the real agent as
            // fee_payer) match, by contrast, is gated on commitTrade
            // actually succeeding on-chain -- if it fails, the trade does
            // not update any agent's balance/position/PnL and is not
            // reported as having happened.
            let payer_agent_id = self
                .onchain_agents
                .iter()
                .find(|(_, agent)| agent.offchain_pubkey == m.fee_payer)
                .map(|(id, _)| id.clone());

            let Some(agent_id) = payer_agent_id else {
                self.process_agent_match(&m, node_id);
                self.step_matches.push(m);
                continue;
            };

            let Some(onchain_agent) = self.onchain_agents.get_mut(&agent_id) else {
                continue;
            };

            match onchain_agent.client.commit_trade(&m).await {
                Ok(trade_hash) => {
                    tracing::info!(
                        agent_id,
                        trade_hash = %hex::encode(trade_hash),
                        "match committed on-chain"
                    );
                    self.process_agent_match(&m, node_id);
                    self.step_matches.push(m);
                }
                Err(error) => {
                    tracing::warn!(
                        agent_id,
                        error,
                        "match rejected: on-chain commitTrade failed, not applying to simulation state"
                    );
                }
            }
        }
    }

    fn process_agent_match(&mut self, m: &Match, node_id: u32) {
        self.total_volume += m.amount;

        let maker_hex = trader_id_to_hex(&m.maker_trader);
        let taker_hex = trader_id_to_hex(&m.taker_trader);

        for agent_id in self.agents.agent_ids() {
            let Some(agent_bytes) = self.agents.get_trader_bytes(&agent_id) else {
                continue;
            };
            let agent_hex = trader_id_to_hex(&agent_bytes);

            if agent_hex == maker_hex {
                if m.seller == agent_bytes {
                    self.agents.record_trade_sell(&agent_id, m.amount, m.price, &m.maker_order_id);
                } else {
                    self.agents.record_trade_buy(&agent_id, m.amount, m.price, &m.maker_order_id);
                }
            }

            if agent_hex == taker_hex {
                if m.seller == agent_bytes {
                    self.agents.record_trade_sell(&agent_id, m.amount, m.price, &m.taker_order_id);
                } else {
                    self.agents.record_trade_buy(&agent_id, m.amount, m.price, &m.taker_order_id);
                }
            }
        }

        self.recent_trades.push(TradeRecord {
            id: order_id_to_hex(&m.maker_order_id),
            symbol: m.symbol.clone(),
            price: m.price,
            amount: m.amount,
            seller: trader_id_to_hex(&m.seller),
            buyer: trader_id_to_hex(&m.fee_payer),
            timestamp: self.virtual_time,
            node_id,
        });
    }

    pub fn mid_price(&self) -> Option<f64> {
        let mut best_bid: Option<u64> = None;
        let mut best_ask: Option<u64> = None;

        for node in &self.nodes {
            if !node.online {
                continue;
            }
            if let Some(bid) = node.orderbook.bids.keys().rev().next().copied() {
                best_bid = Some(best_bid.map_or(bid, |b| b.max(bid)));
            }
            if let Some(ask) = node.orderbook.asks.keys().next().copied() {
                best_ask = Some(best_ask.map_or(ask, |a| a.min(ask)));
            }
        }

        match (best_bid, best_ask) {
            (Some(bid), Some(ask)) => Some((bid as f64 + ask as f64) / 2.0),
            (Some(bid), None) => Some(bid as f64),
            (None, Some(ask)) => Some(ask as f64),
            (None, None) => None,
        }
    }

    pub fn snapshot(&mut self) -> SimulationStateSnapshot {
        let mp = self.mid_price();
        let last_trade_price = self.recent_trades.last().map(|t| t.price);

        let pp = PricePoint {
            timestamp: self.virtual_time,
            mid_price: mp.unwrap_or(0.0),
            last_trade_price,
        };
        self.price_history.push(pp);

        let nodes: Vec<NodeSnapshot> = self
            .nodes
            .iter()
            .map(|n| {
                let oc = n.orderbook.bids.values().map(|v| v.len()).sum::<usize>()
                    + n.orderbook.asks.values().map(|v| v.len()).sum::<usize>();
                NodeSnapshot {
                    id: n.id.0,
                    region: format!("{:?}", n.region),
                    online: n.online,
                    order_count: oc,
                    matches_this_step: n.matches_this_step,
                }
            })
            .collect();

        let mut aggregated_bids: std::collections::BTreeMap<u64, u64> = std::collections::BTreeMap::new();
        let mut aggregated_asks: std::collections::BTreeMap<u64, u64> = std::collections::BTreeMap::new();

        for node in &self.nodes {
            if !node.online {
                continue;
            }
            for (&price, orders) in &node.orderbook.bids {
                let total: u64 = orders.iter().map(|o| o.amount).sum();
                *aggregated_bids.entry(price).or_insert(0) += total;
            }
            for (&price, orders) in &node.orderbook.asks {
                let total: u64 = orders.iter().map(|o| o.amount).sum();
                *aggregated_asks.entry(price).or_insert(0) += total;
            }
        }

        let bids: Vec<BidAskLevel> = aggregated_bids
            .iter()
            .rev()
            .take(50)
            .map(|(price, amt)| BidAskLevel {
                price: *price,
                total_amount: *amt,
                order_count: 0,
            })
            .collect();

        let asks: Vec<BidAskLevel> = aggregated_asks
            .iter()
            .take(50)
            .map(|(price, amt)| BidAskLevel {
                price: *price,
                total_amount: *amt,
                order_count: 0,
            })
            .collect();

        let book = BookDepth {
            symbol: self.symbol.clone(),
            node_id: 0,
            region: "aggregated".to_string(),
            bids,
            asks,
        };

        let recent_clone = self.recent_trades.iter().rev().take(20).rev().cloned().collect();

        SimulationStateSnapshot {
            virtual_time: self.virtual_time,
            step_number: self.step_number,
            symbol: self.symbol.clone(),
            nodes,
            book,
            agents: self.agents.all_snapshots(),
            recent_trades: recent_clone,
            price_history: self.price_history.clone(),
            total_volume: self.total_volume,
        }
    }

    pub fn inject_noise(&mut self, rng: &mut impl Rng, noise_amplitude: f64) {
        let mid = self.mid_price().unwrap_or(3000.0);

        for node in &mut self.nodes {
            if !node.online {
                continue;
            }

            let noise_count = rng.gen_range(1..4);
            for _ in 0..noise_count {
                let noise_price =
                    (mid * (1.0 + rng.gen_range(-noise_amplitude..noise_amplitude))) as u64;
                let noise_price = noise_price.max(1);
                let amt = rng.gen_range(1..20);

                let mut noise_trader = [0u8; 32];
                rng.fill(&mut noise_trader);
                let mut order_id_bytes = [0u8; 32];
                rng.fill(&mut order_id_bytes);

                let order = Order {
                    id: order_id_bytes,
                    trader: noise_trader,
                    symbol: self.symbol.clone(),
                    side: if rng.gen_bool(0.5) { OrderSide::Buy } else { OrderSide::Sell },
                    price: noise_price,
                    amount: amt,
                    signature: Vec::new(),
                    nonce: self.step_number * 1000 + noise_count as u64,
                    expiry: 1000000,
                    settlement_preference: SettlementPreference::Standard,
                    settlement_requester: SettlementRequester::Seller,
                };

                let msg = FloodMessage {
                    order,
                    hop_count: 0,
                    path: vec![node.id],
                    timestamp: self.virtual_time,
                    source_region: node.region,
                };

                node.pending_messages.push((self.virtual_time, msg));
            }
        }
    }

    pub fn step_matches_to_trades(&self) -> Vec<TradeRecord> {
        self.step_matches
            .iter()
            .map(|m| TradeRecord {
                id: order_id_to_hex(&m.maker_order_id),
                symbol: m.symbol.clone(),
                price: m.price,
                amount: m.amount,
                seller: trader_id_to_hex(&m.seller),
                buyer: trader_id_to_hex(&m.fee_payer),
                timestamp: self.virtual_time,
                node_id: 0,
            })
            .collect()
    }
}
