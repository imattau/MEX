use crate::flood::DeterministicFlood;
use crate::heartbeat::HeartbeatTracker;
use crate::transport::{UdpTransport, WireMessage};
use crate::types::{FloodSchedule, Peer, RoutingTable};
use common::{FloodMessage, NodeId, Region};
use security::{encrypt_packet, decrypt_packet};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

const FIBER_LATENCY_MS_PER_100KM: f64 = 1.5;
const GEO_VERIFY_THRESHOLD: f64 = 0.8;

impl MeshNode {
    pub async fn verify_peer_location(
        transport: &UdpTransport,
        peer_id: NodeId,
        claimed_latency_ms: f64,
    ) -> (f64, bool) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        let sig = transport.sign_heartbeat(peer_id, now);
        let pk = transport.public_key();
        let _ = transport
            .send(
                peer_id,
                WireMessage::SignedHeartbeat {
                    node_id: peer_id,
                    timestamp: now,
                    node_public_key: pk,
                    signature: sig,
                },
            )
            .await;

        let start = std::time::Instant::now();
        let result = {
            let t = transport;
            tokio::time::timeout(
                tokio::time::Duration::from_secs(2),
                async {
                    loop {
                        if let Ok((_from, WireMessage::SignedHeartbeat { .. })) = t.recv().await {
                            break;
                        }
                    }
                },
            )
            .await
        };
        let rtt = start.elapsed().as_secs_f64() * 1000.0;

        let plausible = rtt >= claimed_latency_ms * GEO_VERIFY_THRESHOLD;
        (rtt, plausible)
    }
}

const CENSORSHIP_FLAG_THRESHOLD: u32 = 3;
const CENSORSHIP_WINDOW_SECS: u64 = 60;
const ECHO_INTERVAL_SECS: u64 = 5;
const RECENT_ORDER_CACHE_SIZE: usize = 1000;

struct CensorshipMonitor {
    recent_orders: lru::LruCache<[u8; 32], ()>,
    peer_flags: HashMap<NodeId, VecDeque<u64>>,
    flag_threshold: u32,
    window_secs: u64,
}

impl CensorshipMonitor {
    fn new() -> Self {
        use std::num::NonZeroUsize;
        Self {
            recent_orders: lru::LruCache::new(
                NonZeroUsize::new(RECENT_ORDER_CACHE_SIZE).unwrap(),
            ),
            peer_flags: HashMap::new(),
            flag_threshold: CENSORSHIP_FLAG_THRESHOLD,
            window_secs: CENSORSHIP_WINDOW_SECS,
        }
    }

    fn track_order(&mut self, order_id: [u8; 32]) {
        self.recent_orders.put(order_id, ());
    }

    fn flag_peer(&mut self, peer_id: NodeId, now_secs: u64) -> bool {
        let flags = self.peer_flags.entry(peer_id).or_default();
        flags.push_back(now_secs);
        while flags.front().map_or(false, |t| now_secs - t > self.window_secs) {
            flags.pop_front();
        }
        flags.len() as u32 >= self.flag_threshold
    }

    fn pick_random_order(&self) -> Option<[u8; 32]> {
        let keys: Vec<&[u8; 32]> = self.recent_orders.iter().map(|(k, _)| k).collect();
        if keys.is_empty() {
            return None;
        }
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let idx = (seed as usize) % keys.len();
        Some(*keys[idx])
    }

    fn reported_missing(&mut self, peer_id: NodeId) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.flag_peer(peer_id, now)
    }
}

pub struct MeshNode {
    pub node_id: NodeId,
    pub region: Region,
    pub flood: DeterministicFlood,
    heartbeat: HeartbeatTracker,
    heartbeat_interval_ms: f64,
    max_missed_heartbeats: u32,
    transport: Arc<Mutex<UdpTransport>>,
    peer_addrs: HashMap<NodeId, SocketAddr>,
    mesh_key: [u8; 32],
    censorship: CensorshipMonitor,
    reputation: reputation::ReputationEngine,
    rx: mpsc::Receiver<(NodeId, FloodMessage)>,
    tx: mpsc::Sender<(NodeId, FloodMessage)>,
    echo_rx: mpsc::Receiver<(NodeId, Vec<[u8; 32]>)>,
    echo_tx: mpsc::Sender<(NodeId, Vec<[u8; 32]>)>,
}

pub struct MeshConfig {
    pub node_id: NodeId,
    pub region: Region,
    pub listen_addr: SocketAddr,
    pub peers: Vec<(NodeId, SocketAddr, [u8; 32])>,
    pub node_key: Option<([u8; 32], [u8; 32])>,
    pub mesh_encryption_key: Option<[u8; 32]>,
    pub heartbeat_interval_ms: f64,
    pub max_missed_heartbeats: u32,
    pub schedule: Option<FloodSchedule>,
}

impl MeshNode {
    pub async fn new(config: MeshConfig) -> Result<Self, std::io::Error> {
        let node_key = config.node_key.unwrap_or(([0u8; 32], [0u8; 32]));
        let mut transport = UdpTransport::bind(config.listen_addr, Some(node_key)).await?;

        let mesh_key = config.mesh_encryption_key.unwrap_or([0u8; 32]);

        let mut routing = RoutingTable {
            upstream_peers: Vec::new(),
            downstream_peers: Vec::new(),
            zone_peers: Vec::new(),
        };

        let mut peer_addrs = HashMap::new();

        for (id, addr, pubkey) in &config.peers {
            transport.register_peer(*id, *addr, *pubkey);
            peer_addrs.insert(*id, *addr);

            let peer = Peer {
                id: *id,
                latency_ms: 1.0,
                last_heartbeat: 0.0,
                health_score: 1.0,
            };

            routing.zone_peers.push(peer.clone());

            if id.0 < config.node_id.0 {
                routing.upstream_peers.push(peer.clone());
            } else {
                routing.downstream_peers.push(peer.clone());
            }
        }

        tracing::info!(
            node = ?config.node_id,
            upstream = routing.upstream_peers.len(),
            downstream = routing.downstream_peers.len(),
            "Mesh node initialized with censorship detection"
        );

        let flood = DeterministicFlood::new(
            config.node_id,
            config.region,
            routing,
            config.schedule.unwrap_or_default(),
        );

        let heartbeat = HeartbeatTracker::new(
            config.heartbeat_interval_ms,
            config.max_missed_heartbeats,
        );

        let (tx, rx) = mpsc::channel(1024);
        let (echo_tx, echo_rx) = mpsc::channel(256);

        Ok(Self {
            node_id: config.node_id,
            region: config.region,
            flood,
            heartbeat,
            heartbeat_interval_ms: config.heartbeat_interval_ms,
            max_missed_heartbeats: config.max_missed_heartbeats,
            transport: Arc::new(Mutex::new(transport)),
            peer_addrs,
            mesh_key,
            censorship: CensorshipMonitor::new(),
            reputation: reputation::ReputationEngine::new(),
            rx,
            tx,
            echo_rx,
            echo_tx,
        })
    }

    pub fn sender(&self) -> mpsc::Sender<(NodeId, FloodMessage)> {
        self.tx.clone()
    }

    pub async fn run(mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let transport = self.transport.clone();
        let tx = self.tx.clone();
        let echo_tx = self.echo_tx.clone();
        let mesh_key = self.mesh_key;

        let recv_transport = transport.clone();
        tokio::spawn(async move {
            loop {
                let result = {
                    let t = recv_transport.lock().await;
                    t.recv().await
                };
                match result {
                    Ok((from, msg)) => match msg {
                        WireMessage::Flood(fm) => {
                            let _ = tx.send((from, fm)).await;
                        }
                        WireMessage::EncryptedFlood(ref encrypted) => {
                            if mesh_key == [0u8; 32] { continue; }
                            match decrypt_packet(&mesh_key, encrypted) {
                                Ok(decrypted) => {
                                    if let Ok(fm) = bincode::deserialize::<FloodMessage>(&decrypted) {
                                        let _ = tx.send((from, fm)).await;
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "Flood decryption failed");
                                }
                            }
                        }
                        WireMessage::EchoRequest { order_ids } => {
                            let _ = echo_tx.send((from, order_ids)).await;
                        }
                        WireMessage::EchoResponse { present, .. } => {
                            if present.is_empty() {
                                tracing::warn!(?from, "Peer missing expected order");
                                let _ = echo_tx.send((from, vec![])).await;
                            }
                        }
                        WireMessage::SignedHeartbeat { node_id, timestamp, .. } => {
                            tracing::trace!(?node_id, %timestamp, "Signed heartbeat");
                        }
                        WireMessage::Heartbeat { node_id, .. } => {
                            tracing::trace!(?node_id, "Unsigned heartbeat");
                        }
                        WireMessage::Ack { .. } => {}
                    },
                    Err(e) => {
                        tracing::error!(error = %e, "Recv failed");
                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    }
                }
            }
        });

        let mut heartbeat_tick = tokio::time::interval(
            tokio::time::Duration::from_millis(100),
        );
        let mut echo_tick = tokio::time::interval(
            tokio::time::Duration::from_secs(ECHO_INTERVAL_SECS),
        );

        loop {
            tokio::select! {
                Some((from_node, flood_msg)) = self.rx.recv() => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs_f64() * 1000.0;
                    match self.flood.on_receive(flood_msg, now) {
                        Ok(forwards) => {
                            reputation::integration::on_flood_relayed(&mut self.reputation, from_node);
                            let t = self.transport.lock().await;
                            for (target, fwd_msg) in forwards {
                                self.censorship.track_order(fwd_msg.order.id);
                                if self.mesh_key != [0u8; 32] {
                                    let serialized = bincode::serialize(&fwd_msg).unwrap_or_default();
                                    if let Ok(encrypted) = encrypt_packet(&self.mesh_key, &serialized) {
                                        let _ = t.send(target, WireMessage::EncryptedFlood(encrypted)).await;
                                        continue;
                                    }
                                }
                                let _ = t.send(target, WireMessage::Flood(fwd_msg)).await;
                            }
                        }
                        Err(e) => {
                            reputation::integration::on_flood_dropped(&mut self.reputation, from_node);
                            tracing::debug!(?e, "Flood skip");
                        }
                    }
                }

                Some((echo_from, order_ids)) = self.echo_rx.recv() => {
                    let present: Vec<[u8; 32]> = order_ids.iter()
                        .filter(|id| self.flood.received_cache.contains(&**id))
                        .copied()
                        .collect();
                    let missing: Vec<[u8; 32]> = order_ids.iter()
                        .filter(|id| !self.flood.received_cache.contains(&**id))
                        .copied()
                        .collect();
                    let missing_count = missing.len();
                    let t = self.transport.lock().await;
                    let _ = t.send(echo_from, WireMessage::EchoResponse { present, missing }).await;
                    if missing_count > 0 {
                        tracing::warn!(?echo_from, %missing_count, "Echo: peer doesn't know about orders we've seen");
                        if self.censorship.reported_missing(echo_from) {
                            reputation::integration::on_censorship_flag(&mut self.reputation, echo_from);
                        }
                    }
                }

                _ = echo_tick.tick() => {
                    if let Some(order_id) = self.censorship.pick_random_order() {
                        let t = self.transport.lock().await;
                        for peer_id in self.flood.routing_table.downstream_peers.iter().map(|p| p.id) {
                            let _ = t.send(peer_id, WireMessage::EchoRequest {
                                order_ids: vec![order_id],
                            }).await;
                        }
                    }
                }

                _ = heartbeat_tick.tick() => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs_f64();

                    let t = self.transport.lock().await;
                    for (peer_id, _) in &self.peer_addrs {
                        let sig = t.sign_heartbeat(*peer_id, now);
                        let pk = t.public_key();
                        let _ = t.send(*peer_id, WireMessage::SignedHeartbeat {
                            node_id: self.node_id, timestamp: now,
                            node_public_key: pk, signature: sig,
                        }).await;
                    }

                    let dead = self.heartbeat.check_health(now);
                    for node in dead {
                        tracing::warn!(?node, "Peer marked dead");
                        let downtime_secs = std::time::Duration::from_millis(
                            (self.max_missed_heartbeats as f64 * self.heartbeat_interval_ms) as u64,
                        ).as_secs_f64();
                        reputation::integration::on_node_leave(&mut self.reputation, node, downtime_secs);
                        self.flood.routing_table.downstream_peers.retain(|p| p.id != node);
                        self.flood.routing_table.upstream_peers.retain(|p| p.id != node);
                    }
                    for peer_id in self.peer_addrs.keys() {
                        reputation::integration::on_heartbeat_received(&mut self.reputation, *peer_id);
                    }
                }
            }
        }
    }
}
