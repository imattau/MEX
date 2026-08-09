use crate::flood::DeterministicFlood;
use crate::heartbeat::HeartbeatTracker;
use crate::transport::{UdpTransport, WireMessage};
use crate::types::{FloodError, FloodSchedule, Peer, RoutingTable};
use common::{FloodMessage, NodeId, Region};
use security::{decrypt_packet, encrypt_packet};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

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
            tokio::time::timeout(tokio::time::Duration::from_secs(2), async {
                loop {
                    if let Ok((from, WireMessage::SignedHeartbeat { .. })) = t.recv().await {
                        if from == peer_id {
                            break;
                        }
                    }
                }
            })
            .await
        };
        let rtt = start.elapsed().as_secs_f64() * 1000.0;

        // No response from the claimed peer within the timeout window --
        // there's nothing to verify, so this must not be reported as plausible.
        if result.is_err() {
            return (rtt, false);
        }

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
            recent_orders: lru::LruCache::new(NonZeroUsize::new(RECENT_ORDER_CACHE_SIZE).unwrap()),
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
        while flags
            .front()
            .map_or(false, |t| now_secs - t > self.window_secs)
        {
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
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
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

// Correlates a Flood's local arrival with the HopWitness the immediately
// preceding relay sends alongside it, to compute that specific hop's
// observed one-way transit time -- see WireMessage::HopWitness's docs for
// why the origin-carried FloodMessage.timestamp alone can't attribute a
// delay to a specific relay in a multi-hop path.
//
// Stage 2: also retains a verdict history per order (unlike the pending
// maps below, which clear once matched), so a node with genuine
// topological redundancy -- the same order reaching it via more than one
// independent relay -- can check whether OTHER paths for that exact
// order looked normal while one specific hop's didn't. That corroboration
// is what turns "this one hop was slow" into "this one hop was slow
// while everyone else's copy of the SAME order was fine," which is much
// stronger evidence a specific relay is at fault rather than general
// network conditions.
//
// Known simplification, acceptable for this experiment and not for a
// production version: neither the pending maps nor the verdict history
// are evicted on a TTL, so both leak unboundedly over a long-running
// process (the verdict history is at least LRU-bounded by order count,
// unlike the pending maps). Fine for a short, controlled live test; a
// real version needs a proper sweep.
struct HopLatencyMonitor {
    // Keyed by (order_id, hop_node), not just order_id -- the original
    // single-path version of this keyed by order_id alone, which meant a
    // second witness/arrival for the same order from a DIFFERENT hop
    // would silently clobber the first before it could be matched. Since
    // Stage 2's whole point is multiple independent hops reporting on the
    // same order, that bug had to be fixed here first.
    pending_floods: HashMap<([u8; 32], NodeId), f64>,
    pending_witnesses: HashMap<([u8; 32], NodeId), f64>,
    verdicts: lru::LruCache<[u8; 32], Vec<(NodeId, f64, bool)>>,
}

impl HopLatencyMonitor {
    fn new() -> Self {
        Self {
            pending_floods: HashMap::new(),
            pending_witnesses: HashMap::new(),
            verdicts: lru::LruCache::new(std::num::NonZeroUsize::new(10_000).unwrap()),
        }
    }

    fn on_flood_received(
        &mut self,
        order_id: [u8; 32],
        from: NodeId,
        recv_time: f64,
    ) -> Option<(NodeId, f64)> {
        self.pending_floods.insert((order_id, from), recv_time);
        self.try_match(order_id, from)
    }

    fn on_witness_received(
        &mut self,
        order_id: [u8; 32],
        hop_node: NodeId,
        forwarded_at: f64,
    ) -> Option<(NodeId, f64)> {
        self.pending_witnesses
            .insert((order_id, hop_node), forwarded_at);
        self.try_match(order_id, hop_node)
    }

    // Once both halves for (order_id, hop_node) are present, returns
    // (hop_node, observed_one_way_ms) and clears them; None otherwise.
    fn try_match(&mut self, order_id: [u8; 32], hop_node: NodeId) -> Option<(NodeId, f64)> {
        let recv_time = *self.pending_floods.get(&(order_id, hop_node))?;
        let forwarded_at = *self.pending_witnesses.get(&(order_id, hop_node))?;
        self.pending_floods.remove(&(order_id, hop_node));
        self.pending_witnesses.remove(&(order_id, hop_node));
        Some((hop_node, recv_time - forwarded_at))
    }

    fn record_verdict(
        &mut self,
        order_id: [u8; 32],
        hop_node: NodeId,
        observed_ms: f64,
        anomalous: bool,
    ) {
        if let Some(v) = self.verdicts.get_mut(&order_id) {
            v.push((hop_node, observed_ms, anomalous));
        } else {
            self.verdicts
                .put(order_id, vec![(hop_node, observed_ms, anomalous)]);
        }
    }

    // True if, for this exact order, some hop OTHER than `hop_node` was
    // recorded as NOT anomalous -- independent corroboration that
    // `hop_node` specifically is the outlier, not that the whole network
    // is just slow right now. False (not just "unknown") when there's no
    // other recorded path at all -- a single-path observation is real
    // evidence on its own (Stage 1 already established that), just not
    // corroborated evidence.
    fn has_corroborating_non_anomalous_hop(
        &mut self,
        order_id: &[u8; 32],
        hop_node: NodeId,
    ) -> bool {
        self.verdicts
            .get(order_id)
            .map(|v| {
                v.iter()
                    .any(|(h, _, anomalous)| *h != hop_node && !*anomalous)
            })
            .unwrap_or(false)
    }
}

// Stage 3: gates the actual CONSEQUENCE of a misconduct report (a
// reputation penalty via reputation::integration::on_misconduct_reported)
// behind agreement from multiple DISTINCT reporters, not a single node's
// word -- Stage 2's cross-witness check already strengthens what ONE
// node's own report means, but nothing stopped a single node (honest but
// wrong, or outright malicious) from unilaterally tanking another node's
// reputation the moment report_misconduct existed. Broadcasting a report
// is still immediate and ungated (see report_misconduct) -- only whether
// THIS node treats the accusation as confirmed enough to act on is
// gated here.
//
// Real, acknowledged limit: on its own, this has no Sybil resistance.
// Reporter identity here is just a NodeId with no cost to create or
// stake behind it, so an adversary controlling multiple identities can
// manufacture "independent" corroborating reports as cheaply as one.
// Stage 4b (see ChainNodeStatus, is_chain_eligible) closes part of this
// -- a reporter can be required to resolve to an active, staked
// NodeRegistry identity before its vote is even recorded here -- but
// it's still a pass/fail gate, not a stake-WEIGHTED vote: an adversary
// staking the on-chain minimum under several identities still gets one
// full vote per identity. That weighting is a further step, not done.
//
// Also a real limit worth being honest about: reputation here is
// per-node local state, not a shared ledger -- different nodes can reach
// quorum on the same subject at different times (or never), depending
// on which reports each happens to receive. That's inherent to not
// having any consensus layer, not a bug in this specific mechanism.
// Stage 4b: the data MisconductQuorum eligibility gating is checked
// against, pulled from NodeRegistry (see MeshNode::set_chain_status) --
// closes the Sybil gap flagged above: once `require_staked_reporters` is
// on, a reporter's vote only counts if its pubkey resolves to an entry
// here with `active: true`. Just a pass/fail gate, not a weighted vote by
// `stake` amount -- an adversary staking the on-chain minimum under
// several identities still gets one full vote per identity, just no
// longer a FREE one. Weighting by stake is a further step, not done here.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChainNodeStatus {
    pub active: bool,
    pub stake: u64,
}

// Stage 4d: each recorded vote now carries a WEIGHT (see
// MeshNode::reporter_weight), not just a distinct-reporter tally --
// closes the last gap Stage 4b/4c's docs flagged: a pass/fail active
// gate still gave an adversary staking the on-chain minimum under
// several identities one full vote per identity, same as one identity
// with 100x the stake. Quorum now requires BOTH min_reporters distinct
// voices (kept as a hard floor -- see below for why) AND their combined
// weight to clear stake_threshold.
//
// min_reporters is deliberately NOT replaced by the weight condition
// alone: without it, a single sufficiently-staked reporter could
// unilaterally trigger a reputation consequence, which is exactly the
// single-voice attack surface Stage 3 existed to close in the first
// place. Weighting strengthens what a vote is worth; it doesn't relax
// the requirement that more than one independent voice agree.
//
// With require_staked_reporters off, MeshNode::reporter_weight returns a
// flat 1.0 for every reporter and stake_threshold is 0 (see MeshNode::
// new) -- min_reporters is then the only binding constraint, reproducing
// Stage 3's exact distinct-count behavior.
struct MisconductQuorum {
    // subject -> (reporter -> (weight, last_accusation_time))
    accusations: HashMap<NodeId, HashMap<NodeId, (f64, f64)>>,
    min_reporters: usize,
    stake_threshold: f64,
    window_secs: f64,
}

impl MisconductQuorum {
    fn new(min_reporters: usize, stake_threshold: f64, window_secs: f64) -> Self {
        Self {
            accusations: HashMap::new(),
            min_reporters,
            stake_threshold,
            window_secs,
        }
    }

    // Records `reporter`'s accusation of `subject`, worth `weight`, at
    // `now` -- expiring any of that subject's accusations older than
    // window_secs first (so a handful of stale reports from long ago
    // can't quietly accumulate into a quorum). A repeat report from the
    // same reporter replaces its previous weight/timestamp rather than
    // accumulating (still one vote per distinct reporter, just refreshed
    // -- see MeshNode's docs on report spam not manufacturing quorum).
    // Returns (quorum_now_met, distinct_reporter_count, total_weight).
    fn record(
        &mut self,
        subject: NodeId,
        reporter: NodeId,
        weight: f64,
        now: f64,
    ) -> (bool, usize, f64) {
        let reporters = self.accusations.entry(subject).or_default();
        reporters.retain(|_, (_, last_seen)| now - *last_seen < self.window_secs);
        reporters.insert(reporter, (weight, now));
        let count = reporters.len();
        let total_weight: f64 = reporters.values().map(|(w, _)| *w).sum();
        let quorum_met = count >= self.min_reporters && total_weight >= self.stake_threshold;
        (quorum_met, count, total_weight)
    }
}

pub struct MeshNode {
    pub node_id: NodeId,
    pub region: Region,
    pub flood: DeterministicFlood,
    heartbeat: HeartbeatTracker,
    heartbeat_interval_ms: f64,
    max_missed_heartbeats: u32,
    // Arc<UdpTransport>, not Arc<Mutex<UdpTransport>>: both send and recv
    // take &self (tokio's UdpSocket is safe for concurrent send/recv from
    // multiple tasks), so a Mutex here is not just unnecessary but
    // actively harmful -- it previously let the background recv task's
    // spawned loop hold the lock for the full duration of a blocking
    // recv().await, starving every other user of the lock (forwarding
    // sends, heartbeats, echo requests/responses) until another packet
    // happened to arrive and free it. Under sparse traffic (e.g. exactly
    // one flood message with nothing else in flight) this could deadlock
    // forwarding indefinitely -- caught by
    // protocol/tests/mesh_test.rs::test_flood_forwarding_over_udp once
    // that test was given a real assertion instead of none.
    transport: Arc<UdpTransport>,
    peer_addrs: HashMap<NodeId, SocketAddr>,
    mesh_key: [u8; 32],
    censorship: CensorshipMonitor,
    latency_stats: crate::latency::PeerLatencyStats,
    hop_latency: HopLatencyMonitor,
    origin_time: crate::ordering::OriginTimeEstimator,
    // Lets a caller query origin_time AFTER run() has taken ownership of
    // self (estimated_origin_time_ms can't be called from outside
    // anymore at that point) -- see origin_time_query_sender. Same
    // pattern as chain_status_tx/rx.
    origin_time_query_tx: mpsc::Sender<([u8; 32], oneshot::Sender<Option<f64>>)>,
    origin_time_query_rx: Option<mpsc::Receiver<([u8; 32], oneshot::Sender<Option<f64>>)>>,
    compare_orders_query_tx: mpsc::Sender<(
        [u8; 32],
        [u8; 32],
        oneshot::Sender<Option<crate::ordering::OrderingDecision>>,
    )>,
    compare_orders_query_rx: Option<
        mpsc::Receiver<(
            [u8; 32],
            [u8; 32],
            oneshot::Sender<Option<crate::ordering::OrderingDecision>>,
        )>,
    >,
    // Stage P1: OrderSequencer needs a (witnessing_hop, estimate)
    // snapshot per order, not just the estimate -- see sequencer.rs's
    // docs on why it needs the hop for its tie-break input too.
    earliest_witness_query_tx: mpsc::Sender<([u8; 32], oneshot::Sender<Option<(NodeId, f64)>>)>,
    earliest_witness_query_rx:
        Option<mpsc::Receiver<([u8; 32], oneshot::Sender<Option<(NodeId, f64)>>)>>,
    misconduct_quorum: MisconductQuorum,
    // Stage P3a: whether multiple independent nodes' order-batch
    // proposals agree -- see crate::batch_quorum's docs.
    batch_quorum: crate::batch_quorum::OrderBatchQuorum,
    // Fires (batch_key, agreed_hash) once batch_quorum actually reaches
    // threshold for a batch_key -- take-before-run() rule, same as
    // confirmed_misconduct_receiver.
    confirmed_batch_tx: mpsc::Sender<([u8; 32], [u8; 32])>,
    confirmed_batch_rx: Option<mpsc::Receiver<([u8; 32], [u8; 32])>>,
    // Lets propose_batch be triggered AFTER run() has taken ownership of
    // self -- same reason chain_status_sender/compare_orders_query_sender
    // exist: propose_batch(&mut self, ...) can't be called from outside
    // once run() owns self. See propose_batch_sender.
    propose_batch_tx: mpsc::Sender<([u8; 32], Vec<[u8; 32]>)>,
    propose_batch_rx: Option<mpsc::Receiver<([u8; 32], Vec<[u8; 32]>)>>,
    // pubkey -> latest known on-chain status, pushed in by whoever owns
    // the chain connection (see set_chain_status's docs) -- empty until
    // something calls set_chain_status, which is fine: an empty map
    // combined with require_staked_reporters: false (the default) means
    // eligibility gating never triggers.
    chain_status: HashMap<[u8; 32], ChainNodeStatus>,
    require_staked_reporters: bool,
    // Lets a snapshot be pushed in AFTER run() has taken ownership of
    // self (set_chain_status can't be called from outside anymore at
    // that point) -- see chain_status_sender. run() drains this into
    // self.chain_status the same way set_chain_status would.
    chain_status_tx: mpsc::Sender<HashMap<[u8; 32], ChainNodeStatus>>,
    chain_status_rx: Option<mpsc::Receiver<HashMap<[u8; 32], ChainNodeStatus>>>,
    // nonce -> when this node sent that Ping, so RTT is computed from
    // this node's own clock on both ends (send and receive of the
    // matching Pong), never from anything the peer claims.
    pending_pings: HashMap<u64, f64>,
    next_ping_nonce: u64,
    artificial_forward_delay_ms: u64,
    reputation: reputation::ReputationEngine,
    rx: mpsc::Receiver<(NodeId, FloodMessage)>,
    tx: mpsc::Sender<(NodeId, FloodMessage)>,
    echo_rx: mpsc::Receiver<(NodeId, Vec<[u8; 32]>)>,
    echo_tx: mpsc::Sender<(NodeId, Vec<[u8; 32]>)>,
    settlement_tx: mpsc::Sender<(NodeId, prover::TradeBatch, Vec<u8>)>,
    // Taken once via settlement_proof_receiver(), before run() consumes
    // self -- mirrors how sender() exposes tx for injection, but in the
    // opposite direction (received-from-network, not injected-by-us).
    settlement_rx: Option<mpsc::Receiver<(NodeId, prover::TradeBatch, Vec<u8>)>>,
    log_entry_tx: mpsc::Sender<(NodeId, orderlog::LogEntry<orderlog::OrderReceipt>)>,
    log_entry_rx: Option<mpsc::Receiver<(NodeId, orderlog::LogEntry<orderlog::OrderReceipt>)>>,
    misconduct_tx: mpsc::Sender<MisconductEvent>,
    misconduct_rx: Option<mpsc::Receiver<MisconductEvent>>,
    // Stage P3c-2: every Flood arrival genuinely received from another
    // peer (never a self-injected one -- see flood_receiver's docs)
    // duplicated out here, for a caller that wants to independently
    // replicate/apply orders it only learned about via gossip, not just
    // record network-time evidence for them (which happens regardless,
    // via origin_time, whether or not anyone's listening on this).
    flood_observer_tx: mpsc::Sender<(NodeId, FloodMessage)>,
    flood_observer_rx: Option<mpsc::Receiver<(NodeId, FloodMessage)>>,
    // Stage P3c-3 found a real pre-existing latent race, made much more
    // likely to manifest by that stage's mesh routing fix (see its
    // docs): a node with genuine multi-path redundant arrivals for the
    // SAME order (Stage 1's whole point) used to broadcast a FRESH
    // HopWitness for every single arrival, including duplicates. A
    // downstream node's witness/flood matching is keyed only by
    // (order_id, hop_node) -- with two witnesses in flight for the same
    // key, whichever one happens to pair with the downstream flood
    // arrival first could be the LATE one, producing a wildly inflated
    // observed transit time for an otherwise perfectly honest hop (a
    // false anomaly, not a missed real one). Tracked here so a witness
    // is only ever broadcast for the FIRST arrival of a given order_id
    // -- exactly matching what a witness is actually supposed to attest
    // to ("when I first received this"), and eliminating the ambiguity
    // that made the race possible at all.
    witnessed_orders: lru::LruCache<[u8; 32], ()>,
    // Fires (subject) once quorum is actually reached -- see
    // confirmed_misconduct_receiver's docs.
    confirmation_tx: mpsc::Sender<NodeId>,
    confirmation_rx: Option<mpsc::Receiver<NodeId>>,
}

// A WireMessage::MisconductReport this node received, plus who it
// actually arrived from at the transport level (`from`) alongside who
// the message itself claims reported it (`reporter`) -- these are
// usually the same node but nothing here enforces that (see
// MisconductReport's own docs on this not yet being cryptographically
// tied to real evidence).
#[derive(Debug, Clone)]
pub struct MisconductEvent {
    pub from: NodeId,
    pub reporter: NodeId,
    pub subject: NodeId,
    pub reason: String,
    pub timestamp: f64,
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
    // Test-only: artificially delays every Flood/HopWitness this node
    // forwards by this many ms before sending. Exists to simulate
    // deliberate order-withholding for the latency-anomaly-detection
    // experiment (see HopLatencyMonitor) without faking anything else --
    // this node still pings/pongs and forwards honestly, just slowly.
    // None/0 in any real deployment; nothing here enables it by default.
    pub artificial_forward_delay_ms: Option<u64>,
    // Stage 4b: when true, a reporter's vote toward MisconductQuorum
    // only counts if its NodeId resolves (via peer_pubkey) to a pubkey
    // this node's chain_status snapshot (see set_chain_status) marks
    // active. Defaults false in every existing call site -- off
    // reproduces Stage 3's exact distinct-NodeId-counts behavior, so
    // nothing depending on that changes unless a real chain connection
    // is wired up and this is explicitly turned on (see api/src/main.rs).
    pub require_staked_reporters: bool,
    // Stage 4d: minimum COMBINED on-chain stake (see ChainNodeStatus)
    // across all of a subject's distinct eligible reporters before
    // MisconductQuorum treats the accusation as confirmed. Only
    // meaningful when require_staked_reporters is true -- ignored
    // (effectively 0) otherwise, since reporter_weight always returns
    // 1.0 per reporter when chain gating is off, and min_reporters (a
    // fixed floor of 2, not configurable) remains the only binding
    // constraint in that case, reproducing Stage 3's exact behavior. 0
    // in every call site that leaves require_staked_reporters false.
    pub misconduct_stake_threshold: u64,
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

            // Stage P3c-3 found a real bug here: downstream_peers is the
            // ONLY thing that actually drives forwarding (Flood
            // relaying, HopWitness broadcast -- see this file's other
            // uses of routing_table.downstream_peers) and used to be
            // populated ONLY for peers with a numerically larger
            // NodeId, meaning forwarding between any two peers was
            // one-directional: the lower-ID node would forward to the
            // higher-ID one, but never the reverse, since the
            // higher-ID node saw the lower-ID one as merely "upstream"
            // and never forwarded to it. That's fine for a strictly
            // hierarchical/tree topology, but breaks genuine
            // peer-to-peer gossip -- two mutually-configured peers
            // need to relay to EACH OTHER, not just whichever direction
            // ID ordering happens to favor. upstream_peers is kept
            // (still computed the same way) purely for the informational
            // log line below -- it has no other functional use anywhere
            // in this crate (checked before making this change).
            if id.0 < config.node_id.0 {
                routing.upstream_peers.push(peer.clone());
            }
            routing.downstream_peers.push(peer.clone());
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

        let heartbeat =
            HeartbeatTracker::new(config.heartbeat_interval_ms, config.max_missed_heartbeats);

        let (tx, rx) = mpsc::channel(1024);
        let (echo_tx, echo_rx) = mpsc::channel(256);
        let (settlement_tx, settlement_rx) = mpsc::channel(64);
        let (log_entry_tx, log_entry_rx) = mpsc::channel(1024);
        let (misconduct_tx, misconduct_rx) = mpsc::channel(256);
        let (flood_observer_tx, flood_observer_rx) = mpsc::channel(1024);
        let (confirmation_tx, confirmation_rx) = mpsc::channel(256);
        let (confirmed_batch_tx, confirmed_batch_rx) = mpsc::channel(256);
        let (propose_batch_tx, propose_batch_rx) = mpsc::channel(256);
        let (chain_status_tx, chain_status_rx) = mpsc::channel(8);
        let (origin_time_query_tx, origin_time_query_rx) = mpsc::channel(256);
        let (compare_orders_query_tx, compare_orders_query_rx) = mpsc::channel(256);
        let (earliest_witness_query_tx, earliest_witness_query_rx) = mpsc::channel(256);

        Ok(Self {
            node_id: config.node_id,
            region: config.region,
            flood,
            heartbeat,
            heartbeat_interval_ms: config.heartbeat_interval_ms,
            max_missed_heartbeats: config.max_missed_heartbeats,
            transport: Arc::new(transport),
            peer_addrs,
            mesh_key,
            censorship: CensorshipMonitor::new(),
            latency_stats: crate::latency::PeerLatencyStats::new(),
            hop_latency: HopLatencyMonitor::new(),
            origin_time: crate::ordering::OriginTimeEstimator::new(),
            origin_time_query_tx,
            origin_time_query_rx: Some(origin_time_query_rx),
            compare_orders_query_tx,
            compare_orders_query_rx: Some(compare_orders_query_rx),
            earliest_witness_query_tx,
            earliest_witness_query_rx: Some(earliest_witness_query_rx),
            // min_reporters=2: this node's own accusation (if it's the
            // one that detected something, see report_misconduct) plus
            // at least one independent corroborating report from
            // elsewhere. Arbitrary for this prototype -- a real
            // deployment would want this configurable and almost
            // certainly higher. stake_threshold is 0 unless
            // require_staked_reporters is on (see
            // misconduct_stake_threshold's docs on why 0 is a no-op).
            misconduct_quorum: MisconductQuorum::new(
                2,
                if config.require_staked_reporters {
                    config.misconduct_stake_threshold as f64
                } else {
                    0.0
                },
                60.0,
            ),
            // min_reporters=2, same rationale as MisconductQuorum's
            // constant above: this node's own proposal plus at least one
            // independent corroborating proposal from elsewhere.
            batch_quorum: crate::batch_quorum::OrderBatchQuorum::new(2, 60.0),
            confirmed_batch_tx,
            confirmed_batch_rx: Some(confirmed_batch_rx),
            propose_batch_tx,
            propose_batch_rx: Some(propose_batch_rx),
            chain_status: HashMap::new(),
            require_staked_reporters: config.require_staked_reporters,
            chain_status_tx,
            chain_status_rx: Some(chain_status_rx),
            pending_pings: HashMap::new(),
            next_ping_nonce: 0,
            artificial_forward_delay_ms: config.artificial_forward_delay_ms.unwrap_or(0),
            reputation: reputation::ReputationEngine::new(),
            rx,
            tx,
            echo_rx,
            echo_tx,
            settlement_tx,
            settlement_rx: Some(settlement_rx),
            log_entry_tx,
            log_entry_rx: Some(log_entry_rx),
            misconduct_tx,
            misconduct_rx: Some(misconduct_rx),
            flood_observer_tx,
            flood_observer_rx: Some(flood_observer_rx),
            witnessed_orders: lru::LruCache::new(std::num::NonZeroUsize::new(10_000).unwrap()),
            confirmation_tx,
            confirmation_rx: Some(confirmation_rx),
        })
    }

    pub fn sender(&self) -> mpsc::Sender<(NodeId, FloodMessage)> {
        self.tx.clone()
    }

    // Every WireMessage::MisconductReport this node receives, for a
    // caller (e.g. a watchtower loop) to log/act on. This node's own
    // ReputationEngine is also updated directly when this happens (see
    // run()'s misconduct handling) -- this receiver is for external
    // visibility beyond that, same take-before-run() rule as the other
    // receiver() methods.
    pub fn misconduct_receiver(&mut self) -> mpsc::Receiver<MisconductEvent> {
        self.misconduct_rx
            .take()
            .expect("misconduct_receiver already taken")
    }

    // Stage P3c-2: every Flood this node receives genuinely from another
    // peer -- NOT a self-injected one (a node submitting its own order
    // via mesh.sender.try_send, see api::server::apply_accepted_order,
    // gets excluded, since a caller already knows about its own
    // self-submitted orders and doesn't need to be told again). Take
    // before run(); intended for a caller that wants to independently
    // apply/replicate orders it only learned about via gossip -- see
    // api::gossip_replication. Recording network-time evidence
    // (origin_time) for every arrival happens regardless of whether
    // anyone takes this receiver at all.
    pub fn flood_receiver(&mut self) -> mpsc::Receiver<(NodeId, FloodMessage)> {
        self.flood_observer_rx
            .take()
            .expect("flood_receiver already taken")
    }

    // Fires the subject NodeId once this node's own MisconductQuorum
    // actually reaches threshold for them -- unlike misconduct_receiver
    // (every individual accusation, confirmed or not), this only fires
    // on confirmation. Same take-before-run() rule.
    pub fn confirmed_misconduct_receiver(&mut self) -> mpsc::Receiver<NodeId> {
        self.confirmation_rx
            .take()
            .expect("confirmed_misconduct_receiver already taken")
    }

    // Resolves a mesh NodeId to the chain-native pubkey pinned for it at
    // peer-registration time (see UdpTransport::peer_pubkey) -- the same
    // identity NodeRegistry tracks on-chain. Stage 4a: this binding
    // already existed for SignedHeartbeat verification, just wasn't
    // queryable from outside UdpTransport. None means either this NodeId
    // isn't a registered peer, or it was registered with the [0u8; 32]
    // no-key sentinel (unauthenticated, as most of this crate's tests
    // still do).
    pub fn peer_pubkey(&self, node_id: NodeId) -> Option<[u8; 32]> {
        self.transport.peer_pubkey(node_id)
    }

    // Stage O1: this node's own independently-derived estimate of when
    // `order_id` was likely first emitted -- see
    // crate::ordering::OriginTimeEstimator's docs for exactly what this
    // is (and isn't yet) accurate for. None means this node has no
    // established latency baseline yet for whichever peer(s) delivered
    // this order, so no correction was possible.
    pub fn estimated_origin_time_ms(&mut self, order_id: &[u8; 32]) -> Option<f64> {
        self.origin_time.earliest_estimate_ms(order_id)
    }

    // The channel-based counterpart to estimated_origin_time_ms, for a
    // caller that doesn't own the MeshNode anymore (run() has already
    // taken self by value) -- same shape as chain_status_sender. Take
    // before run(); each query is (order_id, reply channel).
    pub fn origin_time_query_sender(
        &self,
    ) -> mpsc::Sender<([u8; 32], oneshot::Sender<Option<f64>>)> {
        self.origin_time_query_tx.clone()
    }

    // Stage O2: ranks two orders using this node's own recorded
    // estimates -- see crate::ordering::OriginTimeEstimator::
    // compare_orders and OrderingDecision's docs for exactly what this
    // does (and doesn't) guarantee.
    pub fn compare_orders(
        &mut self,
        order_a: &[u8; 32],
        order_b: &[u8; 32],
    ) -> Option<crate::ordering::OrderingDecision> {
        self.origin_time.compare_orders(order_a, order_b)
    }

    // The channel-based counterpart to compare_orders, for a caller that
    // doesn't own the MeshNode anymore -- same shape as
    // origin_time_query_sender. Take before run(); each query is
    // (order_a, order_b, reply channel).
    pub fn compare_orders_query_sender(
        &self,
    ) -> mpsc::Sender<(
        [u8; 32],
        [u8; 32],
        oneshot::Sender<Option<crate::ordering::OrderingDecision>>,
    )> {
        self.compare_orders_query_tx.clone()
    }

    // Stage P1: the channel-based counterpart to
    // OriginTimeEstimator::earliest_witness -- (witnessing_hop,
    // estimate_ms) for a single order_id, the raw evidence
    // OrderSequencer::flush needs a snapshot of for every order in a
    // batch. Take before run(); each query is (order_id, reply channel).
    pub fn earliest_witness_query_sender(
        &self,
    ) -> mpsc::Sender<([u8; 32], oneshot::Sender<Option<(NodeId, f64)>>)> {
        self.earliest_witness_query_tx.clone()
    }

    // Like peer_pubkey, but also resolves THIS node's own NodeId to its
    // own pubkey (transport.public_key()) -- peer_pubkey alone can't,
    // since a node was never registered as its own peer. Needed because
    // report_misconduct's self-accusation (see below) must be checkable
    // for chain eligibility the same way an externally-received one is.
    fn reporter_pubkey(&self, reporter: NodeId) -> Option<[u8; 32]> {
        if reporter == self.node_id {
            let pk = self.transport.public_key();
            if pk != [0u8; 32] {
                Some(pk)
            } else {
                None
            }
        } else {
            self.transport.peer_pubkey(reporter)
        }
    }

    // Stage 4b: pushes a fresh on-chain status snapshot (see
    // ChainNodeStatus's docs), keyed by pubkey -- e.g. from a periodic
    // NodeRegistry poll via chain::ChainAdapter, done by whoever owns
    // that connection (this crate never talks to a chain directly).
    // Replaces the whole map each call rather than merging, so a pubkey
    // that's since left the registry (or gone inactive) actually stops
    // being eligible instead of the snapshot only ever growing stale
    // entries.
    pub fn set_chain_status(&mut self, snapshot: HashMap<[u8; 32], ChainNodeStatus>) {
        self.chain_status = snapshot;
    }

    // The channel-based counterpart to set_chain_status, for a caller
    // that doesn't own the MeshNode anymore (run() has already taken
    // self by value) -- e.g. api/src/main.rs's periodic NodeRegistry
    // poll, running as a separate task alongside tokio::spawn(mesh_node.
    // run()). Take before run() the same as sender()/transport(); every
    // send() here fully replaces the previous snapshot once run()'s main
    // loop drains it, same semantics as set_chain_status.
    pub fn chain_status_sender(&self) -> mpsc::Sender<HashMap<[u8; 32], ChainNodeStatus>> {
        self.chain_status_tx.clone()
    }

    // Stage 4d: how much `reporter`'s vote is actually WORTH toward
    // MisconductQuorum -- 1.0 flat (every reporter counts equally)
    // unless require_staked_reporters is on, in which case it's that
    // reporter's real on-chain stake if (and only if) chain_status marks
    // them active, or 0.0 (no vote at all) if they're inactive or don't
    // resolve to a known pubkey. 0.0 is exactly the old is_chain_eligible
    // rejection case -- MisconductQuorum::record still requires
    // min_reporters distinct non-zero votes regardless of how much any
    // one of them is worth, so a single, even enormous, stake can't
    // unilaterally confirm an accusation (see MisconductQuorum's docs).
    fn reporter_weight(&self, reporter: NodeId) -> f64 {
        if !self.require_staked_reporters {
            return 1.0;
        }
        match self
            .reporter_pubkey(reporter)
            .and_then(|pk| self.chain_status.get(&pk))
        {
            Some(status) if status.active => status.stake as f64,
            _ => 0.0,
        }
    }

    // Broadcasts a misconduct report about `subject` to every configured
    // peer -- used both by this node's own CensorshipMonitor (see run())
    // and available to external callers (e.g. a watchtower that detected
    // an invalid settlement proof) via this same method, so both paths
    // produce identical wire messages.
    // &mut self, not &self: broadcasting is still immediate and ungated
    // (any single detection is worth telling the mesh about), but this
    // node's own accusation also counts as its first vote toward ITS OWN
    // quorum for `subject` -- see MisconductQuorum's docs for why the
    // actual reputation consequence needs more than one voice before
    // this node treats it as confirmed.
    // Fires (batch_key, agreed_hash) once this node's own batch_quorum
    // actually reaches threshold -- take-before-run() rule, same as
    // confirmed_misconduct_receiver.
    pub fn confirmed_batch_receiver(&mut self) -> mpsc::Receiver<([u8; 32], [u8; 32])> {
        self.confirmed_batch_rx
            .take()
            .expect("confirmed_batch_receiver already taken")
    }

    // The channel-based counterpart to propose_batch, for a caller that
    // doesn't own the MeshNode anymore (run() has already taken self by
    // value) -- same take-before-run() pattern as
    // origin_time_query_sender/compare_orders_query_sender.
    pub fn propose_batch_sender(&self) -> mpsc::Sender<([u8; 32], Vec<[u8; 32]>)> {
        self.propose_batch_tx.clone()
    }

    // Stage P3a: broadcasts this node's own evidence-derived resolution
    // of `resolved_order_ids` (the actual output of
    // sequencer::OrderSequencer::flush -- this method doesn't resolve
    // anything itself, it only reports and votes on an already-resolved
    // sequence) to every peer, and records it as this node's own first
    // vote toward its own batch_quorum -- same self-counts-as-first-vote
    // pattern report_misconduct already uses. batch_key must be
    // batch_quorum::compute_batch_key(the same order_ids, any order) --
    // computed by the caller, not here, since the caller is the one who
    // knows which order_ids it resolved a sequence for.
    pub async fn propose_batch(&mut self, batch_key: [u8; 32], resolved_order_ids: &[[u8; 32]]) {
        let proposed_hash = crate::batch_quorum::compute_proposal_hash(resolved_order_ids);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        for peer_id in self.peer_ids() {
            let msg = WireMessage::BatchProposal {
                batch_key,
                proposed_hash,
                reporter: self.node_id,
                timestamp,
            };
            let _ = self.transport.send(peer_id, msg).await;
        }
        self.record_batch_proposal(batch_key, self.node_id, proposed_hash, timestamp);
    }

    // Shared by propose_batch's own vote and every incoming
    // WireMessage::BatchProposal this node receives (see run()'s
    // batch_proposal_rx branch).
    fn record_batch_proposal(
        &mut self,
        batch_key: [u8; 32],
        reporter: NodeId,
        proposed_hash: [u8; 32],
        now: f64,
    ) {
        if let Some(agreed_hash) = self
            .batch_quorum
            .record(batch_key, reporter, proposed_hash, now)
        {
            tracing::info!(?batch_key, "order batch quorum reached");
            let _ = self.confirmed_batch_tx.try_send((batch_key, agreed_hash));
        } else {
            tracing::debug!(
                ?batch_key,
                ?reporter,
                distinct_hashes = self.batch_quorum.distinct_hash_count(&batch_key),
                "batch proposal recorded, quorum not yet reached"
            );
        }
    }

    pub async fn report_misconduct(&mut self, subject: NodeId, reason: String) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        for peer_id in self.peer_ids() {
            let msg = WireMessage::MisconductReport {
                reporter: self.node_id,
                subject,
                reason: reason.clone(),
                timestamp,
            };
            let _ = self.transport.send(peer_id, msg).await;
        }
        self.apply_or_record_accusation(subject, self.node_id, &reason, timestamp);
    }

    // Shared by report_misconduct's own accusation and every incoming
    // MisconductReport this node receives (see run()'s
    // misconduct_internal_rx branch) -- records the vote, and only
    // applies the real reputation consequence
    // (reputation::integration::on_misconduct_reported) once
    // MisconductQuorum says enough distinct reporters agree.
    fn apply_or_record_accusation(
        &mut self,
        subject: NodeId,
        reporter: NodeId,
        reason: &str,
        now: f64,
    ) {
        let weight = self.reporter_weight(reporter);
        if weight <= 0.0 {
            tracing::debug!(?subject, ?reporter, "accusation ignored: reporter is not an active staked identity per the last chain_status snapshot");
            return;
        }
        let (quorum_met, count, total_weight) = self
            .misconduct_quorum
            .record(subject, reporter, weight, now);
        if quorum_met {
            tracing::warn!(
                ?subject,
                reporter_count = count,
                total_weight,
                "misconduct quorum reached, applying reputation consequence"
            );
            reputation::integration::on_misconduct_reported(
                &mut self.reputation,
                subject,
                reporter,
                reason,
            );
            let _ = self.confirmation_tx.try_send(subject);
        } else {
            tracing::debug!(
                ?subject,
                reporter_count = count,
                total_weight,
                min_reporters = self.misconduct_quorum.min_reporters,
                stake_threshold = self.misconduct_quorum.stake_threshold,
                "misconduct accusation recorded, quorum not yet reached"
            );
        }
    }

    // Shared by both HopLatencyMonitor arrival branches in run() (a
    // matched (order, hop) pair can complete from either the Flood side
    // or the HopWitness side, whichever arrives second). Records the
    // verdict either way -- not just anomalous ones -- since Stage 2's
    // corroboration check needs to know about normal-looking hops too,
    // and only reports misconduct (annotated with whether any other
    // independent path corroborates it) when this hop specifically
    // looks anomalous.
    async fn handle_hop_latency_result(
        &mut self,
        order_id: [u8; 32],
        hop_node: NodeId,
        observed_ms: f64,
    ) {
        let anomalous = self.latency_stats.is_anomalous(hop_node, observed_ms);
        self.hop_latency
            .record_verdict(order_id, hop_node, observed_ms, anomalous);

        // Stage O3: checked independently of `anomalous` -- is_anomalous
        // is deliberately one-sided (too slow only, see its own docs),
        // but a witness that's suspiciously FAST relative to this hop's
        // baseline (e.g. from a relay that inflated its own measured
        // latency via delayed Pong replies, making its witnessed
        // estimates look artificially early) is exactly the case
        // OriginTimeEstimator needs to distrust for ordering purposes,
        // even though it's never misconduct-reportable the way
        // withholding is.
        if self
            .latency_stats
            .is_implausibly_fast(hop_node, observed_ms)
        {
            self.origin_time.mark_anomalous(order_id, hop_node);
        }

        if !anomalous {
            return;
        }
        // Retroactively tells OriginTimeEstimator this specific hop's
        // estimate for this order shouldn't be trusted over an honest
        // alternative either -- see its docs.
        self.origin_time.mark_anomalous(order_id, hop_node);
        let bound = self
            .latency_stats
            .expected_one_way_bound_ms(hop_node)
            .unwrap_or(0.0);
        let corroborated = self
            .hop_latency
            .has_corroborating_non_anomalous_hop(&order_id, hop_node);
        tracing::warn!(
            ?hop_node,
            observed_ms,
            bound_ms = bound,
            corroborated,
            "hop transit time exceeds established latency baseline"
        );
        let corroboration_note = if corroborated {
            "corroborated: another independent path for the same order showed normal timing"
        } else {
            "uncorroborated: no other independent path observed for this order yet"
        };
        self.report_misconduct(
            hop_node,
            format!("order propagation delay: {observed_ms:.1}ms observed vs {bound:.1}ms baseline bound ({corroboration_note})"),
        ).await;
    }

    // Every WireMessage::SettlementProof this node receives from a peer,
    // for a caller (e.g. a watchtower loop) to independently re-verify --
    // see WireMessage::SettlementProof's docs. Must be called before
    // run(), which consumes self; panics if called twice.
    pub fn settlement_proof_receiver(
        &mut self,
    ) -> mpsc::Receiver<(NodeId, prover::TradeBatch, Vec<u8>)> {
        self.settlement_rx
            .take()
            .expect("settlement_proof_receiver already taken")
    }

    // Every WireMessage::LogEntryBroadcast this node receives, for a
    // caller to mirror into its own HashChainLog (see
    // orderlog::HashChainLog::try_append_remote) -- same
    // take-before-run() rule as settlement_proof_receiver.
    pub fn log_entry_receiver(
        &mut self,
    ) -> mpsc::Receiver<(NodeId, orderlog::LogEntry<orderlog::OrderReceipt>)> {
        self.log_entry_rx
            .take()
            .expect("log_entry_receiver already taken")
    }

    // Direct handle to this node's transport, for a caller that needs to
    // send something MeshNode's own run() loop doesn't originate itself
    // (e.g. broadcasting a SettlementProof to every configured peer) --
    // both UdpTransport::send/recv take &self, so sharing this alongside
    // run()'s own background tasks is safe (see this struct's docs on
    // `transport`).
    pub fn transport(&self) -> Arc<UdpTransport> {
        self.transport.clone()
    }

    pub fn peer_ids(&self) -> Vec<NodeId> {
        self.peer_addrs.keys().copied().collect()
    }

    pub async fn run(mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let tx = self.tx.clone();
        let echo_tx = self.echo_tx.clone();
        let settlement_tx = self.settlement_tx.clone();
        let log_entry_tx = self.log_entry_tx.clone();
        let misconduct_tx = self.misconduct_tx.clone();
        let mesh_key = self.mesh_key;
        let mut chain_status_rx = self.chain_status_rx.take().expect("run() already called");
        let mut origin_time_query_rx = self
            .origin_time_query_rx
            .take()
            .expect("run() already called");
        let mut compare_orders_query_rx = self
            .compare_orders_query_rx
            .take()
            .expect("run() already called");
        let mut earliest_witness_query_rx = self
            .earliest_witness_query_rx
            .take()
            .expect("run() already called");
        let mut propose_batch_rx = self.propose_batch_rx.take().expect("run() already called");

        // Purely internal to this loop (unlike settlement_tx/log_entry_tx/
        // misconduct_tx, no external caller needs raw Pong/HopWitness
        // events -- only the derived anomaly, which goes out as a
        // MisconductReport the same way CensorshipMonitor's does).
        let (pong_tx, mut pong_rx) = mpsc::channel::<(NodeId, u64, f64)>(256);
        let (hop_witness_tx, mut hop_witness_rx) =
            mpsc::channel::<(NodeId, [u8; 32], NodeId, f64)>(1024);
        let (batch_proposal_tx, mut batch_proposal_rx) =
            mpsc::channel::<([u8; 32], [u8; 32], NodeId, f64)>(256);
        // Every incoming MisconductReport is dual-sent: misconduct_tx
        // (external, unchanged -- e.g. watchtower_node printing it) and
        // this one, which only the main loop below drains, to run it
        // through MisconductQuorum and apply_or_record_accusation.
        let (misconduct_internal_tx, mut misconduct_internal_rx) =
            mpsc::channel::<MisconductEvent>(256);

        let recv_transport = self.transport.clone();
        tokio::spawn(async move {
            loop {
                let result = recv_transport.recv().await;
                match result {
                    Ok((from, msg)) => match msg {
                        WireMessage::Flood(fm) => {
                            let _ = tx.send((from, fm)).await;
                        }
                        WireMessage::EncryptedFlood(ref encrypted) => {
                            if mesh_key == [0u8; 32] {
                                continue;
                            }
                            match decrypt_packet(&mesh_key, encrypted) {
                                Ok(decrypted) => {
                                    if let Ok(fm) = bincode::deserialize::<FloodMessage>(&decrypted)
                                    {
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
                        WireMessage::SignedHeartbeat {
                            node_id, timestamp, ..
                        } => {
                            tracing::trace!(?node_id, %timestamp, "Signed heartbeat");
                        }
                        WireMessage::Heartbeat { node_id, .. } => {
                            tracing::trace!(?node_id, "Unsigned heartbeat");
                        }
                        WireMessage::Ack { .. } => {}
                        WireMessage::SettlementProof { batch, proof } => {
                            let _ = settlement_tx.send((from, batch, proof)).await;
                        }
                        WireMessage::LogEntryBroadcast { entry } => {
                            let _ = log_entry_tx.send((from, entry)).await;
                        }
                        WireMessage::MisconductReport {
                            reporter,
                            subject,
                            reason,
                            timestamp,
                        } => {
                            let event = MisconductEvent {
                                from,
                                reporter,
                                subject,
                                reason,
                                timestamp,
                            };
                            let _ = misconduct_tx.send(event.clone()).await;
                            let _ = misconduct_internal_tx.send(event).await;
                        }
                        WireMessage::Ping { nonce, .. } => {
                            // Answered directly here, not routed through
                            // the main loop -- replying needs no mutable
                            // state, just &self.transport, which this
                            // background task already has.
                            let _ = recv_transport.send(from, WireMessage::Pong { nonce }).await;
                        }
                        WireMessage::Pong { nonce } => {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs_f64()
                                * 1000.0;
                            let _ = pong_tx.send((from, nonce, now)).await;
                        }
                        WireMessage::HopWitness {
                            order_id,
                            hop_node,
                            forwarded_at,
                        } => {
                            let _ = hop_witness_tx
                                .send((from, order_id, hop_node, forwarded_at))
                                .await;
                        }
                        WireMessage::BatchProposal {
                            batch_key,
                            proposed_hash,
                            reporter,
                            timestamp,
                        } => {
                            let _ = batch_proposal_tx
                                .send((batch_key, proposed_hash, reporter, timestamp))
                                .await;
                        }
                    },
                    Err(e) => {
                        tracing::error!(error = %e, "Recv failed");
                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    }
                }
            }
        });

        let mut heartbeat_tick = tokio::time::interval(tokio::time::Duration::from_millis(100));
        let mut echo_tick =
            tokio::time::interval(tokio::time::Duration::from_secs(ECHO_INTERVAL_SECS));
        // Deliberately fast relative to heartbeat_tick -- this experiment
        // wants a usable RTT baseline within a couple of real seconds, not
        // production-cadence pinging (which would want to be far less
        // frequent to avoid flooding the network with its own traffic).
        let mut ping_tick = tokio::time::interval(tokio::time::Duration::from_millis(100));

        loop {
            tokio::select! {
                Some((from_node, flood_msg)) = self.rx.recv() => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs_f64() * 1000.0;

                    let order_id = flood_msg.order.id;

                    // Stage O1: recorded for EVERY arrival, including a
                    // later Err(DuplicatePacket) one below -- a duplicate
                    // via a different upstream path is an independent
                    // witness of this order's timing just as much as the
                    // first-accepted arrival is (same rationale Stage 1
                    // already established for recording redundant
                    // arrivals). No baseline yet for `from_node` (None)
                    // means this arrival simply can't contribute an
                    // estimate -- not an error, just not-yet-measured.
                    if let Some(one_way_ms) = self.latency_stats.mean_one_way_ms(from_node) {
                        self.origin_time.record(order_id, from_node, now - one_way_ms);
                    }

                    // Stage P3c-2: forwarded to flood_receiver's channel
                    // only for a genuinely peer-received arrival, not a
                    // self-injected one (from_node == self.node_id for
                    // those -- see apply_accepted_order's injection).
                    if from_node != self.node_id {
                        let _ = self.flood_observer_tx.try_send((from_node, flood_msg.clone()));
                    }

                    // Sent IMMEDIATELY, before on_receive's forwarding
                    // decision and before any artificial_forward_delay_ms
                    // -- this is the fix for the obvious hole in an
                    // earlier version of this: if the witness were sent
                    // alongside the (possibly delayed) forward, a
                    // withholding relay could just timestamp it AFTER its
                    // own delay too and the gap would always look honest.
                    // Emitting it here instead, from this relay's own
                    // earliest possible observation of the order, means a
                    // relay can't retroactively backdate how long it sat
                    // on something without also delaying this witness --
                    // which decouples it from artificial_forward_delay_ms
                    // entirely, so a NAIVE withholding implementation
                    // (delay the forward, nothing else) gets caught. A
                    // sophisticated adversary who deliberately delays this
                    // too would not be -- that's a real, acknowledged
                    // limit of this prototype, not a claim this solves
                    // the general case.
                    //
                    // Only for the FIRST arrival of this order_id -- see
                    // witnessed_orders' docs on the real race a second
                    // (or third...) witness for the same order can cause
                    // downstream.
                    if self.witnessed_orders.put(order_id, ()).is_none() {
                        for peer_id in self.flood.routing_table.downstream_peers.iter().map(|p| p.id) {
                            let _ = self.transport.send(peer_id, WireMessage::HopWitness {
                                order_id,
                                hop_node: self.node_id,
                                forwarded_at: now,
                            }).await;
                        }
                    }

                    // Correlates this arrival with the HopWitness the
                    // immediately preceding relay sent alongside it (if it
                    // has arrived yet -- order over UDP isn't guaranteed,
                    // see on_witness_received below for the other arrival
                    // order). See HopLatencyMonitor's docs.
                    if let Some((hop_node, observed_ms)) = self.hop_latency.on_flood_received(order_id, from_node, now) {
                        self.handle_hop_latency_result(order_id, hop_node, observed_ms).await;
                    }

                    match self.flood.on_receive(flood_msg, from_node, now) {
                        Ok(forwards) => {
                            reputation::integration::on_flood_relayed(&mut self.reputation, from_node);
                            let t = &self.transport;
                            for (target, fwd_msg) in forwards {
                                self.censorship.track_order(fwd_msg.order.id);
                                if self.mesh_key != [0u8; 32] {
                                    let serialized = bincode::serialize(&fwd_msg).unwrap_or_default();
                                    if let Ok(encrypted) = encrypt_packet(&self.mesh_key, &serialized) {
                                        let _ = t.send(target, WireMessage::EncryptedFlood(encrypted)).await;
                                        continue;
                                    }
                                }
                                if self.artificial_forward_delay_ms > 0 {
                                    tokio::time::sleep(std::time::Duration::from_millis(self.artificial_forward_delay_ms)).await;
                                }
                                let _ = t.send(target, WireMessage::Flood(fwd_msg)).await;
                            }
                        }
                        // A duplicate arrival via a genuinely different
                        // upstream path is legitimate mesh redundancy,
                        // not misbehavior -- penalizing it here would
                        // punish exactly the honest multi-path forwarding
                        // Stage 2's cross-witness checks depend on. The
                        // arrival itself is already recorded (see
                        // on_receive), just not re-forwarded.
                        Err(FloodError::DuplicatePacket) => {
                            tracing::trace!(?from_node, "Duplicate order arrival via alternate path (recorded, not penalized)");
                        }
                        Err(e) => {
                            reputation::integration::on_flood_dropped(&mut self.reputation, from_node);
                            tracing::debug!(?e, "Flood skip");
                        }
                    }
                }

                Some((from_peer, nonce, arrived_at)) = pong_rx.recv() => {
                    if let Some(sent_at) = self.pending_pings.remove(&nonce) {
                        let rtt_ms = arrived_at - sent_at;
                        self.latency_stats.record_rtt(from_peer, rtt_ms);
                    }
                }

                Some(event) = misconduct_internal_rx.recv() => {
                    self.apply_or_record_accusation(event.subject, event.reporter, &event.reason, event.timestamp);
                }

                Some((batch_key, proposed_hash, reporter, timestamp)) = batch_proposal_rx.recv() => {
                    self.record_batch_proposal(batch_key, reporter, proposed_hash, timestamp);
                }

                Some((batch_key, resolved_order_ids)) = propose_batch_rx.recv() => {
                    self.propose_batch(batch_key, &resolved_order_ids).await;
                }

                Some(snapshot) = chain_status_rx.recv() => {
                    tracing::debug!(entries = snapshot.len(), "chain_status snapshot updated");
                    self.chain_status = snapshot;
                }

                Some((order_id, reply)) = origin_time_query_rx.recv() => {
                    let _ = reply.send(self.origin_time.earliest_estimate_ms(&order_id));
                }

                Some((order_a, order_b, reply)) = compare_orders_query_rx.recv() => {
                    let _ = reply.send(self.origin_time.compare_orders(&order_a, &order_b));
                }

                Some((order_id, reply)) = earliest_witness_query_rx.recv() => {
                    let _ = reply.send(self.origin_time.earliest_witness(&order_id));
                }

                Some((from_wire, order_id, hop_node, forwarded_at)) = hop_witness_rx.recv() => {
                    // `from_wire` (the UDP sender) should equal `hop_node`
                    // (who the message claims forwarded it) for an honest
                    // peer -- both are kept since nothing here enforces
                    // that they match, same caveat as MisconductReport's.
                    let _ = from_wire;
                    if let Some((matched_hop, observed_ms)) = self.hop_latency.on_witness_received(order_id, hop_node, forwarded_at) {
                        self.handle_hop_latency_result(order_id, matched_hop, observed_ms).await;
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
                    let t = &self.transport;
                    let _ = t.send(echo_from, WireMessage::EchoResponse { present, missing }).await;
                    if missing_count > 0 {
                        tracing::warn!(?echo_from, %missing_count, "Echo: peer doesn't know about orders we've seen");
                        if self.censorship.reported_missing(echo_from) {
                            reputation::integration::on_censorship_flag(&mut self.reputation, echo_from);
                            // Stage D: don't just update our own local
                            // reputation view -- tell the rest of the
                            // mesh what we saw, so a peer who never
                            // echo-probed echo_from themselves still
                            // learns about it.
                            self.report_misconduct(
                                echo_from,
                                format!("censorship: missing {missing_count} order(s) this node had already seen"),
                            ).await;
                        }
                    }
                }

                _ = echo_tick.tick() => {
                    if let Some(order_id) = self.censorship.pick_random_order() {
                        let t = &self.transport;
                        for peer_id in self.flood.routing_table.downstream_peers.iter().map(|p| p.id) {
                            let _ = t.send(peer_id, WireMessage::EchoRequest {
                                order_ids: vec![order_id],
                            }).await;
                        }
                    }
                }

                _ = ping_tick.tick() => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs_f64() * 1000.0;
                    let peer_ids: Vec<NodeId> = self.peer_addrs.keys().copied().collect();
                    for peer_id in peer_ids {
                        let nonce = self.next_ping_nonce;
                        self.next_ping_nonce += 1;
                        self.pending_pings.insert(nonce, now);
                        let _ = self.transport.send(peer_id, WireMessage::Ping { nonce, sent_at: now }).await;
                    }
                    // Bounded cleanup for pings that never got a Pong
                    // (dead peer, packet loss) -- without this,
                    // pending_pings grows forever on a lossy link.
                    self.pending_pings.retain(|_, sent_at| now - *sent_at < 5000.0);
                }

                _ = heartbeat_tick.tick() => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs_f64();

                    let t = &self.transport;
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
