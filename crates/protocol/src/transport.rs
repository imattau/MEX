use common::{FloodMessage, NodeId};
use orderlog::{LogEntry, OrderReceipt};
use prover::TradeBatch;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

const MSG_FLOOD: u8 = 0x01;
const MSG_HEARTBEAT: u8 = 0x02;
const MSG_ACK: u8 = 0x03;
const MSG_ENCRYPTED_FLOOD: u8 = 0x04;
const MSG_SIGNED_HEARTBEAT: u8 = 0x05;
const MSG_ECHO_REQUEST: u8 = 0x06;
const MSG_ECHO_RESPONSE: u8 = 0x07;
const MSG_SETTLEMENT_PROOF: u8 = 0x08;
const MSG_LOG_ENTRY: u8 = 0x09;
const MSG_MISCONDUCT_REPORT: u8 = 0x0A;
const MSG_PING: u8 = 0x0B;
const MSG_PONG: u8 = 0x0C;
const MSG_HOP_WITNESS: u8 = 0x0D;
const MSG_BATCH_PROPOSAL: u8 = 0x0E;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WireMessage {
    Flood(FloodMessage),
    Heartbeat {
        node_id: NodeId,
        timestamp: f64,
    },
    Ack {
        node_id: NodeId,
    },
    EncryptedFlood(Vec<u8>),
    SignedHeartbeat {
        node_id: NodeId,
        timestamp: f64,
        node_public_key: [u8; 32],
        signature: Vec<u8>,
    },
    EchoRequest {
        order_ids: Vec<[u8; 32]>,
    },
    EchoResponse {
        present: Vec<[u8; 32]>,
        missing: Vec<[u8; 32]>,
    },
    // Broadcast by whichever node just submitted a settlement batch
    // on-chain, so any listening peer can independently re-verify the
    // proof (watchtower::WatchtowerClient::monitor_batch) against the
    // exact TradeBatch it was generated from, without trusting the
    // submitter's own self-report. Direct peer-to-peer, not
    // flood-forwarded like Order gossip -- see this stage's scoping
    // notes for why multi-hop propagation of this is a further stage.
    SettlementProof {
        batch: TradeBatch,
        proof: Vec<u8>,
    },
    // Broadcast by the sequencer for every order it commits to its own
    // order_log, in the exact sequence it committed them -- unlike Flood
    // (Stage A), which gossips a bare Order with no ordering guarantee,
    // this carries the actual orderlog::LogEntry (seq, prev_hash,
    // entry_hash, and the signed OrderReceipt), so a peer can verify each
    // one really is the sequencer's next committed entry
    // (orderlog::HashChainLog::try_append_remote) instead of just
    // learning an order existed at some point. Direct peer-to-peer, not
    // flood-forwarded, same as SettlementProof.
    LogEntryBroadcast {
        entry: LogEntry<OrderReceipt>,
    },
    // Stage D: broadcast by any node that independently detects
    // misconduct by another (a peer failing the CensorshipMonitor's echo
    // check, an invalid SettlementProof, a LogEntryBroadcast that fails
    // try_append_remote), instead of that detection only ever updating
    // the detecting node's own local ReputationEngine. `reason` is a
    // plain human-readable description, not a replayable proof -- this
    // makes misconduct KNOWN mesh-wide, it doesn't yet make it
    // independently re-verifiable by whoever receives the report (that
    // would mean embedding the actual evidence -- the batch+proof, the
    // rejected LogEntry -- which is a further extension, not done here).
    MisconductReport {
        reporter: NodeId,
        subject: NodeId,
        reason: String,
        timestamp: f64,
    },
    // Real challenge-response RTT measurement (see latency.rs's docs on
    // why this can't be a self-reported timestamp): the sender records
    // when it sent Ping, and computes RTT itself from when the matching
    // Pong comes back -- the peer being measured never gets to assert
    // its own latency.
    Ping {
        nonce: u64,
        sent_at: f64,
    },
    Pong {
        nonce: u64,
    },
    // Sent by a relay to a specific downstream peer at the same moment it
    // forwards that order's Flood, so the receiver can compute this
    // specific hop's observed transit time (its own local recv time minus
    // forwarded_at) and compare it against that hop's own established
    // latency baseline from Ping/Pong -- see node.rs's HopLatencyMonitor.
    // Without this, only the ORIGIN timestamp is available end to end
    // (FloodMessage.timestamp is carried unchanged through every hop), so
    // a multi-hop delay can never be attributed to a specific relay.
    HopWitness {
        order_id: [u8; 32],
        hop_node: NodeId,
        forwarded_at: f64,
    },
    // Stage P3a: `reporter`'s own independently-resolved sha256 hash of
    // a batch of orders, sequenced via ITS OWN OriginTimeEstimator
    // evidence -- see protocol::batch_quorum's docs. batch_key
    // identifies WHICH set of order_ids this is a proposal for (a hash
    // of the sorted order_id set, order-INsensitive, so any node that
    // knows the same set of order_ids computes the same batch_key
    // regardless of what order it thinks they belong in); proposed_hash
    // is the actual claim being voted on (order-SENSITIVE). Same
    // no-cryptographic-binding caveat as MisconductReport: nothing here
    // proves `reporter` is who actually sent this.
    BatchProposal {
        batch_key: [u8; 32],
        proposed_hash: [u8; 32],
        reporter: NodeId,
        timestamp: f64,
    },
}

pub struct UdpTransport {
    socket: UdpSocket,
    peer_addrs: HashMap<NodeId, SocketAddr>,
    peer_keys: HashMap<NodeId, [u8; 32]>,
    node_private_key: Option<[u8; 32]>,
    node_public_key: [u8; 32],
}

impl UdpTransport {
    pub async fn bind(
        addr: SocketAddr,
        node_key: Option<([u8; 32], [u8; 32])>,
    ) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind(addr).await?;
        let (private_seed, public_key) = node_key.unwrap_or(([0u8; 32], [0u8; 32]));
        Ok(Self {
            socket,
            peer_addrs: HashMap::new(),
            peer_keys: HashMap::new(),
            node_private_key: if private_seed == [0u8; 32] {
                None
            } else {
                Some(private_seed)
            },
            node_public_key: public_key,
        })
    }

    pub fn register_peer(&mut self, node_id: NodeId, addr: SocketAddr, pubkey: [u8; 32]) {
        self.peer_addrs.insert(node_id, addr);
        self.peer_keys.insert(node_id, pubkey);
    }

    // The pubkey pinned for `node_id` at register_peer time -- the same
    // value SignedHeartbeat verification checks against. Exposed so
    // callers (see MeshNode::peer_pubkey) can resolve a mesh NodeId to
    // the chain-native identity NodeRegistry actually tracks, without
    // duplicating this map. [0u8; 32] (the "no key configured" sentinel
    // used throughout this crate, e.g. tests that pass `[0u8; 32]` to
    // register_peer) is returned as None, not Some([0; 32]), since it
    // was never a real key to begin with.
    pub fn peer_pubkey(&self, node_id: NodeId) -> Option<[u8; 32]> {
        match self.peer_keys.get(&node_id) {
            Some(key) if *key != [0u8; 32] => Some(*key),
            _ => None,
        }
    }

    pub fn sign_heartbeat(&self, node_id: NodeId, timestamp: f64) -> Vec<u8> {
        if let Some(ref seed) = self.node_private_key {
            use ed25519_dalek::Signer;
            use ed25519_dalek::SigningKey;
            let sk = SigningKey::from_bytes(seed);
            let mut msg = Vec::new();
            msg.extend_from_slice(&node_id.0.to_be_bytes());
            msg.extend_from_slice(&timestamp.to_be_bytes());
            sk.sign(&msg).to_vec()
        } else {
            vec![]
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.node_public_key
    }

    pub async fn send(&self, node_id: NodeId, msg: WireMessage) -> Result<(), String> {
        let addr = self
            .peer_addrs
            .get(&node_id)
            .ok_or_else(|| format!("Unknown peer: {:?}", node_id))?;

        let (msg_type, payload) = match &msg {
            WireMessage::Flood(_) => (
                MSG_FLOOD,
                bincode::serialize(&msg).map_err(|e| format!("Serialize: {}", e))?,
            ),
            WireMessage::EncryptedFlood(ref data) => (MSG_ENCRYPTED_FLOOD, data.clone()),
            WireMessage::Heartbeat { .. } | WireMessage::Ack { .. } => (
                MSG_HEARTBEAT,
                bincode::serialize(&msg).map_err(|e| format!("Serialize: {}", e))?,
            ),
            WireMessage::SignedHeartbeat { .. } => (
                MSG_SIGNED_HEARTBEAT,
                bincode::serialize(&msg).map_err(|e| format!("Serialize: {}", e))?,
            ),
            WireMessage::EchoRequest { .. } => (
                MSG_ECHO_REQUEST,
                bincode::serialize(&msg).map_err(|e| format!("Serialize: {}", e))?,
            ),
            WireMessage::EchoResponse { .. } => (
                MSG_ECHO_RESPONSE,
                bincode::serialize(&msg).map_err(|e| format!("Serialize: {}", e))?,
            ),
            WireMessage::SettlementProof { .. } => (
                MSG_SETTLEMENT_PROOF,
                bincode::serialize(&msg).map_err(|e| format!("Serialize: {}", e))?,
            ),
            WireMessage::LogEntryBroadcast { .. } => (
                MSG_LOG_ENTRY,
                bincode::serialize(&msg).map_err(|e| format!("Serialize: {}", e))?,
            ),
            WireMessage::MisconductReport { .. } => (
                MSG_MISCONDUCT_REPORT,
                bincode::serialize(&msg).map_err(|e| format!("Serialize: {}", e))?,
            ),
            WireMessage::Ping { .. } => (
                MSG_PING,
                bincode::serialize(&msg).map_err(|e| format!("Serialize: {}", e))?,
            ),
            WireMessage::Pong { .. } => (
                MSG_PONG,
                bincode::serialize(&msg).map_err(|e| format!("Serialize: {}", e))?,
            ),
            WireMessage::HopWitness { .. } => (
                MSG_HOP_WITNESS,
                bincode::serialize(&msg).map_err(|e| format!("Serialize: {}", e))?,
            ),
            WireMessage::BatchProposal { .. } => (
                MSG_BATCH_PROPOSAL,
                bincode::serialize(&msg).map_err(|e| format!("Serialize: {}", e))?,
            ),
        };

        let mut packet = Vec::with_capacity(1 + payload.len());
        packet.push(msg_type);
        packet.extend_from_slice(&payload);

        self.socket
            .send_to(&packet, *addr)
            .await
            .map_err(|e| format!("Send error: {}", e))?;

        Ok(())
    }

    pub async fn recv(&self) -> Result<(NodeId, WireMessage), String> {
        let mut buf = [0u8; 65536];
        let (len, addr) = self
            .socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| format!("Recv error: {}", e))?;

        if len < 2 {
            return Err("Packet too short".to_string());
        }

        let msg_type = buf[0];
        let payload = &buf[1..len];

        let msg = match msg_type {
            MSG_ENCRYPTED_FLOOD => WireMessage::EncryptedFlood(payload.to_vec()),
            MSG_SIGNED_HEARTBEAT
            | MSG_HEARTBEAT
            | MSG_FLOOD
            | MSG_ACK
            | MSG_ECHO_REQUEST
            | MSG_ECHO_RESPONSE
            | MSG_SETTLEMENT_PROOF
            | MSG_LOG_ENTRY
            | MSG_MISCONDUCT_REPORT
            | MSG_PING
            | MSG_PONG
            | MSG_HOP_WITNESS
            | MSG_BATCH_PROPOSAL => bincode::deserialize::<WireMessage>(payload)
                .map_err(|e| format!("Deserialize: {}", e))?,
            _ => return Err(format!("Unknown message type: {}", msg_type)),
        };

        let node_id = self.resolve_sender(addr);

        match &msg {
            WireMessage::SignedHeartbeat {
                node_id: hb_id,
                timestamp,
                node_public_key,
                signature,
            } => {
                let pinned_key = self
                    .peer_keys
                    .get(hb_id)
                    .ok_or_else(|| format!("Unknown peer for heartbeat: {:?}", hb_id))?;
                if pinned_key != node_public_key {
                    return Err("Heartbeat public key does not match pinned peer key".to_string());
                }
                if !self.verify_heartbeat_sig(*hb_id, *timestamp, *pinned_key, signature) {
                    return Err("Invalid heartbeat signature".to_string());
                }
            }
            _ => {}
        }

        Ok((node_id, msg))
    }

    fn verify_heartbeat_sig(
        &self,
        node_id: NodeId,
        timestamp: f64,
        pubkey: [u8; 32],
        signature: &[u8],
    ) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let vk = match VerifyingKey::from_bytes(&pubkey) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let sig = match Signature::from_slice(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let mut msg = Vec::new();
        msg.extend_from_slice(&node_id.0.to_be_bytes());
        msg.extend_from_slice(&timestamp.to_be_bytes());
        vk.verify(&msg, &sig).is_ok()
    }

    fn resolve_sender(&self, addr: SocketAddr) -> NodeId {
        for (id, peer_addr) in &self.peer_addrs {
            if *peer_addr == addr {
                return *id;
            }
        }
        NodeId(u32::MAX)
    }

    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.socket.local_addr()
    }
}
