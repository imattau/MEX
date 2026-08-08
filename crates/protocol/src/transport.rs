use common::{FloodMessage, NodeId};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WireMessage {
    Flood(FloodMessage),
    Heartbeat { node_id: NodeId, timestamp: f64 },
    Ack { node_id: NodeId },
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
            node_private_key: if private_seed == [0u8; 32] { None } else { Some(private_seed) },
            node_public_key: public_key,
        })
    }

    pub fn register_peer(&mut self, node_id: NodeId, addr: SocketAddr, pubkey: [u8; 32]) {
        self.peer_addrs.insert(node_id, addr);
        self.peer_keys.insert(node_id, pubkey);
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
            WireMessage::Flood(_) => {
                (MSG_FLOOD, bincode::serialize(&msg).map_err(|e| format!("Serialize: {}", e))?)
            }
            WireMessage::EncryptedFlood(ref data) => {
                (MSG_ENCRYPTED_FLOOD, data.clone())
            }
            WireMessage::Heartbeat { .. } | WireMessage::Ack { .. } => {
                (MSG_HEARTBEAT, bincode::serialize(&msg).map_err(|e| format!("Serialize: {}", e))?)
            }
            WireMessage::SignedHeartbeat { .. } => {
                (MSG_SIGNED_HEARTBEAT, bincode::serialize(&msg).map_err(|e| format!("Serialize: {}", e))?)
            }
            WireMessage::EchoRequest { .. } => {
                (MSG_ECHO_REQUEST, bincode::serialize(&msg).map_err(|e| format!("Serialize: {}", e))?)
            }
            WireMessage::EchoResponse { .. } => {
                (MSG_ECHO_RESPONSE, bincode::serialize(&msg).map_err(|e| format!("Serialize: {}", e))?)
            }
            WireMessage::SettlementProof { .. } => {
                (MSG_SETTLEMENT_PROOF, bincode::serialize(&msg).map_err(|e| format!("Serialize: {}", e))?)
            }
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
            MSG_ENCRYPTED_FLOOD => {
                WireMessage::EncryptedFlood(payload.to_vec())
            }
            MSG_SIGNED_HEARTBEAT | MSG_HEARTBEAT | MSG_FLOOD | MSG_ACK
            | MSG_ECHO_REQUEST | MSG_ECHO_RESPONSE | MSG_SETTLEMENT_PROOF => {
                bincode::deserialize::<WireMessage>(payload)
                    .map_err(|e| format!("Deserialize: {}", e))?
            }
            _ => return Err(format!("Unknown message type: {}", msg_type)),
        };

        let node_id = self.resolve_sender(addr);

        match &msg {
            WireMessage::SignedHeartbeat { node_id: hb_id, timestamp, node_public_key, signature } => {
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
