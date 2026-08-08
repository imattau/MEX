// Stage C of connecting the gossip mesh to real settlement: a standalone
// process that joins the mesh as a peer and independently re-verifies
// every settlement proof it's broadcast a copy of
// (protocol::WireMessage::SettlementProof), instead of trusting the
// submitting node's own "I settled it" self-report.
//
// watchtower::WatchtowerClient::monitor_batch already existed and did the
// right thing (verify the proof, raise a dispute + slash the signers on
// failure) -- it just had nothing feeding it live data before this. This
// is that feed. It logs the same MockOnChainState side effects
// monitor_batch always produced; it does NOT (yet) submit a real on-chain
// dispute/slash transaction -- that needs a real chain-facing
// implementation of watchtower::OnChainClient, which chain_ethereum's
// EthereumAdapter doesn't have (it only implements the read/settle-side
// ChainAdapter trait). That's a further stage, not this one.
//
// Usage:
//   cargo run -p trader-client --bin watchtower_node -- <node_id> <listen_addr> <peers>
//   e.g. ... -- 2 127.0.0.1:19002 1@127.0.0.1:19001

use common::{NodeId, Region};
use prover::BACKEND;
use protocol::{MeshConfig, MeshNode};
use watchtower::{MockOnChainState, WatchtowerClient};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let node_id: u32 = args.get(1).expect("usage: watchtower_node <node_id> <listen_addr> <peers>").parse().unwrap();
    let listen_addr: std::net::SocketAddr = args.get(2).expect("missing listen_addr").parse().unwrap();
    let peers_str = args.get(3).cloned().unwrap_or_default();

    let peers: Vec<(NodeId, std::net::SocketAddr, [u8; 32])> = peers_str
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|entry| {
            let (id_part, addr_part) = entry.split_once('@').expect("peer entries must be id@host:port");
            (NodeId(id_part.parse().unwrap()), addr_part.parse().unwrap(), [0u8; 32])
        })
        .collect();

    let mut mesh_node = MeshNode::new(MeshConfig {
        node_id: NodeId(node_id),
        region: Region::UsEast1,
        listen_addr,
        peers,
        node_key: None,
        mesh_encryption_key: None,
        heartbeat_interval_ms: 1000.0,
        max_missed_heartbeats: 10,
        schedule: None,
    })
    .await
    .unwrap_or_else(|e| panic!("failed to bind mesh listener on {listen_addr}: {e}"));

    let mut settlement_proofs = mesh_node.settlement_proof_receiver();
    tokio::spawn(mesh_node.run());

    println!("watchtower_node {node_id} listening on {listen_addr}, watching for settlement proofs...");

    let watchtower = WatchtowerClient;
    let mut on_chain = MockOnChainState::new();
    let mut checked = 0u64;

    while let Some((from, batch, proof)) = settlement_proofs.recv().await {
        checked += 1;
        let trades_before = batch.trades.len();
        let ok = watchtower.monitor_batch(&batch, &proof, &BACKEND, &mut on_chain);
        if ok {
            println!(
                "[{checked}] batch from node {from:?} ({trades_before} trades): VALID -- proof independently verified"
            );
        } else {
            println!(
                "[{checked}] batch from node {from:?} ({trades_before} trades): INVALID -- proof failed independent \
                 verification. disputes_raised={}, slashed_signers={} (local record only -- no on-chain action taken, \
                 see this binary's top docs)",
                on_chain.disputes_raised,
                on_chain.slashed_signers.len(),
            );
        }
    }
}
