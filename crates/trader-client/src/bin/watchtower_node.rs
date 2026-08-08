// A standalone process that joins the gossip mesh as a peer and provides
// two independent accountability checks, neither trusting the
// sequencer/settlement node's own self-report:
//
// Stage C: re-verifies every settlement proof it's broadcast a copy of
// (protocol::WireMessage::SettlementProof) using
// watchtower::WatchtowerClient::monitor_batch, which already existed and
// did the right thing (verify the proof, raise a dispute + slash the
// signers on failure) -- it just had nothing feeding it live data before
// this. Logs the same MockOnChainState side effects monitor_batch always
// produced; does NOT (yet) submit a real on-chain dispute/slash
// transaction -- that needs a real chain-facing implementation of
// watchtower::OnChainClient, which chain_ethereum's EthereumAdapter
// doesn't have. A further stage, not this one.
//
// Stage B: mirrors the sequencer's order_log by accepting each broadcast
// LogEntryBroadcast into its own orderlog::HashChainLog, verifying as
// each arrives (orderlog::HashChainLog::try_append_remote) that it's
// really the sequencer's next committed entry, not just gossip that an
// order existed at some point. Prints its mirrored root periodically so
// it can be checked against the sequencer's own published root (GET
// /api/v1/order_log/root) -- if they ever match at the same length,
// this process independently confirms the sequencer hasn't rewritten
// anything it broadcast.
//
// Usage:
//   cargo run -p trader-client --bin watchtower_node -- <node_id> <listen_addr> <peers>
//   e.g. ... -- 2 127.0.0.1:19002 1@127.0.0.1:19001

use common::{NodeId, Region};
use orderlog::{HashChainLog, OrderReceipt};
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
    let mut log_entries = mesh_node.log_entry_receiver();
    tokio::spawn(mesh_node.run());

    println!("watchtower_node {node_id} listening on {listen_addr}, watching for settlement proofs and order log entries...");

    let log_mirror_task = tokio::spawn(async move {
        let mut mirror: HashChainLog<OrderReceipt> = HashChainLog::new();
        while let Some((from, entry)) = log_entries.recv().await {
            let seq = entry.seq;
            match mirror.try_append_remote(entry) {
                Ok(()) => {
                    println!(
                        "[order_log] accepted entry seq={seq} from node {from:?} -- mirror now len={} root={}",
                        mirror.len(),
                        hex::encode(&mirror.root()[..4]),
                    );
                }
                Err(e) => {
                    println!("[order_log] REJECTED entry seq={seq} from node {from:?}: {e}");
                }
            }
        }
    });

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

    let _ = log_mirror_task.await;
}
