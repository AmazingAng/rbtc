use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use tokio::{
    net::TcpStream,
    sync::mpsc,
};
use tracing::{debug, info, warn};

use rbtc_primitives::{
    block::{Block, BlockHeader},
    hash::BlockHash,
    network::Network,
    transaction::Transaction,
};

use crate::{
    message::{GetBlocksMessage, Inventory, InvType, NetworkMessage},
    peer::{run_peer, PeerCommand, PeerEvent},
};

static NEXT_PEER_ID: AtomicU64 = AtomicU64::new(1);

/// Configuration for the peer manager
#[derive(Debug, Clone)]
pub struct PeerManagerConfig {
    pub network: Network,
    pub max_outbound: usize,
    pub max_inbound: usize,
    pub connect_timeout: Duration,
}

impl Default for PeerManagerConfig {
    fn default() -> Self {
        Self {
            network: Network::Mainnet,
            max_outbound: 8,
            max_inbound: 125,
            connect_timeout: Duration::from_secs(10),
        }
    }
}

/// Events emitted by the peer manager to the node
#[derive(Debug)]
pub enum NodeEvent {
    PeerConnected { peer_id: u64, addr: SocketAddr, best_height: i32 },
    PeerDisconnected { peer_id: u64 },
    BlockReceived { peer_id: u64, block: Block },
    HeadersReceived { peer_id: u64, headers: Vec<BlockHeader> },
    TxReceived { peer_id: u64, tx: Transaction },
    InvReceived { peer_id: u64, items: Vec<Inventory> },
}

/// Connected peer metadata
struct ConnectedPeer {
    #[allow(dead_code)]
    addr: SocketAddr,
    best_height: i32,
    cmd_tx: mpsc::UnboundedSender<PeerCommand>,
}

/// Central peer manager – manages connections and dispatches messages
pub struct PeerManager {
    config: PeerManagerConfig,
    peers: HashMap<u64, ConnectedPeer>,
    event_tx: mpsc::UnboundedSender<PeerEvent>,
    event_rx: mpsc::UnboundedReceiver<PeerEvent>,
    node_event_tx: mpsc::UnboundedSender<NodeEvent>,
    best_height: i32,
}

impl PeerManager {
    pub fn new(config: PeerManagerConfig, node_event_tx: mpsc::UnboundedSender<NodeEvent>, best_height: i32) -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        Self {
            config,
            peers: HashMap::new(),
            event_tx,
            event_rx,
            node_event_tx,
            best_height,
        }
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Connect to a peer by address string
    pub async fn connect(&self, addr: &str) {
        let event_tx = self.event_tx.clone();
        let config = self.config.clone();
        let best_height = self.best_height;
        let addr_str = addr.to_string();

        tokio::spawn(async move {
            let result = tokio::time::timeout(
                config.connect_timeout,
                TcpStream::connect(&addr_str),
            ).await;

            match result {
                Ok(Ok(stream)) => {
                    let peer_id = NEXT_PEER_ID.fetch_add(1, Ordering::Relaxed);
                    let peer_addr = stream.peer_addr().unwrap_or_else(|_| {
                        addr_str.parse().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap())
                    });

                    info!("connected to peer {peer_id} at {peer_addr}");

                    let (_cmd_tx, cmd_rx) = mpsc::unbounded_channel();

                    // Notify peer manager of new peer (via a synthetic event)
                    // The run_peer function will send Ready/Disconnected events
                    tokio::spawn(run_peer(
                        peer_id,
                        peer_addr,
                        stream,
                        config.network,
                        best_height,
                        event_tx,
                        cmd_rx,
                    ));
                }
                Ok(Err(e)) => warn!("failed to connect to {addr_str}: {e}"),
                Err(_) => warn!("connection timeout to {addr_str}"),
            }
        });
    }

    /// Connect to DNS seeds
    pub async fn connect_to_seeds(&mut self) {
        let seeds = self.config.network.dns_seeds();
        let port = self.config.network.default_port();

        for seed in seeds {
            let addr = format!("{seed}:{port}");
            info!("connecting to seed: {addr}");
            self.connect(&addr).await;

            // Small delay between seed connections
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Send a message to a specific peer
    pub fn send_to(&self, peer_id: u64, msg: NetworkMessage) {
        if let Some(peer) = self.peers.get(&peer_id) {
            let _ = peer.cmd_tx.send(PeerCommand::Send(msg));
        }
    }

    /// Broadcast a message to all connected peers
    pub fn broadcast(&self, msg: NetworkMessage) {
        for peer in self.peers.values() {
            let _ = peer.cmd_tx.send(PeerCommand::Send(msg.clone()));
        }
    }

    /// Request headers from all peers using block locator
    pub fn request_headers(&self, locator: Vec<BlockHash>) {
        let msg = NetworkMessage::GetHeaders(GetBlocksMessage::new(locator));
        self.broadcast(msg);
    }

    /// Request a specific block by hash
    pub fn request_block(&self, peer_id: u64, hash: BlockHash) {
        let inv = vec![Inventory { inv_type: InvType::WitnessBlock, hash }];
        self.send_to(peer_id, NetworkMessage::GetData(inv));
    }

    /// Request multiple blocks (IBD batch download)
    pub fn request_blocks(&self, peer_id: u64, hashes: &[BlockHash]) {
        let items: Vec<_> = hashes.iter()
            .map(|h| Inventory { inv_type: InvType::WitnessBlock, hash: *h })
            .collect();
        if !items.is_empty() {
            self.send_to(peer_id, NetworkMessage::GetData(items));
        }
    }

    /// Disconnect a peer
    pub fn disconnect(&self, peer_id: u64) {
        if let Some(peer) = self.peers.get(&peer_id) {
            let _ = peer.cmd_tx.send(PeerCommand::Disconnect);
        }
    }

    /// Get the best height among connected peers
    pub fn best_peer_height(&self) -> i32 {
        self.peers.values().map(|p| p.best_height).max().unwrap_or(0)
    }

    /// Get a peer with the best known height
    pub fn best_peer(&self) -> Option<u64> {
        self.peers.iter()
            .max_by_key(|(_, p)| p.best_height)
            .map(|(&id, _)| id)
    }

    /// Update our current best height (e.g. after connecting a block)
    pub fn set_best_height(&mut self, height: i32) {
        self.best_height = height;
    }

    /// Process all pending peer events (non-blocking, call from event loop)
    pub async fn process_events(&mut self) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                PeerEvent::Ready { peer_id, addr, best_height, user_agent } => {
                    // Register the peer's command sender
                    // The cmd_tx was created in connect(); we need to thread it through
                    // For now, we emit the node event
                    info!("peer {peer_id} ready: height={best_height} ua={user_agent}");
                    let _ = self.node_event_tx.send(NodeEvent::PeerConnected {
                        peer_id, addr, best_height,
                    });
                }
                PeerEvent::Disconnected { peer_id } => {
                    self.peers.remove(&peer_id);
                    let _ = self.node_event_tx.send(NodeEvent::PeerDisconnected { peer_id });
                    debug!("peer {peer_id} disconnected");
                }
                PeerEvent::Message { peer_id, message } => {
                    self.handle_message(peer_id, message).await;
                }
            }
        }
    }

    async fn handle_message(&mut self, peer_id: u64, message: NetworkMessage) {
        match message {
            NetworkMessage::Block(block) => {
                let _ = self.node_event_tx.send(NodeEvent::BlockReceived { peer_id, block });
            }
            NetworkMessage::Headers(h) => {
                let _ = self.node_event_tx.send(NodeEvent::HeadersReceived {
                    peer_id,
                    headers: h.headers,
                });
            }
            NetworkMessage::Tx(tx) => {
                let _ = self.node_event_tx.send(NodeEvent::TxReceived { peer_id, tx });
            }
            NetworkMessage::Inv(items) => {
                let _ = self.node_event_tx.send(NodeEvent::InvReceived { peer_id, items });
            }
            NetworkMessage::SendHeaders => {
                // Peer prefers headers over inv – noted
            }
            NetworkMessage::FeeFilter(_) => {
                // Policy, ignore for now
            }
            other => {
                debug!("peer {peer_id}: unhandled message: {}", other.command());
            }
        }
    }

    /// Main event loop – call this in a tokio task
    pub async fn run(mut self) {
        loop {
            self.process_events().await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
