use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use tokio::{
    net::{TcpListener, TcpStream},
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
    /// Port to listen for inbound connections (0 = disabled)
    pub listen_port: u16,
}

impl Default for PeerManagerConfig {
    fn default() -> Self {
        Self {
            network: Network::Mainnet,
            max_outbound: 8,
            max_inbound: 125,
            connect_timeout: Duration::from_secs(10),
            listen_port: 0,
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
    /// BIP152: compact block received
    CmpctBlockReceived { peer_id: u64, cmpct: crate::compact::CompactBlock },
    /// BIP152: peer is requesting missing transactions
    GetBlockTxnReceived { peer_id: u64, req: crate::compact::GetBlockTxn },
    /// BIP152: peer responded with missing transactions
    BlockTxnReceived { peer_id: u64, resp: crate::compact::BlockTxn },
}

/// Connected peer metadata
struct ConnectedPeer {
    #[allow(dead_code)]
    addr: SocketAddr,
    best_height: i32,
    cmd_tx: mpsc::UnboundedSender<PeerCommand>,
}

/// Registration message: associates a peer_id with its command sender channel.
/// Sent by `connect()` / inbound listener before `run_peer` is spawned.
type CmdRegistration = (u64, SocketAddr, mpsc::UnboundedSender<PeerCommand>);

/// Central peer manager – manages connections and dispatches messages
pub struct PeerManager {
    config: PeerManagerConfig,
    peers: HashMap<u64, ConnectedPeer>,
    /// Pending (peer_id → cmd_tx) registrations not yet confirmed by PeerEvent::Ready
    pending_cmd_txs: HashMap<u64, (SocketAddr, mpsc::UnboundedSender<PeerCommand>)>,
    /// Channel for registering new peer cmd senders (outbound + inbound)
    cmd_reg_tx: mpsc::UnboundedSender<CmdRegistration>,
    cmd_reg_rx: mpsc::UnboundedReceiver<CmdRegistration>,
    event_tx: mpsc::UnboundedSender<PeerEvent>,
    event_rx: mpsc::UnboundedReceiver<PeerEvent>,
    node_event_tx: mpsc::UnboundedSender<NodeEvent>,
    best_height: i32,
    #[allow(dead_code)]
    inbound_count: usize,
}

impl PeerManager {
    pub fn new(
        config: PeerManagerConfig,
        node_event_tx: mpsc::UnboundedSender<NodeEvent>,
        best_height: i32,
    ) -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (cmd_reg_tx, cmd_reg_rx) = mpsc::unbounded_channel();
        Self {
            config,
            peers: HashMap::new(),
            pending_cmd_txs: HashMap::new(),
            cmd_reg_tx,
            cmd_reg_rx,
            event_tx,
            event_rx,
            node_event_tx,
            best_height,
            inbound_count: 0,
        }
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Connect to a peer by address string
    pub async fn connect(&self, addr: &str) {
        let peer_id = NEXT_PEER_ID.fetch_add(1, Ordering::Relaxed);
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<PeerCommand>();

        let event_tx = self.event_tx.clone();
        let cmd_reg_tx = self.cmd_reg_tx.clone();
        let config = self.config.clone();
        let best_height = self.best_height;
        let addr_str = addr.to_string();

        tokio::spawn(async move {
            let result = tokio::time::timeout(
                config.connect_timeout,
                TcpStream::connect(&addr_str),
            )
            .await;

            match result {
                Ok(Ok(stream)) => {
                    let peer_addr = stream.peer_addr().unwrap_or_else(|_| {
                        addr_str
                            .parse()
                            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap())
                    });
                    info!("connected to peer {peer_id} at {peer_addr}");
                    // Register cmd_tx BEFORE spawning run_peer
                    let _ = cmd_reg_tx.send((peer_id, peer_addr, cmd_tx));
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

    /// Start listening for inbound connections on the configured port.
    /// Returns immediately; the listener runs in a background task.
    pub async fn start_inbound_listener(&self) -> anyhow::Result<()> {
        if self.config.listen_port == 0 {
            return Ok(());
        }
        let addr = format!("0.0.0.0:{}", self.config.listen_port);
        let listener = TcpListener::bind(&addr).await?;
        info!("listening for inbound connections on {addr}");

        let event_tx = self.event_tx.clone();
        let cmd_reg_tx = self.cmd_reg_tx.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        let peer_id = NEXT_PEER_ID.fetch_add(1, Ordering::Relaxed);
                        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<PeerCommand>();
                        info!("inbound connection {peer_id} from {peer_addr}");
                        // Register BEFORE spawning
                        let _ = cmd_reg_tx.send((peer_id, peer_addr, cmd_tx));
                        tokio::spawn(run_peer(
                            peer_id,
                            peer_addr,
                            stream,
                            config.network,
                            0, // we don't know our height yet in this closure; peer will learn
                            event_tx.clone(),
                            cmd_rx,
                        ));
                    }
                    Err(e) => warn!("inbound accept error: {e}"),
                }
            }
        });

        Ok(())
    }

    /// Resolve DNS seeds and connect to the discovered peer addresses.
    pub async fn connect_to_seeds(&mut self) {
        use tokio::net::lookup_host;

        let seeds = self.config.network.dns_seeds();
        let port = self.config.network.default_port();
        let max = self.config.max_outbound;

        let mut addrs: Vec<SocketAddr> = Vec::new();

        for seed in seeds {
            let host_port = format!("{seed}:{port}");
            info!("resolving seed: {host_port}");
            match lookup_host(host_port).await {
                Ok(resolved) => {
                    for addr in resolved {
                        if addr.is_ipv4() {
                            addrs.push(addr);
                        }
                    }
                }
                Err(e) => warn!("failed to resolve seed {seed}: {e}"),
            }
        }

        info!("DNS seeds resolved to {} addresses", addrs.len());

        // Simple Fisher-Yates shuffle using a time-seeded value.
        {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            std::time::SystemTime::now().hash(&mut h);
            let mut seed = h.finish();
            for i in (1..addrs.len()).rev() {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                let j = (seed >> 33) as usize % (i + 1);
                addrs.swap(i, j);
            }
        }

        for addr in addrs.iter().take(max) {
            self.connect(&addr.to_string()).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
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
        let items: Vec<_> = hashes
            .iter()
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
        self.peers
            .iter()
            .max_by_key(|(_, p)| p.best_height)
            .map(|(&id, _)| id)
    }

    /// Update our current best height (e.g. after connecting a block)
    pub fn set_best_height(&mut self, height: i32) {
        self.best_height = height;
    }

    /// Process all pending peer events (non-blocking, call from event loop)
    pub async fn process_events(&mut self) {
        // Drain command registrations first (must happen before Ready arrives)
        while let Ok((peer_id, addr, cmd_tx)) = self.cmd_reg_rx.try_recv() {
            self.pending_cmd_txs.insert(peer_id, (addr, cmd_tx));
        }

        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                PeerEvent::Ready { peer_id, addr, best_height, user_agent } => {
                    info!("peer {peer_id} ready: height={best_height} ua={user_agent}");

                    // Retrieve the cmd_tx stored during connect / accept
                    let resolved_addr = if let Some((stored_addr, cmd_tx)) =
                        self.pending_cmd_txs.remove(&peer_id)
                    {
                        // BIP152: request high-bandwidth compact blocks (mode=1)
                        let _ = cmd_tx.send(PeerCommand::Send(
                            NetworkMessage::SendCmpct(true, 1)
                        ));
                        self.peers.insert(
                            peer_id,
                            ConnectedPeer { addr: stored_addr, best_height, cmd_tx },
                        );
                        stored_addr
                    } else {
                        warn!("peer {peer_id} sent Ready but no cmd_tx was registered");
                        addr
                    };

                    let _ = self.node_event_tx.send(NodeEvent::PeerConnected {
                        peer_id,
                        addr: resolved_addr,
                        best_height,
                    });
                }
                PeerEvent::Disconnected { peer_id } => {
                    self.peers.remove(&peer_id);
                    self.pending_cmd_txs.remove(&peer_id);
                    let _ =
                        self.node_event_tx.send(NodeEvent::PeerDisconnected { peer_id });
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
                // Peer prefers headers over inv for new block announcements – noted
            }
            NetworkMessage::FeeFilter(rate) => {
                // Store per-peer fee filter for transaction relay filtering
                debug!("peer {peer_id}: feefilter rate={rate} sat/kvB");
            }
            NetworkMessage::CmpctBlock(cmpct) => {
                let _ = self.node_event_tx.send(NodeEvent::CmpctBlockReceived { peer_id, cmpct });
            }
            NetworkMessage::GetBlockTxn(req) => {
                let _ = self.node_event_tx.send(NodeEvent::GetBlockTxnReceived { peer_id, req });
            }
            NetworkMessage::BlockTxn(resp) => {
                let _ = self.node_event_tx.send(NodeEvent::BlockTxnReceived { peer_id, resp });
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
