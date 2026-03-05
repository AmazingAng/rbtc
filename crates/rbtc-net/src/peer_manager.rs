use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
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
    message::{GetBlocksMessage, HeadersMessage, Inventory, InvType, NetworkMessage},
    peer::{run_peer, PeerCommand, PeerEvent},
};

static NEXT_PEER_ID: AtomicU64 = AtomicU64::new(1);

/// Maximum number of candidate addresses kept in memory.
const MAX_CANDIDATE_ADDRS: usize = 1000;
/// How many peers we forward a `addr` announcement to (trickling).
const ADDR_RELAY_FANOUT: usize = 2;
/// Ban duration for misbehaving peers (24 hours).
pub const BAN_DURATION: Duration = Duration::from_secs(24 * 60 * 60);
/// Misbehavior score threshold that triggers a ban.
const BAN_THRESHOLD: u32 = 100;
/// Maximum timestamp drift (seconds) for addr entries we relay.
const ADDR_MAX_DRIFT_SECS: i64 = 10 * 60;

#[derive(Debug, Clone, Copy)]
pub struct RefillStats {
    pub outbound: usize,
    pub connecting: usize,
    pub candidates: usize,
}

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
    /// Peer announced addresses
    AddrReceived { peer_id: u64, addrs: Vec<(u32, u64, [u8; 16], u16)> },
    /// Request to ban a peer's IP (emitted by misbehave())
    BanPeer { ip: IpAddr },
    /// Peer replied notfound for one or more requested items (e.g. pruned node)
    NotFound { peer_id: u64, items: Vec<Inventory> },
    /// Peer requested our mempool contents (BIP35)
    MempoolRequested { peer_id: u64 },
    /// BIP155: peer sent addrv2 addresses
    Addrv2Received { peer_id: u64, msg: crate::message::Addrv2Message },
}

/// Connected peer metadata
struct ConnectedPeer {
    addr: SocketAddr,
    best_height: i32,
    cmd_tx: mpsc::UnboundedSender<PeerCommand>,
    /// Minimum fee rate (sat/kvB) the peer is willing to relay txs for
    fee_filter: u64,
    /// Accumulated misbehavior score
    misbehavior: u32,
    /// true if this is an inbound connection
    inbound: bool,
    /// BIP339: peer supports wtxid-based tx relay
    wtxid_relay: bool,
    /// BIP155: peer prefers addrv2 messages
    prefers_addrv2: bool,
    /// BIP130: peer prefers headers over inv for new block announcements
    prefers_headers: bool,
}

/// Registration message: associates a peer_id with its command sender channel.
/// Sent by `connect()` / inbound listener before `run_peer` is spawned.
type CmdRegistration = (u64, SocketAddr, mpsc::UnboundedSender<PeerCommand>, bool /* inbound */);

/// Central peer manager – manages connections and dispatches messages
pub struct PeerManager {
    config: PeerManagerConfig,
    peers: HashMap<u64, ConnectedPeer>,
    /// Pending (peer_id → cmd_tx) registrations not yet confirmed by PeerEvent::Ready
    pending_cmd_txs: HashMap<u64, (SocketAddr, mpsc::UnboundedSender<PeerCommand>, bool)>,
    /// Channel for registering new peer cmd senders (outbound + inbound)
    cmd_reg_tx: mpsc::UnboundedSender<CmdRegistration>,
    cmd_reg_rx: mpsc::UnboundedReceiver<CmdRegistration>,
    /// Reports outbound connect attempt failures so we can clear in-progress markers.
    connect_fail_tx: mpsc::UnboundedSender<SocketAddr>,
    connect_fail_rx: mpsc::UnboundedReceiver<SocketAddr>,
    event_tx: mpsc::UnboundedSender<PeerEvent>,
    event_rx: mpsc::UnboundedReceiver<PeerEvent>,
    node_event_tx: mpsc::UnboundedSender<NodeEvent>,
    best_height: i32,
    inbound_count: usize,
    /// Current number of established outbound connections
    outbound_count: usize,
    /// Candidate addresses to connect to (populated from addr messages and peer_store)
    candidate_addrs: VecDeque<SocketAddr>,
    /// Addresses currently being connected to (dedup guard)
    connecting_addrs: HashSet<SocketAddr>,
    /// Addresses of established peers
    connected_addrs: HashSet<SocketAddr>,
    /// IPs that are currently banned
    banned_ips: HashSet<IpAddr>,
    /// When we last attempted outbound reconnect
    last_reconnect: std::time::Instant,
}

impl PeerManager {
    pub fn new(
        config: PeerManagerConfig,
        node_event_tx: mpsc::UnboundedSender<NodeEvent>,
        best_height: i32,
    ) -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (cmd_reg_tx, cmd_reg_rx) = mpsc::unbounded_channel();
        let (connect_fail_tx, connect_fail_rx) = mpsc::unbounded_channel();
        Self {
            config,
            peers: HashMap::new(),
            pending_cmd_txs: HashMap::new(),
            cmd_reg_tx,
            cmd_reg_rx,
            connect_fail_tx,
            connect_fail_rx,
            event_tx,
            event_rx,
            node_event_tx,
            best_height,
            inbound_count: 0,
            outbound_count: 0,
            candidate_addrs: VecDeque::new(),
            connecting_addrs: HashSet::new(),
            connected_addrs: HashSet::new(),
            banned_ips: HashSet::new(),
            last_reconnect: std::time::Instant::now(),
        }
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn refill_stats(&self) -> RefillStats {
        RefillStats {
            outbound: self.outbound_count,
            connecting: self.connecting_addrs.len(),
            candidates: self.candidate_addrs.len(),
        }
    }

    /// Seed the candidate address pool from persistent storage (call at startup).
    pub fn seed_candidate_addrs(&mut self, addrs: impl IntoIterator<Item = SocketAddr>) {
        for addr in addrs {
            if self.candidate_addrs.len() >= MAX_CANDIDATE_ADDRS {
                break;
            }
            if !self.connected_addrs.contains(&addr) && !self.connecting_addrs.contains(&addr) {
                self.candidate_addrs.push_back(addr);
            }
        }
    }

    /// Add a discovered address to the candidate pool.
    pub fn add_candidate_addr(&mut self, addr: SocketAddr) {
        if self.candidate_addrs.len() >= MAX_CANDIDATE_ADDRS {
            self.candidate_addrs.pop_front();
        }
        if !self.connected_addrs.contains(&addr) && !self.connecting_addrs.contains(&addr) {
            self.candidate_addrs.push_back(addr);
        }
    }

    /// Mark an IP as locally banned (e.g. loaded from persistent storage).
    pub fn add_ban(&mut self, ip: IpAddr) {
        self.banned_ips.insert(ip);
    }

    /// Get the fee_filter for a specific peer (sat/kvB).
    pub fn peer_fee_filter(&self, peer_id: u64) -> u64 {
        self.peers.get(&peer_id).map(|p| p.fee_filter).unwrap_or(0)
    }

    /// Drain the current candidate address list (used by the node to persist them).
    pub fn candidate_addrs_snapshot(&self) -> Vec<SocketAddr> {
        self.candidate_addrs.iter().copied().collect()
    }

    /// Increment a peer's misbehavior score by `score`.
    /// If the score reaches BAN_THRESHOLD, disconnect and ban the peer's IP.
    pub fn misbehave(&mut self, peer_id: u64, score: u32) {
        let Some(peer) = self.peers.get_mut(&peer_id) else { return };
        peer.misbehavior = peer.misbehavior.saturating_add(score);
        if peer.misbehavior >= BAN_THRESHOLD {
            let ip = peer.addr.ip();
            warn!("peer {peer_id} ({ip}): misbehavior score {} ≥ {BAN_THRESHOLD}, banning", peer.misbehavior);
            let _ = peer.cmd_tx.send(PeerCommand::Disconnect);
            self.banned_ips.insert(ip);
            let _ = self.node_event_tx.send(NodeEvent::BanPeer { ip });
        }
    }

    /// Connect to a peer by address string
    pub async fn connect(&mut self, addr: &str) {
        let Ok(socket_addr) = addr.parse::<SocketAddr>() else {
            // Try async DNS resolution later; for now skip malformed addresses
            self.connect_raw(addr, None).await;
            return;
        };
        if self.connecting_addrs.contains(&socket_addr)
            || self.connected_addrs.contains(&socket_addr)
        {
            return;
        }
        if self.banned_ips.contains(&socket_addr.ip()) {
            debug!("skipping banned address {socket_addr}");
            return;
        }
        self.connecting_addrs.insert(socket_addr);
        self.connect_raw(addr, Some(socket_addr)).await;
    }

    async fn connect_raw(&self, addr: &str, tracked_addr: Option<SocketAddr>) {
        let peer_id = NEXT_PEER_ID.fetch_add(1, Ordering::Relaxed);
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<PeerCommand>();

        let event_tx = self.event_tx.clone();
        let cmd_reg_tx = self.cmd_reg_tx.clone();
        let connect_fail_tx = self.connect_fail_tx.clone();
        let config = self.config.clone();
        let best_height = self.best_height;
        let addr_str = addr.to_string();

        tokio::spawn(async move {
            let result = tokio::time::timeout(
                config.connect_timeout,
                TcpStream::connect(&addr_str),
            )
            .await;
            let success = matches!(&result, Ok(Ok(_)));

            match result {
                Ok(Ok(stream)) => {
                    let peer_addr = stream.peer_addr().unwrap_or_else(|_| {
                        addr_str
                            .parse()
                            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap())
                    });
                    info!("connected to peer {peer_id} at {peer_addr}");
                    // Register cmd_tx BEFORE spawning run_peer (inbound=false)
                    let _ = cmd_reg_tx.send((peer_id, peer_addr, cmd_tx, false));
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

            if !success {
                if let Some(addr) = tracked_addr {
                    let _ = connect_fail_tx.send(addr);
                }
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
                        // Register BEFORE spawning (inbound=true)
                        let _ = cmd_reg_tx.send((peer_id, peer_addr, cmd_tx, true));
                        tokio::spawn(run_peer(
                            peer_id,
                            peer_addr,
                            stream,
                            config.network,
                            0,
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

    /// Connect to DNS seeds
    pub async fn connect_to_seeds(&mut self) {
        let seeds = self.config.network.dns_seeds();
        let port = self.config.network.default_port();

        for seed in seeds {
            let addr = format!("{seed}:{port}");
            info!("connecting to seed: {addr}");
            self.connect(&addr).await;
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

    /// Broadcast an `inv(tx)` announcement, skipping peers whose fee_filter
    /// exceeds `tx_fee_rate_sat_kvb`.
    pub fn broadcast_tx_inv(&self, inv: NetworkMessage, tx_fee_rate_sat_kvb: u64) {
        for peer in self.peers.values() {
            if peer.fee_filter > tx_fee_rate_sat_kvb {
                continue;
            }
            let _ = peer.cmd_tx.send(PeerCommand::Send(inv.clone()));
        }
    }

    /// BIP130: announce a new block to all peers.
    /// Sends `headers` to peers that signalled `sendheaders`, `inv(block)` to others.
    /// Skips `from_peer` (the peer that sent us the block).
    pub fn broadcast_new_block(&self, header: BlockHeader, hash: BlockHash, from_peer: u64) {
        let inv_msg = NetworkMessage::Inv(vec![Inventory {
            inv_type: InvType::Block,
            hash,
        }]);
        let headers_msg = NetworkMessage::Headers(HeadersMessage {
            headers: vec![header],
        });
        for (&pid, peer) in &self.peers {
            if pid == from_peer {
                continue;
            }
            let msg = if peer.prefers_headers {
                headers_msg.clone()
            } else {
                inv_msg.clone()
            };
            let _ = peer.cmd_tx.send(PeerCommand::Send(msg));
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

    /// Return all peer IDs whose reported best_height is >= `min_height`.
    /// Suitable for distributing IBD block-download segments.
    pub fn peers_for_ibd(&self, min_height: u32) -> Vec<u64> {
        self.peers
            .iter()
            .filter(|(_, p)| p.best_height >= min_height as i32)
            .map(|(&id, _)| id)
            .collect()
    }

    /// Update our current best height (e.g. after connecting a block)
    pub fn set_best_height(&mut self, height: i32) {
        self.best_height = height;
    }

    /// Process all pending peer events (non-blocking, call from event loop)
    pub async fn process_events(&mut self) {
        while let Ok(addr) = self.connect_fail_rx.try_recv() {
            self.connecting_addrs.remove(&addr);
            // Keep failed candidates retryable instead of losing them permanently.
            self.add_candidate_addr(addr);
        }

        // Drain command registrations first (must happen before Ready arrives)
        while let Ok((peer_id, addr, cmd_tx, inbound)) = self.cmd_reg_rx.try_recv() {
            self.pending_cmd_txs.insert(peer_id, (addr, cmd_tx, inbound));
        }

        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                PeerEvent::Ready { peer_id, addr, best_height, user_agent, wtxid_relay, prefers_addrv2 } => {
                    info!("peer {peer_id} ready: height={best_height} ua={user_agent}");

                    // Retrieve the cmd_tx stored during connect / accept
                    let resolved_addr = if let Some((stored_addr, cmd_tx, inbound)) =
                        self.pending_cmd_txs.remove(&peer_id)
                    {
                        // Check ban list for inbound connections
                        if inbound && self.banned_ips.contains(&stored_addr.ip()) {
                            warn!("rejected inbound peer {peer_id}: IP {} is banned", stored_addr.ip());
                            let _ = cmd_tx.send(PeerCommand::Disconnect);
                            continue;
                        }

                        // BIP152: request high-bandwidth compact blocks (mode=1)
                        let _ = cmd_tx.send(PeerCommand::Send(NetworkMessage::SendCmpct(true, 1)));
                        // Ask peer for their known addresses
                        let _ = cmd_tx.send(PeerCommand::Send(NetworkMessage::GetAddr));

                        if inbound {
                            self.inbound_count += 1;
                        } else {
                            self.outbound_count += 1;
                            self.connecting_addrs.remove(&stored_addr);
                            self.connected_addrs.insert(stored_addr);
                        }

                        self.peers.insert(
                            peer_id,
                            ConnectedPeer {
                                addr: stored_addr,
                                best_height,
                                cmd_tx,
                                fee_filter: 0,
                                misbehavior: 0,
                                inbound,
                                wtxid_relay,
                                prefers_addrv2,
                                prefers_headers: false,
                            },
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
                    if let Some(peer) = self.peers.remove(&peer_id) {
                        if peer.inbound {
                            self.inbound_count = self.inbound_count.saturating_sub(1);
                        } else {
                            self.outbound_count = self.outbound_count.saturating_sub(1);
                            self.connected_addrs.remove(&peer.addr);
                        }
                    }
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

        // ── Connection manager: attempt to fill outbound slots ────────────────
        let now = std::time::Instant::now();
        let in_progress_outbound = self.outbound_count + self.connecting_addrs.len();
        if now.duration_since(self.last_reconnect) >= Duration::from_secs(30)
            && in_progress_outbound < self.config.max_outbound
        {
            debug!(
                "conn-mgr: refill tick outbound={} connecting={} connected={} candidates={} max_outbound={}",
                self.outbound_count,
                self.connecting_addrs.len(),
                self.connected_addrs.len(),
                self.candidate_addrs.len(),
                self.config.max_outbound
            );
            self.last_reconnect = now;
            while self.outbound_count + self.connecting_addrs.len() < self.config.max_outbound {
                let Some(candidate) = self.candidate_addrs.pop_front() else { break };
                if self.connecting_addrs.contains(&candidate)
                    || self.connected_addrs.contains(&candidate)
                    || self.banned_ips.contains(&candidate.ip())
                {
                    continue;
                }
                info!("conn-mgr: connecting to candidate {candidate}");
                let addr_str = candidate.to_string();
                self.connecting_addrs.insert(candidate);
                self.connect_raw(&addr_str, Some(candidate)).await;
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
                // BIP130: peer prefers headers over inv for new block announcements
                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    peer.prefers_headers = true;
                }
            }
            NetworkMessage::FeeFilter(rate) => {
                // Store the fee filter so we can skip this peer when relaying cheap txs
                debug!("peer {peer_id}: feefilter rate={rate} sat/kvB");
                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    peer.fee_filter = rate;
                }
            }
            NetworkMessage::Addr(msg) => {
                self.handle_addr(peer_id, msg.addrs).await;
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
            NetworkMessage::NotFound(items) => {
                let _ = self.node_event_tx.send(NodeEvent::NotFound { peer_id, items });
            }
            NetworkMessage::WtxidRelay => {
                debug!("peer {peer_id}: supports wtxid relay (BIP339)");
                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    peer.wtxid_relay = true;
                }
            }
            NetworkMessage::SendAddrv2 => {
                debug!("peer {peer_id}: prefers addrv2 (BIP155)");
                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    peer.prefers_addrv2 = true;
                }
            }
            NetworkMessage::Addrv2(msg) => {
                self.handle_addrv2(peer_id, msg).await;
            }
            NetworkMessage::Mempool => {
                debug!("peer {peer_id}: requested mempool contents");
                // The node layer should respond by sending inv messages for
                // all txids in the mempool. Emit as a node event.
                let _ = self.node_event_tx.send(NodeEvent::MempoolRequested { peer_id });
            }
            other => {
                debug!("peer {peer_id}: unhandled message: {}", other.command());
            }
        }
    }

    async fn handle_addr(&mut self, peer_id: u64, entries: Vec<(u32, u64, [u8; 16], u16)>) {
        let now_secs = unix_now() as i64;
        let mut valid: Vec<SocketAddr> = Vec::new();

        for (timestamp, _services, ip_bytes, port) in &entries {
            let ts = *timestamp as i64;
            // Only relay addresses whose timestamps are within ADDR_MAX_DRIFT_SECS of now
            if (ts - now_secs).abs() > ADDR_MAX_DRIFT_SECS {
                continue;
            }
            let ip = ip_bytes_to_ip(*ip_bytes);
            let addr = SocketAddr::new(ip, *port);
            if !self.banned_ips.contains(&ip) {
                self.add_candidate_addr(addr);
                valid.push(addr);
            }
        }

        if valid.is_empty() {
            return;
        }

        // Emit to the node for persistence
        let _ = self.node_event_tx.send(NodeEvent::AddrReceived {
            peer_id,
            addrs: entries,
        });

        // Trickling: forward to a random subset of peers (excluding sender)
        let relay_targets: Vec<u64> = self.peers.keys()
            .filter(|&&id| id != peer_id)
            .copied()
            .take(ADDR_RELAY_FANOUT)
            .collect();

        // Build the addr message with only the valid entries
        // We forward up to 10 valid entries per relay message.
        let relay_addrs: Vec<SocketAddr> = valid.into_iter().take(10).collect();
        let relay_entries: Vec<(u32, u64, [u8; 16], u16)> = relay_addrs.iter()
            .map(|addr| {
                let ip_bytes = socket_addr_to_ip_bytes(addr);
                let ts = now_secs as u32;
                (ts, 1u64, ip_bytes, addr.port())
            })
            .collect();

        let relay_msg = NetworkMessage::Addr(crate::message::AddrMessage { addrs: relay_entries });
        for target in relay_targets {
            self.send_to(target, relay_msg.clone());
        }
    }

    /// Handle BIP155 addrv2 messages. Convert IPv4/IPv6 entries to SocketAddr
    /// and add them to the candidate pool, similar to handle_addr.
    async fn handle_addrv2(&mut self, peer_id: u64, msg: crate::message::Addrv2Message) {
        use crate::message::Addrv2NetId;
        let now_secs = unix_now() as i64;

        for entry in &msg.addrs {
            let ts = entry.timestamp as i64;
            if (ts - now_secs).abs() > ADDR_MAX_DRIFT_SECS {
                continue;
            }
            // Only process IPv4 and IPv6 for now (Tor/I2P/CJDNS require special handling)
            let ip: IpAddr = match Addrv2NetId::from_u8(entry.net_id) {
                Some(Addrv2NetId::Ipv4) if entry.addr.len() == 4 => {
                    let octets: [u8; 4] = entry.addr[..4].try_into().unwrap();
                    IpAddr::V4(std::net::Ipv4Addr::from(octets))
                }
                Some(Addrv2NetId::Ipv6) if entry.addr.len() == 16 => {
                    let octets: [u8; 16] = entry.addr[..16].try_into().unwrap();
                    IpAddr::V6(std::net::Ipv6Addr::from(octets))
                }
                _ => continue, // Skip Tor/I2P/CJDNS/unknown
            };
            let addr = SocketAddr::new(ip, entry.port);
            if !self.banned_ips.contains(&ip) {
                self.add_candidate_addr(addr);
            }
        }

        // Emit raw addrv2 data to node for persistence
        let _ = self.node_event_tx.send(NodeEvent::Addrv2Received { peer_id, msg });
    }

    /// Check if a peer supports wtxid relay (BIP339).
    pub fn peer_wtxid_relay(&self, peer_id: u64) -> bool {
        self.peers.get(&peer_id).map(|p| p.wtxid_relay).unwrap_or(false)
    }

    /// Main event loop – call this in a tokio task
    pub async fn run(mut self) {
        loop {
            self.process_events().await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn ip_bytes_to_ip(bytes: [u8; 16]) -> IpAddr {
    use std::net::Ipv6Addr;
    let v6 = Ipv6Addr::from(bytes);
    if let Some(v4) = v6.to_ipv4_mapped() {
        IpAddr::V4(v4)
    } else if let Some(v4) = v6.to_ipv4() {
        IpAddr::V4(v4)
    } else {
        IpAddr::V6(v6)
    }
}

fn socket_addr_to_ip_bytes(addr: &SocketAddr) -> [u8; 16] {
    match addr.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}
