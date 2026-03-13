use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use rbtc_primitives::hash::Txid;

use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tracing::{debug, info, warn};

use rbtc_primitives::{
    block::{Block, BlockHeader},
    hash::{BlockHash, Hash256},
    network::Network,
    transaction::Transaction,
};

use crate::{
    message::{GetBlocksMessage, HeadersMessage, InvType, Inventory, NetworkMessage},
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

/// Maximum number of inv items per tx announcement message, matching
/// Bitcoin Core's MAX_PEER_TX_ANNOUNCEMENTS.
pub const TX_ANNOUNCEMENT_BATCH_SIZE: usize = 35;

/// Maximum number of block-relay-only outbound connections.
/// Matches Bitcoin Core's MAX_BLOCK_RELAY_ONLY_CONNECTIONS.
pub const MAX_BLOCK_RELAY_ONLY_CONNECTIONS: usize = 2;

/// Maximum number of headers a peer may send in a single `headers` message
/// (Bitcoin Core `MAX_HEADERS_RESULTS` in net_processing.h).
pub const MAX_HEADERS_RESULTS: usize = 2000;

/// Inactivity timeout: disconnect peers with no received messages for this
/// duration.  Matches Bitcoin Core's `TIMEOUT_INTERVAL` (20 minutes).
pub const TIMEOUT_INTERVAL: Duration = Duration::from_secs(20 * 60);

/// Interval between address relay flushes (seconds).
/// Bitcoin Core uses Poisson with ~30 s mean; we use a simple periodic flush.
const ADDR_RELAY_FLUSH_INTERVAL: Duration = Duration::from_secs(30);

/// Maximum number of addresses buffered in a single peer's addr relay queue.
const MAX_ADDR_RELAY_QUEUE: usize = 1000;

/// Number of longest-connected inbound peers protected from eviction.
/// Bitcoin Core protects 8 longest-lived peers (EraseLastKElements).
const EVICTION_PROTECT_LONGEST: usize = 8;

/// Candidate for peer eviction, used by `select_peer_to_evict`.
#[derive(Debug, Clone)]
pub struct EvictionCandidate {
    pub peer_id: u64,
    pub addr: SocketAddr,
    pub connected_time: Instant,
    pub is_protected: bool,
}

/// Pending transaction announcement for relay batching.
#[derive(Debug, Clone)]
pub struct TxAnnouncement {
    pub txid: Hash256,
    pub wtxid: Hash256,
}

/// Per-peer transaction relay state (M16).
///
/// Tracks whether the peer participates in tx relay, what txids it already
/// knows about, and its minimum acceptable fee rate.
#[derive(Debug, Clone)]
pub struct TxRelayState {
    /// Peer has opted in to transaction relay (false after `fRelay=0` in version).
    pub relay_txes: bool,
    /// BIP339: peer supports wtxid-based tx relay.
    pub wtxid_relay: bool,
    /// Minimum fee rate (sat/kvB) the peer will accept.
    pub fee_filter: u64,
    /// Transaction IDs already sent to (or received from) this peer, used to
    /// avoid re-announcing.
    pub known_txids: HashSet<Txid>,
}

impl Default for TxRelayState {
    fn default() -> Self {
        Self {
            relay_txes: true,
            wtxid_relay: false,
            fee_filter: 0,
            known_txids: HashSet::new(),
        }
    }
}

/// Per-peer chain sync state machine (M19).
///
/// Used to detect stalling peers during header download / IBD.
#[derive(Debug, Clone)]
pub struct ChainSyncState {
    /// When we last received a block from this peer.
    pub last_block_time: Instant,
    /// The tip of the header chain this peer is working towards.
    pub work_header_tip: Option<BlockHash>,
    /// Deadline by which the peer must make progress, or we disconnect.
    pub timeout: Option<Instant>,
}

impl ChainSyncState {
    pub fn new() -> Self {
        Self {
            last_block_time: Instant::now(),
            work_header_tip: None,
            timeout: None,
        }
    }

    /// Returns `true` if the peer has exceeded its sync timeout.
    pub fn is_timed_out(&self) -> bool {
        self.timeout.map_or(false, |t| Instant::now() > t)
    }
}

/// Broad network type classification for inbound connection limits (M23).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkType {
    IPv4,
    IPv6,
    Tor,
    Other,
}

impl NetworkType {
    /// Classify a socket address into a network type.
    pub fn from_addr(addr: &SocketAddr) -> Self {
        match addr.ip() {
            IpAddr::V4(_) => NetworkType::IPv4,
            IpAddr::V6(v6) => {
                let octets = v6.octets();
                // Detect IPv4-mapped IPv6 (::ffff:x.x.x.x)
                if octets[..10] == [0; 10] && octets[10] == 0xff && octets[11] == 0xff {
                    NetworkType::IPv4
                } else if octets[..6] == [0xFD, 0x87, 0xD8, 0x7E, 0xEB, 0x43] {
                    // OnionCat prefix used by Tor v2/v3 addresses
                    NetworkType::Tor
                } else {
                    NetworkType::IPv6
                }
            }
        }
    }
}

/// Bitcoin Core-style connection type distinctions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionType {
    /// Default outbound connection: relays blocks, transactions, and addresses.
    OutboundFullRelay,
    /// Only relays blocks; does not participate in tx or addr relay.
    BlockRelayOnly,
    /// Short-lived connection used to test whether an address is reachable.
    Feeler,
    /// Connect, request addresses, then disconnect.
    AddrFetch,
    /// Manually added peer (via `-addnode` or RPC). Not subject to automatic
    /// eviction or disconnect timeouts.
    Manual,
    /// Peer connected to us.
    Inbound,
    /// Short-lived connection opened to a privacy network (Tor, I2P) solely
    /// for broadcasting a transaction.  No addr or block relay; disconnected
    /// after the tx is sent and acknowledged.  (Bitcoin Core v28+)
    PrivateBroadcast,
}

impl ConnectionType {
    /// Returns `true` if this is an inbound connection.
    pub fn is_inbound(&self) -> bool {
        matches!(self, ConnectionType::Inbound)
    }

    /// Returns `true` if this is any outbound connection type
    /// (OutboundFullRelay, BlockRelayOnly, Feeler, AddrFetch, or Manual).
    pub fn is_outbound(&self) -> bool {
        !self.is_inbound()
    }

    /// Returns `true` if this is a block-relay-only connection.
    pub fn is_block_relay_only(&self) -> bool {
        matches!(self, ConnectionType::BlockRelayOnly)
    }

    /// Returns `true` if this is a manually added peer.
    pub fn is_manual(&self) -> bool {
        matches!(self, ConnectionType::Manual)
    }

    /// Returns `true` if this is a private-broadcast connection (short-lived,
    /// privacy-network-only, for relaying our own transactions).
    pub fn is_private_broadcast(&self) -> bool {
        matches!(self, ConnectionType::PrivateBroadcast)
    }

    /// Returns `true` for short-lived connection types that should be
    /// disconnected quickly after their purpose is served (Feeler, AddrFetch,
    /// PrivateBroadcast).
    pub fn is_short_lived(&self) -> bool {
        matches!(
            self,
            ConnectionType::Feeler | ConnectionType::AddrFetch | ConnectionType::PrivateBroadcast
        )
    }

    /// Returns `true` if this connection type participates in addr relay.
    /// PrivateBroadcast and BlockRelayOnly connections do NOT relay addresses.
    pub fn relays_addrs(&self) -> bool {
        !matches!(
            self,
            ConnectionType::BlockRelayOnly | ConnectionType::PrivateBroadcast
        )
    }

    /// Returns `true` if this connection type participates in tx relay.
    /// BlockRelayOnly connections do NOT relay transactions.
    /// PrivateBroadcast connections DO relay transactions (that is their purpose).
    pub fn relays_txs(&self) -> bool {
        !matches!(self, ConnectionType::BlockRelayOnly)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RefillStats {
    pub outbound: usize,
    pub connecting: usize,
    pub candidates: usize,
}

/// Summary information about a connected peer (for `getpeerinfo` RPC).
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub id: u64,
    pub addr: String,
    pub inbound: bool,
    pub startingheight: i32,
    pub conn_type: String,
    /// When this peer connected (for eviction scoring).
    pub connected_time: Instant,
}

/// Detailed per-peer connection statistics, matching Bitcoin Core's CNodeStats.
///
/// Returned by `PeerManager::peer_stats()` for RPC and monitoring.
#[derive(Debug, Clone)]
pub struct PeerStats {
    /// Peer ID.
    pub id: u64,
    /// Peer socket address string.
    pub addr: String,
    /// Advertised service flags.
    pub services: u64,
    /// Unix timestamp of last message sent to this peer.
    pub last_send: u64,
    /// Unix timestamp of last message received from this peer.
    pub last_recv: u64,
    /// Total bytes sent to this peer (placeholder — not tracked yet).
    pub bytes_sent: u64,
    /// Total bytes received from this peer (placeholder — not tracked yet).
    pub bytes_recv: u64,
    /// Unix timestamp when this connection was established.
    pub conn_time: u64,
    /// Last measured ping round-trip time in seconds.
    pub ping_time: f64,
    /// Peer's protocol version.
    pub version: i32,
    /// Peer's user agent / subversion string.
    pub subver: String,
    /// Whether this is an inbound connection.
    pub inbound: bool,
    /// Peer's best known block height at connection time.
    pub startingheight: i32,
    /// Connection type (human-readable).
    pub conn_type: String,
    /// Accumulated misbehavior score (M18).
    pub misbehavior: u32,
}

/// Configuration for the peer manager
#[derive(Debug, Clone)]
pub struct PeerManagerConfig {
    pub network: Network,
    /// Total maximum outbound connections (full-relay + block-relay-only).
    pub max_outbound: usize,
    /// Maximum full-relay outbound connections (tx + block + addr relay).
    pub max_outbound_full_relay: usize,
    /// Maximum block-relay-only outbound connections.
    pub max_block_relay_only: usize,
    pub max_inbound: usize,
    pub connect_timeout: Duration,
    /// Port to listen for inbound connections (0 = disabled)
    pub listen_port: u16,
    /// Per-network-type inbound connection limits (M23).
    /// `None` means no per-type limit (only the global `max_inbound` applies).
    pub max_inbound_per_network: Option<HashMap<NetworkType, usize>>,
}

impl Default for PeerManagerConfig {
    fn default() -> Self {
        Self {
            network: Network::Mainnet,
            max_outbound: 11,
            max_outbound_full_relay: 8,
            max_block_relay_only: 2,
            max_inbound: 125,
            connect_timeout: Duration::from_secs(10),
            listen_port: 0,
            max_inbound_per_network: None,
        }
    }
}

/// Events emitted by the peer manager to the node
#[derive(Debug)]
pub enum NodeEvent {
    PeerConnected {
        peer_id: u64,
        addr: SocketAddr,
        best_height: i32,
    },
    PeerDisconnected {
        peer_id: u64,
    },
    BlockReceived {
        peer_id: u64,
        block: Block,
    },
    HeadersReceived {
        peer_id: u64,
        headers: Vec<BlockHeader>,
    },
    TxReceived {
        peer_id: u64,
        tx: Transaction,
    },
    InvReceived {
        peer_id: u64,
        items: Vec<Inventory>,
    },
    /// BIP152: compact block received
    CmpctBlockReceived {
        peer_id: u64,
        cmpct: crate::compact::CompactBlock,
    },
    /// BIP152: peer is requesting missing transactions
    GetBlockTxnReceived {
        peer_id: u64,
        req: crate::compact::GetBlockTxn,
    },
    /// BIP152: peer responded with missing transactions
    BlockTxnReceived {
        peer_id: u64,
        resp: crate::compact::BlockTxn,
    },
    /// Peer announced addresses
    AddrReceived {
        peer_id: u64,
        addrs: Vec<(u32, u64, [u8; 16], u16)>,
    },
    /// Request to ban a peer's IP (emitted by misbehave())
    BanPeer {
        ip: IpAddr,
    },
    /// Peer replied notfound for one or more requested items (e.g. pruned node)
    NotFound {
        peer_id: u64,
        items: Vec<Inventory>,
    },
    /// Peer requested our mempool contents (BIP35)
    MempoolRequested {
        peer_id: u64,
    },
    /// BIP155: peer sent addrv2 addresses
    Addrv2Received {
        peer_id: u64,
        msg: crate::message::Addrv2Message,
    },
}

/// Connected peer metadata
struct ConnectedPeer {
    addr: SocketAddr,
    best_height: i32,
    cmd_tx: mpsc::UnboundedSender<PeerCommand>,
    /// Minimum fee rate (sat/kvB) the peer is willing to relay txs for
    fee_filter: u64,
    /// Accumulated misbehavior score (M18)
    misbehavior: u32,
    /// Connection type (inbound, outbound full relay, block-relay-only, etc.)
    conn_type: ConnectionType,
    /// BIP339: peer supports wtxid-based tx relay
    wtxid_relay: bool,
    /// BIP155: peer prefers addrv2 messages
    prefers_addrv2: bool,
    /// BIP130: peer prefers headers over inv for new block announcements
    prefers_headers: bool,
    /// BIP152: compact block mode the peer wants us to use.
    /// 0 = not negotiated, 1 = high-bandwidth (push cmpctblock), 2 = low-bandwidth (inv first)
    compact_block_mode: u8,
    /// BIP152: compact block version the peer supports (1 or 2).
    compact_block_version: u64,
    /// When this peer was added to the peers map (for eviction protection).
    connected_time: Instant,
    /// Per-peer transaction relay state (M16).
    tx_relay: TxRelayState,
    /// Per-peer chain sync state machine (M19).
    chain_sync: ChainSyncState,
    /// Last time we received any message from this peer (M22).
    last_recv_time: Instant,
    /// Buffered address relay queue (M24).
    addr_relay_queue: VecDeque<(u32, u64, [u8; 16], u16)>,
    /// When we last flushed this peer's addr relay queue.
    last_addr_flush: Instant,
    /// Peer's user agent string (from version message).
    user_agent: String,
    /// Peer's advertised service flags (from version message).
    services: u64,
}

/// Registration message: associates a peer_id with its command sender channel.
/// Sent by `connect()` / inbound listener before `run_peer` is spawned.
type CmdRegistration = (
    u64,
    SocketAddr,
    mpsc::UnboundedSender<PeerCommand>,
    ConnectionType,
);

/// Central peer manager – manages connections and dispatches messages
pub struct PeerManager {
    config: PeerManagerConfig,
    peers: HashMap<u64, ConnectedPeer>,
    /// Pending (peer_id → cmd_tx) registrations not yet confirmed by PeerEvent::Ready
    pending_cmd_txs: HashMap<u64, (SocketAddr, mpsc::UnboundedSender<PeerCommand>, ConnectionType)>,
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
    /// Outbound full-relay connections (tx + block + addr relay).
    outbound_full_relay_count: usize,
    /// Outbound block-relay-only connections.
    block_relay_only_count: usize,
    /// Address manager with new/tried bucketing and Sybil resistance.
    addrman: crate::addrman::AddrMan,
    /// Addresses currently being connected to (dedup guard)
    connecting_addrs: HashSet<SocketAddr>,
    /// Addresses of established peers
    connected_addrs: HashSet<SocketAddr>,
    /// IPs that are currently banned
    banned_ips: HashSet<IpAddr>,
    /// IP whitelist and associated permissions.
    whitelist: crate::permissions::Whitelist,
    /// Anchor addresses (block-relay-only peers persisted across restarts).
    anchor_addrs: Vec<SocketAddr>,
    /// When we last attempted outbound reconnect
    last_reconnect: std::time::Instant,
    /// Pending transaction announcements queued for batched relay.
    pending_tx_announcements: Vec<TxAnnouncement>,
    /// Median peer clock offset tracker (outbound peers only).
    time_offsets: crate::timeoffsets::TimeOffsets,
    /// Inbound connection count per network type (M23).
    inbound_per_network: HashMap<NetworkType, usize>,
    /// When we last initiated a feeler connection.
    last_feeler: Instant,
    /// Whether we have already tried connecting to anchor peers this session.
    anchors_tried: bool,
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
            outbound_full_relay_count: 0,
            block_relay_only_count: 0,
            addrman: crate::addrman::AddrMan::new_random(),
            connecting_addrs: HashSet::new(),
            connected_addrs: HashSet::new(),
            banned_ips: HashSet::new(),
            whitelist: crate::permissions::Whitelist::new(),
            anchor_addrs: Vec::new(),
            last_reconnect: std::time::Instant::now(),
            pending_tx_announcements: Vec::new(),
            time_offsets: crate::timeoffsets::TimeOffsets::new(),
            inbound_per_network: HashMap::new(),
            last_feeler: Instant::now(),
            anchors_tried: false,
        }
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Return summary information for every connected peer
    /// (used by the `getpeerinfo` RPC).
    pub fn peer_info(&self) -> Vec<PeerInfo> {
        self.peers
            .iter()
            .map(|(id, p)| PeerInfo {
                id: *id,
                addr: p.addr.to_string(),
                inbound: matches!(p.conn_type, ConnectionType::Inbound),
                startingheight: p.best_height,
                conn_type: format!("{:?}", p.conn_type),
                connected_time: p.connected_time,
            })
            .collect()
    }

    /// Return detailed per-peer statistics matching Bitcoin Core's CNodeStats.
    pub fn peer_stats(&self) -> Vec<PeerStats> {
        let boot = Instant::now();
        let unix_now = unix_now();
        self.peers
            .iter()
            .map(|(id, p)| {
                // Approximate unix timestamps from Instant offsets.
                let age_secs = boot.duration_since(p.connected_time).as_secs();
                let conn_time_unix = unix_now.saturating_sub(age_secs);
                let recv_age = boot.duration_since(p.last_recv_time).as_secs();
                let last_recv_unix = unix_now.saturating_sub(recv_age);
                PeerStats {
                    id: *id,
                    addr: p.addr.to_string(),
                    services: p.services,
                    last_send: 0, // not tracked at this layer yet
                    last_recv: last_recv_unix,
                    bytes_sent: 0,
                    bytes_recv: 0,
                    conn_time: conn_time_unix,
                    ping_time: 0.0, // TODO: wire through from peer.rs ping tracking
                    version: 0,     // peer version not stored; future: pass through Ready
                    subver: p.user_agent.clone(),
                    inbound: p.conn_type.is_inbound(),
                    startingheight: p.best_height,
                    conn_type: format!("{:?}", p.conn_type),
                    misbehavior: p.misbehavior,
                }
            })
            .collect()
    }

    /// Alias for `peer_stats()` — returns per-peer CNodeStats-equivalent data.
    pub fn get_peer_stats(&self) -> Vec<PeerStats> {
        self.peer_stats()
    }

    /// Return IDs of all outbound (full-relay) peers.
    pub fn outbound_full_relay_peers(&self) -> Vec<u64> {
        self.peers
            .iter()
            .filter(|(_, p)| p.conn_type == ConnectionType::OutboundFullRelay)
            .map(|(&id, _)| id)
            .collect()
    }

    /// Target number of outbound full-relay connections.
    pub fn max_outbound_full_relay(&self) -> usize {
        self.config.max_outbound_full_relay
    }

    /// Median clock offset (seconds) from outbound peers.
    pub fn median_time_offset(&self) -> i64 {
        self.time_offsets.median()
    }

    pub fn refill_stats(&self) -> RefillStats {
        RefillStats {
            outbound: self.outbound_count,
            connecting: self.connecting_addrs.len(),
            candidates: self.addrman.len(),
        }
    }

    /// Seed the address manager from persistent storage (call at startup).
    pub fn seed_candidate_addrs(&mut self, addrs: impl IntoIterator<Item = SocketAddr>) {
        let dummy_source = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            0,
        );
        let now = crate::addrman::now_unix();
        for addr in addrs {
            self.addrman.add(addr, dummy_source, 0, now);
        }
    }

    /// Seed from AddrInfo entries (preserves full metadata).
    pub fn seed_addrman(&mut self, entries: Vec<crate::addrman::AddrInfo>) {
        self.addrman.load(entries);
    }

    /// Initialize addrman with a specific secret key (from persistent storage).
    pub fn set_addrman_key(&mut self, key: [u8; 32]) {
        let old = std::mem::replace(&mut self.addrman, crate::addrman::AddrMan::new(key));
        // Reload entries from the old addrman (which was randomly keyed)
        let entries: Vec<_> = old.entries().into_iter().cloned().collect();
        if !entries.is_empty() {
            self.addrman.load(entries);
        }
    }

    /// Get a reference to the address manager.
    pub fn addrman(&self) -> &crate::addrman::AddrMan {
        &self.addrman
    }

    /// Add a discovered address to the address manager.
    pub fn add_candidate_addr(&mut self, addr: SocketAddr) {
        self.add_candidate_addr_with_source(addr, addr);
    }

    /// Add a discovered address with explicit source peer.
    pub fn add_candidate_addr_with_source(&mut self, addr: SocketAddr, source: SocketAddr) {
        let now = crate::addrman::now_unix();
        self.addrman.add(addr, source, 0, now);
    }

    /// Mark an IP as locally banned (e.g. loaded from persistent storage).
    pub fn add_ban(&mut self, ip: IpAddr) {
        self.banned_ips.insert(ip);
    }

    /// Remove a specific IP from the ban list.
    pub fn remove_ban(&mut self, ip: &IpAddr) -> bool {
        self.banned_ips.remove(ip)
    }

    /// Clear all banned IPs.
    pub fn clear_bans(&mut self) {
        self.banned_ips.clear();
    }

    /// Return the list of all currently banned IPs.
    pub fn banned_list(&self) -> Vec<IpAddr> {
        self.banned_ips.iter().copied().collect()
    }

    /// Get a mutable reference to the IP whitelist.
    pub fn whitelist_mut(&mut self) -> &mut crate::permissions::Whitelist {
        &mut self.whitelist
    }

    /// Get a reference to the IP whitelist.
    pub fn whitelist(&self) -> &crate::permissions::Whitelist {
        &self.whitelist
    }

    /// Check if a peer IP is whitelisted (and thus immune to bans/eviction).
    pub fn is_whitelisted(&self, ip: &IpAddr) -> bool {
        self.whitelist.is_whitelisted(ip)
    }

    /// Load anchor addresses from persistent storage.
    pub fn load_anchors(&mut self, addrs: Vec<SocketAddr>) {
        self.anchor_addrs = addrs;
    }

    /// Save current block-relay-only peers as anchors for next startup.
    pub fn save_anchors(&self) -> Vec<SocketAddr> {
        self.peers
            .values()
            .filter(|p| p.conn_type == ConnectionType::BlockRelayOnly)
            .take(crate::anchors::MAX_ANCHORS)
            .map(|p| p.addr)
            .collect()
    }

    /// Get anchor addresses (for prioritized connection on startup).
    pub fn anchor_addrs(&self) -> &[SocketAddr] {
        &self.anchor_addrs
    }

    /// Get the fee_filter for a specific peer (sat/kvB).
    pub fn peer_fee_filter(&self, peer_id: u64) -> u64 {
        self.peers.get(&peer_id).map(|p| p.fee_filter).unwrap_or(0)
    }

    /// Snapshot current addresses (used by the node to persist them).
    pub fn candidate_addrs_snapshot(&self) -> Vec<SocketAddr> {
        self.addrman.entries().iter().map(|info| info.addr).collect()
    }

    /// Mark an address as successfully connected.
    pub fn addrman_good(&mut self, addr: &SocketAddr) {
        let now = crate::addrman::now_unix();
        self.addrman.good(addr, now);
    }

    /// Increment a peer's misbehavior score by `score`.
    /// If the score reaches BAN_THRESHOLD, disconnect and ban the peer's IP.
    /// Whitelisted peers with the `NO_BAN` permission are never banned.
    pub fn misbehave(&mut self, peer_id: u64, score: u32, reason: &str) {
        let Some(peer) = self.peers.get_mut(&peer_id) else {
            return;
        };
        peer.misbehavior = peer.misbehavior.saturating_add(score);
        debug!(
            "peer {peer_id}: misbehavior +{score} (now {}) reason: {reason}",
            peer.misbehavior
        );
        if peer.misbehavior >= BAN_THRESHOLD {
            let ip = peer.addr.ip();
            // Skip ban for whitelisted peers with NO_BAN permission
            let perms = self.whitelist.permissions_for(&ip);
            if perms.has(crate::permissions::NetPermissions::NO_BAN) {
                debug!(
                    "peer {peer_id} ({ip}): misbehavior score {} >= {BAN_THRESHOLD}, but whitelisted (NO_BAN)",
                    peer.misbehavior
                );
                return;
            }
            warn!(
                "peer {peer_id} ({ip}): misbehavior score {} >= {BAN_THRESHOLD}, banning (reason: {reason})",
                peer.misbehavior
            );
            let _ = peer.cmd_tx.send(PeerCommand::Disconnect);
            self.banned_ips.insert(ip);
            let _ = self.node_event_tx.send(NodeEvent::BanPeer { ip });
        }
    }

    /// Connect to a peer by address string (user-initiated, full-relay).
    pub async fn connect(&mut self, addr: &str) {
        let Ok(socket_addr) = addr.parse::<SocketAddr>() else {
            self.connect_raw_typed(addr, None, ConnectionType::OutboundFullRelay).await;
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
        self.connect_raw_typed(addr, Some(socket_addr), ConnectionType::OutboundFullRelay).await;
    }

    /// Determine which outbound connection type to fill next.
    fn next_outbound_type(&self) -> Option<ConnectionType> {
        if self.outbound_full_relay_count < self.config.max_outbound_full_relay {
            Some(ConnectionType::OutboundFullRelay)
        } else if self.block_relay_only_count < self.config.max_block_relay_only {
            Some(ConnectionType::BlockRelayOnly)
        } else {
            None
        }
    }

    async fn connect_raw_typed(&self, addr: &str, tracked_addr: Option<SocketAddr>, conn_type: ConnectionType) {
        let peer_id = NEXT_PEER_ID.fetch_add(1, Ordering::Relaxed);
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<PeerCommand>();

        let event_tx = self.event_tx.clone();
        let cmd_reg_tx = self.cmd_reg_tx.clone();
        let connect_fail_tx = self.connect_fail_tx.clone();
        let config = self.config.clone();
        let best_height = self.best_height;
        let addr_str = addr.to_string();

        tokio::spawn(async move {
            let result =
                tokio::time::timeout(config.connect_timeout, TcpStream::connect(&addr_str)).await;
            let success = matches!(&result, Ok(Ok(_)));

            match result {
                Ok(Ok(stream)) => {
                    let peer_addr = stream.peer_addr().unwrap_or_else(|_| {
                        addr_str
                            .parse()
                            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap())
                    });
                    info!("connected to peer {peer_id} at {peer_addr} (type={conn_type:?})");
                    // Register cmd_tx BEFORE spawning run_peer
                    let _ = cmd_reg_tx.send((peer_id, peer_addr, cmd_tx, conn_type));
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
                        // Register BEFORE spawning (inbound)
                        let _ = cmd_reg_tx.send((peer_id, peer_addr, cmd_tx, ConnectionType::Inbound));
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
            // Only relay txs to connection types that participate in tx relay.
            if !peer.conn_type.relays_txs() {
                continue;
            }
            // Respect fRelay=0 from version message (BIP37).
            if !peer.tx_relay.relay_txes {
                continue;
            }
            if peer.fee_filter > tx_fee_rate_sat_kvb {
                continue;
            }
            let _ = peer.cmd_tx.send(PeerCommand::Send(inv.clone()));
        }
    }

    /// Queue a transaction announcement for batched relay.
    ///
    /// Announcements are buffered and sent in batch by `flush_tx_announcements()`,
    /// which is called at the end of each `process_events()` cycle.
    pub fn queue_tx_announcement(&mut self, ann: TxAnnouncement) {
        self.pending_tx_announcements.push(ann);
    }

    /// Flush pending transaction announcements to all eligible peers.
    ///
    /// For each peer:
    /// - Peers that support wtxid relay (BIP339) receive `inv(WitnessTx, wtxid)`
    /// - Other peers receive `inv(Tx, txid)`
    /// - Block-relay-only peers are skipped
    ///
    /// Announcements are sent in batches of up to `TX_ANNOUNCEMENT_BATCH_SIZE`.
    pub fn flush_tx_announcements(&mut self) {
        if self.pending_tx_announcements.is_empty() {
            return;
        }

        for peer in self.peers.values() {
            if !peer.conn_type.relays_txs() {
                continue;
            }
            // Respect fRelay=0 from version message (BIP37).
            if !peer.tx_relay.relay_txes {
                continue;
            }

            // Build inv items for this peer, choosing the right hash type.
            let items: Vec<Inventory> = self
                .pending_tx_announcements
                .iter()
                .map(|ann| {
                    if peer.wtxid_relay {
                        Inventory {
                            inv_type: InvType::WitnessTx,
                            hash: ann.wtxid,
                        }
                    } else {
                        Inventory {
                            inv_type: InvType::Tx,
                            hash: ann.txid,
                        }
                    }
                })
                .collect();

            // Send in batches of TX_ANNOUNCEMENT_BATCH_SIZE.
            for chunk in items.chunks(TX_ANNOUNCEMENT_BATCH_SIZE) {
                let _ = peer
                    .cmd_tx
                    .send(PeerCommand::Send(NetworkMessage::Inv(chunk.to_vec())));
            }
        }

        self.pending_tx_announcements.clear();
    }

    /// M24: flush per-peer addr relay queues.
    ///
    /// For each peer whose queue is non-empty and whose last flush was at least
    /// `ADDR_RELAY_FLUSH_INTERVAL` ago, send a batched `addr` message and
    /// clear the queue.
    pub fn flush_addr_relay_queues(&mut self) {
        let now = Instant::now();
        for peer in self.peers.values_mut() {
            if peer.addr_relay_queue.is_empty() {
                continue;
            }
            if now.duration_since(peer.last_addr_flush) < ADDR_RELAY_FLUSH_INTERVAL {
                continue;
            }
            peer.last_addr_flush = now;
            let entries: Vec<(u32, u64, [u8; 16], u16)> =
                peer.addr_relay_queue.drain(..).collect();
            let msg = NetworkMessage::Addr(crate::message::AddrMessage { addrs: entries });
            let _ = peer.cmd_tx.send(PeerCommand::Send(msg));
        }
    }

    /// M22: disconnect peers that have been inactive for longer than
    /// `TIMEOUT_INTERVAL`. Manual peers are exempt.
    pub fn check_activity_timeouts(&mut self) {
        let now = Instant::now();
        let timed_out: Vec<u64> = self
            .peers
            .iter()
            .filter(|(_, p)| {
                !p.conn_type.is_manual()
                    && now.duration_since(p.last_recv_time) > TIMEOUT_INTERVAL
            })
            .map(|(&id, _)| id)
            .collect();
        for peer_id in timed_out {
            warn!("peer {peer_id}: activity timeout (>{}s), disconnecting", TIMEOUT_INTERVAL.as_secs());
            self.disconnect(peer_id);
        }
    }

    /// M23: check whether a new inbound connection from the given address
    /// would exceed the per-network-type limit. Returns `true` if the
    /// connection should be allowed.
    pub fn check_inbound_network_limit(&self, addr: &SocketAddr) -> bool {
        let Some(ref limits) = self.config.max_inbound_per_network else {
            return true; // no per-type limits configured
        };
        let net_type = NetworkType::from_addr(addr);
        let current = self.inbound_per_network.get(&net_type).copied().unwrap_or(0);
        if let Some(&max) = limits.get(&net_type) {
            current < max
        } else {
            true // no limit for this network type
        }
    }

    /// M20: check whether the given service flags include all desirable
    /// services for outbound connections.
    pub fn has_desirable_services(services: u64) -> bool {
        crate::message::has_all_desirable_services(services)
    }

    /// BIP130/BIP152: announce a new block to all peers.
    ///
    /// - Mode 1 (high-bandwidth) peers: send `cmpctblock` directly if `block` is available
    /// - Other peers that signalled `sendheaders`: send `headers`
    /// - Others: send `inv(block)`
    ///
    /// Skips `from_peer` (the peer that sent us the block).
    pub fn broadcast_new_block(
        &self,
        header: BlockHeader,
        hash: BlockHash,
        from_peer: u64,
        block: Option<&Block>,
    ) {
        let inv_msg = NetworkMessage::Inv(vec![Inventory {
            inv_type: InvType::Block,
            hash: hash.0,
        }]);
        let headers_msg = NetworkMessage::Headers(HeadersMessage {
            headers: vec![header],
        });
        // Build compact block lazily (only if there's at least one mode-1 peer).
        let has_mode1 = self
            .peers
            .iter()
            .any(|(pid, p)| *pid != from_peer && p.compact_block_mode == 1);
        let cmpct_msg = if has_mode1 {
            block.map(|b| {
                let nonce = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;
                NetworkMessage::CmpctBlock(crate::compact::CompactBlock::from_block(b, nonce))
            })
        } else {
            None
        };
        for (&pid, peer) in &self.peers {
            if pid == from_peer {
                continue;
            }
            let msg = if peer.compact_block_mode == 1 {
                // BIP152 high-bandwidth: push compact block directly
                if let Some(ref cmpct) = cmpct_msg {
                    cmpct.clone()
                } else if peer.prefers_headers {
                    headers_msg.clone()
                } else {
                    inv_msg.clone()
                }
            } else if peer.prefers_headers {
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
        let inv = vec![Inventory {
            inv_type: InvType::WitnessBlock,
            hash: hash.0,
        }];
        self.send_to(peer_id, NetworkMessage::GetData(inv));
    }

    /// Request multiple blocks (IBD batch download)
    pub fn request_blocks(&self, peer_id: u64, hashes: &[BlockHash]) {
        let items: Vec<_> = hashes
            .iter()
            .map(|h| Inventory {
                inv_type: InvType::WitnessBlock,
                hash: h.0,
            })
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
        self.peers
            .values()
            .map(|p| p.best_height)
            .max()
            .unwrap_or(0)
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

    /// Select an inbound peer to evict when the inbound connection limit is
    /// reached.  Implements Bitcoin Core's `SelectNodeToEvict` algorithm:
    ///
    /// 1. Protect the 8 longest-connected inbound peers.
    /// 2. Group remaining candidates by /16 subnet (first 2 octets of IPv4).
    /// 3. Return the most-recently-connected peer in the largest subnet group
    ///    (break ties by group size, then by most recent connection time).
    ///
    /// Returns `None` if there are no evictable inbound peers.
    pub fn select_peer_to_evict(&self) -> Option<u64> {
        // Collect all inbound peers as candidates.
        let mut candidates: Vec<EvictionCandidate> = self
            .peers
            .iter()
            .filter(|(_, p)| p.conn_type.is_inbound())
            .map(|(&id, p)| EvictionCandidate {
                peer_id: id,
                addr: p.addr,
                connected_time: p.connected_time,
                is_protected: false,
            })
            .collect();

        if candidates.is_empty() {
            return None;
        }

        // Step (e): Protect the EVICTION_PROTECT_LONGEST longest-connected peers.
        // Sort by connected_time ascending (earliest first) — those are the
        // longest-lived peers.
        candidates.sort_by_key(|c| c.connected_time);
        let protect_count = EVICTION_PROTECT_LONGEST.min(candidates.len());
        for c in candidates.iter_mut().take(protect_count) {
            c.is_protected = true;
        }

        // Remove protected peers.
        candidates.retain(|c| !c.is_protected);
        if candidates.is_empty() {
            return None;
        }

        // Step (f): Group remaining candidates by /16 subnet.
        let mut subnet_groups: HashMap<[u8; 2], Vec<&EvictionCandidate>> = HashMap::new();
        for c in &candidates {
            let key = subnet_key(&c.addr);
            subnet_groups.entry(key).or_default().push(c);
        }

        // Step (g): Find the largest subnet group.
        // Break ties: prefer the group with the most peers. Among groups of
        // equal size, pick arbitrarily (deterministic by key order doesn't
        // matter for Sybil resistance).
        let largest_group = subnet_groups
            .values()
            .max_by_key(|g| g.len())?;

        // From the largest group, evict the most-recently-connected peer
        // (last to arrive = least established).
        largest_group
            .iter()
            .max_by_key(|c| c.connected_time)
            .map(|c| c.peer_id)
    }

    /// Process all pending peer events (non-blocking, call from event loop)
    pub async fn process_events(&mut self) {
        while let Ok(addr) = self.connect_fail_rx.try_recv() {
            self.connecting_addrs.remove(&addr);
            // Keep failed candidates retryable instead of losing them permanently.
            self.add_candidate_addr(addr);
        }

        // Drain command registrations first (must happen before Ready arrives)
        while let Ok((peer_id, addr, cmd_tx, conn_type)) = self.cmd_reg_rx.try_recv() {
            self.pending_cmd_txs
                .insert(peer_id, (addr, cmd_tx, conn_type));
        }

        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                PeerEvent::Ready {
                    peer_id,
                    addr,
                    best_height,
                    user_agent,
                    wtxid_relay,
                    prefers_addrv2,
                    time_offset,
                    relay,
                } => {
                    info!("peer {peer_id} ready: height={best_height} ua={user_agent}");

                    // Retrieve the cmd_tx stored during connect / accept
                    let resolved_addr = if let Some((stored_addr, cmd_tx, conn_type)) =
                        self.pending_cmd_txs.remove(&peer_id)
                    {
                        // Check ban list for inbound connections
                        if conn_type.is_inbound() && self.banned_ips.contains(&stored_addr.ip()) {
                            warn!(
                                "rejected inbound peer {peer_id}: IP {} is banned",
                                stored_addr.ip()
                            );
                            let _ = cmd_tx.send(PeerCommand::Disconnect);
                            continue;
                        }

                        // Feeler connections: disconnect immediately after handshake.
                        if conn_type == ConnectionType::Feeler {
                            info!("feeler {peer_id}: handshake complete, disconnecting");
                            let _ = cmd_tx.send(PeerCommand::Disconnect);
                            self.connecting_addrs.remove(&stored_addr);
                            // The address is reachable; mark as good in addrman.
                            self.addrman_good(&stored_addr);
                            continue;
                        }

                        // PrivateBroadcast connections skip compact blocks and addr
                        // requests — they exist solely for tx relay.
                        if !conn_type.is_private_broadcast() {
                            // BIP152: request high-bandwidth compact blocks (mode=1)
                            let _ = cmd_tx.send(PeerCommand::Send(NetworkMessage::SendCmpct(true, 1)));
                            // Ask peer for their known addresses
                            let _ = cmd_tx.send(PeerCommand::Send(NetworkMessage::GetAddr));
                        }

                        if conn_type.is_inbound() {
                            // M23: per-network-type inbound limit check
                            if !self.check_inbound_network_limit(&stored_addr) {
                                let net_type = NetworkType::from_addr(&stored_addr);
                                warn!(
                                    "rejected inbound peer {peer_id}: per-network limit reached for {net_type:?}"
                                );
                                let _ = cmd_tx.send(PeerCommand::Disconnect);
                                continue;
                            }
                            self.inbound_count += 1;
                            let net_type = NetworkType::from_addr(&stored_addr);
                            *self.inbound_per_network.entry(net_type).or_insert(0) += 1;
                        } else {
                            self.outbound_count += 1;
                            match conn_type {
                                ConnectionType::OutboundFullRelay => self.outbound_full_relay_count += 1,
                                ConnectionType::BlockRelayOnly => self.block_relay_only_count += 1,
                                _ => {}
                            }
                            self.connecting_addrs.remove(&stored_addr);
                            self.connected_addrs.insert(stored_addr);
                            // Mark as successfully connected in addrman
                            self.addrman_good(&stored_addr);
                            // Track clock offset from outbound peers only
                            self.time_offsets.add(time_offset);
                        }

                        // Eviction check for inbound peers: if we are at the
                        // inbound limit, try to evict the least-useful peer.
                        if conn_type.is_inbound()
                            && self.inbound_count > self.config.max_inbound
                        {
                            if let Some(evict_id) = self.select_peer_to_evict() {
                                info!(
                                    "inbound slots full ({} > {}), evicting peer {evict_id}",
                                    self.inbound_count, self.config.max_inbound
                                );
                                if let Some(evict_peer) = self.peers.get(&evict_id) {
                                    let _ = evict_peer.cmd_tx.send(PeerCommand::Disconnect);
                                }
                            }
                        }

                        let now_inst = Instant::now();
                        self.peers.insert(
                            peer_id,
                            ConnectedPeer {
                                addr: stored_addr,
                                best_height,
                                cmd_tx,
                                fee_filter: 0,
                                misbehavior: 0,
                                conn_type,
                                wtxid_relay,
                                prefers_addrv2,
                                prefers_headers: false,
                                compact_block_mode: 0,
                                compact_block_version: 0,
                                connected_time: now_inst,
                                tx_relay: TxRelayState {
                                    relay_txes: relay,
                                    wtxid_relay,
                                    fee_filter: 0,
                                    known_txids: HashSet::new(),
                                },
                                chain_sync: ChainSyncState::new(),
                                last_recv_time: now_inst,
                                addr_relay_queue: VecDeque::new(),
                                last_addr_flush: now_inst,
                                user_agent: user_agent.clone(),
                                services: 0,
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
                        if peer.conn_type.is_inbound() {
                            self.inbound_count = self.inbound_count.saturating_sub(1);
                            let net_type = NetworkType::from_addr(&peer.addr);
                            if let Some(count) = self.inbound_per_network.get_mut(&net_type) {
                                *count = count.saturating_sub(1);
                            }
                        } else {
                            self.outbound_count = self.outbound_count.saturating_sub(1);
                            match peer.conn_type {
                                ConnectionType::OutboundFullRelay => {
                                    self.outbound_full_relay_count = self.outbound_full_relay_count.saturating_sub(1);
                                }
                                ConnectionType::BlockRelayOnly => {
                                    self.block_relay_only_count = self.block_relay_only_count.saturating_sub(1);
                                }
                                _ => {}
                            }
                            self.connected_addrs.remove(&peer.addr);
                        }
                    }
                    self.pending_cmd_txs.remove(&peer_id);
                    let _ = self
                        .node_event_tx
                        .send(NodeEvent::PeerDisconnected { peer_id });
                    debug!("peer {peer_id} disconnected");
                }
                PeerEvent::Message { peer_id, message } => {
                    self.handle_message(peer_id, message).await;
                }
            }
        }

        // ── L16: prioritize anchor peers on first tick ────────────────────────
        self.try_connect_anchors().await;

        // ── Connection manager: attempt to fill outbound slots ────────────────
        let now = std::time::Instant::now();
        let in_progress_outbound = self.outbound_count + self.connecting_addrs.len();
        if now.duration_since(self.last_reconnect) >= Duration::from_secs(30)
            && in_progress_outbound < self.config.max_outbound
        {
            debug!(
                "conn-mgr: refill tick outbound={} connecting={} connected={} addrman={} max_outbound={}",
                self.outbound_count,
                self.connecting_addrs.len(),
                self.connected_addrs.len(),
                self.addrman.len(),
                self.config.max_outbound
            );
            self.last_reconnect = now;
            let mut attempts = 0;
            while self.outbound_count + self.connecting_addrs.len() < self.config.max_outbound {
                let Some(conn_type) = self.next_outbound_type() else {
                    break;
                };
                let Some(candidate) = self.addrman.select(false) else {
                    break;
                };
                attempts += 1;
                if attempts > 30 {
                    break; // avoid infinite loop if all candidates are connecting/banned
                }
                if self.connecting_addrs.contains(&candidate)
                    || self.connected_addrs.contains(&candidate)
                    || self.banned_ips.contains(&candidate.ip())
                {
                    continue;
                }
                let unix_now = crate::addrman::now_unix();
                self.addrman.attempt(&candidate, unix_now);
                info!("conn-mgr: connecting to candidate {candidate} (type={conn_type:?})");
                let addr_str = candidate.to_string();
                self.connecting_addrs.insert(candidate);
                self.connect_raw_typed(&addr_str, Some(candidate), conn_type).await;
            }
        }

        // ── L15: periodic feeler connections ───────────────────────────────────
        self.maybe_start_feeler().await;

        // Flush batched transaction announcements
        self.flush_tx_announcements();

        // M24: flush per-peer addr relay queues on their schedule
        self.flush_addr_relay_queues();

        // M22: disconnect inactive peers
        self.check_activity_timeouts();
    }

    async fn handle_message(&mut self, peer_id: u64, message: NetworkMessage) {
        // M22: update last-recv timestamp for activity timeout tracking.
        if let Some(peer) = self.peers.get_mut(&peer_id) {
            peer.last_recv_time = Instant::now();
        }

        match message {
            NetworkMessage::Block(block) => {
                let _ = self
                    .node_event_tx
                    .send(NodeEvent::BlockReceived { peer_id, block });
            }
            NetworkMessage::Headers(h) => {
                // M21: enforce MAX_HEADERS_RESULTS
                if h.headers.len() > MAX_HEADERS_RESULTS {
                    warn!(
                        "peer {peer_id}: sent {} headers (max {}), disconnecting",
                        h.headers.len(),
                        MAX_HEADERS_RESULTS
                    );
                    self.misbehave(peer_id, 20, "too many headers");
                    self.disconnect(peer_id);
                    return;
                }
                let _ = self.node_event_tx.send(NodeEvent::HeadersReceived {
                    peer_id,
                    headers: h.headers,
                });
            }
            NetworkMessage::Tx(tx) => {
                let _ = self
                    .node_event_tx
                    .send(NodeEvent::TxReceived { peer_id, tx });
            }
            NetworkMessage::Inv(items) => {
                let _ = self
                    .node_event_tx
                    .send(NodeEvent::InvReceived { peer_id, items });
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
                let _ = self
                    .node_event_tx
                    .send(NodeEvent::CmpctBlockReceived { peer_id, cmpct });
            }
            NetworkMessage::GetBlockTxn(req) => {
                let _ = self
                    .node_event_tx
                    .send(NodeEvent::GetBlockTxnReceived { peer_id, req });
            }
            NetworkMessage::BlockTxn(resp) => {
                let _ = self
                    .node_event_tx
                    .send(NodeEvent::BlockTxnReceived { peer_id, resp });
            }
            NetworkMessage::NotFound(items) => {
                let _ = self
                    .node_event_tx
                    .send(NodeEvent::NotFound { peer_id, items });
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
                let _ = self
                    .node_event_tx
                    .send(NodeEvent::MempoolRequested { peer_id });
            }
            NetworkMessage::SendCmpct(announce, version) => {
                // BIP152: peer tells us which compact block mode it wants.
                // announce=true → mode 1 (high-bandwidth: push cmpctblock proactively)
                // announce=false → mode 2 (low-bandwidth: send inv first)
                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    peer.compact_block_mode = if announce { 1 } else { 2 };
                    peer.compact_block_version = version;
                    debug!(
                        "peer {peer_id}: BIP152 sendcmpct announce={announce} version={version} (mode {})",
                        peer.compact_block_mode
                    );
                }
            }
            NetworkMessage::SendTxRcncl { version, salt } => {
                debug!(
                    "peer {peer_id}: BIP330 sendtxrcncl version={version} salt={salt:#x}"
                );
                // Stub: acknowledge the signal but don't enter reconciliation yet.
                // Full minisketch-based reconciliation is future work.
            }
            other => {
                debug!("peer {peer_id}: unhandled message: {}", other.command());
            }
        }
    }

    async fn handle_addr(&mut self, peer_id: u64, entries: Vec<(u32, u64, [u8; 16], u16)>) {
        let now_secs = unix_now() as i64;
        let mut relay_entries: Vec<(u32, u64, [u8; 16], u16)> = Vec::new();

        for &(timestamp, services, ip_bytes, port) in &entries {
            let ts = timestamp as i64;
            // Only relay addresses whose timestamps are within ADDR_MAX_DRIFT_SECS of now
            if (ts - now_secs).abs() > ADDR_MAX_DRIFT_SECS {
                continue;
            }
            let ip = ip_bytes_to_ip(ip_bytes);
            let addr = SocketAddr::new(ip, port);
            if !self.banned_ips.contains(&ip) {
                self.add_candidate_addr(addr);
                relay_entries.push((timestamp, services, ip_bytes, port));
            }
        }

        if relay_entries.is_empty() {
            return;
        }

        // Emit to the node for persistence
        let _ = self.node_event_tx.send(NodeEvent::AddrReceived {
            peer_id,
            addrs: entries,
        });

        // M24: batch addr relay — enqueue entries into per-peer relay queues
        // instead of forwarding immediately.  Queues are flushed periodically
        // in `flush_addr_relay_queues()`.
        let relay_subset: Vec<(u32, u64, [u8; 16], u16)> =
            relay_entries.into_iter().take(10).collect();

        // Select a random subset of eligible peers for relay.
        let eligible_peers: Vec<u64> = self
            .peers
            .iter()
            .filter(|(&id, p)| id != peer_id && p.conn_type.relays_addrs())
            .map(|(&id, _)| id)
            .collect();

        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        let mut targets = eligible_peers;
        targets.shuffle(&mut rng);
        targets.truncate(ADDR_RELAY_FANOUT);

        for target_id in targets {
            if let Some(peer) = self.peers.get_mut(&target_id) {
                for entry in &relay_subset {
                    if peer.addr_relay_queue.len() < MAX_ADDR_RELAY_QUEUE {
                        peer.addr_relay_queue.push_back(*entry);
                    }
                }
            }
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
        let _ = self
            .node_event_tx
            .send(NodeEvent::Addrv2Received { peer_id, msg });
    }

    /// Check if a peer supports wtxid relay (BIP339).
    pub fn peer_wtxid_relay(&self, peer_id: u64) -> bool {
        self.peers
            .get(&peer_id)
            .map(|p| p.wtxid_relay)
            .unwrap_or(false)
    }

    /// At startup, prioritize connecting to saved anchor peers before random
    /// addresses.  Anchors are block-relay-only peers persisted from the
    /// previous session.  This is called once early in the connection loop.
    pub async fn try_connect_anchors(&mut self) {
        if self.anchors_tried {
            return;
        }
        self.anchors_tried = true;

        let anchors: Vec<SocketAddr> = self.anchor_addrs.clone();
        if anchors.is_empty() {
            return;
        }

        info!("connecting to {} saved anchor peer(s)", anchors.len());
        for addr in anchors {
            if self.connecting_addrs.contains(&addr)
                || self.connected_addrs.contains(&addr)
                || self.banned_ips.contains(&addr.ip())
            {
                continue;
            }
            self.connecting_addrs.insert(addr);
            let addr_str = addr.to_string();
            self.connect_raw_typed(&addr_str, Some(addr), ConnectionType::BlockRelayOnly)
                .await;
        }
    }

    /// Periodically initiate a feeler connection (~every 120s) to test
    /// whether a random address from AddrMan's new table is reachable.
    /// Feelers complete the version handshake and then disconnect immediately.
    pub async fn maybe_start_feeler(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_feeler) < Duration::from_secs(120) {
            return;
        }
        self.last_feeler = now;

        // Only run feelers when outbound slots are full (we're not still bootstrapping).
        if self.outbound_count + self.connecting_addrs.len() < self.config.max_outbound {
            return;
        }

        // Pick a random candidate from the new table.
        let Some(candidate) = self.addrman.select(true) else {
            return;
        };
        if self.connecting_addrs.contains(&candidate)
            || self.connected_addrs.contains(&candidate)
            || self.banned_ips.contains(&candidate.ip())
        {
            return;
        }

        debug!("starting feeler to {candidate}");
        let addr_str = candidate.to_string();
        self.connect_feeler(&addr_str).await;
    }

    /// Connect a feeler to the given address. A feeler connection completes
    /// the version handshake to verify the address is reachable, then
    /// immediately disconnects.
    pub async fn connect_feeler(&mut self, addr: &str) {
        let Ok(socket_addr) = addr.parse::<SocketAddr>() else {
            return;
        };
        if self.connecting_addrs.contains(&socket_addr)
            || self.connected_addrs.contains(&socket_addr)
            || self.banned_ips.contains(&socket_addr.ip())
        {
            return;
        }

        let peer_id = NEXT_PEER_ID.fetch_add(1, Ordering::Relaxed);
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<PeerCommand>();

        let event_tx = self.event_tx.clone();
        let cmd_reg_tx = self.cmd_reg_tx.clone();
        let connect_fail_tx = self.connect_fail_tx.clone();
        let config = self.config.clone();
        let best_height = self.best_height;
        let addr_str = addr.to_string();

        self.connecting_addrs.insert(socket_addr);

        tokio::spawn(async move {
            let result =
                tokio::time::timeout(config.connect_timeout, TcpStream::connect(&addr_str)).await;

            match result {
                Ok(Ok(stream)) => {
                    let peer_addr = stream.peer_addr().unwrap_or(socket_addr);
                    info!("feeler connected to {peer_addr} (peer {peer_id})");
                    // Register as Feeler type
                    let _ = cmd_reg_tx.send((peer_id, peer_addr, cmd_tx, ConnectionType::Feeler));
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
                Ok(Err(e)) => {
                    warn!("feeler failed to connect to {addr_str}: {e}");
                    let _ = connect_fail_tx.send(socket_addr);
                }
                Err(_) => {
                    warn!("feeler connection timeout to {addr_str}");
                    let _ = connect_fail_tx.send(socket_addr);
                }
            }
        });
    }

    /// Main event loop – call this in a tokio task
    pub async fn run(mut self) {
        loop {
            self.process_events().await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

/// Discover local network addresses that this node can be reached on.
///
/// Returns a list of socket addresses by probing which addresses the OS
/// assigns when binding to the wildcard address on the given port.  For a
/// more complete implementation, platform-specific APIs (e.g., `getifaddrs`)
/// could be used to enumerate all interfaces.
pub fn discover_local_addresses(port: u16) -> Vec<SocketAddr> {
    let mut addrs = Vec::new();

    // Try binding a UDP socket to the wildcard address — the OS will pick a
    // local interface.  We then connect to a remote address (without sending
    // any data) so the OS resolves which source IP would be used.
    if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        // "Connect" to a well-known external address — this doesn't send any
        // packets for UDP, it just lets us query the local address.
        if sock.connect("8.8.8.8:53").is_ok() {
            if let Ok(local) = sock.local_addr() {
                addrs.push(SocketAddr::new(local.ip(), port));
            }
        }
    }
    // Also try IPv6.
    if let Ok(sock) = std::net::UdpSocket::bind("[::]:0") {
        if sock.connect("[2001:4860:4860::8888]:53").is_ok() {
            if let Ok(local) = sock.local_addr() {
                let ip = local.ip();
                // Skip link-local and loopback.
                if !ip.is_loopback() {
                    addrs.push(SocketAddr::new(ip, port));
                }
            }
        }
    }

    addrs
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

/// Extract the /16 subnet key (first 2 octets) for IPv4 addresses.
/// For IPv6 addresses, uses the first 2 bytes of the address.
fn subnet_key(addr: &SocketAddr) -> [u8; 2] {
    match addr.ip() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            [o[0], o[1]]
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            // Check for IPv4-mapped IPv6 (::ffff:a.b.c.d)
            if o[..10] == [0; 10] && o[10] == 0xff && o[11] == 0xff {
                [o[12], o[13]]
            } else {
                [o[0], o[1]]
            }
        }
    }
}

fn socket_addr_to_ip_bytes(addr: &SocketAddr) -> [u8; 16] {
    match addr.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_type_helpers() {
        assert!(ConnectionType::Inbound.is_inbound());
        assert!(!ConnectionType::Inbound.is_outbound());
        assert!(!ConnectionType::Inbound.is_block_relay_only());

        assert!(!ConnectionType::OutboundFullRelay.is_inbound());
        assert!(ConnectionType::OutboundFullRelay.is_outbound());
        assert!(!ConnectionType::OutboundFullRelay.is_block_relay_only());

        assert!(!ConnectionType::BlockRelayOnly.is_inbound());
        assert!(ConnectionType::BlockRelayOnly.is_outbound());
        assert!(ConnectionType::BlockRelayOnly.is_block_relay_only());

        assert!(!ConnectionType::Feeler.is_inbound());
        assert!(ConnectionType::Feeler.is_outbound());
        assert!(!ConnectionType::Feeler.is_block_relay_only());

        assert!(!ConnectionType::AddrFetch.is_inbound());
        assert!(ConnectionType::AddrFetch.is_outbound());
        assert!(!ConnectionType::AddrFetch.is_block_relay_only());

        // PrivateBroadcast
        assert!(!ConnectionType::PrivateBroadcast.is_inbound());
        assert!(ConnectionType::PrivateBroadcast.is_outbound());
        assert!(!ConnectionType::PrivateBroadcast.is_block_relay_only());
        assert!(ConnectionType::PrivateBroadcast.is_private_broadcast());
        assert!(!ConnectionType::OutboundFullRelay.is_private_broadcast());
    }

    #[test]
    fn connection_type_short_lived() {
        assert!(ConnectionType::Feeler.is_short_lived());
        assert!(ConnectionType::AddrFetch.is_short_lived());
        assert!(ConnectionType::PrivateBroadcast.is_short_lived());
        assert!(!ConnectionType::OutboundFullRelay.is_short_lived());
        assert!(!ConnectionType::BlockRelayOnly.is_short_lived());
        assert!(!ConnectionType::Manual.is_short_lived());
        assert!(!ConnectionType::Inbound.is_short_lived());
    }

    #[test]
    fn connection_type_relay_capabilities() {
        // relays_addrs: everyone except BlockRelayOnly and PrivateBroadcast
        assert!(ConnectionType::OutboundFullRelay.relays_addrs());
        assert!(ConnectionType::Inbound.relays_addrs());
        assert!(ConnectionType::Manual.relays_addrs());
        assert!(ConnectionType::Feeler.relays_addrs());
        assert!(ConnectionType::AddrFetch.relays_addrs());
        assert!(!ConnectionType::BlockRelayOnly.relays_addrs());
        assert!(!ConnectionType::PrivateBroadcast.relays_addrs());

        // relays_txs: everyone except BlockRelayOnly
        assert!(ConnectionType::OutboundFullRelay.relays_txs());
        assert!(ConnectionType::Inbound.relays_txs());
        assert!(ConnectionType::Manual.relays_txs());
        assert!(ConnectionType::PrivateBroadcast.relays_txs());
        assert!(!ConnectionType::BlockRelayOnly.relays_txs());
    }

    #[test]
    fn block_relay_only_skipped_in_tx_broadcast() {
        let (node_tx, _node_rx) = mpsc::unbounded_channel();
        let mut mgr = PeerManager::new(PeerManagerConfig::default(), node_tx, 0);

        // Create two mock peers: one full relay, one block-relay-only
        let (cmd_tx_full, mut cmd_rx_full) = mpsc::unbounded_channel();
        let (cmd_tx_block, mut cmd_rx_block) = mpsc::unbounded_channel();

        let addr_full: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        let addr_block: SocketAddr = "5.6.7.8:8333".parse().unwrap();

        mgr.peers.insert(
            1,
            ConnectedPeer {
                addr: addr_full,
                best_height: 100,
                cmd_tx: cmd_tx_full,
                fee_filter: 0,
                misbehavior: 0,
                conn_type: ConnectionType::OutboundFullRelay,
                wtxid_relay: false,
                prefers_addrv2: false,
                prefers_headers: false,
                compact_block_mode: 0,
                compact_block_version: 0,
                connected_time: Instant::now(),
                tx_relay: TxRelayState::default(),
                chain_sync: ChainSyncState::new(),
                last_recv_time: Instant::now(),
                addr_relay_queue: VecDeque::new(),
                last_addr_flush: Instant::now(),
                user_agent: String::new(),
                services: 0,
            },
        );
        mgr.peers.insert(
            2,
            ConnectedPeer {
                addr: addr_block,
                best_height: 100,
                cmd_tx: cmd_tx_block,
                fee_filter: 0,
                misbehavior: 0,
                conn_type: ConnectionType::BlockRelayOnly,
                wtxid_relay: false,
                prefers_addrv2: false,
                prefers_headers: false,
                compact_block_mode: 0,
                compact_block_version: 0,
                connected_time: Instant::now(),
                tx_relay: TxRelayState::default(),
                chain_sync: ChainSyncState::new(),
                last_recv_time: Instant::now(),
                addr_relay_queue: VecDeque::new(),
                last_addr_flush: Instant::now(),
                user_agent: String::new(),
                services: 0,
            },
        );

        let inv = NetworkMessage::Inv(vec![Inventory {
            inv_type: InvType::Tx,
            hash: rbtc_primitives::hash::Hash256([0u8; 32]),
        }]);
        mgr.broadcast_tx_inv(inv, 1000);

        // Full relay peer should have received the inv
        assert!(cmd_rx_full.try_recv().is_ok(), "full relay peer should receive tx inv");
        // Block relay only peer should NOT have received the inv
        assert!(cmd_rx_block.try_recv().is_err(), "block-relay-only peer should not receive tx inv");
    }

    #[test]
    fn queue_and_flush_announcements() {
        let (node_tx, _node_rx) = mpsc::unbounded_channel();
        let mut mgr = PeerManager::new(PeerManagerConfig::default(), node_tx, 0);

        // Add a mock peer
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
        let addr: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        mgr.peers.insert(
            1,
            ConnectedPeer {
                addr,
                best_height: 100,
                cmd_tx,
                fee_filter: 0,
                misbehavior: 0,
                conn_type: ConnectionType::OutboundFullRelay,
                wtxid_relay: false,
                prefers_addrv2: false,
                prefers_headers: false,
                compact_block_mode: 0,
                compact_block_version: 0,
                connected_time: Instant::now(),
                tx_relay: TxRelayState::default(),
                chain_sync: ChainSyncState::new(),
                last_recv_time: Instant::now(),
                addr_relay_queue: VecDeque::new(),
                last_addr_flush: Instant::now(),
                user_agent: String::new(),
                services: 0,
            },
        );

        // Queue 3 announcements
        for i in 0u8..3 {
            mgr.queue_tx_announcement(TxAnnouncement {
                txid: rbtc_primitives::hash::Hash256([i; 32]),
                wtxid: rbtc_primitives::hash::Hash256([i + 100; 32]),
            });
        }
        assert_eq!(mgr.pending_tx_announcements.len(), 3);

        mgr.flush_tx_announcements();
        assert!(mgr.pending_tx_announcements.is_empty(), "queue should be empty after flush");

        // Peer should have received one inv message with 3 entries
        let msg = cmd_rx.try_recv().unwrap();
        match msg {
            PeerCommand::Send(NetworkMessage::Inv(invs)) => {
                assert_eq!(invs.len(), 3);
                // Non-wtxid peer should get InvType::Tx
                assert_eq!(invs[0].inv_type, InvType::Tx);
            }
            other => panic!("expected Inv message, got {:?}", other),
        }
    }

    #[test]
    fn wtxid_relay_uses_witness_inv() {
        let (node_tx, _node_rx) = mpsc::unbounded_channel();
        let mut mgr = PeerManager::new(PeerManagerConfig::default(), node_tx, 0);

        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
        let addr: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        mgr.peers.insert(
            1,
            ConnectedPeer {
                addr,
                best_height: 100,
                cmd_tx,
                fee_filter: 0,
                misbehavior: 0,
                conn_type: ConnectionType::OutboundFullRelay,
                wtxid_relay: true, // peer supports wtxid relay
                prefers_addrv2: false,
                prefers_headers: false,
                compact_block_mode: 0,
                compact_block_version: 0,
                connected_time: Instant::now(),
                tx_relay: TxRelayState::default(),
                chain_sync: ChainSyncState::new(),
                last_recv_time: Instant::now(),
                addr_relay_queue: VecDeque::new(),
                last_addr_flush: Instant::now(),
                user_agent: String::new(),
                services: 0,
            },
        );

        let txid = rbtc_primitives::hash::Hash256([0xAA; 32]);
        let wtxid = rbtc_primitives::hash::Hash256([0xBB; 32]);
        mgr.queue_tx_announcement(TxAnnouncement { txid, wtxid });
        mgr.flush_tx_announcements();

        let msg = cmd_rx.try_recv().unwrap();
        match msg {
            PeerCommand::Send(NetworkMessage::Inv(invs)) => {
                assert_eq!(invs.len(), 1);
                assert_eq!(invs[0].inv_type, InvType::WitnessTx);
                assert_eq!(invs[0].hash, wtxid);
            }
            other => panic!("expected Inv message, got {:?}", other),
        }
    }

    #[test]
    fn frelay_false_sets_relay_txes_false() {
        let (node_tx, _node_rx) = mpsc::unbounded_channel();
        let mut mgr = PeerManager::new(PeerManagerConfig::default(), node_tx, 0);

        // Simulate a peer with fRelay=false by setting relay_txes=false
        let (cmd_tx, _cmd_rx) = mpsc::unbounded_channel();
        let addr: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        mgr.peers.insert(
            1,
            ConnectedPeer {
                addr,
                best_height: 100,
                cmd_tx,
                fee_filter: 0,
                misbehavior: 0,
                conn_type: ConnectionType::OutboundFullRelay,
                wtxid_relay: false,
                prefers_addrv2: false,
                prefers_headers: false,
                compact_block_mode: 0,
                compact_block_version: 0,
                connected_time: Instant::now(),
                tx_relay: TxRelayState {
                    relay_txes: false, // fRelay=0
                    wtxid_relay: false,
                    fee_filter: 0,
                    known_txids: HashSet::new(),
                },
                chain_sync: ChainSyncState::new(),
                last_recv_time: Instant::now(),
                addr_relay_queue: VecDeque::new(),
                last_addr_flush: Instant::now(),
                user_agent: String::new(),
                services: 0,
            },
        );

        assert!(!mgr.peers.get(&1).unwrap().tx_relay.relay_txes);
    }

    #[test]
    fn frelay_false_suppresses_tx_announcements() {
        let (node_tx, _node_rx) = mpsc::unbounded_channel();
        let mut mgr = PeerManager::new(PeerManagerConfig::default(), node_tx, 0);

        // Peer with relay_txes=false (fRelay=0)
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
        let addr: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        mgr.peers.insert(
            1,
            ConnectedPeer {
                addr,
                best_height: 100,
                cmd_tx,
                fee_filter: 0,
                misbehavior: 0,
                conn_type: ConnectionType::OutboundFullRelay,
                wtxid_relay: false,
                prefers_addrv2: false,
                prefers_headers: false,
                compact_block_mode: 0,
                compact_block_version: 0,
                connected_time: Instant::now(),
                tx_relay: TxRelayState {
                    relay_txes: false, // fRelay=0
                    wtxid_relay: false,
                    fee_filter: 0,
                    known_txids: HashSet::new(),
                },
                chain_sync: ChainSyncState::new(),
                last_recv_time: Instant::now(),
                addr_relay_queue: VecDeque::new(),
                last_addr_flush: Instant::now(),
                user_agent: String::new(),
                services: 0,
            },
        );

        // Queue a tx announcement and flush — peer should NOT receive it
        mgr.queue_tx_announcement(TxAnnouncement {
            txid: rbtc_primitives::hash::Hash256([0xAA; 32]),
            wtxid: rbtc_primitives::hash::Hash256([0xBB; 32]),
        });
        mgr.flush_tx_announcements();

        assert!(
            cmd_rx.try_recv().is_err(),
            "peer with fRelay=0 should not receive tx announcements"
        );
    }

    #[test]
    fn frelay_false_suppresses_broadcast_tx_inv() {
        let (node_tx, _node_rx) = mpsc::unbounded_channel();
        let mut mgr = PeerManager::new(PeerManagerConfig::default(), node_tx, 0);

        // Peer with relay_txes=false (fRelay=0)
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
        let addr: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        mgr.peers.insert(
            1,
            ConnectedPeer {
                addr,
                best_height: 100,
                cmd_tx,
                fee_filter: 0,
                misbehavior: 0,
                conn_type: ConnectionType::OutboundFullRelay,
                wtxid_relay: false,
                prefers_addrv2: false,
                prefers_headers: false,
                compact_block_mode: 0,
                compact_block_version: 0,
                connected_time: Instant::now(),
                tx_relay: TxRelayState {
                    relay_txes: false, // fRelay=0
                    wtxid_relay: false,
                    fee_filter: 0,
                    known_txids: HashSet::new(),
                },
                chain_sync: ChainSyncState::new(),
                last_recv_time: Instant::now(),
                addr_relay_queue: VecDeque::new(),
                last_addr_flush: Instant::now(),
                user_agent: String::new(),
                services: 0,
            },
        );

        let inv = NetworkMessage::Inv(vec![Inventory {
            inv_type: InvType::Tx,
            hash: rbtc_primitives::hash::Hash256([0u8; 32]),
        }]);
        mgr.broadcast_tx_inv(inv, 1000);

        assert!(
            cmd_rx.try_recv().is_err(),
            "peer with fRelay=0 should not receive broadcast tx inv"
        );
    }

    #[test]
    fn sendcmpct_mode1_high_bandwidth() {
        let (node_tx, _node_rx) = mpsc::unbounded_channel();
        let mut mgr = PeerManager::new(PeerManagerConfig::default(), node_tx, 0);

        let (cmd_tx, _cmd_rx) = mpsc::unbounded_channel();
        let addr: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        mgr.peers.insert(
            1,
            ConnectedPeer {
                addr,
                best_height: 100,
                cmd_tx,
                fee_filter: 0,
                misbehavior: 0,
                conn_type: ConnectionType::OutboundFullRelay,
                wtxid_relay: false,
                prefers_addrv2: false,
                prefers_headers: false,
                compact_block_mode: 0,
                compact_block_version: 0,
                connected_time: Instant::now(),
                tx_relay: TxRelayState::default(),
                chain_sync: ChainSyncState::new(),
                last_recv_time: Instant::now(),
                addr_relay_queue: VecDeque::new(),
                last_addr_flush: Instant::now(),
                user_agent: String::new(),
                services: 0,
            },
        );

        // Simulate receiving SendCmpct(true, 1) = mode 1 high-bandwidth
        let peer = mgr.peers.get_mut(&1).unwrap();
        peer.compact_block_mode = 1;
        peer.compact_block_version = 1;

        assert_eq!(mgr.peers[&1].compact_block_mode, 1);
        assert_eq!(mgr.peers[&1].compact_block_version, 1);
    }

    #[test]
    fn sendcmpct_mode2_low_bandwidth() {
        let (node_tx, _node_rx) = mpsc::unbounded_channel();
        let mut mgr = PeerManager::new(PeerManagerConfig::default(), node_tx, 0);

        let (cmd_tx, _cmd_rx) = mpsc::unbounded_channel();
        let addr: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        mgr.peers.insert(
            1,
            ConnectedPeer {
                addr,
                best_height: 100,
                cmd_tx,
                fee_filter: 0,
                misbehavior: 0,
                conn_type: ConnectionType::OutboundFullRelay,
                wtxid_relay: false,
                prefers_addrv2: false,
                prefers_headers: false,
                compact_block_mode: 0,
                compact_block_version: 0,
                connected_time: Instant::now(),
                tx_relay: TxRelayState::default(),
                chain_sync: ChainSyncState::new(),
                last_recv_time: Instant::now(),
                addr_relay_queue: VecDeque::new(),
                last_addr_flush: Instant::now(),
                user_agent: String::new(),
                services: 0,
            },
        );

        // Simulate receiving SendCmpct(false, 1) = mode 2 low-bandwidth
        let peer = mgr.peers.get_mut(&1).unwrap();
        peer.compact_block_mode = 2;
        peer.compact_block_version = 1;

        assert_eq!(mgr.peers[&1].compact_block_mode, 2);
    }

    #[test]
    fn broadcast_new_block_mode1_sends_cmpctblock() {
        use rbtc_primitives::block::Block;
        use rbtc_primitives::transaction::{OutPoint, TxIn, TxOut, Transaction, OUTPOINT_NULL_INDEX};
        use rbtc_primitives::hash::Txid;
        use rbtc_primitives::script::Script;

        let (node_tx, _node_rx) = mpsc::unbounded_channel();
        let mgr_cfg = PeerManagerConfig::default();
        let mut mgr = PeerManager::new(mgr_cfg, node_tx, 0);

        let (cmd_tx1, mut cmd_rx1) = mpsc::unbounded_channel();
        let (cmd_tx2, mut cmd_rx2) = mpsc::unbounded_channel();

        let addr1: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        let addr2: SocketAddr = "5.6.7.8:8333".parse().unwrap();

        // Peer 1: mode 1 (high-bandwidth)
        mgr.peers.insert(
            1,
            ConnectedPeer {
                addr: addr1,
                best_height: 100,
                cmd_tx: cmd_tx1,
                fee_filter: 0,
                misbehavior: 0,
                conn_type: ConnectionType::OutboundFullRelay,
                wtxid_relay: false,
                prefers_addrv2: false,
                prefers_headers: false,
                compact_block_mode: 1,
                compact_block_version: 1,
                connected_time: Instant::now(),
                tx_relay: TxRelayState::default(),
                chain_sync: ChainSyncState::new(),
                last_recv_time: Instant::now(),
                addr_relay_queue: VecDeque::new(),
                last_addr_flush: Instant::now(),
                user_agent: String::new(),
                services: 0,
            },
        );

        // Peer 2: mode 0 (no compact blocks, prefers headers)
        mgr.peers.insert(
            2,
            ConnectedPeer {
                addr: addr2,
                best_height: 100,
                cmd_tx: cmd_tx2,
                fee_filter: 0,
                misbehavior: 0,
                conn_type: ConnectionType::OutboundFullRelay,
                wtxid_relay: false,
                prefers_addrv2: false,
                prefers_headers: true,
                compact_block_mode: 0,
                compact_block_version: 0,
                connected_time: Instant::now(),
                tx_relay: TxRelayState::default(),
                chain_sync: ChainSyncState::new(),
                last_recv_time: Instant::now(),
                addr_relay_queue: VecDeque::new(),
                last_addr_flush: Instant::now(),
                user_agent: String::new(),
                services: 0,
            },
        );

        let header = BlockHeader {
            version: 1,
            prev_block: BlockHash(Hash256::ZERO),
            merkle_root: Hash256::ZERO,
            time: 0,
            bits: 0x207fffff,
            nonce: 0,
        };
        let coinbase = Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint { txid: Txid(Hash256::ZERO), vout: OUTPOINT_NULL_INDEX },
                script_sig: Script::from_bytes(vec![0x04]),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut { value: 50_0000_0000, script_pubkey: Script::new() }],
            0,
        );
        let block = Block::new(header.clone(), vec![coinbase]);
        let hash = BlockHash(Hash256([1; 32]));

        mgr.broadcast_new_block(header, hash, 999, Some(&block));

        // Mode 1 peer should receive CmpctBlock
        let msg1 = cmd_rx1.try_recv().unwrap();
        match msg1 {
            PeerCommand::Send(NetworkMessage::CmpctBlock(_)) => {}
            other => panic!("expected CmpctBlock for mode 1 peer, got {:?}", other),
        }

        // Mode 0 peer with prefers_headers should receive Headers
        let msg2 = cmd_rx2.try_recv().unwrap();
        match msg2 {
            PeerCommand::Send(NetworkMessage::Headers(_)) => {}
            other => panic!("expected Headers for mode 0 peer, got {:?}", other),
        }
    }

    #[test]
    fn next_outbound_type_fills_full_relay_first() {
        let (node_tx, _node_rx) = mpsc::unbounded_channel();
        let mut mgr = PeerManager::new(PeerManagerConfig::default(), node_tx, 0);

        // Initially: should fill full-relay slots first
        assert_eq!(mgr.next_outbound_type(), Some(ConnectionType::OutboundFullRelay));

        // Simulate filling all full-relay slots
        mgr.outbound_full_relay_count = mgr.config.max_outbound_full_relay;
        assert_eq!(mgr.next_outbound_type(), Some(ConnectionType::BlockRelayOnly));

        // Fill all block-relay-only too
        mgr.block_relay_only_count = mgr.config.max_block_relay_only;
        assert_eq!(mgr.next_outbound_type(), None);
    }

    #[test]
    fn default_config_slot_limits() {
        let config = PeerManagerConfig::default();
        assert_eq!(config.max_outbound_full_relay, 8);
        assert_eq!(config.max_block_relay_only, 2);
        assert_eq!(config.max_outbound, 11); // 8 + 2 + headroom for feelers
        assert_eq!(config.max_inbound, 125);
    }

    // ── Eviction tests ──────────────────────────────────────────────────

    /// Helper: insert a mock inbound peer with a specific connected_time.
    fn insert_inbound_peer(
        mgr: &mut PeerManager,
        peer_id: u64,
        addr: SocketAddr,
        connected_time: Instant,
    ) -> mpsc::UnboundedReceiver<PeerCommand> {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        mgr.peers.insert(
            peer_id,
            ConnectedPeer {
                addr,
                best_height: 100,
                cmd_tx,
                fee_filter: 0,
                misbehavior: 0,
                conn_type: ConnectionType::Inbound,
                wtxid_relay: false,
                prefers_addrv2: false,
                prefers_headers: false,
                compact_block_mode: 0,
                compact_block_version: 0,
                connected_time,
                tx_relay: TxRelayState::default(),
                chain_sync: ChainSyncState::new(),
                last_recv_time: connected_time,
                addr_relay_queue: VecDeque::new(),
                last_addr_flush: connected_time,
                user_agent: String::new(),
                services: 0,
            },
        );
        mgr.inbound_count += 1;
        cmd_rx
    }

    #[test]
    fn eviction_returns_none_when_no_inbound_peers() {
        let (node_tx, _node_rx) = mpsc::unbounded_channel();
        let mgr = PeerManager::new(PeerManagerConfig::default(), node_tx, 0);
        assert!(mgr.select_peer_to_evict().is_none());
    }

    #[test]
    fn eviction_returns_none_when_under_limit() {
        let (node_tx, _node_rx) = mpsc::unbounded_channel();
        let mut mgr = PeerManager::new(PeerManagerConfig::default(), node_tx, 0);

        // Add a few inbound peers — still under EVICTION_PROTECT_LONGEST
        let now = Instant::now();
        for i in 1..=4 {
            let addr: SocketAddr = format!("10.0.0.{i}:8333").parse().unwrap();
            let _ = insert_inbound_peer(&mut mgr, i, addr, now);
        }
        // Only 4 inbound peers, all protected by the 8-longest rule.
        assert!(mgr.select_peer_to_evict().is_none());
    }

    #[test]
    fn eviction_protects_longest_connected() {
        let (node_tx, _node_rx) = mpsc::unbounded_channel();
        let mut mgr = PeerManager::new(PeerManagerConfig::default(), node_tx, 0);

        let base = Instant::now();
        // Insert 8 long-lived peers (different subnets) — all should be protected.
        for i in 1..=8u64 {
            let addr: SocketAddr = format!("10.{i}.0.1:8333").parse().unwrap();
            let _ = insert_inbound_peer(&mut mgr, i, addr, base - Duration::from_secs(1000 - i));
        }
        // Only the 8 longest-connected exist, so all are protected.
        assert!(mgr.select_peer_to_evict().is_none());

        // Add a 9th peer on a unique subnet — this one is NOT protected.
        let addr9: SocketAddr = "10.99.0.1:8333".parse().unwrap();
        let _ = insert_inbound_peer(&mut mgr, 9, addr9, base);
        let evicted = mgr.select_peer_to_evict();
        assert_eq!(evicted, Some(9), "newest peer should be evicted");
    }

    #[test]
    fn eviction_selects_from_largest_subnet_group() {
        let (node_tx, _node_rx) = mpsc::unbounded_channel();
        let mut mgr = PeerManager::new(PeerManagerConfig::default(), node_tx, 0);

        let base = Instant::now();

        // 8 long-lived peers on unique subnets (protected).
        for i in 1..=8u64 {
            let addr: SocketAddr = format!("10.{i}.0.1:8333").parse().unwrap();
            let _ = insert_inbound_peer(
                &mut mgr,
                i,
                addr,
                base - Duration::from_secs(10000 + i),
            );
        }

        // 2 peers on subnet 192.168.x.x
        let addr_a: SocketAddr = "192.168.1.1:8333".parse().unwrap();
        let _ = insert_inbound_peer(&mut mgr, 100, addr_a, base - Duration::from_secs(50));
        let addr_b: SocketAddr = "192.168.1.2:8333".parse().unwrap();
        let _ = insert_inbound_peer(&mut mgr, 101, addr_b, base - Duration::from_secs(10));

        // 1 peer on subnet 172.16.x.x
        let addr_c: SocketAddr = "172.16.5.1:8333".parse().unwrap();
        let _ = insert_inbound_peer(&mut mgr, 200, addr_c, base - Duration::from_secs(5));

        // The 192.168/16 subnet has 2 peers (largest group).
        // Among them, peer 101 connected more recently (base - 10s vs base - 50s).
        let evicted = mgr.select_peer_to_evict();
        assert_eq!(
            evicted,
            Some(101),
            "should evict the most recent peer from the largest subnet group"
        );
    }

    #[test]
    fn eviction_ignores_outbound_peers() {
        let (node_tx, _node_rx) = mpsc::unbounded_channel();
        let mut mgr = PeerManager::new(PeerManagerConfig::default(), node_tx, 0);

        // Insert 10 outbound peers — should not be eviction candidates.
        let now = Instant::now();
        for i in 1..=10u64 {
            let (cmd_tx, _rx) = mpsc::unbounded_channel();
            let addr: SocketAddr = format!("10.0.0.{i}:8333").parse().unwrap();
            mgr.peers.insert(
                i,
                ConnectedPeer {
                    addr,
                    best_height: 100,
                    cmd_tx,
                    fee_filter: 0,
                    misbehavior: 0,
                    conn_type: ConnectionType::OutboundFullRelay,
                    wtxid_relay: false,
                    prefers_addrv2: false,
                    prefers_headers: false,
                    compact_block_mode: 0,
                    compact_block_version: 0,
                    connected_time: now,
                    tx_relay: TxRelayState::default(),
                    chain_sync: ChainSyncState::new(),
                    last_recv_time: now,
                    addr_relay_queue: VecDeque::new(),
                    last_addr_flush: now,
                    user_agent: String::new(),
                    services: 0,
                },
            );
        }

        // No inbound peers at all → None.
        assert!(mgr.select_peer_to_evict().is_none());
    }

    #[test]
    fn subnet_key_ipv4() {
        let addr: SocketAddr = "192.168.1.5:8333".parse().unwrap();
        assert_eq!(subnet_key(&addr), [192, 168]);
    }

    #[test]
    fn subnet_key_ipv4_mapped_ipv6() {
        use std::net::{Ipv6Addr, SocketAddrV6};
        // ::ffff:10.20.30.40
        let v6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a14, 0x1e28);
        let addr = SocketAddr::V6(SocketAddrV6::new(v6, 8333, 0, 0));
        assert_eq!(subnet_key(&addr), [10, 20]);
    }

    // ── M15: ConnectionType::Manual ──────────────────────────────────

    #[test]
    fn connection_type_manual() {
        assert!(!ConnectionType::Manual.is_inbound());
        assert!(ConnectionType::Manual.is_outbound());
        assert!(!ConnectionType::Manual.is_block_relay_only());
        assert!(ConnectionType::Manual.is_manual());
        // Other types are not manual
        assert!(!ConnectionType::OutboundFullRelay.is_manual());
        assert!(!ConnectionType::Inbound.is_manual());
    }

    // ── M16: TxRelayState ────────────────────────────────────────────

    #[test]
    fn tx_relay_state_default() {
        let state = TxRelayState::default();
        assert!(state.relay_txes);
        assert!(!state.wtxid_relay);
        assert_eq!(state.fee_filter, 0);
        assert!(state.known_txids.is_empty());
    }

    #[test]
    fn tx_relay_state_known_txids() {
        let mut state = TxRelayState::default();
        let txid = Txid(rbtc_primitives::hash::Hash256([0xAA; 32]));
        assert!(!state.known_txids.contains(&txid));
        state.known_txids.insert(txid);
        assert!(state.known_txids.contains(&txid));
    }

    // ── M17: MAX_BLOCK_RELAY_ONLY_CONNECTIONS ────────────────────────

    #[test]
    fn max_block_relay_only_connections_constant() {
        assert_eq!(MAX_BLOCK_RELAY_ONLY_CONNECTIONS, 2);
        // Config default matches the constant
        assert_eq!(
            PeerManagerConfig::default().max_block_relay_only,
            MAX_BLOCK_RELAY_ONLY_CONNECTIONS
        );
    }

    // ── M18: misbehave with reason ───────────────────────────────────

    #[test]
    fn misbehave_increments_score() {
        let (node_tx, _node_rx) = mpsc::unbounded_channel();
        let mut mgr = PeerManager::new(PeerManagerConfig::default(), node_tx, 0);

        let (cmd_tx, _cmd_rx) = mpsc::unbounded_channel();
        let addr: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        mgr.peers.insert(
            1,
            ConnectedPeer {
                addr,
                best_height: 100,
                cmd_tx,
                fee_filter: 0,
                misbehavior: 0,
                conn_type: ConnectionType::OutboundFullRelay,
                wtxid_relay: false,
                prefers_addrv2: false,
                prefers_headers: false,
                compact_block_mode: 0,
                compact_block_version: 0,
                connected_time: Instant::now(),
                tx_relay: TxRelayState::default(),
                chain_sync: ChainSyncState::new(),
                last_recv_time: Instant::now(),
                addr_relay_queue: VecDeque::new(),
                last_addr_flush: Instant::now(),
                user_agent: String::new(),
                services: 0,
            },
        );

        mgr.misbehave(1, 50, "test reason");
        assert_eq!(mgr.peers[&1].misbehavior, 50);

        // Below threshold — peer still connected
        assert!(mgr.peers.contains_key(&1));

        // Cross threshold — peer gets banned
        mgr.misbehave(1, 50, "second offense");
        assert!(mgr.banned_ips.contains(&addr.ip()));
    }

    // ── M19: ChainSyncState ─────────────────────────────────────────

    #[test]
    fn chain_sync_state_no_timeout_by_default() {
        let state = ChainSyncState::new();
        assert!(!state.is_timed_out());
        assert!(state.work_header_tip.is_none());
        assert!(state.timeout.is_none());
    }

    #[test]
    fn chain_sync_state_detects_timeout() {
        let mut state = ChainSyncState::new();
        // Set a timeout in the past
        state.timeout = Some(Instant::now() - Duration::from_secs(1));
        assert!(state.is_timed_out());
    }

    #[test]
    fn chain_sync_state_not_timed_out_yet() {
        let mut state = ChainSyncState::new();
        // Set a timeout in the future
        state.timeout = Some(Instant::now() + Duration::from_secs(60));
        assert!(!state.is_timed_out());
    }

    // ── M20: has_all_desirable_services ──────────────────────────────

    #[test]
    fn desirable_services_via_peer_manager() {
        use crate::message::{NODE_NETWORK, NODE_WITNESS, NODE_NETWORK_LIMITED};
        assert!(PeerManager::has_desirable_services(NODE_NETWORK | NODE_WITNESS));
        assert!(PeerManager::has_desirable_services(NODE_NETWORK_LIMITED | NODE_WITNESS));
        assert!(!PeerManager::has_desirable_services(NODE_NETWORK));
        assert!(!PeerManager::has_desirable_services(0));
    }

    // ── M21: MAX_HEADERS_RESULTS ─────────────────────────────────────

    #[test]
    fn max_headers_results_constant() {
        assert_eq!(MAX_HEADERS_RESULTS, 2000);
    }

    // ── M22: TIMEOUT_INTERVAL ────────────────────────────────────────

    #[test]
    fn timeout_interval_is_20_minutes() {
        assert_eq!(TIMEOUT_INTERVAL, Duration::from_secs(1200));
    }

    #[test]
    fn activity_timeout_disconnects_stale_peer() {
        let (node_tx, _node_rx) = mpsc::unbounded_channel();
        let mut mgr = PeerManager::new(PeerManagerConfig::default(), node_tx, 0);

        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
        let addr: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        let stale_time = Instant::now() - Duration::from_secs(1300); // >20 min ago
        mgr.peers.insert(
            1,
            ConnectedPeer {
                addr,
                best_height: 100,
                cmd_tx,
                fee_filter: 0,
                misbehavior: 0,
                conn_type: ConnectionType::OutboundFullRelay,
                wtxid_relay: false,
                prefers_addrv2: false,
                prefers_headers: false,
                compact_block_mode: 0,
                compact_block_version: 0,
                connected_time: stale_time,
                tx_relay: TxRelayState::default(),
                chain_sync: ChainSyncState::new(),
                last_recv_time: stale_time,
                addr_relay_queue: VecDeque::new(),
                last_addr_flush: stale_time,
                user_agent: String::new(),
                services: 0,
            },
        );

        mgr.check_activity_timeouts();

        // Should have sent Disconnect
        let msg = cmd_rx.try_recv().unwrap();
        assert!(matches!(msg, PeerCommand::Disconnect));
    }

    #[test]
    fn manual_peers_exempt_from_timeout() {
        let (node_tx, _node_rx) = mpsc::unbounded_channel();
        let mut mgr = PeerManager::new(PeerManagerConfig::default(), node_tx, 0);

        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
        let addr: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        let stale_time = Instant::now() - Duration::from_secs(1300);
        mgr.peers.insert(
            1,
            ConnectedPeer {
                addr,
                best_height: 100,
                cmd_tx,
                fee_filter: 0,
                misbehavior: 0,
                conn_type: ConnectionType::Manual,
                wtxid_relay: false,
                prefers_addrv2: false,
                prefers_headers: false,
                compact_block_mode: 0,
                compact_block_version: 0,
                connected_time: stale_time,
                tx_relay: TxRelayState::default(),
                chain_sync: ChainSyncState::new(),
                last_recv_time: stale_time,
                addr_relay_queue: VecDeque::new(),
                last_addr_flush: stale_time,
                user_agent: String::new(),
                services: 0,
            },
        );

        mgr.check_activity_timeouts();

        // Manual peer should NOT be disconnected
        assert!(cmd_rx.try_recv().is_err());
    }

    // ── M23: per-network-type inbound limits ─────────────────────────

    #[test]
    fn network_type_classification() {
        let ipv4: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        assert_eq!(NetworkType::from_addr(&ipv4), NetworkType::IPv4);

        let ipv6: SocketAddr = "[2001:db8::1]:8333".parse().unwrap();
        assert_eq!(NetworkType::from_addr(&ipv6), NetworkType::IPv6);

        // IPv4-mapped IPv6 → IPv4
        use std::net::{Ipv6Addr, SocketAddrV6};
        let v6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304);
        let mapped = SocketAddr::V6(SocketAddrV6::new(v6, 8333, 0, 0));
        assert_eq!(NetworkType::from_addr(&mapped), NetworkType::IPv4);
    }

    #[test]
    fn per_network_inbound_limit_enforcement() {
        let (node_tx, _node_rx) = mpsc::unbounded_channel();
        let mut config = PeerManagerConfig::default();
        let mut limits = HashMap::new();
        limits.insert(NetworkType::IPv4, 2);
        config.max_inbound_per_network = Some(limits);
        let mut mgr = PeerManager::new(config, node_tx, 0);

        let addr1: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        let addr2: SocketAddr = "5.6.7.8:8333".parse().unwrap();
        let addr3: SocketAddr = "9.10.11.12:8333".parse().unwrap();

        // Two IPv4 inbound connections allowed
        assert!(mgr.check_inbound_network_limit(&addr1));
        *mgr.inbound_per_network.entry(NetworkType::IPv4).or_insert(0) += 1;

        assert!(mgr.check_inbound_network_limit(&addr2));
        *mgr.inbound_per_network.entry(NetworkType::IPv4).or_insert(0) += 1;

        // Third IPv4 should be rejected
        assert!(!mgr.check_inbound_network_limit(&addr3));

        // IPv6 should still be allowed (no limit set)
        let addr_v6: SocketAddr = "[2001:db8::1]:8333".parse().unwrap();
        assert!(mgr.check_inbound_network_limit(&addr_v6));
    }

    // ── M24: addr relay batching ─────────────────────────────────────

    #[test]
    fn addr_relay_queue_flushes_on_interval() {
        let (node_tx, _node_rx) = mpsc::unbounded_channel();
        let mut mgr = PeerManager::new(PeerManagerConfig::default(), node_tx, 0);

        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
        let addr: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        let past = Instant::now() - Duration::from_secs(60); // well past flush interval
        mgr.peers.insert(
            1,
            ConnectedPeer {
                addr,
                best_height: 100,
                cmd_tx,
                fee_filter: 0,
                misbehavior: 0,
                conn_type: ConnectionType::OutboundFullRelay,
                wtxid_relay: false,
                prefers_addrv2: false,
                prefers_headers: false,
                compact_block_mode: 0,
                compact_block_version: 0,
                connected_time: Instant::now(),
                tx_relay: TxRelayState::default(),
                chain_sync: ChainSyncState::new(),
                last_recv_time: Instant::now(),
                addr_relay_queue: VecDeque::new(),
                last_addr_flush: past,
                user_agent: String::new(),
                services: 0,
            },
        );

        // Enqueue some addr entries
        let entry = (1234u32, 1u64, [0u8; 16], 8333u16);
        mgr.peers.get_mut(&1).unwrap().addr_relay_queue.push_back(entry);
        mgr.peers.get_mut(&1).unwrap().addr_relay_queue.push_back(entry);

        // Flush
        mgr.flush_addr_relay_queues();

        // Queue should be drained
        assert!(mgr.peers[&1].addr_relay_queue.is_empty());

        // Peer should have received an Addr message
        let msg = cmd_rx.try_recv().unwrap();
        match msg {
            PeerCommand::Send(NetworkMessage::Addr(addr_msg)) => {
                assert_eq!(addr_msg.addrs.len(), 2);
            }
            other => panic!("expected Addr message, got {:?}", other),
        }
    }

    #[test]
    fn addr_relay_queue_respects_interval() {
        let (node_tx, _node_rx) = mpsc::unbounded_channel();
        let mut mgr = PeerManager::new(PeerManagerConfig::default(), node_tx, 0);

        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
        let addr: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        // last flush was just now — should NOT flush yet
        mgr.peers.insert(
            1,
            ConnectedPeer {
                addr,
                best_height: 100,
                cmd_tx,
                fee_filter: 0,
                misbehavior: 0,
                conn_type: ConnectionType::OutboundFullRelay,
                wtxid_relay: false,
                prefers_addrv2: false,
                prefers_headers: false,
                compact_block_mode: 0,
                compact_block_version: 0,
                connected_time: Instant::now(),
                tx_relay: TxRelayState::default(),
                chain_sync: ChainSyncState::new(),
                last_recv_time: Instant::now(),
                addr_relay_queue: VecDeque::new(),
                last_addr_flush: Instant::now(),
                user_agent: String::new(),
                services: 0,
            },
        );

        let entry = (1234u32, 1u64, [0u8; 16], 8333u16);
        mgr.peers.get_mut(&1).unwrap().addr_relay_queue.push_back(entry);

        mgr.flush_addr_relay_queues();

        // Queue should still contain the entry (interval not elapsed)
        assert_eq!(mgr.peers[&1].addr_relay_queue.len(), 1);
        assert!(cmd_rx.try_recv().is_err());
    }

    // ── L15: feeler timer ─────────────────────────────────────────────

    #[test]
    fn feeler_timer_defaults() {
        let (node_tx, _node_rx) = mpsc::unbounded_channel();
        let mgr = PeerManager::new(PeerManagerConfig::default(), node_tx, 0);
        // last_feeler should be set at construction
        assert!(!mgr.anchors_tried);
    }

    // ── L16: anchor reconnection ──────────────────────────────────────

    #[test]
    fn try_connect_anchors_sets_flag() {
        let (node_tx, _node_rx) = mpsc::unbounded_channel();
        let mut mgr = PeerManager::new(PeerManagerConfig::default(), node_tx, 0);
        assert!(!mgr.anchors_tried);
        // Load some anchors
        mgr.load_anchors(vec!["1.2.3.4:8333".parse().unwrap()]);
        assert_eq!(mgr.anchor_addrs().len(), 1);
    }

    // ── L18: local address discovery ──────────────────────────────────

    #[test]
    fn discover_local_returns_something() {
        // Should return at least one address on most systems.
        let addrs = discover_local_addresses(8333);
        // We can't guarantee a result in all CI environments, but we can
        // verify the function doesn't panic and returns valid SocketAddr.
        for a in &addrs {
            assert_ne!(a.port(), 0);
        }
    }

    // ── L20: PeerStats ────────────────────────────────────────────────

    #[test]
    fn peer_stats_basic() {
        let (node_tx, _node_rx) = mpsc::unbounded_channel();
        let mut mgr = PeerManager::new(PeerManagerConfig::default(), node_tx, 0);

        let (cmd_tx, _cmd_rx) = mpsc::unbounded_channel();
        let addr: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        mgr.peers.insert(
            1,
            ConnectedPeer {
                addr,
                best_height: 800_000,
                cmd_tx,
                fee_filter: 0,
                misbehavior: 0,
                conn_type: ConnectionType::OutboundFullRelay,
                wtxid_relay: false,
                prefers_addrv2: false,
                prefers_headers: false,
                compact_block_mode: 0,
                compact_block_version: 0,
                connected_time: Instant::now(),
                tx_relay: TxRelayState::default(),
                chain_sync: ChainSyncState::new(),
                last_recv_time: Instant::now(),
                addr_relay_queue: VecDeque::new(),
                last_addr_flush: Instant::now(),
                user_agent: "/Satoshi:27.0.0/".to_string(),
                services: 0x0809,
            },
        );

        let stats = mgr.peer_stats();
        assert_eq!(stats.len(), 1);
        let s = &stats[0];
        assert_eq!(s.id, 1);
        assert_eq!(s.addr, "1.2.3.4:8333");
        assert_eq!(s.services, 0x0809);
        assert_eq!(s.subver, "/Satoshi:27.0.0/");
        assert_eq!(s.startingheight, 800_000);
        assert!(!s.inbound);
        assert_eq!(s.conn_type, "OutboundFullRelay");
        // conn_time should be recent (within last few seconds)
        assert!(s.conn_time > 0);
        assert_eq!(s.misbehavior, 0);
    }

    #[test]
    fn peer_stats_empty_when_no_peers() {
        let (node_tx, _node_rx) = mpsc::unbounded_channel();
        let mgr = PeerManager::new(PeerManagerConfig::default(), node_tx, 0);
        assert!(mgr.peer_stats().is_empty());
    }

    #[test]
    fn peer_stats_multiple_peers_with_misbehavior() {
        let (node_tx, _node_rx) = mpsc::unbounded_channel();
        let mut mgr = PeerManager::new(PeerManagerConfig::default(), node_tx, 0);

        // Outbound peer with some misbehavior
        let (cmd_tx1, _rx1) = mpsc::unbounded_channel();
        mgr.peers.insert(
            10,
            ConnectedPeer {
                addr: "10.0.0.1:8333".parse().unwrap(),
                best_height: 850_000,
                cmd_tx: cmd_tx1,
                fee_filter: 1000,
                misbehavior: 25,
                conn_type: ConnectionType::OutboundFullRelay,
                wtxid_relay: true,
                prefers_addrv2: false,
                prefers_headers: true,
                compact_block_mode: 0,
                compact_block_version: 0,
                connected_time: Instant::now(),
                tx_relay: TxRelayState::default(),
                chain_sync: ChainSyncState::new(),
                last_recv_time: Instant::now(),
                addr_relay_queue: VecDeque::new(),
                last_addr_flush: Instant::now(),
                user_agent: "/Satoshi:26.0.0/".to_string(),
                services: 0x0409,
            },
        );

        // Inbound peer
        let (cmd_tx2, _rx2) = mpsc::unbounded_channel();
        mgr.peers.insert(
            20,
            ConnectedPeer {
                addr: "192.168.1.5:12345".parse().unwrap(),
                best_height: 849_999,
                cmd_tx: cmd_tx2,
                fee_filter: 0,
                misbehavior: 0,
                conn_type: ConnectionType::Inbound,
                wtxid_relay: false,
                prefers_addrv2: false,
                prefers_headers: false,
                compact_block_mode: 0,
                compact_block_version: 0,
                connected_time: Instant::now(),
                tx_relay: TxRelayState::default(),
                chain_sync: ChainSyncState::new(),
                last_recv_time: Instant::now(),
                addr_relay_queue: VecDeque::new(),
                last_addr_flush: Instant::now(),
                user_agent: "/btcwire:0.5.0/".to_string(),
                services: 0x01,
            },
        );

        let stats = mgr.get_peer_stats();
        assert_eq!(stats.len(), 2);

        let outbound = stats.iter().find(|s| s.id == 10).unwrap();
        assert_eq!(outbound.misbehavior, 25);
        assert!(!outbound.inbound);
        assert_eq!(outbound.startingheight, 850_000);
        assert_eq!(outbound.services, 0x0409);
        assert_eq!(outbound.subver, "/Satoshi:26.0.0/");

        let inbound = stats.iter().find(|s| s.id == 20).unwrap();
        assert_eq!(inbound.misbehavior, 0);
        assert!(inbound.inbound);
        assert_eq!(inbound.startingheight, 849_999);
        assert_eq!(inbound.conn_type, "Inbound");
        assert_eq!(inbound.subver, "/btcwire:0.5.0/");
    }
}
