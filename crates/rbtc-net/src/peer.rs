use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::mpsc,
    time::timeout,
};
use tracing::{debug, info};

use rbtc_primitives::network::Network;

use crate::{
    error::{NetError, Result},
    message::{Message, NetworkMessage, VersionMessage},
};

/// Connection state of a peer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    Connecting,
    Handshaking,
    Ready,
    Disconnected,
}

/// Events sent from peers to the peer manager
#[derive(Debug)]
pub enum PeerEvent {
    Ready {
        peer_id: u64,
        addr: SocketAddr,
        best_height: i32,
        user_agent: String,
        /// BIP339: peer signaled wtxidrelay during handshake
        wtxid_relay: bool,
        /// BIP155: peer signaled sendaddrv2 during handshake
        prefers_addrv2: bool,
        /// Peer clock offset in seconds (peer_timestamp - local_timestamp)
        time_offset: i64,
        /// BIP37: peer's fRelay flag from version message (false = no tx relay)
        relay: bool,
    },
    Message {
        peer_id: u64,
        message: NetworkMessage,
    },
    Disconnected {
        peer_id: u64,
    },
}

/// Commands sent from peer manager to a peer
#[derive(Debug)]
pub enum PeerCommand {
    Send(NetworkMessage),
    Disconnect,
}

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const PING_INTERVAL: Duration = Duration::from_secs(120);
const PING_TIMEOUT: Duration = Duration::from_secs(30);

/// Transport protocol version for this peer connection.
///
/// Matches Bitcoin Core's `TransportProtocolType` enum in
/// `src/node/connection_types.h:91-95`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportVersion {
    /// Peer could be v1 or v2 — not yet determined.
    ///
    /// This is the initial state for **responder** (non-initiating) connections.
    /// The responder checks incoming bytes against the v1 prefix
    /// (network magic + "version\x00\x00\x00\x00\x00" = 16 bytes). If the
    /// bytes mismatch, the peer is assumed to be v2; if all 16 bytes match,
    /// the peer is v1.
    ///
    /// Matches Bitcoin Core's `TransportProtocolType::DETECTING` and the
    /// `RecvState::KEY_MAYBE_V1` / `SendState::MAYBE_V1` states in
    /// `V2Transport`.
    Detecting,
    /// Classic v1 plaintext framing.
    V1,
    /// BIP324 v2 encrypted framing (ChaCha20-Poly1305 AEAD).
    V2,
}

impl std::fmt::Display for TransportVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportVersion::Detecting => write!(f, "detecting"),
            TransportVersion::V1 => write!(f, "v1"),
            TransportVersion::V2 => write!(f, "v2"),
        }
    }
}

/// Length of the v1 prefix used for transport auto-detection.
///
/// The prefix is: 4-byte network magic + "version\x00\x00\x00\x00\x00" (12 bytes) = 16 bytes.
/// This matches Bitcoin Core's `V1_PREFIX_LEN` used in
/// `V2Transport::ProcessReceivedMaybeV1Bytes()`.
pub const V1_PREFIX_LEN: usize = 16;

/// Result of checking received bytes against the v1 prefix for transport detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectResult {
    /// Incoming bytes do not match the v1 prefix — peer is using v2 transport.
    V2,
    /// All 16 bytes match the v1 prefix — peer is using v1 transport.
    V1,
    /// Not enough bytes yet to distinguish v1 from v2. Need more data.
    NeedMoreData,
}

/// Build the 16-byte v1 prefix for a given network magic.
///
/// Format: `[magic_bytes(4)] + "version\x00\x00\x00\x00\x00"(12)`.
/// This matches Bitcoin Core's v1_prefix in `ProcessReceivedMaybeV1Bytes()`.
pub fn v1_prefix(magic: &[u8; 4]) -> [u8; V1_PREFIX_LEN] {
    let mut prefix = [0u8; V1_PREFIX_LEN];
    prefix[..4].copy_from_slice(magic);
    prefix[4] = b'v';
    prefix[5] = b'e';
    prefix[6] = b'r';
    prefix[7] = b's';
    prefix[8] = b'i';
    prefix[9] = b'o';
    prefix[10] = b'n';
    // bytes 11..16 are already 0
    prefix
}

/// Detect whether incoming bytes indicate a v1 or v2 transport connection.
///
/// This implements Bitcoin Core's `V2Transport::ProcessReceivedMaybeV1Bytes()`
/// logic. Called by a **responder** node that starts in `Detecting` state.
///
/// - If `received` diverges from the v1 prefix at any byte, returns `DetectResult::V2`.
/// - If `received` matches all 16 bytes of the v1 prefix, returns `DetectResult::V1`.
/// - If `received` is a prefix of (but shorter than) the v1 prefix, returns
///   `DetectResult::NeedMoreData`.
pub fn detect_transport(received: &[u8], magic: &[u8; 4]) -> DetectResult {
    let prefix = v1_prefix(magic);
    let check_len = received.len().min(V1_PREFIX_LEN);

    // Compare received bytes against the v1 prefix
    if received[..check_len] != prefix[..check_len] {
        // Mismatch — peer is v2
        return DetectResult::V2;
    }

    if received.len() >= V1_PREFIX_LEN {
        // Full match — peer is v1
        DetectResult::V1
    } else {
        // Partial match — need more data
        DetectResult::NeedMoreData
    }
}

/// A connected Bitcoin peer
pub struct Peer {
    pub id: u64,
    pub addr: SocketAddr,
    pub state: PeerState,
    pub services: u64,
    pub best_height: i32,
    pub user_agent: String,
    pub last_ping: Option<Instant>,
    pub pending_ping_nonce: Option<u64>,
    pub transport: TransportVersion,
}

impl Peer {
    pub fn new(id: u64, addr: SocketAddr) -> Self {
        Self {
            id,
            addr,
            state: PeerState::Connecting,
            services: 0,
            best_height: 0,
            user_agent: String::new(),
            last_ping: None,
            pending_ping_nonce: None,
            transport: TransportVersion::V1,
        }
    }
}

/// Run the peer actor: handles I/O for a single TCP connection
pub async fn run_peer(
    id: u64,
    addr: SocketAddr,
    stream: TcpStream,
    network: Network,
    best_height: i32,
    event_tx: mpsc::UnboundedSender<PeerEvent>,
    mut cmd_rx: mpsc::UnboundedReceiver<PeerCommand>,
) {
    let result = run_peer_inner(
        id,
        addr,
        stream,
        network,
        best_height,
        &event_tx,
        &mut cmd_rx,
    )
    .await;
    if let Err(e) = result {
        debug!("peer {id} ({addr}): disconnected: {e}");
    }
    let _ = event_tx.send(PeerEvent::Disconnected { peer_id: id });
}

async fn run_peer_inner(
    id: u64,
    addr: SocketAddr,
    stream: TcpStream,
    network: Network,
    best_height: i32,
    event_tx: &mpsc::UnboundedSender<PeerEvent>,
    cmd_rx: &mut mpsc::UnboundedReceiver<PeerCommand>,
) -> Result<()> {
    let magic = network.magic();
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // Send our version
    let our_nonce: u64 = rand_nonce();
    let version_msg = VersionMessage::new(best_height, our_nonce);
    let msg_bytes = Message::new(magic, NetworkMessage::Version(version_msg)).encode_to_bytes();
    write_half.write_all(&msg_bytes).await?;

    // Handshake
    let mut got_version = false;
    let mut got_verack = false;
    let mut peer_version = 0i32;
    let mut peer_height = 0i32;
    let mut peer_ua = String::new();
    let mut peer_services = 0u64;
    let mut peer_wtxid_relay = false;
    let mut peer_sendaddrv2 = false;
    let mut peer_time_offset: i64 = 0;
    let mut peer_relay = true;

    timeout(HANDSHAKE_TIMEOUT, async {
        while !got_version || !got_verack {
            let msg = Message::read_from(&mut reader, &magic).await?;
            match msg.payload {
                NetworkMessage::Version(v) => {
                    peer_version = v.version;
                    peer_height = v.start_height;
                    peer_ua = v.user_agent.clone();
                    peer_services = v.services;
                    // Compute time offset (peer clock - our clock)
                    let local_time = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    peer_time_offset = v.timestamp - local_time;
                    peer_relay = v.relay;
                    got_version = true;
                    // Reject peers with protocol version too old to support
                    // modern features (SegWit, compact blocks, etc.)
                    if peer_version < 70015 {
                        return Err(NetError::HandshakeFailed(format!(
                            "peer protocol version {} too old (minimum 70015)",
                            peer_version
                        )));
                    }
                    // BIP339: send wtxidrelay before verack
                    let wtxid = Message::new(magic, NetworkMessage::WtxidRelay).encode_to_bytes();
                    write_half.write_all(&wtxid).await?;
                    // BIP155: send sendaddrv2 before verack
                    let addrv2 = Message::new(magic, NetworkMessage::SendAddrv2).encode_to_bytes();
                    write_half.write_all(&addrv2).await?;
                    // Send verack
                    let verack = Message::new(magic, NetworkMessage::Verack).encode_to_bytes();
                    write_half.write_all(&verack).await?;
                }
                NetworkMessage::Verack => {
                    got_verack = true;
                }
                NetworkMessage::WtxidRelay => {
                    peer_wtxid_relay = true;
                }
                NetworkMessage::SendAddrv2 => {
                    peer_sendaddrv2 = true;
                }
                _ => {}
            }
        }
        Ok::<(), NetError>(())
    })
    .await
    .map_err(|_| NetError::HandshakeFailed("timeout".into()))??;

    info!("peer {id} ({addr}) handshake complete: version={peer_version} height={peer_height} ua={peer_ua}");

    event_tx
        .send(PeerEvent::Ready {
            peer_id: id,
            addr,
            best_height: peer_height,
            user_agent: peer_ua,
            wtxid_relay: peer_wtxid_relay,
            prefers_addrv2: peer_sendaddrv2,
            time_offset: peer_time_offset,
            relay: peer_relay,
        })
        .map_err(|_| NetError::ChannelError)?;

    // Send sendheaders (prefer headers over inv for new blocks)
    let sh = Message::new(magic, NetworkMessage::SendHeaders).encode_to_bytes();
    write_half.write_all(&sh).await?;

    // Main I/O loop
    let mut last_ping = Instant::now();
    let mut pending_ping: Option<u64> = None;

    loop {
        tokio::select! {
            // Incoming message
            msg_result = Message::read_from(&mut reader, &magic) => {
                match msg_result {
                    Ok(msg) => {
                        match &msg.payload {
                            NetworkMessage::Ping(nonce) => {
                                let pong = Message::new(magic, NetworkMessage::Pong(*nonce)).encode_to_bytes();
                                write_half.write_all(&pong).await?;
                            }
                            NetworkMessage::Pong(nonce) => {
                                if pending_ping == Some(*nonce) {
                                    pending_ping = None;
                                    last_ping = Instant::now();
                                }
                            }
                            _ => {
                                event_tx.send(PeerEvent::Message {
                                    peer_id: id,
                                    message: msg.payload,
                                }).map_err(|_| NetError::ChannelError)?;
                            }
                        }
                    }
                    Err(e) => return Err(e),
                }
            }

            // Outgoing command
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(PeerCommand::Send(msg)) => {
                        let bytes = Message::new(magic, msg).encode_to_bytes();
                        write_half.write_all(&bytes).await?;
                    }
                    Some(PeerCommand::Disconnect) | None => {
                        return Ok(());
                    }
                }
            }

            // Ping timer
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                if last_ping.elapsed() > PING_INTERVAL && pending_ping.is_none() {
                    let nonce = rand_nonce();
                    pending_ping = Some(nonce);
                    let ping = Message::new(magic, NetworkMessage::Ping(nonce)).encode_to_bytes();
                    write_half.write_all(&ping).await?;
                }
                if pending_ping.is_some()
                    && last_ping.elapsed() > PING_INTERVAL + PING_TIMEOUT
                {
                    return Err(NetError::ConnectionClosed);
                }
            }
        }
    }
}

fn rand_nonce() -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    std::time::SystemTime::now().hash(&mut h);
    std::thread::current().id().hash(&mut h);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mainnet magic bytes.
    const MAINNET_MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
    /// Testnet3 magic bytes.
    const TESTNET_MAGIC: [u8; 4] = [0x0b, 0x11, 0x09, 0x07];

    #[test]
    fn transport_version_display() {
        assert_eq!(TransportVersion::Detecting.to_string(), "detecting");
        assert_eq!(TransportVersion::V1.to_string(), "v1");
        assert_eq!(TransportVersion::V2.to_string(), "v2");
    }

    #[test]
    fn transport_version_has_detecting_variant() {
        // Matches Bitcoin Core's TransportProtocolType::DETECTING
        let t = TransportVersion::Detecting;
        assert_eq!(t, TransportVersion::Detecting);
        assert_ne!(t, TransportVersion::V1);
        assert_ne!(t, TransportVersion::V2);
    }

    #[test]
    fn v1_prefix_mainnet() {
        let prefix = v1_prefix(&MAINNET_MAGIC);
        assert_eq!(prefix.len(), V1_PREFIX_LEN);
        assert_eq!(&prefix[..4], &MAINNET_MAGIC);
        assert_eq!(&prefix[4..11], b"version");
        assert_eq!(&prefix[11..16], &[0, 0, 0, 0, 0]);
    }

    #[test]
    fn v1_prefix_testnet() {
        let prefix = v1_prefix(&TESTNET_MAGIC);
        assert_eq!(&prefix[..4], &TESTNET_MAGIC);
        assert_eq!(&prefix[4..11], b"version");
    }

    #[test]
    fn detect_v1_full_match() {
        let prefix = v1_prefix(&MAINNET_MAGIC);
        assert_eq!(detect_transport(&prefix, &MAINNET_MAGIC), DetectResult::V1);
    }

    #[test]
    fn detect_v1_with_extra_bytes() {
        // More than 16 bytes, first 16 match v1 prefix
        let mut data = v1_prefix(&MAINNET_MAGIC).to_vec();
        data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(detect_transport(&data, &MAINNET_MAGIC), DetectResult::V1);
    }

    #[test]
    fn detect_need_more_data_partial_match() {
        let prefix = v1_prefix(&MAINNET_MAGIC);
        // Feed 1..15 bytes that match the prefix — all should return NeedMoreData
        for len in 1..V1_PREFIX_LEN {
            assert_eq!(
                detect_transport(&prefix[..len], &MAINNET_MAGIC),
                DetectResult::NeedMoreData,
                "expected NeedMoreData for {len} matching bytes"
            );
        }
    }

    #[test]
    fn detect_v2_first_byte_mismatch() {
        // First byte doesn't match magic — immediately v2
        let data = [0x00];
        assert_eq!(detect_transport(&data, &MAINNET_MAGIC), DetectResult::V2);
    }

    #[test]
    fn detect_v2_mismatch_after_magic() {
        // Magic matches but 5th byte is not 'v' — v2
        let mut data = [0u8; 5];
        data[..4].copy_from_slice(&MAINNET_MAGIC);
        data[4] = 0x03; // EllSwift pubkey byte, not 'v'
        assert_eq!(detect_transport(&data, &MAINNET_MAGIC), DetectResult::V2);
    }

    #[test]
    fn detect_v2_mismatch_mid_command() {
        // First 8 bytes match ("version" starts ok) but byte 9 differs
        let prefix = v1_prefix(&MAINNET_MAGIC);
        let mut data = prefix[..9].to_vec();
        data[8] = 0xFF; // corrupt 'i' in "version"
        assert_eq!(detect_transport(&data, &MAINNET_MAGIC), DetectResult::V2);
    }

    #[test]
    fn detect_v2_random_bytes() {
        // Random non-v1 data should be detected as v2
        let data = [0x02, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
        assert_eq!(detect_transport(&data, &MAINNET_MAGIC), DetectResult::V2);
    }

    #[test]
    fn detect_wrong_network_magic_is_v2() {
        // A valid mainnet v1 prefix checked against testnet magic => v2
        let mainnet_prefix = v1_prefix(&MAINNET_MAGIC);
        assert_eq!(
            detect_transport(&mainnet_prefix, &TESTNET_MAGIC),
            DetectResult::V2
        );
    }

    #[test]
    fn detect_empty_input_needs_more_data() {
        // Edge case: empty buffer
        // Empty slice trivially matches (0 bytes compared), need more data
        let data: &[u8] = &[];
        assert_eq!(
            detect_transport(data, &MAINNET_MAGIC),
            DetectResult::NeedMoreData,
        );
    }
}
