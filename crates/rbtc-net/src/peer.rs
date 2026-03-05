use std::net::SocketAddr;
use std::time::{Duration, Instant};

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
    },
    Message { peer_id: u64, message: NetworkMessage },
    Disconnected { peer_id: u64 },
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
    let result = run_peer_inner(id, addr, stream, network, best_height, &event_tx, &mut cmd_rx).await;
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

    timeout(HANDSHAKE_TIMEOUT, async {
        while !got_version || !got_verack {
            let msg = Message::read_from(&mut reader, &magic).await?;
            match msg.payload {
                NetworkMessage::Version(v) => {
                    peer_version = v.version;
                    peer_height = v.start_height;
                    peer_ua = v.user_agent.clone();
                    peer_services = v.services;
                    got_version = true;
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
    }).await.map_err(|_| NetError::HandshakeFailed("timeout".into()))??;

    info!("peer {id} ({addr}) handshake complete: version={peer_version} height={peer_height} ua={peer_ua}");

    event_tx.send(PeerEvent::Ready {
        peer_id: id,
        addr,
        best_height: peer_height,
        user_agent: peer_ua,
        wtxid_relay: peer_wtxid_relay,
        prefers_addrv2: peer_sendaddrv2,
    }).map_err(|_| NetError::ChannelError)?;

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
                if let Some(_) = pending_ping {
                    if last_ping.elapsed() > PING_INTERVAL + PING_TIMEOUT {
                        return Err(NetError::ConnectionClosed);
                    }
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
