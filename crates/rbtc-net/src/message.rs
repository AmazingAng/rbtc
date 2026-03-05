use std::io::{Read, Write};

use rbtc_primitives::{
    block::{Block, BlockHeader},
    codec::{decode_list, encode_list, Decodable, Encodable, VarInt},
    hash::{BlockHash, Hash256},
    transaction::Transaction,
};
use rbtc_crypto::sha256d;

use crate::error::{NetError, Result};

/// Maximum message payload size (32 MB)
const MAX_MESSAGE_SIZE: u32 = 32 * 1024 * 1024;

// ── Service flag constants (Bitcoin Core `protocol.h`) ──────────────────────

/// Full node — can serve full blocks.
pub const NODE_NETWORK: u64         = 1 << 0;
/// BIP111 — supports bloom filtering (deprecated since Core v0.19, NOT set).
pub const NODE_BLOOM: u64           = 1 << 2;
/// BIP144 — supports segregated witness.
pub const NODE_WITNESS: u64         = 1 << 3;
/// BIP157 — can serve compact block filters.
pub const NODE_COMPACT_FILTERS: u64 = 1 << 6;
/// BIP159 — limited node (pruned, only recent blocks).
pub const NODE_NETWORK_LIMITED: u64 = 1 << 10;

/// Our default service flags: full node + segwit.
pub const LOCAL_SERVICES: u64 = NODE_NETWORK | NODE_WITNESS;

/// Format service flags as a human-readable string for logging.
pub fn service_flags_to_string(flags: u64) -> String {
    let mut names = Vec::new();
    if flags & NODE_NETWORK != 0         { names.push("NODE_NETWORK"); }
    if flags & NODE_BLOOM != 0           { names.push("NODE_BLOOM"); }
    if flags & NODE_WITNESS != 0         { names.push("NODE_WITNESS"); }
    if flags & NODE_COMPACT_FILTERS != 0 { names.push("NODE_COMPACT_FILTERS"); }
    if flags & NODE_NETWORK_LIMITED != 0 { names.push("NODE_NETWORK_LIMITED"); }
    if names.is_empty() { "NONE".to_string() } else { names.join("|") }
}

/// Bitcoin P2P message
#[derive(Debug, Clone)]
pub struct Message {
    pub magic: [u8; 4],
    pub payload: NetworkMessage,
}

impl Message {
    pub fn new(magic: [u8; 4], payload: NetworkMessage) -> Self {
        Self { magic, payload }
    }

    pub fn encode_to_bytes(&self) -> Vec<u8> {
        let command = self.payload.command();
        let payload_bytes = self.payload.encode_payload();

        let checksum = compute_checksum(&payload_bytes);

        let mut buf = Vec::new();
        buf.extend_from_slice(&self.magic);

        // Command: 12 bytes, null-padded
        let mut cmd_bytes = [0u8; 12];
        let cmd_str = command.as_bytes();
        cmd_bytes[..cmd_str.len().min(12)].copy_from_slice(&cmd_str[..cmd_str.len().min(12)]);
        buf.extend_from_slice(&cmd_bytes);

        // Payload length (4 bytes LE)
        buf.extend_from_slice(&(payload_bytes.len() as u32).to_le_bytes());

        // Checksum (4 bytes)
        buf.extend_from_slice(&checksum);

        // Payload
        buf.extend_from_slice(&payload_bytes);
        buf
    }

    /// Read a single message from a reader
    pub async fn read_from<R: tokio::io::AsyncReadExt + Unpin>(
        reader: &mut R,
        expected_magic: &[u8; 4],
    ) -> Result<Self> {
        // Read 24-byte header
        let mut header = [0u8; 24];
        reader.read_exact(&mut header).await?;

        let magic: [u8; 4] = header[0..4].try_into().unwrap();
        let expected_magic_u32 = u32::from_le_bytes(*expected_magic);
        let got_magic_u32 = u32::from_le_bytes(magic);

        if magic != *expected_magic {
            return Err(NetError::InvalidMagic {
                expected: expected_magic_u32,
                got: got_magic_u32,
            });
        }

        let command_bytes: [u8; 12] = header[4..16].try_into().unwrap();
        let length = u32::from_le_bytes(header[16..20].try_into().unwrap());
        let checksum: [u8; 4] = header[20..24].try_into().unwrap();

        if length > MAX_MESSAGE_SIZE {
            return Err(NetError::MessageTooLarge(length));
        }

        let mut payload_bytes = vec![0u8; length as usize];
        reader.read_exact(&mut payload_bytes).await?;

        // Verify checksum
        let computed = compute_checksum(&payload_bytes);
        if computed != checksum {
            return Err(NetError::ChecksumMismatch);
        }

        // Parse command
        let cmd = parse_command(&command_bytes);
        let payload = NetworkMessage::decode_payload(&cmd, &payload_bytes)?;

        Ok(Self { magic, payload })
    }
}

fn compute_checksum(payload: &[u8]) -> [u8; 4] {
    let hash = sha256d(payload);
    [hash.0[0], hash.0[1], hash.0[2], hash.0[3]]
}

fn parse_command(bytes: &[u8; 12]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(12);
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Bitcoin inventory item type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvType {
    Error = 0,
    Tx = 1,
    Block = 2,
    FilteredBlock = 3,
    CmpctBlock = 4,
    WitnessTx = 0x40000001,
    WitnessBlock = 0x40000002,
}

impl InvType {
    pub fn from_u32(n: u32) -> Self {
        match n {
            1 => Self::Tx,
            2 => Self::Block,
            3 => Self::FilteredBlock,
            4 => Self::CmpctBlock,
            0x40000001 => Self::WitnessTx,
            0x40000002 => Self::WitnessBlock,
            _ => Self::Error,
        }
    }
}

/// An inventory item (type + hash)
#[derive(Debug, Clone)]
pub struct Inventory {
    pub inv_type: InvType,
    pub hash: Hash256,
}

impl Encodable for Inventory {
    fn encode<W: Write>(&self, w: &mut W) -> rbtc_primitives::codec::Result<usize> {
        let mut n = (self.inv_type as u32).encode(w)?;
        n += self.hash.0.encode(w)?;
        Ok(n)
    }
}

impl Decodable for Inventory {
    fn decode<R: Read>(r: &mut R) -> rbtc_primitives::codec::Result<Self> {
        let t = u32::decode(r)?;
        let hash = Hash256(<[u8; 32]>::decode(r)?);
        Ok(Self { inv_type: InvType::from_u32(t), hash })
    }
}

/// Version message payload
#[derive(Debug, Clone)]
pub struct VersionMessage {
    pub version: i32,
    pub services: u64,
    pub timestamp: i64,
    pub recv_services: u64,
    pub recv_addr: [u8; 16],
    pub recv_port: u16,
    pub from_services: u64,
    pub from_addr: [u8; 16],
    pub from_port: u16,
    pub nonce: u64,
    pub user_agent: String,
    pub start_height: i32,
    pub relay: bool,
}

impl VersionMessage {
    pub fn new(best_height: i32, nonce: u64) -> Self {
        Self {
            version: 70016,
            services: LOCAL_SERVICES, // NODE_NETWORK | NODE_WITNESS
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
            recv_services: 0,
            recv_addr: [0u8; 16],
            recv_port: 0,
            from_services: LOCAL_SERVICES,
            from_addr: [0u8; 16],
            from_port: 0,
            nonce,
            user_agent: "/rbtc:0.1.0/".to_string(),
            start_height: best_height,
            relay: true,
        }
    }

    fn encode_payload(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.version.encode(&mut buf).ok();
        self.services.encode(&mut buf).ok();
        self.timestamp.encode(&mut buf).ok();
        // recv addr (26 bytes: 8 services + 16 IP + 2 port)
        self.recv_services.encode(&mut buf).ok();
        buf.extend_from_slice(&self.recv_addr);
        buf.extend_from_slice(&self.recv_port.to_be_bytes()); // port is big-endian!
        // from addr
        self.from_services.encode(&mut buf).ok();
        buf.extend_from_slice(&self.from_addr);
        buf.extend_from_slice(&self.from_port.to_be_bytes());
        self.nonce.encode(&mut buf).ok();
        // user_agent as varint-prefixed string
        VarInt(self.user_agent.len() as u64).encode(&mut buf).ok();
        buf.extend_from_slice(self.user_agent.as_bytes());
        self.start_height.encode(&mut buf).ok();
        buf.push(if self.relay { 1 } else { 0 });
        buf
    }

    fn decode_payload(data: &[u8]) -> Result<Self> {
        let mut cur = std::io::Cursor::new(data);
        let version = i32::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
        let services = u64::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
        let timestamp = i64::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
        let recv_services = u64::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
        let mut recv_addr = [0u8; 16];
        std::io::Read::read_exact(&mut cur, &mut recv_addr).map_err(|e| NetError::Decode(e.to_string()))?;
        let mut port_bytes = [0u8; 2];
        std::io::Read::read_exact(&mut cur, &mut port_bytes).map_err(|e| NetError::Decode(e.to_string()))?;
        let recv_port = u16::from_be_bytes(port_bytes);
        let from_services = u64::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
        let mut from_addr = [0u8; 16];
        std::io::Read::read_exact(&mut cur, &mut from_addr).map_err(|e| NetError::Decode(e.to_string()))?;
        let mut from_port_bytes = [0u8; 2];
        std::io::Read::read_exact(&mut cur, &mut from_port_bytes).map_err(|e| NetError::Decode(e.to_string()))?;
        let from_port = u16::from_be_bytes(from_port_bytes);
        let nonce = u64::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
        let VarInt(ua_len) = VarInt::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
        let mut ua_bytes = vec![0u8; ua_len as usize];
        std::io::Read::read_exact(&mut cur, &mut ua_bytes).map_err(|e| NetError::Decode(e.to_string()))?;
        let user_agent = String::from_utf8_lossy(&ua_bytes).into_owned();
        let start_height = i32::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
        let relay_byte = u8::decode(&mut cur).unwrap_or(1);

        Ok(Self {
            version, services, timestamp,
            recv_services, recv_addr, recv_port,
            from_services, from_addr, from_port,
            nonce, user_agent, start_height,
            relay: relay_byte != 0,
        })
    }
}

/// GetBlocks / GetHeaders message
#[derive(Debug, Clone)]
pub struct GetBlocksMessage {
    pub version: u32,
    pub locator_hashes: Vec<BlockHash>,
    pub stop_hash: BlockHash,
}

impl GetBlocksMessage {
    pub fn new(locator: Vec<BlockHash>) -> Self {
        Self {
            version: 70016,
            locator_hashes: locator,
            stop_hash: Hash256::ZERO,
        }
    }

    fn encode_payload(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.version.encode(&mut buf).ok();
        VarInt(self.locator_hashes.len() as u64).encode(&mut buf).ok();
        for h in &self.locator_hashes {
            h.0.encode(&mut buf).ok();
        }
        self.stop_hash.0.encode(&mut buf).ok();
        buf
    }

    fn decode_payload(data: &[u8]) -> Result<Self> {
        let mut cur = std::io::Cursor::new(data);
        let version = u32::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
        let VarInt(count) = VarInt::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
        let mut locator_hashes = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let h = <[u8; 32]>::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
            locator_hashes.push(Hash256(h));
        }
        let stop = <[u8; 32]>::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
        Ok(Self { version, locator_hashes, stop_hash: Hash256(stop) })
    }
}

/// Headers message
#[derive(Debug, Clone)]
pub struct HeadersMessage {
    pub headers: Vec<BlockHeader>,
}

impl HeadersMessage {
    fn encode_payload(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        VarInt(self.headers.len() as u64).encode(&mut buf).ok();
        for h in &self.headers {
            h.encode(&mut buf).ok();
            // Each header followed by 0x00 (tx count)
            buf.push(0);
        }
        buf
    }

    fn decode_payload(data: &[u8]) -> Result<Self> {
        let mut cur = std::io::Cursor::new(data);
        let VarInt(count) = VarInt::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
        let mut headers = Vec::with_capacity(count.min(2000) as usize);
        for _ in 0..count {
            let h = BlockHeader::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
            let _tx_count = u8::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
            headers.push(h);
        }
        Ok(Self { headers })
    }
}

/// Ping/Pong message
#[derive(Debug, Clone)]
pub struct PingMessage {
    pub nonce: u64,
}

/// Addr message (peer addresses)
#[derive(Debug, Clone)]
pub struct AddrMessage {
    pub addrs: Vec<(u32, u64, [u8; 16], u16)>, // (timestamp, services, ip, port)
}

// ── BIP155: addrv2 ──────────────────────────────────────────────────────────

/// BIP155 network ID for addrv2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Addrv2NetId {
    Ipv4 = 1,
    Ipv6 = 2,
    TorV2 = 3,   // deprecated
    TorV3 = 4,
    I2p   = 5,
    Cjdns = 6,
}

impl Addrv2NetId {
    pub fn from_u8(n: u8) -> Option<Self> {
        match n {
            1 => Some(Self::Ipv4),
            2 => Some(Self::Ipv6),
            3 => Some(Self::TorV2),
            4 => Some(Self::TorV3),
            5 => Some(Self::I2p),
            6 => Some(Self::Cjdns),
            _ => None,
        }
    }

    /// Expected address length for this network type.
    pub fn addr_len(&self) -> Option<usize> {
        match self {
            Self::Ipv4  => Some(4),
            Self::Ipv6  => Some(16),
            Self::TorV2 => Some(10),
            Self::TorV3 => Some(32),
            Self::I2p   => Some(32),
            Self::Cjdns => Some(16),
        }
    }
}

/// A single address entry in a BIP155 addrv2 message.
#[derive(Debug, Clone)]
pub struct Addrv2Entry {
    pub timestamp: u32,
    pub services: u64,  // CompactSize-encoded in wire format
    pub net_id: u8,
    pub addr: Vec<u8>,
    pub port: u16,
}

/// BIP155 addrv2 message
#[derive(Debug, Clone)]
pub struct Addrv2Message {
    pub addrs: Vec<Addrv2Entry>,
}

impl Addrv2Message {
    fn encode_payload(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        VarInt(self.addrs.len() as u64).encode(&mut buf).ok();
        for entry in &self.addrs {
            entry.timestamp.encode(&mut buf).ok();
            VarInt(entry.services).encode(&mut buf).ok();
            buf.push(entry.net_id);
            VarInt(entry.addr.len() as u64).encode(&mut buf).ok();
            buf.extend_from_slice(&entry.addr);
            buf.extend_from_slice(&entry.port.to_be_bytes());
        }
        buf
    }

    fn decode_payload(data: &[u8]) -> Result<Self> {
        let mut cur = std::io::Cursor::new(data);
        let VarInt(count) = VarInt::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
        let count = count.min(1000) as usize; // BIP155: max 1000 entries
        let mut addrs = Vec::with_capacity(count);
        for _ in 0..count {
            let timestamp = u32::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
            let VarInt(services) = VarInt::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
            let net_id = u8::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
            let VarInt(addr_len) = VarInt::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
            let mut addr = vec![0u8; addr_len as usize];
            std::io::Read::read_exact(&mut cur, &mut addr).map_err(|e| NetError::Decode(e.to_string()))?;
            let mut port_bytes = [0u8; 2];
            std::io::Read::read_exact(&mut cur, &mut port_bytes).map_err(|e| NetError::Decode(e.to_string()))?;
            let port = u16::from_be_bytes(port_bytes);
            addrs.push(Addrv2Entry { timestamp, services, net_id, addr, port });
        }
        Ok(Self { addrs })
    }
}

// ── BIP157: Compact Block Filters ─────────────────────────────────────────

/// BIP157 getcfilters / getcfheaders request (same wire layout).
#[derive(Debug, Clone)]
pub struct GetCFiltersMessage {
    pub filter_type: u8,
    pub start_height: u32,
    pub stop_hash: Hash256,
}

impl GetCFiltersMessage {
    fn encode_payload(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(37);
        buf.push(self.filter_type);
        buf.extend_from_slice(&self.start_height.to_le_bytes());
        buf.extend_from_slice(&self.stop_hash.0);
        buf
    }

    fn decode_payload(data: &[u8]) -> Result<Self> {
        if data.len() < 37 {
            return Err(NetError::Decode("getcfilters too short".into()));
        }
        let filter_type = data[0];
        let start_height = u32::from_le_bytes(data[1..5].try_into().unwrap());
        let mut stop_hash = [0u8; 32];
        stop_hash.copy_from_slice(&data[5..37]);
        Ok(Self { filter_type, start_height, stop_hash: Hash256(stop_hash) })
    }
}

/// BIP157 cfilter response.
#[derive(Debug, Clone)]
pub struct CFilterMessage {
    pub filter_type: u8,
    pub block_hash: Hash256,
    pub filter: Vec<u8>,
}

impl CFilterMessage {
    fn encode_payload(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(33 + self.filter.len());
        buf.push(self.filter_type);
        buf.extend_from_slice(&self.block_hash.0);
        buf.extend_from_slice(&self.filter);
        buf
    }

    fn decode_payload(data: &[u8]) -> Result<Self> {
        if data.len() < 33 {
            return Err(NetError::Decode("cfilter too short".into()));
        }
        let filter_type = data[0];
        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&data[1..33]);
        let filter = data[33..].to_vec();
        Ok(Self { filter_type, block_hash: Hash256(block_hash), filter })
    }
}

/// BIP157 cfheaders response.
#[derive(Debug, Clone)]
pub struct CFHeadersMessage {
    pub filter_type: u8,
    pub stop_hash: Hash256,
    pub prev_filter_header: Hash256,
    pub filter_hashes: Vec<Hash256>,
}

impl CFHeadersMessage {
    fn encode_payload(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(65 + self.filter_hashes.len() * 32 + 3);
        buf.push(self.filter_type);
        buf.extend_from_slice(&self.stop_hash.0);
        buf.extend_from_slice(&self.prev_filter_header.0);
        VarInt(self.filter_hashes.len() as u64).encode(&mut buf).ok();
        for h in &self.filter_hashes {
            buf.extend_from_slice(&h.0);
        }
        buf
    }

    fn decode_payload(data: &[u8]) -> Result<Self> {
        if data.len() < 65 {
            return Err(NetError::Decode("cfheaders too short".into()));
        }
        let filter_type = data[0];
        let mut stop_hash = [0u8; 32];
        stop_hash.copy_from_slice(&data[1..33]);
        let mut prev_filter_header = [0u8; 32];
        prev_filter_header.copy_from_slice(&data[33..65]);
        let mut cur = std::io::Cursor::new(&data[65..]);
        let VarInt(count) = VarInt::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
        let mut filter_hashes = Vec::with_capacity(count.min(2000) as usize);
        for _ in 0..count {
            let h = <[u8; 32]>::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
            filter_hashes.push(Hash256(h));
        }
        Ok(Self {
            filter_type,
            stop_hash: Hash256(stop_hash),
            prev_filter_header: Hash256(prev_filter_header),
            filter_hashes,
        })
    }
}

/// BIP157 getcfcheckpt request.
#[derive(Debug, Clone)]
pub struct GetCFCheckptMessage {
    pub filter_type: u8,
    pub stop_hash: Hash256,
}

impl GetCFCheckptMessage {
    fn encode_payload(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(33);
        buf.push(self.filter_type);
        buf.extend_from_slice(&self.stop_hash.0);
        buf
    }

    fn decode_payload(data: &[u8]) -> Result<Self> {
        if data.len() < 33 {
            return Err(NetError::Decode("getcfcheckpt too short".into()));
        }
        let filter_type = data[0];
        let mut stop_hash = [0u8; 32];
        stop_hash.copy_from_slice(&data[1..33]);
        Ok(Self { filter_type, stop_hash: Hash256(stop_hash) })
    }
}

/// BIP157 cfcheckpt response.
#[derive(Debug, Clone)]
pub struct CFCheckptMessage {
    pub filter_type: u8,
    pub stop_hash: Hash256,
    pub filter_headers: Vec<Hash256>,
}

impl CFCheckptMessage {
    fn encode_payload(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(33 + self.filter_headers.len() * 32 + 3);
        buf.push(self.filter_type);
        buf.extend_from_slice(&self.stop_hash.0);
        VarInt(self.filter_headers.len() as u64).encode(&mut buf).ok();
        for h in &self.filter_headers {
            buf.extend_from_slice(&h.0);
        }
        buf
    }

    fn decode_payload(data: &[u8]) -> Result<Self> {
        if data.len() < 33 {
            return Err(NetError::Decode("cfcheckpt too short".into()));
        }
        let filter_type = data[0];
        let mut stop_hash = [0u8; 32];
        stop_hash.copy_from_slice(&data[1..33]);
        let mut cur = std::io::Cursor::new(&data[33..]);
        let VarInt(count) = VarInt::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
        let mut filter_headers = Vec::with_capacity(count.min(2000) as usize);
        for _ in 0..count {
            let h = <[u8; 32]>::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
            filter_headers.push(Hash256(h));
        }
        Ok(Self {
            filter_type,
            stop_hash: Hash256(stop_hash),
            filter_headers,
        })
    }
}

/// All supported network message types
#[derive(Debug, Clone)]
pub enum NetworkMessage {
    Version(VersionMessage),
    Verack,
    Ping(u64),
    Pong(u64),
    GetHeaders(GetBlocksMessage),
    GetBlocks(GetBlocksMessage),
    Headers(HeadersMessage),
    Inv(Vec<Inventory>),
    GetData(Vec<Inventory>),
    NotFound(Vec<Inventory>),
    Block(Block),
    Tx(Transaction),
    Addr(AddrMessage),
    SendHeaders,
    FeeFilter(u64),
    SendCmpct(bool, u64),
    /// BIP152: compact block announcement
    CmpctBlock(crate::compact::CompactBlock),
    /// BIP152: request missing transactions from a compact block
    GetBlockTxn(crate::compact::GetBlockTxn),
    /// BIP152: response with missing transactions
    BlockTxn(crate::compact::BlockTxn),
    GetAddr,
    Reject { message: String, code: u8, reason: String },
    /// BIP339: signal wtxid-based tx relay (sent before verack)
    WtxidRelay,
    /// BIP155: signal preference for addrv2 messages (sent before verack)
    SendAddrv2,
    /// BIP155: extended address message with variable-length network addresses
    Addrv2(Addrv2Message),
    /// Request peer to send inv for all txids in its mempool
    Mempool,
    /// BIP157: request compact block filters for a range of blocks
    GetCFilters(GetCFiltersMessage),
    /// BIP157: compact block filter for a single block
    CFilter(CFilterMessage),
    /// BIP157: request compact filter headers for a range of blocks
    GetCFHeaders(GetCFiltersMessage),
    /// BIP157: compact filter headers response
    CFHeaders(CFHeadersMessage),
    /// BIP157: request compact filter header checkpoints
    GetCFCheckpt(GetCFCheckptMessage),
    /// BIP157: compact filter header checkpoints response
    CFCheckpt(CFCheckptMessage),
    Unknown { command: String, data: Vec<u8> },
}

impl NetworkMessage {
    pub fn command(&self) -> &'static str {
        match self {
            Self::Version(_) => "version",
            Self::Verack => "verack",
            Self::Ping(_) => "ping",
            Self::Pong(_) => "pong",
            Self::GetHeaders(_) => "getheaders",
            Self::GetBlocks(_) => "getblocks",
            Self::Headers(_) => "headers",
            Self::Inv(_) => "inv",
            Self::GetData(_) => "getdata",
            Self::NotFound(_) => "notfound",
            Self::Block(_) => "block",
            Self::Tx(_) => "tx",
            Self::Addr(_) => "addr",
            Self::SendHeaders => "sendheaders",
            Self::FeeFilter(_) => "feefilter",
            Self::SendCmpct(_, _) => "sendcmpct",
            Self::CmpctBlock(_) => "cmpctblock",
            Self::GetBlockTxn(_) => "getblocktxn",
            Self::BlockTxn(_) => "blocktxn",
            Self::GetAddr => "getaddr",
            Self::Reject { .. } => "reject",
            Self::WtxidRelay => "wtxidrelay",
            Self::SendAddrv2 => "sendaddrv2",
            Self::Addrv2(_) => "addrv2",
            Self::Mempool => "mempool",
            Self::GetCFilters(_) => "getcfilters",
            Self::CFilter(_) => "cfilter",
            Self::GetCFHeaders(_) => "getcfheaders",
            Self::CFHeaders(_) => "cfheaders",
            Self::GetCFCheckpt(_) => "getcfcheckpt",
            Self::CFCheckpt(_) => "cfcheckpt",
            Self::Unknown { .. } => "unknown",
        }
    }

    pub fn encode_payload(&self) -> Vec<u8> {
        match self {
            Self::Version(v) => v.encode_payload(),
            Self::Verack => Vec::new(),
            Self::Ping(nonce) | Self::Pong(nonce) => nonce.to_le_bytes().to_vec(),
            Self::GetHeaders(m) | Self::GetBlocks(m) => m.encode_payload(),
            Self::Headers(m) => m.encode_payload(),
            Self::Inv(items) | Self::GetData(items) | Self::NotFound(items) => {
                let mut buf = Vec::new();
                encode_list(items, &mut buf).ok();
                buf
            }
            Self::Block(b) => b.encode_to_vec(),
            Self::Tx(tx) => tx.encode_to_vec(),
            Self::Addr(a) => {
                let mut buf = Vec::new();
                VarInt(a.addrs.len() as u64).encode(&mut buf).ok();
                for (ts, services, ip, port) in &a.addrs {
                    ts.encode(&mut buf).ok();
                    services.encode(&mut buf).ok();
                    buf.extend_from_slice(ip);
                    buf.extend_from_slice(&port.to_be_bytes());
                }
                buf
            }
            Self::SendHeaders => Vec::new(),
            Self::GetAddr => Vec::new(),
            Self::WtxidRelay => Vec::new(),
            Self::SendAddrv2 => Vec::new(),
            Self::Addrv2(m) => m.encode_payload(),
            Self::Mempool => Vec::new(),
            Self::GetCFilters(m) | Self::GetCFHeaders(m) => m.encode_payload(),
            Self::CFilter(m) => m.encode_payload(),
            Self::CFHeaders(m) => m.encode_payload(),
            Self::GetCFCheckpt(m) => m.encode_payload(),
            Self::CFCheckpt(m) => m.encode_payload(),
            Self::FeeFilter(rate) => rate.to_le_bytes().to_vec(),
            Self::SendCmpct(announce, version) => {
                let mut buf = vec![if *announce { 1u8 } else { 0u8 }];
                buf.extend_from_slice(&version.to_le_bytes());
                buf
            }
            Self::CmpctBlock(cb) => cb.encode_payload(),
            Self::GetBlockTxn(gbt) => gbt.encode_payload(),
            Self::BlockTxn(bt) => bt.encode_payload(),
            Self::Reject { message, code, reason } => {
                let mut buf = Vec::new();
                VarInt(message.len() as u64).encode(&mut buf).ok();
                buf.extend_from_slice(message.as_bytes());
                buf.push(*code);
                VarInt(reason.len() as u64).encode(&mut buf).ok();
                buf.extend_from_slice(reason.as_bytes());
                buf
            }
            Self::Unknown { data, .. } => data.clone(),
        }
    }

    pub fn decode_payload(command: &str, data: &[u8]) -> Result<Self> {
        let msg = match command {
            "version" => Self::Version(
                VersionMessage::decode_payload(data)?
            ),
            "verack" => Self::Verack,
            "ping" => {
                if data.len() >= 8 {
                    Self::Ping(u64::from_le_bytes(data[..8].try_into().unwrap()))
                } else {
                    Self::Ping(0)
                }
            }
            "pong" => {
                if data.len() >= 8 {
                    Self::Pong(u64::from_le_bytes(data[..8].try_into().unwrap()))
                } else {
                    Self::Pong(0)
                }
            }
            "getheaders" => Self::GetHeaders(GetBlocksMessage::decode_payload(data)?),
            "getblocks" => Self::GetBlocks(GetBlocksMessage::decode_payload(data)?),
            "headers" => Self::Headers(HeadersMessage::decode_payload(data)?),
            "inv" => {
                let items = decode_list::<Inventory, _>(&mut std::io::Cursor::new(data))
                    .map_err(|e| NetError::Decode(e.to_string()))?;
                Self::Inv(items)
            }
            "getdata" => {
                let items = decode_list::<Inventory, _>(&mut std::io::Cursor::new(data))
                    .map_err(|e| NetError::Decode(e.to_string()))?;
                Self::GetData(items)
            }
            "notfound" => {
                let items = decode_list::<Inventory, _>(&mut std::io::Cursor::new(data))
                    .map_err(|e| NetError::Decode(e.to_string()))?;
                Self::NotFound(items)
            }
            "block" => {
                let block = Block::decode_from_slice(data)
                    .map_err(|e| NetError::Decode(e.to_string()))?;
                Self::Block(block)
            }
            "tx" => {
                let tx = Transaction::decode_from_slice(data)
                    .map_err(|e| NetError::Decode(e.to_string()))?;
                Self::Tx(tx)
            }
            "sendheaders" => Self::SendHeaders,
            "getaddr" => Self::GetAddr,
            "wtxidrelay" => Self::WtxidRelay,
            "sendaddrv2" => Self::SendAddrv2,
            "addrv2" => Self::Addrv2(Addrv2Message::decode_payload(data)?),
            "mempool" => Self::Mempool,
            "getcfilters" => Self::GetCFilters(GetCFiltersMessage::decode_payload(data)?),
            "cfilter" => Self::CFilter(CFilterMessage::decode_payload(data)?),
            "getcfheaders" => Self::GetCFHeaders(GetCFiltersMessage::decode_payload(data)?),
            "cfheaders" => Self::CFHeaders(CFHeadersMessage::decode_payload(data)?),
            "getcfcheckpt" => Self::GetCFCheckpt(GetCFCheckptMessage::decode_payload(data)?),
            "cfcheckpt" => Self::CFCheckpt(CFCheckptMessage::decode_payload(data)?),
            "feefilter" if data.len() >= 8 => {
                Self::FeeFilter(u64::from_le_bytes(data[..8].try_into().unwrap()))
            }
            "sendcmpct" if data.len() >= 9 => {
                let announce = data[0] != 0;
                let version = u64::from_le_bytes(data[1..9].try_into().unwrap());
                Self::SendCmpct(announce, version)
            }
            "cmpctblock" => {
                let cb = crate::compact::CompactBlock::decode_payload(data)?;
                Self::CmpctBlock(cb)
            }
            "getblocktxn" => {
                let gbt = crate::compact::GetBlockTxn::decode_payload(data)?;
                Self::GetBlockTxn(gbt)
            }
            "blocktxn" => {
                let bt = crate::compact::BlockTxn::decode_payload(data)?;
                Self::BlockTxn(bt)
            }
            _ => Self::Unknown { command: command.to_string(), data: data.to_vec() },
        };
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::network::Network;

    #[test]
    fn message_encode_verack() {
        let magic = Network::Mainnet.magic();
        let msg = Message::new(magic, NetworkMessage::Verack);
        let bytes = msg.encode_to_bytes();
        assert!(bytes.len() >= 24);
        assert_eq!(&bytes[0..4], &magic[..]);
    }

    #[test]
    fn inv_type_from_u32() {
        assert_eq!(InvType::from_u32(1), InvType::Tx);
        assert_eq!(InvType::from_u32(2), InvType::Block);
        assert_eq!(InvType::from_u32(0), InvType::Error);
    }

    #[test]
    fn version_message_roundtrip() {
        let v = VersionMessage::new(0, 42);
        let payload = v.encode_payload();
        let decoded = VersionMessage::decode_payload(&payload).unwrap();
        assert_eq!(decoded.nonce, 42);
    }

    #[test]
    fn getblocks_message_roundtrip() {
        let m = GetBlocksMessage::new(vec![Hash256::ZERO]);
        let payload = m.encode_payload();
        let decoded = GetBlocksMessage::decode_payload(&payload).unwrap();
        assert_eq!(decoded.locator_hashes.len(), 1);
    }

    #[test]
    fn network_message_command() {
        assert_eq!(NetworkMessage::Verack.command(), "verack");
        assert_eq!(NetworkMessage::SendHeaders.command(), "sendheaders");
        assert_eq!(NetworkMessage::WtxidRelay.command(), "wtxidrelay");
        assert_eq!(NetworkMessage::SendAddrv2.command(), "sendaddrv2");
        assert_eq!(NetworkMessage::Mempool.command(), "mempool");
    }

    #[test]
    fn wtxidrelay_empty_payload() {
        let payload = NetworkMessage::WtxidRelay.encode_payload();
        assert!(payload.is_empty());
        let decoded = NetworkMessage::decode_payload("wtxidrelay", &[]).unwrap();
        assert!(matches!(decoded, NetworkMessage::WtxidRelay));
    }

    #[test]
    fn sendaddrv2_empty_payload() {
        let payload = NetworkMessage::SendAddrv2.encode_payload();
        assert!(payload.is_empty());
        let decoded = NetworkMessage::decode_payload("sendaddrv2", &[]).unwrap();
        assert!(matches!(decoded, NetworkMessage::SendAddrv2));
    }

    #[test]
    fn mempool_empty_payload() {
        let payload = NetworkMessage::Mempool.encode_payload();
        assert!(payload.is_empty());
        let decoded = NetworkMessage::decode_payload("mempool", &[]).unwrap();
        assert!(matches!(decoded, NetworkMessage::Mempool));
    }

    #[test]
    fn addrv2_roundtrip() {
        let msg = Addrv2Message {
            addrs: vec![
                Addrv2Entry {
                    timestamp: 1700000000,
                    services: LOCAL_SERVICES,
                    net_id: 1,      // IPv4
                    addr: vec![127, 0, 0, 1],
                    port: 8333,
                },
                Addrv2Entry {
                    timestamp: 1700000000,
                    services: 1,
                    net_id: 4, // TorV3
                    addr: vec![0xab; 32],
                    port: 9050,
                },
            ],
        };
        let payload = msg.encode_payload();
        let decoded_msg = NetworkMessage::decode_payload("addrv2", &payload).unwrap();
        match decoded_msg {
            NetworkMessage::Addrv2(m) => {
                assert_eq!(m.addrs.len(), 2);
                assert_eq!(m.addrs[0].net_id, 1);
                assert_eq!(m.addrs[0].addr, vec![127, 0, 0, 1]);
                assert_eq!(m.addrs[0].port, 8333);
                assert_eq!(m.addrs[1].net_id, 4);
                assert_eq!(m.addrs[1].addr.len(), 32);
            }
            _ => panic!("expected Addrv2"),
        }
    }

    #[test]
    fn addrv2_net_id() {
        assert_eq!(Addrv2NetId::from_u8(1), Some(Addrv2NetId::Ipv4));
        assert_eq!(Addrv2NetId::Ipv4.addr_len(), Some(4));
        assert_eq!(Addrv2NetId::from_u8(4), Some(Addrv2NetId::TorV3));
        assert_eq!(Addrv2NetId::TorV3.addr_len(), Some(32));
        assert_eq!(Addrv2NetId::from_u8(99), None);
    }

    #[test]
    fn service_flags_constants() {
        assert_eq!(LOCAL_SERVICES, NODE_NETWORK | NODE_WITNESS);
        assert_eq!(LOCAL_SERVICES, 0x09); // 1 | 8
        assert_eq!(NODE_BLOOM, 4);
        assert_eq!(NODE_COMPACT_FILTERS, 64);
        assert_eq!(NODE_NETWORK_LIMITED, 1024);
    }

    #[test]
    fn service_flags_to_string_display() {
        assert_eq!(service_flags_to_string(LOCAL_SERVICES), "NODE_NETWORK|NODE_WITNESS");
        assert_eq!(service_flags_to_string(0), "NONE");
        assert_eq!(
            service_flags_to_string(NODE_NETWORK | NODE_WITNESS | NODE_COMPACT_FILTERS),
            "NODE_NETWORK|NODE_WITNESS|NODE_COMPACT_FILTERS"
        );
    }

    #[test]
    fn bip157_getcfilters_roundtrip() {
        let msg = GetCFiltersMessage {
            filter_type: 0,
            start_height: 100,
            stop_hash: Hash256([0xab; 32]),
        };
        let payload = msg.encode_payload();
        let decoded = GetCFiltersMessage::decode_payload(&payload).unwrap();
        assert_eq!(decoded.filter_type, 0);
        assert_eq!(decoded.start_height, 100);
        assert_eq!(decoded.stop_hash, Hash256([0xab; 32]));
        // Via NetworkMessage
        let nm = NetworkMessage::GetCFilters(msg);
        assert_eq!(nm.command(), "getcfilters");
        let enc = nm.encode_payload();
        let dec = NetworkMessage::decode_payload("getcfilters", &enc).unwrap();
        assert!(matches!(dec, NetworkMessage::GetCFilters(_)));
    }

    #[test]
    fn bip157_cfilter_roundtrip() {
        let msg = CFilterMessage {
            filter_type: 0,
            block_hash: Hash256([0xcd; 32]),
            filter: vec![0x01, 0x02, 0x03, 0x04],
        };
        let payload = msg.encode_payload();
        let decoded = CFilterMessage::decode_payload(&payload).unwrap();
        assert_eq!(decoded.filter_type, 0);
        assert_eq!(decoded.block_hash, Hash256([0xcd; 32]));
        assert_eq!(decoded.filter, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn bip157_cfheaders_roundtrip() {
        let msg = CFHeadersMessage {
            filter_type: 0,
            stop_hash: Hash256([0x11; 32]),
            prev_filter_header: Hash256([0x22; 32]),
            filter_hashes: vec![Hash256([0x33; 32]), Hash256([0x44; 32])],
        };
        let payload = msg.encode_payload();
        let decoded = CFHeadersMessage::decode_payload(&payload).unwrap();
        assert_eq!(decoded.filter_type, 0);
        assert_eq!(decoded.stop_hash, Hash256([0x11; 32]));
        assert_eq!(decoded.prev_filter_header, Hash256([0x22; 32]));
        assert_eq!(decoded.filter_hashes.len(), 2);
        assert_eq!(decoded.filter_hashes[1], Hash256([0x44; 32]));
    }

    #[test]
    fn bip157_cfcheckpt_roundtrip() {
        let msg = CFCheckptMessage {
            filter_type: 0,
            stop_hash: Hash256([0x55; 32]),
            filter_headers: vec![Hash256([0x66; 32])],
        };
        let payload = msg.encode_payload();
        let decoded = CFCheckptMessage::decode_payload(&payload).unwrap();
        assert_eq!(decoded.filter_type, 0);
        assert_eq!(decoded.stop_hash, Hash256([0x55; 32]));
        assert_eq!(decoded.filter_headers.len(), 1);
    }

    #[test]
    fn bip157_getcfcheckpt_roundtrip() {
        let msg = GetCFCheckptMessage {
            filter_type: 0,
            stop_hash: Hash256([0x77; 32]),
        };
        let payload = msg.encode_payload();
        let decoded = GetCFCheckptMessage::decode_payload(&payload).unwrap();
        assert_eq!(decoded.filter_type, 0);
        assert_eq!(decoded.stop_hash, Hash256([0x77; 32]));
        let nm = NetworkMessage::GetCFCheckpt(msg);
        assert_eq!(nm.command(), "getcfcheckpt");
    }
}
