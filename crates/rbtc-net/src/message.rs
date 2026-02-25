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
            services: 0x0000000000000409, // NODE_NETWORK | NODE_BLOOM | NODE_WITNESS
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
            recv_services: 0,
            recv_addr: [0u8; 16],
            recv_port: 0,
            from_services: 0x0000000000000409,
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
    GetAddr,
    Reject { message: String, code: u8, reason: String },
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
            Self::GetAddr => "getaddr",
            Self::Reject { .. } => "reject",
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
            Self::FeeFilter(rate) => rate.to_le_bytes().to_vec(),
            Self::SendCmpct(announce, version) => {
                let mut buf = vec![if *announce { 1u8 } else { 0u8 }];
                buf.extend_from_slice(&version.to_le_bytes());
                buf
            }
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
            "feefilter" if data.len() >= 8 => {
                Self::FeeFilter(u64::from_le_bytes(data[..8].try_into().unwrap()))
            }
            "sendcmpct" if data.len() >= 9 => {
                let announce = data[0] != 0;
                let version = u64::from_le_bytes(data[1..9].try_into().unwrap());
                Self::SendCmpct(announce, version)
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
    }
}
