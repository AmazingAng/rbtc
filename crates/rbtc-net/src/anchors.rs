//! Anchor connections — persisted block-relay-only peers.
//!
//! Bitcoin Core saves 2 block-relay-only peer addresses as "anchors" at
//! shutdown and prioritizes reconnecting to them at startup.  This provides
//! continuity of the block-relay topology across restarts and makes eclipse
//! attacks harder.

use std::io::{Read, Write};
use std::net::SocketAddr;

/// Maximum number of anchor peers to persist.
pub const MAX_ANCHORS: usize = 2;

/// File name used for anchor persistence (relative to data dir).
pub const ANCHORS_FILE: &str = "anchors.dat";

/// Serialize anchor addresses to bytes (simple newline-delimited text).
pub fn save_anchors(anchors: &[SocketAddr]) -> Vec<u8> {
    let limited = &anchors[..anchors.len().min(MAX_ANCHORS)];
    let mut buf = Vec::new();
    for addr in limited {
        writeln!(&mut buf, "{}", addr).ok();
    }
    buf
}

/// Deserialize anchor addresses from bytes.
pub fn load_anchors(data: &[u8]) -> Vec<SocketAddr> {
    let text = String::from_utf8_lossy(data);
    text.lines()
        .filter_map(|line| line.trim().parse::<SocketAddr>().ok())
        .take(MAX_ANCHORS)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn addr(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port))
    }

    #[test]
    fn save_load_roundtrip() {
        let addrs = vec![addr(1, 2, 3, 4, 8333), addr(5, 6, 7, 8, 8333)];
        let data = save_anchors(&addrs);
        let loaded = load_anchors(&data);
        assert_eq!(loaded, addrs);
    }

    #[test]
    fn save_limits_to_max() {
        let addrs = vec![
            addr(1, 2, 3, 4, 8333),
            addr(5, 6, 7, 8, 8333),
            addr(9, 10, 11, 12, 8333),
        ];
        let data = save_anchors(&addrs);
        let loaded = load_anchors(&data);
        assert_eq!(loaded.len(), MAX_ANCHORS);
    }

    #[test]
    fn load_empty() {
        let loaded = load_anchors(b"");
        assert!(loaded.is_empty());
    }

    #[test]
    fn load_ignores_invalid_lines() {
        let data = b"1.2.3.4:8333\nnot_an_addr\n5.6.7.8:8333\n";
        let loaded = load_anchors(data);
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0], addr(1, 2, 3, 4, 8333));
        assert_eq!(loaded[1], addr(5, 6, 7, 8, 8333));
    }

    #[test]
    fn anchors_file_constant() {
        assert_eq!(ANCHORS_FILE, "anchors.dat");
    }

    #[test]
    fn max_anchors_is_two() {
        assert_eq!(MAX_ANCHORS, 2);
    }
}
