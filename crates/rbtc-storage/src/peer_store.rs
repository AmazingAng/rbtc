use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    db::{Database, CF_ADDRMAN_META, CF_PEER_ADDRS, CF_PEER_BANS},
    error::Result,
};

/// Persistent peer address and ban storage.
pub struct PeerStore<'a> {
    db: &'a Database,
}

impl<'a> PeerStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    // ── Ban management ────────────────────────────────────────────────────────

    /// Ban `ip` for `duration`.  The expiry timestamp is stored in CF_PEER_BANS.
    pub fn ban(&self, ip: IpAddr, duration: Duration) -> Result<()> {
        let expiry = unix_now() + duration.as_secs();
        self.db
            .put_cf(CF_PEER_BANS, &ip_key(ip), &expiry.to_le_bytes())
    }

    /// Return true if `ip` is currently banned (expiry in the future).
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        match self.db.get_cf(CF_PEER_BANS, &ip_key(ip)) {
            Ok(Some(bytes)) if bytes.len() == 8 => {
                let expiry = u64::from_le_bytes(bytes.try_into().unwrap());
                expiry > unix_now()
            }
            _ => false,
        }
    }

    /// Remove all ban entries whose expiry timestamp is in the past.
    pub fn expire_bans(&self) -> Result<usize> {
        let now = unix_now();
        let mut expired_keys: Vec<Vec<u8>> = Vec::new();

        for (key, val) in self.db.iter_cf(CF_PEER_BANS)? {
            if val.len() == 8 {
                let expiry = u64::from_le_bytes(val[..8].try_into().unwrap());
                if expiry <= now {
                    expired_keys.push(key.to_vec());
                }
            }
        }

        let count = expired_keys.len();
        for key in expired_keys {
            self.db.delete_cf(CF_PEER_BANS, &key)?;
        }
        Ok(count)
    }

    // ── Address book ─────────────────────────────────────────────────────────

    /// Persist a list of known peer addresses.
    /// `last_seen` is a Unix timestamp (seconds), `services` is the peer's service bits.
    pub fn save_addrs(&self, addrs: &[(SocketAddr, u64, u64)]) -> Result<()> {
        let mut batch = self.db.new_batch();
        for (addr, last_seen, services) in addrs {
            let key = addr_key(*addr);
            let mut val = [0u8; 16];
            val[..8].copy_from_slice(&last_seen.to_le_bytes());
            val[8..].copy_from_slice(&services.to_le_bytes());
            self.db
                .batch_put_cf(&mut batch, CF_PEER_ADDRS, &key, &val)?;
        }
        self.db.write_batch(batch)
    }

    /// Load all stored peer addresses.
    /// Returns a list of `(addr, last_seen_unix, services)`.
    pub fn load_addrs(&self) -> Result<Vec<(SocketAddr, u64, u64)>> {
        let mut result = Vec::new();
        for (key, val) in self.db.iter_cf(CF_PEER_ADDRS)? {
            if key.len() == 18 && val.len() >= 16 {
                if let Some(addr) = decode_addr_key(&key) {
                    let last_seen = u64::from_le_bytes(val[..8].try_into().unwrap());
                    let services = u64::from_le_bytes(val[8..16].try_into().unwrap());
                    result.push((addr, last_seen, services));
                }
            }
        }
        Ok(result)
    }

    // ── AddrMan persistence ──────────────────────────────────────────────────

    /// Save the addrman secret key.
    pub fn save_addrman_key(&self, key: &[u8; 32]) -> Result<()> {
        self.db.put_cf(CF_ADDRMAN_META, b"secret_key", key)
    }

    /// Load the addrman secret key (None if not yet created).
    pub fn load_addrman_key(&self) -> Result<Option<[u8; 32]>> {
        match self.db.get_cf(CF_ADDRMAN_META, b"secret_key")? {
            Some(bytes) if bytes.len() == 32 => {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                Ok(Some(key))
            }
            _ => Ok(None),
        }
    }

    /// Save addrman entries in extended format.
    /// Value: last_seen(8) + services(8) + last_try(8) + last_success(8) + n_attempts(4) +
    ///        in_tried(1) + source_ip_port(18) = 55 bytes
    pub fn save_addrman_entries(&self, entries: &[AddrEntry]) -> Result<()> {
        // Clear existing entries first
        let existing: Vec<Vec<u8>> = self
            .db
            .iter_cf(CF_PEER_ADDRS)?
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        let mut batch = self.db.new_batch();
        for key in &existing {
            self.db.batch_delete_cf(&mut batch, CF_PEER_ADDRS, key)?;
        }
        for entry in entries {
            let key = addr_key(entry.addr);
            let mut val = vec![0u8; 55];
            val[0..8].copy_from_slice(&entry.last_seen.to_le_bytes());
            val[8..16].copy_from_slice(&entry.services.to_le_bytes());
            val[16..24].copy_from_slice(&entry.last_try.to_le_bytes());
            val[24..32].copy_from_slice(&entry.last_success.to_le_bytes());
            val[32..36].copy_from_slice(&entry.n_attempts.to_le_bytes());
            val[36] = if entry.in_tried { 1 } else { 0 };
            let source_key = addr_key(entry.source);
            val[37..55].copy_from_slice(&source_key);
            self.db
                .batch_put_cf(&mut batch, CF_PEER_ADDRS, &key, &val)?;
        }
        self.db.write_batch(batch)
    }

    /// Load addrman entries in extended format.
    pub fn load_addrman_entries(&self) -> Result<Vec<AddrEntry>> {
        let mut result = Vec::new();
        for (key, val) in self.db.iter_cf(CF_PEER_ADDRS)? {
            if key.len() == 18 && val.len() >= 55 {
                if let Some(addr) = decode_addr_key(&key) {
                    let last_seen = u64::from_le_bytes(val[0..8].try_into().unwrap());
                    let services = u64::from_le_bytes(val[8..16].try_into().unwrap());
                    let last_try = u64::from_le_bytes(val[16..24].try_into().unwrap());
                    let last_success = u64::from_le_bytes(val[24..32].try_into().unwrap());
                    let n_attempts = u32::from_le_bytes(val[32..36].try_into().unwrap());
                    let in_tried = val[36] != 0;
                    let source = decode_addr_key(&val[37..55])
                        .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0));
                    result.push(AddrEntry {
                        addr,
                        services,
                        last_seen,
                        last_try,
                        last_success,
                        n_attempts,
                        in_tried,
                        source,
                    });
                }
            } else if key.len() == 18 && val.len() == 16 {
                // Legacy format: just last_seen + services
                if let Some(addr) = decode_addr_key(&key) {
                    let last_seen = u64::from_le_bytes(val[..8].try_into().unwrap());
                    let services = u64::from_le_bytes(val[8..16].try_into().unwrap());
                    result.push(AddrEntry {
                        addr,
                        services,
                        last_seen,
                        last_try: 0,
                        last_success: 0,
                        n_attempts: 0,
                        in_tried: false,
                        source: SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
                    });
                }
            }
        }
        Ok(result)
    }
}

/// Extended address entry for addrman persistence.
pub struct AddrEntry {
    pub addr: SocketAddr,
    pub services: u64,
    pub last_seen: u64,
    pub last_try: u64,
    pub last_success: u64,
    pub n_attempts: u32,
    pub in_tried: bool,
    pub source: SocketAddr,
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Encode an `IpAddr` to a fixed-length byte key for CF_PEER_BANS.
/// IPv4 → 4 bytes, IPv6 → 16 bytes.
fn ip_key(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

/// Encode a `SocketAddr` to 18 bytes for CF_PEER_ADDRS.
/// Layout: 16 bytes IPv6 (IPv4-mapped) + 2 bytes port (BE).
fn addr_key(addr: SocketAddr) -> [u8; 18] {
    let mut key = [0u8; 18];
    let ip_bytes: [u8; 16] = match addr.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    };
    key[..16].copy_from_slice(&ip_bytes);
    key[16..].copy_from_slice(&addr.port().to_be_bytes());
    key
}

fn decode_addr_key(key: &[u8]) -> Option<SocketAddr> {
    if key.len() != 18 {
        return None;
    }
    let ip_bytes: [u8; 16] = key[..16].try_into().ok()?;
    let port = u16::from_be_bytes([key[16], key[17]]);
    let ip6 = Ipv6Addr::from(ip_bytes);
    let ip = if let Some(v4) = ip6.to_ipv4_mapped() {
        IpAddr::V4(v4)
    } else if let Some(v4) = ip6.to_ipv4() {
        IpAddr::V4(v4)
    } else {
        IpAddr::V6(ip6)
    };
    Some(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn open_db() -> (TempDir, Database) {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        (dir, db)
    }

    #[test]
    fn ban_and_is_banned() {
        let (_dir, db) = open_db();
        let store = PeerStore::new(&db);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(!store.is_banned(ip));
        store.ban(ip, Duration::from_secs(3600)).unwrap();
        assert!(store.is_banned(ip));
    }

    #[test]
    fn ban_expiry_is_not_banned_after_expire() {
        let (_dir, db) = open_db();
        let store = PeerStore::new(&db);
        let ip: IpAddr = "5.6.7.8".parse().unwrap();
        // Write an already-expired ban directly
        let past_expiry: u64 = 1; // epoch + 1s, definitely in the past
        db.put_cf(CF_PEER_BANS, &ip_key(ip), &past_expiry.to_le_bytes())
            .unwrap();
        assert!(!store.is_banned(ip));
        let count = store.expire_bans().unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn save_and_load_addrs() {
        let (_dir, db) = open_db();
        let store = PeerStore::new(&db);
        let addr1: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        let addr2: SocketAddr = "[::1]:8333".parse().unwrap();
        store
            .save_addrs(&[(addr1, 1000, 1), (addr2, 2000, 9)])
            .unwrap();
        let loaded = store.load_addrs().unwrap();
        assert_eq!(loaded.len(), 2);
        // Find addr1
        let entry1 = loaded.iter().find(|(a, _, _)| *a == addr1).unwrap();
        assert_eq!(entry1.1, 1000);
        assert_eq!(entry1.2, 1);
    }

    #[test]
    fn addr_key_roundtrip_ipv4() {
        let addr: SocketAddr = "192.168.1.1:18333".parse().unwrap();
        let key = addr_key(addr);
        let decoded = decode_addr_key(&key).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn addr_key_roundtrip_ipv6() {
        let addr: SocketAddr = "[2001:db8::1]:8333".parse().unwrap();
        let key = addr_key(addr);
        let decoded = decode_addr_key(&key).unwrap();
        assert_eq!(decoded.port(), addr.port());
    }
}
