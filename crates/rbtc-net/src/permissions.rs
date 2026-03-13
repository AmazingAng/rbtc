//! Net permissions and whitelisting.
//!
//! Bitcoin Core's `-whitelist` flag grants trusted peers various exemptions
//! from normal P2P policy.  This module provides the `NetPermissions` flags
//! and a helper to check whether a peer IP is whitelisted.

use std::collections::HashSet;
use std::net::IpAddr;

/// Permission flags that can be granted to whitelisted peers.
///
/// Mirrors Bitcoin Core's `NetPermissionFlags` in `net_permissions.h`.
/// Stored as a `u32` bitfield.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetPermissions(pub u32);

impl NetPermissions {
    /// No permissions.
    pub const NONE: Self = Self(0);
    /// Allow peer to request BIP37 bloom filters even if NODE_BLOOM is off.
    pub const BLOOM_FILTER: Self = Self(1 << 0);
    /// Relay transactions to this peer even if not in mempool policy.
    pub const RELAY: Self = Self(1 << 1);
    /// Force-relay transactions from this peer (override fee filter, etc.).
    pub const FORCE_RELAY: Self = Self(1 << 2);
    /// Never ban this peer for misbehavior.
    pub const NO_BAN: Self = Self(1 << 3);
    /// Allow this peer to request mempool contents (BIP35 `mempool` msg).
    pub const MEMPOOL: Self = Self(1 << 4);
    /// Allow downloading blocks/txs from this peer even during IBD.
    pub const DOWNLOAD: Self = Self(1 << 5);
    /// Allow receiving addr messages from this peer.
    pub const ADDR: Self = Self(1 << 6);
    /// Treat as an implicit P2P connection (internal).
    pub const IMPLICIT_P2P: Self = Self(1 << 7);

    /// Full set of permissions.
    pub const ALL: Self = Self(0xFF);

    /// Default permissions granted to whitelisted peers.
    /// Matches Bitcoin Core's default whitelist permissions.
    pub fn default_whitelist() -> Self {
        Self(Self::RELAY.0 | Self::NO_BAN.0 | Self::MEMPOOL.0 | Self::DOWNLOAD.0)
    }

    /// Check if a specific flag is set.
    pub fn has(self, flag: Self) -> bool {
        (self.0 & flag.0) == flag.0
    }

    /// Combine two permission sets.
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Check if no permissions are set.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// A whitelist of trusted peer IPs and the permissions they receive.
#[derive(Debug, Clone)]
pub struct Whitelist {
    /// Set of whitelisted IP addresses.
    pub ips: HashSet<IpAddr>,
    /// Permissions granted to whitelisted peers.
    pub permissions: NetPermissions,
}

impl Whitelist {
    /// Create an empty whitelist with default permissions.
    pub fn new() -> Self {
        Self {
            ips: HashSet::new(),
            permissions: NetPermissions::default_whitelist(),
        }
    }

    /// Create a whitelist with specific IPs and permissions.
    pub fn with_ips(ips: HashSet<IpAddr>, permissions: NetPermissions) -> Self {
        Self { ips, permissions }
    }

    /// Check whether a peer IP is whitelisted.
    pub fn is_whitelisted(&self, ip: &IpAddr) -> bool {
        self.ips.contains(ip)
    }

    /// Get permissions for a peer IP. Returns empty permissions if not whitelisted.
    pub fn permissions_for(&self, ip: &IpAddr) -> NetPermissions {
        if self.ips.contains(ip) {
            self.permissions
        } else {
            NetPermissions::NONE
        }
    }

    /// Add an IP to the whitelist.
    pub fn add(&mut self, ip: IpAddr) {
        self.ips.insert(ip);
    }

    /// Remove an IP from the whitelist.
    pub fn remove(&mut self, ip: &IpAddr) -> bool {
        self.ips.remove(ip)
    }
}

impl Default for Whitelist {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn default_whitelist_permissions() {
        let perms = NetPermissions::default_whitelist();
        assert!(perms.has(NetPermissions::RELAY));
        assert!(perms.has(NetPermissions::NO_BAN));
        assert!(perms.has(NetPermissions::MEMPOOL));
        assert!(perms.has(NetPermissions::DOWNLOAD));
        assert!(!perms.has(NetPermissions::BLOOM_FILTER));
        assert!(!perms.has(NetPermissions::FORCE_RELAY));
    }

    #[test]
    fn all_permissions() {
        let all = NetPermissions::ALL;
        assert!(all.has(NetPermissions::BLOOM_FILTER));
        assert!(all.has(NetPermissions::RELAY));
        assert!(all.has(NetPermissions::FORCE_RELAY));
        assert!(all.has(NetPermissions::NO_BAN));
        assert!(all.has(NetPermissions::MEMPOOL));
        assert!(all.has(NetPermissions::DOWNLOAD));
        assert!(all.has(NetPermissions::ADDR));
        assert!(all.has(NetPermissions::IMPLICIT_P2P));
    }

    #[test]
    fn whitelist_check() {
        let ip1: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut wl = Whitelist::new();
        wl.add(ip1);

        assert!(wl.is_whitelisted(&ip1));
        assert!(!wl.is_whitelisted(&ip2));
    }

    #[test]
    fn whitelist_permissions_for() {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let other: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut wl = Whitelist::new();
        wl.add(ip);

        let perms = wl.permissions_for(&ip);
        assert!(perms.has(NetPermissions::NO_BAN));

        let no_perms = wl.permissions_for(&other);
        assert!(no_perms.is_empty());
    }

    #[test]
    fn whitelist_remove() {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let mut wl = Whitelist::new();
        wl.add(ip);
        assert!(wl.is_whitelisted(&ip));
        assert!(wl.remove(&ip));
        assert!(!wl.is_whitelisted(&ip));
    }

    #[test]
    fn whitelist_with_custom_permissions() {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let mut ips = HashSet::new();
        ips.insert(ip);
        let wl = Whitelist::with_ips(ips, NetPermissions::ALL);
        let perms = wl.permissions_for(&ip);
        assert!(perms.has(NetPermissions::BLOOM_FILTER));
        assert!(perms.has(NetPermissions::FORCE_RELAY));
    }

    #[test]
    fn no_ban_flag_check() {
        let perms = NetPermissions::NO_BAN;
        assert!(perms.has(NetPermissions::NO_BAN));
        assert!(!perms.has(NetPermissions::RELAY));
    }

    #[test]
    fn union_combines_flags() {
        let a = NetPermissions::RELAY;
        let b = NetPermissions::NO_BAN;
        let combined = a.union(b);
        assert!(combined.has(NetPermissions::RELAY));
        assert!(combined.has(NetPermissions::NO_BAN));
        assert!(!combined.has(NetPermissions::MEMPOOL));
    }

    #[test]
    fn none_is_empty() {
        assert!(NetPermissions::NONE.is_empty());
        assert!(!NetPermissions::RELAY.is_empty());
    }
}
