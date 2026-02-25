use rbtc_primitives::hash::{Hash160, Hash256};
use ripemd::{Digest as RipemdDigest, Ripemd160};
use sha2::{Digest, Sha256};

/// SHA-256 of data
pub fn sha256(data: &[u8]) -> Hash256 {
    let result = Sha256::digest(data);
    Hash256(result.into())
}

/// Double SHA-256 (SHA256d) – used for block hashes and txids
pub fn sha256d(data: &[u8]) -> Hash256 {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    Hash256(second.into())
}

/// RIPEMD-160(SHA-256(data)) – used for Bitcoin addresses
pub fn hash160(data: &[u8]) -> Hash160 {
    let sha = Sha256::digest(data);
    let ripe = Ripemd160::digest(sha);
    Hash160(ripe.into())
}

/// BIP340 / Taproot tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)
pub fn tagged_hash(tag: &[u8], msg: &[u8]) -> Hash256 {
    let tag_hash = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(&tag_hash);
    hasher.update(&tag_hash);
    hasher.update(msg);
    Hash256(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_deterministic() {
        let h = sha256(b"hello");
        assert_eq!(h.0.len(), 32);
        assert_eq!(sha256(b"hello"), sha256(b"hello"));
    }

    #[test]
    fn sha256d_deterministic() {
        let h = sha256d(b"hello");
        assert_eq!(h.0.len(), 32);
        assert_ne!(sha256d(b"hello"), sha256(b"hello"));
    }

    #[test]
    fn hash160_deterministic() {
        let h = hash160(b"hello");
        assert_eq!(h.0.len(), 20);
    }

    #[test]
    fn tagged_hash_deterministic() {
        let h = tagged_hash(b"TapSighash", b"");
        assert_eq!(h.0.len(), 32);
        assert_eq!(tagged_hash(b"tag", b"msg"), tagged_hash(b"tag", b"msg"));
    }
}
