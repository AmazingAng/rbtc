use rbtc_primitives::hash::{Hash160, Hash256};
use ripemd::{Digest as RipemdDigest, Ripemd160};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use sha3::Sha3_256;

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

/// SHA-1 – used for legacy protocols (Bitcoin Core CSHA1)
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let result = Sha1::digest(data);
    result.into()
}

/// SHA-512 – used for HMAC-SHA512 internals, Ed25519, etc. (Bitcoin Core CSHA512)
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let result = Sha512::digest(data);
    result.into()
}

/// SHA3-256 – used for SHA3 commitments (Bitcoin Core SHA3_256)
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let result = Sha3_256::digest(data);
    result.into()
}

/// BIP340 / Taproot tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)
pub fn tagged_hash(tag: &[u8], msg: &[u8]) -> Hash256 {
    let tag_hash = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(msg);
    Hash256(hasher.finalize().into())
}

/// Compute the BIP341 TapLeaf hash for a given leaf version and script.
///
/// `TapLeaf = tagged_hash("TapLeaf", leaf_version || compact_size(script.len()) || script)`
pub fn tap_leaf_hash(leaf_version: u8, script: &[u8]) -> Hash256 {
    let mut msg = Vec::with_capacity(1 + 5 + script.len());
    msg.push(leaf_version);
    // Encode script length as Bitcoin compact size (varint)
    let len = script.len() as u64;
    if len < 253 {
        msg.push(len as u8);
    } else if len <= 0xffff {
        msg.push(0xfd);
        msg.extend_from_slice(&(len as u16).to_le_bytes());
    } else if len <= 0xffff_ffff {
        msg.push(0xfe);
        msg.extend_from_slice(&(len as u32).to_le_bytes());
    } else {
        msg.push(0xff);
        msg.extend_from_slice(&len.to_le_bytes());
    }
    msg.extend_from_slice(script);
    tagged_hash(b"TapLeaf", &msg)
}

/// Compute the BIP341 TapTweak hash for key tweaking.
///
/// `TapTweak = tagged_hash("TapTweak", pubkey || merkle_root)`
/// If merkle_root is None (key-path only, no scripts), hashes just the pubkey.
/// Matches Bitcoin Core `XOnlyPubKey::ComputeTapTweakHash`.
pub fn tap_tweak_hash(pubkey: &[u8; 32], merkle_root: Option<&[u8; 32]>) -> Hash256 {
    let mut msg = Vec::with_capacity(64);
    msg.extend_from_slice(pubkey);
    if let Some(root) = merkle_root {
        msg.extend_from_slice(root);
    }
    tagged_hash(b"TapTweak", &msg)
}

/// Compute the BIP341 TapBranch hash from two child hashes.
///
/// `TapBranch = tagged_hash("TapBranch", sorted(a, b))`
/// The two children are sorted lexicographically before hashing.
pub fn tap_branch_hash(a: &Hash256, b: &Hash256) -> Hash256 {
    let mut msg = [0u8; 64];
    if a.0 <= b.0 {
        msg[..32].copy_from_slice(&a.0);
        msg[32..].copy_from_slice(&b.0);
    } else {
        msg[..32].copy_from_slice(&b.0);
        msg[32..].copy_from_slice(&a.0);
    }
    tagged_hash(b"TapBranch", &msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_known_vector() {
        // SHA1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        let result = sha1(b"abc");
        let expected = hex::decode("a9993e364706816aba3e25717850c26c9cd0d89d").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn sha512_known_vector() {
        // SHA512("abc") from NIST
        let result = sha512(b"abc");
        let expected = hex::decode(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        )
        .unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn sha3_256_known_vector() {
        // SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
        let result = sha3_256(b"");
        let expected =
            hex::decode("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
                .unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

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

    #[test]
    fn tap_leaf_hash_deterministic() {
        let script = vec![0xac]; // OP_CHECKSIG
        let h1 = tap_leaf_hash(0xc0, &script);
        let h2 = tap_leaf_hash(0xc0, &script);
        assert_eq!(h1, h2);
        assert_eq!(h1.0.len(), 32);
        // Different leaf version → different hash
        let h3 = tap_leaf_hash(0xc2, &script);
        assert_ne!(h1, h3);
    }

    #[test]
    fn tap_leaf_hash_known_vector() {
        // Leaf version 0xc0, script = OP_1 (0x51)
        // This should match: tagged_hash("TapLeaf", 0xc0 || 0x01 || 0x51)
        let expected = tagged_hash(b"TapLeaf", &[0xc0, 0x01, 0x51]);
        let computed = tap_leaf_hash(0xc0, &[0x51]);
        assert_eq!(computed, expected);
    }

    #[test]
    fn tap_tweak_hash_no_script() {
        // BIP341 test vector #0: key-path only (no script tree)
        let pubkey: [u8; 32] =
            hex::decode("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d")
                .unwrap()
                .try_into()
                .unwrap();
        let tweak = tap_tweak_hash(&pubkey, None);
        assert_eq!(
            hex::encode(tweak.0),
            "b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70"
        );
    }

    #[test]
    fn tap_tweak_hash_with_merkle_root() {
        // BIP341 test vector #1: internalPubkey + merkleRoot → tweak
        let pubkey: [u8; 32] =
            hex::decode("187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27")
                .unwrap()
                .try_into()
                .unwrap();
        let merkle_root: [u8; 32] =
            hex::decode("5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21")
                .unwrap()
                .try_into()
                .unwrap();
        let tweak = tap_tweak_hash(&pubkey, Some(&merkle_root));
        assert_eq!(
            hex::encode(tweak.0),
            "cbd8679ba636c1110ea247542cfbd964131a6be84f873f7f3b62a777528ed001"
        );
    }

    #[test]
    fn tap_tweak_hash_consistent_with_tagged_hash() {
        // tap_tweak_hash(pk, None) == tagged_hash("TapTweak", pk)
        let pk = [0xaa; 32];
        assert_eq!(tap_tweak_hash(&pk, None), tagged_hash(b"TapTweak", &pk));
        // tap_tweak_hash(pk, Some(root)) == tagged_hash("TapTweak", pk || root)
        let root = [0xbb; 32];
        let mut msg = Vec::new();
        msg.extend_from_slice(&pk);
        msg.extend_from_slice(&root);
        assert_eq!(
            tap_tweak_hash(&pk, Some(&root)),
            tagged_hash(b"TapTweak", &msg)
        );
    }

    #[test]
    fn tap_branch_hash_sorted() {
        let a = Hash256([0x01; 32]);
        let b = Hash256([0x02; 32]);
        // tap_branch_hash should sort: a < b, so (a, b) and (b, a) give same result
        assert_eq!(tap_branch_hash(&a, &b), tap_branch_hash(&b, &a));
    }
}
