//! BIP137 Bitcoin message signing and verification.
//!
//! Implements the standard `signmessage` / `verifymessage` protocol used by
//! Bitcoin Core, where a message is prefixed with the magic string
//! `"\x18Bitcoin Signed Message:\n"`, length-prefixed, and double-SHA256 hashed
//! before signing with ECDSA recoverable signatures.

use sha2::{Digest, Sha256};

use crate::digest::hash160;
use crate::sig::{recover_compact, sign_compact, CryptoError};

/// Bitcoin message signing magic prefix.
/// The leading 0x18 byte is the length of "Bitcoin Signed Message:\n" (24 bytes).
const MESSAGE_MAGIC: &[u8] = b"\x18Bitcoin Signed Message:\n";

/// Encode a length as a Bitcoin compact-size (varint).
fn compact_size(len: usize) -> Vec<u8> {
    if len < 253 {
        vec![len as u8]
    } else if len <= 0xffff {
        let mut v = vec![0xfd];
        v.extend_from_slice(&(len as u16).to_le_bytes());
        v
    } else if len <= 0xffff_ffff {
        let mut v = vec![0xfe];
        v.extend_from_slice(&(len as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xff];
        v.extend_from_slice(&(len as u64).to_le_bytes());
        v
    }
}

/// Compute the Bitcoin message hash: `SHA256d(magic || varint(len) || message)`.
///
/// This is the double-SHA256 digest of the concatenation of the magic prefix,
/// the compact-size encoded message length, and the raw message bytes.
pub fn message_hash(message: &str) -> [u8; 32] {
    let msg_bytes = message.as_bytes();
    let len_varint = compact_size(msg_bytes.len());

    let mut buf = Vec::with_capacity(MESSAGE_MAGIC.len() + len_varint.len() + msg_bytes.len());
    buf.extend_from_slice(MESSAGE_MAGIC);
    buf.extend_from_slice(&len_varint);
    buf.extend_from_slice(msg_bytes);

    let first = Sha256::digest(&buf);
    let second = Sha256::digest(first);
    second.into()
}

/// Sign a message with a private key, producing a 65-byte compact recoverable signature.
///
/// The returned signature format is:
/// `[flag_byte] || r(32) || s(32)`
///
/// where `flag_byte = 27 + recovery_id + 4` (the +4 indicates a compressed key).
pub fn sign_message(privkey: &[u8; 32], message: &str) -> Result<[u8; 65], CryptoError> {
    let hash = message_hash(message);
    sign_compact(privkey, &hash)
}

/// Verify a signed message against a P2PKH address.
///
/// Returns `true` if the recovered public key from the signature matches the
/// given Base58Check-encoded P2PKH address.
pub fn verify_message(address: &str, signature: &[u8; 65], message: &str) -> bool {
    let hash = message_hash(message);

    // Recover the compressed public key (33 bytes) from the compact signature.
    let pubkey = match recover_compact(signature, &hash) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    // Compute P2PKH address from the recovered compressed pubkey:
    // HASH160 = RIPEMD160(SHA256(pubkey))
    let h160 = hash160(&pubkey);

    // 2. Prepend version byte 0x00 (mainnet) and base58check encode.
    //    To support testnet (0x6f), we extract the version from the provided address.
    let version = match bs58::decode(address).with_check(None).into_vec() {
        Ok(decoded) if !decoded.is_empty() => decoded[0],
        _ => return false,
    };

    let mut versioned = Vec::with_capacity(21);
    versioned.push(version);
    versioned.extend_from_slice(&h160.0);

    // base58check encode: payload || sha256d(payload)[0..4]
    let checksum = Sha256::digest(Sha256::digest(&versioned));
    let mut full = versioned;
    full.extend_from_slice(&checksum[..4]);
    let computed_address = bs58::encode(full).into_string();

    computed_address == address
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    /// Helper: derive the P2PKH mainnet address from a secret key.
    fn p2pkh_address_from_privkey(privkey: &[u8; 32]) -> String {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array(*privkey).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let compressed = pk.serialize(); // 33 bytes

        let h160 = hash160(&compressed);

        let mut versioned = Vec::with_capacity(21);
        versioned.push(0x00); // mainnet
        versioned.extend_from_slice(&h160.0);

        let checksum = Sha256::digest(Sha256::digest(&versioned));
        let mut full = versioned;
        full.extend_from_slice(&checksum[..4]);
        bs58::encode(full).into_string()
    }

    #[test]
    fn message_hash_deterministic() {
        let h1 = message_hash("Hello, Bitcoin!");
        let h2 = message_hash("Hello, Bitcoin!");
        assert_eq!(h1, h2);

        // Different messages produce different hashes.
        let h3 = message_hash("Goodbye, Bitcoin!");
        assert_ne!(h1, h3);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let privkey: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        let message = "This is a test message for BIP137 signing.";
        let address = p2pkh_address_from_privkey(&privkey);

        let signature = sign_message(&privkey, message).unwrap();
        assert_eq!(signature.len(), 65);
        // Flag byte should be in range 31..=34 (27 + recid + 4, compressed)
        assert!(signature[0] >= 31 && signature[0] <= 34);

        assert!(verify_message(&address, &signature, message));
    }

    #[test]
    fn verify_wrong_message_fails() {
        let privkey: [u8; 32] = [0x42; 32];
        let message = "Original message";
        let address = p2pkh_address_from_privkey(&privkey);

        let signature = sign_message(&privkey, message).unwrap();

        // Verification with a different message must fail.
        assert!(!verify_message(&address, &signature, "Tampered message"));
    }

    #[test]
    fn verify_wrong_address_fails() {
        let privkey1: [u8; 32] = [0x42; 32];
        let privkey2: [u8; 32] = [0x77; 32];
        let message = "Test message";

        let address2 = p2pkh_address_from_privkey(&privkey2);
        let signature = sign_message(&privkey1, message).unwrap();

        // Signature from key1 should not verify against key2's address.
        assert!(!verify_message(&address2, &signature, message));
    }

    #[test]
    fn message_hash_empty_message() {
        // Empty message should still produce a valid 32-byte hash.
        let h = message_hash("");
        assert_eq!(h.len(), 32);
        // And it should be deterministic.
        assert_eq!(h, message_hash(""));
    }

    #[test]
    fn verify_invalid_address_returns_false() {
        let privkey: [u8; 32] = [0x42; 32];
        let message = "Test";
        let signature = sign_message(&privkey, message).unwrap();

        // A garbage address should return false, not panic.
        assert!(!verify_message("not-a-valid-address", &signature, message));
    }
}
