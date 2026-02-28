use secp256k1::{
    ecdsa::Signature as EcdsaSig, schnorr::Signature as SchnorrSig, Message, PublicKey,
    Secp256k1, XOnlyPublicKey,
};
use std::collections::{HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::{Mutex, OnceLock};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid message")]
    InvalidMessage,
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),
}

const DEFAULT_SIG_CACHE_CAPACITY: usize = 100_000;

struct SigCache {
    entries: HashSet<u64>,
    order: VecDeque<u64>,
    capacity: usize,
}

impl SigCache {
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashSet::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn contains(&self, key: u64) -> bool {
        self.entries.contains(&key)
    }

    fn insert(&mut self, key: u64) {
        if !self.entries.insert(key) {
            return;
        }
        self.order.push_back(key);
        if self.order.len() > self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.entries.remove(&old);
            }
        }
    }
}

static SIG_CACHE: OnceLock<Mutex<SigCache>> = OnceLock::new();

fn sig_cache() -> &'static Mutex<SigCache> {
    SIG_CACHE.get_or_init(|| Mutex::new(SigCache::new(DEFAULT_SIG_CACHE_CAPACITY)))
}

fn make_sig_cache_key(
    algo_tag: u8,
    strict_der: bool,
    pubkey: &[u8],
    sig: &[u8],
    msg: &[u8; 32],
) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    algo_tag.hash(&mut hasher);
    strict_der.hash(&mut hasher);
    pubkey.hash(&mut hasher);
    sig.hash(&mut hasher);
    msg.hash(&mut hasher);
    hasher.finish()
}

fn cache_contains(key: u64) -> bool {
    match sig_cache().lock() {
        Ok(cache) => cache.contains(key),
        Err(_) => false,
    }
}

fn cache_insert(key: u64) {
    if let Ok(mut cache) = sig_cache().lock() {
        cache.insert(key);
    }
}

/// Verify an ECDSA signature.
/// `pubkey` – 33-byte compressed or 65-byte uncompressed public key.
/// `sig_der` – DER-encoded signature bytes (without sighash byte).
/// `msg`     – 32-byte sighash.
/// `strict_der` – when false, accepts legacy lax-DER parsing (pre-BIP66).
pub fn verify_ecdsa_with_policy(
    pubkey: &[u8],
    sig_der: &[u8],
    msg: &[u8; 32],
    strict_der: bool,
) -> Result<(), CryptoError> {
    let cache_key = make_sig_cache_key(0, strict_der, pubkey, sig_der, msg);
    if cache_contains(cache_key) {
        return Ok(());
    }

    let secp = Secp256k1::verification_only();
    let pk = PublicKey::from_slice(pubkey).map_err(|_| CryptoError::InvalidPublicKey)?;

    let mut sig = if strict_der {
        EcdsaSig::from_der(sig_der).map_err(|_| CryptoError::InvalidSignature)?
    } else {
        EcdsaSig::from_der_lax(sig_der).map_err(|_| CryptoError::InvalidSignature)?
    };
    // Normalize S to low-S: the secp256k1 C library's verify requires low-S.
    // Pre-BIP66 Bitcoin transactions may use high-S signatures; both (r,s) and
    // (r, n-s) are mathematically equivalent for verification purposes.
    sig.normalize_s();
    let message = Message::from_digest(*msg);

    secp.verify_ecdsa(message, &sig, &pk)
        .map_err(|_| CryptoError::VerificationFailed)?;
    cache_insert(cache_key);
    Ok(())
}

/// Verify a strict-DER ECDSA signature (BIP66 behavior).
pub fn verify_ecdsa(pubkey: &[u8], sig_der: &[u8], msg: &[u8; 32]) -> Result<(), CryptoError> {
    verify_ecdsa_with_policy(pubkey, sig_der, msg, true)
}

/// Verify a 64-byte Schnorr signature (BIP340 / Taproot).
/// `pubkey` – 32-byte x-only public key.
/// `sig`    – 64 bytes, or 65 bytes with sighash type appended.
/// `msg`    – 32-byte tagged sighash.
pub fn verify_schnorr(pubkey: &[u8], sig: &[u8], msg: &[u8; 32]) -> Result<(), CryptoError> {
    let cache_key = make_sig_cache_key(1, true, pubkey, sig, msg);
    if cache_contains(cache_key) {
        return Ok(());
    }

    if pubkey.len() != 32 {
        return Err(CryptoError::InvalidPublicKey);
    }
    if sig.len() != 64 && sig.len() != 65 {
        return Err(CryptoError::InvalidSignature);
    }

    let secp = Secp256k1::verification_only();

    let pk_arr: [u8; 32] = pubkey.try_into().map_err(|_| CryptoError::InvalidPublicKey)?;
    let xonly = XOnlyPublicKey::from_byte_array(pk_arr)
        .map_err(|_| CryptoError::InvalidPublicKey)?;

    let sig_bytes = if sig.len() == 65 { &sig[..64] } else { sig };
    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| CryptoError::InvalidSignature)?;
    let schnorr_sig = SchnorrSig::from_byte_array(sig_arr);

    secp.verify_schnorr(&schnorr_sig, msg, &xonly)
        .map_err(|_| CryptoError::VerificationFailed)?;
    cache_insert(cache_key);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_ecdsa_invalid_pubkey_empty() {
        let msg = [0u8; 32];
        let sig = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        let r = verify_ecdsa(&[], &sig, &msg);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), CryptoError::InvalidPublicKey));
    }

    #[test]
    fn verify_ecdsa_invalid_pubkey_bad_bytes() {
        let msg = [0u8; 32];
        let pk = [0u8; 33];
        let sig = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        let r = verify_ecdsa(&pk, &sig, &msg);
        assert!(r.is_err());
    }

    #[test]
    fn verify_ecdsa_invalid_signature() {
        let msg = [0u8; 32];
        let pk = [
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
            0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
            0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];
        let bad_sig = [0u8; 10];
        let r = verify_ecdsa(&pk, &bad_sig, &msg);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), CryptoError::InvalidSignature));
    }

    #[test]
    fn verify_ecdsa_sig_with_sighash_byte() {
        let msg = [0u8; 32];
        let pk = [
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
            0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
            0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];
        let der_plus_sighash = [
            0x30, 0x44, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01,
        ];
        let r = verify_ecdsa(&pk, &der_plus_sighash, &msg);
        assert!(r.is_err());
    }

    #[test]
    fn verify_schnorr_invalid_pubkey_len() {
        let msg = [0u8; 32];
        let pk = [0u8; 31];
        let sig = [0u8; 64];
        assert!(verify_schnorr(&pk, &sig, &msg).is_err());
        let pk65 = [0u8; 65];
        assert!(verify_schnorr(&pk65, &sig, &msg).is_err());
    }

    #[test]
    fn verify_schnorr_invalid_sig_len() {
        let msg = [0u8; 32];
        let pk = [0u8; 32];
        assert!(verify_schnorr(&pk, &[0u8; 63], &msg).is_err());
        assert!(verify_schnorr(&pk, &[0u8; 66], &msg).is_err());
    }

    #[test]
    fn verify_schnorr_invalid_pubkey() {
        let msg = [0u8; 32];
        let pk = [0u8; 32];
        let sig = [0u8; 64];
        let r = verify_schnorr(&pk, &sig, &msg);
        assert!(r.is_err());
    }

    #[test]
    fn verify_schnorr_65_bytes() {
        let msg = [0u8; 32];
        let pk = [
            0x17, 0x7c, 0x31, 0x4d, 0x3c, 0x77, 0x2d, 0xfc, 0x6d, 0x2f, 0x98, 0x2e, 0x2e, 0x1e,
            0x57, 0xeb, 0x0d, 0xcd, 0x0f, 0xaf, 0x60, 0x1e, 0xc4, 0x49, 0xb7, 0x26, 0x7e, 0x72,
            0x52, 0x57, 0x3f, 0xaf, 0xe3,
        ];
        let mut sig65 = [0u8; 65];
        sig65[..64].copy_from_slice(&[0u8; 64]);
        sig65[64] = 0x01;
        let r = verify_schnorr(&pk, &sig65, &msg);
        assert!(r.is_err());
    }
}
