use crate::sigcache::global_sig_cache;
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId, Signature as EcdsaSig},
    schnorr::Signature as SchnorrSig,
    Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey,
};
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

/// Algo tags for distinguishing cache entries.
const ALGO_ECDSA_STRICT: u8 = 0;
const ALGO_ECDSA_LAX: u8 = 2;
const ALGO_SCHNORR: u8 = 1;

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
    let cache = global_sig_cache();
    let algo_tag = if strict_der { ALGO_ECDSA_STRICT } else { ALGO_ECDSA_LAX };
    if cache.contains_tagged(algo_tag, sig_der, pubkey, msg) {
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
    cache.insert_tagged(algo_tag, sig_der, pubkey, msg);
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
    let cache = global_sig_cache();
    if cache.contains_tagged(ALGO_SCHNORR, sig, pubkey, msg) {
        return Ok(());
    }

    if pubkey.len() != 32 {
        return Err(CryptoError::InvalidPublicKey);
    }
    if sig.len() != 64 && sig.len() != 65 {
        return Err(CryptoError::InvalidSignature);
    }

    let secp = Secp256k1::verification_only();

    let pk_arr: [u8; 32] = pubkey
        .try_into()
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    let xonly =
        XOnlyPublicKey::from_byte_array(pk_arr).map_err(|_| CryptoError::InvalidPublicKey)?;

    let sig_bytes = if sig.len() == 65 { &sig[..64] } else { sig };
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidSignature)?;
    let schnorr_sig = SchnorrSig::from_byte_array(sig_arr);

    secp.verify_schnorr(&schnorr_sig, msg, &xonly)
        .map_err(|_| CryptoError::VerificationFailed)?;
    cache.insert_tagged(ALGO_SCHNORR, sig, pubkey, msg);
    Ok(())
}

/// Batch-verify multiple ECDSA signatures. Returns Ok(()) if ALL signatures
/// are valid, or Err with the index of the first invalid signature.
///
/// Note: true batch verification requires libsecp256k1's batch API which
/// isn't exposed via the secp256k1 crate. This implementation validates
/// each signature individually but presents a batch API, making it easy
/// to swap in a true batch implementation later.
pub fn batch_verify_ecdsa(
    items: &[(secp256k1::ecdsa::Signature, secp256k1::Message, secp256k1::PublicKey)],
) -> Result<(), (usize, CryptoError)> {
    let secp = Secp256k1::verification_only();
    for (i, (sig, msg, pk)) in items.iter().enumerate() {
        secp.verify_ecdsa(*msg, sig, pk)
            .map_err(|_| (i, CryptoError::VerificationFailed))?;
    }
    Ok(())
}

/// Batch-verify multiple Schnorr signatures. Returns Ok(()) if ALL signatures
/// are valid, or Err with the index of the first invalid signature.
///
/// Note: true batch verification requires libsecp256k1's batch API which
/// isn't exposed via the secp256k1 crate. This implementation validates
/// each signature individually but presents a batch API, making it easy
/// to swap in a true batch implementation later.
pub fn batch_verify_schnorr(
    items: &[(secp256k1::schnorr::Signature, secp256k1::Message, secp256k1::XOnlyPublicKey)],
) -> Result<(), (usize, CryptoError)> {
    let secp = Secp256k1::verification_only();
    for (i, (sig, msg, pk)) in items.iter().enumerate() {
        secp.verify_schnorr(sig, &msg[..], pk)
            .map_err(|_| (i, CryptoError::VerificationFailed))?;
    }
    Ok(())
}

/// Sign a 32-byte message hash with a secret key, producing a 65-byte compact signature.
/// Format: [recovery_flag] || r(32) || s(32)
/// recovery_flag = 27 + recovery_id + 4 (compressed)
pub fn sign_compact(secret_key: &[u8; 32], msg: &[u8; 32]) -> Result<[u8; 65], CryptoError> {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_byte_array(*secret_key).map_err(|_| CryptoError::InvalidSignature)?;
    let message = Message::from_digest(*msg);
    let recoverable_sig = secp.sign_ecdsa_recoverable(message, &sk);
    let (recovery_id, sig_bytes) = recoverable_sig.serialize_compact();
    let recid_byte: u8 = match recovery_id {
        RecoveryId::Zero => 0,
        RecoveryId::One => 1,
        RecoveryId::Two => 2,
        RecoveryId::Three => 3,
    };
    let flag = 27 + recid_byte + 4;
    let mut compact = [0u8; 65];
    compact[0] = flag;
    compact[1..65].copy_from_slice(&sig_bytes);
    Ok(compact)
}

/// Recover a compressed public key from a 65-byte compact signature and 32-byte message hash.
/// Returns the 33-byte compressed public key.
pub fn recover_compact(compact_sig: &[u8; 65], msg: &[u8; 32]) -> Result<[u8; 33], CryptoError> {
    let flag = compact_sig[0];
    if flag < 31 || flag > 34 {
        return Err(CryptoError::InvalidSignature);
    }
    let recovery_id_val = flag - 27 - 4;
    let recovery_id = RecoveryId::from_u8_masked(recovery_id_val);
    let sig = RecoverableSignature::from_compact(&compact_sig[1..65], recovery_id)
        .map_err(|_| CryptoError::InvalidSignature)?;
    let secp = Secp256k1::new();
    let message = Message::from_digest(*msg);
    let pubkey = secp
        .recover_ecdsa(message, &sig)
        .map_err(|_| CryptoError::InvalidSignature)?;
    Ok(pubkey.serialize())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a valid ECDSA (signature, message, pubkey) tuple from a secret key and message bytes.
    fn make_ecdsa_item(
        sk_bytes: &[u8; 32],
        msg_bytes: &[u8; 32],
    ) -> (secp256k1::ecdsa::Signature, Message, PublicKey) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array(*sk_bytes).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let msg = Message::from_digest(*msg_bytes);
        let sig = secp.sign_ecdsa(msg, &sk);
        (sig, msg, pk)
    }

    /// Helper: create a valid Schnorr (signature, message, xonly_pubkey) tuple.
    fn make_schnorr_item(
        sk_bytes: &[u8; 32],
        msg_bytes: &[u8; 32],
    ) -> (SchnorrSig, Message, XOnlyPublicKey) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array(*sk_bytes).unwrap();
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &sk);
        let (xonly, _parity) = keypair.x_only_public_key();
        let msg = Message::from_digest(*msg_bytes);
        let sig = secp.sign_schnorr_no_aux_rand(msg_bytes, &keypair);
        (sig, msg, xonly)
    }

    #[test]
    fn batch_ecdsa_all_valid() {
        let items: Vec<_> = (1u8..=3)
            .map(|i| {
                let sk = [i; 32];
                let msg = [i + 10; 32];
                make_ecdsa_item(&sk, &msg)
            })
            .collect();
        assert!(batch_verify_ecdsa(&items).is_ok());
    }

    #[test]
    fn batch_ecdsa_one_invalid() {
        let mut items: Vec<_> = (1u8..=3)
            .map(|i| {
                let sk = [i; 32];
                let msg = [i + 10; 32];
                make_ecdsa_item(&sk, &msg)
            })
            .collect();
        // Corrupt the signature at index 1 by swapping in a different message
        items[1].1 = Message::from_digest([0xff; 32]);
        let err = batch_verify_ecdsa(&items).unwrap_err();
        assert_eq!(err.0, 1);
        assert!(matches!(err.1, CryptoError::VerificationFailed));
    }

    #[test]
    fn batch_schnorr_all_valid() {
        let items: Vec<_> = (1u8..=3)
            .map(|i| {
                let sk = [i; 32];
                let msg = [i + 10; 32];
                make_schnorr_item(&sk, &msg)
            })
            .collect();
        assert!(batch_verify_schnorr(&items).is_ok());
    }

    #[test]
    fn batch_schnorr_one_invalid() {
        let mut items: Vec<_> = (1u8..=3)
            .map(|i| {
                let sk = [i; 32];
                let msg = [i + 10; 32];
                make_schnorr_item(&sk, &msg)
            })
            .collect();
        // Corrupt at index 2
        items[2].1 = Message::from_digest([0xff; 32]);
        let err = batch_verify_schnorr(&items).unwrap_err();
        assert_eq!(err.0, 2);
        assert!(matches!(err.1, CryptoError::VerificationFailed));
    }

    #[test]
    fn batch_empty_passes() {
        assert!(batch_verify_ecdsa(&[]).is_ok());
        assert!(batch_verify_schnorr(&[]).is_ok());
    }

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

    #[test]
    fn sign_compact_then_recover() {
        // Use a known valid secret key (32 bytes, non-zero, within curve order)
        let secret_key: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        let msg: [u8; 32] = [0xaa; 32];

        // Derive the expected compressed pubkey
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&secret_key).unwrap();
        let expected_pk = PublicKey::from_secret_key(&secp, &sk).serialize();

        // Sign compact
        let compact_sig = sign_compact(&secret_key, &msg).unwrap();

        // First byte should be in range 31..=34 (27 + recid + 4)
        assert!(compact_sig[0] >= 31 && compact_sig[0] <= 34);

        // Recover and compare
        let recovered_pk = recover_compact(&compact_sig, &msg).unwrap();
        assert_eq!(recovered_pk, expected_pk);
    }

    #[test]
    fn sign_compact_different_messages_differ() {
        let secret_key: [u8; 32] = [0x42; 32];
        let msg1: [u8; 32] = [0x01; 32];
        let msg2: [u8; 32] = [0x02; 32];

        let sig1 = sign_compact(&secret_key, &msg1).unwrap();
        let sig2 = sign_compact(&secret_key, &msg2).unwrap();
        assert_ne!(sig1, sig2);

        // Each should recover correctly
        let pk1 = recover_compact(&sig1, &msg1).unwrap();
        let pk2 = recover_compact(&sig2, &msg2).unwrap();
        assert_eq!(pk1, pk2); // same key, different messages
    }

    #[test]
    fn recover_compact_invalid_flag_too_low() {
        let mut bad_sig = [0u8; 65];
        bad_sig[0] = 26; // below valid range
        let msg = [0u8; 32];
        let r = recover_compact(&bad_sig, &msg);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), CryptoError::InvalidSignature));
    }

    #[test]
    fn recover_compact_invalid_flag_too_high() {
        let mut bad_sig = [0u8; 65];
        bad_sig[0] = 35; // above valid range
        let msg = [0u8; 32];
        let r = recover_compact(&bad_sig, &msg);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), CryptoError::InvalidSignature));
    }

    #[test]
    fn recover_compact_wrong_message_gives_different_key() {
        let secret_key: [u8; 32] = [0x77; 32];
        let msg: [u8; 32] = [0xbb; 32];
        let wrong_msg: [u8; 32] = [0xcc; 32];

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&secret_key).unwrap();
        let expected_pk = PublicKey::from_secret_key(&secp, &sk).serialize();

        let compact_sig = sign_compact(&secret_key, &msg).unwrap();
        // Recovering with wrong message should give a different pubkey
        let recovered_pk = recover_compact(&compact_sig, &wrong_msg).unwrap();
        assert_ne!(recovered_pk, expected_pk);
    }
}
