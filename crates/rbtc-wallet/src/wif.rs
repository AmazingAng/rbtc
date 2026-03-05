//! WIF (Wallet Import Format) encoding and decoding for private keys.

use secp256k1::SecretKey;
use sha2::{Digest, Sha256};

use rbtc_primitives::network::Network;

use crate::error::WalletError;

fn base58check_encode(payload: &[u8]) -> String {
    let checksum = Sha256::digest(Sha256::digest(payload));
    let mut full = payload.to_vec();
    full.extend_from_slice(&checksum[..4]);
    bs58::encode(full).into_string()
}

/// Encode a private key as WIF (compressed, as required for SegWit/Taproot).
pub fn to_wif(key: &SecretKey, network: Network) -> String {
    let version = match network {
        Network::Mainnet => 0x80u8,
        _ => 0xef,
    };
    let key_bytes = key.secret_bytes();
    let mut payload = Vec::with_capacity(34);
    payload.push(version);
    payload.extend_from_slice(&key_bytes);
    payload.push(0x01); // compressed-key flag
    base58check_encode(&payload)
}

/// Decode a WIF string back to a `SecretKey`. Returns `(key, network)`.
pub fn from_wif(wif: &str) -> Result<(SecretKey, Network), WalletError> {
    let decoded = bs58::decode(wif)
        .with_check(None)
        .into_vec()
        .map_err(|_| WalletError::InvalidWif)?;

    // Expected lengths: 33 (uncompressed) or 34 (compressed) after stripping version
    if decoded.len() < 33 || decoded.len() > 34 {
        return Err(WalletError::InvalidWif);
    }

    let version = decoded[0];
    let network = match version {
        0x80 => Network::Mainnet,
        0xef => Network::Regtest,
        _ => return Err(WalletError::InvalidWif),
    };

    let key_bytes: &[u8; 32] = decoded[1..33]
        .try_into()
        .map_err(|_| WalletError::InvalidWif)?;
    let key = SecretKey::from_byte_array(*key_bytes).map_err(|_| WalletError::InvalidWif)?;
    Ok((key, network))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key() -> SecretKey {
        SecretKey::from_byte_array([1u8; 32]).unwrap()
    }

    #[test]
    fn wif_roundtrip_mainnet() {
        let key = sample_key();
        let wif = to_wif(&key, Network::Mainnet);
        assert!(wif.starts_with('K') || wif.starts_with('L') || wif.starts_with('5'));
        let (decoded, net) = from_wif(&wif).unwrap();
        assert_eq!(net, Network::Mainnet);
        assert_eq!(decoded.secret_bytes(), key.secret_bytes());
    }

    #[test]
    fn wif_roundtrip_regtest() {
        let key = sample_key();
        let wif = to_wif(&key, Network::Regtest);
        let (decoded, net) = from_wif(&wif).unwrap();
        assert_eq!(net, Network::Regtest);
        assert_eq!(decoded.secret_bytes(), key.secret_bytes());
    }

    #[test]
    fn invalid_wif_rejected() {
        assert!(from_wif("notvalidwif").is_err());
        assert!(from_wif("").is_err());
    }
}
