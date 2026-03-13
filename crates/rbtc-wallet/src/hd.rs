//! BIP32 Hierarchical Deterministic key derivation.
//!
//! Implements `ExtendedPrivKey` and `ExtendedPubKey` with support for
//! hardened and normal child derivation, path parsing, and xpub/xprv
//! serialisation (Base58Check).

use hmac::{Hmac, Mac};
use secp256k1::{Keypair, PublicKey, Scalar, SecretKey};
use sha2::Sha512;

use rbtc_crypto::hash160;

use crate::error::WalletError;

type HmacSha512 = Hmac<Sha512>;

/// First index of the hardened range (BIP32 convention).
pub const HARDENED: u32 = 0x8000_0000;

// ── DerivationPath ────────────────────────────────────────────────────────────

/// A parsed BIP32 derivation path, e.g. `m/84'/0'/0'/0/0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationPath(pub Vec<u32>);

impl DerivationPath {
    pub fn parse(s: &str) -> Result<Self, WalletError> {
        let s = s.trim_start_matches("m/");
        if s.is_empty() {
            return Ok(Self(vec![]));
        }
        let mut indices = Vec::new();
        for part in s.split('/') {
            let (num_str, hardened) = if let Some(stripped) = part.strip_suffix('\'') {
                (stripped, true)
            } else {
                (part, false)
            };
            let n: u32 = num_str
                .parse()
                .map_err(|_| WalletError::InvalidPath(s.to_string()))?;
            indices.push(if hardened { n | HARDENED } else { n });
        }
        Ok(Self(indices))
    }
}

// ── ExtendedPrivKey ───────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ExtendedPrivKey {
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
    pub chaincode: [u8; 32],
    pub private_key: SecretKey,
}

impl ExtendedPrivKey {
    /// Derive the BIP32 master key from a 64-byte seed.
    pub fn from_seed(seed: &[u8]) -> Result<Self, WalletError> {
        let mut mac =
            HmacSha512::new_from_slice(b"Bitcoin seed").expect("HMAC accepts any key length");
        mac.update(seed);
        let result = mac.finalize().into_bytes();

        let private_key = SecretKey::from_byte_array(
            result[..32]
                .try_into()
                .map_err(|_| WalletError::InvalidKey)?,
        )
        .map_err(|_| WalletError::InvalidKey)?;
        let mut chaincode = [0u8; 32];
        chaincode.copy_from_slice(&result[32..]);

        Ok(Self {
            depth: 0,
            parent_fingerprint: [0u8; 4],
            child_number: 0,
            chaincode,
            private_key,
        })
    }

    /// Derive one child at `index`. Supports both normal (< HARDENED) and
    /// hardened (>= HARDENED) indices.
    pub fn derive_child(&self, index: u32) -> Result<Self, WalletError> {
        let secp = secp256k1::Secp256k1::signing_only();
        let public_key = PublicKey::from_secret_key(&secp, &self.private_key);
        let pub_bytes = public_key.serialize(); // 33-byte compressed

        let mut data = Vec::with_capacity(37);
        if index >= HARDENED {
            data.push(0x00);
            data.extend_from_slice(&self.private_key.secret_bytes());
        } else {
            data.extend_from_slice(&pub_bytes);
        }
        data.extend_from_slice(&index.to_be_bytes());

        let mut mac =
            HmacSha512::new_from_slice(&self.chaincode).expect("HMAC accepts any key length");
        mac.update(&data);
        let result = mac.finalize().into_bytes();

        let il: [u8; 32] = result[..32].try_into().unwrap();
        let ir: [u8; 32] = result[32..].try_into().unwrap();

        let il_scalar = Scalar::from_be_bytes(il).map_err(|_| WalletError::InvalidKey)?;
        let child_key = self
            .private_key
            .add_tweak(&il_scalar)
            .map_err(|_| WalletError::InvalidKey)?;

        let parent_hash = hash160(&pub_bytes);
        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&parent_hash.0[..4]);

        Ok(Self {
            depth: self.depth.saturating_add(1),
            parent_fingerprint,
            child_number: index,
            chaincode: ir,
            private_key: child_key,
        })
    }

    /// Derive along a full `DerivationPath`.
    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, WalletError> {
        let mut key = self.clone();
        for &index in &path.0 {
            key = key.derive_child(index)?;
        }
        Ok(key)
    }

    /// Return the corresponding compressed public key.
    pub fn public_key(&self) -> PublicKey {
        let secp = secp256k1::Secp256k1::signing_only();
        PublicKey::from_secret_key(&secp, &self.private_key)
    }

    /// Return the secp256k1 keypair (useful for Schnorr / Taproot).
    pub fn keypair(&self) -> Keypair {
        let secp = secp256k1::Secp256k1::new();
        Keypair::from_secret_key(&secp, &self.private_key)
    }

    /// Compute the BIP32 fingerprint (first 4 bytes of hash160 of compressed pubkey).
    pub fn fingerprint(&self) -> [u8; 4] {
        let pub_bytes = self.public_key().serialize();
        let h = hash160(&pub_bytes);
        h.0[..4].try_into().unwrap()
    }
}

// ── ExtendedPubKey ────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ExtendedPubKey {
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
    pub chaincode: [u8; 32],
    pub public_key: PublicKey,
}

impl ExtendedPubKey {
    /// Decode from a Base58Check-encoded xpub/tpub string (BIP32 serialization).
    ///
    /// Format: 4 version + 1 depth + 4 fingerprint + 4 child_number + 32 chaincode + 33 pubkey = 78 bytes
    pub fn from_base58(s: &str) -> Result<Self, WalletError> {
        let decoded = bs58::decode(s)
            .with_check(None)
            .into_vec()
            .map_err(|_| WalletError::InvalidKey)?;
        if decoded.len() != 78 {
            return Err(WalletError::InvalidKey);
        }
        // Version bytes: 0x0488B21E (xpub) or 0x043587CF (tpub)
        // We accept both without checking — the caller knows the network.
        let depth = decoded[4];
        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&decoded[5..9]);
        let child_number = u32::from_be_bytes(decoded[9..13].try_into().unwrap());
        let mut chaincode = [0u8; 32];
        chaincode.copy_from_slice(&decoded[13..45]);
        let public_key =
            PublicKey::from_slice(&decoded[45..78]).map_err(|_| WalletError::InvalidKey)?;

        Ok(Self {
            depth,
            parent_fingerprint,
            child_number,
            chaincode,
            public_key,
        })
    }

    /// Derive from `ExtendedPrivKey`.
    pub fn from_xprv(xprv: &ExtendedPrivKey) -> Self {
        Self {
            depth: xprv.depth,
            parent_fingerprint: xprv.parent_fingerprint,
            child_number: xprv.child_number,
            chaincode: xprv.chaincode,
            public_key: xprv.public_key(),
        }
    }

    /// Derive a *normal* (non-hardened) child public key.
    pub fn derive_child(&self, index: u32) -> Result<Self, WalletError> {
        if index >= HARDENED {
            return Err(WalletError::InvalidPath(
                "cannot derive hardened child from public key".into(),
            ));
        }

        let pub_bytes = self.public_key.serialize();
        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&pub_bytes);
        data.extend_from_slice(&index.to_be_bytes());

        let mut mac =
            HmacSha512::new_from_slice(&self.chaincode).expect("HMAC accepts any key length");
        mac.update(&data);
        let result = mac.finalize().into_bytes();

        let il: [u8; 32] = result[..32].try_into().unwrap();
        let ir: [u8; 32] = result[32..].try_into().unwrap();

        let secp = secp256k1::Secp256k1::verification_only();
        let il_scalar = Scalar::from_be_bytes(il).map_err(|_| WalletError::InvalidKey)?;
        let child_pub = self
            .public_key
            .add_exp_tweak(&secp, &il_scalar)
            .map_err(|_| WalletError::InvalidKey)?;

        let parent_hash = hash160(&pub_bytes);
        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&parent_hash.0[..4]);

        Ok(Self {
            depth: self.depth.saturating_add(1),
            parent_fingerprint,
            child_number: index,
            chaincode: ir,
            public_key: child_pub,
        })
    }

    /// Serialize to a Base58Check-encoded xpub string (BIP32, mainnet version bytes).
    pub fn to_base58(&self) -> String {
        let mut data = Vec::with_capacity(78);
        // Version: 0x0488B21E = xpub
        data.extend_from_slice(&[0x04, 0x88, 0xB2, 0x1E]);
        data.push(self.depth);
        data.extend_from_slice(&self.parent_fingerprint);
        data.extend_from_slice(&self.child_number.to_be_bytes());
        data.extend_from_slice(&self.chaincode);
        data.extend_from_slice(&self.public_key.serialize());
        bs58::encode(data).with_check().into_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_from_hex(hex: &str) -> Vec<u8> {
        hex::decode(hex).unwrap()
    }

    #[test]
    fn master_key_from_seed() {
        // BIP32 Test Vector 1
        let seed = seed_from_hex("000102030405060708090a0b0c0d0e0f");
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();
        assert_eq!(master.depth, 0);
        assert_eq!(master.child_number, 0);
        assert_eq!(master.parent_fingerprint, [0u8; 4]);
        let pub_bytes = master.public_key().serialize();
        assert_eq!(pub_bytes.len(), 33);
    }

    #[test]
    fn derive_hardened_child() {
        let seed = seed_from_hex("000102030405060708090a0b0c0d0e0f");
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();
        let child = master.derive_child(0 | HARDENED).unwrap();
        assert_eq!(child.depth, 1);
        assert_eq!(child.child_number, 0 | HARDENED);
        assert_ne!(
            child.private_key.secret_bytes(),
            master.private_key.secret_bytes()
        );
    }

    #[test]
    fn derive_normal_child() {
        let seed = seed_from_hex("000102030405060708090a0b0c0d0e0f");
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();
        let child = master.derive_child(1).unwrap();
        assert_eq!(child.depth, 1);
        assert_eq!(child.child_number, 1);
    }

    #[test]
    fn parse_derivation_path() {
        let path = DerivationPath::parse("m/84'/0'/0'/0/0").unwrap();
        assert_eq!(
            path.0,
            vec![84 | HARDENED, 0 | HARDENED, 0 | HARDENED, 0, 0]
        );
    }

    #[test]
    fn derive_full_path() {
        let seed = seed_from_hex("000102030405060708090a0b0c0d0e0f");
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();
        let path = DerivationPath::parse("m/0'/1/2'").unwrap();
        let derived = master.derive_path(&path).unwrap();
        assert_eq!(derived.depth, 3);
    }

    #[test]
    fn xpub_child_matches_xprv_child_pubkey() {
        let seed = seed_from_hex("000102030405060708090a0b0c0d0e0f");
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();
        // Derive private child at index 0
        let prv_child = master.derive_child(0).unwrap();
        // Derive public child at index 0 from master's xpub
        let xpub = ExtendedPubKey::from_xprv(&master);
        let pub_child = xpub.derive_child(0).unwrap();
        // Both should yield the same public key
        assert_eq!(
            prv_child.public_key().serialize(),
            pub_child.public_key.serialize()
        );
    }
}
