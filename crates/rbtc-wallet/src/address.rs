//! Bitcoin address generation for P2PKH, P2WPKH, and P2TR.

use bech32::{segwit, Fe32, Hrp};
use secp256k1::{Keypair, PublicKey, Scalar, XOnlyPublicKey};
use sha2::{Digest, Sha256};

use rbtc_crypto::{hash160, tagged_hash};
use rbtc_primitives::{network::Network, script::Script};

use crate::error::WalletError;

// ── AddressType ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    /// Legacy P2PKH — BIP44 path m/44'/coin'/account'/change/index
    Legacy,
    /// Native SegWit P2WPKH — BIP84 path m/84'/coin'/account'/change/index
    SegWit,
    /// Taproot P2TR — BIP86 path m/86'/coin'/account'/change/index
    Taproot,
}

impl AddressType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "legacy" | "p2pkh" => Some(Self::Legacy),
            "bech32" | "p2wpkh" | "segwit" => Some(Self::SegWit),
            "bech32m" | "p2tr" | "taproot" => Some(Self::Taproot),
            _ => None,
        }
    }
}

// ── Network helpers ────────────────────────────────────────────────────────────

fn bech32_hrp(network: Network) -> Hrp {
    let s = match network {
        Network::Mainnet  => "bc",
        Network::Testnet4 => "tb",
        Network::Regtest  => "bcrt",
        Network::Signet   => "tb",
    };
    Hrp::parse(s).expect("static HRP string is always valid")
}

/// Version byte for P2PKH addresses.
fn p2pkh_version(network: Network) -> u8 {
    match network {
        Network::Mainnet => 0x00,
        _                => 0x6f,
    }
}

/// Version byte for P2SH addresses (not currently used for derivation but kept for completeness).
#[allow(dead_code)]
fn p2sh_version(network: Network) -> u8 {
    match network {
        Network::Mainnet => 0x05,
        _                => 0xc4,
    }
}

// ── Base58Check ──────────────────────────────────────────────────────────────

fn base58check_encode(payload: &[u8]) -> String {
    let checksum = Sha256::digest(Sha256::digest(payload));
    let mut full = payload.to_vec();
    full.extend_from_slice(&checksum[..4]);
    bs58::encode(full).into_string()
}

// ── Address construction ──────────────────────────────────────────────────────

/// Construct a P2PKH address from a compressed/uncompressed public key.
pub fn p2pkh_address(pubkey: &PublicKey, network: Network) -> String {
    let compressed = pubkey.serialize();
    let h160 = hash160(&compressed);
    let mut versioned = Vec::with_capacity(21);
    versioned.push(p2pkh_version(network));
    versioned.extend_from_slice(&h160.0);
    base58check_encode(&versioned)
}

/// Construct a P2WPKH (native SegWit) address from a compressed public key.
pub fn p2wpkh_address(pubkey: &PublicKey, network: Network) -> Result<String, WalletError> {
    let compressed = pubkey.serialize();
    let h160 = hash160(&compressed);
    let hrp = bech32_hrp(network);
    let witver = Fe32::try_from(0u8).unwrap(); // witness version 0 → bech32
    segwit::encode(hrp, witver, &h160.0)
        .map_err(|e| WalletError::AddressEncoding(e.to_string()))
}

/// Compute the Taproot output key and x-only bytes for a given internal key.
/// This follows BIP341 key-path-only tweaking: Q = P + H_TapTweak(P)*G.
pub fn taproot_output_key(
    keypair: &Keypair,
) -> Result<(Keypair, XOnlyPublicKey), WalletError> {
    let secp = secp256k1::Secp256k1::new();
    let (xonly, _parity) = keypair.x_only_public_key();
    let tweak_bytes = tagged_hash(b"TapTweak", &xonly.serialize());
    let tweak_scalar =
        Scalar::from_be_bytes(tweak_bytes.0).map_err(|_| WalletError::InvalidKey)?;
    let tweaked = keypair
        .add_xonly_tweak(&secp, &tweak_scalar)
        .map_err(|_| WalletError::InvalidKey)?;
    let (tweaked_xonly, _) = tweaked.x_only_public_key();
    Ok((tweaked, tweaked_xonly))
}

/// Construct a P2TR (Taproot) address from an internal key (keypair).
pub fn p2tr_address(keypair: &Keypair, network: Network) -> Result<String, WalletError> {
    let (_tweaked_kp, output_xonly) = taproot_output_key(keypair)?;
    let output_key_bytes = output_xonly.serialize(); // 32 bytes
    let hrp = bech32_hrp(network);
    let witver = Fe32::try_from(1u8).unwrap(); // witness version 1 → bech32m
    segwit::encode(hrp, witver, &output_key_bytes)
        .map_err(|e| WalletError::AddressEncoding(e.to_string()))
}

// ── scriptPubKey builders ─────────────────────────────────────────────────────

/// Build the scriptPubKey for a P2PKH output.
pub fn p2pkh_script(pubkey: &PublicKey) -> Script {
    let h160 = hash160(&pubkey.serialize());
    let mut v = Vec::with_capacity(25);
    v.push(0x76); // OP_DUP
    v.push(0xa9); // OP_HASH160
    v.push(0x14); // push 20 bytes
    v.extend_from_slice(&h160.0);
    v.push(0x88); // OP_EQUALVERIFY
    v.push(0xac); // OP_CHECKSIG
    Script::from_bytes(v)
}

/// Build the scriptPubKey for a P2WPKH output.
pub fn p2wpkh_script(pubkey: &PublicKey) -> Script {
    let h160 = hash160(&pubkey.serialize());
    let mut v = Vec::with_capacity(22);
    v.push(0x00); // OP_0
    v.push(0x14); // push 20 bytes
    v.extend_from_slice(&h160.0);
    Script::from_bytes(v)
}

/// Build the scriptPubKey for a P2TR output given the *output* x-only key.
pub fn p2tr_script(output_key: &XOnlyPublicKey) -> Script {
    let key_bytes = output_key.serialize();
    let mut v = Vec::with_capacity(34);
    v.push(0x51); // OP_1
    v.push(0x20); // push 32 bytes
    v.extend_from_slice(&key_bytes);
    Script::from_bytes(v)
}

/// Derive the BIP344 P2WPKH script_code used in sighash_segwit_v0.
/// It is `OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG`.
pub fn p2wpkh_script_code(pubkey: &PublicKey) -> Script {
    p2pkh_script(pubkey)
}

// ── Address → scriptPubKey parsing ───────────────────────────────────────────

/// Parse a Bitcoin address string and return the corresponding scriptPubKey.
pub fn address_to_script(address: &str) -> Result<Script, WalletError> {
    // Try bech32 / bech32m first
    if let Ok((hrp, version, program)) = segwit::decode(address) {
        let _ = hrp;
        let v = version.to_u8();
        let mut s = Vec::with_capacity(2 + program.len());
        s.push(if v == 0 { 0x00 } else { 0x50 + v }); // OP_0 or OP_N
        s.push(program.len() as u8);
        s.extend_from_slice(&program);
        return Ok(Script::from_bytes(s));
    }

    // Try Base58Check (P2PKH / P2SH)
    if let Ok(decoded) = bs58::decode(address).with_check(None).into_vec() {
        if decoded.len() < 21 {
            return Err(WalletError::InvalidAddress(address.to_string()));
        }
        let version = decoded[0];
        let hash = &decoded[1..21];
        let script = match version {
            // P2PKH mainnet (0x00) or testnet (0x6f)
            0x00 | 0x6f => {
                let mut v = Vec::with_capacity(25);
                v.extend_from_slice(&[0x76, 0xa9, 0x14]);
                v.extend_from_slice(hash);
                v.extend_from_slice(&[0x88, 0xac]);
                Script::from_bytes(v)
            }
            // P2SH mainnet (0x05) or testnet (0xc4)
            0x05 | 0xc4 => {
                let mut v = Vec::with_capacity(23);
                v.extend_from_slice(&[0xa9, 0x14]);
                v.extend_from_slice(hash);
                v.push(0x87);
                Script::from_bytes(v)
            }
            _ => return Err(WalletError::InvalidAddress(address.to_string())),
        };
        return Ok(script);
    }

    Err(WalletError::InvalidAddress(address.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hd::ExtendedPrivKey;

    fn test_key() -> (PublicKey, Keypair) {
        let seed = [1u8; 64];
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();
        let kp = master.keypair();
        let pk = master.public_key();
        (pk, kp)
    }

    #[test]
    fn p2pkh_address_length() {
        let (pk, _) = test_key();
        let addr = p2pkh_address(&pk, Network::Mainnet);
        assert!(addr.starts_with('1') || addr.starts_with('m') || addr.starts_with('n'));
    }

    #[test]
    fn p2wpkh_address_mainnet() {
        let (pk, _) = test_key();
        let addr = p2wpkh_address(&pk, Network::Mainnet).unwrap();
        assert!(addr.starts_with("bc1q"));
    }

    #[test]
    fn p2wpkh_address_regtest() {
        let (pk, _) = test_key();
        let addr = p2wpkh_address(&pk, Network::Regtest).unwrap();
        assert!(addr.starts_with("bcrt1q"));
    }

    #[test]
    fn p2tr_address_mainnet() {
        let (_, kp) = test_key();
        let addr = p2tr_address(&kp, Network::Mainnet).unwrap();
        assert!(addr.starts_with("bc1p"));
    }

    #[test]
    fn p2tr_address_regtest() {
        let (_, kp) = test_key();
        let addr = p2tr_address(&kp, Network::Regtest).unwrap();
        assert!(addr.starts_with("bcrt1p"));
    }

    #[test]
    fn p2pkh_script_correct() {
        let (pk, _) = test_key();
        let spk = p2pkh_script(&pk);
        assert!(spk.is_p2pkh());
    }

    #[test]
    fn p2wpkh_script_correct() {
        let (pk, _) = test_key();
        let spk = p2wpkh_script(&pk);
        assert!(spk.is_p2wpkh());
    }

    #[test]
    fn p2tr_script_correct() {
        let (_, kp) = test_key();
        let (_, xonly) = taproot_output_key(&kp).unwrap();
        let spk = p2tr_script(&xonly);
        assert!(spk.is_p2tr());
    }

    #[test]
    fn address_to_script_p2wpkh_roundtrip() {
        let (pk, _) = test_key();
        let addr = p2wpkh_address(&pk, Network::Mainnet).unwrap();
        let spk = address_to_script(&addr).unwrap();
        assert!(spk.is_p2wpkh());
    }

    #[test]
    fn address_to_script_p2tr_roundtrip() {
        let (_, kp) = test_key();
        let addr = p2tr_address(&kp, Network::Mainnet).unwrap();
        let spk = address_to_script(&addr).unwrap();
        assert!(spk.is_p2tr());
    }
}
