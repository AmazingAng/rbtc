//! Bitcoin address generation for P2PKH, P2WPKH, and P2TR.

use bech32::{segwit, Fe32, Hrp};
use secp256k1::{Keypair, PublicKey, Scalar, XOnlyPublicKey};
use sha2::{Digest, Sha256};

use rbtc_crypto::{hash160, sha256, tagged_hash};
use rbtc_primitives::{network::Network, script::Script};

use crate::error::WalletError;

// ── AddressType ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    /// Legacy P2PKH — BIP44 path m/44'/coin'/account'/change/index
    Legacy,
    /// P2SH-wrapped SegWit P2WPKH — BIP49 path m/49'/coin'/account'/change/index
    P2shP2wpkh,
    /// Native SegWit P2WPKH — BIP84 path m/84'/coin'/account'/change/index
    SegWit,
    /// Taproot P2TR — BIP86 path m/86'/coin'/account'/change/index
    Taproot,
}

impl AddressType {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "legacy" | "p2pkh" => Some(Self::Legacy),
            "p2sh-p2wpkh" | "p2sh_p2wpkh" | "nested-segwit" => Some(Self::P2shP2wpkh),
            "bech32" | "p2wpkh" | "segwit" => Some(Self::SegWit),
            "bech32m" | "p2tr" | "taproot" => Some(Self::Taproot),
            _ => None,
        }
    }
}

// ── Network helpers ────────────────────────────────────────────────────────────

fn bech32_hrp(network: Network) -> Hrp {
    let s = match network {
        Network::Mainnet => "bc",
        Network::Testnet3 | Network::Testnet4 => "tb",
        Network::Regtest => "bcrt",
        Network::Signet => "tb",
    };
    Hrp::parse(s).expect("static HRP string is always valid")
}

/// Version byte for P2PKH addresses.
fn p2pkh_version(network: Network) -> u8 {
    match network {
        Network::Mainnet => 0x00,
        _ => 0x6f,
    }
}

/// Version byte for P2SH addresses.
pub(crate) fn p2sh_version(network: Network) -> u8 {
    match network {
        Network::Mainnet => 0x05,
        _ => 0xc4,
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

/// Construct a P2SH address from a 20-byte script hash (HASH160 of the redeemScript).
pub fn p2sh_address(script_hash: &[u8; 20], network: Network) -> String {
    let mut versioned = Vec::with_capacity(21);
    versioned.push(p2sh_version(network));
    versioned.extend_from_slice(script_hash);
    base58check_encode(&versioned)
}

/// Construct a P2SH-P2WPKH (nested SegWit) address from a 20-byte pubkey hash.
///
/// This wraps a P2WPKH witness program (`OP_0 <20-byte-pubkey-hash>`) inside
/// a P2SH address.  The redeemScript is the 22-byte witness program; the
/// address is `base58check(0x05 || HASH160(redeemScript))` on mainnet.
pub fn p2sh_p2wpkh_address(pubkey_hash: &[u8; 20], network: Network) -> String {
    // redeemScript = OP_0 PUSH20 <pubkey_hash>  (22 bytes)
    let mut redeem_script = Vec::with_capacity(22);
    redeem_script.push(0x00); // OP_0
    redeem_script.push(0x14); // push 20 bytes
    redeem_script.extend_from_slice(pubkey_hash);

    let script_hash = hash160(&redeem_script);
    p2sh_address(&script_hash.0, network)
}

/// Generate a P2WSH address from a witness script.
/// The address encodes SHA256(witness_script) as a bech32 witness v0 program.
pub fn p2wsh_address(witness_script: &[u8], network: Network) -> String {
    let script_hash = sha256(witness_script);
    let hrp = bech32_hrp(network);
    let witver = Fe32::try_from(0u8).unwrap(); // witness version 0 → bech32
    segwit::encode(hrp, witver, &script_hash.0)
        .expect("32-byte program with witness v0 is always valid bech32")
}

/// Generate a P2SH-wrapped P2WSH address from a witness script.
pub fn p2sh_p2wsh_address(witness_script: &[u8], network: Network) -> String {
    // witness program = OP_0 PUSH32 <sha256(witness_script)>  (34 bytes)
    let script_hash = sha256(witness_script);
    let mut witness_program = Vec::with_capacity(34);
    witness_program.push(0x00); // OP_0
    witness_program.push(0x20); // push 32 bytes
    witness_program.extend_from_slice(&script_hash.0);

    let program_hash = hash160(&witness_program);
    p2sh_address(&program_hash.0, network)
}

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
    segwit::encode(hrp, witver, &h160.0).map_err(|e| WalletError::AddressEncoding(e.to_string()))
}

/// Compute the Taproot output key and x-only bytes for a given internal key.
/// This follows BIP341 key-path-only tweaking: Q = P + H_TapTweak(P)*G.
pub fn taproot_output_key(keypair: &Keypair) -> Result<(Keypair, XOnlyPublicKey), WalletError> {
    let secp = secp256k1::Secp256k1::new();
    let (xonly, _parity) = keypair.x_only_public_key();
    let tweak_bytes = tagged_hash(b"TapTweak", &xonly.serialize());
    let tweak_scalar = Scalar::from_be_bytes(tweak_bytes.0).map_err(|_| WalletError::InvalidKey)?;
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

/// Build the P2SH scriptPubKey for a P2SH-P2WPKH output.
///
/// The redeemScript is `OP_0 <20-byte-pubkey-hash>` (a P2WPKH witness program).
/// The scriptPubKey is `OP_HASH160 <HASH160(redeemScript)> OP_EQUAL`.
pub fn p2sh_p2wpkh_script(pubkey: &PublicKey) -> Script {
    let pubkey_hash = hash160(&pubkey.serialize());

    // redeemScript = OP_0 PUSH20 <pubkey_hash>  (22 bytes)
    let mut redeem_script = Vec::with_capacity(22);
    redeem_script.push(0x00); // OP_0
    redeem_script.push(0x14); // push 20 bytes
    redeem_script.extend_from_slice(&pubkey_hash.0);

    let script_hash = hash160(&redeem_script);

    // scriptPubKey = OP_HASH160 PUSH20 <script_hash> OP_EQUAL  (23 bytes)
    let mut v = Vec::with_capacity(23);
    v.push(0xa9); // OP_HASH160
    v.push(0x14); // push 20 bytes
    v.extend_from_slice(&script_hash.0);
    v.push(0x87); // OP_EQUAL
    Script::from_bytes(v)
}

/// Construct a P2SH-P2WPKH address from a compressed public key.
pub fn p2sh_p2wpkh_address_from_pubkey(
    pubkey: &PublicKey,
    network: Network,
) -> String {
    let pubkey_hash = hash160(&pubkey.serialize());
    p2sh_p2wpkh_address(&pubkey_hash.0, network)
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

/// Build the scriptPubKey for a P2WSH output from a witness script.
pub fn p2wsh_script(witness_script: &[u8]) -> Script {
    let script_hash = sha256(witness_script);
    let mut v = Vec::with_capacity(34);
    v.push(0x00); // OP_0
    v.push(0x20); // push 32 bytes
    v.extend_from_slice(&script_hash.0);
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
        // Validate HRP against known Bitcoin networks
        let hrp_str = hrp.as_str();
        if hrp_str != "bc" && hrp_str != "tb" && hrp_str != "bcrt" {
            return Err(WalletError::InvalidAddress(address.to_string()));
        }
        let v = version.to_u8();
        let mut s = Vec::with_capacity(2 + program.len());
        s.push(if v == 0 { 0x00 } else { 0x50 + v }); // OP_0 or OP_N
        s.push(program.len() as u8);
        s.extend_from_slice(&program);
        return Ok(Script::from_bytes(s));
    }

    // Try Base58Check (P2PKH / P2SH)
    if let Ok(decoded) = bs58::decode(address).with_check(None).into_vec() {
        if decoded.len() != 21 {
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

    #[test]
    fn p2sh_address_mainnet_prefix() {
        let script_hash = [0xabu8; 20];
        let addr = p2sh_address(&script_hash, Network::Mainnet);
        assert!(
            addr.starts_with('3'),
            "mainnet P2SH should start with '3', got {addr}"
        );
    }

    #[test]
    fn p2sh_address_testnet_prefix() {
        let script_hash = [0xabu8; 20];
        let addr = p2sh_address(&script_hash, Network::Testnet4);
        assert!(
            addr.starts_with('2'),
            "testnet P2SH should start with '2', got {addr}"
        );
    }

    #[test]
    fn p2sh_address_roundtrip_via_address_to_script() {
        let script_hash = [0x42u8; 20];
        let addr = p2sh_address(&script_hash, Network::Mainnet);
        let spk = address_to_script(&addr).unwrap();
        assert!(spk.is_p2sh(), "decoded script should be P2SH");
    }

    #[test]
    fn p2sh_p2wpkh_address_mainnet() {
        let (pk, _) = test_key();
        let h160 = hash160(&pk.serialize());
        let addr = p2sh_p2wpkh_address(&h160.0, Network::Mainnet);
        assert!(
            addr.starts_with('3'),
            "mainnet P2SH-P2WPKH should start with '3', got {addr}"
        );
        // Verify it decodes as P2SH
        let spk = address_to_script(&addr).unwrap();
        assert!(spk.is_p2sh());
    }

    #[test]
    fn p2sh_p2wpkh_address_testnet() {
        let (pk, _) = test_key();
        let h160 = hash160(&pk.serialize());
        let addr = p2sh_p2wpkh_address(&h160.0, Network::Testnet4);
        assert!(
            addr.starts_with('2'),
            "testnet P2SH-P2WPKH should start with '2', got {addr}"
        );
    }

    // ── P2WSH tests ──────────────────────────────────────────────────────────

    #[test]
    fn p2wsh_address_mainnet_prefix() {
        // A simple witness script (OP_1 = 0x51)
        let witness_script = vec![0x51];
        let addr = p2wsh_address(&witness_script, Network::Mainnet);
        // P2WSH bech32 addresses start with bc1q and are longer than P2WPKH
        // (32-byte program vs 20-byte)
        assert!(
            addr.starts_with("bc1q"),
            "mainnet P2WSH should start with 'bc1q', got {addr}"
        );
        // P2WSH addresses are longer than P2WPKH (62 chars for mainnet vs 42)
        assert!(
            addr.len() > 50,
            "P2WSH address should be longer than P2WPKH, got len={}",
            addr.len()
        );
    }

    #[test]
    fn p2wsh_address_testnet_prefix() {
        let witness_script = vec![0x51];
        let addr = p2wsh_address(&witness_script, Network::Testnet4);
        assert!(
            addr.starts_with("tb1q"),
            "testnet P2WSH should start with 'tb1q', got {addr}"
        );
    }

    #[test]
    fn p2sh_p2wsh_address_mainnet_prefix() {
        let witness_script = vec![0x51];
        let addr = p2sh_p2wsh_address(&witness_script, Network::Mainnet);
        assert!(
            addr.starts_with('3'),
            "mainnet P2SH-P2WSH should start with '3', got {addr}"
        );
        // Verify it decodes as P2SH
        let spk = address_to_script(&addr).unwrap();
        assert!(spk.is_p2sh());
    }

    #[test]
    fn p2sh_p2wsh_address_testnet_prefix() {
        let witness_script = vec![0x51];
        let addr = p2sh_p2wsh_address(&witness_script, Network::Testnet4);
        assert!(
            addr.starts_with('2'),
            "testnet P2SH-P2WSH should start with '2', got {addr}"
        );
    }

    #[test]
    fn p2wsh_roundtrip_script_hash() {
        use rbtc_crypto::sha256 as crypto_sha256;

        // Create a witness script, generate address, decode back, verify hash
        let witness_script = vec![0x52, 0x21]; // some arbitrary script bytes
        let addr = p2wsh_address(&witness_script, Network::Mainnet);
        let spk = address_to_script(&addr).unwrap();

        // scriptPubKey should be OP_0 PUSH32 <sha256(witness_script)>
        assert!(spk.is_p2wsh(), "decoded script should be P2WSH");

        let spk_bytes = spk.as_bytes();
        let expected_hash = crypto_sha256(&witness_script);
        // spk_bytes[0] = 0x00 (OP_0), spk_bytes[1] = 0x20, spk_bytes[2..34] = hash
        assert_eq!(&spk_bytes[2..34], &expected_hash.0);
    }

    #[test]
    fn p2wsh_script_correct() {
        let witness_script = vec![0x51, 0xae]; // OP_1 OP_CHECKMULTISIG
        let spk = p2wsh_script(&witness_script);
        assert!(spk.is_p2wsh());
    }
}
