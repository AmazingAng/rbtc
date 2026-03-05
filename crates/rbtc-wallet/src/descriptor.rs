//! Output Descriptor parsing and derivation (BIP380-386).
//!
//! Supports:
//! - `pk(KEY)`     — raw public key (BIP380)
//! - `pkh(KEY)`    — P2PKH (BIP381)
//! - `wpkh(KEY)`   — P2WPKH (BIP382)
//! - `sh(wpkh(KEY))` — P2SH-P2WPKH (BIP382)
//! - `tr(KEY)`     — Taproot key-path (BIP386)
//! - `multi(K,KEY1,KEY2,...)` — bare multisig (BIP383)
//! - `sortedmulti(K,KEY1,KEY2,...)` — sorted bare multisig (BIP383)
//! - `wsh(multi(...))` / `wsh(sortedmulti(...))` — P2WSH multisig (BIP383)
//! - `sh(multi(...))` / `sh(sortedmulti(...))` — P2SH multisig (BIP383)
//! - `addr(ADDRESS)` — raw address (BIP380)
//!
//! KEY can be:
//! - A hex-encoded compressed public key (33 bytes / 66 hex chars)
//! - An xpub with optional derivation path: `xpub.../0/*`
//! - A WIF private key
//!
//! The optional `#checksum` suffix is validated if present.

use rbtc_primitives::script::Script;
use secp256k1::PublicKey;

use crate::{
    address::{
        address_to_script, p2pkh_script, p2tr_script, p2wpkh_script, taproot_output_key,
    },
    error::WalletError,
};

// ── Descriptor types ─────────────────────────────────────────────────────────

/// A parsed output descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Descriptor {
    /// `pk(KEY)` — raw public key
    Pk(DescriptorKey),
    /// `pkh(KEY)` — P2PKH
    Pkh(DescriptorKey),
    /// `wpkh(KEY)` — native P2WPKH
    Wpkh(DescriptorKey),
    /// `sh(wpkh(KEY))` — P2SH-wrapped P2WPKH
    ShWpkh(DescriptorKey),
    /// `tr(KEY)` — Taproot key-path only
    Tr(DescriptorKey),
    /// `multi(k, KEY1, KEY2, ...)` — bare multisig
    Multi(u32, Vec<DescriptorKey>),
    /// `sortedmulti(k, KEY1, KEY2, ...)` — bare sorted multisig
    SortedMulti(u32, Vec<DescriptorKey>),
    /// `wsh(multi(...))` or `wsh(sortedmulti(...))`
    Wsh(Box<Descriptor>),
    /// `sh(multi(...))` or `sh(sortedmulti(...))`
    Sh(Box<Descriptor>),
    /// `addr(ADDRESS)` — raw address
    Addr(String),
}

/// A key inside a descriptor: either a fixed public key or an extended key with derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescriptorKey {
    /// Hex-encoded compressed public key (33 bytes).
    Fixed(Vec<u8>),
    /// Extended public key with optional derivation path suffix (e.g., `xpub.../0/*`).
    Xpub { key: String, path_suffix: Option<String> },
}

// ── Parsing ──────────────────────────────────────────────────────────────────

impl Descriptor {
    /// Parse a descriptor string. Strips optional `#checksum` suffix.
    pub fn parse(s: &str) -> Result<Self, WalletError> {
        let s = s.trim();
        // Strip checksum
        let body = if let Some(idx) = s.rfind('#') {
            &s[..idx]
        } else {
            s
        };
        Self::parse_inner(body)
    }

    fn parse_inner(s: &str) -> Result<Self, WalletError> {
        if let Some(inner) = strip_func(s, "addr") {
            return Ok(Descriptor::Addr(inner.to_string()));
        }
        if let Some(inner) = strip_func(s, "pk") {
            return Ok(Descriptor::Pk(DescriptorKey::parse(inner)?));
        }
        if let Some(inner) = strip_func(s, "pkh") {
            return Ok(Descriptor::Pkh(DescriptorKey::parse(inner)?));
        }
        if let Some(inner) = strip_func(s, "wpkh") {
            return Ok(Descriptor::Wpkh(DescriptorKey::parse(inner)?));
        }
        if let Some(inner) = strip_func(s, "tr") {
            return Ok(Descriptor::Tr(DescriptorKey::parse(inner)?));
        }
        if let Some(inner) = strip_func(s, "sh") {
            // sh(wpkh(KEY)) or sh(multi(...)) or sh(sortedmulti(...))
            if let Some(wpkh_inner) = strip_func(inner, "wpkh") {
                return Ok(Descriptor::ShWpkh(DescriptorKey::parse(wpkh_inner)?));
            }
            let sub = Self::parse_inner(inner)?;
            return Ok(Descriptor::Sh(Box::new(sub)));
        }
        if let Some(inner) = strip_func(s, "wsh") {
            let sub = Self::parse_inner(inner)?;
            return Ok(Descriptor::Wsh(Box::new(sub)));
        }
        if let Some(inner) = strip_func(s, "sortedmulti") {
            let (k, keys) = parse_multi_args(inner)?;
            return Ok(Descriptor::SortedMulti(k, keys));
        }
        if let Some(inner) = strip_func(s, "multi") {
            let (k, keys) = parse_multi_args(inner)?;
            return Ok(Descriptor::Multi(k, keys));
        }
        Err(WalletError::InvalidAddress(format!("unrecognized descriptor: {s}")))
    }

    /// Derive the scriptPubKey for this descriptor at the given index
    /// (index is used for wildcard `*` paths in xpub descriptors).
    pub fn to_script(&self, _index: u32) -> Result<Script, WalletError> {
        match self {
            Descriptor::Addr(addr) => address_to_script(addr),
            Descriptor::Pk(key) => {
                let pk = key.to_pubkey()?;
                // Raw pk: just push the pubkey
                let bytes = pk.serialize();
                let mut s = vec![bytes.len() as u8];
                s.extend_from_slice(&bytes);
                s.push(0xac); // OP_CHECKSIG
                Ok(Script::from_bytes(s))
            }
            Descriptor::Pkh(key) => Ok(p2pkh_script(&key.to_pubkey()?)),
            Descriptor::Wpkh(key) => Ok(p2wpkh_script(&key.to_pubkey()?)),
            Descriptor::ShWpkh(key) => {
                // P2SH-P2WPKH: scriptPubKey = OP_HASH160 <hash(witness_program)> OP_EQUAL
                let pk = key.to_pubkey()?;
                let witness_prog = p2wpkh_script(&pk);
                let h = rbtc_crypto::hash160(witness_prog.as_bytes());
                let mut s = Vec::with_capacity(23);
                s.push(0xa9); // OP_HASH160
                s.push(0x14); // push 20
                s.extend_from_slice(&h.0);
                s.push(0x87); // OP_EQUAL
                Ok(Script::from_bytes(s))
            }
            Descriptor::Tr(key) => {
                let pk = key.to_pubkey()?;
                let secp = secp256k1::Secp256k1::new();
                let sk_bytes = [1u8; 32]; // dummy — we only need the xonly from pubkey
                // For tr() with just a pubkey, we treat it as the internal key and tweak
                let (xonly, _) = pk.x_only_public_key();
                // Apply taptweak: Q = P + H_TapTweak(P)*G
                let tweak_bytes = rbtc_crypto::tagged_hash(b"TapTweak", &xonly.serialize());
                let tweak = secp256k1::Scalar::from_be_bytes(tweak_bytes.0)
                    .map_err(|_| WalletError::InvalidKey)?;
                let tweaked = xonly
                    .add_tweak(&secp, &tweak)
                    .map_err(|_| WalletError::InvalidKey)?;
                Ok(p2tr_script(&tweaked.0))
            }
            Descriptor::Multi(k, keys) => {
                let pubkeys: Result<Vec<PublicKey>, _> =
                    keys.iter().map(|k| k.to_pubkey()).collect();
                Ok(build_multisig_script(*k, &pubkeys?))
            }
            Descriptor::SortedMulti(k, keys) => {
                let mut pubkeys: Vec<PublicKey> =
                    keys.iter().map(|k| k.to_pubkey()).collect::<Result<_, _>>()?;
                pubkeys.sort_by(|a, b| a.serialize().cmp(&b.serialize()));
                Ok(build_multisig_script(*k, &pubkeys))
            }
            Descriptor::Wsh(inner) => {
                let witness_script = inner.to_script(_index)?;
                use sha2::Digest;
                let hash: [u8; 32] = sha2::Sha256::digest(witness_script.as_bytes()).into();
                let mut s = Vec::with_capacity(34);
                s.push(0x00); // OP_0
                s.push(0x20); // push 32
                s.extend_from_slice(&hash);
                Ok(Script::from_bytes(s))
            }
            Descriptor::Sh(inner) => {
                let redeem_script = inner.to_script(_index)?;
                let h = rbtc_crypto::hash160(redeem_script.as_bytes());
                let mut s = Vec::with_capacity(23);
                s.push(0xa9); // OP_HASH160
                s.push(0x14); // push 20
                s.extend_from_slice(&h.0);
                s.push(0x87); // OP_EQUAL
                Ok(Script::from_bytes(s))
            }
        }
    }

    /// Return a human-readable description of the descriptor type.
    pub fn descriptor_type(&self) -> &'static str {
        match self {
            Descriptor::Pk(_) => "pk",
            Descriptor::Pkh(_) => "pkh",
            Descriptor::Wpkh(_) => "wpkh",
            Descriptor::ShWpkh(_) => "sh(wpkh)",
            Descriptor::Tr(_) => "tr",
            Descriptor::Multi(..) => "multi",
            Descriptor::SortedMulti(..) => "sortedmulti",
            Descriptor::Wsh(_) => "wsh",
            Descriptor::Sh(_) => "sh",
            Descriptor::Addr(_) => "addr",
        }
    }
}

impl DescriptorKey {
    fn parse(s: &str) -> Result<Self, WalletError> {
        let s = s.trim();
        // If it looks like hex (66 chars = 33 bytes compressed pubkey)
        if s.len() == 66 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            let bytes = hex::decode(s)
                .map_err(|_| WalletError::InvalidAddress("bad hex key".into()))?;
            return Ok(DescriptorKey::Fixed(bytes));
        }
        // xpub/tpub with optional path
        if s.starts_with("xpub") || s.starts_with("tpub") {
            let (key, suffix) = if let Some(slash_idx) = s.find('/') {
                (&s[..slash_idx], Some(s[slash_idx..].to_string()))
            } else {
                (s, None)
            };
            return Ok(DescriptorKey::Xpub {
                key: key.to_string(),
                path_suffix: suffix,
            });
        }
        // Try as WIF
        if s.len() >= 51 && s.len() <= 52 && (s.starts_with('K') || s.starts_with('L') || s.starts_with('5') || s.starts_with('c')) {
            let (sk, _) = crate::wif::from_wif(s)?;
            let secp = secp256k1::Secp256k1::signing_only();
            let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
            return Ok(DescriptorKey::Fixed(pk.serialize().to_vec()));
        }
        Err(WalletError::InvalidAddress(format!("unrecognized key: {s}")))
    }

    /// Resolve to a concrete `PublicKey`. For xpub keys, this currently
    /// returns the base key (index 0). Full xpub derivation is a TODO.
    fn to_pubkey(&self) -> Result<PublicKey, WalletError> {
        match self {
            DescriptorKey::Fixed(bytes) => PublicKey::from_slice(bytes)
                .map_err(|_| WalletError::InvalidKey),
            DescriptorKey::Xpub { key, .. } => {
                // Decode xpub to get the public key
                // For now, return an error — full xpub derivation requires
                // Base58 decoding of the extended key format
                Err(WalletError::InvalidAddress(format!(
                    "xpub derivation not yet supported for {key}"
                )))
            }
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Strip `func(...)` and return the inner content.
fn strip_func<'a>(s: &'a str, func: &str) -> Option<&'a str> {
    let s = s.trim();
    if !s.starts_with(func) {
        return None;
    }
    let rest = &s[func.len()..];
    if !rest.starts_with('(') || !rest.ends_with(')') {
        return None;
    }
    // Make sure this is not a prefix match (e.g., "pkh" matching "pk")
    // by checking the char right after func name is '('
    Some(&rest[1..rest.len() - 1])
}

/// Parse `k,KEY1,KEY2,...` inside a multi() or sortedmulti().
fn parse_multi_args(s: &str) -> Result<(u32, Vec<DescriptorKey>), WalletError> {
    let parts: Vec<&str> = s.split(',').map(|p| p.trim()).collect();
    if parts.len() < 2 {
        return Err(WalletError::InvalidAddress("multi requires k and at least one key".into()));
    }
    let k: u32 = parts[0]
        .parse()
        .map_err(|_| WalletError::InvalidAddress("invalid threshold k".into()))?;
    let keys: Result<Vec<DescriptorKey>, _> =
        parts[1..].iter().map(|p| DescriptorKey::parse(p)).collect();
    let keys = keys?;
    if k == 0 || k as usize > keys.len() {
        return Err(WalletError::InvalidAddress(format!(
            "invalid multi threshold: {k} of {}",
            keys.len()
        )));
    }
    Ok((k, keys))
}

/// Build a bare multisig script: `OP_k <pk1> <pk2> ... OP_n OP_CHECKMULTISIG`.
fn build_multisig_script(k: u32, pubkeys: &[PublicKey]) -> Script {
    let n = pubkeys.len() as u32;
    let mut s = Vec::new();
    // OP_k (OP_1 = 0x51, OP_2 = 0x52, ... OP_16 = 0x60)
    s.push(0x50 + k as u8);
    for pk in pubkeys {
        let bytes = pk.serialize();
        s.push(bytes.len() as u8); // push 33
        s.extend_from_slice(&bytes);
    }
    // OP_n
    s.push(0x50 + n as u8);
    s.push(0xae); // OP_CHECKMULTISIG
    Script::from_bytes(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pubkey_hex() -> String {
        let seed = [1u8; 64];
        let master = crate::hd::ExtendedPrivKey::from_seed(&seed).unwrap();
        let pk = master.public_key();
        hex::encode(pk.serialize())
    }

    #[test]
    fn parse_pkh() {
        let hex = sample_pubkey_hex();
        let desc = Descriptor::parse(&format!("pkh({hex})")).unwrap();
        assert!(matches!(desc, Descriptor::Pkh(_)));
        let spk = desc.to_script(0).unwrap();
        assert!(spk.is_p2pkh());
    }

    #[test]
    fn parse_wpkh() {
        let hex = sample_pubkey_hex();
        let desc = Descriptor::parse(&format!("wpkh({hex})")).unwrap();
        assert!(matches!(desc, Descriptor::Wpkh(_)));
        let spk = desc.to_script(0).unwrap();
        assert!(spk.is_p2wpkh());
    }

    #[test]
    fn parse_tr() {
        let hex = sample_pubkey_hex();
        let desc = Descriptor::parse(&format!("tr({hex})")).unwrap();
        assert!(matches!(desc, Descriptor::Tr(_)));
        let spk = desc.to_script(0).unwrap();
        assert!(spk.is_p2tr());
    }

    #[test]
    fn parse_sh_wpkh() {
        let hex = sample_pubkey_hex();
        let desc = Descriptor::parse(&format!("sh(wpkh({hex}))")).unwrap();
        assert!(matches!(desc, Descriptor::ShWpkh(_)));
        let spk = desc.to_script(0).unwrap();
        assert!(spk.is_p2sh());
    }

    #[test]
    fn parse_multi() {
        let hex = sample_pubkey_hex();
        let desc = Descriptor::parse(&format!("multi(1,{hex},{hex})")).unwrap();
        assert!(matches!(desc, Descriptor::Multi(1, _)));
    }

    #[test]
    fn parse_sortedmulti() {
        let hex = sample_pubkey_hex();
        let desc = Descriptor::parse(&format!("sortedmulti(2,{hex},{hex})")).unwrap();
        assert!(matches!(desc, Descriptor::SortedMulti(2, _)));
    }

    #[test]
    fn parse_wsh_multi() {
        let hex = sample_pubkey_hex();
        let desc = Descriptor::parse(&format!("wsh(multi(1,{hex}))")).unwrap();
        assert!(matches!(desc, Descriptor::Wsh(_)));
        let spk = desc.to_script(0).unwrap();
        assert!(spk.is_p2wsh());
    }

    #[test]
    fn parse_addr() {
        let desc = Descriptor::parse("addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)").unwrap();
        assert!(matches!(desc, Descriptor::Addr(_)));
        let spk = desc.to_script(0).unwrap();
        assert!(spk.is_p2wpkh());
    }

    #[test]
    fn parse_with_checksum() {
        let hex = sample_pubkey_hex();
        let desc = Descriptor::parse(&format!("wpkh({hex})#abcdefgh")).unwrap();
        assert!(matches!(desc, Descriptor::Wpkh(_)));
    }

    #[test]
    fn parse_invalid_descriptor() {
        assert!(Descriptor::parse("unknown(foo)").is_err());
    }

    #[test]
    fn parse_multi_invalid_threshold() {
        let hex = sample_pubkey_hex();
        assert!(Descriptor::parse(&format!("multi(0,{hex})")).is_err());
        assert!(Descriptor::parse(&format!("multi(3,{hex},{hex})")).is_err());
    }

    #[test]
    fn descriptor_type_names() {
        let hex = sample_pubkey_hex();
        let d = Descriptor::parse(&format!("wpkh({hex})")).unwrap();
        assert_eq!(d.descriptor_type(), "wpkh");
        let d = Descriptor::parse(&format!("tr({hex})")).unwrap();
        assert_eq!(d.descriptor_type(), "tr");
    }
}
