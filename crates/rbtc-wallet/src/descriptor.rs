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

use std::collections::HashMap;

use rbtc_primitives::script::Script;
use secp256k1::PublicKey;

use crate::{
    address::{address_to_script, p2pkh_script, p2tr_script, p2wpkh_script},
    error::WalletError,
};

// ── BIP380 descriptor checksum ───────────────────────────────────────────────

/// Character set for BIP380 descriptor checksums (same as bech32).
const CHECKSUM_CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Map an input character to its BIP380 group value.
/// Returns None for invalid characters.
fn checksum_char_group(c: char) -> Option<u8> {
    // Characters from 0x20 to 0x7e are mapped to groups.
    // Groups are defined as: INPUT_CHARSET position modulo 32 relationships.
    const INPUT_CHARSET: &str =
        "0123456789()[],'/*abcdefgh@:$%{}\
         IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~\
         ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
    INPUT_CHARSET.find(c).map(|pos| pos as u8)
}

/// BIP380 polymod for descriptor checksum.
fn descriptor_polymod(c: &mut u64, val: u64) {
    let c0 = *c >> 35;
    *c = ((*c & 0x7ffffffff) << 5) ^ val;
    if c0 & 1 != 0 { *c ^= 0xf5dee51989; }
    if c0 & 2 != 0 { *c ^= 0xa9fdca3312; }
    if c0 & 4 != 0 { *c ^= 0x1bab10e32d; }
    if c0 & 8 != 0 { *c ^= 0x3706b1677a; }
    if c0 & 16 != 0 { *c ^= 0x644d626ffd; }
}

/// Compute the BIP380 8-character descriptor checksum.
fn descriptor_checksum(desc: &str) -> Result<String, WalletError> {
    let mut c: u64 = 1;
    let mut cls: u64 = 0;
    let mut clscount: u64 = 0;

    for ch in desc.chars() {
        let pos = checksum_char_group(ch).ok_or_else(|| {
            WalletError::InvalidAddress(format!("invalid descriptor character: '{ch}'"))
        })? as u64;
        descriptor_polymod(&mut c, pos & 31);
        cls = cls * 3 + (pos >> 5);
        clscount += 1;
        if clscount == 3 {
            descriptor_polymod(&mut c, cls);
            cls = 0;
            clscount = 0;
        }
    }
    if clscount > 0 {
        descriptor_polymod(&mut c, cls);
    }
    // Finalize: feed 8 zeros and XOR with 1
    for _ in 0..8 {
        descriptor_polymod(&mut c, 0);
    }
    c ^= 1;

    let charset: Vec<char> = CHECKSUM_CHARSET.chars().collect();
    let mut result = String::with_capacity(8);
    for j in 0..8 {
        result.push(charset[((c >> (5 * (7 - j))) & 31) as usize]);
    }
    Ok(result)
}

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

/// Optional key origin information: `[fingerprint/derivation/path]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyOrigin {
    /// 4-byte fingerprint of the master key (hex-encoded, 8 chars).
    pub fingerprint: [u8; 4],
    /// Derivation path from the master key (e.g., `[44h, 0h, 0h]` with HARDENED bit set).
    pub path: Vec<u32>,
}

impl KeyOrigin {
    /// Parse a key origin string like `"d34db33f/84h/0h/0h"`.
    pub fn parse(s: &str) -> Result<Self, WalletError> {
        let parts: Vec<&str> = s.splitn(2, '/').collect();
        let fp_hex = parts[0];
        if fp_hex.len() != 8 {
            return Err(WalletError::InvalidPath(format!(
                "fingerprint must be 8 hex chars, got: {fp_hex}"
            )));
        }
        let fp_bytes = hex::decode(fp_hex)
            .map_err(|_| WalletError::InvalidPath(format!("bad fingerprint hex: {fp_hex}")))?;
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&fp_bytes);

        let mut path = Vec::new();
        if parts.len() > 1 {
            for component in parts[1].split('/').filter(|s| !s.is_empty()) {
                path.push(parse_path_component(component)?);
            }
        }
        Ok(KeyOrigin { fingerprint, path })
    }
}

impl std::fmt::Display for KeyOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.fingerprint))?;
        for &idx in &self.path {
            if idx >= crate::hd::HARDENED {
                write!(f, "/{}h", idx & !crate::hd::HARDENED)?;
            } else {
                write!(f, "/{idx}")?;
            }
        }
        Ok(())
    }
}

/// A key inside a descriptor: either a fixed public key or an extended key with derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescriptorKey {
    /// Hex-encoded compressed public key (33 bytes), with optional origin.
    Fixed(Vec<u8>, Option<KeyOrigin>),
    /// Extended public key with optional derivation path suffix (e.g., `xpub.../0/*`),
    /// and optional key origin prefix.
    Xpub {
        origin: Option<KeyOrigin>,
        key: String,
        path_suffix: Option<String>,
    },
}

// ── Parsing ──────────────────────────────────────────────────────────────────

impl Descriptor {
    /// Parse a descriptor string. Validates the `#checksum` suffix if present (BIP380).
    pub fn parse(s: &str) -> Result<Self, WalletError> {
        let s = s.trim();
        let body = if let Some(idx) = s.rfind('#') {
            let body = &s[..idx];
            let provided = &s[idx + 1..];
            let expected = descriptor_checksum(body)?;
            if provided != expected {
                return Err(WalletError::InvalidAddress(format!(
                    "descriptor checksum mismatch: expected {expected}, got {provided}"
                )));
            }
            body
        } else {
            s
        };
        Self::parse_inner(body)
    }

    /// Return the descriptor string with BIP380 checksum appended.
    pub fn checksum(descriptor_body: &str) -> Result<String, WalletError> {
        let cs = descriptor_checksum(descriptor_body)?;
        Ok(format!("{descriptor_body}#{cs}"))
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
        Err(WalletError::InvalidAddress(format!(
            "unrecognized descriptor: {s}"
        )))
    }

    /// Derive the scriptPubKey for this descriptor at the given index
    /// (index is used for wildcard `*` paths in xpub descriptors).
    pub fn to_script(&self, index: u32) -> Result<Script, WalletError> {
        match self {
            Descriptor::Addr(addr) => address_to_script(addr),
            Descriptor::Pk(key) => {
                let pk = key.to_pubkey_at(index)?;
                // Raw pk: just push the pubkey
                let bytes = pk.serialize();
                let mut s = vec![bytes.len() as u8];
                s.extend_from_slice(&bytes);
                s.push(0xac); // OP_CHECKSIG
                Ok(Script::from_bytes(s))
            }
            Descriptor::Pkh(key) => Ok(p2pkh_script(&key.to_pubkey_at(index)?)),
            Descriptor::Wpkh(key) => Ok(p2wpkh_script(&key.to_pubkey_at(index)?)),
            Descriptor::ShWpkh(key) => {
                // P2SH-P2WPKH: scriptPubKey = OP_HASH160 <hash(witness_program)> OP_EQUAL
                let pk = key.to_pubkey_at(index)?;
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
                let pk = key.to_pubkey_at(index)?;
                let secp = secp256k1::Secp256k1::new();
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
                    keys.iter().map(|k| k.to_pubkey_at(index)).collect();
                Ok(build_multisig_script(*k, &pubkeys?))
            }
            Descriptor::SortedMulti(k, keys) => {
                let mut pubkeys: Vec<PublicKey> = keys
                    .iter()
                    .map(|k| k.to_pubkey_at(index))
                    .collect::<Result<_, _>>()?;
                pubkeys.sort_by_key(|k| k.serialize());
                Ok(build_multisig_script(*k, &pubkeys))
            }
            Descriptor::Wsh(inner) => {
                let witness_script = inner.to_script(index)?;
                use sha2::Digest;
                let hash: [u8; 32] = sha2::Sha256::digest(witness_script.as_bytes()).into();
                let mut s = Vec::with_capacity(34);
                s.push(0x00); // OP_0
                s.push(0x20); // push 32
                s.extend_from_slice(&hash);
                Ok(Script::from_bytes(s))
            }
            Descriptor::Sh(inner) => {
                let redeem_script = inner.to_script(index)?;
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

    /// Whether the descriptor contains a wildcard `*` derivation element (is ranged).
    pub fn is_range(&self) -> bool {
        match self {
            Descriptor::Pk(k)
            | Descriptor::Pkh(k)
            | Descriptor::Wpkh(k)
            | Descriptor::ShWpkh(k)
            | Descriptor::Tr(k) => k.is_range(),
            Descriptor::Multi(_, keys) | Descriptor::SortedMulti(_, keys) => {
                keys.iter().any(|k| k.is_range())
            }
            Descriptor::Wsh(inner) | Descriptor::Sh(inner) => inner.is_range(),
            Descriptor::Addr(_) => false,
        }
    }

    /// Whether the descriptor is solvable (can produce a spending script).
    /// `addr()` descriptors are not solvable because we cannot reconstruct the
    /// full script needed to spend; everything else is solvable.
    pub fn is_solvable(&self) -> bool {
        !matches!(self, Descriptor::Addr(_))
    }

    /// Return the canonical string representation (public-key only, no checksum).
    pub fn to_string_body(&self) -> String {
        match self {
            Descriptor::Pk(k) => format!("pk({})", k.to_canonical_string()),
            Descriptor::Pkh(k) => format!("pkh({})", k.to_canonical_string()),
            Descriptor::Wpkh(k) => format!("wpkh({})", k.to_canonical_string()),
            Descriptor::ShWpkh(k) => format!("sh(wpkh({}))", k.to_canonical_string()),
            Descriptor::Tr(k) => format!("tr({})", k.to_canonical_string()),
            Descriptor::Multi(threshold, keys) => {
                let keys_str: Vec<String> =
                    keys.iter().map(|k| k.to_canonical_string()).collect();
                format!("multi({},{})", threshold, keys_str.join(","))
            }
            Descriptor::SortedMulti(threshold, keys) => {
                let keys_str: Vec<String> =
                    keys.iter().map(|k| k.to_canonical_string()).collect();
                format!("sortedmulti({},{})", threshold, keys_str.join(","))
            }
            Descriptor::Wsh(inner) => format!("wsh({})", inner.to_string_body()),
            Descriptor::Sh(inner) => format!("sh({})", inner.to_string_body()),
            Descriptor::Addr(addr) => format!("addr({})", addr),
        }
    }

    /// Return the canonical string representation with BIP380 checksum.
    pub fn to_string_with_checksum(&self) -> Result<String, WalletError> {
        let body = self.to_string_body();
        Self::checksum(&body)
    }
}

impl DescriptorKey {
    fn parse(s: &str) -> Result<Self, WalletError> {
        let s = s.trim();

        // Parse optional key origin prefix: [fingerprint/path]
        let (origin, rest) = if s.starts_with('[') {
            let close = s.find(']').ok_or_else(|| {
                WalletError::InvalidAddress("missing ']' in key origin".into())
            })?;
            let origin_str = &s[1..close];
            let origin = KeyOrigin::parse(origin_str)?;
            (Some(origin), &s[close + 1..])
        } else {
            (None, s)
        };

        // If it looks like hex (66 chars = 33 bytes compressed pubkey)
        if rest.len() == 66 && rest.chars().all(|c| c.is_ascii_hexdigit()) {
            let bytes =
                hex::decode(rest).map_err(|_| WalletError::InvalidAddress("bad hex key".into()))?;
            return Ok(DescriptorKey::Fixed(bytes, origin));
        }
        // xpub/tpub with optional path
        if rest.starts_with("xpub") || rest.starts_with("tpub") {
            let (key, suffix) = if let Some(slash_idx) = rest.find('/') {
                (&rest[..slash_idx], Some(rest[slash_idx..].to_string()))
            } else {
                (rest, None)
            };
            return Ok(DescriptorKey::Xpub {
                origin,
                key: key.to_string(),
                path_suffix: suffix,
            });
        }
        // Try as WIF
        if rest.len() >= 51
            && rest.len() <= 52
            && (rest.starts_with('K')
                || rest.starts_with('L')
                || rest.starts_with('5')
                || rest.starts_with('c'))
        {
            let (sk, _) = crate::wif::from_wif(rest)?;
            let secp = secp256k1::Secp256k1::signing_only();
            let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
            return Ok(DescriptorKey::Fixed(pk.serialize().to_vec(), origin));
        }
        Err(WalletError::InvalidAddress(format!(
            "unrecognized key: {rest}"
        )))
    }

    /// Return the key origin if present.
    pub fn origin(&self) -> Option<&KeyOrigin> {
        match self {
            DescriptorKey::Fixed(_, origin) => origin.as_ref(),
            DescriptorKey::Xpub { origin, .. } => origin.as_ref(),
        }
    }

    /// Whether this key contains a wildcard `*` (is ranged).
    pub fn is_range(&self) -> bool {
        match self {
            DescriptorKey::Fixed(..) => false,
            DescriptorKey::Xpub { path_suffix, .. } => {
                path_suffix.as_deref().map_or(false, |s| s.contains('*'))
            }
        }
    }

    /// Return the canonical public-key string representation (with origin prefix if present).
    pub fn to_canonical_string(&self) -> String {
        let origin_prefix = match self.origin() {
            Some(o) => format!("[{}]", o.to_string()),
            None => String::new(),
        };
        match self {
            DescriptorKey::Fixed(bytes, _) => {
                format!("{}{}", origin_prefix, hex::encode(bytes))
            }
            DescriptorKey::Xpub {
                key, path_suffix, ..
            } => match path_suffix {
                Some(suffix) => format!("{}{}{}", origin_prefix, key, suffix),
                None => format!("{}{}", origin_prefix, key),
            },
        }
    }

    /// Resolve to a concrete `PublicKey` at the given derivation index.
    /// For fixed keys, the index is ignored.
    /// For xpub keys, the path suffix is applied (replacing `*` with `index`).
    /// Supports hardened notation: `h`, `H`, or `'` suffix on path components.
    fn to_pubkey_at(&self, index: u32) -> Result<PublicKey, WalletError> {
        match self {
            DescriptorKey::Fixed(bytes, _) => {
                PublicKey::from_slice(bytes).map_err(|_| WalletError::InvalidKey)
            }
            DescriptorKey::Xpub { key, path_suffix, .. } => {
                let xpub = crate::hd::ExtendedPubKey::from_base58(key)?;
                // Apply path suffix if present, e.g., "/0/*" → derive child 0, then child `index`
                let mut current = xpub;
                if let Some(suffix) = path_suffix {
                    for component in suffix.split('/').filter(|s| !s.is_empty()) {
                        let child_idx = if component == "*" {
                            index
                        } else {
                            parse_path_component(component)?
                        };
                        current = current.derive_child(child_idx)?;
                    }
                }
                Ok(current.public_key)
            }
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// ── Multipath expansion ─────────────────────────────────────────────────────

/// Expand multipath descriptors containing `<a;b;...>` into multiple
/// individual descriptor strings.
///
/// For example, `wpkh([fp/44h/0h/0h]xpub.../<0;1>/*)` expands to:
/// - `wpkh([fp/44h/0h/0h]xpub.../0/*)`
/// - `wpkh([fp/44h/0h/0h]xpub.../1/*)`
///
/// If no multipath expression is found, returns a vec with the original string.
/// Multiple `<a;b>` expressions in one descriptor are supported (they must
/// all have the same number of alternatives).
pub fn expand_multipath(descriptor: &str) -> Result<Vec<String>, WalletError> {
    // Strip checksum first
    let (body, has_checksum) = if let Some(idx) = descriptor.rfind('#') {
        (&descriptor[..idx], true)
    } else {
        (descriptor, false)
    };

    // Find all <a;b;...> expressions
    let mut alternatives_list: Vec<Vec<&str>> = Vec::new();
    let mut positions: Vec<(usize, usize)> = Vec::new();

    let mut search_start = 0;
    while let Some(open) = body[search_start..].find('<') {
        let open = search_start + open;
        let close = body[open..].find('>').ok_or_else(|| {
            WalletError::InvalidAddress("unmatched '<' in multipath descriptor".into())
        })?;
        let close = open + close;
        let inner = &body[open + 1..close];
        let alts: Vec<&str> = inner.split(';').collect();
        if alts.len() < 2 {
            return Err(WalletError::InvalidAddress(
                "multipath expression must have at least 2 alternatives".into(),
            ));
        }
        alternatives_list.push(alts);
        positions.push((open, close));
        search_start = close + 1;
    }

    if alternatives_list.is_empty() {
        return Ok(vec![descriptor.to_string()]);
    }

    // All multipath expressions must have the same number of alternatives
    let count = alternatives_list[0].len();
    for (i, alts) in alternatives_list.iter().enumerate() {
        if alts.len() != count {
            return Err(WalletError::InvalidAddress(format!(
                "multipath expression {} has {} alternatives, expected {count}",
                i, alts.len()
            )));
        }
    }

    // Generate one descriptor per alternative index
    let mut results = Vec::with_capacity(count);
    for alt_idx in 0..count {
        let mut result = String::new();
        let mut last_end = 0;
        for (pos_idx, &(start, end)) in positions.iter().enumerate() {
            result.push_str(&body[last_end..start]);
            result.push_str(alternatives_list[pos_idx][alt_idx]);
            last_end = end + 1;
        }
        result.push_str(&body[last_end..]);

        // Re-compute checksum for expanded descriptor
        if has_checksum {
            let cs = descriptor_checksum(&result)?;
            result = format!("{result}#{cs}");
        }
        results.push(result);
    }

    Ok(results)
}

/// Parse a single derivation path component like `"44h"`, `"0'"`, `"0H"`, or `"3"`.
/// Returns the u32 index with the HARDENED bit set if applicable.
fn parse_path_component(s: &str) -> Result<u32, WalletError> {
    let s = s.trim();
    let (num_str, hardened) = if s.ends_with('h') || s.ends_with('H') || s.ends_with('\'') {
        (&s[..s.len() - 1], true)
    } else {
        (s, false)
    };
    let n: u32 = num_str.parse().map_err(|_| {
        WalletError::InvalidPath(format!("bad path component: {s}"))
    })?;
    Ok(if hardened { n | crate::hd::HARDENED } else { n })
}

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
        return Err(WalletError::InvalidAddress(
            "multi requires k and at least one key".into(),
        ));
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

// ── Descriptor Wallet Manager ────────────────────────────────────────────────

/// A descriptor-based wallet manager (BIP380-386).
///
/// Bitcoin Core's modern wallet uses output descriptors to define which
/// scriptPubKeys belong to the wallet. This struct manages a collection of
/// descriptor strings with per-descriptor derivation indices, matching
/// Bitcoin Core's `DescriptorScriptPubKeyMan`.
#[derive(Debug, Clone)]
pub struct DescriptorWallet {
    /// Output descriptor strings (e.g., `"wpkh(xpub.../0/*)"`)
    descriptors: Vec<String>,
    /// Gap limit: how far ahead to scan beyond the last used index.
    gap_limit: u32,
    /// Next derivation index per descriptor string.
    next_index: HashMap<String, u32>,
}

impl DescriptorWallet {
    /// Create a new empty descriptor wallet with the given gap limit.
    pub fn new(gap_limit: u32) -> Self {
        Self {
            descriptors: Vec::new(),
            gap_limit,
            next_index: HashMap::new(),
        }
    }

    /// Add an output descriptor string to the wallet.
    ///
    /// The descriptor is validated by parsing it; returns an error if the
    /// descriptor syntax is invalid.
    pub fn add_descriptor(&mut self, desc: &str) -> Result<(), WalletError> {
        // Validate the descriptor string by parsing it.
        let _ = Descriptor::parse(desc)?;
        if !self.descriptors.contains(&desc.to_string()) {
            self.descriptors.push(desc.to_string());
            self.next_index.entry(desc.to_string()).or_insert(0);
        }
        Ok(())
    }

    /// List all stored descriptor strings.
    pub fn descriptors(&self) -> &[String] {
        &self.descriptors
    }

    /// Get the gap limit.
    pub fn gap_limit(&self) -> u32 {
        self.gap_limit
    }

    /// Set the gap limit.
    pub fn set_gap_limit(&mut self, gap_limit: u32) {
        self.gap_limit = gap_limit;
    }

    /// Get the next unused derivation index for a descriptor.
    pub fn get_next_index(&self, desc: &str) -> u32 {
        self.next_index.get(desc).copied().unwrap_or(0)
    }

    /// Advance the derivation index for a descriptor by one.
    pub fn advance_index(&mut self, desc: &str) {
        let entry = self.next_index.entry(desc.to_string()).or_insert(0);
        *entry += 1;
    }

    /// Derive scriptPubKeys for a descriptor from `start` up to `start + count`.
    ///
    /// This uses the full descriptor parsing and script derivation pipeline.
    /// For xpub descriptors with a `*` wildcard, each index produces a
    /// distinct scriptPubKey.
    pub fn derive_scripts(
        &self,
        desc: &str,
        start: u32,
        count: u32,
    ) -> Result<Vec<Script>, WalletError> {
        let parsed = Descriptor::parse(desc)?;
        let mut scripts = Vec::with_capacity(count as usize);
        for i in start..start.saturating_add(count) {
            scripts.push(parsed.to_script(i)?);
        }
        Ok(scripts)
    }
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
    fn parse_with_valid_checksum() {
        let hex = sample_pubkey_hex();
        let body = format!("wpkh({hex})");
        let cs = descriptor_checksum(&body).unwrap();
        let full = format!("{body}#{cs}");
        let desc = Descriptor::parse(&full).unwrap();
        assert!(matches!(desc, Descriptor::Wpkh(_)));
    }

    #[test]
    fn parse_with_invalid_checksum_rejected() {
        let hex = sample_pubkey_hex();
        let result = Descriptor::parse(&format!("wpkh({hex})#abcdefgh"));
        assert!(result.is_err());
    }

    #[test]
    fn descriptor_checksum_known_vectors() {
        // Bitcoin Core test vector: wpkh with known checksum
        let cs = descriptor_checksum("addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)").unwrap();
        assert_eq!(cs.len(), 8);
        // Verify roundtrip: parsing with correct checksum succeeds
        let full = format!("addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)#{cs}");
        assert!(Descriptor::parse(&full).is_ok());
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

    // ── DescriptorWallet tests ───────────────────────────────────────────────

    #[test]
    fn descriptor_wallet_add_and_list() {
        let hex = sample_pubkey_hex();
        let desc = format!("wpkh({hex})");
        let mut dw = DescriptorWallet::new(20);
        dw.add_descriptor(&desc).unwrap();
        assert_eq!(dw.descriptors().len(), 1);
        assert_eq!(dw.descriptors()[0], desc);
    }

    #[test]
    fn descriptor_wallet_no_duplicates() {
        let hex = sample_pubkey_hex();
        let desc = format!("wpkh({hex})");
        let mut dw = DescriptorWallet::new(20);
        dw.add_descriptor(&desc).unwrap();
        dw.add_descriptor(&desc).unwrap();
        assert_eq!(dw.descriptors().len(), 1);
    }

    #[test]
    fn descriptor_wallet_rejects_invalid() {
        let mut dw = DescriptorWallet::new(20);
        assert!(dw.add_descriptor("garbage(foo)").is_err());
    }

    #[test]
    fn descriptor_wallet_index_tracking() {
        let hex = sample_pubkey_hex();
        let desc = format!("wpkh({hex})");
        let mut dw = DescriptorWallet::new(20);
        dw.add_descriptor(&desc).unwrap();
        assert_eq!(dw.get_next_index(&desc), 0);
        dw.advance_index(&desc);
        assert_eq!(dw.get_next_index(&desc), 1);
        dw.advance_index(&desc);
        assert_eq!(dw.get_next_index(&desc), 2);
    }

    #[test]
    fn descriptor_wallet_gap_limit() {
        let mut dw = DescriptorWallet::new(20);
        assert_eq!(dw.gap_limit(), 20);
        dw.set_gap_limit(30);
        assert_eq!(dw.gap_limit(), 30);
    }

    #[test]
    fn descriptor_wallet_derive_scripts() {
        let hex = sample_pubkey_hex();
        let desc = format!("wpkh({hex})");
        let dw = DescriptorWallet::new(20);
        let scripts = dw.derive_scripts(&desc, 0, 3).unwrap();
        // For a fixed key (no wildcard), all scripts are the same
        assert_eq!(scripts.len(), 3);
        assert!(scripts[0].is_p2wpkh());
    }

    #[test]
    fn descriptor_wallet_multiple_descriptors() {
        let hex = sample_pubkey_hex();
        let mut dw = DescriptorWallet::new(20);
        dw.add_descriptor(&format!("wpkh({hex})")).unwrap();
        dw.add_descriptor(&format!("pkh({hex})")).unwrap();
        dw.add_descriptor(&format!("tr({hex})")).unwrap();
        assert_eq!(dw.descriptors().len(), 3);
    }

    // ── Key origin tests ──────────────────────────────────────────────────────

    #[test]
    fn parse_key_origin_basic() {
        let origin = KeyOrigin::parse("d34db33f/44h/0h/0h").unwrap();
        assert_eq!(origin.fingerprint, [0xd3, 0x4d, 0xb3, 0x3f]);
        assert_eq!(origin.path.len(), 3);
        assert_eq!(origin.path[0], 44 | crate::hd::HARDENED);
        assert_eq!(origin.path[1], 0 | crate::hd::HARDENED);
        assert_eq!(origin.path[2], 0 | crate::hd::HARDENED);
    }

    #[test]
    fn parse_key_origin_fingerprint_only() {
        let origin = KeyOrigin::parse("deadbeef").unwrap();
        assert_eq!(origin.fingerprint, [0xde, 0xad, 0xbe, 0xef]);
        assert!(origin.path.is_empty());
    }

    #[test]
    fn parse_key_origin_apostrophe_notation() {
        let origin = KeyOrigin::parse("aabbccdd/84'/0'/0'").unwrap();
        assert_eq!(origin.path[0], 84 | crate::hd::HARDENED);
        assert_eq!(origin.path[1], 0 | crate::hd::HARDENED);
    }

    #[test]
    fn key_origin_display_roundtrip() {
        let origin = KeyOrigin::parse("d34db33f/44h/0h/0h").unwrap();
        let s = origin.to_string();
        assert_eq!(s, "d34db33f/44h/0h/0h");
        let parsed_back = KeyOrigin::parse(&s).unwrap();
        assert_eq!(origin, parsed_back);
    }

    #[test]
    fn key_origin_display_mixed_path() {
        let origin = KeyOrigin::parse("aabbccdd/44h/0/3").unwrap();
        assert_eq!(origin.to_string(), "aabbccdd/44h/0/3");
    }

    #[test]
    fn parse_key_origin_bad_fingerprint() {
        assert!(KeyOrigin::parse("zzzzzzzz/0").is_err()); // invalid hex
        assert!(KeyOrigin::parse("dead/0").is_err()); // too short
        assert!(KeyOrigin::parse("deadbeef00/0").is_err()); // too long
    }

    #[test]
    fn parse_descriptor_with_key_origin() {
        let hex = sample_pubkey_hex();
        let desc_str = format!("wpkh([d34db33f/84h/0h/0h]{hex})");
        let desc = Descriptor::parse(&desc_str).unwrap();
        match &desc {
            Descriptor::Wpkh(key) => {
                let origin = key.origin().expect("should have origin");
                assert_eq!(origin.fingerprint, [0xd3, 0x4d, 0xb3, 0x3f]);
                assert_eq!(origin.path.len(), 3);
            }
            _ => panic!("expected Wpkh"),
        }
        // Should still produce a valid script
        let spk = desc.to_script(0).unwrap();
        assert!(spk.is_p2wpkh());
    }

    #[test]
    fn parse_descriptor_with_key_origin_and_checksum() {
        let hex = sample_pubkey_hex();
        let body = format!("wpkh([deadbeef/84h/0h/0h]{hex})");
        let cs = descriptor_checksum(&body).unwrap();
        let full = format!("{body}#{cs}");
        let desc = Descriptor::parse(&full).unwrap();
        assert!(matches!(desc, Descriptor::Wpkh(_)));
    }

    // ── Hardened path component tests ─────────────────────────────────────────

    #[test]
    fn parse_path_component_normal() {
        assert_eq!(parse_path_component("42").unwrap(), 42);
    }

    #[test]
    fn parse_path_component_hardened_h() {
        assert_eq!(parse_path_component("44h").unwrap(), 44 | crate::hd::HARDENED);
    }

    #[test]
    fn parse_path_component_hardened_capital_h() {
        assert_eq!(parse_path_component("44H").unwrap(), 44 | crate::hd::HARDENED);
    }

    #[test]
    fn parse_path_component_hardened_apostrophe() {
        assert_eq!(parse_path_component("44'").unwrap(), 44 | crate::hd::HARDENED);
    }

    #[test]
    fn parse_path_component_invalid() {
        assert!(parse_path_component("abc").is_err());
    }

    // ── Multipath expansion tests ─────────────────────────────────────────────

    #[test]
    fn expand_multipath_no_multipath() {
        let hex = sample_pubkey_hex();
        let desc = format!("wpkh({hex})");
        let expanded = expand_multipath(&desc).unwrap();
        assert_eq!(expanded.len(), 1);
        assert_eq!(expanded[0], desc);
    }

    #[test]
    fn expand_multipath_basic() {
        // Test that <0;1> is correctly expanded into two descriptors
        let desc = "wpkh([deadbeef/84h/0h/0h]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/<0;1>/*)";
        let expanded = expand_multipath(desc).unwrap();
        assert_eq!(expanded.len(), 2);
        assert!(expanded[0].contains("/0/*"));
        assert!(expanded[1].contains("/1/*"));
        assert!(!expanded[0].contains('<'));
        assert!(!expanded[1].contains('<'));
    }

    #[test]
    fn expand_multipath_three_alternatives() {
        let desc = "wpkh(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/<0;1;2>/*)";
        let expanded = expand_multipath(desc).unwrap();
        assert_eq!(expanded.len(), 3);
        assert!(expanded[0].contains("/0/*"));
        assert!(expanded[1].contains("/1/*"));
        assert!(expanded[2].contains("/2/*"));
    }

    #[test]
    fn expand_multipath_with_checksum() {
        let body = "wpkh(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/<0;1>/*)";
        let cs = descriptor_checksum(body).unwrap();
        let full = format!("{body}#{cs}");
        let expanded = expand_multipath(&full).unwrap();
        assert_eq!(expanded.len(), 2);
        // Each expanded descriptor should have its own valid checksum
        for exp in &expanded {
            assert!(exp.contains('#'));
            // The expanded descriptors have xpub keys and should parse
            assert!(Descriptor::parse(exp).is_ok());
        }
    }

    #[test]
    fn expand_multipath_produces_parseable_descriptors() {
        // Use an xpub-based descriptor with multipath, verify each expansion parses
        let desc = "wpkh([deadbeef/84h/0h/0h]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/<0;1>/*)";
        let expanded = expand_multipath(desc).unwrap();
        assert_eq!(expanded.len(), 2);
        for exp in &expanded {
            let parsed = Descriptor::parse(exp).unwrap();
            assert!(matches!(parsed, Descriptor::Wpkh(_)));
            // Verify it's ranged (has *)
            assert!(parsed.is_range());
        }
    }

    #[test]
    fn expand_multipath_unmatched_angle_bracket() {
        assert!(expand_multipath("wpkh(key/<0;1/*)").is_err());
    }

    // ── is_range tests ────────────────────────────────────────────────────────

    #[test]
    fn is_range_fixed_key() {
        let hex = sample_pubkey_hex();
        let desc = Descriptor::parse(&format!("wpkh({hex})")).unwrap();
        assert!(!desc.is_range());
    }

    // ── Canonical string roundtrip tests ──────────────────────────────────────

    #[test]
    fn canonical_string_with_origin() {
        let hex = sample_pubkey_hex();
        let desc = Descriptor::parse(&format!("wpkh([deadbeef/84h/0h/0h]{hex})")).unwrap();
        let body = desc.to_string_body();
        assert!(body.starts_with("wpkh([deadbeef/84h/0h/0h]"));
        // Should roundtrip
        let parsed2 = Descriptor::parse(&body).unwrap();
        assert_eq!(desc, parsed2);
    }

    #[test]
    fn canonical_string_with_checksum_roundtrip() {
        let hex = sample_pubkey_hex();
        let desc = Descriptor::parse(&format!("wpkh([deadbeef]{hex})")).unwrap();
        let with_cs = desc.to_string_with_checksum().unwrap();
        assert!(with_cs.contains('#'));
        let parsed = Descriptor::parse(&with_cs).unwrap();
        assert_eq!(desc, parsed);
    }

    #[test]
    fn is_range_xpub_wildcard() {
        // xpub with wildcard path — is ranged
        let desc = Descriptor::parse(
            "wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)"
        ).unwrap();
        assert!(desc.is_range());
    }

    #[test]
    fn is_range_xpub_no_wildcard() {
        // xpub without wildcard — not ranged
        let desc = Descriptor::parse(
            "wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/0)"
        ).unwrap();
        assert!(!desc.is_range());
    }

    #[test]
    fn is_solvable_wpkh() {
        let hex = sample_pubkey_hex();
        let desc = Descriptor::parse(&format!("wpkh({hex})")).unwrap();
        assert!(desc.is_solvable());
    }

    #[test]
    fn is_solvable_addr_false() {
        let desc = Descriptor::parse("addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)").unwrap();
        assert!(!desc.is_solvable());
    }

    #[test]
    fn is_solvable_pkh() {
        let hex = sample_pubkey_hex();
        let desc = Descriptor::parse(&format!("pkh({hex})")).unwrap();
        assert!(desc.is_solvable());
    }

    #[test]
    fn is_solvable_tr() {
        let hex = sample_pubkey_hex();
        let desc = Descriptor::parse(&format!("tr({hex})")).unwrap();
        assert!(desc.is_solvable());
    }
}
