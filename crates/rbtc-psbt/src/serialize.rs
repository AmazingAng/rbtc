//! PSBT binary serialization / deserialization and Base64 wrapper.
//!
//! Wire format:
//!   "psbt\xff"           — magic (5 bytes)
//!   <global-map>         — key-value entries, terminated by 0x00
//!   for each input:  <input-map>
//!   for each output: <output-map>

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rbtc_primitives::{
    codec::{Decodable, Encodable, VarInt},
    script::Script,
    transaction::{Transaction, TxOut},
};

use crate::{
    error::{PsbtError, Result},
    types::{ProprietaryKey, Psbt, PsbtGlobal, PsbtInput, PsbtOutput, TapTreeLeaf},
};

const PSBT_MAGIC: &[u8] = b"psbt\xff";

// ── Helpers ───────────────────────────────────────────────────────────────────

fn write_kv(buf: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    VarInt(key.len() as u64).encode(buf).ok();
    buf.extend_from_slice(key);
    VarInt(value.len() as u64).encode(buf).ok();
    buf.extend_from_slice(value);
}

fn write_separator(buf: &mut Vec<u8>) {
    buf.push(0x00);
}

fn encode_tx_legacy(tx: &Transaction) -> Vec<u8> {
    let mut buf = Vec::new();
    tx.encode_legacy(&mut buf).ok();
    buf
}

fn encode_txout(txout: &TxOut) -> Vec<u8> {
    let mut buf = Vec::new();
    txout.value.encode(&mut buf).ok();
    txout.script_pubkey.encode(&mut buf).ok();
    buf
}

fn decode_txout(data: &[u8]) -> Result<TxOut> {
    let mut cur = std::io::Cursor::new(data);
    let value = u64::decode(&mut cur).map_err(|e| PsbtError::Decode(e.to_string()))?;
    let script_pubkey = Script::decode(&mut cur).map_err(|e| PsbtError::Decode(e.to_string()))?;
    Ok(TxOut {
        value: value as i64,
        script_pubkey,
    })
}

/// Encode a ProprietaryKey into PSBT wire key format:
/// `0xFC || compact_size(identifier.len()) || identifier || varint(subtype) || key_data`
fn encode_proprietary_key(pk: &ProprietaryKey) -> Vec<u8> {
    let mut key = vec![0xFC];
    VarInt(pk.identifier.len() as u64).encode(&mut key).ok();
    key.extend_from_slice(&pk.identifier);
    VarInt(pk.subtype).encode(&mut key).ok();
    key.extend_from_slice(&pk.key_data);
    key
}

/// Decode a PSBT wire key (starting after 0xFC type byte) into a ProprietaryKey.
fn decode_proprietary_key(key_data: &[u8]) -> Option<ProprietaryKey> {
    let mut cur = std::io::Cursor::new(key_data);
    let VarInt(id_len) = VarInt::decode(&mut cur).ok()?;
    let pos = cur.position() as usize;
    let end = pos + id_len as usize;
    if end > key_data.len() {
        return None;
    }
    let identifier = key_data[pos..end].to_vec();
    let mut cur2 = std::io::Cursor::new(&key_data[end..]);
    let VarInt(subtype) = VarInt::decode(&mut cur2).ok()?;
    let rest_start = end + cur2.position() as usize;
    let rest = key_data[rest_start..].to_vec();
    Some(ProprietaryKey {
        identifier,
        subtype,
        key_data: rest,
    })
}

/// Check that a 33-byte slice is a valid compressed pubkey (prefix 0x02 or 0x03).
/// Matches Bitcoin Core's CPubKey::IsValid() + compressed size check.
fn is_valid_compressed_pubkey(data: &[u8]) -> bool {
    data.len() == 33 && (data[0] == 0x02 || data[0] == 0x03)
}

/// Decode MuSig2 participant pubkeys value: N concatenated 33-byte compressed pubkeys.
/// Validates each pubkey format, matching Bitcoin Core's DeserializeMuSig2ParticipantPubkeys.
fn decode_musig2_participants(value: &[u8], context: &'static str) -> Result<Vec<Vec<u8>>> {
    if value.len() % 33 != 0 {
        return Err(PsbtError::InvalidMusig2Pubkey {
            field: context,
            reason: "participant pubkeys value size is not a multiple of 33",
        });
    }
    let mut result = Vec::new();
    for chunk in value.chunks_exact(33) {
        if !is_valid_compressed_pubkey(chunk) {
            return Err(PsbtError::InvalidMusig2Pubkey {
                field: context,
                reason: "participant pubkey has invalid compressed format",
            });
        }
        result.push(chunk.to_vec());
    }
    Ok(result)
}

/// Validate the aggregate pubkey in a MuSig2 key field (bytes after the type byte).
/// Matches Bitcoin Core's DeserializeMuSig2ParticipantPubkeys aggregate key check.
fn validate_musig2_aggregate_pubkey(key_bytes: &[u8], context: &'static str) -> Result<()> {
    if !is_valid_compressed_pubkey(key_bytes) {
        return Err(PsbtError::InvalidMusig2Pubkey {
            field: context,
            reason: "aggregate pubkey has invalid compressed format",
        });
    }
    Ok(())
}

/// Validate the participant + aggregate pubkey pair in a MuSig2 pubnonce/partial_sig key.
/// Key layout: participant(33) || aggregate(33) [|| leaf_hash(32)]
/// Matches Bitcoin Core's DeserializeMuSig2ParticipantDataIdentifier.
fn validate_musig2_data_identifier(key_bytes: &[u8], context: &'static str) -> Result<()> {
    if key_bytes.len() < 66 {
        return Err(PsbtError::InvalidMusig2Pubkey {
            field: context,
            reason: "key too short for participant + aggregate pubkeys",
        });
    }
    let participant = &key_bytes[..33];
    let aggregate = &key_bytes[33..66];
    if !is_valid_compressed_pubkey(participant) {
        return Err(PsbtError::InvalidMusig2Pubkey {
            field: context,
            reason: "participant pubkey has invalid compressed format",
        });
    }
    if !is_valid_compressed_pubkey(aggregate) {
        return Err(PsbtError::InvalidMusig2Pubkey {
            field: context,
            reason: "aggregate pubkey has invalid compressed format",
        });
    }
    Ok(())
}

/// Encode MuSig2 participant pubkeys value.
fn encode_musig2_participants(pks: &[Vec<u8>]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(pks.len() * 33);
    for pk in pks {
        buf.extend_from_slice(pk);
    }
    buf
}

/// Maximum depth for a Taproot tree leaf (BIP341: TAPROOT_CONTROL_MAX_NODE_COUNT).
const TAPROOT_CONTROL_MAX_NODE_COUNT: u8 = 128;

/// BIP341: leaf version mask. Valid leaf versions have no odd bits.
const TAPROOT_LEAF_MASK: u8 = 0xfe;

/// Parse TAP_TREE raw bytes into validated `TapTreeLeaf` tuples.
///
/// Format: `(depth: u8, leaf_ver: u8, compact_size(script.len()) + script)*`
/// Validates:
/// - Non-empty tree
/// - depth ≤ 128 (TAPROOT_CONTROL_MAX_NODE_COUNT)
/// - leaf_ver is even (leaf_ver & ~TAPROOT_LEAF_MASK == 0)
/// - Tree completeness (ValidDepths check matching Bitcoin Core's TaprootBuilder)
fn parse_tap_tree(data: &[u8]) -> Result<Vec<TapTreeLeaf>> {
    if data.is_empty() {
        return Err(PsbtError::TapTreeEmpty);
    }
    let mut cur = std::io::Cursor::new(data);
    let mut leaves = Vec::new();
    let total = data.len() as u64;
    while cur.position() < total {
        // Read depth (1 byte)
        let pos = cur.position() as usize;
        if pos >= data.len() {
            return Err(PsbtError::TapTreeTruncated);
        }
        let depth = data[pos];
        cur.set_position((pos + 1) as u64);

        // Read leaf_ver (1 byte)
        let pos = cur.position() as usize;
        if pos >= data.len() {
            return Err(PsbtError::TapTreeTruncated);
        }
        let leaf_ver = data[pos];
        cur.set_position((pos + 1) as u64);

        // Read script (compact_size prefixed)
        let VarInt(script_len) = VarInt::decode(&mut cur)
            .map_err(|_| PsbtError::TapTreeTruncated)?;
        let pos = cur.position() as usize;
        let script_len = script_len as usize;
        if pos + script_len > data.len() {
            return Err(PsbtError::TapTreeTruncated);
        }
        let script = data[pos..pos + script_len].to_vec();
        cur.set_position((pos + script_len) as u64);

        // Validate depth
        if depth > TAPROOT_CONTROL_MAX_NODE_COUNT {
            return Err(PsbtError::TapTreeDepthExceeded { depth });
        }
        // Validate leaf version (must be even)
        if (leaf_ver & !TAPROOT_LEAF_MASK) != 0 {
            return Err(PsbtError::TapTreeInvalidLeafVersion { leaf_ver });
        }

        leaves.push(TapTreeLeaf {
            depth,
            leaf_version: leaf_ver,
            script,
        });
    }

    // TaprootBuilder completeness check (matching Bitcoin Core's ValidDepths)
    if !valid_tap_tree_depths(&leaves) {
        return Err(PsbtError::TapTreeMalformed);
    }

    Ok(leaves)
}

/// Check that the leaf depths form a valid complete binary Merkle tree.
/// Matches Bitcoin Core's `TaprootBuilder::ValidDepths` exactly.
fn valid_tap_tree_depths(leaves: &[TapTreeLeaf]) -> bool {
    let mut branch: Vec<bool> = Vec::new();
    for leaf in leaves {
        let mut depth = leaf.depth as usize;
        // New depth can't be shallower than existing unfinished branches
        if depth + 1 < branch.len() {
            return false;
        }
        // Combine nodes going up (like TaprootBuilder::Insert)
        while branch.len() > depth && branch[depth] {
            branch.pop();
            if depth == 0 {
                return false;
            }
            depth -= 1;
        }
        if branch.len() <= depth {
            branch.resize(depth + 1, false);
        }
        debug_assert!(!branch[depth]);
        branch[depth] = true;
    }
    // Complete tree: exactly one root node
    branch.is_empty() || (branch.len() == 1 && branch[0])
}

/// Serialize `TapTreeLeaf` tuples back to the wire format.
fn serialize_tap_tree(leaves: &[TapTreeLeaf]) -> Vec<u8> {
    let mut buf = Vec::new();
    for leaf in leaves {
        buf.push(leaf.depth);
        buf.push(leaf.leaf_version);
        VarInt(leaf.script.len() as u64).encode(&mut buf).ok();
        buf.extend_from_slice(&leaf.script);
    }
    buf
}

// ── Encoding ──────────────────────────────────────────────────────────────────

impl Psbt {
    /// Serialize to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(PSBT_MAGIC);

        // Global map
        if self.global.version < 2 {
            // v0: include unsigned_tx
            if let Some(ref tx) = self.global.unsigned_tx {
                let tx_bytes = encode_tx_legacy(tx);
                write_kv(&mut buf, &[0x00], &tx_bytes);
            }
        } else {
            // v2: include tx_version, fallback_locktime, input/output counts
            if let Some(v) = self.global.tx_version {
                write_kv(&mut buf, &[0x02], &v.to_le_bytes());
            }
            if let Some(lt) = self.global.fallback_locktime {
                write_kv(&mut buf, &[0x03], &lt.to_le_bytes());
            }
            if let Some(ic) = self.global.input_count {
                let mut varint_buf = Vec::new();
                VarInt(ic).encode(&mut varint_buf).ok();
                write_kv(&mut buf, &[0x04], &varint_buf);
            }
            if let Some(oc) = self.global.output_count {
                let mut varint_buf = Vec::new();
                VarInt(oc).encode(&mut varint_buf).ok();
                write_kv(&mut buf, &[0x05], &varint_buf);
            }
            if let Some(m) = self.global.tx_modifiable {
                write_kv(&mut buf, &[0x06], &[m]);
            }
        }
        // Global XPUB entries (type 0x01)
        for (xpub_bytes, (fingerprint, path)) in &self.global.xpub {
            let mut key = vec![0x01];
            key.extend_from_slice(xpub_bytes);
            let mut val = fingerprint.clone();
            for &idx in path {
                val.extend_from_slice(&idx.to_le_bytes());
            }
            write_kv(&mut buf, &key, &val);
        }
        if self.global.version != 0 {
            write_kv(&mut buf, &[0xfb], &self.global.version.to_le_bytes());
        }
        for (pk, v) in &self.global.proprietary {
            let key = encode_proprietary_key(pk);
            write_kv(&mut buf, &key, v);
        }
        for (k, v) in &self.global.unknown {
            write_kv(&mut buf, k, v);
        }
        write_separator(&mut buf);

        // Per-input maps
        for input in &self.inputs {
            encode_input(input, &mut buf);
        }

        // Per-output maps
        for output in &self.outputs {
            encode_output(output, &mut buf);
        }

        buf
    }

    /// Serialize to standard Base64 string.
    pub fn to_base64(&self) -> String {
        B64.encode(self.serialize())
    }

    /// Deserialize from bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < 5 || &data[..5] != PSBT_MAGIC {
            return Err(PsbtError::InvalidMagic);
        }

        let mut pos = 5usize;

        // Parse a complete key-value map; returns (keys, values) as byte vecs.
        // Detects duplicate keys and returns DuplicateKey error.
        let parse_map = |pos: &mut usize| -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
            let mut entries = Vec::new();
            let mut seen_keys = std::collections::BTreeSet::new();
            loop {
                let mut cur = std::io::Cursor::new(&data[*pos..]);
                let VarInt(key_len) =
                    VarInt::decode(&mut cur).map_err(|e| PsbtError::Decode(e.to_string()))?;
                let hdr = cur.position() as usize;
                *pos += hdr;
                if key_len == 0 {
                    break; // separator
                }
                let key_start = *pos;
                *pos += key_len as usize;
                if *pos > data.len() {
                    return Err(PsbtError::Decode("key truncated".into()));
                }
                let key = data[key_start..*pos].to_vec();

                if !seen_keys.insert(key.clone()) {
                    let hex_key: String = key.iter().map(|b| format!("{:02x}", b)).collect();
                    return Err(PsbtError::DuplicateKey(hex_key));
                }

                // value
                let mut vcur = std::io::Cursor::new(&data[*pos..]);
                let VarInt(val_len) =
                    VarInt::decode(&mut vcur).map_err(|e| PsbtError::Decode(e.to_string()))?;
                let vhdr = vcur.position() as usize;
                *pos += vhdr;
                let val_start = *pos;
                *pos += val_len as usize;
                if *pos > data.len() {
                    return Err(PsbtError::Decode("value truncated".into()));
                }
                let val = data[val_start..*pos].to_vec();

                entries.push((key, val));
            }
            Ok(entries)
        };

        // --- Global map ---
        let global_entries = parse_map(&mut pos)?;
        let mut unsigned_tx: Option<Transaction> = None;
        let mut version = 0u32;
        let mut tx_version: Option<i32> = None;
        let mut fallback_locktime: Option<u32> = None;
        let mut g_input_count: Option<u64> = None;
        let mut g_output_count: Option<u64> = None;
        let mut tx_modifiable: Option<u8> = None;
        let mut global_xpub: std::collections::BTreeMap<Vec<u8>, (Vec<u8>, Vec<u32>)> = std::collections::BTreeMap::new();
        let mut global_proprietary: std::collections::BTreeMap<ProprietaryKey, Vec<u8>> = std::collections::BTreeMap::new();
        let mut global_unknown = std::collections::BTreeMap::new();

        for (key, value) in global_entries {
            match key.as_slice() {
                [0x00] => {
                    let tx = Transaction::decode_from_slice(&value)
                        .map_err(|e| PsbtError::Decode(e.to_string()))?;
                    unsigned_tx = Some(tx);
                }
                k if k.first() == Some(&0x01) && k.len() == 79 => {
                    // PSBT_GLOBAL_XPUB: key = 0x01 || xpub(78), value = fingerprint(4) || path(n*4)
                    let xpub_bytes = k[1..].to_vec();
                    if value.len() >= 4 && (value.len() - 4) % 4 == 0 {
                        let fingerprint = value[..4].to_vec();
                        let path: Vec<u32> = value[4..]
                            .chunks_exact(4)
                            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                            .collect();
                        global_xpub.insert(xpub_bytes, (fingerprint, path));
                    }
                }
                [0x02] if value.len() == 4 => {
                    tx_version = Some(i32::from_le_bytes(value[..4].try_into().unwrap()));
                }
                [0x03] if value.len() == 4 => {
                    fallback_locktime = Some(u32::from_le_bytes(value[..4].try_into().unwrap()));
                }
                [0x04] => {
                    let mut cur = std::io::Cursor::new(value.as_slice());
                    if let Ok(VarInt(n)) = VarInt::decode(&mut cur) {
                        g_input_count = Some(n);
                    }
                }
                [0x05] => {
                    let mut cur = std::io::Cursor::new(value.as_slice());
                    if let Ok(VarInt(n)) = VarInt::decode(&mut cur) {
                        g_output_count = Some(n);
                    }
                }
                [0x06] if value.len() == 1 => {
                    tx_modifiable = Some(value[0]);
                }
                [0xfb] if value.len() == 4 => {
                    version = u32::from_le_bytes(value[..4].try_into().unwrap());
                    // Reject unknown versions (rbtc supports v0 and v2; v1 is unused but
                    // we reject 3+ like Bitcoin Core rejects > PSBT_HIGHEST_VERSION).
                    if version > 2 {
                        return Err(PsbtError::UnsupportedVersion(version));
                    }
                }
                k if k.first() == Some(&0xfc) => {
                    if let Some(pk) = decode_proprietary_key(&k[1..]) {
                        global_proprietary.insert(pk, value);
                    } else {
                        global_unknown.insert(key, value);
                    }
                }
                _ => {
                    global_unknown.insert(key, value);
                }
            }
        }

        // Determine input/output count based on version.
        let (input_count, output_count) = if version >= 2 {
            // v2: get counts from global fields
            let ic = g_input_count.ok_or(PsbtError::MissingField("input_count"))? as usize;
            let oc = g_output_count.ok_or(PsbtError::MissingField("output_count"))? as usize;
            (ic, oc)
        } else {
            // v0: get counts from unsigned_tx
            let tx = unsigned_tx.as_ref().ok_or(PsbtError::MissingField("unsigned_tx"))?;
            (tx.inputs.len(), tx.outputs.len())
        };

        let global = PsbtGlobal {
            unsigned_tx,
            version,
            tx_version,
            fallback_locktime,
            input_count: g_input_count,
            output_count: g_output_count,
            tx_modifiable,
            xpub: global_xpub,
            proprietary: global_proprietary,
            unknown: global_unknown,
        };

        // --- Per-input maps ---
        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let entries = parse_map(&mut pos)?;
            let mut inp = PsbtInput::default();
            for (key, value) in entries {
                match key.as_slice() {
                    [0x00] => {
                        if let Ok(tx) = Transaction::decode_from_slice(&value) {
                            inp.non_witness_utxo = Some(tx);
                        }
                    }
                    [0x01] => {
                        if let Ok(txout) = decode_txout(&value) {
                            inp.witness_utxo = Some(txout);
                        }
                    }
                    k if k.first() == Some(&0x02) && k.len() == 34 => {
                        inp.partial_sigs.insert(k[1..].to_vec(), value);
                    }
                    [0x03] if value.len() == 4 => {
                        inp.sighash_type = Some(u32::from_le_bytes(value[..4].try_into().unwrap()));
                    }
                    [0x04] => {
                        inp.redeem_script = Some(Script::from_bytes(value));
                    }
                    [0x05] => {
                        inp.witness_script = Some(Script::from_bytes(value));
                    }
                    k if k.first() == Some(&0x06) && k.len() == 34 => {
                        // BIP32 derivation: key = 0x06 || pubkey(33)
                        // value = fingerprint(4) || path(n * 4 bytes LE u32)
                        let pubkey = k[1..].to_vec();
                        if value.len() >= 4 && (value.len() - 4) % 4 == 0 {
                            let fingerprint = value[..4].to_vec();
                            let path: Vec<u32> = value[4..]
                                .chunks_exact(4)
                                .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                                .collect();
                            inp.bip32_derivation.insert(pubkey, (fingerprint, path));
                        }
                    }
                    [0x07] => {
                        inp.final_script_sig = Some(Script::from_bytes(value));
                    }
                    [0x08] => {
                        let mut cur = std::io::Cursor::new(value.as_slice());
                        if let Ok(VarInt(count)) = VarInt::decode(&mut cur) {
                            let mut witness = Vec::new();
                            for _ in 0..count {
                                if let Ok(VarInt(len)) = VarInt::decode(&mut cur) {
                                    let start = cur.position() as usize;
                                    let end = start + len as usize;
                                    if end <= value.len() {
                                        witness.push(value[start..end].to_vec());
                                    }
                                    cur.set_position(end as u64);
                                }
                            }
                            inp.final_script_witness = Some(witness);
                        }
                    }
                    // Preimage fields (0x0A-0x0D)
                    k if k.first() == Some(&0x0a) && k.len() == 21 => {
                        // RIPEMD160: key = 0x0A || hash(20), value = preimage
                        inp.ripemd160_preimages.insert(k[1..].to_vec(), value);
                    }
                    k if k.first() == Some(&0x0b) && k.len() == 33 => {
                        // SHA256: key = 0x0B || hash(32), value = preimage
                        inp.sha256_preimages.insert(k[1..].to_vec(), value);
                    }
                    k if k.first() == Some(&0x0c) && k.len() == 21 => {
                        // HASH160: key = 0x0C || hash(20), value = preimage
                        inp.hash160_preimages.insert(k[1..].to_vec(), value);
                    }
                    k if k.first() == Some(&0x0d) && k.len() == 33 => {
                        // HASH256: key = 0x0D || hash(32), value = preimage
                        inp.hash256_preimages.insert(k[1..].to_vec(), value);
                    }
                    // v2 input fields
                    [0x0e] if value.len() == 32 => {
                        use rbtc_primitives::hash::{Hash256, Txid};
                        let mut h = [0u8; 32];
                        h.copy_from_slice(&value);
                        inp.previous_txid = Some(Txid(Hash256(h)));
                    }
                    [0x0f] if value.len() == 4 => {
                        inp.output_index = Some(u32::from_le_bytes(value[..4].try_into().unwrap()));
                    }
                    [0x10] if value.len() == 4 => {
                        inp.sequence = Some(u32::from_le_bytes(value[..4].try_into().unwrap()));
                    }
                    [0x11] if value.len() == 4 => {
                        inp.required_time_locktime = Some(u32::from_le_bytes(value[..4].try_into().unwrap()));
                    }
                    [0x12] if value.len() == 4 => {
                        inp.required_height_locktime = Some(u32::from_le_bytes(value[..4].try_into().unwrap()));
                    }
                    [0x13] => {
                        // C2: TAP_KEY_SIG must be 64 or 65 bytes (Schnorr sig +
                        // optional sighash byte), matching Bitcoin Core validation.
                        if value.len() < 64 || value.len() > 65 {
                            return Err(PsbtError::InvalidSignatureLength {
                                field: "input tap_key_sig",
                                got: value.len(),
                            });
                        }
                        inp.tap_key_sig = Some(value);
                    }
                    k if k.first() == Some(&0x14) && k.len() == 65 => {
                        // TAP_SCRIPT_SIG: key = 0x14 || x-only pubkey (32) || leaf_hash (32)
                        // C3: signature value must be 64 or 65 bytes, matching Bitcoin Core.
                        if value.len() < 64 || value.len() > 65 {
                            return Err(PsbtError::InvalidSignatureLength {
                                field: "input tap_script_sig",
                                got: value.len(),
                            });
                        }
                        inp.tap_script_sig.insert(k[1..].to_vec(), value);
                    }
                    k if k.first() == Some(&0x15) && k.len() > 1 => {
                        // TAP_LEAF_SCRIPT: key = 0x15 || control block
                        let control_block = k[1..].to_vec();
                        // BIP341: control block must be 33 + 32*k bytes
                        if control_block.len() < 33 || (control_block.len() - 33) % 32 != 0 {
                            return Err(PsbtError::InvalidControlBlockSize {
                                got: control_block.len(),
                            });
                        }
                        if value.is_empty() {
                            return Err(PsbtError::Decode(
                                "Input Taproot leaf script must be at least 1 byte".into(),
                            ));
                        }
                        let leaf_version = value[value.len() - 1];
                        let script = value[..value.len() - 1].to_vec();
                        inp.tap_leaf_script.insert(control_block, (script, leaf_version));
                    }
                    k if k.first() == Some(&0x16) && k.len() == 33 => {
                        // TAP_BIP32_DERIVATION: key = 0x16 || x-only pubkey (32)
                        let xonly_pubkey = k[1..].to_vec();
                        let mut cur = std::io::Cursor::new(value.as_slice());
                        if let Ok(VarInt(num_hashes)) = VarInt::decode(&mut cur) {
                            let pos = cur.position() as usize;
                            let hash_bytes = num_hashes as usize * 32;
                            if value.len() >= pos + hash_bytes + 4 {
                                let mut leaf_hashes = std::collections::BTreeSet::new();
                                for i in 0..num_hashes as usize {
                                    let start = pos + i * 32;
                                    leaf_hashes.insert(value[start..start + 32].to_vec());
                                }
                                let fp_start = pos + hash_bytes;
                                let fingerprint = value[fp_start..fp_start + 4].to_vec();
                                let path: Vec<u32> = value[fp_start + 4..]
                                    .chunks_exact(4)
                                    .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                                    .collect();
                                inp.tap_bip32_derivation.insert(xonly_pubkey, (leaf_hashes, fingerprint, path));
                            }
                        }
                    }
                    [0x17] if value.len() == 32 => {
                        // C1: TAP_INTERNAL_KEY key must be exactly 1 byte (the type
                        // byte only, no extra data), matching Bitcoin Core validation.
                        // BIP371: value MUST be 32 bytes (x-only public key).
                        inp.tap_internal_key = Some(value);
                    }
                    [0x17] => {
                        return Err(PsbtError::InvalidValueSize {
                            field: "input tap_internal_key",
                            expected: 32,
                            got: value.len(),
                        });
                    }
                    k if k.first() == Some(&0x17) && k.len() != 1 => {
                        // C1: Reject TAP_INTERNAL_KEY with extra key bytes.
                        return Err(PsbtError::InvalidKeySize {
                            field: "input tap_internal_key",
                            expected: 1,
                            got: k.len(),
                        });
                    }
                    [0x18] if value.len() == 32 => {
                        inp.tap_merkle_root = Some(value);
                    }
                    // BIP373 MuSig2 input fields
                    k if k.first() == Some(&0x1a) && k.len() == 34 => {
                        // MUSIG2_PARTICIPANT_PUBKEYS: key = 0x1a || aggregate_pubkey(33)
                        validate_musig2_aggregate_pubkey(&k[1..], "input musig2_participant_pubkeys")?;
                        let agg_pk = k[1..].to_vec();
                        inp.musig2_participant_pubkeys
                            .insert(agg_pk, decode_musig2_participants(&value, "input musig2_participant_pubkeys")?);
                    }
                    k if k.first() == Some(&0x1b) && (k.len() == 67 || k.len() == 99) => {
                        // MUSIG2_PUB_NONCE: key = 0x1b || participant(33) || aggregate(33) [|| leaf_hash(32)]
                        // 67 bytes = key-path (no leaf_hash), 99 bytes = script-path (with leaf_hash)
                        validate_musig2_data_identifier(&k[1..], "input musig2_pub_nonce")?;
                        inp.musig2_pub_nonce.insert(k[1..].to_vec(), value);
                    }
                    k if k.first() == Some(&0x1c) && (k.len() == 67 || k.len() == 99) => {
                        // MUSIG2_PARTIAL_SIG: key = 0x1c || participant(33) || aggregate(33) [|| leaf_hash(32)]
                        // 67 bytes = key-path (no leaf_hash), 99 bytes = script-path (with leaf_hash)
                        validate_musig2_data_identifier(&k[1..], "input musig2_partial_sig")?;
                        inp.musig2_partial_sig.insert(k[1..].to_vec(), value);
                    }
                    k if k.first() == Some(&0xfc) => {
                        if let Some(pk) = decode_proprietary_key(&k[1..]) {
                            inp.proprietary.insert(pk, value);
                        } else {
                            inp.unknown.insert(key, value);
                        }
                    }
                    _ => {
                        inp.unknown.insert(key, value);
                    }
                }
            }
            inputs.push(inp);
        }

        // --- Per-output maps ---
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            let entries = parse_map(&mut pos)?;
            let mut out = PsbtOutput::default();
            for (key, value) in entries {
                match key.as_slice() {
                    [0x00] => {
                        out.redeem_script = Some(Script::from_bytes(value));
                    }
                    [0x01] => {
                        out.witness_script = Some(Script::from_bytes(value));
                    }
                    k if k.first() == Some(&0x02) && k.len() == 34 => {
                        let pubkey = k[1..].to_vec();
                        if value.len() >= 4 && (value.len() - 4) % 4 == 0 {
                            let fingerprint = value[..4].to_vec();
                            let path: Vec<u32> = value[4..]
                                .chunks_exact(4)
                                .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                                .collect();
                            out.bip32_derivation.insert(pubkey, (fingerprint, path));
                        }
                    }
                    // v2 output fields
                    [0x03] if value.len() == 8 => {
                        out.amount = Some(i64::from_le_bytes(value[..8].try_into().unwrap()));
                    }
                    [0x04] => {
                        out.script = Some(Script::from_bytes(value));
                    }
                    // BIP371 taproot output fields
                    [0x05] if value.len() == 32 => {
                        // C1: Output TAP_INTERNAL_KEY key must be exactly 1 byte.
                        // BIP371: value MUST be 32 bytes (x-only public key).
                        out.tap_internal_key = Some(value);
                    }
                    [0x05] => {
                        return Err(PsbtError::InvalidValueSize {
                            field: "output tap_internal_key",
                            expected: 32,
                            got: value.len(),
                        });
                    }
                    k if k.first() == Some(&0x05) && k.len() != 1 => {
                        // C1: Reject output TAP_INTERNAL_KEY with extra key bytes.
                        return Err(PsbtError::InvalidKeySize {
                            field: "output tap_internal_key",
                            expected: 1,
                            got: k.len(),
                        });
                    }
                    [0x06] => {
                        // BIP371: parse tap_tree as (depth, leaf_ver, compact_size+script)*
                        out.tap_tree = Some(parse_tap_tree(&value)?);
                    }
                    k if k.first() == Some(&0x07) && k.len() == 33 => {
                        // TAP_BIP32_DERIVATION: key = 0x07 || x-only pubkey (32)
                        let xonly_pubkey = k[1..].to_vec();
                        let mut cur = std::io::Cursor::new(value.as_slice());
                        if let Ok(VarInt(num_hashes)) = VarInt::decode(&mut cur) {
                            let pos = cur.position() as usize;
                            let hash_bytes = num_hashes as usize * 32;
                            if value.len() >= pos + hash_bytes + 4 {
                                let mut leaf_hashes = std::collections::BTreeSet::new();
                                for i in 0..num_hashes as usize {
                                    let start = pos + i * 32;
                                    leaf_hashes.insert(value[start..start + 32].to_vec());
                                }
                                let fp_start = pos + hash_bytes;
                                let fingerprint = value[fp_start..fp_start + 4].to_vec();
                                let path: Vec<u32> = value[fp_start + 4..]
                                    .chunks_exact(4)
                                    .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                                    .collect();
                                out.tap_bip32_derivation.insert(xonly_pubkey, (leaf_hashes, fingerprint, path));
                            }
                        }
                    }
                    // BIP373 MuSig2 output fields
                    k if k.first() == Some(&0x08) && k.len() == 34 => {
                        validate_musig2_aggregate_pubkey(&k[1..], "output musig2_participant_pubkeys")?;
                        let agg_pk = k[1..].to_vec();
                        out.musig2_participant_pubkeys
                            .insert(agg_pk, decode_musig2_participants(&value, "output musig2_participant_pubkeys")?);
                    }
                    k if k.first() == Some(&0xfc) => {
                        if let Some(pk) = decode_proprietary_key(&k[1..]) {
                            out.proprietary.insert(pk, value);
                        } else {
                            out.unknown.insert(key, value);
                        }
                    }
                    _ => {
                        out.unknown.insert(key, value);
                    }
                }
            }
            outputs.push(out);
        }

        let psbt = Psbt {
            global,
            inputs,
            outputs,
        };

        // Validate non_witness_utxo txids against the unsigned_tx prevouts
        // (matches Bitcoin Core: non_witness_utxo.GetHash() == tx.vin[i].prevout.hash)
        if let Some(ref tx) = psbt.global.unsigned_tx {
            for (i, inp) in psbt.inputs.iter().enumerate() {
                if let Some(ref nw_utxo) = inp.non_witness_utxo {
                    let expected = &tx.inputs[i].previous_output.txid;
                    let got = nw_utxo.txid();
                    if got != expected {
                        return Err(PsbtError::NonWitnessUtxoTxidMismatch {
                            index: i,
                            expected: format!("{:?}", expected),
                            got: format!("{:?}", got),
                        });
                    }
                }
            }
        }

        Ok(psbt)
    }

    /// Deserialize from Base64 string.
    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = B64
            .decode(s.trim())
            .map_err(|e| PsbtError::Base64(e.to_string()))?;
        Self::deserialize(&bytes)
    }
}

fn encode_input(inp: &PsbtInput, buf: &mut Vec<u8>) {
    if let Some(ref tx) = inp.non_witness_utxo {
        write_kv(buf, &[0x00], &encode_tx_legacy(tx));
    }
    if let Some(ref txout) = inp.witness_utxo {
        write_kv(buf, &[0x01], &encode_txout(txout));
    }
    for (pubkey, sig) in &inp.partial_sigs {
        let mut key = vec![0x02];
        key.extend_from_slice(pubkey);
        write_kv(buf, &key, sig);
    }
    if let Some(sh) = inp.sighash_type {
        write_kv(buf, &[0x03], &sh.to_le_bytes());
    }
    if let Some(ref s) = inp.redeem_script {
        write_kv(buf, &[0x04], s.as_bytes());
    }
    if let Some(ref s) = inp.witness_script {
        write_kv(buf, &[0x05], s.as_bytes());
    }
    for (pubkey, (fingerprint, path)) in &inp.bip32_derivation {
        let mut key = vec![0x06];
        key.extend_from_slice(pubkey);
        let mut val = fingerprint.clone();
        for &idx in path {
            val.extend_from_slice(&idx.to_le_bytes());
        }
        write_kv(buf, &key, &val);
    }
    // Preimage fields (0x0A-0x0D)
    for (hash, preimage) in &inp.ripemd160_preimages {
        let mut key = vec![0x0a];
        key.extend_from_slice(hash);
        write_kv(buf, &key, preimage);
    }
    for (hash, preimage) in &inp.sha256_preimages {
        let mut key = vec![0x0b];
        key.extend_from_slice(hash);
        write_kv(buf, &key, preimage);
    }
    for (hash, preimage) in &inp.hash160_preimages {
        let mut key = vec![0x0c];
        key.extend_from_slice(hash);
        write_kv(buf, &key, preimage);
    }
    for (hash, preimage) in &inp.hash256_preimages {
        let mut key = vec![0x0d];
        key.extend_from_slice(hash);
        write_kv(buf, &key, preimage);
    }
    if let Some(ref s) = inp.final_script_sig {
        write_kv(buf, &[0x07], s.as_bytes());
    }
    if let Some(ref witness) = inp.final_script_witness {
        let mut w_buf = Vec::new();
        VarInt(witness.len() as u64).encode(&mut w_buf).ok();
        for item in witness {
            VarInt(item.len() as u64).encode(&mut w_buf).ok();
            w_buf.extend_from_slice(item);
        }
        write_kv(buf, &[0x08], &w_buf);
    }
    // v2 fields
    if let Some(ref txid) = inp.previous_txid {
        write_kv(buf, &[0x0e], &txid.0 .0);
    }
    if let Some(idx) = inp.output_index {
        write_kv(buf, &[0x0f], &idx.to_le_bytes());
    }
    if let Some(seq) = inp.sequence {
        write_kv(buf, &[0x10], &seq.to_le_bytes());
    }
    if let Some(t) = inp.required_time_locktime {
        write_kv(buf, &[0x11], &t.to_le_bytes());
    }
    if let Some(h) = inp.required_height_locktime {
        write_kv(buf, &[0x12], &h.to_le_bytes());
    }
    // BIP371 taproot fields
    if let Some(ref sig) = inp.tap_key_sig {
        write_kv(buf, &[0x13], sig);
    }
    for (pubkey_leafhash, sig) in &inp.tap_script_sig {
        let mut key = vec![0x14];
        key.extend_from_slice(pubkey_leafhash);
        write_kv(buf, &key, sig);
    }
    for (control_block, (script, leaf_version)) in &inp.tap_leaf_script {
        let mut key = vec![0x15];
        key.extend_from_slice(control_block);
        let mut val = script.clone();
        val.push(*leaf_version);
        write_kv(buf, &key, &val);
    }
    for (xonly_pubkey, (leaf_hashes, fingerprint, path)) in &inp.tap_bip32_derivation {
        let mut key = vec![0x16];
        key.extend_from_slice(xonly_pubkey);
        let mut val = Vec::new();
        VarInt(leaf_hashes.len() as u64).encode(&mut val).ok();
        for lh in leaf_hashes {
            val.extend_from_slice(lh);
        }
        val.extend_from_slice(fingerprint);
        for &idx in path {
            val.extend_from_slice(&idx.to_le_bytes());
        }
        write_kv(buf, &key, &val);
    }
    if let Some(ref key) = inp.tap_internal_key {
        write_kv(buf, &[0x17], key);
    }
    if let Some(ref root) = inp.tap_merkle_root {
        write_kv(buf, &[0x18], root);
    }
    // BIP373 MuSig2 input fields
    for (agg_pk, participants) in &inp.musig2_participant_pubkeys {
        let mut key = vec![0x1a];
        key.extend_from_slice(agg_pk);
        write_kv(buf, &key, &encode_musig2_participants(participants));
    }
    for (composite_key, nonce) in &inp.musig2_pub_nonce {
        let mut key = vec![0x1b];
        key.extend_from_slice(composite_key);
        write_kv(buf, &key, nonce);
    }
    for (composite_key, sig) in &inp.musig2_partial_sig {
        let mut key = vec![0x1c];
        key.extend_from_slice(composite_key);
        write_kv(buf, &key, sig);
    }
    for (pk, v) in &inp.proprietary {
        let key = encode_proprietary_key(pk);
        write_kv(buf, &key, v);
    }
    for (k, v) in &inp.unknown {
        write_kv(buf, k, v);
    }
    write_separator(buf);
}

fn encode_output(out: &PsbtOutput, buf: &mut Vec<u8>) {
    if let Some(ref s) = out.redeem_script {
        write_kv(buf, &[0x00], s.as_bytes());
    }
    if let Some(ref s) = out.witness_script {
        write_kv(buf, &[0x01], s.as_bytes());
    }
    for (pubkey, (fingerprint, path)) in &out.bip32_derivation {
        let mut key = vec![0x02];
        key.extend_from_slice(pubkey);
        let mut val = fingerprint.clone();
        for &idx in path {
            val.extend_from_slice(&idx.to_le_bytes());
        }
        write_kv(buf, &key, &val);
    }
    // v2 fields
    if let Some(amt) = out.amount {
        write_kv(buf, &[0x03], &amt.to_le_bytes());
    }
    if let Some(ref s) = out.script {
        write_kv(buf, &[0x04], s.as_bytes());
    }
    // BIP371 taproot output fields
    if let Some(ref key) = out.tap_internal_key {
        write_kv(buf, &[0x05], key);
    }
    if let Some(ref tree) = out.tap_tree {
        let encoded = serialize_tap_tree(tree);
        write_kv(buf, &[0x06], &encoded);
    }
    for (xonly_pubkey, (leaf_hashes, fingerprint, path)) in &out.tap_bip32_derivation {
        let mut key = vec![0x07];
        key.extend_from_slice(xonly_pubkey);
        let mut val = Vec::new();
        VarInt(leaf_hashes.len() as u64).encode(&mut val).ok();
        for lh in leaf_hashes {
            val.extend_from_slice(lh);
        }
        val.extend_from_slice(fingerprint);
        for &idx in path {
            val.extend_from_slice(&idx.to_le_bytes());
        }
        write_kv(buf, &key, &val);
    }
    // BIP373 MuSig2 output fields
    for (agg_pk, participants) in &out.musig2_participant_pubkeys {
        let mut key = vec![0x08];
        key.extend_from_slice(agg_pk);
        write_kv(buf, &key, &encode_musig2_participants(participants));
    }
    for (pk, v) in &out.proprietary {
        let key = encode_proprietary_key(pk);
        write_kv(buf, &key, v);
    }
    for (k, v) in &out.unknown {
        write_kv(buf, k, v);
    }
    write_separator(buf);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::{
        hash::Hash256,
        script::Script,
        transaction::{OutPoint, Transaction, TxIn, TxOut},
        Txid,
    };

    fn make_tx() -> Transaction {
        Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid(Hash256([1; 32])),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut {
                value: 50_000,
                script_pubkey: Script::from_bytes(vec![0x51]),
            }],
            0,
        )
    }

    #[test]
    fn psbt_roundtrip_empty() {
        let tx = make_tx();
        let psbt = Psbt {
            inputs: vec![PsbtInput::default()],
            outputs: vec![PsbtOutput::default()],
            global: PsbtGlobal {
                version: 0,
                unknown: Default::default(),
                unsigned_tx: Some(tx),
                tx_version: None,
                fallback_locktime: None,
                input_count: None,
                output_count: None,
                tx_modifiable: None,
                xpub: Default::default(),
                proprietary: Default::default(),
            },
        };
        let bytes = psbt.serialize();
        let decoded = Psbt::deserialize(&bytes).expect("decode failed");
        assert_eq!(
            decoded.global.unsigned_tx.as_ref().unwrap().inputs.len(),
            psbt.global.unsigned_tx.as_ref().unwrap().inputs.len()
        );
    }

    #[test]
    fn psbt_bip32_derivation_roundtrip() {
        let tx = make_tx();
        let mut inp = PsbtInput::default();
        // Fake 33-byte compressed pubkey
        let pubkey = vec![0x02; 33];
        let fingerprint = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let path = vec![44 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0, 0];
        inp.bip32_derivation
            .insert(pubkey.clone(), (fingerprint.clone(), path.clone()));

        let mut out = PsbtOutput::default();
        out.bip32_derivation
            .insert(pubkey.clone(), (fingerprint.clone(), path.clone()));
        out.redeem_script = Some(Script::from_bytes(vec![0x51]));

        let psbt = Psbt {
            inputs: vec![inp],
            outputs: vec![out],
            global: PsbtGlobal {
                version: 0,
                unknown: Default::default(),
                unsigned_tx: Some(tx),
                tx_version: None,
                fallback_locktime: None,
                input_count: None,
                output_count: None,
                tx_modifiable: None,
                xpub: Default::default(),
                proprietary: Default::default(),
            },
        };
        let bytes = psbt.serialize();
        let decoded = Psbt::deserialize(&bytes).expect("decode failed");

        // Check input BIP32 derivation
        let (fp, p) = decoded.inputs[0]
            .bip32_derivation
            .get(&pubkey)
            .expect("missing input bip32");
        assert_eq!(fp, &fingerprint);
        assert_eq!(p, &path);

        // Check output BIP32 derivation
        let (fp, p) = decoded.outputs[0]
            .bip32_derivation
            .get(&pubkey)
            .expect("missing output bip32");
        assert_eq!(fp, &fingerprint);
        assert_eq!(p, &path);

        // Check output redeem_script survived
        assert!(decoded.outputs[0].redeem_script.is_some());
    }

    #[test]
    fn psbt_tap_leaf_script_roundtrip() {
        let tx = make_tx();
        let mut inp = PsbtInput::default();

        // Fake control block (33 bytes: leaf version + 32-byte internal key)
        let control_block = vec![0xc0; 33];
        let script = vec![0x20; 35]; // fake tapscript
        let leaf_version = 0xc0u8;
        inp.tap_leaf_script
            .insert(control_block.clone(), (script.clone(), leaf_version));

        // Also set tap_internal_key and tap_merkle_root
        let internal_key = vec![0xab; 32];
        inp.tap_internal_key = Some(internal_key.clone());
        let merkle_root = vec![0xcd; 32];
        inp.tap_merkle_root = Some(merkle_root.clone());

        // Set tap_bip32_derivation
        let xonly_pubkey = vec![0x02; 32];
        let leaf_hash = vec![0xee; 32];
        let fingerprint = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let path = vec![86 | 0x80000000, 0 | 0x80000000, 0];
        inp.tap_bip32_derivation.insert(
            xonly_pubkey.clone(),
            ([leaf_hash.clone()].into_iter().collect(), fingerprint.clone(), path.clone()),
        );

        // Set tap_script_sig
        let sig_key = {
            let mut k = vec![0x02; 32]; // x-only pubkey
            k.extend_from_slice(&[0xaa; 32]); // leaf hash
            k
        };
        let sig_value = vec![0xff; 64]; // Schnorr signature
        inp.tap_script_sig.insert(sig_key.clone(), sig_value.clone());

        // Output taproot fields
        let mut out = PsbtOutput::default();
        out.tap_internal_key = Some(vec![0x11; 32]);
        out.tap_tree = Some(vec![
            TapTreeLeaf { depth: 0, leaf_version: 0xc0, script: vec![0x01, 0x02] },
        ]);
        out.tap_bip32_derivation.insert(
            vec![0x33; 32],
            ([vec![0x44; 32]].into_iter().collect(), vec![0xAA, 0xBB, 0xCC, 0xDD], vec![0]),
        );

        let psbt = Psbt {
            inputs: vec![inp],
            outputs: vec![out],
            global: PsbtGlobal {
                version: 0,
                unknown: Default::default(),
                unsigned_tx: Some(tx),
                tx_version: None,
                fallback_locktime: None,
                input_count: None,
                output_count: None,
                tx_modifiable: None,
                xpub: Default::default(),
                proprietary: Default::default(),
            },
        };
        let bytes = psbt.serialize();
        let decoded = Psbt::deserialize(&bytes).expect("decode failed");

        // Verify tap_leaf_script roundtrip
        let (dec_script, dec_lv) = decoded.inputs[0]
            .tap_leaf_script
            .get(&control_block)
            .expect("missing tap_leaf_script");
        assert_eq!(dec_script, &script);
        assert_eq!(*dec_lv, leaf_version);

        // Verify tap_internal_key roundtrip
        assert_eq!(decoded.inputs[0].tap_internal_key.as_ref().unwrap(), &internal_key);

        // Verify tap_merkle_root roundtrip
        assert_eq!(decoded.inputs[0].tap_merkle_root.as_ref().unwrap(), &merkle_root);

        // Verify tap_bip32_derivation roundtrip
        let (dec_lh, dec_fp, dec_path) = decoded.inputs[0]
            .tap_bip32_derivation
            .get(&xonly_pubkey)
            .expect("missing tap_bip32_derivation");
        let expected_lh: std::collections::BTreeSet<Vec<u8>> = [leaf_hash].into_iter().collect();
        assert_eq!(dec_lh, &expected_lh);
        assert_eq!(dec_fp, &fingerprint);
        assert_eq!(dec_path, &path);

        // Verify tap_script_sig roundtrip
        assert_eq!(
            decoded.inputs[0].tap_script_sig.get(&sig_key).unwrap(),
            &sig_value
        );

        // Verify output taproot fields
        assert_eq!(decoded.outputs[0].tap_internal_key.as_ref().unwrap(), &vec![0x11; 32]);
        assert_eq!(
            decoded.outputs[0].tap_tree.as_ref().unwrap(),
            &vec![TapTreeLeaf { depth: 0, leaf_version: 0xc0, script: vec![0x01, 0x02] }],
        );
        let (out_lh, out_fp, out_path) = decoded.outputs[0]
            .tap_bip32_derivation
            .get(&vec![0x33; 32])
            .expect("missing output tap_bip32_derivation");
        let expected_out_lh: std::collections::BTreeSet<Vec<u8>> = [vec![0x44; 32]].into_iter().collect();
        assert_eq!(out_lh, &expected_out_lh);
        assert_eq!(out_fp, &vec![0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(out_path, &vec![0u32]);
    }

    #[test]
    fn psbt_base64_roundtrip() {
        let tx = make_tx();
        let psbt = Psbt {
            inputs: vec![PsbtInput::default()],
            outputs: vec![PsbtOutput::default()],
            global: PsbtGlobal {
                version: 0,
                unknown: Default::default(),
                unsigned_tx: Some(tx),
                tx_version: None,
                fallback_locktime: None,
                input_count: None,
                output_count: None,
                tx_modifiable: None,
                xpub: Default::default(),
                proprietary: Default::default(),
            },
        };
        let b64 = psbt.to_base64();
        let decoded = Psbt::from_base64(&b64).expect("base64 decode failed");
        assert_eq!(decoded.global.unsigned_tx.as_ref().unwrap().outputs[0].value, 50_000);
    }

    #[test]
    fn psbt_global_xpub_roundtrip() {
        let tx = make_tx();
        let mut xpub_map = std::collections::BTreeMap::new();
        // 78-byte fake extended public key
        let xpub_bytes: Vec<u8> = (0..78).collect();
        let fingerprint = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let path = vec![44 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000];
        xpub_map.insert(xpub_bytes.clone(), (fingerprint.clone(), path.clone()));

        let psbt = Psbt {
            inputs: vec![PsbtInput::default()],
            outputs: vec![PsbtOutput::default()],
            global: PsbtGlobal {
                version: 0,
                unknown: Default::default(),
                unsigned_tx: Some(tx),
                tx_version: None,
                fallback_locktime: None,
                input_count: None,
                output_count: None,
                tx_modifiable: None,
                xpub: xpub_map,
                proprietary: Default::default(),
            },
        };
        let bytes = psbt.serialize();
        let decoded = Psbt::deserialize(&bytes).expect("decode failed");

        let (dec_fp, dec_path) = decoded.global.xpub.get(&xpub_bytes).expect("missing xpub");
        assert_eq!(dec_fp, &fingerprint);
        assert_eq!(dec_path, &path);
    }

    #[test]
    fn psbt_preimage_fields_roundtrip() {
        let tx = make_tx();
        let mut inp = PsbtInput::default();

        // RIPEMD160 preimage (hash = 20 bytes)
        let ripemd_hash = vec![0x11; 20];
        let ripemd_preimage = vec![0x01, 0x02, 0x03];
        inp.ripemd160_preimages.insert(ripemd_hash.clone(), ripemd_preimage.clone());

        // SHA256 preimage (hash = 32 bytes)
        let sha256_hash = vec![0x22; 32];
        let sha256_preimage = vec![0x04, 0x05, 0x06];
        inp.sha256_preimages.insert(sha256_hash.clone(), sha256_preimage.clone());

        // HASH160 preimage (hash = 20 bytes)
        let hash160_hash = vec![0x33; 20];
        let hash160_preimage = vec![0x07, 0x08];
        inp.hash160_preimages.insert(hash160_hash.clone(), hash160_preimage.clone());

        // HASH256 preimage (hash = 32 bytes)
        let hash256_hash = vec![0x44; 32];
        let hash256_preimage = vec![0x09, 0x0a, 0x0b, 0x0c];
        inp.hash256_preimages.insert(hash256_hash.clone(), hash256_preimage.clone());

        let psbt = Psbt {
            inputs: vec![inp],
            outputs: vec![PsbtOutput::default()],
            global: PsbtGlobal {
                version: 0,
                unknown: Default::default(),
                unsigned_tx: Some(tx),
                tx_version: None,
                fallback_locktime: None,
                input_count: None,
                output_count: None,
                tx_modifiable: None,
                xpub: Default::default(),
                proprietary: Default::default(),
            },
        };
        let bytes = psbt.serialize();
        let decoded = Psbt::deserialize(&bytes).expect("decode failed");

        assert_eq!(decoded.inputs[0].ripemd160_preimages.get(&ripemd_hash).unwrap(), &ripemd_preimage);
        assert_eq!(decoded.inputs[0].sha256_preimages.get(&sha256_hash).unwrap(), &sha256_preimage);
        assert_eq!(decoded.inputs[0].hash160_preimages.get(&hash160_hash).unwrap(), &hash160_preimage);
        assert_eq!(decoded.inputs[0].hash256_preimages.get(&hash256_hash).unwrap(), &hash256_preimage);
    }

    #[test]
    fn psbt_duplicate_key_detection() {
        // Build raw PSBT bytes with a duplicate key in the global map.
        // We'll duplicate the unsigned_tx key (0x00).
        let tx = make_tx();
        let psbt = Psbt {
            inputs: vec![PsbtInput::default()],
            outputs: vec![PsbtOutput::default()],
            global: PsbtGlobal {
                version: 0,
                unknown: Default::default(),
                unsigned_tx: Some(tx),
                tx_version: None,
                fallback_locktime: None,
                input_count: None,
                output_count: None,
                tx_modifiable: None,
                xpub: Default::default(),
                proprietary: Default::default(),
            },
        };
        let _bytes = psbt.serialize();

        // Build raw bytes manually with a duplicate key in the global map.
        let mut raw = Vec::new();
        raw.extend_from_slice(PSBT_MAGIC);

        // Write the unsigned_tx entry twice
        let tx_bytes = encode_tx_legacy(psbt.global.unsigned_tx.as_ref().unwrap());
        write_kv(&mut raw, &[0x00], &tx_bytes);
        write_kv(&mut raw, &[0x00], &tx_bytes); // DUPLICATE!
        write_separator(&mut raw); // end global map

        // Write empty input and output maps
        write_separator(&mut raw); // empty input map
        write_separator(&mut raw); // empty output map

        let result = Psbt::deserialize(&raw);
        assert!(result.is_err());
        match result.unwrap_err() {
            PsbtError::DuplicateKey(key_hex) => {
                assert_eq!(key_hex, "00");
            }
            other => panic!("expected DuplicateKey error, got: {:?}", other),
        }
    }

    #[test]
    fn psbt_musig2_input_fields_roundtrip() {
        let tx = make_tx();
        let mut inp = PsbtInput::default();

        // MuSig2 participant pubkeys: aggregate(33) → [participant1(33), participant2(33)]
        let agg_pk = vec![0x02; 33];
        let p1 = vec![0x03; 33];
        let mut p2 = vec![0x02]; p2.extend_from_slice(&[0x04; 32]); // valid compressed (0x02 prefix)
        inp.musig2_participant_pubkeys
            .insert(agg_pk.clone(), vec![p1.clone(), p2.clone()]);

        // MuSig2 pub nonce: participant(33) || aggregate(33) || leaf_hash(32) → nonce(66)
        let mut nonce_key = vec![0x03; 33];
        nonce_key.extend_from_slice(&[0x02; 33]);
        nonce_key.extend_from_slice(&[0xaa; 32]);
        let nonce_val = vec![0xbb; 66];
        inp.musig2_pub_nonce
            .insert(nonce_key.clone(), nonce_val.clone());

        // MuSig2 partial sig: same key format → sig(32)
        let mut sig_key = vec![0x03; 33]; // valid compressed prefix
        sig_key.extend_from_slice(&[0x02; 33]);
        sig_key.extend_from_slice(&[0xcc; 32]);
        let sig_val = vec![0xdd; 32];
        inp.musig2_partial_sig
            .insert(sig_key.clone(), sig_val.clone());

        let psbt = Psbt {
            inputs: vec![inp],
            outputs: vec![PsbtOutput::default()],
            global: PsbtGlobal {
                version: 0,
                unknown: Default::default(),
                unsigned_tx: Some(tx),
                tx_version: None,
                fallback_locktime: None,
                input_count: None,
                output_count: None,
                tx_modifiable: None,
                xpub: Default::default(),
                proprietary: Default::default(),
            },
        };
        let bytes = psbt.serialize();
        let decoded = Psbt::deserialize(&bytes).expect("decode failed");

        // Check participant pubkeys
        let pks = decoded.inputs[0]
            .musig2_participant_pubkeys
            .get(&agg_pk)
            .expect("missing musig2 participants");
        assert_eq!(pks, &vec![p1, p2]);

        // Check pub nonce
        assert_eq!(
            decoded.inputs[0].musig2_pub_nonce.get(&nonce_key).unwrap(),
            &nonce_val
        );

        // Check partial sig
        assert_eq!(
            decoded.inputs[0].musig2_partial_sig.get(&sig_key).unwrap(),
            &sig_val
        );
    }

    #[test]
    fn psbt_musig2_output_fields_roundtrip() {
        let tx = make_tx();
        let mut out = PsbtOutput::default();

        let agg_pk = vec![0x02; 33];
        let mut p1 = vec![0x03]; p1.extend_from_slice(&[0x05; 32]); // valid compressed
        let mut p2 = vec![0x02]; p2.extend_from_slice(&[0x06; 32]); // valid compressed
        out.musig2_participant_pubkeys
            .insert(agg_pk.clone(), vec![p1.clone(), p2.clone()]);

        let psbt = Psbt {
            inputs: vec![PsbtInput::default()],
            outputs: vec![out],
            global: PsbtGlobal {
                version: 0,
                unknown: Default::default(),
                unsigned_tx: Some(tx),
                tx_version: None,
                fallback_locktime: None,
                input_count: None,
                output_count: None,
                tx_modifiable: None,
                xpub: Default::default(),
                proprietary: Default::default(),
            },
        };
        let bytes = psbt.serialize();
        let decoded = Psbt::deserialize(&bytes).expect("decode failed");

        let pks = decoded.outputs[0]
            .musig2_participant_pubkeys
            .get(&agg_pk)
            .expect("missing musig2 output participants");
        assert_eq!(pks, &vec![p1, p2]);
    }

    #[test]
    fn psbt_proprietary_key_roundtrip() {
        use crate::types::ProprietaryKey;

        let tx = make_tx();
        let mut global_prop = std::collections::BTreeMap::new();
        let pk = ProprietaryKey {
            identifier: b"mycompany".to_vec(),
            subtype: 42,
            key_data: vec![0x01, 0x02],
        };
        global_prop.insert(pk.clone(), b"global_value".to_vec());

        let mut inp = PsbtInput::default();
        let inp_pk = ProprietaryKey {
            identifier: b"test".to_vec(),
            subtype: 1,
            key_data: vec![],
        };
        inp.proprietary
            .insert(inp_pk.clone(), b"input_value".to_vec());

        let mut out = PsbtOutput::default();
        let out_pk = ProprietaryKey {
            identifier: b"vendor".to_vec(),
            subtype: 100,
            key_data: vec![0xff],
        };
        out.proprietary
            .insert(out_pk.clone(), b"output_value".to_vec());

        let psbt = Psbt {
            inputs: vec![inp],
            outputs: vec![out],
            global: PsbtGlobal {
                version: 0,
                unknown: Default::default(),
                unsigned_tx: Some(tx),
                tx_version: None,
                fallback_locktime: None,
                input_count: None,
                output_count: None,
                tx_modifiable: None,
                xpub: Default::default(),
                proprietary: global_prop,
            },
        };
        let bytes = psbt.serialize();
        let decoded = Psbt::deserialize(&bytes).expect("decode failed");

        // Global proprietary
        assert_eq!(
            decoded.global.proprietary.get(&pk).unwrap(),
            b"global_value"
        );

        // Input proprietary
        assert_eq!(
            decoded.inputs[0].proprietary.get(&inp_pk).unwrap(),
            b"input_value"
        );

        // Output proprietary
        assert_eq!(
            decoded.outputs[0].proprietary.get(&out_pk).unwrap(),
            b"output_value"
        );
    }

    #[test]
    fn psbt_finalizer_leaf_hash_matching() {
        // Verify the finalizer correctly matches signatures to leaf scripts by leaf hash
        use crate::types::ProprietaryKey;

        let tx = make_tx();
        let mut psbt = Psbt::create(tx);

        let leaf_script_a = vec![0xac]; // OP_CHECKSIG
        let leaf_script_b = vec![0x51]; // OP_TRUE
        let leaf_version = 0xc0u8;

        // Two different leaf scripts with different control blocks
        let mut cb_a = vec![leaf_version];
        cb_a.extend_from_slice(&[0x11; 32]); // internal key variant A
        let mut cb_b = vec![leaf_version];
        cb_b.extend_from_slice(&[0x22; 32]); // internal key variant B

        // Compute actual leaf hashes
        let lh_a = rbtc_crypto::tap_leaf_hash(leaf_version, &leaf_script_a);
        let lh_b = rbtc_crypto::tap_leaf_hash(leaf_version, &leaf_script_b);

        // Only sign for leaf B (not A)
        let xonly_pk = vec![0x03; 32];
        let mut sig_key_b = xonly_pk.clone();
        sig_key_b.extend_from_slice(&lh_b.0);
        let sig_b: Vec<u8> = (0..64).collect();

        let inp = &mut psbt.inputs[0];
        inp.witness_utxo = Some(TxOut {
            value: 50_000,
            script_pubkey: Script::new(),
        });
        inp.tap_leaf_script
            .insert(cb_a.clone(), (leaf_script_a.clone(), leaf_version));
        inp.tap_leaf_script
            .insert(cb_b.clone(), (leaf_script_b.clone(), leaf_version));
        inp.tap_script_sig
            .insert(sig_key_b.clone(), sig_b.clone());
        inp.tap_internal_key = Some(vec![0x02; 32]);

        psbt.finalize().unwrap();

        let witness = psbt.inputs[0].final_script_witness.as_ref().unwrap();
        assert_eq!(witness.len(), 3);
        assert_eq!(witness[0], sig_b); // signature for leaf B
        assert_eq!(witness[1], leaf_script_b); // leaf B script
        assert_eq!(witness[2], cb_b); // leaf B control block
    }

    // ── M23: PSBT_HIGHEST_VERSION enforcement ────────────────────────────

    #[test]
    fn rejects_psbt_version_3_and_above() {
        // Build a valid v0 PSBT, then patch the version field to 3.
        let tx = make_tx();
        let mut psbt = Psbt {
            inputs: vec![PsbtInput::default()],
            outputs: vec![PsbtOutput::default()],
            global: PsbtGlobal {
                version: 3,
                unsigned_tx: Some(tx),
                tx_version: None,
                fallback_locktime: None,
                input_count: None,
                output_count: None,
                tx_modifiable: None,
                xpub: Default::default(),
                proprietary: Default::default(),
                unknown: Default::default(),
            },
        };
        let bytes = psbt.serialize();
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::UnsupportedVersion(3)),
            "expected UnsupportedVersion(3), got: {err}"
        );
    }

    #[test]
    fn accepts_psbt_version_0_and_2() {
        // v0
        let tx = make_tx();
        let psbt_v0 = Psbt {
            inputs: vec![PsbtInput::default()],
            outputs: vec![PsbtOutput::default()],
            global: PsbtGlobal {
                version: 0,
                unsigned_tx: Some(tx),
                tx_version: None,
                fallback_locktime: None,
                input_count: None,
                output_count: None,
                tx_modifiable: None,
                xpub: Default::default(),
                proprietary: Default::default(),
                unknown: Default::default(),
            },
        };
        let bytes = psbt_v0.serialize();
        Psbt::deserialize(&bytes).expect("v0 should be accepted");

        // v2 — need proper v2 fields
        let mut inp = PsbtInput::default();
        inp.previous_txid = Some(Txid(Hash256([1; 32])));
        inp.output_index = Some(0);
        let mut out = PsbtOutput::default();
        out.amount = Some(50_000);
        out.script = Some(Script::from_bytes(vec![0x51]));

        let psbt_v2 = Psbt {
            inputs: vec![inp],
            outputs: vec![out],
            global: PsbtGlobal {
                version: 2,
                unsigned_tx: None,
                tx_version: Some(2),
                fallback_locktime: Some(0),
                input_count: Some(1),
                output_count: Some(1),
                tx_modifiable: None,
                xpub: Default::default(),
                proprietary: Default::default(),
                unknown: Default::default(),
            },
        };
        let bytes = psbt_v2.serialize();
        Psbt::deserialize(&bytes).expect("v2 should be accepted");
    }

    // ── M24: non_witness_utxo txid validation ────────────────────────────

    #[test]
    fn rejects_non_witness_utxo_txid_mismatch() {
        let tx = make_tx();
        let mut psbt = Psbt {
            inputs: vec![PsbtInput::default()],
            outputs: vec![PsbtOutput::default()],
            global: PsbtGlobal {
                version: 0,
                unsigned_tx: Some(tx),
                tx_version: None,
                fallback_locktime: None,
                input_count: None,
                output_count: None,
                tx_modifiable: None,
                xpub: Default::default(),
                proprietary: Default::default(),
                unknown: Default::default(),
            },
        };
        // Set a non_witness_utxo with a different txid than the prevout
        let wrong_tx = Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint { txid: Txid(Hash256([0xff; 32])), vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut { value: 99_999, script_pubkey: Script::new() }],
            0,
        );
        psbt.inputs[0].non_witness_utxo = Some(wrong_tx);
        let bytes = psbt.serialize();
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::NonWitnessUtxoTxidMismatch { .. }),
            "expected NonWitnessUtxoTxidMismatch, got: {err}"
        );
    }

    #[test]
    fn accepts_matching_non_witness_utxo_txid() {
        let tx = make_tx();
        // The prevout references txid [1;32]. Build a prev_tx whose txid matches.
        // We need to set the non_witness_utxo to a tx whose txid equals [1;32].
        // Since txid is a hash, we can't forge it. Instead, construct the unsigned tx
        // to reference the txid of the prev_tx we'll supply.
        let prev_tx = Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint { txid: Txid(Hash256([0; 32])), vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut { value: 50_000, script_pubkey: Script::from_bytes(vec![0x51]) }],
            0,
        );
        let prev_txid = prev_tx.txid().clone();

        // Build a new unsigned tx that references prev_tx
        let unsigned = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint { txid: prev_txid, vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut { value: 40_000, script_pubkey: Script::from_bytes(vec![0x51]) }],
            0,
        );

        let mut inp = PsbtInput::default();
        inp.non_witness_utxo = Some(prev_tx);

        let psbt = Psbt {
            inputs: vec![inp],
            outputs: vec![PsbtOutput::default()],
            global: PsbtGlobal {
                version: 0,
                unsigned_tx: Some(unsigned),
                tx_version: None,
                fallback_locktime: None,
                input_count: None,
                output_count: None,
                tx_modifiable: None,
                xpub: Default::default(),
                proprietary: Default::default(),
                unknown: Default::default(),
            },
        };
        let bytes = psbt.serialize();
        Psbt::deserialize(&bytes).expect("matching non_witness_utxo txid should pass");
    }

    // ── M25: MuSig2 67-byte key-path keys ───────────────────────────────

    #[test]
    fn musig2_pub_nonce_67_byte_key_path() {
        let tx = make_tx();
        let mut inp = PsbtInput::default();

        // 67-byte key: 0x1b || participant(33) || aggregate(33) — no leaf_hash
        let mut nonce_key_66 = vec![0x03; 33]; // participant
        nonce_key_66.extend_from_slice(&[0x02; 33]); // aggregate
        assert_eq!(nonce_key_66.len(), 66); // stored without the type byte prefix
        let nonce_val = vec![0xbb; 66];
        inp.musig2_pub_nonce
            .insert(nonce_key_66.clone(), nonce_val.clone());

        let psbt = Psbt {
            inputs: vec![inp],
            outputs: vec![PsbtOutput::default()],
            global: PsbtGlobal {
                version: 0,
                unsigned_tx: Some(tx),
                tx_version: None,
                fallback_locktime: None,
                input_count: None,
                output_count: None,
                tx_modifiable: None,
                xpub: Default::default(),
                proprietary: Default::default(),
                unknown: Default::default(),
            },
        };
        let bytes = psbt.serialize();
        let decoded = Psbt::deserialize(&bytes).expect("67-byte MuSig2 pub_nonce key should parse");
        assert_eq!(
            decoded.inputs[0].musig2_pub_nonce.get(&nonce_key_66).unwrap(),
            &nonce_val
        );
    }

    #[test]
    fn musig2_partial_sig_67_byte_key_path() {
        let tx = make_tx();
        let mut inp = PsbtInput::default();

        // 67-byte key: 0x1c || participant(33) || aggregate(33) — no leaf_hash
        let mut sig_key_66 = vec![0x03; 33]; // valid compressed prefix
        sig_key_66.extend_from_slice(&[0x02; 33]);
        assert_eq!(sig_key_66.len(), 66);
        let sig_val = vec![0xdd; 32];
        inp.musig2_partial_sig
            .insert(sig_key_66.clone(), sig_val.clone());

        let psbt = Psbt {
            inputs: vec![inp],
            outputs: vec![PsbtOutput::default()],
            global: PsbtGlobal {
                version: 0,
                unsigned_tx: Some(tx),
                tx_version: None,
                fallback_locktime: None,
                input_count: None,
                output_count: None,
                tx_modifiable: None,
                xpub: Default::default(),
                proprietary: Default::default(),
                unknown: Default::default(),
            },
        };
        let bytes = psbt.serialize();
        let decoded = Psbt::deserialize(&bytes).expect("67-byte MuSig2 partial_sig key should parse");
        assert_eq!(
            decoded.inputs[0].musig2_partial_sig.get(&sig_key_66).unwrap(),
            &sig_val
        );
    }

    // ── C1/C2/C3: Taproot deserialization validation ─────────────────────

    /// Build a minimal valid v0 PSBT with one input and one output, then
    /// inject an extra key-value pair into the input map by patching bytes.
    /// Returns the raw bytes ready for `Psbt::deserialize`.
    fn build_psbt_with_input_kv(extra_key: &[u8], extra_value: &[u8]) -> Vec<u8> {
        let tx = make_tx();
        let psbt = Psbt {
            inputs: vec![PsbtInput::default()],
            outputs: vec![PsbtOutput::default()],
            global: PsbtGlobal {
                version: 0,
                unsigned_tx: Some(tx),
                tx_version: None,
                fallback_locktime: None,
                input_count: None,
                output_count: None,
                tx_modifiable: None,
                xpub: Default::default(),
                proprietary: Default::default(),
                unknown: Default::default(),
            },
        };
        let mut bytes = psbt.serialize();
        // The input map is at the end: ... 0x00 (global sep) <input map> 0x00 (input sep) <output map> 0x00
        // Find the global separator (first 0x00 after magic+global), then inject before input sep.
        // Easier: rebuild manually. Serialize global + inject input kv + output.
        // Actually simplest: find the input separator byte and inject before it.
        //
        // The serialized format is: magic | global-kvs | 0x00 | input-kvs | 0x00 | output-kvs | 0x00
        // For an empty input, the input section is just 0x00.
        // We need to find that first 0x00 after the global separator.

        // Strategy: scan for the global 0x00 separator (after the unsigned_tx kv).
        // After that, the next byte starts the input map. For an empty input it's 0x00.
        // We insert our kv pair before that 0x00.

        // Find global separator: it's the first standalone 0x00 varint after the magic.
        // The global section has one KV: key=0x00, value=<tx>. After that: separator=0x00.
        // Then input map starts.

        // Let's find the position of the input separator (the second 0x00 that acts as separator).
        // We know the magic is 5 bytes. After that, global KVs, then 0x00.
        // The input map for empty PsbtInput is just 0x00.
        // The output map for empty PsbtOutput is just 0x00.

        // Find global separator position by scanning.
        let mut pos = 5; // skip magic
        loop {
            let klen = read_varint_at(&bytes, &mut pos);
            if klen == 0 {
                // This is the global separator
                break;
            }
            pos += klen as usize; // skip key
            let vlen = read_varint_at(&bytes, &mut pos);
            pos += vlen as usize; // skip value
        }
        // pos is now right after the global separator.
        // The next byte starts the input map. For empty input, bytes[pos] == 0x00.
        // Inject our KV pair before that separator.
        let inject_pos = pos;

        let mut injected = Vec::new();
        // key-len + key
        VarInt(extra_key.len() as u64).encode(&mut injected).ok();
        injected.extend_from_slice(extra_key);
        // value-len + value
        VarInt(extra_value.len() as u64).encode(&mut injected).ok();
        injected.extend_from_slice(extra_value);

        let mut result = bytes[..inject_pos].to_vec();
        result.extend_from_slice(&injected);
        result.extend_from_slice(&bytes[inject_pos..]);
        result
    }

    fn build_psbt_with_output_kv(extra_key: &[u8], extra_value: &[u8]) -> Vec<u8> {
        let tx = make_tx();
        let psbt = Psbt {
            inputs: vec![PsbtInput::default()],
            outputs: vec![PsbtOutput::default()],
            global: PsbtGlobal {
                version: 0,
                unsigned_tx: Some(tx),
                tx_version: None,
                fallback_locktime: None,
                input_count: None,
                output_count: None,
                tx_modifiable: None,
                xpub: Default::default(),
                proprietary: Default::default(),
                unknown: Default::default(),
            },
        };
        let bytes = psbt.serialize();

        // Find global sep, then input sep, then inject before output sep.
        let mut pos = 5;
        loop {
            let klen = read_varint_at(&bytes, &mut pos);
            if klen == 0 { break; }
            pos += klen as usize;
            let vlen = read_varint_at(&bytes, &mut pos);
            pos += vlen as usize;
        }
        // Skip input map (empty, just 0x00)
        loop {
            let klen = read_varint_at(&bytes, &mut pos);
            if klen == 0 { break; }
            pos += klen as usize;
            let vlen = read_varint_at(&bytes, &mut pos);
            pos += vlen as usize;
        }
        // pos is right after input separator, at start of output map.
        let inject_pos = pos;

        let mut injected = Vec::new();
        VarInt(extra_key.len() as u64).encode(&mut injected).ok();
        injected.extend_from_slice(extra_key);
        VarInt(extra_value.len() as u64).encode(&mut injected).ok();
        injected.extend_from_slice(extra_value);

        let mut result = bytes[..inject_pos].to_vec();
        result.extend_from_slice(&injected);
        result.extend_from_slice(&bytes[inject_pos..]);
        result
    }

    fn read_varint_at(bytes: &[u8], pos: &mut usize) -> u64 {
        let mut cur = std::io::Cursor::new(&bytes[*pos..]);
        let vi = VarInt::decode(&mut cur).unwrap();
        *pos += cur.position() as usize;
        vi.0
    }

    // ── C1: TAP_INTERNAL_KEY key-size validation ─────────────────────────

    #[test]
    fn tap_internal_key_input_valid() {
        // key = [0x17] (1 byte), value = 32-byte x-only pubkey
        let bytes = build_psbt_with_input_kv(&[0x17], &[0x02; 32]);
        let psbt = Psbt::deserialize(&bytes).expect("valid tap_internal_key should parse");
        assert_eq!(psbt.inputs[0].tap_internal_key.as_ref().unwrap(), &vec![0x02; 32]);
    }

    #[test]
    fn tap_internal_key_input_extra_key_bytes_rejected() {
        // key = [0x17, 0x00] (2 bytes) — should be rejected
        let bytes = build_psbt_with_input_kv(&[0x17, 0x00], &[0x02; 32]);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::InvalidKeySize { field: "input tap_internal_key", expected: 1, got: 2 }),
            "expected InvalidKeySize, got: {err}"
        );
    }

    #[test]
    fn tap_internal_key_output_valid() {
        let bytes = build_psbt_with_output_kv(&[0x05], &[0x02; 32]);
        let psbt = Psbt::deserialize(&bytes).expect("valid output tap_internal_key should parse");
        assert_eq!(psbt.outputs[0].tap_internal_key.as_ref().unwrap(), &vec![0x02; 32]);
    }

    #[test]
    fn tap_internal_key_output_extra_key_bytes_rejected() {
        let bytes = build_psbt_with_output_kv(&[0x05, 0x00], &[0x02; 32]);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::InvalidKeySize { field: "output tap_internal_key", expected: 1, got: 2 }),
            "expected InvalidKeySize, got: {err}"
        );
    }

    // ── C1b: TAP_INTERNAL_KEY value-size validation (BIP371: must be 32 bytes) ──

    #[test]
    fn tap_internal_key_input_31_bytes_rejected() {
        let bytes = build_psbt_with_input_kv(&[0x17], &[0x02; 31]);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::InvalidValueSize { field: "input tap_internal_key", expected: 32, got: 31 }),
            "expected InvalidValueSize(31), got: {err}"
        );
    }

    #[test]
    fn tap_internal_key_input_33_bytes_rejected() {
        let bytes = build_psbt_with_input_kv(&[0x17], &[0x02; 33]);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::InvalidValueSize { field: "input tap_internal_key", expected: 32, got: 33 }),
            "expected InvalidValueSize(33), got: {err}"
        );
    }

    #[test]
    fn tap_internal_key_input_0_bytes_rejected() {
        let bytes = build_psbt_with_input_kv(&[0x17], &[]);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::InvalidValueSize { field: "input tap_internal_key", expected: 32, got: 0 }),
            "expected InvalidValueSize(0), got: {err}"
        );
    }

    #[test]
    fn tap_internal_key_output_31_bytes_rejected() {
        let bytes = build_psbt_with_output_kv(&[0x05], &[0x02; 31]);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::InvalidValueSize { field: "output tap_internal_key", expected: 32, got: 31 }),
            "expected InvalidValueSize(31), got: {err}"
        );
    }

    #[test]
    fn tap_internal_key_output_33_bytes_rejected() {
        let bytes = build_psbt_with_output_kv(&[0x05], &[0x02; 33]);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::InvalidValueSize { field: "output tap_internal_key", expected: 32, got: 33 }),
            "expected InvalidValueSize(33), got: {err}"
        );
    }

    #[test]
    fn tap_internal_key_output_0_bytes_rejected() {
        let bytes = build_psbt_with_output_kv(&[0x05], &[]);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::InvalidValueSize { field: "output tap_internal_key", expected: 32, got: 0 }),
            "expected InvalidValueSize(0), got: {err}"
        );
    }

    // ── C2: TAP_KEY_SIG (0x13) signature length validation ───────────────

    #[test]
    fn tap_key_sig_64_bytes_valid() {
        let bytes = build_psbt_with_input_kv(&[0x13], &vec![0xAA; 64]);
        let psbt = Psbt::deserialize(&bytes).expect("64-byte tap_key_sig should parse");
        assert_eq!(psbt.inputs[0].tap_key_sig.as_ref().unwrap().len(), 64);
    }

    #[test]
    fn tap_key_sig_65_bytes_valid() {
        let bytes = build_psbt_with_input_kv(&[0x13], &vec![0xAA; 65]);
        let psbt = Psbt::deserialize(&bytes).expect("65-byte tap_key_sig should parse");
        assert_eq!(psbt.inputs[0].tap_key_sig.as_ref().unwrap().len(), 65);
    }

    #[test]
    fn tap_key_sig_63_bytes_rejected() {
        let bytes = build_psbt_with_input_kv(&[0x13], &vec![0xAA; 63]);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::InvalidSignatureLength { field: "input tap_key_sig", got: 63 }),
            "expected InvalidSignatureLength(63), got: {err}"
        );
    }

    #[test]
    fn tap_key_sig_66_bytes_rejected() {
        let bytes = build_psbt_with_input_kv(&[0x13], &vec![0xAA; 66]);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::InvalidSignatureLength { field: "input tap_key_sig", got: 66 }),
            "expected InvalidSignatureLength(66), got: {err}"
        );
    }

    // ── C3: TAP_SCRIPT_SIG (0x14) signature length validation ────────────

    #[test]
    fn tap_script_sig_64_bytes_valid() {
        // key = 0x14 || x-only pubkey (32) || leaf_hash (32) = 65 bytes total
        let mut key = vec![0x14];
        key.extend_from_slice(&[0x02; 32]); // x-only pubkey
        key.extend_from_slice(&[0x03; 32]); // leaf hash
        let bytes = build_psbt_with_input_kv(&key, &vec![0xBB; 64]);
        let psbt = Psbt::deserialize(&bytes).expect("64-byte tap_script_sig should parse");
        let mut expected_map_key = vec![0x02; 32];
        expected_map_key.extend_from_slice(&[0x03; 32]);
        assert_eq!(psbt.inputs[0].tap_script_sig.get(&expected_map_key).unwrap().len(), 64);
    }

    #[test]
    fn tap_script_sig_65_bytes_valid() {
        let mut key = vec![0x14];
        key.extend_from_slice(&[0x02; 32]);
        key.extend_from_slice(&[0x03; 32]);
        let bytes = build_psbt_with_input_kv(&key, &vec![0xBB; 65]);
        let psbt = Psbt::deserialize(&bytes).expect("65-byte tap_script_sig should parse");
        let mut expected_map_key = vec![0x02; 32];
        expected_map_key.extend_from_slice(&[0x03; 32]);
        assert_eq!(psbt.inputs[0].tap_script_sig.get(&expected_map_key).unwrap().len(), 65);
    }

    #[test]
    fn tap_script_sig_63_bytes_rejected() {
        let mut key = vec![0x14];
        key.extend_from_slice(&[0x02; 32]);
        key.extend_from_slice(&[0x03; 32]);
        let bytes = build_psbt_with_input_kv(&key, &vec![0xBB; 63]);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::InvalidSignatureLength { field: "input tap_script_sig", got: 63 }),
            "expected InvalidSignatureLength(63), got: {err}"
        );
    }

    // ── M3: TAP_BIP32_DERIVATION leaf hashes use BTreeSet (dedup + sorted) ──

    #[test]
    fn tap_bip32_derivation_deduplicates_leaf_hashes() {
        // Build TAP_BIP32_DERIVATION value with duplicate leaf hashes
        let xonly = vec![0x02; 32];
        let leaf_a = vec![0xaa; 32];
        let leaf_b = vec![0xbb; 32];

        // Wire format: varint(3) || hash_a || hash_b || hash_a || fingerprint || path
        // 3 hashes where hash_a appears twice — should be deduplicated to 2
        let mut value = Vec::new();
        VarInt(3).encode(&mut value).unwrap();
        value.extend_from_slice(&leaf_a);
        value.extend_from_slice(&leaf_b);
        value.extend_from_slice(&leaf_a); // duplicate
        value.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // fingerprint
        value.extend_from_slice(&0u32.to_le_bytes()); // path element

        let mut key = vec![0x16];
        key.extend_from_slice(&xonly);
        let bytes = build_psbt_with_input_kv(&key, &value);
        let psbt = Psbt::deserialize(&bytes).expect("should parse");

        let (leaf_hashes, _, _) = psbt.inputs[0]
            .tap_bip32_derivation
            .get(&xonly)
            .expect("missing tap_bip32_derivation");

        // BTreeSet should deduplicate: 3 input hashes → 2 unique
        assert_eq!(leaf_hashes.len(), 2);
        assert!(leaf_hashes.contains(&leaf_a));
        assert!(leaf_hashes.contains(&leaf_b));
    }

    #[test]
    fn tap_bip32_derivation_leaf_hashes_sorted() {
        // Verify leaf hashes are sorted (BTreeSet property)
        let xonly = vec![0x02; 32];
        let leaf_big = vec![0xff; 32];
        let leaf_small = vec![0x01; 32];

        let mut inp = PsbtInput::default();
        let mut set = std::collections::BTreeSet::new();
        set.insert(leaf_big.clone());
        set.insert(leaf_small.clone());
        inp.tap_bip32_derivation.insert(
            xonly.clone(),
            (set, vec![0xDE, 0xAD, 0xBE, 0xEF], vec![0]),
        );

        let tx = make_tx();
        let psbt = Psbt {
            inputs: vec![inp],
            outputs: vec![PsbtOutput::default()],
            global: PsbtGlobal {
                version: 0,
                unsigned_tx: Some(tx),
                tx_version: None,
                fallback_locktime: None,
                input_count: None,
                output_count: None,
                tx_modifiable: None,
                xpub: Default::default(),
                proprietary: Default::default(),
                unknown: Default::default(),
            },
        };
        let bytes = psbt.serialize();
        let decoded = Psbt::deserialize(&bytes).expect("roundtrip failed");

        let (lh, _, _) = decoded.inputs[0]
            .tap_bip32_derivation
            .get(&xonly)
            .expect("missing");

        // BTreeSet iterates in sorted order; first < second
        let hashes: Vec<_> = lh.iter().collect();
        assert_eq!(hashes.len(), 2);
        assert!(hashes[0] < hashes[1], "leaf hashes should be sorted");
    }

    #[test]
    fn output_tap_bip32_derivation_deduplicates_leaf_hashes() {
        // Same dedup test for output TAP_BIP32_DERIVATION (type 0x07)
        let xonly = vec![0x02; 32];
        let leaf_a = vec![0xaa; 32];

        // Wire format: varint(2) || hash_a || hash_a || fingerprint || path
        let mut value = Vec::new();
        VarInt(2).encode(&mut value).unwrap();
        value.extend_from_slice(&leaf_a);
        value.extend_from_slice(&leaf_a); // duplicate
        value.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        value.extend_from_slice(&0u32.to_le_bytes());

        // Build PSBT with output KV — use the raw-byte injection approach
        let tx = make_tx();
        let base_psbt = Psbt {
            inputs: vec![PsbtInput::default()],
            outputs: vec![PsbtOutput::default()],
            global: PsbtGlobal {
                version: 0,
                unsigned_tx: Some(tx),
                tx_version: None,
                fallback_locktime: None,
                input_count: None,
                output_count: None,
                tx_modifiable: None,
                xpub: Default::default(),
                proprietary: Default::default(),
                unknown: Default::default(),
            },
        };
        let mut raw = base_psbt.serialize();

        // The output map is at the end: just a 0x00 separator.
        // Replace the last 0x00 (output map terminator) with our KV + 0x00.
        let last_zero = raw.len() - 1;
        assert_eq!(raw[last_zero], 0x00);
        raw.truncate(last_zero);

        // Write output key
        let mut out_key = vec![0x07];
        out_key.extend_from_slice(&xonly);
        VarInt(out_key.len() as u64).encode(&mut raw).unwrap();
        raw.extend_from_slice(&out_key);
        VarInt(value.len() as u64).encode(&mut raw).unwrap();
        raw.extend_from_slice(&value);
        raw.push(0x00); // terminate output map

        let psbt = Psbt::deserialize(&raw).expect("should parse output tap_bip32");
        let (leaf_hashes, _, _) = psbt.outputs[0]
            .tap_bip32_derivation
            .get(&xonly)
            .expect("missing output tap_bip32_derivation");

        // 2 duplicates → 1 unique
        assert_eq!(leaf_hashes.len(), 1);
        assert!(leaf_hashes.contains(&leaf_a));
    }

    // ── M4: MuSig2 pubkey format validation ─────────────────────────────────

    #[test]
    fn musig2_invalid_aggregate_pubkey_rejected() {
        // Key = 0x1a || invalid_aggregate(33 bytes with 0x04 prefix = uncompressed)
        let mut key = vec![0x1a];
        key.extend_from_slice(&[0x04; 33]); // 0x04 prefix is not valid compressed
        // Value: one valid participant
        let participant = vec![0x02; 33];
        let bytes = build_psbt_with_input_kv(&key, &participant);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::InvalidMusig2Pubkey { field: "input musig2_participant_pubkeys", .. }),
            "expected InvalidMusig2Pubkey for aggregate, got: {err}"
        );
    }

    #[test]
    fn musig2_invalid_participant_pubkey_rejected() {
        // Valid aggregate key, invalid participant
        let mut key = vec![0x1a];
        key.extend_from_slice(&[0x02; 33]); // valid aggregate
        // Value: one invalid participant (0x05 prefix)
        let participant = vec![0x05; 33];
        let bytes = build_psbt_with_input_kv(&key, &participant);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::InvalidMusig2Pubkey { field: "input musig2_participant_pubkeys", .. }),
            "expected InvalidMusig2Pubkey for participant, got: {err}"
        );
    }

    #[test]
    fn musig2_participants_not_multiple_of_33_rejected() {
        // Valid aggregate, value not a multiple of 33 bytes
        let mut key = vec![0x1a];
        key.extend_from_slice(&[0x02; 33]);
        let value = vec![0x02; 34]; // 34 bytes, not multiple of 33
        let bytes = build_psbt_with_input_kv(&key, &value);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::InvalidMusig2Pubkey { field: "input musig2_participant_pubkeys", .. }),
            "expected InvalidMusig2Pubkey for non-multiple-of-33, got: {err}"
        );
    }

    #[test]
    fn musig2_pub_nonce_invalid_participant_rejected() {
        // Key = 0x1b || invalid_participant(33) || valid_aggregate(33)
        let mut key = vec![0x1b];
        key.extend_from_slice(&[0x04; 33]); // invalid participant
        key.extend_from_slice(&[0x02; 33]); // valid aggregate
        let nonce = vec![0xbb; 66];
        let bytes = build_psbt_with_input_kv(&key, &nonce);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::InvalidMusig2Pubkey { field: "input musig2_pub_nonce", .. }),
            "expected InvalidMusig2Pubkey for pub_nonce participant, got: {err}"
        );
    }

    #[test]
    fn musig2_pub_nonce_invalid_aggregate_rejected() {
        // Key = 0x1b || valid_participant(33) || invalid_aggregate(33)
        let mut key = vec![0x1b];
        key.extend_from_slice(&[0x02; 33]); // valid participant
        key.extend_from_slice(&[0x00; 33]); // invalid aggregate (0x00 prefix)
        let nonce = vec![0xbb; 66];
        let bytes = build_psbt_with_input_kv(&key, &nonce);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::InvalidMusig2Pubkey { field: "input musig2_pub_nonce", .. }),
            "expected InvalidMusig2Pubkey for pub_nonce aggregate, got: {err}"
        );
    }

    #[test]
    fn musig2_partial_sig_invalid_pubkeys_rejected() {
        // Key = 0x1c || invalid_participant(33) || valid_aggregate(33)
        let mut key = vec![0x1c];
        key.extend_from_slice(&[0xff; 33]); // invalid participant
        key.extend_from_slice(&[0x03; 33]); // valid aggregate
        let sig = vec![0xdd; 32];
        let bytes = build_psbt_with_input_kv(&key, &sig);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::InvalidMusig2Pubkey { field: "input musig2_partial_sig", .. }),
            "expected InvalidMusig2Pubkey for partial_sig, got: {err}"
        );
    }

    #[test]
    fn musig2_valid_pubkeys_accepted() {
        // All valid compressed pubkeys should pass validation
        let mut key = vec![0x1a];
        key.extend_from_slice(&[0x03; 33]); // valid aggregate (0x03 prefix)
        let mut value = vec![0x02; 33]; // valid participant 1
        value.extend_from_slice(&[0x03; 33]); // valid participant 2
        let bytes = build_psbt_with_input_kv(&key, &value);
        let psbt = Psbt::deserialize(&bytes).expect("valid musig2 pubkeys should parse");
        let pks = psbt.inputs[0]
            .musig2_participant_pubkeys
            .get(&vec![0x03; 33])
            .expect("missing musig2 participants");
        assert_eq!(pks.len(), 2);
    }

    #[test]
    fn musig2_output_invalid_aggregate_rejected() {
        // Output MuSig2 (type 0x08) with invalid aggregate pubkey
        let tx = make_tx();
        let mut out = PsbtOutput::default();
        // Manually insert with invalid key — the validation happens on deserialize
        let invalid_agg = vec![0x04; 33]; // invalid prefix
        out.musig2_participant_pubkeys
            .insert(invalid_agg, vec![vec![0x02; 33]]);

        let psbt = Psbt {
            inputs: vec![PsbtInput::default()],
            outputs: vec![out],
            global: PsbtGlobal {
                version: 0,
                unsigned_tx: Some(tx),
                tx_version: None,
                fallback_locktime: None,
                input_count: None,
                output_count: None,
                tx_modifiable: None,
                xpub: Default::default(),
                proprietary: Default::default(),
                unknown: Default::default(),
            },
        };
        let raw = psbt.serialize();
        let err = Psbt::deserialize(&raw).unwrap_err();
        assert!(
            matches!(err, PsbtError::InvalidMusig2Pubkey { field: "output musig2_participant_pubkeys", .. }),
            "expected InvalidMusig2Pubkey for output aggregate, got: {err}"
        );
    }

    // ── M1: TAP_LEAF_SCRIPT control block size validation ─────────────────

    #[test]
    fn tap_leaf_script_valid_control_block_33() {
        // 33 bytes = 33 + 32*0 (no merkle path nodes)
        let mut key = vec![0x15];
        key.extend_from_slice(&[0xc0; 33]); // leaf_ver(1) + internal_key(32)
        let mut value = vec![0x51]; // OP_TRUE script
        value.push(0xc0); // leaf_version
        let bytes = build_psbt_with_input_kv(&key, &value);
        assert!(Psbt::deserialize(&bytes).is_ok());
    }

    #[test]
    fn tap_leaf_script_valid_control_block_65() {
        // 65 bytes = 33 + 32*1 (one merkle path node)
        let mut key = vec![0x15];
        key.extend_from_slice(&[0xc0; 65]);
        let mut value = vec![0x51];
        value.push(0xc0);
        let bytes = build_psbt_with_input_kv(&key, &value);
        assert!(Psbt::deserialize(&bytes).is_ok());
    }

    #[test]
    fn tap_leaf_script_control_block_too_short() {
        // 32 bytes < 33 minimum
        let mut key = vec![0x15];
        key.extend_from_slice(&[0xc0; 32]);
        let mut value = vec![0x51];
        value.push(0xc0);
        let bytes = build_psbt_with_input_kv(&key, &value);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::InvalidControlBlockSize { got: 32 }),
            "expected InvalidControlBlockSize(32), got: {err}"
        );
    }

    #[test]
    fn tap_leaf_script_control_block_bad_size_34() {
        // 34 bytes: (34-33)%32 = 1 != 0
        let mut key = vec![0x15];
        key.extend_from_slice(&[0xc0; 34]);
        let mut value = vec![0x51];
        value.push(0xc0);
        let bytes = build_psbt_with_input_kv(&key, &value);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::InvalidControlBlockSize { got: 34 }),
            "expected InvalidControlBlockSize(34), got: {err}"
        );
    }

    #[test]
    fn tap_leaf_script_control_block_bad_size_66() {
        // 66 bytes: (66-33)%32 = 1 != 0
        let mut key = vec![0x15];
        key.extend_from_slice(&[0xc0; 66]);
        let mut value = vec![0x51];
        value.push(0xc0);
        let bytes = build_psbt_with_input_kv(&key, &value);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::InvalidControlBlockSize { got: 66 }),
            "expected InvalidControlBlockSize(66), got: {err}"
        );
    }

    #[test]
    fn tap_leaf_script_empty_value_rejected() {
        // Valid control block but empty value
        let mut key = vec![0x15];
        key.extend_from_slice(&[0xc0; 33]);
        let bytes = build_psbt_with_input_kv(&key, &[]);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::Decode(_)),
            "expected Decode error for empty value, got: {err}"
        );
    }

    // ── H1: TAP_TREE validation ───────────────────────────────────────────

    /// Helper: build raw tap_tree bytes from (depth, leaf_ver, script) tuples
    fn build_tap_tree_bytes(leaves: &[(u8, u8, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        for &(depth, leaf_ver, script) in leaves {
            buf.push(depth);
            buf.push(leaf_ver);
            VarInt(script.len() as u64).encode(&mut buf).ok();
            buf.extend_from_slice(script);
        }
        buf
    }

    #[test]
    fn tap_tree_valid_single_leaf() {
        let tree_bytes = build_tap_tree_bytes(&[(0, 0xc0, &[0x51])]);
        let bytes = build_psbt_with_output_kv(&[0x06], &tree_bytes);
        let psbt = Psbt::deserialize(&bytes).expect("valid single-leaf tap_tree");
        let tree = psbt.outputs[0].tap_tree.as_ref().unwrap();
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].depth, 0);
        assert_eq!(tree[0].leaf_version, 0xc0);
        assert_eq!(tree[0].script, vec![0x51]);
    }

    #[test]
    fn tap_tree_valid_two_leaves() {
        // Two leaves at depth 1 form a complete binary tree
        let tree_bytes = build_tap_tree_bytes(&[
            (1, 0xc0, &[0x51]),
            (1, 0xc0, &[0x52]),
        ]);
        let bytes = build_psbt_with_output_kv(&[0x06], &tree_bytes);
        let psbt = Psbt::deserialize(&bytes).expect("valid two-leaf tap_tree");
        assert_eq!(psbt.outputs[0].tap_tree.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn tap_tree_valid_three_leaves() {
        // Three leaves: depths [1, 2, 2] form a complete tree
        let tree_bytes = build_tap_tree_bytes(&[
            (1, 0xc0, &[0x51]),
            (2, 0xc0, &[0x52]),
            (2, 0xc0, &[0x53]),
        ]);
        let bytes = build_psbt_with_output_kv(&[0x06], &tree_bytes);
        assert!(Psbt::deserialize(&bytes).is_ok());
    }

    #[test]
    fn tap_tree_depth_128_valid() {
        // Depth exactly 128 is the maximum allowed
        let tree_bytes = build_tap_tree_bytes(&[(128, 0xc0, &[0x51])]);
        // Note: a single leaf at depth 128 won't form a complete tree,
        // but let's test the depth check alone. This will fail on completeness.
        let bytes = build_psbt_with_output_kv(&[0x06], &tree_bytes);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        // Depth 128 is valid, but single leaf at depth 128 is not a complete tree
        assert!(
            matches!(err, PsbtError::TapTreeMalformed),
            "expected TapTreeMalformed, got: {err}"
        );
    }

    #[test]
    fn tap_tree_depth_129_rejected() {
        let tree_bytes = build_tap_tree_bytes(&[(129, 0xc0, &[0x51])]);
        let bytes = build_psbt_with_output_kv(&[0x06], &tree_bytes);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::TapTreeDepthExceeded { depth: 129 }),
            "expected TapTreeDepthExceeded(129), got: {err}"
        );
    }

    #[test]
    fn tap_tree_depth_255_rejected() {
        let tree_bytes = build_tap_tree_bytes(&[(255, 0xc0, &[0x51])]);
        let bytes = build_psbt_with_output_kv(&[0x06], &tree_bytes);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::TapTreeDepthExceeded { depth: 255 }),
            "expected TapTreeDepthExceeded(255), got: {err}"
        );
    }

    #[test]
    fn tap_tree_odd_leaf_version_rejected() {
        // leaf_ver 0xc1 has bit 0 set — invalid
        let tree_bytes = build_tap_tree_bytes(&[(0, 0xc1, &[0x51])]);
        let bytes = build_psbt_with_output_kv(&[0x06], &tree_bytes);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::TapTreeInvalidLeafVersion { leaf_ver: 0xc1 }),
            "expected TapTreeInvalidLeafVersion(0xc1), got: {err}"
        );
    }

    #[test]
    fn tap_tree_leaf_version_0x01_rejected() {
        let tree_bytes = build_tap_tree_bytes(&[(0, 0x01, &[0x51])]);
        let bytes = build_psbt_with_output_kv(&[0x06], &tree_bytes);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::TapTreeInvalidLeafVersion { leaf_ver: 0x01 }),
            "expected TapTreeInvalidLeafVersion(0x01), got: {err}"
        );
    }

    #[test]
    fn tap_tree_leaf_version_0x00_valid() {
        // 0x00 is even — valid leaf version
        let tree_bytes = build_tap_tree_bytes(&[(0, 0x00, &[0x51])]);
        let bytes = build_psbt_with_output_kv(&[0x06], &tree_bytes);
        assert!(Psbt::deserialize(&bytes).is_ok());
    }

    #[test]
    fn tap_tree_empty_rejected() {
        let bytes = build_psbt_with_output_kv(&[0x06], &[]);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::TapTreeEmpty),
            "expected TapTreeEmpty, got: {err}"
        );
    }

    #[test]
    fn tap_tree_malformed_incomplete_tree() {
        // Two leaves both at depth 0 — not a valid binary tree
        let tree_bytes = build_tap_tree_bytes(&[
            (0, 0xc0, &[0x51]),
            (0, 0xc0, &[0x52]),
        ]);
        let bytes = build_psbt_with_output_kv(&[0x06], &tree_bytes);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::TapTreeMalformed),
            "expected TapTreeMalformed, got: {err}"
        );
    }

    #[test]
    fn tap_tree_malformed_single_leaf_depth_1() {
        // Single leaf at depth 1 is not complete
        let tree_bytes = build_tap_tree_bytes(&[(1, 0xc0, &[0x51])]);
        let bytes = build_psbt_with_output_kv(&[0x06], &tree_bytes);
        let err = Psbt::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, PsbtError::TapTreeMalformed),
            "expected TapTreeMalformed, got: {err}"
        );
    }

    #[test]
    fn tap_tree_roundtrip() {
        // Build a valid 3-leaf tree and verify roundtrip
        let leaves = vec![
            TapTreeLeaf { depth: 1, leaf_version: 0xc0, script: vec![0x51] },
            TapTreeLeaf { depth: 2, leaf_version: 0xc0, script: vec![0x52, 0x93] },
            TapTreeLeaf { depth: 2, leaf_version: 0xc0, script: vec![0x53, 0x94, 0x87] },
        ];
        let mut out = PsbtOutput::default();
        out.tap_tree = Some(leaves.clone());

        let tx = make_tx();
        let psbt = Psbt {
            inputs: vec![PsbtInput::default()],
            outputs: vec![out],
            global: PsbtGlobal {
                version: 0,
                unsigned_tx: Some(tx),
                tx_version: None,
                fallback_locktime: None,
                input_count: None,
                output_count: None,
                tx_modifiable: None,
                xpub: Default::default(),
                proprietary: Default::default(),
                unknown: Default::default(),
            },
        };
        let raw = psbt.serialize();
        let decoded = Psbt::deserialize(&raw).expect("roundtrip should succeed");
        assert_eq!(decoded.outputs[0].tap_tree.as_ref().unwrap(), &leaves);
    }
}
