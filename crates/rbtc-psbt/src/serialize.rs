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
    types::{Psbt, PsbtGlobal, PsbtInput, PsbtOutput},
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
    Ok(TxOut { value, script_pubkey })
}

// ── Encoding ──────────────────────────────────────────────────────────────────

impl Psbt {
    /// Serialize to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(PSBT_MAGIC);

        // Global map
        let tx_bytes = encode_tx_legacy(&self.global.unsigned_tx);
        write_kv(&mut buf, &[0x00], &tx_bytes);
        if self.global.version != 0 {
            write_kv(&mut buf, &[0xfb], &self.global.version.to_le_bytes());
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

        // Helper: read a varint-prefixed byte string
        macro_rules! read_bytes {
            () => {{
                let mut cur = std::io::Cursor::new(&data[pos..]);
                let VarInt(len) = VarInt::decode(&mut cur)
                    .map_err(|e| PsbtError::Decode(e.to_string()))?;
                let hdr_len = cur.position() as usize;
                let start = pos + hdr_len;
                let end = start + len as usize;
                if end > data.len() {
                    return Err(PsbtError::Decode("truncated".into()));
                }
                pos = end;
                &data[start..end]
            }};
        }

        // Parse a complete key-value map; returns (keys, values) as byte vecs
        let mut parse_map = |pos: &mut usize| -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
            let mut entries = Vec::new();
            loop {
                let mut cur = std::io::Cursor::new(&data[*pos..]);
                let VarInt(key_len) = VarInt::decode(&mut cur)
                    .map_err(|e| PsbtError::Decode(e.to_string()))?;
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

                // value
                let mut vcur = std::io::Cursor::new(&data[*pos..]);
                let VarInt(val_len) = VarInt::decode(&mut vcur)
                    .map_err(|e| PsbtError::Decode(e.to_string()))?;
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
        let mut global_unknown = std::collections::BTreeMap::new();

        for (key, value) in global_entries {
            match key.as_slice() {
                [0x00] => {
                    let tx = Transaction::decode_from_slice(&value)
                        .map_err(|e| PsbtError::Decode(e.to_string()))?;
                    unsigned_tx = Some(tx);
                }
                [0xfb] if value.len() == 4 => {
                    version = u32::from_le_bytes(value[..4].try_into().unwrap());
                }
                _ => { global_unknown.insert(key, value); }
            }
        }

        let unsigned_tx = unsigned_tx.ok_or(PsbtError::MissingField("unsigned_tx"))?;
        let input_count = unsigned_tx.inputs.len();
        let output_count = unsigned_tx.outputs.len();

        let global = PsbtGlobal { unsigned_tx, version, unknown: global_unknown };

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
                    _ => { inp.unknown.insert(key, value); }
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
                    [0x02] => { out.redeem_script = Some(Script::from_bytes(value)); }
                    [0x03] => { out.witness_script = Some(Script::from_bytes(value)); }
                    _ => { out.unknown.insert(key, value); }
                }
            }
            outputs.push(out);
        }

        Ok(Psbt { global, inputs, outputs })
    }

    /// Deserialize from Base64 string.
    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = B64.decode(s.trim()).map_err(|e| PsbtError::Base64(e.to_string()))?;
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
    for (k, v) in &inp.unknown {
        write_kv(buf, k, v);
    }
    write_separator(buf);
}

fn encode_output(out: &PsbtOutput, buf: &mut Vec<u8>) {
    if let Some(ref s) = out.redeem_script {
        write_kv(buf, &[0x02], s.as_bytes());
    }
    if let Some(ref s) = out.witness_script {
        write_kv(buf, &[0x03], s.as_bytes());
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
    };

    fn make_tx() -> Transaction {
        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256([1; 32]), vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 50_000,
                script_pubkey: Script::from_bytes(vec![0x51]),
            }],
            lock_time: 0,
        }
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
                unsigned_tx: tx,
            },
        };
        let bytes = psbt.serialize();
        let decoded = Psbt::deserialize(&bytes).expect("decode failed");
        assert_eq!(
            decoded.global.unsigned_tx.inputs.len(),
            psbt.global.unsigned_tx.inputs.len()
        );
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
                unsigned_tx: tx,
            },
        };
        let b64 = psbt.to_base64();
        let decoded = Psbt::from_base64(&b64).expect("base64 decode failed");
        assert_eq!(
            decoded.global.unsigned_tx.outputs[0].value,
            50_000
        );
    }
}
