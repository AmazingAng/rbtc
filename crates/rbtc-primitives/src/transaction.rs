use crate::{
    codec::{decode_list, encode_list, CodecError, Decodable, Encodable, Result, VarInt},
    hash::{Hash256, TxId},
    script::Script,
};
use std::io::{Read, Write};

/// Reference to a previous transaction output
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OutPoint {
    pub txid: TxId,
    pub vout: u32,
}

impl OutPoint {
    pub fn null() -> Self {
        Self {
            txid: Hash256::ZERO,
            vout: 0xffffffff,
        }
    }

    pub fn is_null(&self) -> bool {
        self.txid == Hash256::ZERO && self.vout == 0xffffffff
    }
}

impl Encodable for OutPoint {
    fn encode<W: Write>(&self, w: &mut W) -> Result<usize> {
        let mut n = self.txid.0.encode(w)?;
        n += self.vout.encode(w)?;
        Ok(n)
    }
}

impl Decodable for OutPoint {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let txid = Hash256(<[u8; 32]>::decode(r)?);
        let vout = u32::decode(r)?;
        Ok(Self { txid, vout })
    }
}

/// Transaction input
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    pub previous_output: OutPoint,
    pub script_sig: Script,
    pub sequence: u32,
    /// Segregated witness data for this input
    pub witness: Vec<Vec<u8>>,
}

impl TxIn {
    pub fn is_coinbase(&self) -> bool {
        self.previous_output.is_null()
    }
}

impl Encodable for TxIn {
    fn encode<W: Write>(&self, w: &mut W) -> Result<usize> {
        let mut n = self.previous_output.encode(w)?;
        n += self.script_sig.encode(w)?;
        n += self.sequence.encode(w)?;
        Ok(n)
    }
}

impl Decodable for TxIn {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let previous_output = OutPoint::decode(r)?;
        let script_sig = Script::decode(r)?;
        let sequence = u32::decode(r)?;
        Ok(Self {
            previous_output,
            script_sig,
            sequence,
            witness: Vec::new(),
        })
    }
}

/// Transaction output
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    /// Value in satoshis
    pub value: u64,
    pub script_pubkey: Script,
}

impl Encodable for TxOut {
    fn encode<W: Write>(&self, w: &mut W) -> Result<usize> {
        let mut n = self.value.encode(w)?;
        n += self.script_pubkey.encode(w)?;
        Ok(n)
    }
}

impl Decodable for TxOut {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let value = u64::decode(r)?;
        let script_pubkey = Script::decode(r)?;
        Ok(Self {
            value,
            script_pubkey,
        })
    }
}

/// Witness stack for a single input
fn encode_witness<W: Write>(witness: &[Vec<u8>], w: &mut W) -> Result<usize> {
    let mut n = VarInt(witness.len() as u64).encode(w)?;
    for item in witness {
        n += item.encode(w)?;
    }
    Ok(n)
}

fn decode_witness<R: Read>(r: &mut R) -> Result<Vec<Vec<u8>>> {
    let VarInt(len) = VarInt::decode(r)?;
    let mut items = Vec::with_capacity(len as usize);
    for _ in 0..len {
        items.push(Vec::<u8>::decode(r)?);
    }
    Ok(items)
}

/// Bitcoin transaction (supports Legacy and SegWit)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub version: i32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
}

impl Transaction {
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].is_coinbase()
    }

    pub fn has_witness(&self) -> bool {
        self.inputs.iter().any(|i| !i.witness.is_empty())
    }

    /// Total output value in satoshis
    pub fn output_value(&self) -> u64 {
        self.outputs.iter().map(|o| o.value).sum()
    }

    /// Encode without witness data (for txid computation)
    pub fn encode_legacy<W: Write>(&self, w: &mut W) -> Result<usize> {
        let mut n = self.version.encode(w)?;
        n += encode_list(&self.inputs, w)?;
        n += encode_list(&self.outputs, w)?;
        n += self.lock_time.encode(w)?;
        Ok(n)
    }

    /// Encode with witness data (wtxid computation / network serialization)
    pub fn encode_segwit<W: Write>(&self, w: &mut W) -> Result<usize> {
        let mut n = self.version.encode(w)?;
        // SegWit marker + flag
        n += (0u8).encode(w)?;
        n += (1u8).encode(w)?;
        n += encode_list(&self.inputs, w)?;
        n += encode_list(&self.outputs, w)?;
        for input in &self.inputs {
            n += encode_witness(&input.witness, w)?;
        }
        n += self.lock_time.encode(w)?;
        Ok(n)
    }

    /// Serialise for network (with segwit if applicable)
    pub fn encode_net<W: Write>(&self, w: &mut W) -> Result<usize> {
        if self.has_witness() {
            self.encode_segwit(w)
        } else {
            self.encode_legacy(w)
        }
    }

    /// Compute transaction weight
    pub fn weight(&self) -> u64 {
        let base_size = self.encode_legacy_size();
        let total_size = self.encode_total_size();
        // weight = base * 4 + witness_only_data * 1
        // Since total = base + witness_extra, witness_extra = total - base
        (base_size as u64) * 4 + (total_size - base_size) as u64
    }

    fn encode_legacy_size(&self) -> usize {
        self.encode_legacy(&mut std::io::sink()).unwrap_or(0)
    }

    fn encode_total_size(&self) -> usize {
        if self.has_witness() {
            self.encode_segwit(&mut std::io::sink()).unwrap_or(0)
        } else {
            self.encode_legacy_size()
        }
    }

    pub fn vsize(&self) -> u64 {
        self.weight().div_ceil(4)
    }
}

impl Encodable for Transaction {
    fn encode<W: Write>(&self, w: &mut W) -> Result<usize> {
        self.encode_net(w)
    }
}

impl Decodable for Transaction {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let version = i32::decode(r)?;

        // Peek at the next byte to detect segwit marker
        let first_byte = u8::decode(r)?;
        let (inputs, outputs, has_witness) = if first_byte == 0x00 {
            // SegWit: marker=0x00, flag must be 0x01
            let flag = u8::decode(r)?;
            if flag != 0x01 {
                return Err(CodecError::InvalidData(format!(
                    "invalid segwit flag: {flag}"
                )));
            }
            let inputs = decode_list::<TxIn, _>(r)?;
            let outputs = decode_list::<TxOut, _>(r)?;
            (inputs, outputs, true)
        } else {
            // Legacy: first_byte is actually the first byte of the input count varint
            let input_count = read_varint_with_first_byte(r, first_byte)?;
            let mut inputs = Vec::with_capacity(input_count as usize);
            for _ in 0..input_count {
                inputs.push(TxIn::decode(r)?);
            }
            let outputs = decode_list::<TxOut, _>(r)?;
            (inputs, outputs, false)
        };

        let mut tx = Transaction {
            version,
            inputs,
            outputs,
            lock_time: 0,
        };

        if has_witness {
            for input in &mut tx.inputs {
                input.witness = decode_witness(r)?;
            }
        }

        tx.lock_time = u32::decode(r)?;
        Ok(tx)
    }
}

/// Read a varint when we've already consumed the first byte
fn read_varint_with_first_byte<R: Read>(r: &mut R, first: u8) -> Result<u64> {
    match first {
        0xff => {
            let n = u64::decode(r)?;
            Ok(n)
        }
        0xfe => Ok(u32::decode(r)? as u64),
        0xfd => Ok(u16::decode(r)? as u64),
        n => Ok(n as u64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{Decodable, Encodable};
    use std::io::Cursor;

    fn coinbase_tx() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![0x02, 0x00, 0x00]),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 50_0000_0000,
                script_pubkey: Script::new(),
            }],
            lock_time: 0,
        }
    }

    #[test]
    fn outpoint_null_is_null() {
        let o = OutPoint::null();
        assert!(o.is_null());
        assert_eq!(o.txid, Hash256::ZERO);
        assert_eq!(o.vout, 0xffffffff);
    }

    #[test]
    fn outpoint_encode_decode() {
        let o = OutPoint {
            txid: Hash256([1; 32]),
            vout: 5,
        };
        let buf = o.encode_to_vec();
        let d = OutPoint::decode_from_slice(&buf).unwrap();
        assert_eq!(d.txid.0, o.txid.0);
        assert_eq!(d.vout, o.vout);
    }

    #[test]
    fn txin_is_coinbase() {
        let i = TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![],
        };
        assert!(i.is_coinbase());
        let i2 = TxIn {
            previous_output: OutPoint {
                txid: Hash256([1; 32]),
                vout: 0,
            },
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![],
        };
        assert!(!i2.is_coinbase());
    }

    #[test]
    fn txin_txout_encode_decode() {
        let txin = TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes(vec![0x01, 0x00]),
            sequence: 0xfffffffe,
            witness: vec![],
        };
        let buf = txin.encode_to_vec();
        let d = TxIn::decode_from_slice(&buf).unwrap();
        assert_eq!(d.sequence, txin.sequence);
        assert!(d.witness.is_empty());

        let txout = TxOut {
            value: 1000,
            script_pubkey: Script::new(),
        };
        let buf = txout.encode_to_vec();
        let d = TxOut::decode_from_slice(&buf).unwrap();
        assert_eq!(d.value, 1000);
    }

    #[test]
    fn transaction_is_coinbase_has_witness_output_value() {
        let tx = coinbase_tx();
        assert!(tx.is_coinbase());
        assert!(!tx.has_witness());
        assert_eq!(tx.output_value(), 50_0000_0000);

        let mut tx2 = tx.clone();
        tx2.inputs[0].witness.push(vec![0]);
        assert!(tx2.has_witness());
    }

    #[test]
    fn transaction_encode_legacy_roundtrip() {
        let tx = coinbase_tx();
        let mut buf = Vec::new();
        tx.encode_legacy(&mut buf).unwrap();
        assert!(!buf.is_empty());
        let decoded = Transaction::decode_from_slice(&tx.encode_to_vec()).unwrap();
        assert_eq!(decoded.version, tx.version);
    }

    #[test]
    fn transaction_weight_vsize() {
        let tx = coinbase_tx();
        let w = tx.weight();
        assert!(w > 0);
        let vsize = tx.vsize();
        assert!(vsize >= w / 4);
    }

    #[test]
    fn transaction_encode_decode_legacy() {
        let tx = coinbase_tx();
        let buf = tx.encode_to_vec();
        let decoded = Transaction::decode_from_slice(&buf).unwrap();
        assert_eq!(decoded.version, tx.version);
        assert_eq!(decoded.inputs.len(), 1);
        assert_eq!(decoded.outputs.len(), 1);
        assert_eq!(decoded.lock_time, 0);
    }

    #[test]
    fn transaction_encode_segwit_has_witness() {
        let mut tx = coinbase_tx();
        tx.inputs[0].witness = vec![vec![1, 2, 3]];
        let mut buf = Vec::new();
        tx.encode_segwit(&mut buf).unwrap();
        assert!(!buf.is_empty());
        let decoded = Transaction::decode_from_slice(&buf).unwrap();
        assert!(!decoded.inputs[0].witness.is_empty());
        assert_eq!(decoded.inputs[0].witness[0], vec![1, 2, 3]);
    }

    #[test]
    fn transaction_decode_invalid_segwit_flag() {
        let buf = [1i32.to_le_bytes().as_slice(), &[0x00, 0x02]].concat();
        let mut c = Cursor::new(buf);
        let r = Transaction::decode(&mut c);
        assert!(r.is_err());
    }
}
