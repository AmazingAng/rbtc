use crate::{
    codec::{decode_list, encode_list, CodecError, Decodable, Encodable, Result, VarInt},
    hash::{Hash256, Txid, Wtxid},
    script::Script,
};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// CAmount (matches Bitcoin Core: typedef int64_t CAmount)
// ---------------------------------------------------------------------------

/// Monetary value in satoshis. Signed to match Bitcoin Core (`int64_t`).
/// `CTxOut::SetNull()` uses -1 as sentinel.
pub type CAmount = i64;

/// Satoshis per bitcoin
pub const COIN: CAmount = 100_000_000;

/// Maximum total supply (consensus-critical)
pub const MAX_MONEY: CAmount = 21_000_000 * COIN;

/// Returns true if `value` is within the valid monetary range `[0, MAX_MONEY]`.
pub fn money_range(value: CAmount) -> bool {
    value >= 0 && value <= MAX_MONEY
}

// ---------------------------------------------------------------------------
// Serialization params (matches Bitcoin Core's TransactionSerParams)
// ---------------------------------------------------------------------------

/// Controls whether witness data is (de)serialized.
#[derive(Clone, Copy, Debug)]
pub struct TxSerParams {
    pub allow_witness: bool,
}

pub const TX_WITH_WITNESS: TxSerParams = TxSerParams {
    allow_witness: true,
};
pub const TX_NO_WITNESS: TxSerParams = TxSerParams {
    allow_witness: false,
};

// ---------------------------------------------------------------------------
// OutPoint
// ---------------------------------------------------------------------------

/// Reference to a previous transaction output
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutPoint {
    pub txid: Txid,
    pub vout: u32,
}

/// Matches Bitcoin Core: `static constexpr uint32_t NULL_INDEX`
pub const OUTPOINT_NULL_INDEX: u32 = u32::MAX;

impl OutPoint {
    pub fn new(txid: Txid, vout: u32) -> Self {
        Self { txid, vout }
    }

    pub fn null() -> Self {
        Self {
            txid: Txid::ZERO,
            vout: OUTPOINT_NULL_INDEX,
        }
    }

    pub fn is_null(&self) -> bool {
        self.txid == Txid::ZERO && self.vout == OUTPOINT_NULL_INDEX
    }
}

impl Encodable for OutPoint {
    fn encode<W: Write>(&self, w: &mut W) -> Result<usize> {
        let mut n = self.txid.0 .0.encode(w)?;
        n += self.vout.encode(w)?;
        Ok(n)
    }
}

impl Decodable for OutPoint {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let txid = Txid(Hash256(<[u8; 32]>::decode(r)?));
        let vout = u32::decode(r)?;
        Ok(Self { txid, vout })
    }
}

// ---------------------------------------------------------------------------
// TxIn
// ---------------------------------------------------------------------------

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
    // Sequence number constants (matches Bitcoin Core CTxIn)
    pub const SEQUENCE_FINAL: u32 = 0xffffffff;
    pub const MAX_SEQUENCE_NONFINAL: u32 = Self::SEQUENCE_FINAL - 1;
    pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
    pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
    pub const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000ffff;
    pub const SEQUENCE_LOCKTIME_GRANULARITY: u32 = 9;

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

// ---------------------------------------------------------------------------
// TxOut
// ---------------------------------------------------------------------------

/// Transaction output
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    /// Value in satoshis (signed, matching Bitcoin Core's CAmount / int64_t).
    /// -1 represents a null/empty output.
    pub value: CAmount,
    pub script_pubkey: Script,
}

impl TxOut {
    pub fn set_null(&mut self) {
        self.value = -1;
        self.script_pubkey = Script::new();
    }

    pub fn is_null(&self) -> bool {
        self.value == -1
    }
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
        let value = i64::decode(r)?;
        let script_pubkey = Script::decode(r)?;
        Ok(Self {
            value,
            script_pubkey,
        })
    }
}

// ---------------------------------------------------------------------------
// Witness encode/decode helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Transaction (immutable, with cached hashes – matches Bitcoin Core CTransaction)
// ---------------------------------------------------------------------------

/// The basic transaction that is broadcast on the network and contained in
/// blocks.  Fields are conceptually immutable once constructed; the cached
/// `hash` / `witness_hash` are computed at construction time.
///
/// Matches Bitcoin Core's `CTransaction`.
///
/// **Note on `version` type:** Bitcoin Core recently changed `CTransaction::nVersion`
/// from `int32_t` to `uint32_t`. We keep `i32` here because the wire format is
/// identical (4 LE bytes) and negative versions (e.g. version 2 via BIP68/BIP112)
/// are never used in practice. The cast `version as u32` is safe for any
/// serialized value.
#[derive(Debug, Clone)]
pub struct Transaction {
    pub version: i32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,

    // Memory-only cached fields (matches Bitcoin Core: const Txid hash, etc.)
    m_has_witness: bool,
    hash: Txid,
    witness_hash: Wtxid,
}

/// Shared, reference-counted transaction pointer (matches `CTransactionRef`).
pub type TransactionRef = Arc<Transaction>;

/// Helper to create a `TransactionRef`.
pub fn make_transaction_ref(tx: Transaction) -> TransactionRef {
    Arc::new(tx)
}

/// SHA-256d (double SHA-256) used for txid / block hash computation.
/// Placed here so rbtc-primitives can compute hashes without depending on
/// rbtc-crypto.
pub(crate) fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    second.into()
}

/// Compute the txid (hash of non-witness serialization).
fn compute_txid(
    version: i32,
    inputs: &[TxIn],
    outputs: &[TxOut],
    lock_time: u32,
) -> Txid {
    let mut buf = Vec::new();
    serialize_tx_fields(version, inputs, outputs, lock_time, false, &mut buf)
        .expect("vec write never fails");
    Txid(Hash256(sha256d(&buf)))
}

/// Compute the wtxid (hash of full witness serialization).
fn compute_wtxid(
    version: i32,
    inputs: &[TxIn],
    outputs: &[TxOut],
    lock_time: u32,
    has_witness: bool,
) -> Wtxid {
    if !has_witness {
        // When there is no witness, wtxid == txid
        let txid = compute_txid(version, inputs, outputs, lock_time);
        return Wtxid(txid.0);
    }
    let mut buf = Vec::new();
    serialize_tx_fields(version, inputs, outputs, lock_time, true, &mut buf)
        .expect("vec write never fails");
    Wtxid(Hash256(sha256d(&buf)))
}

/// Core serialization logic, shared by encode methods and hash computation.
fn serialize_tx_fields<W: Write>(
    version: i32,
    inputs: &[TxIn],
    outputs: &[TxOut],
    lock_time: u32,
    with_witness: bool,
    w: &mut W,
) -> Result<usize> {
    let mut n = version.encode(w)?;
    if with_witness {
        // SegWit marker + flag
        n += (0u8).encode(w)?;
        n += (1u8).encode(w)?;
    }
    n += encode_list(inputs, w)?;
    n += encode_list(outputs, w)?;
    if with_witness {
        for input in inputs {
            n += encode_witness(&input.witness, w)?;
        }
    }
    n += lock_time.encode(w)?;
    Ok(n)
}

impl Transaction {
    /// Default transaction version (matches Bitcoin Core `CTransaction::CURRENT_VERSION`).
    pub const CURRENT_VERSION: i32 = 2;

    /// Construct from a `MutableTransaction`, computing and caching hashes.
    pub fn from_mutable(mtx: MutableTransaction) -> Self {
        let has_witness = mtx.inputs.iter().any(|i| !i.witness.is_empty());
        let hash = compute_txid(mtx.version, &mtx.inputs, &mtx.outputs, mtx.lock_time);
        let witness_hash = compute_wtxid(
            mtx.version, &mtx.inputs, &mtx.outputs, mtx.lock_time, has_witness,
        );
        Self {
            version: mtx.version,
            inputs: mtx.inputs,
            outputs: mtx.outputs,
            lock_time: mtx.lock_time,
            m_has_witness: has_witness,
            hash,
            witness_hash,
        }
    }

    /// Construct directly from parts, computing hashes.
    pub fn from_parts(
        version: i32,
        inputs: Vec<TxIn>,
        outputs: Vec<TxOut>,
        lock_time: u32,
    ) -> Self {
        let has_witness = inputs.iter().any(|i| !i.witness.is_empty());
        let hash = compute_txid(version, &inputs, &outputs, lock_time);
        let witness_hash = compute_wtxid(version, &inputs, &outputs, lock_time, has_witness);
        Self {
            version,
            inputs,
            outputs,
            lock_time,
            m_has_witness: has_witness,
            hash,
            witness_hash,
        }
    }

    /// Construct with pre-computed hashes (when the caller already knows them).
    pub fn from_parts_with_hash(
        version: i32,
        inputs: Vec<TxIn>,
        outputs: Vec<TxOut>,
        lock_time: u32,
        hash: Txid,
        witness_hash: Wtxid,
    ) -> Self {
        let has_witness = inputs.iter().any(|i| !i.witness.is_empty());
        Self {
            version,
            inputs,
            outputs,
            lock_time,
            m_has_witness: has_witness,
            hash,
            witness_hash,
        }
    }

    // --- Cached accessors (zero-cost, matches Bitcoin Core) ---

    pub fn txid(&self) -> &Txid {
        &self.hash
    }

    pub fn wtxid(&self) -> &Wtxid {
        &self.witness_hash
    }

    // --- Query methods ---

    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].is_coinbase()
    }

    pub fn has_witness(&self) -> bool {
        self.m_has_witness
    }

    pub fn is_null(&self) -> bool {
        self.inputs.is_empty() && self.outputs.is_empty()
    }

    /// Total output value with overflow and range checking
    /// (matches Bitcoin Core `CTransaction::GetValueOut`).
    pub fn get_value_out(&self) -> std::result::Result<CAmount, &'static str> {
        let mut total: CAmount = 0;
        for output in &self.outputs {
            if !money_range(output.value) {
                return Err("value out of range");
            }
            total = total
                .checked_add(output.value)
                .filter(|&v| money_range(v))
                .ok_or("value out of range")?;
        }
        Ok(total)
    }

    /// Simple unchecked output sum (for non-consensus contexts).
    pub fn output_value(&self) -> CAmount {
        self.outputs.iter().map(|o| o.value).sum()
    }

    // --- Serialization with params (matches Bitcoin Core) ---

    /// Serialize with explicit params controlling witness inclusion.
    pub fn serialize_with_params<W: Write>(
        &self, w: &mut W, params: TxSerParams,
    ) -> Result<usize> {
        let with_witness = params.allow_witness && self.m_has_witness;
        serialize_tx_fields(
            self.version, &self.inputs, &self.outputs, self.lock_time, with_witness, w,
        )
    }

    /// Encode without witness data (for txid computation).
    pub fn encode_legacy<W: Write>(&self, w: &mut W) -> Result<usize> {
        self.serialize_with_params(w, TX_NO_WITNESS)
    }

    /// Encode with witness data (for wtxid computation / network).
    pub fn encode_segwit<W: Write>(&self, w: &mut W) -> Result<usize> {
        self.serialize_with_params(w, TX_WITH_WITNESS)
    }

    /// Serialise for network (with segwit if applicable).
    pub fn encode_net<W: Write>(&self, w: &mut W) -> Result<usize> {
        self.serialize_with_params(w, TX_WITH_WITNESS)
    }

    /// Compute transaction weight (BIP 141).
    pub fn weight(&self) -> u64 {
        let base_size = self.encode_legacy_size();
        let total_size = self.encode_total_size();
        (base_size as u64) * 4 + (total_size - base_size) as u64
    }

    /// Compute the non-witness (base) serialized size.
    /// This is the size of the transaction without witness data.
    pub fn encode_legacy_size(&self) -> usize {
        self.encode_legacy(&mut std::io::sink()).unwrap_or(0)
    }

    fn encode_total_size(&self) -> usize {
        if self.m_has_witness {
            self.encode_segwit(&mut std::io::sink()).unwrap_or(0)
        } else {
            self.encode_legacy_size()
        }
    }

    /// Compute total serialized size (with witness). Matches `CTransaction::ComputeTotalSize`.
    pub fn compute_total_size(&self) -> usize {
        self.encode_total_size()
    }

    pub fn vsize(&self) -> u64 {
        self.weight().div_ceil(4)
    }
}

impl PartialEq for Transaction {
    /// Transactions are equal iff their wtxids match (Bitcoin Core behaviour).
    fn eq(&self, other: &Self) -> bool {
        self.witness_hash == other.witness_hash
    }
}
impl Eq for Transaction {}

impl std::hash::Hash for Transaction {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.witness_hash.hash(state);
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

        let mut tx_inputs = inputs;

        if has_witness {
            for input in &mut tx_inputs {
                input.witness = decode_witness(r)?;
            }
            // Bitcoin Core: "It's illegal to encode witnesses when all witness stacks are empty."
            if !tx_inputs.iter().any(|i| !i.witness.is_empty()) {
                return Err(CodecError::InvalidData(
                    "Superfluous witness record".into(),
                ));
            }
        }

        let lock_time = u32::decode(r)?;
        Ok(Transaction::from_parts(version, tx_inputs, outputs, lock_time))
    }
}

// ---------------------------------------------------------------------------
// MutableTransaction (matches Bitcoin Core CMutableTransaction)
// ---------------------------------------------------------------------------

/// A mutable version of Transaction.  Modify fields freely, then convert
/// to an immutable `Transaction` via `Transaction::from_mutable()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutableTransaction {
    pub version: i32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
}

impl MutableTransaction {
    pub fn new() -> Self {
        Self {
            version: Transaction::CURRENT_VERSION,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
        }
    }

    pub fn from_transaction(tx: &Transaction) -> Self {
        Self {
            version: tx.version,
            inputs: tx.inputs.clone(),
            outputs: tx.outputs.clone(),
            lock_time: tx.lock_time,
        }
    }

    pub fn has_witness(&self) -> bool {
        self.inputs.iter().any(|i| !i.witness.is_empty())
    }

    /// Compute the txid on the fly (not cached).
    pub fn compute_txid(&self) -> Txid {
        compute_txid(self.version, &self.inputs, &self.outputs, self.lock_time)
    }

    /// Encode without witness data.
    pub fn encode_legacy<W: Write>(&self, w: &mut W) -> Result<usize> {
        serialize_tx_fields(self.version, &self.inputs, &self.outputs, self.lock_time, false, w)
    }
}

impl Default for MutableTransaction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

impl std::fmt::Display for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Transaction(txid={}, inputs={}, outputs={}, weight={})",
            self.txid(),
            self.inputs.len(),
            self.outputs.len(),
            self.weight(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{Decodable, Encodable};
    use std::io::Cursor;

    fn coinbase_tx() -> Transaction {
        Transaction::from_mutable(MutableTransaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![0x02, 0x00, 0x00]),
                sequence: TxIn::SEQUENCE_FINAL,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 50_0000_0000,
                script_pubkey: Script::new(),
            }],
            lock_time: 0,
        })
    }

    #[test]
    fn outpoint_null_is_null() {
        let o = OutPoint::null();
        assert!(o.is_null());
        assert_eq!(o.txid, Txid::ZERO);
        assert_eq!(o.vout, OUTPOINT_NULL_INDEX);
    }

    #[test]
    fn outpoint_encode_decode() {
        let o = OutPoint {
            txid: Txid(Hash256([1; 32])),
            vout: 5,
        };
        let buf = o.encode_to_vec();
        let d = OutPoint::decode_from_slice(&buf).unwrap();
        assert_eq!(d.txid.0 .0, o.txid.0 .0);
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
                txid: Txid(Hash256([1; 32])),
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
    fn txout_null() {
        let mut out = TxOut {
            value: 1000,
            script_pubkey: Script::new(),
        };
        assert!(!out.is_null());
        out.set_null();
        assert!(out.is_null());
        assert_eq!(out.value, -1);
    }

    #[test]
    fn transaction_is_coinbase_has_witness_output_value() {
        let tx = coinbase_tx();
        assert!(tx.is_coinbase());
        assert!(!tx.has_witness());
        assert_eq!(tx.output_value(), 50_0000_0000);

        let mut mtx = MutableTransaction::from_transaction(&tx);
        mtx.inputs[0].witness.push(vec![0]);
        let tx2 = Transaction::from_mutable(mtx);
        assert!(tx2.has_witness());
    }

    #[test]
    fn transaction_cached_txid_is_stable() {
        let tx = coinbase_tx();
        let txid1 = *tx.txid();
        let txid2 = *tx.txid();
        assert_eq!(txid1, txid2);
        assert!(!txid1.is_null()); // real hash, not zero
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
        let mut mtx = MutableTransaction::from_transaction(&coinbase_tx());
        mtx.inputs[0].witness = vec![vec![1, 2, 3]];
        let tx = Transaction::from_mutable(mtx);
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

    #[test]
    fn transaction_decode_superfluous_witness() {
        // Build a segwit-encoded tx with all-empty witness stacks
        let mut buf = Vec::new();
        1i32.encode(&mut buf).unwrap(); // version
        0u8.encode(&mut buf).unwrap(); // marker
        1u8.encode(&mut buf).unwrap(); // flag
        // 1 input
        VarInt(1).encode(&mut buf).unwrap();
        OutPoint::null().encode(&mut buf).unwrap();
        Script::new().encode(&mut buf).unwrap();
        TxIn::SEQUENCE_FINAL.encode(&mut buf).unwrap();
        // 1 output
        VarInt(1).encode(&mut buf).unwrap();
        0i64.encode(&mut buf).unwrap();
        Script::new().encode(&mut buf).unwrap();
        // empty witness for input 0
        VarInt(0).encode(&mut buf).unwrap();
        // lock_time
        0u32.encode(&mut buf).unwrap();

        let r = Transaction::decode_from_slice(&buf);
        assert!(r.is_err());
        assert!(
            r.unwrap_err().to_string().contains("Superfluous witness"),
            "should reject superfluous witness"
        );
    }

    #[test]
    fn get_value_out_overflow() {
        let tx = Transaction::from_mutable(MutableTransaction {
            version: 1,
            inputs: vec![],
            outputs: vec![
                TxOut {
                    value: MAX_MONEY,
                    script_pubkey: Script::new(),
                },
                TxOut {
                    value: 1,
                    script_pubkey: Script::new(),
                },
            ],
            lock_time: 0,
        });
        assert!(tx.get_value_out().is_err());
    }

    #[test]
    fn get_value_out_negative() {
        let tx = Transaction::from_mutable(MutableTransaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut {
                value: -1,
                script_pubkey: Script::new(),
            }],
            lock_time: 0,
        });
        assert!(tx.get_value_out().is_err());
    }

    #[test]
    fn money_range_checks() {
        assert!(money_range(0));
        assert!(money_range(MAX_MONEY));
        assert!(!money_range(MAX_MONEY + 1));
        assert!(!money_range(-1));
    }

    #[test]
    fn mutable_transaction_compute_txid() {
        let mtx = MutableTransaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![0x02, 0x00, 0x00]),
                sequence: TxIn::SEQUENCE_FINAL,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 50_0000_0000,
                script_pubkey: Script::new(),
            }],
            lock_time: 0,
        };
        let txid = mtx.compute_txid();
        let tx = Transaction::from_mutable(mtx);
        assert_eq!(txid, *tx.txid());
    }

    #[test]
    fn transaction_equality_by_wtxid() {
        let tx1 = coinbase_tx();
        let tx2 = coinbase_tx();
        assert_eq!(tx1, tx2);
    }

    #[test]
    fn ser_params() {
        let tx = coinbase_tx();
        let mut legacy = Vec::new();
        tx.serialize_with_params(&mut legacy, TX_NO_WITNESS).unwrap();
        let mut full = Vec::new();
        tx.serialize_with_params(&mut full, TX_WITH_WITNESS).unwrap();
        // No witness in coinbase_tx, so both should be the same
        assert_eq!(legacy, full);
    }
}
