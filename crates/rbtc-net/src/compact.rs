//! BIP152 Compact Block relay.
//!
//! Compact Blocks allow a node that already has most mempool transactions to
//! reconstruct a newly-announced block from a compact representation:
//!
//!   1. Peer sends `cmpctblock` (our `CompactBlock`) containing a 6-byte
//!      short TxID for every transaction.
//!   2. We match short IDs against our mempool.  Any missing transactions are
//!      requested via `getblocktxn` (`GetBlockTxn`).
//!   3. The peer responds with `blocktxn` (`BlockTxn`) containing the raw
//!      transactions.
//!   4. We reassemble the full block and call `handle_block`.
//!
//! Short TxID (BIP152 §3.3):
//!   key  = SHA256(header_bytes || nonce_le64)  →  k0 = first 8 LE bytes,
//!                                                   k1 = next  8 LE bytes
//!   id   = SipHash-2-4(k0, k1, txid_le)  &  0x0000_ffff_ffff_ffff  (48 bits)

use siphasher::sip::SipHasher24;
use std::hash::Hasher;

use rbtc_crypto::sha256d;
use rbtc_primitives::{
    block::BlockHeader,
    codec::{Decodable, Encodable, VarInt},
    hash::Hash256,
    transaction::Transaction,
};

use crate::error::{NetError, Result};

// ── Data Structures ───────────────────────────────────────────────────────────

/// A prefilled transaction entry inside `CompactBlock`.
#[derive(Debug, Clone)]
pub struct PrefilledTransaction {
    /// Differential index (relative to the previous prefilled tx).
    pub index: u16,
    pub tx: Transaction,
}

/// `cmpctblock` message payload (BIP152).
#[derive(Debug, Clone)]
pub struct CompactBlock {
    pub header: BlockHeader,
    /// SipHash key material: 64-bit nonce chosen by the sender.
    pub nonce: u64,
    /// 6-byte short TxIDs for every non-prefilled transaction.
    pub short_ids: Vec<u64>,
    /// Always includes the coinbase; may include others.
    pub prefilled_txns: Vec<PrefilledTransaction>,
}

/// `getblocktxn` message payload (BIP152).
#[derive(Debug, Clone)]
pub struct GetBlockTxn {
    pub block_hash: Hash256,
    /// Sorted list of 0-based transaction indexes that are missing.
    pub indexes: Vec<u32>,
}

/// `blocktxn` message payload (BIP152).
#[derive(Debug, Clone)]
pub struct BlockTxn {
    pub block_hash: Hash256,
    pub txns: Vec<Transaction>,
}

// ── Short TxID ────────────────────────────────────────────────────────────────

/// Derive the SipHash-2-4 key pair from the block header and compact-block nonce.
///
/// key_material = SHA256d(80-byte-header || nonce_le64)
/// k0 = first  8 bytes interpreted as LE u64
/// k1 = second 8 bytes interpreted as LE u64
fn siphash_keys(header: &BlockHeader, nonce: u64) -> (u64, u64) {
    let mut preimage = Vec::with_capacity(88);
    // Encode the 80-byte block header
    header.version.encode(&mut preimage).ok();
    header.prev_block.0.0.encode(&mut preimage).ok();
    header.merkle_root.0.encode(&mut preimage).ok();
    header.time.encode(&mut preimage).ok();
    header.bits.encode(&mut preimage).ok();
    header.nonce.encode(&mut preimage).ok();
    preimage.extend_from_slice(&nonce.to_le_bytes());

    let hash = sha256d(&preimage);
    let k0 = u64::from_le_bytes(hash.0[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(hash.0[8..16].try_into().unwrap());
    (k0, k1)
}

/// Calculate the 6-byte (48-bit) short TxID for `txid` as defined in BIP152.
pub fn short_txid(header: &BlockHeader, nonce: u64, txid: &Hash256) -> u64 {
    let (k0, k1) = siphash_keys(header, nonce);
    let mut h = SipHasher24::new_with_keys(k0, k1);
    h.write(&txid.0);
    h.finish() & 0x0000_ffff_ffff_ffff
}

// ── Construction ─────────────────────────────────────────────────────────────

impl CompactBlock {
    /// Construct a compact block from a full block.
    /// Coinbase is always prefilled (index 0). Remaining transactions get short TxIDs.
    /// `nonce` is the SipHash key material nonce (caller should use a random value).
    pub fn from_block(block: &rbtc_primitives::block::Block, nonce: u64) -> Self {
        let header = block.header.clone();
        let mut short_ids = Vec::new();
        let mut prefilled_txns = Vec::new();

        for (i, tx) in block.transactions.iter().enumerate() {
            if i == 0 {
                // Coinbase is always prefilled at index 0
                prefilled_txns.push(PrefilledTransaction {
                    index: 0,
                    tx: tx.clone(),
                });
            } else {
                let txid_hash = tx.txid().0;
                let sid = short_txid(&header, nonce, &txid_hash);
                short_ids.push(sid);
            }
        }

        CompactBlock {
            header,
            nonce,
            short_ids,
            prefilled_txns,
        }
    }
}

// ── Encode / Decode ───────────────────────────────────────────────────────────

impl CompactBlock {
    pub fn encode_payload(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.header.encode(&mut buf).ok();
        self.nonce.encode(&mut buf).ok();
        // short_ids: varint count then 6-byte each
        VarInt(self.short_ids.len() as u64).encode(&mut buf).ok();
        for id in &self.short_ids {
            buf.extend_from_slice(&id.to_le_bytes()[..6]);
        }
        // prefilled_txns
        VarInt(self.prefilled_txns.len() as u64)
            .encode(&mut buf)
            .ok();
        let mut prev_idx: u64 = 0;
        for pt in &self.prefilled_txns {
            let diff = pt.index as u64 - prev_idx;
            VarInt(diff).encode(&mut buf).ok();
            pt.tx.encode(&mut buf).ok();
            prev_idx = pt.index as u64 + 1;
        }
        buf
    }

    pub fn decode_payload(data: &[u8]) -> Result<Self> {
        let mut cur = std::io::Cursor::new(data);
        let header = BlockHeader::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
        let nonce = u64::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;

        let VarInt(sid_count) =
            VarInt::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
        let mut short_ids = Vec::with_capacity(sid_count as usize);
        for _ in 0..sid_count {
            let mut bytes = [0u8; 8];
            std::io::Read::read_exact(&mut cur, &mut bytes[..6])
                .map_err(|e| NetError::Decode(e.to_string()))?;
            short_ids.push(u64::from_le_bytes(bytes));
        }

        let VarInt(pt_count) =
            VarInt::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
        let mut prefilled_txns = Vec::with_capacity(pt_count as usize);
        let mut running_idx: u64 = 0;
        for _ in 0..pt_count {
            let VarInt(diff) =
                VarInt::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
            running_idx += diff;
            let tx = Transaction::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
            prefilled_txns.push(PrefilledTransaction {
                index: running_idx as u16,
                tx,
            });
            running_idx += 1;
        }

        Ok(Self {
            header,
            nonce,
            short_ids,
            prefilled_txns,
        })
    }
}

impl GetBlockTxn {
    pub fn encode_payload(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.block_hash.0.encode(&mut buf).ok();
        VarInt(self.indexes.len() as u64).encode(&mut buf).ok();
        // Differential encoding of sorted indexes
        let mut prev: u64 = 0;
        for &idx in &self.indexes {
            let diff = idx as u64 - prev;
            VarInt(diff).encode(&mut buf).ok();
            prev = idx as u64 + 1;
        }
        buf
    }

    pub fn decode_payload(data: &[u8]) -> Result<Self> {
        let mut cur = std::io::Cursor::new(data);
        let hash_bytes =
            <[u8; 32]>::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
        let block_hash = Hash256(hash_bytes);
        let VarInt(count) =
            VarInt::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
        let mut indexes = Vec::with_capacity(count as usize);
        let mut running: u64 = 0;
        for _ in 0..count {
            let VarInt(diff) =
                VarInt::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
            running += diff;
            indexes.push(running as u32);
            running += 1;
        }
        Ok(Self {
            block_hash,
            indexes,
        })
    }
}

impl BlockTxn {
    pub fn encode_payload(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.block_hash.0.encode(&mut buf).ok();
        VarInt(self.txns.len() as u64).encode(&mut buf).ok();
        for tx in &self.txns {
            tx.encode(&mut buf).ok();
        }
        buf
    }

    pub fn decode_payload(data: &[u8]) -> Result<Self> {
        let mut cur = std::io::Cursor::new(data);
        let hash_bytes =
            <[u8; 32]>::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
        let block_hash = Hash256(hash_bytes);
        let VarInt(count) =
            VarInt::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
        let mut txns = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let tx = Transaction::decode(&mut cur).map_err(|e| NetError::Decode(e.to_string()))?;
            txns.push(tx);
        }
        Ok(Self { block_hash, txns })
    }
}

// ── Block reconstruction helper ───────────────────────────────────────────────

/// Try to reconstruct a full block from a `CompactBlock` and a mempool lookup.
///
/// `mempool_txs` is a slice of `(short_id, Transaction)` pairs — the caller
/// should pre-compute short IDs for all mempool transactions using
/// `short_txid(&cmpct.header, cmpct.nonce, txid)`.
///
/// Returns `Ok(Some(block))` if all transactions were found, or
/// `Ok(None)` with a sorted list of missing 0-based indexes if a
/// `getblocktxn` round-trip is needed.
pub fn reconstruct_block(
    cmpct: &CompactBlock,
    mempool_lookup: &std::collections::HashMap<u64, Transaction>,
) -> (Option<rbtc_primitives::block::Block>, Vec<u32>) {
    let total = cmpct.short_ids.len() + cmpct.prefilled_txns.len();
    let mut slots: Vec<Option<Transaction>> = vec![None; total];

    // Place prefilled transactions first
    for pt in &cmpct.prefilled_txns {
        let idx = pt.index as usize;
        if idx < slots.len() {
            slots[idx] = Some(pt.tx.clone());
        }
    }

    // Fill remaining slots from mempool
    let mut short_id_iter = cmpct.short_ids.iter();
    let mut missing = Vec::new();
    for (slot_idx, slot) in slots.iter_mut().enumerate() {
        if slot.is_some() {
            continue;
        }
        if let Some(&sid) = short_id_iter.next() {
            if let Some(tx) = mempool_lookup.get(&sid) {
                *slot = Some(tx.clone());
            } else {
                missing.push(slot_idx as u32);
            }
        }
    }

    if missing.is_empty() {
        let transactions: Vec<Transaction> = slots.into_iter().flatten().collect();
        let block = rbtc_primitives::block::Block::new(cmpct.header.clone(), transactions);
        (Some(block), vec![])
    } else {
        (None, missing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::block::BlockHeader;
    use rbtc_primitives::hash::{BlockHash, Hash256};

    fn dummy_header() -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block: BlockHash(Hash256::ZERO),
            merkle_root: Hash256::ZERO,
            time: 0,
            bits: 0x207fffff,
            nonce: 0,
        }
    }

    #[test]
    fn short_txid_deterministic() {
        let header = dummy_header();
        let txid = Hash256([0xab; 32]);
        let a = short_txid(&header, 42, &txid);
        let b = short_txid(&header, 42, &txid);
        assert_eq!(a, b);
        // Must fit in 48 bits
        assert_eq!(a & !0x0000_ffff_ffff_ffff, 0);
    }

    #[test]
    fn short_txid_different_nonce() {
        let header = dummy_header();
        let txid = Hash256([0xcd; 32]);
        let a = short_txid(&header, 1, &txid);
        let b = short_txid(&header, 2, &txid);
        assert_ne!(a, b);
    }

    #[test]
    fn getblocktxn_roundtrip() {
        let msg = GetBlockTxn {
            block_hash: Hash256([7; 32]),
            indexes: vec![0, 2, 5],
        };
        let bytes = msg.encode_payload();
        let decoded = GetBlockTxn::decode_payload(&bytes).unwrap();
        assert_eq!(decoded.block_hash.0, msg.block_hash.0);
        assert_eq!(decoded.indexes, msg.indexes);
    }

    fn dummy_coinbase() -> Transaction {
        use rbtc_primitives::transaction::{OutPoint, TxIn, TxOut, OUTPOINT_NULL_INDEX};
        use rbtc_primitives::hash::Txid;
        use rbtc_primitives::script::Script;
        Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint { txid: Txid(Hash256::ZERO), vout: OUTPOINT_NULL_INDEX },
                script_sig: Script::from_bytes(vec![0x04, 0xff, 0xff, 0x00, 0x1d]),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut { value: 50_0000_0000, script_pubkey: Script::new() }],
            0,
        )
    }

    fn dummy_tx(marker: u8) -> Transaction {
        use rbtc_primitives::transaction::{OutPoint, TxIn, TxOut};
        use rbtc_primitives::hash::Txid;
        use rbtc_primitives::script::Script;
        Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint { txid: Txid(Hash256([marker; 32])), vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut { value: 1_0000_0000, script_pubkey: Script::new() }],
            0,
        )
    }

    #[test]
    fn from_block_coinbase_only() {
        let coinbase = dummy_coinbase();
        let block = rbtc_primitives::block::Block::new(dummy_header(), vec![coinbase.clone()]);
        let cmpct = CompactBlock::from_block(&block, 42);

        assert_eq!(cmpct.prefilled_txns.len(), 1);
        assert_eq!(cmpct.prefilled_txns[0].index, 0);
        assert_eq!(cmpct.short_ids.len(), 0);
        assert_eq!(cmpct.nonce, 42);
    }

    #[test]
    fn from_block_includes_coinbase_prefilled() {
        let coinbase = dummy_coinbase();
        let tx1 = dummy_tx(1);
        let block = rbtc_primitives::block::Block::new(
            dummy_header(),
            vec![coinbase.clone(), tx1.clone()],
        );
        let cmpct = CompactBlock::from_block(&block, 100);

        assert_eq!(cmpct.prefilled_txns.len(), 1);
        assert_eq!(cmpct.prefilled_txns[0].index, 0);
        assert_eq!(cmpct.short_ids.len(), 1);
    }

    #[test]
    fn from_block_short_ids_match() {
        let coinbase = dummy_coinbase();
        let tx1 = dummy_tx(1);
        let tx2 = dummy_tx(2);
        let block = rbtc_primitives::block::Block::new(
            dummy_header(),
            vec![coinbase, tx1.clone(), tx2.clone()],
        );
        let nonce = 999;
        let cmpct = CompactBlock::from_block(&block, nonce);

        // Verify short IDs match what short_txid() would compute
        let expected_sid1 = short_txid(&dummy_header(), nonce, &tx1.txid().0);
        let expected_sid2 = short_txid(&dummy_header(), nonce, &tx2.txid().0);
        assert_eq!(cmpct.short_ids.len(), 2);
        assert_eq!(cmpct.short_ids[0], expected_sid1);
        assert_eq!(cmpct.short_ids[1], expected_sid2);
    }

    #[test]
    fn from_block_roundtrip_with_mempool() {
        let coinbase = dummy_coinbase();
        let tx1 = dummy_tx(1);
        let tx2 = dummy_tx(2);
        let block = rbtc_primitives::block::Block::new(
            dummy_header(),
            vec![coinbase.clone(), tx1.clone(), tx2.clone()],
        );
        let nonce = 42;
        let cmpct = CompactBlock::from_block(&block, nonce);

        // Build mempool lookup from the non-coinbase txs
        let mut mempool_lookup = std::collections::HashMap::new();
        for tx in &[&tx1, &tx2] {
            let sid = short_txid(&cmpct.header, cmpct.nonce, &tx.txid().0);
            mempool_lookup.insert(sid, (*tx).clone());
        }

        let (maybe_block, missing) = reconstruct_block(&cmpct, &mempool_lookup);
        assert!(missing.is_empty());
        let reconstructed = maybe_block.unwrap();
        assert_eq!(reconstructed.transactions.len(), 3);
    }
}
