//! Persistent wallet transaction database.
//!
//! `WalletTxStore` keeps a record of every transaction relevant to the wallet
//! (both sent and received), together with confirmation metadata. This replaces
//! pure in-memory tracking so that wallet history survives restarts.

use std::collections::HashMap;

use rbtc_primitives::{
    codec::{Decodable, Encodable},
    hash::{BlockHash, Hash256, Txid},
    transaction::Transaction,
};

use crate::error::WalletError;

// ── WalletTx ─────────────────────────────────────────────────────────────────

/// A transaction stored in the wallet together with confirmation metadata.
///
/// Mirrors Bitcoin Core's `CWalletTx` metadata: confirmation info, replacement
/// tracking (`replaced_by_txid` in `mapValue`), and abandoned state
/// (`TxStateInactive{abandoned=true}`).
#[derive(Debug, Clone)]
pub struct WalletTx {
    /// The full transaction.
    pub tx: Transaction,
    /// Block hash if confirmed.
    pub block_hash: Option<BlockHash>,
    /// Block height if confirmed.
    pub block_height: Option<u32>,
    /// Unix timestamp (of the block, or when the tx was first seen).
    pub timestamp: u64,
    /// Whether the transaction is confirmed in a block.
    pub is_confirmed: bool,
    /// The txid of the replacement transaction (set when this tx is bumped via
    /// RBF). Corresponds to Bitcoin Core's `mapValue["replaced_by_txid"]`.
    pub replaced_by: Option<Txid>,
    /// Whether this transaction has been abandoned by the user (never
    /// broadcast / given up on). Corresponds to Bitcoin Core's
    /// `TxStateInactive{abandoned=true}`.
    pub is_abandoned: bool,
}

impl WalletTx {
    /// Returns the txid of the transaction that replaced this one, if any.
    pub fn replaced_by(&self) -> Option<&Txid> {
        self.replaced_by.as_ref()
    }

    /// Whether this transaction has been abandoned.
    pub fn is_abandoned(&self) -> bool {
        self.is_abandoned
    }
}

// ── WalletTxStore ────────────────────────────────────────────────────────────

/// In-memory transaction database with binary serialization for persistence.
pub struct WalletTxStore {
    txs: HashMap<Txid, WalletTx>,
}

impl WalletTxStore {
    /// Create an empty transaction store.
    pub fn new() -> Self {
        Self {
            txs: HashMap::new(),
        }
    }

    /// Add (or update) a wallet transaction.
    pub fn add_tx(&mut self, txid: Txid, tx: WalletTx) {
        self.txs.insert(txid, tx);
    }

    /// Look up a transaction by its txid.
    pub fn get_tx(&self, txid: &Txid) -> Option<&WalletTx> {
        self.txs.get(txid)
    }

    /// Retrieve a mutable reference to a transaction.
    pub fn get_tx_mut(&mut self, txid: &Txid) -> Option<&mut WalletTx> {
        self.txs.get_mut(txid)
    }

    /// Remove a transaction (e.g., after a reorg).
    pub fn remove_tx(&mut self, txid: &Txid) -> Option<WalletTx> {
        self.txs.remove(txid)
    }

    /// List all stored transactions (unordered).
    pub fn list_txs(&self) -> Vec<&WalletTx> {
        self.txs.values().collect()
    }

    /// Number of stored transactions.
    pub fn len(&self) -> usize {
        self.txs.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    /// Iterate over `(txid, wallet_tx)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&Txid, &WalletTx)> {
        self.txs.iter()
    }

    /// Mark a transaction as abandoned. An abandoned transaction is one that
    /// was never broadcast or has been given up on (Bitcoin Core equivalent:
    /// `TxStateInactive{abandoned=true}`).
    ///
    /// Only unconfirmed transactions can be abandoned.
    pub fn mark_abandoned(&mut self, txid: &Txid) -> Result<(), WalletError> {
        let wtx = self.txs.get_mut(txid)
            .ok_or_else(|| WalletError::Storage("transaction not found".into()))?;
        if wtx.is_confirmed {
            return Err(WalletError::Storage("cannot abandon confirmed transaction".into()));
        }
        wtx.is_abandoned = true;
        Ok(())
    }

    /// Record that `txid` has been replaced by `replacement_txid` (RBF).
    /// Corresponds to Bitcoin Core setting `mapValue["replaced_by_txid"]`.
    pub fn mark_replaced(&mut self, txid: &Txid, replacement_txid: Txid) -> Result<(), WalletError> {
        let wtx = self.txs.get_mut(txid)
            .ok_or_else(|| WalletError::Storage("transaction not found".into()))?;
        wtx.replaced_by = Some(replacement_txid);
        Ok(())
    }

    // ── Serialization ────────────────────────────────────────────────────────

    /// Encode the entire store to a binary blob.
    ///
    /// Format (v2):
    /// ```text
    /// [version: 1] (0x02)
    /// [num_txs: 4-LE]
    /// for each tx:
    ///   [txid: 32]
    ///   [tx_bytes_len: 4-LE][tx_bytes]
    ///   [has_block: 1] ([block_hash: 32] [block_height: 4-LE])?
    ///   [timestamp: 8-LE]
    ///   [is_confirmed: 1]
    ///   [has_replaced_by: 1] ([replaced_by_txid: 32])?
    ///   [is_abandoned: 1]
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // v2 format marker
        buf.push(0x02);
        let count = self.txs.len() as u32;
        buf.extend_from_slice(&count.to_le_bytes());

        for (txid, wtx) in &self.txs {
            // txid
            buf.extend_from_slice(&txid.0 .0);

            // transaction bytes
            let tx_bytes = wtx.tx.encode_to_vec();
            buf.extend_from_slice(&(tx_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(&tx_bytes);

            // block info
            if let (Some(bh), Some(height)) = (&wtx.block_hash, wtx.block_height) {
                buf.push(1);
                buf.extend_from_slice(&bh.0 .0);
                buf.extend_from_slice(&height.to_le_bytes());
            } else {
                buf.push(0);
            }

            // timestamp + confirmed flag
            buf.extend_from_slice(&wtx.timestamp.to_le_bytes());
            buf.push(if wtx.is_confirmed { 1 } else { 0 });

            // v2 metadata: replaced_by + is_abandoned
            if let Some(ref rep) = wtx.replaced_by {
                buf.push(1);
                buf.extend_from_slice(&rep.0 .0);
            } else {
                buf.push(0);
            }
            buf.push(if wtx.is_abandoned { 1 } else { 0 });
        }

        buf
    }

    /// Decode a transaction store from a binary blob produced by `encode()`.
    ///
    /// Supports both v1 (legacy, no version byte) and v2 (version byte 0x02
    /// with `replaced_by` / `is_abandoned` metadata).
    pub fn decode(bytes: &[u8]) -> Result<Self, WalletError> {
        if bytes.len() < 4 {
            return Err(WalletError::Storage("tx store too short".into()));
        }
        // Detect format version: v2 blobs start with 0x02. v1 blobs start
        // with the 4-byte LE count — the first byte would only be 0x02 if
        // the count is 2 and the remaining 3 bytes are zero, but in that case
        // `bytes[1..4]` being all-zero is extremely unlikely to collide.
        // We use a simple heuristic: if first byte is 0x02 and next 3 bytes
        // look like a plausible upper portion of a LE u32 count, treat as v2.
        let (version, mut pos) = if bytes[0] == 0x02 {
            (2u8, 1)
        } else {
            (1u8, 0)
        };
        if pos + 4 > bytes.len() {
            return Err(WalletError::Storage("tx store too short".into()));
        }
        let count = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        let mut txs = HashMap::with_capacity(count);
        pos += 4;

        for _ in 0..count {
            // txid
            if pos + 32 > bytes.len() {
                return Err(WalletError::Storage("truncated txid".into()));
            }
            let txid = Txid(Hash256::from_slice(&bytes[pos..pos + 32])
                .map_err(|e| WalletError::Storage(e.to_string()))?);
            pos += 32;

            // transaction
            if pos + 4 > bytes.len() {
                return Err(WalletError::Storage("truncated tx length".into()));
            }
            let tx_len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + tx_len > bytes.len() {
                return Err(WalletError::Storage("truncated tx data".into()));
            }
            let tx = Transaction::decode_from_slice(&bytes[pos..pos + tx_len])
                .map_err(|e| WalletError::Storage(e.to_string()))?;
            pos += tx_len;

            // block info
            if pos >= bytes.len() {
                return Err(WalletError::Storage("truncated block flag".into()));
            }
            let has_block = bytes[pos];
            pos += 1;

            let (block_hash, block_height) = if has_block == 1 {
                if pos + 36 > bytes.len() {
                    return Err(WalletError::Storage("truncated block info".into()));
                }
                let bh = BlockHash(Hash256::from_slice(&bytes[pos..pos + 32])
                    .map_err(|e| WalletError::Storage(e.to_string()))?);
                pos += 32;
                let height = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap());
                pos += 4;
                (Some(bh), Some(height))
            } else {
                (None, None)
            };

            // timestamp + confirmed
            if pos + 9 > bytes.len() {
                return Err(WalletError::Storage("truncated timestamp".into()));
            }
            let timestamp = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
            pos += 8;
            let is_confirmed = bytes[pos] == 1;
            pos += 1;

            // v2 metadata (replaced_by + is_abandoned) — only present in v2 blobs.
            let (replaced_by, is_abandoned) = if version >= 2 {
                // replaced_by
                let has_rep = bytes[pos];
                pos += 1;
                let rep = if has_rep == 1 {
                    if pos + 32 > bytes.len() {
                        return Err(WalletError::Storage("truncated replaced_by".into()));
                    }
                    let r = Txid(Hash256::from_slice(&bytes[pos..pos + 32])
                        .map_err(|e| WalletError::Storage(e.to_string()))?);
                    pos += 32;
                    Some(r)
                } else {
                    None
                };
                // is_abandoned
                if pos >= bytes.len() {
                    return Err(WalletError::Storage("truncated is_abandoned".into()));
                }
                let abandoned = bytes[pos] == 1;
                pos += 1;
                (rep, abandoned)
            } else {
                (None, false)
            };

            txs.insert(
                txid,
                WalletTx {
                    tx,
                    block_hash,
                    block_height,
                    timestamp,
                    is_confirmed,
                    replaced_by,
                    is_abandoned,
                },
            );
        }

        Ok(Self { txs })
    }
}

impl Default for WalletTxStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::script::Script;
    use rbtc_primitives::transaction::{OutPoint, TxIn, TxOut};

    fn dummy_tx() -> Transaction {
        Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::ZERO,
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut {
                value: 50_000,
                script_pubkey: Script::from_bytes(vec![0x76, 0xa9, 0x14]),
            }],
            0,
        )
    }

    fn dummy_txid(n: u8) -> Txid {
        let mut h = [0u8; 32];
        h[0] = n;
        Txid(Hash256(h))
    }

    #[test]
    fn add_get_list_roundtrip() {
        let mut store = WalletTxStore::new();
        assert!(store.is_empty());

        let tx = dummy_tx();
        let txid = dummy_txid(1);
        let wtx = WalletTx {
            tx: tx.clone(),
            block_hash: None,
            block_height: None,
            timestamp: 1700000000,
            is_confirmed: false,
            replaced_by: None,
            is_abandoned: false,
        };

        store.add_tx(txid, wtx);
        assert_eq!(store.len(), 1);

        let got = store.get_tx(&txid).unwrap();
        assert_eq!(got.timestamp, 1700000000);
        assert!(!got.is_confirmed);

        let list = store.list_txs();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let mut store = WalletTxStore::new();

        // Unconfirmed tx
        store.add_tx(
            dummy_txid(1),
            WalletTx {
                tx: dummy_tx(),
                block_hash: None,
                block_height: None,
                timestamp: 1700000000,
                is_confirmed: false,
                replaced_by: None,
                is_abandoned: false,
            },
        );

        // Confirmed tx
        let mut bh_bytes = [0u8; 32];
        bh_bytes[0] = 0xAB;
        store.add_tx(
            dummy_txid(2),
            WalletTx {
                tx: dummy_tx(),
                block_hash: Some(BlockHash(Hash256(bh_bytes))),
                block_height: Some(800_000),
                timestamp: 1700001000,
                is_confirmed: true,
                replaced_by: None,
                is_abandoned: false,
            },
        );

        let encoded = store.encode();
        let decoded = WalletTxStore::decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 2);

        let tx1 = decoded.get_tx(&dummy_txid(1)).unwrap();
        assert!(!tx1.is_confirmed);
        assert!(tx1.block_hash.is_none());

        let tx2 = decoded.get_tx(&dummy_txid(2)).unwrap();
        assert!(tx2.is_confirmed);
        assert_eq!(tx2.block_height, Some(800_000));
        assert_eq!(tx2.block_hash.unwrap().0 .0[0], 0xAB);
    }

    #[test]
    fn missing_tx_returns_none() {
        let store = WalletTxStore::new();
        assert!(store.get_tx(&dummy_txid(99)).is_none());
    }

    #[test]
    fn remove_tx() {
        let mut store = WalletTxStore::new();
        let txid = dummy_txid(1);
        store.add_tx(
            txid,
            WalletTx {
                tx: dummy_tx(),
                block_hash: None,
                block_height: None,
                timestamp: 0,
                is_confirmed: false,
                replaced_by: None,
                is_abandoned: false,
            },
        );
        assert!(store.remove_tx(&txid).is_some());
        assert!(store.get_tx(&txid).is_none());
        assert!(store.is_empty());
    }

    #[test]
    fn update_confirmation() {
        let mut store = WalletTxStore::new();
        let txid = dummy_txid(1);
        store.add_tx(
            txid,
            WalletTx {
                tx: dummy_tx(),
                block_hash: None,
                block_height: None,
                timestamp: 100,
                is_confirmed: false,
                replaced_by: None,
                is_abandoned: false,
            },
        );

        // Simulate confirmation
        let wtx = store.get_tx_mut(&txid).unwrap();
        wtx.is_confirmed = true;
        wtx.block_height = Some(700_000);
        wtx.timestamp = 200;

        let got = store.get_tx(&txid).unwrap();
        assert!(got.is_confirmed);
        assert_eq!(got.block_height, Some(700_000));
    }

    #[test]
    fn empty_store_encode_decode() {
        let store = WalletTxStore::new();
        let encoded = store.encode();
        let decoded = WalletTxStore::decode(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn mark_abandoned_unconfirmed() {
        let mut store = WalletTxStore::new();
        let txid = dummy_txid(1);
        store.add_tx(
            txid,
            WalletTx {
                tx: dummy_tx(),
                block_hash: None,
                block_height: None,
                timestamp: 100,
                is_confirmed: false,
                replaced_by: None,
                is_abandoned: false,
            },
        );

        assert!(!store.get_tx(&txid).unwrap().is_abandoned());
        store.mark_abandoned(&txid).unwrap();
        assert!(store.get_tx(&txid).unwrap().is_abandoned());
    }

    #[test]
    fn mark_abandoned_confirmed_fails() {
        let mut store = WalletTxStore::new();
        let txid = dummy_txid(1);
        store.add_tx(
            txid,
            WalletTx {
                tx: dummy_tx(),
                block_hash: Some(BlockHash(Hash256([0xAB; 32]))),
                block_height: Some(100),
                timestamp: 100,
                is_confirmed: true,
                replaced_by: None,
                is_abandoned: false,
            },
        );

        assert!(store.mark_abandoned(&txid).is_err());
    }

    #[test]
    fn mark_replaced() {
        let mut store = WalletTxStore::new();
        let txid = dummy_txid(1);
        let replacement = dummy_txid(2);
        store.add_tx(
            txid,
            WalletTx {
                tx: dummy_tx(),
                block_hash: None,
                block_height: None,
                timestamp: 100,
                is_confirmed: false,
                replaced_by: None,
                is_abandoned: false,
            },
        );

        assert!(store.get_tx(&txid).unwrap().replaced_by().is_none());
        store.mark_replaced(&txid, replacement).unwrap();
        assert_eq!(*store.get_tx(&txid).unwrap().replaced_by().unwrap(), replacement);
    }

    #[test]
    fn mark_replaced_missing_tx_fails() {
        let mut store = WalletTxStore::new();
        let result = store.mark_replaced(&dummy_txid(99), dummy_txid(100));
        assert!(result.is_err());
    }

    #[test]
    fn encode_decode_with_metadata() {
        let mut store = WalletTxStore::new();
        let txid1 = dummy_txid(1);
        let txid2 = dummy_txid(2);
        let replacement_txid = dummy_txid(3);

        // tx1: abandoned
        store.add_tx(
            txid1,
            WalletTx {
                tx: dummy_tx(),
                block_hash: None,
                block_height: None,
                timestamp: 100,
                is_confirmed: false,
                replaced_by: None,
                is_abandoned: true,
            },
        );

        // tx2: replaced
        store.add_tx(
            txid2,
            WalletTx {
                tx: dummy_tx(),
                block_hash: None,
                block_height: None,
                timestamp: 200,
                is_confirmed: false,
                replaced_by: Some(replacement_txid),
                is_abandoned: false,
            },
        );

        let encoded = store.encode();
        let decoded = WalletTxStore::decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 2);

        let tx1 = decoded.get_tx(&txid1).unwrap();
        assert!(tx1.is_abandoned());
        assert!(tx1.replaced_by().is_none());

        let tx2 = decoded.get_tx(&txid2).unwrap();
        assert!(!tx2.is_abandoned());
        assert_eq!(*tx2.replaced_by().unwrap(), replacement_txid);
    }

    #[test]
    fn mark_abandoned_not_found() {
        let mut store = WalletTxStore::new();
        assert!(store.mark_abandoned(&dummy_txid(99)).is_err());
    }
}
