//! Persistent wallet storage backed by a dedicated RocksDB column family.
//!
//! Key scheme (all under CF_WALLET):
//!   `meta:xprv_enc`   → encrypted xprv bytes (nonce || ciphertext)
//!   `meta:index`      → next address derivation index (4 LE bytes)
//!   `addr:{address}`  → serialised AddressInfo (JSON)
//!   `utxo:{outpoint}` → serialised WalletUtxo (JSON)

use serde::{Deserialize, Serialize};

use rbtc_primitives::transaction::OutPoint;
use rbtc_storage::Database;

use crate::error::WalletError;

pub const CF_WALLET: &str = "wallet";

// ── Stored types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAddressInfo {
    pub address: String,
    /// "legacy" | "segwit" | "taproot"
    pub addr_type: String,
    /// BIP32 derivation path string, e.g. "m/84'/0'/0'/0/3"
    pub derivation_path: String,
    /// Compressed public key bytes (hex)
    pub pubkey_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredWalletUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub script_pubkey_hex: String,
    pub height: u32,
    pub address: String,
    pub confirmed: bool,
}

// ── WalletStore ───────────────────────────────────────────────────────────────

pub struct WalletStore<'a> {
    db: &'a Database,
}

impl<'a> WalletStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    // ── Encrypted xprv ───────────────────────────────────────────────────────

    pub fn save_encrypted_xprv(&self, data: &[u8]) -> Result<(), WalletError> {
        self.db
            .put_cf(CF_WALLET, b"meta:xprv_enc", data)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    pub fn load_encrypted_xprv(&self) -> Result<Option<Vec<u8>>, WalletError> {
        self.db
            .get_cf(CF_WALLET, b"meta:xprv_enc")
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    // ── Derivation index ─────────────────────────────────────────────────────

    pub fn save_address_index(&self, index: u32) -> Result<(), WalletError> {
        self.db
            .put_cf(CF_WALLET, b"meta:index", &index.to_le_bytes())
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    pub fn load_address_index(&self) -> Result<u32, WalletError> {
        match self
            .db
            .get_cf(CF_WALLET, b"meta:index")
            .map_err(|e| WalletError::Storage(e.to_string()))?
        {
            Some(bytes) if bytes.len() >= 4 => {
                Ok(u32::from_le_bytes(bytes[..4].try_into().unwrap()))
            }
            _ => Ok(0),
        }
    }

    // ── Address info ─────────────────────────────────────────────────────────

    pub fn put_address(&self, info: &StoredAddressInfo) -> Result<(), WalletError> {
        let key = format!("addr:{}", info.address);
        let val = serde_json::to_vec(info)
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        self.db
            .put_cf(CF_WALLET, key.as_bytes(), &val)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    pub fn iter_addresses(&self) -> Vec<StoredAddressInfo> {
        let Ok(iter) = self.db.iter_cf(CF_WALLET) else {
            return vec![];
        };
        iter.filter_map(|(k, v)| {
            if k.starts_with(b"addr:") {
                serde_json::from_slice(&v).ok()
            } else {
                None
            }
        })
        .collect()
    }

    // ── Wallet UTXOs ─────────────────────────────────────────────────────────

    fn utxo_key(outpoint: &OutPoint) -> String {
        format!("utxo:{}:{}", outpoint.txid.to_hex(), outpoint.vout)
    }

    pub fn put_utxo(&self, outpoint: &OutPoint, utxo: &StoredWalletUtxo) -> Result<(), WalletError> {
        let key = Self::utxo_key(outpoint);
        let val = serde_json::to_vec(utxo)
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        self.db
            .put_cf(CF_WALLET, key.as_bytes(), &val)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    pub fn remove_utxo(&self, outpoint: &OutPoint) -> Result<(), WalletError> {
        let key = Self::utxo_key(outpoint);
        self.db
            .delete_cf(CF_WALLET, key.as_bytes())
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    // ── Imported private keys ──────────────────────────────────────────────

    /// Store an imported private key (WIF-encoded) for the given address.
    pub fn put_imported_key(&self, address: &str, wif: &str) -> Result<(), WalletError> {
        let key = format!("key:{address}");
        self.db
            .put_cf(CF_WALLET, key.as_bytes(), wif.as_bytes())
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Load an imported private key (WIF) for the given address.
    pub fn get_imported_key(&self, address: &str) -> Result<Option<String>, WalletError> {
        let key = format!("key:{address}");
        self.db
            .get_cf(CF_WALLET, key.as_bytes())
            .map(|opt| opt.map(|bytes| String::from_utf8_lossy(&bytes).to_string()))
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Iterate all imported keys. Returns `(address, wif)` pairs.
    pub fn iter_imported_keys(&self) -> Vec<(String, String)> {
        let Ok(iter) = self.db.iter_cf(CF_WALLET) else {
            return vec![];
        };
        iter.filter_map(|(k, v)| {
            if k.starts_with(b"key:") {
                let addr = String::from_utf8_lossy(&k[4..]).to_string();
                let wif = String::from_utf8_lossy(&v).to_string();
                Some((addr, wif))
            } else {
                None
            }
        })
        .collect()
    }

    pub fn iter_utxos(&self) -> Vec<(OutPoint, StoredWalletUtxo)> {
        let Ok(iter) = self.db.iter_cf(CF_WALLET) else {
            return vec![];
        };
        iter.filter_map(|(k, v)| {
            if !k.starts_with(b"utxo:") {
                return None;
            }
            let utxo: StoredWalletUtxo = serde_json::from_slice(&v).ok()?;
            let txid = rbtc_primitives::hash::Hash256::from_hex(&utxo.txid).ok()?;
            let outpoint = OutPoint { txid, vout: utxo.vout };
            Some((outpoint, utxo))
        })
        .collect()
    }
}
