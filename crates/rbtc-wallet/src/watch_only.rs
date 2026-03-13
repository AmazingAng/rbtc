//! Watch-only wallet: tracks balances and UTXOs using only an extended public
//! key (xpub). Cannot sign transactions.

use std::collections::HashMap;

use tracing::debug;

use rbtc_primitives::{
    block::Block,
    hash::Txid,
    network::Network,
    script::Script,
    transaction::{OutPoint, Transaction},
};

use crate::{
    address::{
        p2pkh_address, p2pkh_script, p2sh_p2wpkh_address_from_pubkey, p2sh_p2wpkh_script,
        p2wpkh_address, p2wpkh_script, AddressType,
    },
    error::WalletError,
    hd::ExtendedPubKey,
    wallet::WalletUtxo,
};

// ── AddressInfo (watch-only) ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct AddressInfo {
    pub addr_type: AddressType,
    pub derivation_index: u32,
    pub script_pubkey: Script,
    pub pubkey_bytes: Vec<u8>,
}

// ── WatchOnlyWallet ──────────────────────────────────────────────────────────

/// A wallet that holds only an extended public key. It can derive addresses,
/// scan blocks for incoming/outgoing transactions, and report balances, but
/// it **cannot** sign transactions.
pub struct WatchOnlyWallet {
    master_pub: ExtendedPubKey,
    network: Network,
    /// address string -> AddressInfo
    addresses: HashMap<String, AddressInfo>,
    /// scriptPubKey bytes -> address string (for O(1) block scanning)
    script_to_addr: HashMap<Vec<u8>, String>,
    /// Tracked UTXOs
    utxos: HashMap<OutPoint, WalletUtxo>,
}

impl WatchOnlyWallet {
    /// Create a watch-only wallet from an extended public key.
    ///
    /// The `xpub` should already be derived to the account level
    /// (e.g. `m/84'/0'/0'`), so that `derive_address` appends `/0/index`.
    pub fn from_xpub(xpub: &ExtendedPubKey, network: Network) -> Self {
        Self {
            master_pub: xpub.clone(),
            network,
            addresses: HashMap::new(),
            script_to_addr: HashMap::new(),
            utxos: HashMap::new(),
        }
    }

    /// Always returns `true` -- this is a watch-only wallet.
    pub fn is_watch_only(&self) -> bool {
        true
    }

    /// Derive an address at the given index for the given address type.
    ///
    /// Uses BIP44-style external chain: `<xpub>/0/<index>`.
    /// Only non-hardened derivation is possible from a public key.
    pub fn derive_address(
        &mut self,
        addr_type: AddressType,
        index: u32,
    ) -> Result<String, WalletError> {
        // Derive <xpub>/0/<index>  (external chain)
        let chain_key = self.master_pub.derive_child(0)?;
        let child_key = chain_key.derive_child(index)?;
        let pubkey = child_key.public_key;
        let pubkey_bytes = pubkey.serialize().to_vec();

        let (address, spk) = match addr_type {
            AddressType::Legacy => {
                let spk = p2pkh_script(&pubkey);
                let addr = p2pkh_address(&pubkey, self.network);
                (addr, spk)
            }
            AddressType::P2shP2wpkh => {
                let spk = p2sh_p2wpkh_script(&pubkey);
                let addr = p2sh_p2wpkh_address_from_pubkey(&pubkey, self.network);
                (addr, spk)
            }
            AddressType::SegWit => {
                let spk = p2wpkh_script(&pubkey);
                let addr = p2wpkh_address(&pubkey, self.network)?;
                (addr, spk)
            }
            AddressType::Taproot => {
                // For taproot we need the x-only key.  Without a keypair we
                // build a simple P2TR output: OP_1 <32-byte x-only pubkey>.
                let compressed = pubkey.serialize();
                let mut script_bytes = Vec::with_capacity(34);
                script_bytes.push(0x51); // OP_1
                script_bytes.push(0x20); // push 32 bytes
                script_bytes.extend_from_slice(&compressed[1..33]);
                let spk = Script::from_bytes(script_bytes);

                // Encode as bech32m (bc1p / tb1p / bcrt1p)
                let hrp = match self.network {
                    Network::Mainnet => "bc",
                    Network::Testnet4 | Network::Testnet3 | Network::Signet => "tb",
                    Network::Regtest => "bcrt",
                };
                let addr = bech32::encode::<bech32::Bech32m>(
                    bech32::Hrp::parse(hrp).map_err(|e| {
                        WalletError::AddressEncoding(format!("bech32m hrp: {e}"))
                    })?,
                    &{
                        let mut witness = vec![1u8]; // witness version 1
                        witness.extend_from_slice(&compressed[1..33]);
                        witness
                    },
                )
                .map_err(|e| WalletError::AddressEncoding(format!("bech32m encode: {e}")))?;

                (addr, spk)
            }
        };

        let info = AddressInfo {
            addr_type,
            derivation_index: index,
            script_pubkey: spk.clone(),
            pubkey_bytes,
        };
        self.addresses.insert(address.clone(), info);
        self.script_to_addr
            .insert(spk.as_bytes().to_vec(), address.clone());

        Ok(address)
    }

    /// Sum of all confirmed UTXO values (in satoshi).
    pub fn get_balance(&self) -> u64 {
        self.utxos
            .values()
            .filter(|u| u.confirmed)
            .map(|u| u.value)
            .sum()
    }

    /// Scan a block for wallet-related outputs, adding new UTXOs and
    /// removing spent ones.
    pub fn scan_block(&mut self, block: &Block, height: u32) {
        for tx in &block.transactions {
            let txid = {
                let mut buf = Vec::new();
                tx.encode_legacy(&mut buf).ok();
                rbtc_crypto::sha256d(&buf)
            };

            // Check outputs for wallet addresses
            for (vout, output) in tx.outputs.iter().enumerate() {
                let spk_bytes = output.script_pubkey.as_bytes().to_vec();
                if let Some(address) = self.script_to_addr.get(&spk_bytes) {
                    let address = address.clone();
                    let outpoint = OutPoint {
                        txid: Txid(txid),
                        vout: vout as u32,
                    };
                    let addr_type = self
                        .addresses
                        .get(&address)
                        .map(|i| i.addr_type)
                        .unwrap_or(AddressType::SegWit);

                    let utxo = WalletUtxo {
                        outpoint: outpoint.clone(),
                        value: output.value as u64,
                        script_pubkey: output.script_pubkey.clone(),
                        height,
                        address: address.clone(),
                        confirmed: true,
                        addr_type,
                        is_own_change: false,
                        is_coinbase: false, // watch-only doesn't track coinbase status
                    };

                    debug!(
                        "watch-only: received {} sat to {address} in block {height}",
                        output.value
                    );
                    self.utxos.insert(outpoint, utxo);
                }
            }

            // Remove spent UTXOs
            for input in &tx.inputs {
                if self.utxos.remove(&input.previous_output).is_some() {
                    debug!(
                        "watch-only: spent utxo {}:{}",
                        input.previous_output.txid.to_hex(),
                        input.previous_output.vout
                    );
                }
            }
        }
    }

    /// Return all tracked UTXOs.
    pub fn get_utxos(&self) -> Vec<WalletUtxo> {
        self.utxos.values().cloned().collect()
    }

    /// Attempt to sign a transaction. Always fails for watch-only wallets.
    pub fn sign_transaction(&self, _tx: &Transaction) -> Result<Transaction, WalletError> {
        Err(WalletError::WatchOnly)
    }

    /// Number of tracked addresses.
    pub fn address_count(&self) -> usize {
        self.addresses.len()
    }

    /// List all tracked addresses.
    pub fn addresses(&self) -> Vec<String> {
        self.addresses.keys().cloned().collect()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hd::ExtendedPrivKey;

    /// Helper: build an account-level xpub for testing.
    /// Derives m/84'/1'/0' from the "abandon..." mnemonic seed, then
    /// returns the corresponding ExtendedPubKey.
    fn test_account_xpub() -> ExtendedPubKey {
        let mnemonic = crate::mnemonic::Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let seed = mnemonic.to_seed("");
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();
        let path = crate::hd::DerivationPath::parse("m/84'/1'/0'").unwrap();
        let account_prv = master.derive_path(&path).unwrap();
        ExtendedPubKey::from_xprv(&account_prv)
    }

    #[test]
    fn watch_only_from_xpub() {
        let xpub = test_account_xpub();
        let w = WatchOnlyWallet::from_xpub(&xpub, Network::Regtest);
        assert_eq!(w.address_count(), 0);
        assert_eq!(w.get_balance(), 0);
    }

    #[test]
    fn watch_only_derive_address() {
        let xpub = test_account_xpub();
        let mut w = WatchOnlyWallet::from_xpub(&xpub, Network::Regtest);

        let addr = w.derive_address(AddressType::SegWit, 0).unwrap();
        assert!(
            addr.starts_with("bcrt1q"),
            "expected bcrt1q prefix, got {addr}"
        );
        assert_eq!(w.address_count(), 1);

        // Deriving the same index again should return the same address.
        let addr2 = w.derive_address(AddressType::SegWit, 0).unwrap();
        assert_eq!(addr, addr2);

        // Different index yields a different address.
        let addr3 = w.derive_address(AddressType::SegWit, 1).unwrap();
        assert_ne!(addr, addr3);
    }

    #[test]
    fn watch_only_is_watch_only() {
        let xpub = test_account_xpub();
        let w = WatchOnlyWallet::from_xpub(&xpub, Network::Regtest);
        assert!(w.is_watch_only());
    }

    #[test]
    fn watch_only_get_balance_empty() {
        let xpub = test_account_xpub();
        let w = WatchOnlyWallet::from_xpub(&xpub, Network::Regtest);
        assert_eq!(w.get_balance(), 0);
        assert!(w.get_utxos().is_empty());
    }

    #[test]
    fn watch_only_sign_fails() {
        use rbtc_primitives::transaction::MutableTransaction;

        let xpub = test_account_xpub();
        let w = WatchOnlyWallet::from_xpub(&xpub, Network::Regtest);
        let dummy_tx = Transaction::from_mutable(MutableTransaction::new());
        let result = w.sign_transaction(&dummy_tx);
        assert!(result.is_err());
        match result {
            Err(WalletError::WatchOnly) => {} // expected
            other => panic!("expected WatchOnly error, got {other:?}"),
        }
    }
}
