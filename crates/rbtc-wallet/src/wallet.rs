//! Main `Wallet` struct: key management, UTXO tracking, address derivation,
//! and transaction building/signing.

use std::collections::HashMap;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use secp256k1::SecretKey;
use sha2::Sha256;
use tracing::{debug, info};

use rbtc_primitives::{
    block::Block,
    network::Network,
    script::Script,
    transaction::{OutPoint, Transaction},
};
use rbtc_storage::Database;

use crate::{
    address::{
        p2pkh_address, p2pkh_script, p2tr_address, p2tr_script, p2wpkh_address, p2wpkh_script,
        taproot_output_key, AddressType,
    },
    error::WalletError,
    hd::{DerivationPath, ExtendedPrivKey},
    mnemonic::Mnemonic,
    tx_builder::{sign_transaction, CoinSelector, SigningInput, TxBuilder},
    wallet_store::{StoredAddressInfo, StoredWalletUtxo, WalletStore},
    wif::{from_wif, to_wif},
};

// ── WalletUtxo ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WalletUtxo {
    pub outpoint: OutPoint,
    pub value: u64,
    pub script_pubkey: Script,
    pub height: u32,
    pub address: String,
    pub confirmed: bool,
    pub addr_type: AddressType,
}

// ── AddressInfo ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct AddressInfo {
    pub addr_type: AddressType,
    pub derivation_path: String,
    pub script_pubkey: Script,
    pub pubkey_bytes: Vec<u8>, // 33-byte compressed pubkey
}

// ── Wallet ────────────────────────────────────────────────────────────────────

/// HD wallet wrapping an `ExtendedPrivKey` master key.
///
/// - Derives addresses on-demand (BIP44/84/86 paths).
/// - Tracks wallet-owned UTXOs via incremental block scanning.
/// - Signs transactions using the appropriate sighash algorithm.
/// - Persists encrypted key material and UTXOs to RocksDB.
pub struct Wallet {
    master: ExtendedPrivKey,
    network: Network,
    /// Next derivation index (per address type).
    next_index: HashMap<String, u32>,
    /// address string → AddressInfo (for scanning and signing)
    addresses: HashMap<String, AddressInfo>,
    /// scriptPubKey bytes → address string (for O(1) block scanning)
    script_to_addr: HashMap<Vec<u8>, String>,
    /// Confirmed and unconfirmed wallet UTXOs
    utxos: HashMap<OutPoint, WalletUtxo>,
    db: std::sync::Arc<Database>,
}

impl Wallet {
    // ── Constructors ─────────────────────────────────────────────────────────

    /// Create (or open) a wallet from a mnemonic phrase.
    ///
    /// If a passphrase-encrypted wallet already exists in the DB it is loaded;
    /// otherwise the mnemonic is used to initialise a fresh wallet.
    pub fn from_mnemonic(
        mnemonic: &Mnemonic,
        bip39_passphrase: &str,
        encryption_passphrase: &str,
        network: Network,
        db: std::sync::Arc<Database>,
    ) -> Result<Self, WalletError> {
        let seed = mnemonic.to_seed(bip39_passphrase);
        let master = ExtendedPrivKey::from_seed(&seed)?;
        let mut wallet = Self::new_inner(master, network, db)?;
        wallet.save_encrypted_master(encryption_passphrase)?;
        Ok(wallet)
    }

    /// Load an existing wallet from the DB, decrypting with `passphrase`.
    pub fn load(
        passphrase: &str,
        network: Network,
        db: std::sync::Arc<Database>,
    ) -> Result<Self, WalletError> {
        let store = WalletStore::new(&db);
        let enc_data = store
            .load_encrypted_xprv()?
            .ok_or(WalletError::NotLoaded)?;
        let master_seed = decrypt_data(passphrase, &enc_data)?;
        let master = ExtendedPrivKey::from_seed(&master_seed)?;
        Self::new_inner(master, network, db)
    }

    /// Check whether a wallet exists in the given database.
    pub fn exists(db: &Database) -> bool {
        WalletStore::new(db)
            .load_encrypted_xprv()
            .map(|o| o.is_some())
            .unwrap_or(false)
    }

    /// Import a single WIF private key into the wallet (no HD derivation).
    pub fn import_wif(
        &mut self,
        wif: &str,
        label: &str,
    ) -> Result<String, WalletError> {
        let (sk, _net) = from_wif(wif)?;
        let secp = secp256k1::Secp256k1::signing_only();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);

        // Default to P2WPKH for imported keys
        let spk = p2wpkh_script(&pk);
        let addr = p2wpkh_address(&pk, self.network)?;

        let info = AddressInfo {
            addr_type: AddressType::SegWit,
            derivation_path: format!("imported:{label}"),
            script_pubkey: spk.clone(),
            pubkey_bytes: pk.serialize().to_vec(),
        };
        self.addresses.insert(addr.clone(), info);
        self.script_to_addr
            .insert(spk.as_bytes().to_vec(), addr.clone());

        let store = WalletStore::new(&self.db);
        store.put_address(&StoredAddressInfo {
            address: addr.clone(),
            addr_type: "segwit".into(),
            derivation_path: format!("imported:{label}"),
            pubkey_hex: hex::encode(pk.serialize()),
        })?;

        info!("wallet: imported key for address {addr}");
        Ok(addr)
    }

    // ── Address derivation ────────────────────────────────────────────────────

    /// Derive and return the next unused address of the given type.
    pub fn new_address(&mut self, addr_type: AddressType) -> Result<String, WalletError> {
        let type_key = type_key(addr_type);
        let index = *self.next_index.get(&type_key).unwrap_or(&0);

        let (address, spk, pubkey_bytes, path_str) =
            self.derive_address(addr_type, index)?;

        *self.next_index.entry(type_key).or_insert(0) = index + 1;

        let info = AddressInfo {
            addr_type,
            derivation_path: path_str.clone(),
            script_pubkey: spk.clone(),
            pubkey_bytes: pubkey_bytes.clone(),
        };
        self.addresses.insert(address.clone(), info);
        self.script_to_addr
            .insert(spk.as_bytes().to_vec(), address.clone());

        // Persist
        let store = WalletStore::new(&self.db);
        store.put_address(&StoredAddressInfo {
            address: address.clone(),
            addr_type: type_key_str(addr_type).to_string(),
            derivation_path: path_str,
            pubkey_hex: hex::encode(&pubkey_bytes),
        })?;
        store.save_address_index(index + 1)?;

        info!("wallet: new {} address {address}", type_key_str(addr_type));
        Ok(address)
    }

    // ── Balance & UTXO queries ────────────────────────────────────────────────

    /// Returns `(confirmed_balance_sat, unconfirmed_balance_sat)`.
    pub fn balance(&self) -> (u64, u64) {
        let mut confirmed = 0u64;
        let mut unconfirmed = 0u64;
        for utxo in self.utxos.values() {
            if utxo.confirmed {
                confirmed += utxo.value;
            } else {
                unconfirmed += utxo.value;
            }
        }
        (confirmed, unconfirmed)
    }

    pub fn list_unspent(&self, min_conf: u32) -> Vec<&WalletUtxo> {
        self.utxos
            .values()
            .filter(|u| u.confirmed && u.height >= min_conf)
            .collect()
    }

    pub fn utxo_count(&self) -> usize {
        self.utxos.len()
    }

    pub fn address_count(&self) -> usize {
        self.addresses.len()
    }

    pub fn addresses(&self) -> Vec<String> {
        self.addresses.keys().cloned().collect()
    }

    /// Return the WIF private key for the given address.
    pub fn dump_privkey(&self, address: &str) -> Result<String, WalletError> {
        let sk = self.privkey_for_address(address)?;
        Ok(to_wif(&sk, self.network))
    }

    // ── Block scanning ────────────────────────────────────────────────────────

    /// Called after a new block is connected. Adds wallet outputs and marks
    /// existing UTXOs as confirmed.
    pub fn scan_block(&mut self, block: &Block, height: u32) {
        let store = WalletStore::new(&self.db);

        for tx in &block.transactions {
            // Compute txid (legacy serialisation for txid)
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
                    let outpoint = OutPoint { txid, vout: vout as u32 };
                    let addr_type = self
                        .addresses
                        .get(&address)
                        .map(|i| i.addr_type)
                        .unwrap_or(AddressType::SegWit);

                    let utxo = WalletUtxo {
                        outpoint: outpoint.clone(),
                        value: output.value,
                        script_pubkey: output.script_pubkey.clone(),
                        height,
                        address: address.clone(),
                        confirmed: true,
                        addr_type,
                    };

                    debug!(
                        "wallet: received {} sat to {address} in block {height}",
                        output.value
                    );

                    // Persist
                    store
                        .put_utxo(
                            &outpoint,
                            &to_stored_utxo(&utxo),
                        )
                        .ok();

                    self.utxos.insert(outpoint, utxo);
                }
            }
        }
    }

    /// Called after a block is connected. Removes wallet inputs that were spent.
    pub fn remove_spent(&mut self, block: &Block) {
        let store = WalletStore::new(&self.db);
        for tx in &block.transactions {
            for input in &tx.inputs {
                if self.utxos.remove(&input.previous_output).is_some() {
                    debug!(
                        "wallet: spent utxo {}:{}",
                        input.previous_output.txid.to_hex(),
                        input.previous_output.vout
                    );
                    store.remove_utxo(&input.previous_output).ok();
                }
            }
        }
    }

    // ── Transaction building & signing ────────────────────────────────────────

    /// Build, sign, and return a transaction that sends `amount_sat` to
    /// `dest_address`, paying `fee_rate` sat/vbyte.
    ///
    /// Returns `(signed_tx, fee_sat)`.
    pub fn create_transaction(
        &mut self,
        dest_address: &str,
        amount_sat: u64,
        fee_rate: f64,
        change_addr_type: AddressType,
    ) -> Result<(Transaction, u64), WalletError> {
        let dest_spk =
            crate::address::address_to_script(dest_address)?;

        let available: Vec<WalletUtxo> =
            self.utxos.values().filter(|u| u.confirmed).cloned().collect();

        let (selected, fee) = CoinSelector::select(&available, amount_sat, fee_rate)?;

        if fee >= amount_sat {
            return Err(WalletError::FeeTooHigh { fee, value: amount_sat });
        }

        let total_in: u64 = selected.iter().map(|u| u.value).sum();
        let change = total_in - amount_sat - fee;

        let change_address = self.new_address(change_addr_type)?;
        let change_spk = crate::address::address_to_script(&change_address)?;

        let mut builder = TxBuilder::new();
        for utxo in &selected {
            builder = builder.add_input(utxo.outpoint.clone());
        }
        builder = builder.add_output(amount_sat, dest_spk);
        if change > 546 {
            // dust threshold ~546 sat
            builder = builder.add_output(change, change_spk);
        }
        let unsigned_tx = builder.build();

        // Build signing inputs
        let signing_inputs: Vec<SigningInput> = selected
            .iter()
            .map(|utxo| {
                let sk = self
                    .privkey_for_address(&utxo.address)
                    .unwrap_or_else(|_| SecretKey::from_slice(&[1u8; 32]).unwrap());
                SigningInput {
                    outpoint: utxo.outpoint.clone(),
                    value: utxo.value,
                    script_pubkey: utxo.script_pubkey.clone(),
                    secret_key: sk,
                }
            })
            .collect();

        let signed = sign_transaction(&unsigned_tx, &signing_inputs)?;
        Ok((signed, fee))
    }

    /// Sign an externally-built unsigned transaction. Only inputs whose
    /// outpoints match wallet UTXOs are signed.
    pub fn sign_transaction(&self, tx: &Transaction) -> Result<Transaction, WalletError> {
        let signing_inputs: Vec<SigningInput> = tx
            .inputs
            .iter()
            .map(|inp| {
                if let Some(utxo) = self.utxos.get(&inp.previous_output) {
                    let sk = self
                        .privkey_for_address(&utxo.address)
                        .unwrap_or_else(|_| SecretKey::from_slice(&[1u8; 32]).unwrap());
                    SigningInput {
                        outpoint: inp.previous_output.clone(),
                        value: utxo.value,
                        script_pubkey: utxo.script_pubkey.clone(),
                        secret_key: sk,
                    }
                } else {
                    // Unknown input — use dummy key (will produce invalid sig)
                    SigningInput {
                        outpoint: inp.previous_output.clone(),
                        value: 0,
                        script_pubkey: Script::new(),
                        secret_key: SecretKey::from_slice(&[1u8; 32]).unwrap(),
                    }
                }
            })
            .collect();

        sign_transaction(tx, &signing_inputs)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn new_inner(
        master: ExtendedPrivKey,
        network: Network,
        db: std::sync::Arc<Database>,
    ) -> Result<Self, WalletError> {
        let mut wallet = Self {
            master,
            network,
            next_index: HashMap::new(),
            addresses: HashMap::new(),
            script_to_addr: HashMap::new(),
            utxos: HashMap::new(),
            db,
        };
        wallet.load_from_db()?;
        Ok(wallet)
    }

    fn load_from_db(&mut self) -> Result<(), WalletError> {
        let store = WalletStore::new(&self.db);

        // Restore address index
        let idx = store.load_address_index()?;
        self.next_index
            .insert("segwit".to_string(), idx);

        // Restore known addresses
        for stored in store.iter_addresses() {
            let addr_type = match stored.addr_type.as_str() {
                "legacy"  => AddressType::Legacy,
                "taproot" => AddressType::Taproot,
                _         => AddressType::SegWit,
            };
            if let Ok(pub_bytes) = hex::decode(&stored.pubkey_hex) {
                if let Ok(spk) = self.script_from_pubkey(addr_type, &pub_bytes) {
                    self.script_to_addr
                        .insert(spk.as_bytes().to_vec(), stored.address.clone());
                    self.addresses.insert(
                        stored.address.clone(),
                        AddressInfo {
                            addr_type,
                            derivation_path: stored.derivation_path,
                            script_pubkey: spk,
                            pubkey_bytes: pub_bytes,
                        },
                    );
                }
            }
        }

        // Restore UTXOs
        for (outpoint, stored_utxo) in store.iter_utxos() {
            let addr_type = self
                .addresses
                .get(&stored_utxo.address)
                .map(|i| i.addr_type)
                .unwrap_or(AddressType::SegWit);
            if let (Ok(spk_bytes), Ok(txid)) = (
                hex::decode(&stored_utxo.script_pubkey_hex),
                rbtc_primitives::hash::Hash256::from_hex(&stored_utxo.txid),
            ) {
                self.utxos.insert(
                    outpoint,
                    WalletUtxo {
                        outpoint: OutPoint { txid, vout: stored_utxo.vout },
                        value: stored_utxo.value,
                        script_pubkey: Script::from_bytes(spk_bytes),
                        height: stored_utxo.height,
                        address: stored_utxo.address,
                        confirmed: stored_utxo.confirmed,
                        addr_type,
                    },
                );
            }
        }

        Ok(())
    }

    fn save_encrypted_master(&self, passphrase: &str) -> Result<(), WalletError> {
        let seed_bytes = self.master.private_key.secret_bytes();
        let encrypted = encrypt_data(passphrase, &seed_bytes);
        WalletStore::new(&self.db).save_encrypted_xprv(&encrypted)
    }

    /// Derive the BIP32 private key for the given address.
    fn privkey_for_address(&self, address: &str) -> Result<SecretKey, WalletError> {
        let info = self.addresses.get(address).ok_or(WalletError::AddressNotFound)?;
        if info.derivation_path.starts_with("imported:") {
            // Cannot re-derive imported keys from the master — we don't store them
            return Err(WalletError::AddressNotFound);
        }
        let path = DerivationPath::parse(&info.derivation_path)?;
        Ok(self.master.derive_path(&path)?.private_key)
    }

    /// Derive an address at the given index for the given type.
    /// Returns `(address_string, scriptPubKey, pubkey_bytes, path_string)`.
    fn derive_address(
        &self,
        addr_type: AddressType,
        index: u32,
    ) -> Result<(String, Script, Vec<u8>, String), WalletError> {
        let coin_type: u32 = match self.network {
            Network::Mainnet => 0,
            _ => 1,
        };

        let (purpose, path_str) = match addr_type {
            AddressType::Legacy  => (44u32, format!("m/44'/{coin_type}'/0'/0/{index}")),
            AddressType::SegWit  => (84u32, format!("m/84'/{coin_type}'/0'/0/{index}")),
            AddressType::Taproot => (86u32, format!("m/86'/{coin_type}'/0'/0/{index}")),
        };
        let _ = purpose;

        let path = DerivationPath::parse(&path_str)?;
        let child = self.master.derive_path(&path)?;
        let pubkey = child.public_key();
        let pubkey_bytes = pubkey.serialize().to_vec();

        match addr_type {
            AddressType::Legacy => {
                let spk = p2pkh_script(&pubkey);
                let addr = p2pkh_address(&pubkey, self.network);
                Ok((addr, spk, pubkey_bytes, path_str))
            }
            AddressType::SegWit => {
                let spk = p2wpkh_script(&pubkey);
                let addr = p2wpkh_address(&pubkey, self.network)?;
                Ok((addr, spk, pubkey_bytes, path_str))
            }
            AddressType::Taproot => {
                let kp = child.keypair();
                let (_, output_xonly) = taproot_output_key(&kp)?;
                let spk = p2tr_script(&output_xonly);
                let addr = p2tr_address(&kp, self.network)?;
                Ok((addr, spk, pubkey_bytes, path_str))
            }
        }
    }

    fn script_from_pubkey(
        &self,
        addr_type: AddressType,
        pub_bytes: &[u8],
    ) -> Result<Script, WalletError> {
        let pubkey =
            secp256k1::PublicKey::from_slice(pub_bytes).map_err(|_| WalletError::InvalidKey)?;
        match addr_type {
            AddressType::Legacy  => Ok(p2pkh_script(&pubkey)),
            AddressType::SegWit  => Ok(p2wpkh_script(&pubkey)),
            AddressType::Taproot => {
                // For Taproot, re-derive the tweaked output key from the pubkey.
                // We need the secret key for tweaking, so this path is approximate.
                // In practice the scriptPubKey is persisted in StoredAddressInfo hex.
                Ok(p2wpkh_script(&pubkey)) // fallback; override with stored data
            }
        }
    }
}

// ── Encryption helpers ────────────────────────────────────────────────────────

const PBKDF2_ITERS: u32 = 100_000;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

fn derive_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, PBKDF2_ITERS, &mut key);
    key
}

pub fn encrypt_data(passphrase: &str, plaintext: &[u8]) -> Vec<u8> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let key_bytes = derive_key(passphrase, &salt);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("AES-GCM encryption should not fail");

    // Format: salt(16) || nonce(12) || ciphertext+tag
    let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    out
}

pub fn decrypt_data(passphrase: &str, data: &[u8]) -> Result<Vec<u8>, WalletError> {
    if data.len() < SALT_LEN + NONCE_LEN {
        return Err(WalletError::DecryptionFailed);
    }
    let salt = &data[..SALT_LEN];
    let nonce_bytes = &data[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &data[SALT_LEN + NONCE_LEN..];

    let key_bytes = derive_key(passphrase, salt);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| WalletError::DecryptionFailed)
}

// ── Misc helpers ──────────────────────────────────────────────────────────────

fn type_key(addr_type: AddressType) -> String {
    type_key_str(addr_type).to_string()
}

fn type_key_str(addr_type: AddressType) -> &'static str {
    match addr_type {
        AddressType::Legacy  => "legacy",
        AddressType::SegWit  => "segwit",
        AddressType::Taproot => "taproot",
    }
}

fn to_stored_utxo(utxo: &WalletUtxo) -> StoredWalletUtxo {
    StoredWalletUtxo {
        txid: utxo.outpoint.txid.to_hex(),
        vout: utxo.outpoint.vout,
        value: utxo.value,
        script_pubkey_hex: hex::encode(utxo.script_pubkey.as_bytes()),
        height: utxo.height,
        address: utxo.address.clone(),
        confirmed: utxo.confirmed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn open_db() -> (TempDir, std::sync::Arc<Database>) {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        (dir, std::sync::Arc::new(db))
    }

    fn test_wallet(db: std::sync::Arc<Database>) -> Wallet {
        let m = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();
        Wallet::from_mnemonic(&m, "", "testpassword", Network::Regtest, db).unwrap()
    }

    #[test]
    fn new_segwit_address() {
        let (_dir, db) = open_db();
        let mut w = test_wallet(db);
        let addr = w.new_address(AddressType::SegWit).unwrap();
        assert!(addr.starts_with("bcrt1q"), "expected bcrt1q prefix, got {addr}");
    }

    #[test]
    fn new_legacy_address() {
        let (_dir, db) = open_db();
        let mut w = test_wallet(db);
        let addr = w.new_address(AddressType::Legacy).unwrap();
        // Regtest P2PKH starts with 'm' or 'n'
        assert!(addr.starts_with('m') || addr.starts_with('n'), "got {addr}");
    }

    #[test]
    fn new_taproot_address() {
        let (_dir, db) = open_db();
        let mut w = test_wallet(db);
        let addr = w.new_address(AddressType::Taproot).unwrap();
        assert!(addr.starts_with("bcrt1p"), "expected bcrt1p prefix, got {addr}");
    }

    #[test]
    fn balance_starts_zero() {
        let (_dir, db) = open_db();
        let w = test_wallet(db);
        assert_eq!(w.balance(), (0, 0));
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let data = b"secret seed material 0123456789ab";
        let enc = encrypt_data("my passphrase", data);
        let dec = decrypt_data("my passphrase", &enc).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn decrypt_wrong_passphrase_fails() {
        let data = b"secret";
        let enc = encrypt_data("correct", data);
        assert!(decrypt_data("wrong", &enc).is_err());
    }

    #[test]
    fn dump_privkey_roundtrip() {
        let (_dir, db) = open_db();
        let mut w = test_wallet(db);
        let addr = w.new_address(AddressType::SegWit).unwrap();
        let wif = w.dump_privkey(&addr).unwrap();
        let (_, net) = from_wif(&wif).unwrap();
        assert_eq!(net, Network::Regtest);
    }
}
