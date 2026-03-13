//! Encrypted wallet database for persistent keypool storage.
//!
//! `WalletDb` provides a file-backed key-value store that can encrypt private
//! keys at rest using AES-256-GCM with a key derived via PBKDF2-SHA256.
//!
//! Key layout:
//!   `privkey:{label}` → encrypted private key bytes
//!   `meta:salt`       → 16-byte encryption salt
//!   `meta:encrypted`  → flag (b"1" when encryption is active)
//!   (arbitrary user-defined keys are also supported)

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;

use crate::error::WalletError;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
/// PBKDF2-HMAC-SHA256 iteration count. Bitcoin Core uses 25,000 for legacy
/// wallets but increased to 100,000 in newer releases for stronger brute-force
/// resistance.
const PBKDF2_ITERS: u32 = 100_000;

/// An encrypted private key: `[salt:16][nonce:12][ciphertext]`.
#[derive(Debug, Clone)]
pub struct EncryptedKey {
    pub salt: [u8; SALT_LEN],
    pub encrypted_data: Vec<u8>,
}

impl EncryptedKey {
    /// Serialize to `[salt:16][data:N]` (data already contains nonce+ciphertext).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SALT_LEN + self.encrypted_data.len());
        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(&self.encrypted_data);
        buf
    }

    /// Deserialize from `[salt:16][data:N]`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WalletError> {
        if bytes.len() < SALT_LEN + NONCE_LEN + 1 {
            return Err(WalletError::DecryptionFailed);
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[..SALT_LEN]);
        Ok(Self {
            salt,
            encrypted_data: bytes[SALT_LEN..].to_vec(),
        })
    }
}

/// File-backed wallet database with optional encryption for private keys.
///
/// Data is stored as a simple binary format:
///   `[num_entries:4-LE] ( [key_len:4-LE][key][val_len:4-LE][val] )*`
pub struct WalletDb {
    path: Option<PathBuf>,
    data: HashMap<Vec<u8>, Vec<u8>>,
    encrypted: bool,
    /// Encryption salt — stored in `meta:salt` and used for key derivation.
    enc_salt: [u8; SALT_LEN],
    /// Derived encryption key (zeroed when locked).
    enc_key: Option<[u8; 32]>,
}

impl WalletDb {
    /// Open (or create) a wallet database at `path`.
    ///
    /// If `passphrase` is `Some`, the database is unlocked for reading/writing
    /// encrypted private keys. If `None`, encryption-related operations will
    /// return errors until `decrypt()` is called.
    pub fn open(path: &Path, passphrase: Option<&[u8]>) -> Result<Self, WalletError> {
        let mut db = if path.exists() {
            let raw = fs::read(path).map_err(|e| WalletError::Storage(e.to_string()))?;
            let mut db = Self::decode_file(&raw)?;
            db.path = Some(path.to_path_buf());
            db
        } else {
            Self {
                path: Some(path.to_path_buf()),
                data: HashMap::new(),
                encrypted: false,
                enc_salt: [0u8; SALT_LEN],
                enc_key: None,
            }
        };

        if let Some(pass) = passphrase {
            if db.encrypted {
                db.unlock(pass)?;
            }
        }

        Ok(db)
    }

    /// Create a new in-memory wallet database (no file backing).
    pub fn new_memory() -> Self {
        Self {
            path: None,
            data: HashMap::new(),
            encrypted: false,
            enc_salt: [0u8; SALT_LEN],
            enc_key: None,
        }
    }

    /// Whether the database has encryption enabled.
    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    /// Whether the database is currently unlocked (encryption key available).
    pub fn is_unlocked(&self) -> bool {
        !self.encrypted || self.enc_key.is_some()
    }

    // ── Generic key-value operations ─────────────────────────────────────────

    /// Store a key-value pair (unencrypted metadata).
    pub fn put(&mut self, key: &[u8], value: &[u8]) {
        self.data.insert(key.to_vec(), value.to_vec());
    }

    /// Retrieve a value by key.
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.data.get(key).map(|v| v.as_slice())
    }

    /// Remove a key.
    pub fn remove(&mut self, key: &[u8]) {
        self.data.remove(key);
    }

    // ── Private key storage ──────────────────────────────────────────────────

    /// Store a private key. If encryption is active and unlocked the key is
    /// encrypted before storage; otherwise it is stored in plaintext.
    pub fn put_private_key(&mut self, label: &str, secret: &[u8]) -> Result<(), WalletError> {
        let db_key = format!("privkey:{label}");
        if self.encrypted {
            let enc_key = self.enc_key.ok_or(WalletError::EncryptionError)?;
            let enc = encrypt_with_key(&enc_key, secret);
            self.data.insert(db_key.into_bytes(), enc);
        } else {
            self.data.insert(db_key.into_bytes(), secret.to_vec());
        }
        Ok(())
    }

    /// Retrieve a private key. Decrypts if encryption is active.
    pub fn get_private_key(&self, label: &str) -> Result<Option<Vec<u8>>, WalletError> {
        let db_key = format!("privkey:{label}");
        match self.data.get(db_key.as_bytes()) {
            None => Ok(None),
            Some(stored) => {
                if self.encrypted {
                    let enc_key = self.enc_key.ok_or(WalletError::DecryptionFailed)?;
                    let plain = decrypt_with_key(&enc_key, stored)?;
                    Ok(Some(plain))
                } else {
                    Ok(Some(stored.clone()))
                }
            }
        }
    }

    // ── Encryption lifecycle ─────────────────────────────────────────────────

    /// Encrypt all private keys in the database with the given passphrase.
    ///
    /// After this call, `is_encrypted()` returns `true` and the derived key is
    /// held in memory so that subsequent `put_private_key` / `get_private_key`
    /// calls work without re-entering the passphrase.
    pub fn encrypt(&mut self, passphrase: &[u8]) -> Result<(), WalletError> {
        if self.encrypted {
            return Err(WalletError::EncryptionError);
        }

        // Generate salt
        let mut salt = [0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let derived = derive_key(passphrase, &salt);

        // Re-encrypt every existing private key entry
        let priv_keys: Vec<(Vec<u8>, Vec<u8>)> = self
            .data
            .iter()
            .filter(|(k, _)| k.starts_with(b"privkey:"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        for (k, plaintext) in priv_keys {
            let enc = encrypt_with_key(&derived, &plaintext);
            self.data.insert(k, enc);
        }

        self.enc_salt = salt;
        self.enc_key = Some(derived);
        self.encrypted = true;

        // Persist meta markers
        self.data
            .insert(b"meta:salt".to_vec(), salt.to_vec());
        self.data
            .insert(b"meta:encrypted".to_vec(), b"1".to_vec());

        Ok(())
    }

    /// Decrypt all private keys in the database (removes encryption).
    pub fn decrypt(&mut self, passphrase: &[u8]) -> Result<(), WalletError> {
        if !self.encrypted {
            return Ok(());
        }

        let derived = derive_key(passphrase, &self.enc_salt);

        // Decrypt every private key entry
        let priv_keys: Vec<(Vec<u8>, Vec<u8>)> = self
            .data
            .iter()
            .filter(|(k, _)| k.starts_with(b"privkey:"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        // Verify we can decrypt all before mutating
        let mut decrypted = Vec::with_capacity(priv_keys.len());
        for (k, ciphertext) in &priv_keys {
            let plain = decrypt_with_key(&derived, ciphertext)?;
            decrypted.push((k.clone(), plain));
        }

        for (k, plain) in decrypted {
            self.data.insert(k, plain);
        }

        self.encrypted = false;
        self.enc_key = None;
        self.data.remove(b"meta:salt".as_ref());
        self.data.remove(b"meta:encrypted".as_ref());

        Ok(())
    }

    /// Unlock an encrypted database with the given passphrase (derives the key
    /// and verifies it can decrypt at least one entry, if any exist).
    fn unlock(&mut self, passphrase: &[u8]) -> Result<(), WalletError> {
        let derived = derive_key(passphrase, &self.enc_salt);

        // Verify passphrase by attempting to decrypt the first private key
        let first_priv = self
            .data
            .iter()
            .find(|(k, _)| k.starts_with(b"privkey:"));
        if let Some((_k, ciphertext)) = first_priv {
            decrypt_with_key(&derived, ciphertext)?;
        }

        self.enc_key = Some(derived);
        Ok(())
    }

    // ── Persistence ──────────────────────────────────────────────────────────

    /// Flush the database to disk (no-op for in-memory databases).
    pub fn flush(&self) -> Result<(), WalletError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let encoded = self.encode_file();
        fs::write(path, encoded).map_err(|e| WalletError::Storage(e.to_string()))
    }

    fn encode_file(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let count = self.data.len() as u32;
        buf.extend_from_slice(&count.to_le_bytes());
        for (k, v) in &self.data {
            buf.extend_from_slice(&(k.len() as u32).to_le_bytes());
            buf.extend_from_slice(k);
            buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
            buf.extend_from_slice(v);
        }
        buf
    }

    fn decode_file(data: &[u8]) -> Result<Self, WalletError> {
        if data.len() < 4 {
            return Err(WalletError::Storage("wallet db too short".into()));
        }
        let count = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
        let mut map = HashMap::with_capacity(count);
        let mut pos = 4;

        for _ in 0..count {
            if pos + 4 > data.len() {
                return Err(WalletError::Storage("truncated wallet db".into()));
            }
            let klen = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + klen > data.len() {
                return Err(WalletError::Storage("truncated wallet db key".into()));
            }
            let key = data[pos..pos + klen].to_vec();
            pos += klen;

            if pos + 4 > data.len() {
                return Err(WalletError::Storage("truncated wallet db".into()));
            }
            let vlen = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + vlen > data.len() {
                return Err(WalletError::Storage("truncated wallet db value".into()));
            }
            let val = data[pos..pos + vlen].to_vec();
            pos += vlen;

            map.insert(key, val);
        }

        let encrypted = map
            .get(b"meta:encrypted".as_ref())
            .map(|v| v == b"1")
            .unwrap_or(false);

        let mut enc_salt = [0u8; SALT_LEN];
        if let Some(salt_bytes) = map.get(b"meta:salt".as_ref()) {
            if salt_bytes.len() == SALT_LEN {
                enc_salt.copy_from_slice(salt_bytes);
            }
        }

        Ok(Self {
            path: None,
            data: map,
            encrypted,
            enc_salt,
            enc_key: None,
        })
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn derive_key(passphrase: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase, salt, PBKDF2_ITERS, &mut key);
    key
}

fn encrypt_with_key(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let aes_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).expect("AES-GCM encrypt");
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    out
}

fn decrypt_with_key(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, WalletError> {
    if data.len() < NONCE_LEN + 1 {
        return Err(WalletError::DecryptionFailed);
    }
    let nonce = Nonce::from_slice(&data[..NONCE_LEN]);
    let aes_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);
    cipher
        .decrypt(nonce, &data[NONCE_LEN..])
        .map_err(|_| WalletError::DecryptionFailed)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mut db = WalletDb::new_memory();
        let secret = b"deadbeef_secret_key_32bytes_long";
        db.put_private_key("key0", secret).unwrap();

        // Before encryption, key is readable in plaintext
        assert!(!db.is_encrypted());
        assert_eq!(
            db.get_private_key("key0").unwrap().unwrap(),
            secret.to_vec()
        );

        // Encrypt
        db.encrypt(b"hunter2").unwrap();
        assert!(db.is_encrypted());

        // Key is still readable (we hold the derived key in memory)
        assert_eq!(
            db.get_private_key("key0").unwrap().unwrap(),
            secret.to_vec()
        );

        // Decrypt (remove encryption)
        db.decrypt(b"hunter2").unwrap();
        assert!(!db.is_encrypted());
        assert_eq!(
            db.get_private_key("key0").unwrap().unwrap(),
            secret.to_vec()
        );
    }

    #[test]
    fn wrong_passphrase_fails() {
        let mut db = WalletDb::new_memory();
        db.put_private_key("key0", b"secret").unwrap();
        db.encrypt(b"correct").unwrap();

        // Attempting to decrypt with wrong passphrase should fail
        let enc_file = db.encode_file();
        let mut db2 = WalletDb::decode_file(&enc_file).unwrap();
        assert!(db2.is_encrypted());
        assert!(db2.unlock(b"wrong").is_err());
    }

    #[test]
    fn is_encrypted_flag() {
        let mut db = WalletDb::new_memory();
        assert!(!db.is_encrypted());
        db.encrypt(b"pass").unwrap();
        assert!(db.is_encrypted());
        db.decrypt(b"pass").unwrap();
        assert!(!db.is_encrypted());
    }

    #[test]
    fn file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.dat");

        // Create and populate
        {
            let mut db = WalletDb::open(&path, None).unwrap();
            db.put_private_key("addr1", b"secret_key_1").unwrap();
            db.put(b"meta:label", b"my wallet");
            db.encrypt(b"passphrase123").unwrap();
            db.flush().unwrap();
        }

        // Re-open with correct passphrase
        {
            let db = WalletDb::open(&path, Some(b"passphrase123")).unwrap();
            assert!(db.is_encrypted());
            assert!(db.is_unlocked());
            assert_eq!(
                db.get_private_key("addr1").unwrap().unwrap(),
                b"secret_key_1".to_vec()
            );
            assert_eq!(db.get(b"meta:label"), Some(b"my wallet".as_ref()));
        }

        // Re-open without passphrase — should be encrypted but locked
        {
            let db = WalletDb::open(&path, None).unwrap();
            assert!(db.is_encrypted());
            assert!(!db.is_unlocked());
        }
    }

    #[test]
    fn put_key_after_encrypt() {
        let mut db = WalletDb::new_memory();
        db.encrypt(b"pass").unwrap();
        db.put_private_key("new_key", b"new_secret").unwrap();
        assert_eq!(
            db.get_private_key("new_key").unwrap().unwrap(),
            b"new_secret".to_vec()
        );

        // Verify it was stored encrypted (raw bytes differ from plaintext)
        let raw = db.data.get(b"privkey:new_key".as_ref()).unwrap();
        assert_ne!(raw, b"new_secret");
    }

    #[test]
    fn missing_key_returns_none() {
        let db = WalletDb::new_memory();
        assert!(db.get_private_key("nonexistent").unwrap().is_none());
    }
}
