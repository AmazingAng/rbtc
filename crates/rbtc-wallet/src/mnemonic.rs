//! BIP39 mnemonic support — thin wrapper around the `bip39` crate.

use bip39::Mnemonic as Bip39Mnemonic;
use rand::RngCore;

use crate::error::WalletError;

/// Wraps a BIP39 mnemonic phrase.
#[derive(Clone)]
pub struct Mnemonic(Bip39Mnemonic);

impl Mnemonic {
    /// Generate a fresh mnemonic with the given word count (12 or 24).
    pub fn generate(word_count: usize) -> Result<Self, WalletError> {
        let entropy_bytes = match word_count {
            12 => 16,
            15 => 20,
            18 => 24,
            21 => 28,
            24 => 32,
            _ => return Err(WalletError::InvalidMnemonic(
                "word_count must be 12, 15, 18, 21, or 24".into(),
            )),
        };
        let mut entropy = vec![0u8; entropy_bytes];
        rand::rngs::OsRng.fill_bytes(&mut entropy);
        Bip39Mnemonic::from_entropy(&entropy)
            .map(Self)
            .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))
    }

    /// Parse a mnemonic from a whitespace-separated phrase string.
    pub fn from_phrase(phrase: &str) -> Result<Self, WalletError> {
        Bip39Mnemonic::parse(phrase)
            .map(Self)
            .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))
    }

    /// Derive the 64-byte BIP39 seed using PBKDF2-HMAC-SHA512.
    /// `passphrase` is the optional BIP39 password (often "").
    pub fn to_seed(&self, passphrase: &str) -> [u8; 64] {
        self.0.to_seed(passphrase)
    }

    /// Return the mnemonic phrase as a string (words separated by spaces).
    pub fn phrase(&self) -> String {
        self.0.to_string()
    }
}

impl std::fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_12_words() {
        let m = Mnemonic::generate(12).unwrap();
        assert_eq!(m.phrase().split_whitespace().count(), 12);
    }

    #[test]
    fn generate_24_words() {
        let m = Mnemonic::generate(24).unwrap();
        assert_eq!(m.phrase().split_whitespace().count(), 24);
    }

    #[test]
    fn roundtrip_phrase() {
        let m = Mnemonic::generate(12).unwrap();
        let phrase = m.phrase();
        let m2 = Mnemonic::from_phrase(&phrase).unwrap();
        assert_eq!(m.to_seed(""), m2.to_seed(""));
    }

    #[test]
    fn invalid_phrase_rejected() {
        assert!(Mnemonic::from_phrase("not valid mnemonic words at all here now").is_err());
    }

    #[test]
    fn seed_differs_with_passphrase() {
        let m = Mnemonic::generate(12).unwrap();
        let s1 = m.to_seed("");
        let s2 = m.to_seed("hunter2");
        assert_ne!(s1, s2);
    }
}
