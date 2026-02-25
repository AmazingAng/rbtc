use std::fmt;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HashError {
    #[error("invalid hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("invalid length: expected {expected}, got {got}")]
    Length { expected: usize, got: usize },
}

/// 32-byte hash (used for block hashes, txids, etc.)
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    pub const ZERO: Self = Self([0u8; 32]);

    pub fn from_slice(s: &[u8]) -> Result<Self, HashError> {
        if s.len() != 32 {
            return Err(HashError::Length { expected: 32, got: s.len() });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(s);
        Ok(Self(arr))
    }

    /// Parse from hex string (big-endian display, stored little-endian)
    pub fn from_hex(s: &str) -> Result<Self, HashError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(HashError::Length { expected: 32, got: bytes.len() });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        // Bitcoin displays hashes in reversed byte order
        arr.reverse();
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Return display hex (reversed, big-endian display)
    pub fn to_hex(&self) -> String {
        let mut reversed = self.0;
        reversed.reverse();
        hex::encode(reversed)
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash256({})", self.to_hex())
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Default for Hash256 {
    fn default() -> Self {
        Self::ZERO
    }
}

/// 20-byte hash (used for P2PKH/P2SH addresses)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash160(pub [u8; 20]);

impl Hash160 {
    pub const ZERO: Self = Self([0u8; 20]);

    pub fn from_slice(s: &[u8]) -> Result<Self, HashError> {
        if s.len() != 20 {
            return Err(HashError::Length { expected: 20, got: s.len() });
        }
        let mut arr = [0u8; 20];
        arr.copy_from_slice(s);
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl fmt::Debug for Hash160 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash160({})", hex::encode(self.0))
    }
}

impl fmt::Display for Hash160 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Default for Hash160 {
    fn default() -> Self {
        Self::ZERO
    }
}

/// Block hash newtype
pub type BlockHash = Hash256;

/// Transaction ID newtype
pub type TxId = Hash256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash256_from_slice_ok() {
        let bytes = [1u8; 32];
        let h = Hash256::from_slice(&bytes).unwrap();
        assert_eq!(h.0, bytes);
        assert_eq!(h.as_bytes(), &bytes);
    }

    #[test]
    fn hash256_from_slice_wrong_length() {
        assert!(Hash256::from_slice(&[0u8; 31]).is_err());
        assert!(Hash256::from_slice(&[0u8; 33]).is_err());
        let e = Hash256::from_slice(&[0u8; 0]).unwrap_err();
        assert!(matches!(e, HashError::Length { expected: 32, got: 0 }));
    }

    #[test]
    fn hash256_from_hex_ok() {
        let s = "0000000000000000000000000000000000000000000000000000000000000001";
        let h = Hash256::from_hex(s).unwrap();
        let mut expected = [0u8; 32];
        expected[0] = 1;
        assert_eq!(h.0, expected);
        assert_eq!(h.to_hex(), s);
    }

    #[test]
    fn hash256_from_hex_bad_hex() {
        assert!(Hash256::from_hex("zz").is_err());
    }

    #[test]
    fn hash256_from_hex_wrong_length() {
        let short = "00";
        assert!(Hash256::from_hex(short).is_err());
    }

    #[test]
    fn hash256_zero_default_display_debug() {
        assert_eq!(Hash256::ZERO, Hash256::default());
        let h = Hash256::ZERO;
        let _ = format!("{}", h);
        let _ = format!("{:?}", h);
    }

    #[test]
    fn hash160_from_slice_ok() {
        let bytes = [2u8; 20];
        let h = Hash160::from_slice(&bytes).unwrap();
        assert_eq!(h.0, bytes);
        assert_eq!(h.as_bytes(), &bytes);
    }

    #[test]
    fn hash160_from_slice_wrong_length() {
        assert!(Hash160::from_slice(&[0u8; 19]).is_err());
        assert!(Hash160::from_slice(&[0u8; 21]).is_err());
    }

    #[test]
    fn hash160_zero_default_display_debug() {
        assert_eq!(Hash160::ZERO, Hash160::default());
        let h = Hash160::ZERO;
        let _ = format!("{}", h);
        let _ = format!("{:?}", h);
    }
}
