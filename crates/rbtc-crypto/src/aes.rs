//! AES-256-CBC encryption/decryption.
//!
//! Provides PKCS#7-padded AES-256-CBC, matching Bitcoin Core's wallet
//! encryption layer (`CCrypter`).

use aes::cipher::{
    block_padding::Pkcs7, BlockDecrypt, BlockDecryptMut, BlockEncrypt, BlockEncryptMut, KeyInit,
    KeyIvInit,
};
use aes::Aes256;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Encrypt a single 16-byte block with AES-256 in ECB mode (no padding, no IV).
///
/// Matches Bitcoin Core's `AES256Encrypt::Encrypt()`.
pub fn aes256_ecb_encrypt(key: &[u8; 32], plaintext: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes256::new(key.into());
    let mut block = aes::Block::clone_from_slice(plaintext);
    cipher.encrypt_block(&mut block);
    block.into()
}

/// Decrypt a single 16-byte block with AES-256 in ECB mode (no padding, no IV).
///
/// Matches Bitcoin Core's `AES256Decrypt::Decrypt()`.
pub fn aes256_ecb_decrypt(key: &[u8; 32], ciphertext: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes256::new(key.into());
    let mut block = aes::Block::clone_from_slice(ciphertext);
    cipher.decrypt_block(&mut block);
    block.into()
}

/// Encrypt `data` with AES-256-CBC using PKCS#7 padding.
pub fn aes256_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let encryptor = Aes256CbcEnc::new(key.into(), iv.into());
    encryptor.encrypt_padded_vec_mut::<Pkcs7>(data)
}

/// Decrypt `data` with AES-256-CBC, removing PKCS#7 padding.
///
/// Returns an error if the padding is invalid (wrong key / corrupted data).
pub fn aes256_cbc_decrypt(
    key: &[u8; 32],
    iv: &[u8; 16],
    data: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let decryptor = Aes256CbcDec::new(key.into(), iv.into());
    decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(data)
        .map_err(|_| "AES-256-CBC decryption failed: invalid padding")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes256_ecb_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = [0x55u8; 16];
        let ciphertext = aes256_ecb_encrypt(&key, &plaintext);
        assert_ne!(ciphertext, plaintext);
        let decrypted = aes256_ecb_decrypt(&key, &ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes256_ecb_known_vector() {
        // NIST AES-256 ECB test vector (FIPS 197 Appendix C.3)
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let plaintext: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let expected: [u8; 16] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
            0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
        ];

        let ciphertext = aes256_ecb_encrypt(&key, &plaintext);
        assert_eq!(ciphertext, expected);

        let decrypted = aes256_ecb_decrypt(&key, &ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes256_ecb_zero_key_zero_plaintext() {
        let key = [0u8; 32];
        let plaintext = [0u8; 16];
        let ciphertext = aes256_ecb_encrypt(&key, &plaintext);
        // Should produce deterministic non-zero output
        assert_ne!(ciphertext, plaintext);
        let decrypted = aes256_ecb_decrypt(&key, &ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes256_cbc_roundtrip() {
        let key = [0x42u8; 32];
        let iv = [0x13u8; 16];
        let plaintext = b"Bitcoin: A Peer-to-Peer Electronic Cash System";

        let ciphertext = aes256_cbc_encrypt(&key, &iv, plaintext);
        assert_ne!(&ciphertext[..], &plaintext[..]);

        let decrypted = aes256_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn aes256_cbc_roundtrip_empty() {
        let key = [0xffu8; 32];
        let iv = [0x00u8; 16];
        let plaintext = b"";

        let ciphertext = aes256_cbc_encrypt(&key, &iv, plaintext);
        // Even empty plaintext produces a 16-byte block (PKCS#7 padding)
        assert_eq!(ciphertext.len(), 16);

        let decrypted = aes256_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn aes256_cbc_wrong_key_fails() {
        let key = [0x42u8; 32];
        let iv = [0x13u8; 16];
        let plaintext = b"secret data";

        let ciphertext = aes256_cbc_encrypt(&key, &iv, plaintext);

        let wrong_key = [0x00u8; 32];
        let result = aes256_cbc_decrypt(&wrong_key, &iv, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn aes256_cbc_block_aligned() {
        // Test with data that is exactly one block (16 bytes)
        let key = [0xabu8; 32];
        let iv = [0xcdu8; 16];
        let plaintext = [0x55u8; 16];

        let ciphertext = aes256_cbc_encrypt(&key, &iv, &plaintext);
        // Block-aligned input gets an extra padding block
        assert_eq!(ciphertext.len(), 32);

        let decrypted = aes256_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }
}
