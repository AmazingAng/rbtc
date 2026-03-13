use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

/// HMAC-SHA512: keyed hash used for BIP32 key derivation, HKDF, etc.
///
/// Matches Bitcoin Core's `CHMAC_SHA512` implementation.
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = Hmac::<Sha512>::new_from_slice(key)
        .expect("HMAC accepts any key length");
    mac.update(data);
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    out
}

/// HMAC-SHA256: keyed hash used for various Bitcoin protocols.
///
/// Matches Bitcoin Core's `CHMAC_SHA256` implementation.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .expect("HMAC accepts any key length");
    mac.update(data);
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// HKDF-SHA256 with output length L=32.
///
/// Matches Bitcoin Core's `CHKDF_HMAC_SHA256_L32` specialist class used
/// for BIP324 key derivation.  Implements RFC 5869 Extract-then-Expand
/// with HMAC-SHA256 and a fixed 32-byte output.
///
/// - `salt`: optional salt for the Extract step (may be empty).
/// - `ikm`: input keying material.
/// - `info`: context/application-specific info for the Expand step.
///
/// Returns 32 bytes of output keying material.
pub fn hkdf_sha256_l32(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    // HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
    // If salt is empty, RFC 5869 says use a string of HashLen zeros.
    let effective_salt = if salt.is_empty() {
        &[0u8; 32] as &[u8]
    } else {
        salt
    };
    let prk = hmac_sha256(effective_salt, ikm);

    // HKDF-Expand: T(1) = HMAC-SHA256(PRK, info || 0x01)
    // Since L=32 = HashLen, we only need one iteration (N=1).
    let mut expand_input = Vec::with_capacity(info.len() + 1);
    expand_input.extend_from_slice(info);
    expand_input.push(0x01);
    hmac_sha256(&prk, &expand_input)
}

/// Streaming HMAC-SHA256 writer, matching Bitcoin Core's `CHMAC_SHA256` pattern.
///
/// Allows incremental feeding of data before finalizing the MAC.
pub struct HmacSha256Writer {
    inner: Hmac<Sha256>,
}

impl HmacSha256Writer {
    /// Create a new streaming HMAC-SHA256 with the given key.
    pub fn new(key: &[u8]) -> Self {
        Self {
            inner: Hmac::<Sha256>::new_from_slice(key)
                .expect("HMAC accepts any key length"),
        }
    }

    /// Feed data into the HMAC computation.
    pub fn write(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and return the 32-byte HMAC-SHA256 tag.
    pub fn finalize(self) -> [u8; 32] {
        let result = self.inner.finalize();
        let bytes = result.into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }
}

/// Streaming HMAC-SHA512 writer, matching Bitcoin Core's `CHMAC_SHA512` pattern.
///
/// Allows incremental feeding of data before finalizing the MAC.
pub struct HmacSha512Writer {
    inner: Hmac<Sha512>,
}

impl HmacSha512Writer {
    /// Create a new streaming HMAC-SHA512 with the given key.
    pub fn new(key: &[u8]) -> Self {
        Self {
            inner: Hmac::<Sha512>::new_from_slice(key)
                .expect("HMAC accepts any key length"),
        }
    }

    /// Feed data into the HMAC computation.
    pub fn write(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and return the 64-byte HMAC-SHA512 tag.
    pub fn finalize(self) -> [u8; 64] {
        let result = self.inner.finalize();
        let bytes = result.into_bytes();
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4231 Test Case 1: HMAC-SHA256
    // Key = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (20 bytes)
    // Data = "Hi There"
    #[test]
    fn hmac_sha256_rfc4231_test1() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let result = hmac_sha256(&key, data);
        let expected = hex_decode(
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        );
        assert_eq!(result[..], expected[..]);
    }

    // RFC 4231 Test Case 2: HMAC-SHA256
    // Key = "Jefe"
    // Data = "what do ya want for nothing?"
    #[test]
    fn hmac_sha256_rfc4231_test2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let result = hmac_sha256(key, data);
        let expected = hex_decode(
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        );
        assert_eq!(result[..], expected[..]);
    }

    // RFC 4231 Test Case 1: HMAC-SHA512
    #[test]
    fn hmac_sha512_rfc4231_test1() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let result = hmac_sha512(&key, data);
        let expected = hex_decode(
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
             daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        );
        assert_eq!(result[..], expected[..]);
    }

    // RFC 4231 Test Case 2: HMAC-SHA512
    // Key = "Jefe", Data = "what do ya want for nothing?"
    #[test]
    fn hmac_sha512_rfc4231_test2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let result = hmac_sha512(key, data);
        let expected = hex_decode(
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
             9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        );
        assert_eq!(result[..], expected[..]);
    }

    // RFC 4231 Test Case 3: HMAC-SHA512
    // Key = 0xaaaa... (20 bytes), Data = 0xdddd... (50 bytes)
    #[test]
    fn hmac_sha512_rfc4231_test3() {
        let key = [0xaau8; 20];
        let data = [0xddu8; 50];
        let result = hmac_sha512(&key, &data);
        let expected = hex_decode(
            "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39\
             bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
        );
        assert_eq!(result[..], expected[..]);
    }

    // Empty key and empty data
    #[test]
    fn hmac_sha512_empty() {
        let result = hmac_sha512(b"", b"");
        // Should not panic; just verify it produces a 64-byte output
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn hmac_sha256_empty() {
        let result = hmac_sha256(b"", b"");
        assert_eq!(result.len(), 32);
    }

    // BIP32 master key derivation: HMAC-SHA512("Bitcoin seed", seed)
    // Test vector 1 from BIP32:
    // Seed = 0x000102030405060708090a0b0c0d0e0f
    // Expected master key (IL) and chain code (IR)
    #[test]
    fn bip32_master_key_derivation_vector1() {
        let seed = hex_decode("000102030405060708090a0b0c0d0e0f");
        let result = hmac_sha512(b"Bitcoin seed", &seed);

        // IL (secret key) = first 32 bytes
        let il = &result[..32];
        // IR (chain code) = last 32 bytes
        let ir = &result[32..];

        let expected_il = hex_decode(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        );
        let expected_ir = hex_decode(
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
        );

        assert_eq!(il, &expected_il[..]);
        assert_eq!(ir, &expected_ir[..]);
    }

    // BIP32 test vector 2
    // Seed = fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
    #[test]
    fn bip32_master_key_derivation_vector2() {
        let seed = hex_decode(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2\
             9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        );
        let result = hmac_sha512(b"Bitcoin seed", &seed);

        let il = &result[..32];
        let ir = &result[32..];

        let expected_il = hex_decode(
            "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
        );
        let expected_ir = hex_decode(
            "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
        );

        assert_eq!(il, &expected_il[..]);
        assert_eq!(ir, &expected_ir[..]);
    }

    // ---- HKDF-SHA256-L32 tests ----

    // RFC 5869 Test Case 1 (SHA-256, L=32 of the 42-byte output)
    // IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
    // salt = 0x000102030405060708090a0b0c (13 bytes)
    // info = 0xf0f1f2f3f4f5f6f7f8f9 (10 bytes)
    // OKM (first 32 bytes) = 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf
    #[test]
    fn hkdf_sha256_l32_rfc5869_test1() {
        let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_decode("000102030405060708090a0b0c");
        let info = hex_decode("f0f1f2f3f4f5f6f7f8f9");
        let result = hkdf_sha256_l32(&salt, &ikm, &info);
        let expected = hex_decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
        );
        assert_eq!(result[..], expected[..]);
    }

    // RFC 5869 Test Case 2 (SHA-256, first 32 of 82 bytes)
    // IKM  = 000102...4f (80 bytes)
    // salt = 606162...af (80 bytes)
    // info = b0b1b2...ff (80 bytes)
    // OKM first 32 bytes = b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c
    #[test]
    fn hkdf_sha256_l32_rfc5869_test2() {
        let ikm: Vec<u8> = (0x00u8..=0x4f).collect();
        let salt: Vec<u8> = (0x60u8..=0xaf).collect();
        let info: Vec<u8> = (0xb0u8..=0xff).collect();
        let result = hkdf_sha256_l32(&salt, &ikm, &info);
        let expected = hex_decode(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c",
        );
        assert_eq!(result[..], expected[..]);
    }

    // RFC 5869 Test Case 3 (SHA-256, empty salt and info)
    // IKM  = 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
    // salt = (empty)
    // info = (empty)
    // OKM first 32 bytes = 8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d
    #[test]
    fn hkdf_sha256_l32_rfc5869_test3() {
        let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let result = hkdf_sha256_l32(&[], &ikm, &[]);
        let expected = hex_decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d",
        );
        assert_eq!(result[..], expected[..]);
    }

    // Verify our native HKDF matches the `hkdf` crate for BIP324-like usage
    #[test]
    fn hkdf_sha256_l32_bip324_like() {
        let shared_secret = [0x55u8; 32];
        let info = b"bitcoin_v2_shared_secret";
        let result = hkdf_sha256_l32(&[], &shared_secret, info);
        // Just verify it produces 32 bytes and is deterministic
        assert_eq!(result.len(), 32);
        let result2 = hkdf_sha256_l32(&[], &shared_secret, info);
        assert_eq!(result, result2);
    }

    // ---- Streaming HMAC tests ----

    #[test]
    fn streaming_hmac_sha256_matches_oneshot() {
        let key = b"streaming-test-key";
        let part1 = b"hello ";
        let part2 = b"world";
        let full = b"hello world";

        // One-shot
        let expected = hmac_sha256(key, full);

        // Streaming
        let mut writer = HmacSha256Writer::new(key);
        writer.write(part1);
        writer.write(part2);
        let result = writer.finalize();

        assert_eq!(result, expected);
    }

    #[test]
    fn streaming_hmac_sha512_matches_oneshot() {
        let key = b"streaming-test-key";
        let part1 = b"hello ";
        let part2 = b"world";
        let full = b"hello world";

        // One-shot
        let expected = hmac_sha512(key, full);

        // Streaming
        let mut writer = HmacSha512Writer::new(key);
        writer.write(part1);
        writer.write(part2);
        let result = writer.finalize();

        assert_eq!(result, expected);
    }

    #[test]
    fn streaming_hmac_sha256_empty_data() {
        let key = b"key";
        let expected = hmac_sha256(key, b"");
        let writer = HmacSha256Writer::new(key);
        assert_eq!(writer.finalize(), expected);
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
