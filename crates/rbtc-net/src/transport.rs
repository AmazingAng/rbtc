use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};

use crate::bip324;

/// BIP324 rekey interval: rekey the cipher after every 224 messages.
///
/// This matches Bitcoin Core's `BIP324Cipher::REKEY_INTERVAL` (224), not 2^24.
pub const REKEY_INTERVAL: u32 = 224;

/// Forward-secure ChaCha20 stream cipher (FSChaCha20).
///
/// This matches Bitcoin Core's `FSChaCha20` in `src/crypto/chacha20.h`.
/// It wraps a ChaCha20 stream cipher and automatically rekeys after
/// `rekey_interval` `crypt()` calls by consuming 32 bytes of keystream
/// as the new key, then seeking the new cipher to nonce `{0, rekey_counter}`.
///
/// Used for the BIP324 L (length) cipher to encrypt 3-byte message lengths.
pub struct FSChaCha20 {
    /// Current 32-byte key.
    key: [u8; 32],
    /// The rekey interval (number of crypt() calls between rekeys).
    rekey_interval: u32,
    /// Number of crypt() calls since the last rekey (0..rekey_interval).
    chunk_counter: u32,
    /// Number of rekeys performed so far; used as nonce after rekey.
    rekey_counter: u64,
    /// Buffered keystream from the current ChaCha20 block.
    /// We generate a full 64-byte block and consume bytes from it.
    buffer: [u8; 64],
    /// Number of unconsumed bytes remaining in `buffer` (at the tail end).
    buf_left: usize,
    /// The current block counter for seeking within the stream.
    block_counter: u32,
}

impl FSChaCha20 {
    /// Create a new FSChaCha20 with the given 32-byte key and rekey interval.
    pub fn new(key: &[u8; 32], rekey_interval: u32) -> Self {
        Self {
            key: *key,
            rekey_interval,
            chunk_counter: 0,
            rekey_counter: 0,
            buffer: [0u8; 64],
            buf_left: 0,
            block_counter: 0,
        }
    }

    /// Build a 12-byte nonce from (nonce_first: u32, nonce_last: u64).
    /// Layout: [nonce_first as LE32][nonce_last as LE64] = 12 bytes.
    fn build_nonce(first: u32, last: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&first.to_le_bytes());
        nonce[4..12].copy_from_slice(&last.to_le_bytes());
        nonce
    }

    /// Generate keystream bytes from the internal ChaCha20 state.
    /// This creates a fresh ChaCha20 instance at the current position
    /// and generates exactly `out.len()` bytes of keystream.
    fn keystream(&mut self, out: &mut [u8]) {
        // We need to handle the buffered state properly.
        // For simplicity matching Bitcoin Core: we maintain a buffer of one
        // ChaCha20 block (64 bytes) and consume from it.
        let mut offset = 0;
        while offset < out.len() {
            if self.buf_left == 0 {
                // Generate a new block of keystream
                let nonce = Self::build_nonce(0, self.rekey_counter);
                let mut cipher = chacha20::ChaCha20::new(
                    (&self.key).into(),
                    (&nonce).into(),
                );
                // Seek to the current block counter
                // ChaCha20 in the chacha20 crate starts at counter 0.
                // We need to skip `block_counter` blocks of 64 bytes.
                if self.block_counter > 0 {
                    let skip = self.block_counter as usize * 64;
                    let mut discard = vec![0u8; skip];
                    cipher.apply_keystream(&mut discard);
                }
                // Generate one block
                self.buffer = [0u8; 64];
                cipher.apply_keystream(&mut self.buffer);
                self.buf_left = 64;
                self.block_counter += 1;
            }

            let start = 64 - self.buf_left;
            let available = self.buf_left;
            let needed = out.len() - offset;
            let take = available.min(needed);
            out[offset..offset + take].copy_from_slice(&self.buffer[start..start + take]);
            self.buf_left -= take;
            offset += take;
        }
    }

    /// Encrypt or decrypt `input` into `output` (XOR with keystream).
    /// After each call, checks if a rekey is needed.
    pub fn crypt(&mut self, input: &[u8], output: &mut [u8]) {
        assert_eq!(input.len(), output.len());

        // XOR with keystream
        let mut ks = vec![0u8; input.len()];
        self.keystream(&mut ks);
        for i in 0..input.len() {
            output[i] = input[i] ^ ks[i];
        }

        // Check rekey
        self.chunk_counter += 1;
        if self.chunk_counter == self.rekey_interval {
            // Get 32 bytes of keystream as new key
            let mut new_key = [0u8; 32];
            self.keystream(&mut new_key);

            // Update key and reset state
            self.key = new_key;
            self.rekey_counter += 1;
            self.chunk_counter = 0;
            self.block_counter = 0;
            self.buf_left = 0;
        }
    }

    /// Return the current chunk counter (for testing).
    pub fn chunk_counter(&self) -> u32 {
        self.chunk_counter
    }

    /// Return the current rekey counter (for testing).
    pub fn rekey_counter(&self) -> u64 {
        self.rekey_counter
    }
}

/// BIP324 v2 encrypted message frame.
///
/// Wire format (per BIP324):
/// ```text
/// [3 bytes: encrypted length (LE, encrypted with L cipher / FSChaCha20)]
/// [encrypted payload (encrypted with P cipher / FSChaCha20Poly1305)]:
///   [1 byte: header — bit 7 = ignore/decoy]
///   [remaining: message contents]
///     for short-id messages: [1 byte: short command ID] [payload]
///     for long-form messages: [0x00] [12 bytes: ASCII command] [payload]
/// [16 bytes: Poly1305 tag]
/// ```
///
/// The rekey mechanism matches Bitcoin Core's `FSChaCha20Poly1305::NextPacket()`:
/// after every REKEY_INTERVAL (224) messages, generate a ChaCha20 keystream block
/// at nonce `{0xFFFFFFFF, rekey_counter}` (via the AEAD cipher — encrypting 32
/// zero bytes, which yields keystream from block 1 per RFC 8439), take the first
/// 32 bytes as the new AEAD key, reset the packet counter, and increment the
/// rekey counter.
///
/// Nonce structure: `{packet_counter (LE32), rekey_counter (LE64)}` = 96 bits,
/// matching Bitcoin Core's `AEADChaCha20Poly1305::Nonce96`.
pub struct V2Cipher {
    /// P cipher for payload AEAD (send direction).
    send_p_cipher: ChaCha20Poly1305,
    /// P cipher for payload AEAD (receive direction).
    recv_p_cipher: ChaCha20Poly1305,
    /// L cipher for length encryption (send direction), keyed from `send_l_key`.
    send_l_cipher: FSChaCha20,
    /// L cipher for length decryption (receive direction), keyed from `recv_l_key`.
    recv_l_cipher: FSChaCha20,
    /// Number of messages encrypted since last send rekey (packet counter).
    send_packet_counter: u32,
    /// Number of messages decrypted since last recv rekey (packet counter).
    recv_packet_counter: u32,
    /// Number of send rekeys performed so far.
    send_rekey_counter: u64,
    /// Number of recv rekeys performed so far.
    recv_rekey_counter: u64,
}

impl V2Cipher {
    /// Create a new V2Cipher from session keys.
    ///
    /// Uses the P (payload) keys for the ChaCha20Poly1305 AEAD cipher and the
    /// L (length) keys for FSChaCha20 length encryption, matching Bitcoin Core's
    /// `BIP324Cipher` which uses separate L and P ciphers per direction.
    pub fn new(keys: &bip324::SessionKeys) -> Self {
        let send_p_cipher = ChaCha20Poly1305::new_from_slice(&keys.send_p_key)
            .expect("32-byte key is valid for ChaCha20Poly1305");
        let recv_p_cipher = ChaCha20Poly1305::new_from_slice(&keys.recv_p_key)
            .expect("32-byte key is valid for ChaCha20Poly1305");
        let send_l_cipher = FSChaCha20::new(&keys.send_l_key, REKEY_INTERVAL);
        let recv_l_cipher = FSChaCha20::new(&keys.recv_l_key, REKEY_INTERVAL);
        Self {
            send_p_cipher,
            recv_p_cipher,
            send_l_cipher,
            recv_l_cipher,
            send_packet_counter: 0,
            recv_packet_counter: 0,
            send_rekey_counter: 0,
            recv_rekey_counter: 0,
        }
    }

    /// Build the 12-byte nonce from packet_counter (u32) and rekey_counter (u64).
    ///
    /// Bitcoin Core nonce layout: {packet_counter (LE32), rekey_counter (LE64)} = 96 bits.
    /// This matches `AEADChaCha20Poly1305::Nonce96`.
    fn nonce_bytes(packet_counter: u32, rekey_counter: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&packet_counter.to_le_bytes());
        nonce[4..12].copy_from_slice(&rekey_counter.to_le_bytes());
        nonce
    }

    /// Rekey a P cipher by generating a keystream block at the special rekey nonce.
    ///
    /// This matches Bitcoin Core's `FSChaCha20Poly1305::NextPacket()`:
    /// - Use nonce = `{0xFFFFFFFF (LE32), rekey_counter (LE64)}`
    /// - The AEAD's `Keystream()` generates keystream from ChaCha20 block 1
    ///   (block 0 is reserved for the poly1305 key per RFC 8439)
    /// - Take the first 32 bytes as the new AEAD key
    /// - Reset packet_counter to 0, increment rekey_counter
    ///
    /// We achieve this by encrypting 32 zero bytes (empty AAD) with the current
    /// AEAD cipher at the special nonce. Since RFC 8439 uses block 0 for the
    /// poly1305 key and block 1+ for encryption, encrypting zeros gives us
    /// `keystream_block1 XOR 0 = keystream_block1`, matching Bitcoin Core's
    /// `AEADChaCha20Poly1305::Keystream()`.
    fn rekey_cipher(
        cipher: &mut ChaCha20Poly1305,
        rekey_counter: &mut u64,
        packet_counter: &mut u32,
    ) {
        // Special rekey nonce: {0xFFFFFFFF, rekey_counter}
        let nonce = Self::nonce_bytes(0xFFFF_FFFF_u32, *rekey_counter);

        // Encrypt 32 zero bytes with empty AAD.
        // Result = 32 bytes ciphertext (= keystream from block 1) + 16 bytes poly1305 tag.
        let zeros = [0u8; 32];
        let ciphertext = cipher
            .encrypt(&nonce.into(), zeros.as_ref())
            .expect("encryption of 32 zero bytes should not fail");

        // First 32 bytes of ciphertext are the new key
        let mut new_key = [0u8; 32];
        new_key.copy_from_slice(&ciphertext[..32]);

        *cipher = ChaCha20Poly1305::new_from_slice(&new_key)
            .expect("32-byte key is valid for ChaCha20Poly1305");

        // Reset packet counter, increment rekey counter
        *packet_counter = 0;
        *rekey_counter += 1;
    }

    /// Advance the send cipher: increment packet counter, rekey if needed.
    ///
    /// This matches Bitcoin Core's `FSChaCha20Poly1305::NextPacket()` which
    /// increments the counter first, then checks if it equals `m_rekey_interval`.
    fn next_send_packet(&mut self) {
        self.send_packet_counter += 1;
        if self.send_packet_counter == REKEY_INTERVAL {
            Self::rekey_cipher(
                &mut self.send_p_cipher,
                &mut self.send_rekey_counter,
                &mut self.send_packet_counter,
            );
        }
    }

    /// Advance the recv cipher: increment packet counter, rekey if needed.
    fn next_recv_packet(&mut self) {
        self.recv_packet_counter += 1;
        if self.recv_packet_counter == REKEY_INTERVAL {
            Self::rekey_cipher(
                &mut self.recv_p_cipher,
                &mut self.recv_rekey_counter,
                &mut self.recv_packet_counter,
            );
        }
    }

    /// Encrypt a message frame (command + payload) for sending.
    ///
    /// Returns the complete wire frame: 3-byte encrypted length + ciphertext + tag.
    pub fn encrypt_message(&mut self, command: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
        self.encrypt_message_with_flags(command, payload, 0)
    }

    /// Encrypt a decoy message (ignore flag set).
    pub fn encrypt_decoy(&mut self, payload: &[u8]) -> Result<Vec<u8>, String> {
        self.encrypt_message_with_flags("", payload, 0x80)
    }

    fn encrypt_message_with_flags(
        &mut self,
        command: &str,
        payload: &[u8],
        header_byte: u8,
    ) -> Result<Vec<u8>, String> {
        // Build plaintext: header_byte + command encoding + payload
        // The header byte's bit 7 (0x80) is the ignore/decoy flag (matching
        // Bitcoin Core's IGNORE_BIT).
        let mut plaintext = Vec::new();
        plaintext.push(header_byte);

        if let Some(id) = bip324::v2_command_id(command) {
            plaintext.push(id);
        } else if !command.is_empty() {
            plaintext.push(0); // long-form command
            let mut cmd_bytes = [0u8; 12];
            let cmd = command.as_bytes();
            let len = cmd.len().min(12);
            cmd_bytes[..len].copy_from_slice(&cmd[..len]);
            plaintext.extend_from_slice(&cmd_bytes);
        }

        plaintext.extend_from_slice(payload);

        // Build nonce from current counters: {packet_counter, rekey_counter}
        let nonce = Self::nonce_bytes(self.send_packet_counter, self.send_rekey_counter);

        let ciphertext = self
            .send_p_cipher
            .encrypt(&nonce.into(), plaintext.as_ref())
            .map_err(|e| format!("encryption error: {e}"))?;

        // Advance counter (and rekey if needed) AFTER encrypting, matching
        // Bitcoin Core's Encrypt() then NextPacket() sequence.
        self.next_send_packet();

        // Wire frame: 3-byte encrypted length (via L cipher) + ciphertext
        let ct_len = ciphertext.len() as u32;
        let len_plaintext = [ct_len.to_le_bytes()[0], ct_len.to_le_bytes()[1], ct_len.to_le_bytes()[2]];
        let mut len_encrypted = [0u8; 3];
        self.send_l_cipher.crypt(&len_plaintext, &mut len_encrypted);

        let mut frame = Vec::with_capacity(3 + ciphertext.len());
        frame.extend_from_slice(&len_encrypted);
        frame.extend_from_slice(&ciphertext);
        Ok(frame)
    }

    /// Decrypt a received message frame.
    ///
    /// Input should be the raw ciphertext (after reading 3-byte length prefix).
    /// Returns `(command, payload, is_decoy)`.
    pub fn decrypt_message(
        &mut self,
        ciphertext: &[u8],
    ) -> Result<(String, Vec<u8>, bool), String> {
        let nonce = Self::nonce_bytes(self.recv_packet_counter, self.recv_rekey_counter);

        let plaintext = self
            .recv_p_cipher
            .decrypt(&nonce.into(), ciphertext)
            .map_err(|e| format!("decryption error: {e}"))?;

        // Advance counter (and rekey if needed) AFTER decrypting
        self.next_recv_packet();

        if plaintext.is_empty() {
            return Err("empty plaintext".into());
        }

        let header_byte = plaintext[0];
        let is_decoy = (header_byte & 0x80) != 0;

        if plaintext.len() < 2 {
            // Decoy/ignore packets may have no command content
            if is_decoy {
                return Ok(("".to_string(), vec![], true));
            }
            return Err("plaintext too short for command".into());
        }

        let command_id = plaintext[1];
        let (command, payload_start) = if command_id == 0 {
            // Long-form: 12-byte ASCII command follows
            if plaintext.len() < 14 {
                return Err("plaintext too short for long-form command".into());
            }
            let cmd_bytes = &plaintext[2..14];
            let cmd = std::str::from_utf8(cmd_bytes)
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_string();
            (cmd, 14)
        } else {
            let cmd = bip324::v2_command_name(command_id)
                .unwrap_or("unknown")
                .to_string();
            (cmd, 2)
        };

        let payload = plaintext[payload_start..].to_vec();
        Ok((command, payload, is_decoy))
    }

    /// Decrypt a 3-byte encrypted length prefix using the receive L cipher.
    ///
    /// This must be called once per received message, before `decrypt_message()`,
    /// to recover the plaintext length from the FSChaCha20-encrypted length bytes.
    pub fn decrypt_length(&mut self, encrypted_len: &[u8; 3]) -> u32 {
        let mut plaintext = [0u8; 3];
        self.recv_l_cipher.crypt(encrypted_len, &mut plaintext);
        u32::from_le_bytes([plaintext[0], plaintext[1], plaintext[2], 0])
    }

    /// Current send packet counter (for testing/debugging).
    pub fn send_packet_counter(&self) -> u32 {
        self.send_packet_counter
    }

    /// Current recv packet counter (for testing/debugging).
    pub fn recv_packet_counter(&self) -> u32 {
        self.recv_packet_counter
    }

    /// Number of send rekeys performed (for testing/debugging).
    pub fn send_rekey_counter(&self) -> u64 {
        self.send_rekey_counter
    }

    /// Number of recv rekeys performed (for testing/debugging).
    pub fn recv_rekey_counter(&self) -> u64 {
        self.recv_rekey_counter
    }
}

/// Read the 3-byte LE length prefix from a frame.
pub fn read_frame_length(header: &[u8; 3]) -> u32 {
    u32::from_le_bytes([header[0], header[1], header[2], 0])
}

/// Encode a 3-byte LE length prefix.
pub fn write_frame_length(len: u32) -> [u8; 3] {
    let bytes = len.to_le_bytes();
    [bytes[0], bytes[1], bytes[2]]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip324::{derive_session_keys, generate_ephemeral_keypair, ecdh_shared_secret};

    /// Default mainnet magic for tests.
    const MAINNET_MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];

    fn make_cipher_pair() -> (V2Cipher, V2Cipher) {
        let (sk_a, es_a) = generate_ephemeral_keypair();
        let (_sk_b, es_b) = generate_ephemeral_keypair();
        let shared = ecdh_shared_secret(&sk_a, &es_a, &es_b, true);
        let init_keys = derive_session_keys(&shared.to_secret_bytes(), true, &MAINNET_MAGIC);
        let resp_keys = derive_session_keys(&shared.to_secret_bytes(), false, &MAINNET_MAGIC);
        (V2Cipher::new(&init_keys), V2Cipher::new(&resp_keys))
    }

    /// Helper: extract encrypted length from frame, decrypt it, return (len, ciphertext_slice).
    fn decode_frame<'a>(receiver: &mut V2Cipher, frame: &'a [u8]) -> (u32, &'a [u8]) {
        let enc_len = [frame[0], frame[1], frame[2]];
        let len = receiver.decrypt_length(&enc_len);
        let ct = &frame[3..3 + len as usize];
        (len, ct)
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let (mut sender, mut receiver) = make_cipher_pair();
        let frame = sender.encrypt_message("ping", b"test payload").unwrap();

        // Extract length (encrypted) and ciphertext
        let (_, ct) = decode_frame(&mut receiver, &frame);

        let (cmd, payload, is_decoy) = receiver.decrypt_message(ct).unwrap();
        assert_eq!(cmd, "ping");
        assert_eq!(payload, b"test payload");
        assert!(!is_decoy);
    }

    #[test]
    fn short_command_id_roundtrip() {
        let (mut sender, mut receiver) = make_cipher_pair();

        let commands = ["block", "tx", "inv", "headers", "getdata"];
        for cmd in commands {
            let frame = sender.encrypt_message(cmd, b"").unwrap();
            let (_, ct) = decode_frame(&mut receiver, &frame);
            let (got_cmd, payload, _) = receiver.decrypt_message(ct).unwrap();
            assert_eq!(got_cmd, cmd);
            assert!(payload.is_empty());
        }
    }

    #[test]
    fn unknown_command_uses_long_form() {
        let (mut sender, mut receiver) = make_cipher_pair();
        let frame = sender.encrypt_message("customcmd", b"data").unwrap();
        let (_, ct) = decode_frame(&mut receiver, &frame);
        let (cmd, payload, _) = receiver.decrypt_message(ct).unwrap();
        assert_eq!(cmd, "customcmd");
        assert_eq!(payload, b"data");
    }

    #[test]
    fn version_verack_use_long_form() {
        // version and verack are NOT in the BIP324 short-id table
        let (mut sender, mut receiver) = make_cipher_pair();
        for cmd in &["version", "verack"] {
            let frame = sender.encrypt_message(cmd, b"v1").unwrap();
            let (_, ct) = decode_frame(&mut receiver, &frame);
            let (got_cmd, got_payload, _) = receiver.decrypt_message(ct).unwrap();
            assert_eq!(&got_cmd, cmd);
            assert_eq!(got_payload, b"v1");
        }
    }

    #[test]
    fn packet_counter_increments_per_message() {
        let (mut sender, mut receiver) = make_cipher_pair();
        assert_eq!(sender.send_packet_counter(), 0);
        assert_eq!(receiver.recv_packet_counter(), 0);

        for i in 0u8..5 {
            let frame = sender.encrypt_message("ping", &[i]).unwrap();
            let (_, ct) = decode_frame(&mut receiver, &frame);
            receiver.decrypt_message(ct).unwrap();
        }

        assert_eq!(sender.send_packet_counter(), 5);
        assert_eq!(receiver.recv_packet_counter(), 5);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (mut sender, mut receiver) = make_cipher_pair();
        let mut frame = sender.encrypt_message("block", b"data").unwrap();

        // Tamper with ciphertext (not the length prefix)
        let mid = 3 + (frame.len() - 3) / 2;
        frame[mid] ^= 0xFF;

        let (_, ct) = decode_frame(&mut receiver, &frame);
        let result = receiver.decrypt_message(ct);
        assert!(result.is_err());
    }

    #[test]
    fn decoy_messages() {
        let (mut sender, mut receiver) = make_cipher_pair();
        let frame = sender.encrypt_decoy(b"ignore me").unwrap();
        let (_, ct) = decode_frame(&mut receiver, &frame);
        let (_, _, is_decoy) = receiver.decrypt_message(ct).unwrap();
        assert!(is_decoy);
    }

    #[test]
    fn empty_payload() {
        let (mut sender, mut receiver) = make_cipher_pair();
        let frame = sender.encrypt_message("pong", b"").unwrap();
        let (_, ct) = decode_frame(&mut receiver, &frame);
        let (cmd, payload, _) = receiver.decrypt_message(ct).unwrap();
        assert_eq!(cmd, "pong");
        assert!(payload.is_empty());
    }

    #[test]
    fn large_payload() {
        let (mut sender, mut receiver) = make_cipher_pair();
        let big = vec![0x42u8; 100_000]; // 100KB
        let frame = sender.encrypt_message("block", &big).unwrap();
        let (_, ct) = decode_frame(&mut receiver, &frame);
        let (cmd, payload, _) = receiver.decrypt_message(ct).unwrap();
        assert_eq!(cmd, "block");
        assert_eq!(payload.len(), 100_000);
        assert_eq!(payload, big);
    }

    #[test]
    fn multiple_sequential_messages() {
        let (mut sender, mut receiver) = make_cipher_pair();
        // version and verack now use long-form (not in short-id table)
        let messages = vec![
            ("version", b"v1".to_vec()),
            ("verack", vec![]),
            ("ping", vec![1, 2, 3, 4, 5, 6, 7, 8]),
            ("pong", vec![1, 2, 3, 4, 5, 6, 7, 8]),
            ("getdata", vec![0xAA; 36]),
        ];

        for (cmd, payload) in &messages {
            let frame = sender.encrypt_message(cmd, payload).unwrap();
            let (_, ct) = decode_frame(&mut receiver, &frame);
            let (got_cmd, got_payload, _) = receiver.decrypt_message(ct).unwrap();
            assert_eq!(&got_cmd, cmd);
            assert_eq!(&got_payload, payload);
        }
    }

    #[test]
    fn frame_length_encode_decode() {
        let len = 0x01_23_45u32;
        let encoded = write_frame_length(len);
        let decoded = read_frame_length(&encoded);
        assert_eq!(decoded, len);

        // Small value
        let encoded = write_frame_length(42);
        let decoded = read_frame_length(&encoded);
        assert_eq!(decoded, 42);

        // Max 3-byte value
        let max = 0xFF_FF_FF;
        let encoded = write_frame_length(max);
        let decoded = read_frame_length(&encoded);
        assert_eq!(decoded, max);
    }

    #[test]
    fn wrong_nonce_fails_decryption() {
        let (mut sender, mut receiver) = make_cipher_pair();

        // Send two messages
        let _frame1 = sender.encrypt_message("ping", b"first").unwrap();
        let frame2 = sender.encrypt_message("pong", b"second").unwrap();

        // Try to decrypt frame2 first (skipping frame1).
        // frame2 was encrypted with packet_counter=1, but receiver is at packet_counter=0.
        // Consume L cipher state for consistency, then use the actual P ciphertext.
        let enc_len2 = [frame2[0], frame2[1], frame2[2]];
        let _ = receiver.decrypt_length(&enc_len2);
        let ct2 = &frame2[3..];
        let result = receiver.decrypt_message(ct2);
        assert!(result.is_err(), "out-of-order message should fail AEAD auth");
    }

    #[test]
    fn rekey_interval_constant() {
        // Bitcoin Core uses REKEY_INTERVAL = 224
        assert_eq!(REKEY_INTERVAL, 224);
    }

    #[test]
    fn rekey_happens_at_message_224() {
        // Verify rekey triggers after exactly REKEY_INTERVAL (224) messages
        let (mut sender, mut receiver) = make_cipher_pair();

        // Send 224 messages — rekey should trigger after the 224th
        for i in 0..REKEY_INTERVAL {
            let frame = sender
                .encrypt_message("ping", &(i as u32).to_le_bytes())
                .unwrap();
            let (_, ct) = decode_frame(&mut receiver, &frame);
            receiver.decrypt_message(ct).unwrap();
        }

        // After 224 messages, both sides should have rekeyed:
        // packet_counter reset to 0, rekey_counter incremented to 1
        assert_eq!(sender.send_packet_counter(), 0);
        assert_eq!(sender.send_rekey_counter(), 1);
        assert_eq!(receiver.recv_packet_counter(), 0);
        assert_eq!(receiver.recv_rekey_counter(), 1);
    }

    #[test]
    fn messages_after_rekey_decrypt_correctly() {
        // Send messages across the rekey boundary and verify they still decrypt
        let (mut sender, mut receiver) = make_cipher_pair();

        // Send REKEY_INTERVAL + 10 messages
        let total = REKEY_INTERVAL + 10;
        for i in 0..total {
            let frame = sender
                .encrypt_message("ping", &(i as u32).to_le_bytes())
                .unwrap();
            let (_, ct) = decode_frame(&mut receiver, &frame);
            let (cmd, payload, _) = receiver.decrypt_message(ct).unwrap();
            assert_eq!(cmd, "ping");
            assert_eq!(payload, (i as u32).to_le_bytes());
        }

        // Verify state: packet_counter should be 10, rekey_counter should be 1
        assert_eq!(sender.send_packet_counter(), 10);
        assert_eq!(sender.send_rekey_counter(), 1);
    }

    #[test]
    fn rekey_produces_different_key() {
        // Verify the rekey actually changes the cipher by checking that
        // encrypting the same plaintext before and after rekey produces
        // different ciphertext (different key + packet_counter=0 in both cases).
        let (sk_a, es_a) = generate_ephemeral_keypair();
        let (_sk_b, es_b) = generate_ephemeral_keypair();
        let shared = ecdh_shared_secret(&sk_a, &es_a, &es_b, true);
        let keys = derive_session_keys(&shared.to_secret_bytes(), true, &MAINNET_MAGIC);

        // First cipher: encrypt at packet_counter=0
        let mut cipher1 = V2Cipher::new(&keys);
        let frame_before = cipher1.encrypt_message("ping", b"test").unwrap();

        // Second cipher: advance to rekey, then encrypt at packet_counter=0 (post-rekey)
        let mut cipher2 = V2Cipher::new(&keys);
        for i in 0..REKEY_INTERVAL {
            cipher2
                .encrypt_message("ping", &(i as u32).to_le_bytes())
                .unwrap();
        }
        // Now cipher2 has rekeyed, packet_counter=0
        assert_eq!(cipher2.send_packet_counter(), 0);
        assert_eq!(cipher2.send_rekey_counter(), 1);

        let frame_after = cipher2.encrypt_message("ping", b"test").unwrap();

        // The AEAD ciphertext should differ because the key changed.
        // Skip the 3-byte L-encrypted length (L ciphers are at different states).
        assert_ne!(
            &frame_before[3..], &frame_after[3..],
            "rekey must produce a different key — same plaintext should encrypt differently"
        );
    }

    #[test]
    fn rekey_resets_packet_counter() {
        let (sk_a, es_a) = generate_ephemeral_keypair();
        let (_sk_b, es_b) = generate_ephemeral_keypair();
        let shared = ecdh_shared_secret(&sk_a, &es_a, &es_b, true);
        let init_keys = derive_session_keys(&shared.to_secret_bytes(), true, &MAINNET_MAGIC);

        let mut cipher = V2Cipher::new(&init_keys);
        assert_eq!(cipher.send_packet_counter(), 0);

        // Send REKEY_INTERVAL messages to trigger rekey
        for i in 0..REKEY_INTERVAL {
            cipher
                .encrypt_message("ping", &(i as u32).to_le_bytes())
                .unwrap();
        }

        // After rekey, packet counter should be reset to 0
        assert_eq!(cipher.send_packet_counter(), 0);
        assert_eq!(cipher.send_rekey_counter(), 1);
    }

    #[test]
    fn packet_counter_increments() {
        let (mut sender, _receiver) = make_cipher_pair();
        assert_eq!(sender.send_packet_counter(), 0);
        sender.encrypt_message("ping", b"test1").unwrap();
        assert_eq!(sender.send_packet_counter(), 1);
        sender.encrypt_message("pong", b"test2").unwrap();
        assert_eq!(sender.send_packet_counter(), 2);
    }

    #[test]
    fn length_encryption_differs_from_plaintext() {
        // Verify that the encrypted 3-byte length is different from the plaintext length.
        let (mut sender, _receiver) = make_cipher_pair();
        let frame = sender.encrypt_message("ping", b"test payload").unwrap();

        // The plaintext length would be the ciphertext size (payload + tag).
        // With L cipher encryption, the first 3 bytes should NOT match the plaintext LE encoding.
        let ct_len = (frame.len() - 3) as u32;
        let plaintext_len_bytes = [
            ct_len.to_le_bytes()[0],
            ct_len.to_le_bytes()[1],
            ct_len.to_le_bytes()[2],
        ];
        let encrypted_len_bytes = [frame[0], frame[1], frame[2]];
        // With overwhelming probability the encrypted bytes differ from plaintext
        // (they are XORed with keystream). We check they are not identical.
        assert_ne!(
            encrypted_len_bytes, plaintext_len_bytes,
            "encrypted length should differ from plaintext length"
        );
    }

    #[test]
    fn length_decrypt_roundtrip() {
        // Verify that decrypt_length(encrypt_length(x)) == x
        let (mut sender, mut receiver) = make_cipher_pair();
        let frame = sender.encrypt_message("block", b"some block data").unwrap();
        let encrypted_len = [frame[0], frame[1], frame[2]];
        let decrypted_len = receiver.decrypt_length(&encrypted_len);
        let actual_ct_len = (frame.len() - 3) as u32;
        assert_eq!(decrypted_len, actual_ct_len);
    }

    #[test]
    fn l_cipher_rekeys_at_correct_interval() {
        // Verify the FSChaCha20 L cipher rekeys after REKEY_INTERVAL crypt() calls.
        let key = [0x42u8; 32];
        let mut cipher = FSChaCha20::new(&key, REKEY_INTERVAL);

        assert_eq!(cipher.chunk_counter(), 0);
        assert_eq!(cipher.rekey_counter(), 0);

        // Perform REKEY_INTERVAL - 1 encryptions
        for _ in 0..(REKEY_INTERVAL - 1) {
            let mut out = [0u8; 3];
            cipher.crypt(&[0u8; 3], &mut out);
        }
        assert_eq!(cipher.chunk_counter(), REKEY_INTERVAL - 1);
        assert_eq!(cipher.rekey_counter(), 0);

        // The next encryption should trigger a rekey
        let mut out = [0u8; 3];
        cipher.crypt(&[0u8; 3], &mut out);
        assert_eq!(cipher.chunk_counter(), 0);
        assert_eq!(cipher.rekey_counter(), 1);

        // After another REKEY_INTERVAL encryptions, rekey again
        for _ in 0..REKEY_INTERVAL {
            let mut out = [0u8; 3];
            cipher.crypt(&[0u8; 3], &mut out);
        }
        assert_eq!(cipher.chunk_counter(), 0);
        assert_eq!(cipher.rekey_counter(), 2);
    }

    #[test]
    fn fschacha20_crypt_roundtrip() {
        // Verify that two FSChaCha20 instances with the same key produce the same
        // keystream, so encrypt then decrypt recovers the original.
        let key = [0xAB; 32];
        let mut enc = FSChaCha20::new(&key, REKEY_INTERVAL);
        let mut dec = FSChaCha20::new(&key, REKEY_INTERVAL);

        for i in 0u8..10 {
            let plaintext = [i, i.wrapping_add(1), i.wrapping_add(2)];
            let mut ciphertext = [0u8; 3];
            let mut recovered = [0u8; 3];
            enc.crypt(&plaintext, &mut ciphertext);
            dec.crypt(&ciphertext, &mut recovered);
            assert_eq!(recovered, plaintext, "roundtrip failed at iteration {i}");
        }
    }

    #[test]
    fn fschacha20_different_keys_differ() {
        let key1 = [0x01; 32];
        let key2 = [0x02; 32];
        let mut c1 = FSChaCha20::new(&key1, REKEY_INTERVAL);
        let mut c2 = FSChaCha20::new(&key2, REKEY_INTERVAL);

        let input = [0u8; 3];
        let mut out1 = [0u8; 3];
        let mut out2 = [0u8; 3];
        c1.crypt(&input, &mut out1);
        c2.crypt(&input, &mut out2);
        assert_ne!(out1, out2, "different keys should produce different output");
    }

    #[test]
    fn new_short_id_commands_roundtrip() {
        // Test commands that were missing from the old short-id table
        let (mut sender, mut receiver) = make_cipher_pair();
        let new_commands = [
            "filteradd", "filterclear", "filterload", "merkleblock",
            "getcfilters", "cfilter", "getcfheaders", "cfheaders",
            "getcfcheckpt", "cfcheckpt", "addrv2",
        ];
        for cmd in new_commands {
            let frame = sender.encrypt_message(cmd, b"test").unwrap();
            let (_, ct) = decode_frame(&mut receiver, &frame);
            let (got_cmd, got_payload, _) = receiver.decrypt_message(ct).unwrap();
            assert_eq!(got_cmd, cmd, "roundtrip failed for {cmd}");
            assert_eq!(got_payload, b"test");
        }
    }
}
