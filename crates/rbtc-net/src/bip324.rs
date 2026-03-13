use hkdf::Hkdf;
use sha2::Sha256;

use secp256k1::ellswift::{ElligatorSwift, ElligatorSwiftSharedSecret, Party};

/// Session keys derived from ECDH shared secret.
///
/// BIP324 derives **4 cipher keys** (not 2): separate L (length) and P (payload/AEAD)
/// keys for each direction. The L key feeds an FSChaCha20 stream cipher for 3-byte
/// length encryption; the P key feeds an FSChaCha20Poly1305 AEAD for payload encryption.
#[derive(Debug, Clone)]
pub struct SessionKeys {
    /// Key for the FSChaCha20 length cipher (send direction).
    pub send_l_key: [u8; 32],
    /// Key for the FSChaCha20Poly1305 AEAD cipher (send direction).
    pub send_p_key: [u8; 32],
    /// Key for the FSChaCha20 length cipher (receive direction).
    pub recv_l_key: [u8; 32],
    /// Key for the FSChaCha20Poly1305 AEAD cipher (receive direction).
    pub recv_p_key: [u8; 32],
    /// 32-byte session identifier (same for both sides).
    pub session_id: [u8; 32],
    /// Garbage terminator we should send (first or last 16 bytes of the 32-byte
    /// HKDF output for "garbage_terminators", depending on role).
    pub send_garbage_terminator: [u8; GARBAGE_TERMINATOR_LEN],
    /// Garbage terminator we expect to receive.
    pub recv_garbage_terminator: [u8; GARBAGE_TERMINATOR_LEN],
}

/// Derive session keys from an ECDH shared secret, matching Bitcoin Core's
/// `BIP324Cipher::Initialize()` (see `src/bip324.cpp`).
///
/// The HKDF salt is `"bitcoin_v2_shared_secret" + network_magic` (4 bytes).
/// Six HKDF-Expand calls produce, in order:
///   1. `"initiator_L"` -> initiator's FSChaCha20 length key
///   2. `"initiator_P"` -> initiator's FSChaCha20Poly1305 AEAD key
///   3. `"responder_L"` -> responder's FSChaCha20 length key
///   4. `"responder_P"` -> responder's FSChaCha20Poly1305 AEAD key
///   5. `"garbage_terminators"` -> 32 bytes; first 16 = initiator's send terminator,
///      last 16 = responder's send terminator
///   6. `"session_id"` -> 32-byte session identifier
///
/// The `initiator` flag determines which direction gets which keys.
/// `network_magic` is the 4-byte message start bytes (e.g. `[0xf9,0xbe,0xb4,0xd9]` for mainnet).
pub fn derive_session_keys(
    shared_secret: &[u8],
    initiator: bool,
    network_magic: &[u8; 4],
) -> SessionKeys {
    // Salt = "bitcoin_v2_shared_secret" + 4-byte network magic
    let mut salt = Vec::with_capacity(24 + 4);
    salt.extend_from_slice(b"bitcoin_v2_shared_secret");
    salt.extend_from_slice(network_magic);

    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);

    let mut initiator_l = [0u8; 32];
    let mut initiator_p = [0u8; 32];
    let mut responder_l = [0u8; 32];
    let mut responder_p = [0u8; 32];
    let mut garbage_terminators = [0u8; 32];
    let mut session_id = [0u8; 32];

    hk.expand(b"initiator_L", &mut initiator_l)
        .expect("32 bytes is valid for HKDF-SHA256");
    hk.expand(b"initiator_P", &mut initiator_p)
        .expect("32 bytes is valid for HKDF-SHA256");
    hk.expand(b"responder_L", &mut responder_l)
        .expect("32 bytes is valid for HKDF-SHA256");
    hk.expand(b"responder_P", &mut responder_p)
        .expect("32 bytes is valid for HKDF-SHA256");
    hk.expand(b"garbage_terminators", &mut garbage_terminators)
        .expect("32 bytes is valid for HKDF-SHA256");
    hk.expand(b"session_id", &mut session_id)
        .expect("32 bytes is valid for HKDF-SHA256");

    // First 16 bytes of garbage_terminators = initiator's send terminator
    // Last 16 bytes = responder's send terminator
    let mut init_garbage_term = [0u8; GARBAGE_TERMINATOR_LEN];
    let mut resp_garbage_term = [0u8; GARBAGE_TERMINATOR_LEN];
    init_garbage_term.copy_from_slice(&garbage_terminators[..GARBAGE_TERMINATOR_LEN]);
    resp_garbage_term.copy_from_slice(&garbage_terminators[GARBAGE_TERMINATOR_LEN..]);

    if initiator {
        SessionKeys {
            send_l_key: initiator_l,
            send_p_key: initiator_p,
            recv_l_key: responder_l,
            recv_p_key: responder_p,
            session_id,
            send_garbage_terminator: init_garbage_term,
            recv_garbage_terminator: resp_garbage_term,
        }
    } else {
        SessionKeys {
            send_l_key: responder_l,
            send_p_key: responder_p,
            recv_l_key: initiator_l,
            recv_p_key: initiator_p,
            session_id,
            send_garbage_terminator: resp_garbage_term,
            recv_garbage_terminator: init_garbage_term,
        }
    }
}

/// BIP324 short message IDs, matching Bitcoin Core `V2_MESSAGE_IDS` in `src/net.cpp`.
///
/// Index 0 means "12-byte long-form encoding follows". Indices 1..=28 are alphabetically
/// ordered command names per the BIP324 specification.
const V2_SHORT_IDS: [&str; 29] = [
    "",            // 0: long-form
    "addr",        // 1
    "block",       // 2
    "blocktxn",    // 3
    "cmpctblock",  // 4
    "feefilter",   // 5
    "filteradd",   // 6
    "filterclear",  // 7
    "filterload",  // 8
    "getblocks",   // 9
    "getblocktxn", // 10
    "getdata",     // 11
    "getheaders",  // 12
    "headers",     // 13
    "inv",         // 14
    "mempool",     // 15
    "merkleblock", // 16
    "notfound",    // 17
    "ping",        // 18
    "pong",        // 19
    "sendcmpct",   // 20
    "tx",          // 21
    "getcfilters", // 22
    "cfilter",     // 23
    "getcfheaders", // 24
    "cfheaders",   // 25
    "getcfcheckpt", // 26
    "cfcheckpt",   // 27
    "addrv2",      // 28
];

/// Map a command string to its BIP324 1-byte short ID.
///
/// Returns `None` for commands that have no short encoding (they must use the
/// 12-byte long-form encoding with short ID 0).
pub fn v2_command_id(command: &str) -> Option<u8> {
    for (i, &name) in V2_SHORT_IDS.iter().enumerate().skip(1) {
        if name == command {
            return Some(i as u8);
        }
    }
    None
}

/// Map a BIP324 1-byte short ID back to its command string.
///
/// Returns `None` for ID 0 (long-form) or unknown IDs.
pub fn v2_command_name(id: u8) -> Option<&'static str> {
    let idx = id as usize;
    if idx == 0 || idx >= V2_SHORT_IDS.len() {
        return None;
    }
    let name = V2_SHORT_IDS[idx];
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Perform BIP324 ECDH using ElligatorSwift-encoded public keys.
///
/// Uses `ElligatorSwift::shared_secret` with the built-in BIP324 hash function
/// (`secp256k1_ellswift_xdh_hash_function_bip324`). Returns the 32-byte shared
/// secret that should be fed into `derive_session_keys`.
///
/// `our_ellswift` and `their_ellswift` are the 64-byte ElligatorSwift encodings.
/// The `party` parameter indicates whether we are the initiator or responder,
/// which affects the hash computation (initiator = A, responder = B).
pub fn ecdh_shared_secret(
    our_secret: &secp256k1::SecretKey,
    our_ellswift: &ElligatorSwift,
    their_ellswift: &ElligatorSwift,
    initiator: bool,
) -> ElligatorSwiftSharedSecret {
    let party = if initiator { Party::Initiator } else { Party::Responder };
    let (ellswift_a, ellswift_b) = if initiator {
        (*our_ellswift, *their_ellswift)
    } else {
        (*their_ellswift, *our_ellswift)
    };
    ElligatorSwift::shared_secret(ellswift_a, ellswift_b, *our_secret, party, None)
}

/// Maximum garbage length in BIP324 handshake (4095 bytes).
pub const MAX_GARBAGE_LEN: usize = 4095;

/// Length of the garbage terminator (16 bytes).
pub const GARBAGE_TERMINATOR_LEN: usize = 16;

/// Size of an EllSwift public key encoding (64 bytes).
///
/// BIP324 uses 64-byte ElligatorSwift-encoded public keys for indistinguishability
/// from uniformly random data. The encoding is performed by the secp256k1 library's
/// `ElligatorSwift` type.
pub const ELLSWIFT_KEY_LEN: usize = 64;

/// Generate an ephemeral secp256k1 keypair and its ElligatorSwift encoding.
///
/// Returns `(secret_key, ellswift_encoding)`. The ElligatorSwift encoding is the
/// 64-byte representation used in the BIP324 handshake, indistinguishable from
/// uniformly random bytes.
pub fn generate_ephemeral_keypair() -> (secp256k1::SecretKey, ElligatorSwift) {
    use rand::RngCore;
    let secp = secp256k1::Secp256k1::new();
    let mut rng = rand::thread_rng();
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);
    let sk = secp256k1::SecretKey::from_byte_array(secret_bytes).expect("valid secret key");
    // Generate random auxiliary data for additional entropy in the encoding
    let mut aux_rand = [0u8; 32];
    rng.fill_bytes(&mut aux_rand);
    let ellswift = ElligatorSwift::from_seckey(&secp, sk, Some(aux_rand));
    (sk, ellswift)
}

/// Generate random garbage bytes for the BIP324 handshake.
/// Length is random between 0 and MAX_GARBAGE_LEN.
pub fn generate_garbage() -> Vec<u8> {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let len = (rng.next_u32() as usize) % (MAX_GARBAGE_LEN + 1);
    let mut garbage = vec![0u8; len];
    if len > 0 {
        rng.fill_bytes(&mut garbage);
    }
    garbage
}

/// Build the initiator's handshake payload: 64-byte ellswift pubkey + garbage + garbage_terminator.
pub fn build_initiator_hello(
    our_ellswift: &ElligatorSwift,
    keys: &SessionKeys,
) -> Vec<u8> {
    let ellswift_bytes = our_ellswift.to_array();
    let garbage = generate_garbage();
    let mut payload = Vec::with_capacity(ELLSWIFT_KEY_LEN + garbage.len() + GARBAGE_TERMINATOR_LEN);
    payload.extend_from_slice(&ellswift_bytes);
    payload.extend_from_slice(&garbage);
    payload.extend_from_slice(&keys.send_garbage_terminator);
    payload
}

/// Parse a peer's hello: find the garbage terminator to extract their ElligatorSwift-encoded pubkey.
///
/// Returns `(ellswift, garbage_len)` on success. Expects the `recv_garbage_terminator`
/// from our session keys (which matches the peer's send terminator).
pub fn parse_hello(
    data: &[u8],
    recv_garbage_terminator: &[u8; GARBAGE_TERMINATOR_LEN],
) -> Option<(ElligatorSwift, usize)> {
    if data.len() < ELLSWIFT_KEY_LEN + GARBAGE_TERMINATOR_LEN {
        return None;
    }
    let mut ellswift_bytes = [0u8; ELLSWIFT_KEY_LEN];
    ellswift_bytes.copy_from_slice(&data[..ELLSWIFT_KEY_LEN]);
    let ellswift = ElligatorSwift::from_array(ellswift_bytes);

    // Scan for the garbage terminator after the pubkey
    let search_start = ELLSWIFT_KEY_LEN;
    let search_end = data.len().saturating_sub(GARBAGE_TERMINATOR_LEN);
    for i in search_start..=search_end {
        if data[i..i + GARBAGE_TERMINATOR_LEN] == *recv_garbage_terminator {
            return Some((ellswift, i - search_start));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Default mainnet magic for tests.
    const MAINNET_MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];

    #[test]
    fn derive_session_keys_deterministic() {
        let secret = [0x42u8; 32];
        let keys1 = derive_session_keys(&secret, true, &MAINNET_MAGIC);
        let keys2 = derive_session_keys(&secret, true, &MAINNET_MAGIC);
        assert_eq!(keys1.send_l_key, keys2.send_l_key);
        assert_eq!(keys1.send_p_key, keys2.send_p_key);
        assert_eq!(keys1.recv_l_key, keys2.recv_l_key);
        assert_eq!(keys1.recv_p_key, keys2.recv_p_key);
        assert_eq!(keys1.session_id, keys2.session_id);
    }

    #[test]
    fn initiator_responder_keys_swapped() {
        let secret = [0xAB; 32];
        let init_keys = derive_session_keys(&secret, true, &MAINNET_MAGIC);
        let resp_keys = derive_session_keys(&secret, false, &MAINNET_MAGIC);
        // Initiator's send_l = Responder's recv_l, etc.
        assert_eq!(init_keys.send_l_key, resp_keys.recv_l_key);
        assert_eq!(init_keys.send_p_key, resp_keys.recv_p_key);
        assert_eq!(init_keys.recv_l_key, resp_keys.send_l_key);
        assert_eq!(init_keys.recv_p_key, resp_keys.send_p_key);
        assert_eq!(init_keys.session_id, resp_keys.session_id);
        // Garbage terminators also swap
        assert_eq!(init_keys.send_garbage_terminator, resp_keys.recv_garbage_terminator);
        assert_eq!(init_keys.recv_garbage_terminator, resp_keys.send_garbage_terminator);
    }

    #[test]
    fn session_keys_all_different() {
        let secret = [0x01; 32];
        let keys = derive_session_keys(&secret, true, &MAINNET_MAGIC);
        // All 4 cipher keys should be distinct
        assert_ne!(keys.send_l_key, keys.send_p_key);
        assert_ne!(keys.send_l_key, keys.recv_l_key);
        assert_ne!(keys.send_l_key, keys.recv_p_key);
        assert_ne!(keys.send_p_key, keys.recv_l_key);
        assert_ne!(keys.send_p_key, keys.recv_p_key);
        assert_ne!(keys.recv_l_key, keys.recv_p_key);
        // Session ID should differ from all cipher keys
        assert_ne!(keys.send_l_key, keys.session_id);
        assert_ne!(keys.send_p_key, keys.session_id);
    }

    #[test]
    fn different_network_magic_gives_different_keys() {
        let secret = [0x42u8; 32];
        let mainnet = derive_session_keys(&secret, true, &MAINNET_MAGIC);
        let testnet = derive_session_keys(&secret, true, &[0x0b, 0x11, 0x09, 0x07]);
        assert_ne!(mainnet.send_l_key, testnet.send_l_key);
        assert_ne!(mainnet.send_p_key, testnet.send_p_key);
        assert_ne!(mainnet.session_id, testnet.session_id);
    }

    #[test]
    fn v2_command_id_bitcoin_core_mapping() {
        // Verify the full Bitcoin Core BIP324 short ID table
        let expected: &[(u8, &str)] = &[
            (1, "addr"),
            (2, "block"),
            (3, "blocktxn"),
            (4, "cmpctblock"),
            (5, "feefilter"),
            (6, "filteradd"),
            (7, "filterclear"),
            (8, "filterload"),
            (9, "getblocks"),
            (10, "getblocktxn"),
            (11, "getdata"),
            (12, "getheaders"),
            (13, "headers"),
            (14, "inv"),
            (15, "mempool"),
            (16, "merkleblock"),
            (17, "notfound"),
            (18, "ping"),
            (19, "pong"),
            (20, "sendcmpct"),
            (21, "tx"),
            (22, "getcfilters"),
            (23, "cfilter"),
            (24, "getcfheaders"),
            (25, "cfheaders"),
            (26, "getcfcheckpt"),
            (27, "cfcheckpt"),
            (28, "addrv2"),
        ];
        for &(id, cmd) in expected {
            assert_eq!(v2_command_id(cmd), Some(id), "command_id mismatch for {cmd}");
            assert_eq!(v2_command_name(id), Some(cmd), "command_name mismatch for id {id}");
        }
    }

    #[test]
    fn v2_command_id_all_28() {
        // Ensure all 28 short IDs are assigned
        for id in 1..=28u8 {
            assert!(v2_command_name(id).is_some(), "missing command for id {id}");
        }
    }

    #[test]
    fn unknown_command_returns_none() {
        assert!(v2_command_id("unknowncmd").is_none());
        assert!(v2_command_id("version").is_none()); // version is NOT in the short-id table
        assert!(v2_command_id("verack").is_none());  // verack is NOT in the short-id table
        assert!(v2_command_name(255).is_none());
        assert!(v2_command_name(0).is_none());
        assert!(v2_command_name(29).is_none());
    }

    #[test]
    fn ellswift_shared_secret_symmetric() {
        // Both parties should derive the same shared secret via ElligatorSwift ECDH
        let (sk_a, es_a) = generate_ephemeral_keypair();
        let (sk_b, es_b) = generate_ephemeral_keypair();

        let secret_a = ecdh_shared_secret(&sk_a, &es_a, &es_b, true);
        let secret_b = ecdh_shared_secret(&sk_b, &es_b, &es_a, false);
        assert_eq!(secret_a.to_secret_bytes(), secret_b.to_secret_bytes());
    }

    #[test]
    fn generate_keypair_produces_valid_ellswift() {
        let (sk, es) = generate_ephemeral_keypair();
        // The ElligatorSwift encoding should decode to the same public key
        let pk_from_es = secp256k1::PublicKey::from_ellswift(es);
        let pk_from_sk = secp256k1::PublicKey::from_secret_key_global(&sk);
        assert_eq!(pk_from_es, pk_from_sk);
    }

    #[test]
    fn full_handshake_key_derivation() {
        // Simulate initiator and responder with real ElligatorSwift ECDH
        let (sk_init, es_init) = generate_ephemeral_keypair();
        let (sk_resp, es_resp) = generate_ephemeral_keypair();

        let shared_init = ecdh_shared_secret(&sk_init, &es_init, &es_resp, true);
        let shared_resp = ecdh_shared_secret(&sk_resp, &es_resp, &es_init, false);
        assert_eq!(shared_init.to_secret_bytes(), shared_resp.to_secret_bytes());

        let init_keys = derive_session_keys(&shared_init.to_secret_bytes(), true, &MAINNET_MAGIC);
        let resp_keys = derive_session_keys(&shared_resp.to_secret_bytes(), false, &MAINNET_MAGIC);

        // Initiator's send should decrypt with responder's recv
        assert_eq!(init_keys.send_l_key, resp_keys.recv_l_key);
        assert_eq!(init_keys.send_p_key, resp_keys.recv_p_key);
        assert_eq!(init_keys.recv_l_key, resp_keys.send_l_key);
        assert_eq!(init_keys.recv_p_key, resp_keys.send_p_key);
    }

    #[test]
    fn garbage_terminators_from_session_keys() {
        let secret = [0x42u8; 32];
        let init_keys = derive_session_keys(&secret, true, &MAINNET_MAGIC);
        let resp_keys = derive_session_keys(&secret, false, &MAINNET_MAGIC);

        // Initiator's send terminator == Responder's recv terminator
        assert_eq!(init_keys.send_garbage_terminator, resp_keys.recv_garbage_terminator);
        assert_eq!(init_keys.recv_garbage_terminator, resp_keys.send_garbage_terminator);

        // The two terminators should be different from each other
        assert_ne!(init_keys.send_garbage_terminator, init_keys.recv_garbage_terminator);
    }

    #[test]
    fn garbage_length_within_bounds() {
        for _ in 0..10 {
            let garbage = generate_garbage();
            assert!(garbage.len() <= MAX_GARBAGE_LEN);
        }
    }

    #[test]
    fn ellswift_encoding_is_64_bytes() {
        let (_sk, es) = generate_ephemeral_keypair();
        let encoded = es.to_array();
        assert_eq!(encoded.len(), ELLSWIFT_KEY_LEN);
    }

    #[test]
    fn ellswift_key_is_64_bytes() {
        assert_eq!(ELLSWIFT_KEY_LEN, 64);
    }

    #[test]
    fn ellswift_from_array_roundtrip() {
        let (_sk, es) = generate_ephemeral_keypair();
        let bytes = es.to_array();
        let es2 = ElligatorSwift::from_array(bytes);
        assert_eq!(es, es2);
    }

    #[test]
    fn build_and_parse_hello_roundtrip() {
        let (sk_init, es_init) = generate_ephemeral_keypair();
        let (sk_resp, es_resp) = generate_ephemeral_keypair();

        let shared = ecdh_shared_secret(&sk_init, &es_init, &es_resp, true);
        let init_keys = derive_session_keys(&shared.to_secret_bytes(), true, &MAINNET_MAGIC);
        let resp_keys = derive_session_keys(&shared.to_secret_bytes(), false, &MAINNET_MAGIC);

        let hello = build_initiator_hello(&es_init, &init_keys);

        // Hello should contain at least ellswift key + terminator
        assert!(hello.len() >= ELLSWIFT_KEY_LEN + GARBAGE_TERMINATOR_LEN);

        // Responder parses using their recv_garbage_terminator (= initiator's send terminator)
        let (parsed_es, _garbage_len) = parse_hello(&hello, &resp_keys.recv_garbage_terminator).unwrap();
        assert_eq!(parsed_es, es_init);
    }

    #[test]
    fn parse_hello_fails_with_wrong_terminator() {
        let (sk_init, es_init) = generate_ephemeral_keypair();
        let (_sk_resp, es_resp) = generate_ephemeral_keypair();

        let shared = ecdh_shared_secret(&sk_init, &es_init, &es_resp, true);
        let init_keys = derive_session_keys(&shared.to_secret_bytes(), true, &MAINNET_MAGIC);

        let hello = build_initiator_hello(&es_init, &init_keys);

        // Try parsing with a wrong terminator
        let wrong_term = [0xFFu8; GARBAGE_TERMINATOR_LEN];
        assert!(parse_hello(&hello, &wrong_term).is_none());
    }

    #[test]
    fn ellswift_encoding_differs_from_compressed_pubkey() {
        // Verify that ElligatorSwift encoding is NOT just a padded compressed key
        let (sk, es) = generate_ephemeral_keypair();
        let pk = secp256k1::PublicKey::from_secret_key_global(&sk);
        let compressed = pk.serialize(); // 33 bytes
        let es_bytes = es.to_array();
        // The first 33 bytes of ellswift should NOT match the compressed key
        // (ElligatorSwift uses a completely different encoding)
        assert_ne!(&es_bytes[..33], &compressed[..]);
    }
}
