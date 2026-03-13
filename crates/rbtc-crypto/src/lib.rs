pub mod aes;
pub mod cleanse;
pub mod digest;
pub mod hmac;
pub mod merkle;
pub mod message;
pub mod muhash;
pub mod random;
pub mod sig;
pub mod sigcache;
pub mod sighash;
pub mod siphash;

pub use aes::{aes256_cbc_decrypt, aes256_cbc_encrypt, aes256_ecb_decrypt, aes256_ecb_encrypt};
pub use digest::{
    hash160, sha1, sha256, sha256d, sha3_256, sha512, tagged_hash, tap_branch_hash, tap_leaf_hash,
    tap_tweak_hash,
};
pub use hmac::{
    hkdf_sha256_l32, hmac_sha256, hmac_sha512, HmacSha256Writer, HmacSha512Writer,
};
pub use merkle::{merkle_root, witness_merkle_root, witness_merkle_root_with_coinbase};
pub use message::{message_hash, sign_message, verify_message};
pub use sig::{
    batch_verify_ecdsa, batch_verify_schnorr, recover_compact, sign_compact, verify_ecdsa,
    verify_ecdsa_with_policy, verify_schnorr, CryptoError,
};
pub use sighash::{
    sighash_legacy, sighash_segwit_v0, sighash_segwit_v0_cached, sighash_taproot,
    sighash_taproot_cached, PrecomputedSighashData, SighashType,
};
pub use random::{
    fast_random_bool, fast_random_range, fast_random_shuffle, fast_random_u32, fast_random_u64,
    get_rand_bytes, get_strong_rand_bytes, random_bytes, random_bytes_32,
};
pub use sigcache::{global_sig_cache, SigCache};
pub use siphash::{siphash_2_4, siphash_2_4_u256, siphash_2_4_u256_extra};
pub use cleanse::memory_cleanse;
