pub mod engine;
pub mod opcode;
pub mod sigops;
pub mod standard;

pub use engine::{ScriptEngine, ScriptError, ScriptFlags};
// Re-export the consolidated SigCache from rbtc-crypto so that downstream
// users who previously imported it from rbtc-script continue to compile.
pub use rbtc_crypto::sigcache::SigCache;
pub use sigops::{count_legacy_sigops, count_p2sh_sigops, count_witness_sigops};
pub use standard::{verify_input, ScriptContext};
