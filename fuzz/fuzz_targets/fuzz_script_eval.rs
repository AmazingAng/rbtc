#![no_main]
use libfuzzer_sys::fuzz_target;
use rbtc_primitives::script::Script;
use rbtc_script::ScriptEngine;

fuzz_target!(|data: &[u8]| {
    // Evaluate arbitrary bytes as a Bitcoin script.
    // Must not panic regardless of input.
    if data.len() > 10_000 {
        return; // avoid extremely slow inputs
    }
    let script = Script::from_bytes(data.to_vec());
    let mut engine = ScriptEngine::new();
    let _ = engine.eval_script(&script);
});
