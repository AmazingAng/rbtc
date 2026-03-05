#![no_main]
use libfuzzer_sys::fuzz_target;
use rbtc_primitives::codec::Decodable;
use rbtc_primitives::transaction::Transaction;

fuzz_target!(|data: &[u8]| {
    // Attempt to decode arbitrary bytes as a transaction.
    // Must not panic regardless of input.
    let _ = Transaction::decode(&mut std::io::Cursor::new(data));
});
