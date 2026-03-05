#![no_main]
use libfuzzer_sys::fuzz_target;
use rbtc_primitives::block::BlockHeader;
use rbtc_primitives::codec::Decodable;

fuzz_target!(|data: &[u8]| {
    // Attempt to decode arbitrary bytes as a block header.
    // Must not panic regardless of input.
    let _ = BlockHeader::decode(&mut std::io::Cursor::new(data));
});
