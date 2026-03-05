/// Bitcoin Core base58_encode_decode.json test harness.
///
/// Format: `[hex_string, base58_string]`
/// Tests round-trip encoding/decoding of raw base58 (NOT base58check).

#[test]
fn base58_encode_decode_json() {
    let json_text = include_str!("data/base58_encode_decode.json");
    let data: Vec<Vec<String>> = serde_json::from_str(json_text).expect("parse base58 json");

    let mut total = 0usize;
    let mut failures = Vec::<String>::new();

    for (i, entry) in data.iter().enumerate() {
        if entry.len() != 2 {
            continue;
        }
        let hex_str = &entry[0];
        let expected_b58 = &entry[1];

        let bytes = hex::decode(hex_str).unwrap_or_else(|e| panic!("[{i}] bad hex: {e}"));

        // Test encode
        let encoded = bs58::encode(&bytes).into_string();
        total += 1;
        if encoded != *expected_b58 {
            failures.push(format!(
                "[{i}] encode: hex={hex_str} expected={expected_b58} got={encoded}"
            ));
        }

        // Test decode
        let decoded = bs58::decode(expected_b58)
            .into_vec()
            .unwrap_or_else(|e| panic!("[{i}] decode failed: {e}"));
        if decoded != bytes {
            failures.push(format!(
                "[{i}] decode: b58={expected_b58} expected={hex_str} got={}",
                hex::encode(&decoded)
            ));
        }
    }

    if !failures.is_empty() {
        for f in &failures {
            eprintln!("  FAIL: {f}");
        }
        panic!("{} / {total} base58 cases failed", failures.len());
    }

    println!("base58_encode_decode.json: {total} cases all passed");
}
