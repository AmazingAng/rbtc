use rbtc_crypto::sighash::sighash_legacy_with_u32;
/// Bitcoin Core sighash.json test harness.
///
/// Format: `["raw_transaction_hex, script_hex, input_index, hashType, expected_sighash"]`
/// First entry is the header row. Remaining 500 entries are legacy sighash test vectors.
use rbtc_primitives::{codec::Decodable, script::Script, transaction::Transaction};
use serde_json::Value;

fn decode_hex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("bad hex '{s}': {e}"))
}

#[test]
fn sighash_json() {
    let json_text = include_str!("data/sighash.json");
    let data: Vec<Value> = serde_json::from_str(json_text).expect("parse sighash.json");

    let mut total = 0usize;
    let mut failures = Vec::<String>::new();

    for (i, entry) in data.iter().enumerate() {
        let arr = match entry.as_array() {
            Some(a) if a.len() == 5 => a,
            _ => continue, // skip header or malformed
        };

        // All fields must be the right types
        let tx_hex = match arr[0].as_str() {
            Some(s) => s,
            None => continue,
        };
        let script_hex = match arr[1].as_str() {
            Some(s) => s,
            None => continue,
        };
        let input_index = match arr[2].as_i64() {
            Some(n) => n as usize,
            None => continue,
        };
        let hash_type = match arr[3].as_i64() {
            Some(n) => n as i32,
            None => continue,
        };
        let expected_hex = match arr[4].as_str() {
            Some(s) => s,
            None => continue,
        };

        // Decode transaction
        let tx_bytes = decode_hex(tx_hex);
        let tx = match Transaction::decode(&mut std::io::Cursor::new(&tx_bytes)) {
            Ok(t) => t,
            Err(e) => {
                failures.push(format!("[{i}] failed to decode tx: {e}"));
                total += 1;
                continue;
            }
        };

        // Decode script
        let script = Script::from_bytes(decode_hex(script_hex));

        // Compute sighash (legacy, raw u32 hash type)
        let got = sighash_legacy_with_u32(&tx, input_index, &script, hash_type as u32);
        // Bitcoin Core sighash.json stores hashes in internal byte order (reversed)
        let mut reversed = got.0;
        reversed.reverse();
        let got_hex = hex::encode(reversed);

        total += 1;
        if got_hex != expected_hex {
            failures.push(format!(
                "[{i}] input={input_index} hashType={hash_type}: expected={expected_hex} got={got_hex}"
            ));
        }
    }

    if !failures.is_empty() {
        eprintln!(
            "\n=== SIGHASH TEST FAILURES ({}/{total}) ===",
            failures.len()
        );
        for f in &failures[..failures.len().min(20)] {
            eprintln!("  FAIL: {f}");
        }
        panic!("{} / {total} sighash.json cases failed", failures.len());
    }

    println!("sighash.json: {total} cases all passed");
}
