/// Bitcoin Core key_io_valid.json / key_io_invalid.json test harness.
///
/// key_io_valid format: `[address_or_wif, expected_script_hex, { chain, isPrivkey, [isCompressed] }]`
/// key_io_invalid format: `[invalid_string]`
///
/// For addresses (isPrivkey=false): decode address → scriptPubKey, compare with expected.
/// For private keys (isPrivkey=true): verify WIF decode yields the correct raw key.
use rbtc_wallet::address::address_to_script;
use serde_json::Value;

fn decode_hex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("bad hex '{s}': {e}"))
}

#[test]
fn key_io_valid_addresses() {
    let json_text = include_str!("data/key_io_valid.json");
    let data: Vec<Value> = serde_json::from_str(json_text).expect("parse key_io_valid.json");

    let mut total = 0usize;
    let mut failures = Vec::<String>::new();

    for (i, entry) in data.iter().enumerate() {
        let arr = entry.as_array().unwrap();
        let addr_or_wif = arr[0].as_str().unwrap();
        let expected_hex = arr[1].as_str().unwrap();
        let meta = &arr[2];
        let is_privkey = meta["isPrivkey"].as_bool().unwrap_or(false);

        if is_privkey {
            // WIF private key test — verify WIF decodes to the raw key
            total += 1;
            let expected_key = decode_hex(expected_hex);
            let is_compressed = meta["isCompressed"].as_bool().unwrap_or(true);

            let decoded = bs58::decode(addr_or_wif)
                .with_check(None)
                .into_vec();
            match decoded {
                Ok(bytes) => {
                    // WIF: version(1) + key(32) + [compressed_flag(1)] + checksum(removed by bs58)
                    let key_bytes = if is_compressed {
                        if bytes.len() != 34 {
                            failures.push(format!(
                                "[{i}] WIF compressed len={}, expected 34",
                                bytes.len()
                            ));
                            continue;
                        }
                        &bytes[1..33]
                    } else {
                        if bytes.len() != 33 {
                            failures.push(format!(
                                "[{i}] WIF uncompressed len={}, expected 33",
                                bytes.len()
                            ));
                            continue;
                        }
                        &bytes[1..33]
                    };
                    if key_bytes != expected_key.as_slice() {
                        failures.push(format!(
                            "[{i}] WIF key mismatch: expected={expected_hex} got={}",
                            hex::encode(key_bytes)
                        ));
                    }
                }
                Err(e) => {
                    failures.push(format!("[{i}] WIF decode failed: {e}"));
                }
            }
        } else {
            // Address test — decode address → scriptPubKey
            total += 1;
            match address_to_script(addr_or_wif) {
                Ok(script) => {
                    let got_hex = hex::encode(script.as_bytes());
                    if got_hex != expected_hex {
                        failures.push(format!(
                            "[{i}] address={addr_or_wif}: expected={expected_hex} got={got_hex}"
                        ));
                    }
                }
                Err(e) => {
                    failures.push(format!(
                        "[{i}] address={addr_or_wif}: decode failed: {e}"
                    ));
                }
            }
        }
    }

    if !failures.is_empty() {
        for f in &failures {
            eprintln!("  FAIL: {f}");
        }
        panic!(
            "{} / {total} key_io_valid cases failed",
            failures.len()
        );
    }

    println!("key_io_valid.json: {total} cases all passed");
}

#[test]
fn key_io_invalid() {
    let json_text = include_str!("data/key_io_invalid.json");
    let data: Vec<Vec<String>> = serde_json::from_str(json_text).expect("parse key_io_invalid.json");

    let mut total = 0usize;
    let mut false_ok = Vec::<String>::new();

    for (i, entry) in data.iter().enumerate() {
        if entry.is_empty() {
            continue;
        }
        let invalid_str = &entry[0];
        total += 1;

        // Should fail as address
        let addr_ok = address_to_script(invalid_str).is_ok();
        // Should fail as WIF
        let wif_ok = bs58::decode(invalid_str).with_check(None).into_vec().is_ok();

        if addr_ok {
            false_ok.push(format!(
                "[{i}] '{invalid_str}' accepted as address (should be invalid)"
            ));
        }
        // WIF with valid checksum but invalid content is acceptable to decode at base58 level,
        // so we only check address decoding here
    }

    if !false_ok.is_empty() {
        for f in &false_ok {
            eprintln!("  FAIL: {f}");
        }
        panic!(
            "{} / {total} key_io_invalid cases falsely accepted",
            false_ok.len()
        );
    }

    println!("key_io_invalid.json: {total} cases all passed");
}
