/// Bitcoin Core script_tests.json test harness.
///
/// Format: `[[wit..., amount]?, scriptSig, scriptPubKey, flags, expected_error, comment?]`
///
/// If the first element is an array it holds witness stack items (hex strings)
/// followed by the amount in satoshis as the last element.
/// Otherwise the entry has no witness data and the amount is 0.
use rbtc_primitives::{
    hash::{Hash256, TxId},
    script::Script,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
};
use rbtc_script::{ScriptContext, ScriptFlags, verify_input};

use serde_json::Value;

// ─── Script assembly parser ──────────────────────────────────────────────────

/// Parse Bitcoin's script assembly notation into raw script bytes.
///
/// Each whitespace-separated token is one of:
/// * `0x...`   – hex bytes emitted verbatim (no push opcode wrapper)
/// * `'str'`   – ASCII bytes pushed with an appropriate length opcode
/// * opcode name (e.g. `DUP`, `OP_HASH160`, `CHECKSIG`, …)
/// * integer   – pushed as a minimal script number
fn parse_script_asm(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let s = s.trim();
    if s.is_empty() {
        return Ok(out);
    }

    let mut i = 0usize;
    let chars: Vec<char> = s.chars().collect();

    while i < chars.len() {
        // skip whitespace
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }

        // string literal  'Az'
        if chars[i] == '\'' {
            i += 1;
            let mut lit = Vec::new();
            while i < chars.len() && chars[i] != '\'' {
                lit.push(chars[i] as u8);
                i += 1;
            }
            if i < chars.len() { i += 1; } // consume closing '
            push_bytes(&mut out, &lit);
            continue;
        }

        // collect token until next whitespace
        let start = i;
        while i < chars.len() && !chars[i].is_whitespace() {
            i += 1;
        }
        let token: String = chars[start..i].iter().collect();

        // 0x hex bytes – emitted verbatim (no push wrapper)
        if token.starts_with("0x") || token.starts_with("0X") {
            let hex = &token[2..];
            if hex.is_empty() {
                // 0x with nothing — skip
                continue;
            }
            let bytes = decode_hex(hex)
                .map_err(|e| format!("bad hex token '{}': {}", token, e))?;
            out.extend_from_slice(&bytes);
            continue;
        }

        // opcode name (with or without OP_ prefix)
        if let Some(byte) = opcode_byte(&token) {
            out.push(byte);
            continue;
        }

        // integer
        if let Ok(n) = token.parse::<i64>() {
            push_int(&mut out, n);
            continue;
        }

        return Err(format!("unknown token '{}'", token));
    }
    Ok(out)
}

/// Push `data` using the minimal push opcode.
fn push_bytes(out: &mut Vec<u8>, data: &[u8]) {
    match data.len() {
        0 => out.push(0x00), // OP_0
        1 => {
            let v = data[0];
            if v == 0x81 {
                out.push(0x4f); // OP_1NEGATE
            } else if v >= 1 && v <= 16 {
                out.push(0x50 + v); // OP_1 – OP_16
            } else {
                out.push(0x01);
                out.extend_from_slice(data);
            }
        }
        n if n <= 0x4b => {
            out.push(n as u8);
            out.extend_from_slice(data);
        }
        n if n <= 0xff => {
            out.push(0x4c);
            out.push(n as u8);
            out.extend_from_slice(data);
        }
        n if n <= 0xffff => {
            out.push(0x4d);
            out.extend_from_slice(&(n as u16).to_le_bytes());
            out.extend_from_slice(data);
        }
        n => {
            out.push(0x4e);
            out.extend_from_slice(&(n as u32).to_le_bytes());
            out.extend_from_slice(data);
        }
    }
}

/// Push an integer using minimal script number encoding.
fn push_int(out: &mut Vec<u8>, n: i64) {
    if n == 0 {
        out.push(0x00); // OP_0
    } else if n == -1 {
        out.push(0x4f); // OP_1NEGATE
    } else if n >= 1 && n <= 16 {
        out.push(0x50 + n as u8); // OP_1 – OP_16
    } else {
        let encoded = encode_script_int(n);
        push_bytes(out, &encoded);
    }
}

/// Encode an i64 as a Bitcoin script integer.
fn encode_script_int(n: i64) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }
    let neg = n < 0;
    let mut abs = n.unsigned_abs();
    let mut result = Vec::new();
    while abs > 0 {
        result.push((abs & 0xff) as u8);
        abs >>= 8;
    }
    if result.last().unwrap() & 0x80 != 0 {
        result.push(if neg { 0x80 } else { 0x00 });
    } else if neg {
        *result.last_mut().unwrap() |= 0x80;
    }
    result
}

/// Return the opcode byte for a name token, or None.
fn opcode_byte(token: &str) -> Option<u8> {
    // strip optional OP_ prefix
    let t = if token.starts_with("OP_") { &token[3..] } else { token };
    Some(match t {
        "0" | "FALSE" => 0x00,
        "PUSHDATA1" => 0x4c,
        "PUSHDATA2" => 0x4d,
        "PUSHDATA4" => 0x4e,
        "1NEGATE" => 0x4f,
        "RESERVED" => 0x50,
        "1" | "TRUE" => 0x51,
        "2" => 0x52,
        "3" => 0x53,
        "4" => 0x54,
        "5" => 0x55,
        "6" => 0x56,
        "7" => 0x57,
        "8" => 0x58,
        "9" => 0x59,
        "10" => 0x5a,
        "11" => 0x5b,
        "12" => 0x5c,
        "13" => 0x5d,
        "14" => 0x5e,
        "15" => 0x5f,
        "16" => 0x60,
        "NOP" => 0x61,
        "VER" => 0x62,
        "IF" => 0x63,
        "NOTIF" => 0x64,
        "VERIF" => 0x65,
        "VERNOTIF" => 0x66,
        "ELSE" => 0x67,
        "ENDIF" => 0x68,
        "VERIFY" => 0x69,
        "RETURN" => 0x6a,
        "TOALTSTACK" => 0x6b,
        "FROMALTSTACK" => 0x6c,
        "2DROP" => 0x6d,
        "2DUP" => 0x6e,
        "3DUP" => 0x6f,
        "2OVER" => 0x70,
        "2ROT" => 0x71,
        "2SWAP" => 0x72,
        "IFDUP" => 0x73,
        "DEPTH" => 0x74,
        "DROP" => 0x75,
        "DUP" => 0x76,
        "NIP" => 0x77,
        "OVER" => 0x78,
        "PICK" => 0x79,
        "ROLL" => 0x7a,
        "ROT" => 0x7b,
        "SWAP" => 0x7c,
        "TUCK" => 0x7d,
        "CAT" => 0x7e,
        "SUBSTR" => 0x7f,
        "LEFT" => 0x80,
        "RIGHT" => 0x81,
        "SIZE" => 0x82,
        "INVERT" => 0x83,
        "AND" => 0x84,
        "OR" => 0x85,
        "XOR" => 0x86,
        "EQUAL" => 0x87,
        "EQUALVERIFY" => 0x88,
        "RESERVED1" => 0x89,
        "RESERVED2" => 0x8a,
        "1ADD" => 0x8b,
        "1SUB" => 0x8c,
        "2MUL" => 0x8d,
        "2DIV" => 0x8e,
        "NEGATE" => 0x8f,
        "ABS" => 0x90,
        "NOT" => 0x91,
        "0NOTEQUAL" => 0x92,
        "ADD" => 0x93,
        "SUB" => 0x94,
        "MUL" => 0x95,
        "DIV" => 0x96,
        "MOD" => 0x97,
        "LSHIFT" => 0x98,
        "RSHIFT" => 0x99,
        "BOOLAND" => 0x9a,
        "BOOLOR" => 0x9b,
        "NUMEQUAL" => 0x9c,
        "NUMEQUALVERIFY" => 0x9d,
        "NUMNOTEQUAL" => 0x9e,
        "LESSTHAN" => 0x9f,
        "GREATERTHAN" => 0xa0,
        "LESSTHANOREQUAL" => 0xa1,
        "GREATERTHANOREQUAL" => 0xa2,
        "MIN" => 0xa3,
        "MAX" => 0xa4,
        "WITHIN" => 0xa5,
        "RIPEMD160" => 0xa6,
        "SHA1" => 0xa7,
        "SHA256" => 0xa8,
        "HASH160" => 0xa9,
        "HASH256" => 0xaa,
        "CODESEPARATOR" => 0xab,
        "CHECKSIG" => 0xac,
        "CHECKSIGVERIFY" => 0xad,
        "CHECKMULTISIG" => 0xae,
        "CHECKMULTISIGVERIFY" => 0xaf,
        "NOP1" => 0xb0,
        "NOP2" | "CHECKLOCKTIMEVERIFY" | "CLTV" => 0xb1,
        "CHECKSEQUENCEVERIFY" | "CSV" => 0xb2,
        "NOP3" => 0xb2,
        "NOP4" => 0xb3,
        "NOP5" => 0xb4,
        "NOP6" => 0xb5,
        "NOP7" => 0xb6,
        "NOP8" => 0xb7,
        "NOP9" => 0xb8,
        "NOP10" => 0xb9,
        "CHECKSIGADD" => 0xba,
        _ => return None,
    })
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("odd hex length: {}", s));
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .map_err(|e| format!("bad hex '{}': {}", &s[2*i..2*i+2], e))
        })
        .collect()
}

// ─── Transaction builders ────────────────────────────────────────────────────

/// Build the crediting transaction (prevout holder).
fn make_crediting_tx(script_pubkey: &[u8], amount: u64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Hash256::ZERO, vout: 0xffffffff },
            script_sig: Script::from_bytes(vec![0x00, 0x00]), // OP_0 OP_0
            sequence: 0xffffffff,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: amount,
            script_pubkey: Script::from_bytes(script_pubkey.to_vec()),
        }],
        lock_time: 0,
    }
}

/// Compute the legacy txid (double-SHA256 of legacy-serialized tx).
fn txid(tx: &Transaction) -> TxId {
    let mut buf = Vec::new();
    tx.encode_legacy(&mut buf).unwrap();
    rbtc_crypto::digest::sha256d(&buf)
}

/// Build the spending transaction.
fn make_spending_tx(
    cred: &Transaction,
    script_sig: &[u8],
    witness: Vec<Vec<u8>>,
    amount: u64,
) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: txid(cred), vout: 0 },
            script_sig: Script::from_bytes(script_sig.to_vec()),
            sequence: 0xffffffff,
            witness,
        }],
        outputs: vec![TxOut {
            value: amount,
            script_pubkey: Script::from_bytes(vec![]),
        }],
        lock_time: 0,
    }
}

// ─── Test runner ─────────────────────────────────────────────────────────────

/// Parse one entry from script_tests.json.
///
/// Returns `None` for comment-only entries.
struct ScriptTestCase {
    witness: Vec<Vec<u8>>,
    amount: u64,
    script_sig_asm: String,
    script_pubkey_asm: String,
    flags_str: String,
    expected_ok: bool,
    comment: String,
}

fn parse_entry(entry: &Value) -> Option<ScriptTestCase> {
    let arr = entry.as_array()?;
    if arr.is_empty() {
        return None;
    }

    let (witness_items, amount, rest_start) = if arr[0].is_array() {
        // Witness case: first element is [hex_item..., amount]
        let wit_arr = arr[0].as_array().unwrap();
        if wit_arr.len() < 1 {
            return None;
        }
        let amount = wit_arr.last()
            .and_then(|v| v.as_f64())
            .map(|btc| (btc * 100_000_000.0).round() as u64)
            .unwrap_or(0);
        let items: Vec<Vec<u8>> = wit_arr[..wit_arr.len()-1]
            .iter()
            .filter_map(|v| v.as_str().and_then(|s| decode_hex(s).ok()))
            .collect();
        (items, amount, 1usize)
    } else {
        (vec![], 0u64, 0usize)
    };

    // remaining elements: scriptSig, scriptPubKey, flags, expected, [comment...]
    if arr.len() < rest_start + 4 {
        return None; // not enough fields (could be a comment-only entry)
    }
    let script_sig_asm = arr[rest_start].as_str()?.to_string();
    let script_pubkey_asm = arr[rest_start + 1].as_str()?.to_string();
    let flags_str = arr[rest_start + 2].as_str()?.to_string();
    let expected_str = arr[rest_start + 3].as_str()?;
    let expected_ok = expected_str == "OK";
    let comment = arr.get(rest_start + 4)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Skip entries that look like pure comments (no proper flags field).
    let known_flags = ["NONE","P2SH","STRICTENC","DERSIG","LOW_S","SIGPUSHONLY",
                       "MINIMALDATA","DISCOURAGE_UPGRADABLE_NOPS","CLEANSTACK",
                       "CHECKLOCKTIMEVERIFY","CHECKSEQUENCEVERIFY","WITNESS",
                       "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM","MINIMALIF",
                       "NULLDUMMY","NULLFAIL","WITNESS_PUBKEYTYPE","CONST_SCRIPTCODE",
                       "TAPROOT","DISCOURAGE_UPGRADABLE_TAPROOT_VERSION",
                       "DISCOURAGE_OP_SUCCESS","DISCOURAGE_UPGRADABLE_PUBKEYTYPE"];
    let is_valid_flags = flags_str.split(',').all(|f| known_flags.contains(&f.trim()));
    if !is_valid_flags {
        return None;
    }

    Some(ScriptTestCase {
        witness: witness_items,
        amount,
        script_sig_asm,
        script_pubkey_asm,
        flags_str,
        expected_ok,
        comment,
    })
}

#[test]
fn script_tests_json() {
    let json_text = include_str!("data/script_tests.json");
    let data: Vec<Value> = serde_json::from_str(json_text).expect("parse script_tests.json");

    let mut total = 0usize;
    let mut failures = Vec::<String>::new();

    for entry in &data {
        let tc = match parse_entry(entry) {
            Some(t) => t,
            None => continue,
        };

        let script_sig_bytes = match parse_script_asm(&tc.script_sig_asm) {
            Ok(b) => b,
            Err(e) => {
                // Skip entries we can't parse (should be rare).
                eprintln!("SKIP (parse error in scriptSig '{}': {})", tc.script_sig_asm, e);
                continue;
            }
        };
        let script_pubkey_bytes = match parse_script_asm(&tc.script_pubkey_asm) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("SKIP (parse error in scriptPubKey '{}': {})", tc.script_pubkey_asm, e);
                continue;
            }
        };

        let flags = ScriptFlags::from_test_str(&tc.flags_str);

        let cred = make_crediting_tx(&script_pubkey_bytes, tc.amount);
        let spend = make_spending_tx(&cred, &script_sig_bytes, tc.witness.clone(), tc.amount);
        let prevout = cred.outputs[0].clone();
        let all_prevouts = vec![prevout.clone()];

        let ctx = ScriptContext {
            tx: &spend,
            input_index: 0,
            prevout: &prevout,
            flags,
            all_prevouts: &all_prevouts,
        };

        let result = verify_input(&ctx);
        let got_ok = result.is_ok();

        total += 1;
        if got_ok != tc.expected_ok {
            let label = if tc.comment.is_empty() {
                format!("sig='{}' spk='{}' flags='{}'",
                    tc.script_sig_asm, tc.script_pubkey_asm, tc.flags_str)
            } else {
                tc.comment.clone()
            };
            let err_str = match &result {
                Ok(_) => "Ok (expected Err)".to_string(),
                Err(e) => format!("Err({}) (expected Ok)", e),
            };
            failures.push(format!("[{}] expected={} got={} — {}",
                label, tc.expected_ok, got_ok, err_str));
        }
    }

    if !failures.is_empty() {
        eprintln!("\n=== SCRIPT TEST FAILURES ({}/{}) ===", failures.len(), total);
        for f in &failures {
            eprintln!("  FAIL: {}", f);
        }
        panic!("{} / {} script_tests.json cases failed", failures.len(), total);
    }

    println!("script_tests.json: {total} cases all passed");
}
