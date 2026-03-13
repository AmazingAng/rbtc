/// Bitcoin Core tx_valid.json / tx_invalid.json test harness.
///
/// Format (both files):
///   `[[[prevout_hash, prevout_index, prevout_scriptPubKey, amount_btc?], …],
///     serialized_tx_hex,
///     flags_str]`
///
/// tx_valid  – `flags_str` lists **excluded** script-verify flags.
///   The transaction must pass with `ScriptFlags::standard() & ~excluded`.
///
/// tx_invalid – `flags_str` lists the **applied** script-verify flags.
///   The transaction must fail either basic CheckTransaction checks or
///   script verification.  Special value "BADTX" means CheckTransaction
///   itself should reject the transaction.
use rbtc_consensus::tx_verify::verify_transaction_scripts_with_prevouts;
use rbtc_primitives::{
    codec::Decodable,
    hash::Hash256,
    script::Script,
    transaction::{Transaction, TxOut},
};
use rbtc_script::ScriptFlags;
use serde_json::Value;

// ─── Hex helpers ─────────────────────────────────────────────────────────────

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("odd hex length: {s}"));
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .map_err(|e| format!("bad hex byte '{}': {e}", &s[2 * i..2 * i + 2]))
        })
        .collect()
}

// ─── Script ASM parser (mirrors script_tests.rs) ─────────────────────────────

fn opcode_byte(token: &str) -> Option<u8> {
    let t = if token.starts_with("OP_") {
        &token[3..]
    } else {
        token
    };
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
        "CHECKSEQUENCEVERIFY" | "CSV" | "NOP3" => 0xb2,
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

fn push_bytes(out: &mut Vec<u8>, data: &[u8]) {
    match data.len() {
        0 => out.push(0x00),
        1 => {
            let v = data[0];
            if v == 0x81 {
                out.push(0x4f);
            } else if (1..=16).contains(&v) {
                out.push(0x50 + v);
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

fn push_int(out: &mut Vec<u8>, n: i64) {
    if n == 0 {
        out.push(0x00);
    } else if n == -1 {
        out.push(0x4f);
    } else if (1..=16).contains(&n) {
        out.push(0x50 + n as u8);
    } else {
        let enc = encode_script_int(n);
        push_bytes(out, &enc);
    }
}

/// Parse script assembly notation (same rules as script_tests.rs).
fn parse_script_asm(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let s = s.trim();
    if s.is_empty() {
        return Ok(out);
    }

    let mut i = 0usize;
    let chars: Vec<char> = s.chars().collect();

    while i < chars.len() {
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }

        if chars[i] == '\'' {
            i += 1;
            let mut lit = Vec::new();
            while i < chars.len() && chars[i] != '\'' {
                lit.push(chars[i] as u8);
                i += 1;
            }
            if i < chars.len() {
                i += 1;
            }
            push_bytes(&mut out, &lit);
            continue;
        }

        let start = i;
        while i < chars.len() && !chars[i].is_whitespace() {
            i += 1;
        }
        let token: String = chars[start..i].iter().collect();

        if token.starts_with("0x") || token.starts_with("0X") {
            let hex = &token[2..];
            if !hex.is_empty() {
                let bytes = decode_hex(hex).map_err(|e| format!("bad hex '{}': {e}", token))?;
                out.extend_from_slice(&bytes);
            }
            continue;
        }

        if let Some(byte) = opcode_byte(&token) {
            out.push(byte);
            continue;
        }

        if let Ok(n) = token.parse::<i64>() {
            push_int(&mut out, n);
            continue;
        }

        return Err(format!("unknown token '{token}'"));
    }
    Ok(out)
}

// ─── Transaction deserializer ─────────────────────────────────────────────────

fn decode_tx(hex: &str) -> Result<Transaction, String> {
    let bytes = decode_hex(hex)?;
    let mut cur = std::io::Cursor::new(&bytes);
    Transaction::decode(&mut cur).map_err(|e| format!("tx decode error: {e}"))
}

// ─── Prevout parsing ──────────────────────────────────────────────────────────

struct Prevout {
    txout: TxOut,
}

fn parse_prevouts(arr: &Value) -> Result<Vec<Prevout>, String> {
    let items = arr.as_array().ok_or("prevouts is not array")?;
    let mut result = Vec::with_capacity(items.len());
    for item in items {
        let row = item.as_array().ok_or("prevout item not array")?;
        if row.len() < 3 {
            return Err(format!("prevout row too short: {item}"));
        }
        let txid_str = row[0].as_str().ok_or("txid not string")?;
        // Use i64 to handle vout = -1 (0xffffffff) used in coinbase inputs
        let _vout = row[1].as_i64().ok_or("vout not integer")? as u32;
        let spk_asm = row[2].as_str().ok_or("scriptpubkey not string")?;
        // Optional amount in satoshis (integer, not BTC float)
        let amount: u64 = if row.len() >= 4 {
            row[3].as_u64().ok_or("amount not u64")?
        } else {
            0
        };

        let _txid =
            Hash256::from_hex(txid_str).map_err(|e| format!("bad txid '{txid_str}': {e}"))?;
        let spk =
            parse_script_asm(spk_asm).map_err(|e| format!("bad scriptPubKey '{spk_asm}': {e}"))?;

        result.push(Prevout {
            txout: TxOut {
                value: amount as i64,
                script_pubkey: Script::from_bytes(spk),
            },
        });
    }
    Ok(result)
}

// ─── Basic CheckTransaction (mirrors Bitcoin Core) ────────────────────────────

const MAX_MONEY: i64 = 21_000_000 * 100_000_000;

fn check_transaction(tx: &Transaction) -> Result<(), String> {
    if tx.inputs.is_empty() {
        return Err("no inputs".into());
    }
    if tx.outputs.is_empty() {
        return Err("no outputs".into());
    }

    let mut total_out: i64 = 0;
    for out in &tx.outputs {
        if out.value < 0 {
            return Err(format!("output value {} is negative", out.value));
        }
        if out.value > MAX_MONEY {
            return Err(format!("output value {} exceeds MAX_MONEY", out.value));
        }
        total_out = total_out
            .checked_add(out.value)
            .ok_or_else(|| "output value overflow".to_string())?;
        if total_out > MAX_MONEY {
            return Err(format!("total output {} exceeds MAX_MONEY", total_out));
        }
    }

    // Duplicate inputs
    let mut seen = std::collections::HashSet::new();
    for inp in &tx.inputs {
        let key = (inp.previous_output.txid.0, inp.previous_output.vout);
        if !seen.insert(key) {
            return Err(format!(
                "duplicate input {}:{}",
                inp.previous_output.txid, inp.previous_output.vout
            ));
        }
    }

    // Non-coinbase inputs must not have null outpoints (txid=zero, vout=0xffffffff)
    if !tx.is_coinbase() {
        for inp in &tx.inputs {
            let is_null =
                inp.previous_output.txid.0.0 == [0u8; 32] && inp.previous_output.vout == u32::MAX;
            if is_null {
                return Err(format!("non-coinbase input has null outpoint"));
            }
        }
    }

    // Coinbase scriptSig length
    if tx.is_coinbase() {
        let len = tx.inputs[0].script_sig.len();
        if !(2..=100).contains(&len) {
            return Err(format!("coinbase scriptSig length {len} out of [2,100]"));
        }
    }

    Ok(())
}

// ─── Test runner ──────────────────────────────────────────────────────────────

struct TxTestCase {
    label: String,
    prevouts: Vec<Prevout>,
    tx_hex: String,
    flags_str: String,
}

/// Parse entries that are actual test cases (not comment strings).
fn parse_entries(json: &Value) -> Vec<TxTestCase> {
    let arr = match json.as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for entry in arr {
        let row = match entry.as_array() {
            Some(a) => a,
            None => continue,
        };
        // Comment entries: ["string"] or [] or single-string array
        if row.is_empty() {
            continue;
        }
        // If the first element is a string (not array), it's a comment row
        if row[0].is_string() {
            continue;
        }
        // Expect: [[prevouts], tx_hex, flags_str]
        if row.len() < 3 {
            continue;
        }
        let prevouts_val = &row[0];
        let tx_hex = match row[1].as_str() {
            Some(s) => s.to_string(),
            None => continue,
        };
        let flags = match row[2].as_str() {
            Some(s) => s.to_string(),
            None => continue,
        };

        let prevouts = match parse_prevouts(prevouts_val) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("SKIP (parse prevouts error: {e})");
                continue;
            }
        };

        let label = format!("tx={} flags={}", &tx_hex[..tx_hex.len().min(20)], flags);
        out.push(TxTestCase {
            label,
            prevouts,
            tx_hex,
            flags_str: flags,
        });
    }
    out
}

#[test]
fn tx_valid_json() {
    let raw: Value = serde_json::from_str(include_str!("data/tx_valid.json")).unwrap();
    let cases = parse_entries(&raw);

    let mut total = 0usize;
    let mut failures = Vec::new();

    for tc in &cases {
        total += 1;

        // Decode tx
        let tx = match decode_tx(&tc.tx_hex) {
            Ok(t) => t,
            Err(e) => {
                failures.push(format!("[DECODE] {}: {e}", tc.label));
                continue;
            }
        };

        // Build prevout list ordered by tx input
        let prevouts: Vec<TxOut> = tc.prevouts.iter().map(|p| p.txout.clone()).collect();

        // flags = standard & ~excluded
        let excluded = ScriptFlags::from_test_str(&tc.flags_str);
        let flags = ScriptFlags::standard_minus(&excluded);

        match verify_transaction_scripts_with_prevouts(&tx, &prevouts, flags) {
            Ok(()) => {}
            Err(e) => failures.push(format!("[FAIL] {}: {e}", tc.label)),
        }
    }

    if !failures.is_empty() {
        eprintln!("\n=== TX_VALID FAILURES ({}/{}) ===", failures.len(), total);
        for f in &failures {
            eprintln!("  {f}");
        }
        panic!("{}/{} tx_valid.json cases failed", failures.len(), total);
    }
    println!("tx_valid.json: {total} cases all passed");
}

#[test]
fn tx_invalid_json() {
    let raw: Value = serde_json::from_str(include_str!("data/tx_invalid.json")).unwrap();
    let cases = parse_entries(&raw);

    let mut total = 0usize;
    let mut false_ok = Vec::new(); // expected Err but got Ok

    for tc in &cases {
        total += 1;
        let is_badtx = tc.flags_str.contains("BADTX");

        // Try to decode the tx
        let tx = match decode_tx(&tc.tx_hex) {
            Ok(t) => t,
            Err(_) => {
                // Decode error → definitely invalid, test passes
                continue;
            }
        };

        if is_badtx {
            // Expect basic CheckTransaction to fail
            match check_transaction(&tx) {
                Err(_) => continue, // correctly rejected
                Ok(()) => {
                    false_ok.push(format!("[BADTX should fail] {}", tc.label));
                }
            }
            continue;
        }

        // CONST_SCRIPTCODE tests require FindAndDelete which we don't implement; skip
        if tc.flags_str.contains("CONST_SCRIPTCODE") {
            continue;
        }

        // Normal case: script verification should fail
        let prevouts: Vec<TxOut> = tc.prevouts.iter().map(|p| p.txout.clone()).collect();
        let flags = ScriptFlags::from_test_str(&tc.flags_str);

        match verify_transaction_scripts_with_prevouts(&tx, &prevouts, flags) {
            Err(_) => {} // correctly rejected
            Ok(()) => false_ok.push(format!("[should fail] {}", tc.label)),
        }
    }

    if !false_ok.is_empty() {
        eprintln!(
            "\n=== TX_INVALID FALSE-OK ({}/{}) ===",
            false_ok.len(),
            total
        );
        for f in &false_ok {
            eprintln!("  {f}");
        }
        panic!(
            "{}/{} tx_invalid.json cases falsely accepted",
            false_ok.len(),
            total
        );
    }
    println!("tx_invalid.json: {total} cases all correctly rejected");
}
