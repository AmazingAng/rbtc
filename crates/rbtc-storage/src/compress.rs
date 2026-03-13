/// UTXO compression matching Bitcoin Core's CompressAmount and script compression.
///
/// See Bitcoin Core `src/compressor.cpp` for the reference implementation.

use secp256k1::PublicKey;

// ---------------------------------------------------------------------------
// Amount compression
// ---------------------------------------------------------------------------

/// Compress a satoshi amount into a compact representation.
/// Amounts divisible by powers of 10 compress better.
/// Matches Bitcoin Core's `CTxOutCompressor::CompressAmount`.
pub fn compress_amount(mut n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut e: u64 = 0;
    while n % 10 == 0 && e < 9 {
        n /= 10;
        e += 1;
    }
    if e < 9 {
        let d = (n % 10) - 1;
        n /= 10;
        1 + (n * 9 + d) * 10 + e
    } else {
        1 + (n - 1) * 10 + 9
    }
}

/// Decompress a compact amount back to satoshis.
pub fn decompress_amount(mut x: u64) -> u64 {
    if x == 0 {
        return 0;
    }
    x -= 1;
    let mut e = x % 10;
    x /= 10;
    let mut n;
    if e < 9 {
        let d = (x % 9) + 1;
        x /= 9;
        n = x * 10 + d;
    } else {
        n = x + 1;
    }
    while e > 0 {
        n *= 10;
        e -= 1;
    }
    n
}

// ---------------------------------------------------------------------------
// Script compression
// ---------------------------------------------------------------------------

/// Script compression type identifiers (matching Bitcoin Core).
const SCRIPT_TYPE_P2PKH: u8 = 0x00;
const SCRIPT_TYPE_P2SH: u8 = 0x01;
// 0x02 / 0x03 — compressed pubkey P2PK (parity encoded in type byte)
// 0x04 / 0x05 — uncompressed pubkey P2PK (parity encoded in type byte)

/// Compress a scriptPubKey.
///
/// The compressed format is a single type byte followed by the compressed payload:
/// - Type 0x00: P2PKH — 20-byte pubkey hash
/// - Type 0x01: P2SH  — 20-byte script hash
/// - Type 0x02/0x03: Compressed pubkey P2PK — 32-byte x-coordinate
/// - Type 0x04/0x05: Uncompressed pubkey P2PK — 32-byte x-coordinate
/// - Otherwise: (script.len() + 6) as type byte, followed by raw script
pub fn compress_script(script: &[u8]) -> Vec<u8> {
    // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    // 76 a9 14 <20> 88 ac  (25 bytes)
    if script.len() == 25
        && script[0] == 0x76
        && script[1] == 0xa9
        && script[2] == 0x14
        && script[23] == 0x88
        && script[24] == 0xac
    {
        let mut out = Vec::with_capacity(21);
        out.push(SCRIPT_TYPE_P2PKH);
        out.extend_from_slice(&script[3..23]);
        return out;
    }

    // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
    // a9 14 <20> 87  (23 bytes)
    if script.len() == 23
        && script[0] == 0xa9
        && script[1] == 0x14
        && script[22] == 0x87
    {
        let mut out = Vec::with_capacity(21);
        out.push(SCRIPT_TYPE_P2SH);
        out.extend_from_slice(&script[2..22]);
        return out;
    }

    // P2PK with compressed pubkey: <33 bytes pubkey> OP_CHECKSIG
    // (script[0] == 0x21 means push 33 bytes; script[1] is 0x02 or 0x03)
    if script.len() == 35
        && script[0] == 0x21
        && (script[1] == 0x02 || script[1] == 0x03)
        && script[34] == 0xac
    {
        let mut out = Vec::with_capacity(33);
        out.push(script[1]); // 0x02 or 0x03
        out.extend_from_slice(&script[2..34]);
        return out;
    }

    // P2PK with uncompressed pubkey: <65 bytes pubkey> OP_CHECKSIG
    // (script[0] == 0x41 means push 65 bytes; script[1] is 0x04)
    if script.len() == 67
        && script[0] == 0x41
        && script[1] == 0x04
        && script[66] == 0xac
    {
        // Encode parity of y-coordinate in the type byte (0x04 or 0x05).
        let parity = script[65] & 1; // last byte of y
        let mut out = Vec::with_capacity(33);
        out.push(0x04 | parity);
        out.extend_from_slice(&script[2..34]); // x-coordinate only
        return out;
    }

    // Fallback: store raw script with type = script.len() + 6
    let type_byte = (script.len() as u64) + 6;
    let mut out = Vec::new();
    // Encode type as varint
    encode_varint(&mut out, type_byte);
    out.extend_from_slice(script);
    out
}

/// Decompress a script from its compressed form.
///
/// Returns the full scriptPubKey.
pub fn decompress_script(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }

    let (type_val, consumed) = decode_varint(data);
    let payload = &data[consumed..];

    match type_val {
        0x00 => {
            // P2PKH
            if payload.len() < 20 {
                return data.to_vec();
            }
            let mut script = Vec::with_capacity(25);
            script.push(0x76); // OP_DUP
            script.push(0xa9); // OP_HASH160
            script.push(0x14); // push 20 bytes
            script.extend_from_slice(&payload[..20]);
            script.push(0x88); // OP_EQUALVERIFY
            script.push(0xac); // OP_CHECKSIG
            script
        }
        0x01 => {
            // P2SH
            if payload.len() < 20 {
                return data.to_vec();
            }
            let mut script = Vec::with_capacity(23);
            script.push(0xa9); // OP_HASH160
            script.push(0x14); // push 20 bytes
            script.extend_from_slice(&payload[..20]);
            script.push(0x87); // OP_EQUAL
            script
        }
        0x02 | 0x03 => {
            // Compressed pubkey P2PK
            if payload.len() < 32 {
                return data.to_vec();
            }
            let mut script = Vec::with_capacity(35);
            script.push(0x21); // push 33 bytes
            script.push(type_val as u8); // 0x02 or 0x03
            script.extend_from_slice(&payload[..32]);
            script.push(0xac); // OP_CHECKSIG
            script
        }
        0x04 | 0x05 => {
            // Uncompressed pubkey P2PK — reconstruct full 65-byte uncompressed
            // key from x-coordinate using EC point decompression.
            if payload.len() < 32 {
                return data.to_vec();
            }
            let parity_byte = 0x02 | ((type_val as u8) & 1);
            let mut compressed_key = Vec::with_capacity(33);
            compressed_key.push(parity_byte);
            compressed_key.extend_from_slice(&payload[..32]);
            match PublicKey::from_slice(&compressed_key) {
                Ok(pk) => {
                    let uncompressed = pk.serialize_uncompressed();
                    let mut script = Vec::with_capacity(67);
                    script.push(0x41); // push 65 bytes
                    script.extend_from_slice(&uncompressed);
                    script.push(0xac); // OP_CHECKSIG
                    script
                }
                Err(_) => data.to_vec(),
            }
        }
        n if n >= 6 => {
            // Raw script; length = n - 6
            let script_len = (n - 6) as usize;
            if payload.len() < script_len {
                return data.to_vec();
            }
            payload[..script_len].to_vec()
        }
        _ => data.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Bitcoin Core base-128 VARINT (serialize.h WriteVarInt / ReadVarInt)
//
// NOT the same as the network compact-size encoding.  Used for DB
// serialisation of Coin (height/coinbase code, compressed amount,
// compressed script type).
//
// Encoding: MSB-first base-128 with +1 offset on continuation bytes.
//   while n >= 0x80 { write (n & 0x7F) | 0x80; n = (n >> 7) - 1 }
//   write n
// Bytes are emitted MSB-first (high group first).
// ---------------------------------------------------------------------------

/// Encode `n` using Bitcoin Core's base-128 VARINT and append to `buf`.
pub fn write_varint(buf: &mut Vec<u8>, n: u64) {
    // Collect digits LSB-first, then reverse for MSB-first output.
    let mut tmp = [0u8; 10]; // u64 needs at most 10 bytes
    let mut len = 0usize;
    let mut v = n;
    loop {
        tmp[len] = (v & 0x7F) as u8 | if len > 0 { 0x80 } else { 0x00 };
        if v <= 0x7F {
            break;
        }
        v = (v >> 7) - 1;
        len += 1;
    }
    // tmp[0..=len] holds the digits LSB-first; write in reverse (MSB-first).
    for i in (0..=len).rev() {
        buf.push(tmp[i]);
    }
}

/// Decode Bitcoin Core's base-128 VARINT from `data`.
/// Returns `(value, bytes_consumed)`.
pub fn read_varint(data: &[u8]) -> (u64, usize) {
    let mut n: u64 = 0;
    let mut i = 0;
    loop {
        if i >= data.len() {
            return (n, i);
        }
        let b = data[i];
        i += 1;
        n = (n << 7) | (b & 0x7F) as u64;
        if b & 0x80 != 0 {
            n += 1;
        } else {
            return (n, i);
        }
    }
}

/// Write Bitcoin Core's base-128 VARINT to a `std::io::Write` stream.
pub fn write_varint_to<W: std::io::Write>(w: &mut W, n: u64) -> std::io::Result<()> {
    let mut buf = Vec::new();
    write_varint(&mut buf, n);
    w.write_all(&buf)
}

/// Read Bitcoin Core's base-128 VARINT from a `std::io::Read` stream.
pub fn read_varint_from<R: std::io::Read>(r: &mut R) -> std::io::Result<u64> {
    let mut n: u64 = 0;
    loop {
        let mut byte = [0u8; 1];
        r.read_exact(&mut byte)?;
        n = (n << 7) | (byte[0] & 0x7F) as u64;
        if byte[0] & 0x80 != 0 {
            n += 1;
        } else {
            return Ok(n);
        }
    }
}

// ---------------------------------------------------------------------------
// Script compression — parts API (type + payload separate)
//
// Matches Bitcoin Core's ScriptCompression formatter: the type is encoded
// as a VARINT separately from the payload bytes.
// ---------------------------------------------------------------------------

/// Number of special (fixed-payload) script types.
const NUM_SPECIAL_SCRIPTS: u64 = 6;

/// Returns the payload size for special script types 0–5.
pub fn special_script_size(script_type: u64) -> usize {
    match script_type {
        0x00 | 0x01 => 20, // P2PKH / P2SH — 20-byte hash
        0x02 | 0x03 | 0x04 | 0x05 => 32, // P2PK — 32-byte x-coordinate
        _ => 0,
    }
}

/// Compress a scriptPubKey into (type, payload) matching Bitcoin Core's
/// `ScriptCompression` formatter.
///
/// - Type 0: P2PKH, payload = 20-byte pubkey hash
/// - Type 1: P2SH, payload = 20-byte script hash
/// - Type 2/3: compressed pubkey P2PK, payload = 32-byte x-coordinate
/// - Type 4/5: uncompressed pubkey P2PK, payload = 32-byte x-coordinate
/// - Type N >= 6: raw script, payload = raw script bytes (len = N - 6)
pub fn compress_script_parts(script: &[u8]) -> (u64, Vec<u8>) {
    // P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    if script.len() == 25
        && script[0] == 0x76
        && script[1] == 0xa9
        && script[2] == 0x14
        && script[23] == 0x88
        && script[24] == 0xac
    {
        return (0x00, script[3..23].to_vec());
    }

    // P2SH: OP_HASH160 <20> OP_EQUAL
    if script.len() == 23
        && script[0] == 0xa9
        && script[1] == 0x14
        && script[22] == 0x87
    {
        return (0x01, script[2..22].to_vec());
    }

    // P2PK compressed: <0x21> <02|03><32> OP_CHECKSIG
    if script.len() == 35
        && script[0] == 0x21
        && (script[1] == 0x02 || script[1] == 0x03)
        && script[34] == 0xac
    {
        return (script[1] as u64, script[2..34].to_vec());
    }

    // P2PK uncompressed: <0x41> <04><64> OP_CHECKSIG
    if script.len() == 67
        && script[0] == 0x41
        && script[1] == 0x04
        && script[66] == 0xac
    {
        let parity = script[65] & 1;
        return (0x04 | parity as u64, script[2..34].to_vec());
    }

    // Fallback: raw script
    let script_type = (script.len() as u64) + NUM_SPECIAL_SCRIPTS;
    (script_type, script.to_vec())
}

/// Decompress a (type, payload) pair back into a full scriptPubKey.
pub fn decompress_script_parts(script_type: u64, payload: &[u8]) -> Vec<u8> {
    match script_type {
        0x00 => {
            if payload.len() < 20 { return payload.to_vec(); }
            let mut s = Vec::with_capacity(25);
            s.extend_from_slice(&[0x76, 0xa9, 0x14]);
            s.extend_from_slice(&payload[..20]);
            s.extend_from_slice(&[0x88, 0xac]);
            s
        }
        0x01 => {
            if payload.len() < 20 { return payload.to_vec(); }
            let mut s = Vec::with_capacity(23);
            s.extend_from_slice(&[0xa9, 0x14]);
            s.extend_from_slice(&payload[..20]);
            s.push(0x87);
            s
        }
        0x02 | 0x03 => {
            if payload.len() < 32 { return payload.to_vec(); }
            let mut s = Vec::with_capacity(35);
            s.push(0x21);
            s.push(script_type as u8);
            s.extend_from_slice(&payload[..32]);
            s.push(0xac);
            s
        }
        0x04 | 0x05 => {
            // Uncompressed pubkey P2PK — reconstruct full 65-byte uncompressed
            // key from x-coordinate using EC point decompression.
            if payload.len() < 32 { return payload.to_vec(); }
            let parity_byte = 0x02 | ((script_type as u8) & 1);
            let mut compressed_key = Vec::with_capacity(33);
            compressed_key.push(parity_byte);
            compressed_key.extend_from_slice(&payload[..32]);
            match PublicKey::from_slice(&compressed_key) {
                Ok(pk) => {
                    let uncompressed = pk.serialize_uncompressed();
                    let mut s = Vec::with_capacity(67);
                    s.push(0x41); // push 65 bytes
                    s.extend_from_slice(&uncompressed);
                    s.push(0xac); // OP_CHECKSIG
                    s
                }
                Err(_) => payload.to_vec(),
            }
        }
        n if n >= NUM_SPECIAL_SCRIPTS => {
            let script_len = (n - NUM_SPECIAL_SCRIPTS) as usize;
            if payload.len() < script_len { return payload.to_vec(); }
            payload[..script_len].to_vec()
        }
        _ => payload.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Legacy compact-size varint (network encoding) — kept for compress_script
// backward compatibility (used by existing undo data, snapshot format, etc.)
// ---------------------------------------------------------------------------

fn encode_varint(buf: &mut Vec<u8>, n: u64) {
    if n < 253 {
        buf.push(n as u8);
    } else if n <= 0xFFFF {
        buf.push(253);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        buf.push(254);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(255);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

fn decode_varint(data: &[u8]) -> (u64, usize) {
    if data.is_empty() {
        return (0, 0);
    }
    match data[0] {
        253 => {
            if data.len() < 3 {
                return (data[0] as u64, 1);
            }
            let v = u16::from_le_bytes([data[1], data[2]]);
            (v as u64, 3)
        }
        254 => {
            if data.len() < 5 {
                return (data[0] as u64, 1);
            }
            let v = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            (v as u64, 5)
        }
        255 => {
            if data.len() < 9 {
                return (data[0] as u64, 1);
            }
            let v = u64::from_le_bytes([
                data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
            ]);
            (v, 9)
        }
        b => (b as u64, 1),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compress_amount_zero() {
        assert_eq!(compress_amount(0), 0);
        assert_eq!(decompress_amount(0), 0);
    }

    #[test]
    fn compress_decompress_amount_roundtrip() {
        let test_values: &[u64] = &[
            0,
            1,
            2,
            10,
            50,
            100,
            500,
            1000,
            5000,
            10_000,
            50_000,
            100_000,
            500_000,
            1_000_000,
            10_000_000,
            50_000_000,
            100_000_000,        // 1 BTC
            500_000_000,
            1_000_000_000,
            2_100_000_000_000_000, // 21M BTC
            123_456_789,
            99_999_999,
            1_234,
            7,
        ];
        for &v in test_values {
            let compressed = compress_amount(v);
            let decompressed = decompress_amount(compressed);
            assert_eq!(
                decompressed, v,
                "roundtrip failed for {v}: compressed={compressed}, decompressed={decompressed}"
            );
        }
    }

    #[test]
    fn compress_amount_known_values() {
        // 1 BTC = 100_000_000 sats — a round number should compress well
        let one_btc = 100_000_000u64;
        let compressed = compress_amount(one_btc);
        // Verify it decompresses back
        assert_eq!(decompress_amount(compressed), one_btc);
        // The compressed value should be much smaller than the raw amount
        assert!(compressed < one_btc);

        // 1 sat
        let one_sat = 1u64;
        let c1 = compress_amount(one_sat);
        assert_eq!(decompress_amount(c1), one_sat);

        // 50 BTC (block reward)
        let fifty_btc = 5_000_000_000u64;
        let c50 = compress_amount(fifty_btc);
        assert_eq!(decompress_amount(c50), fifty_btc);
        assert!(c50 < fifty_btc);
    }

    #[test]
    fn compress_script_p2pkh() {
        // Standard P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        let mut script = vec![0x76, 0xa9, 0x14];
        let hash = [0xab; 20];
        script.extend_from_slice(&hash);
        script.push(0x88);
        script.push(0xac);

        let compressed = compress_script(&script);
        assert_eq!(compressed.len(), 21);
        assert_eq!(compressed[0], SCRIPT_TYPE_P2PKH);
        assert_eq!(&compressed[1..], &hash);
    }

    #[test]
    fn compress_script_p2sh() {
        // Standard P2SH: OP_HASH160 <20 bytes> OP_EQUAL
        let mut script = vec![0xa9, 0x14];
        let hash = [0xcd; 20];
        script.extend_from_slice(&hash);
        script.push(0x87);

        let compressed = compress_script(&script);
        assert_eq!(compressed.len(), 21);
        assert_eq!(compressed[0], SCRIPT_TYPE_P2SH);
        assert_eq!(&compressed[1..], &hash);
    }

    #[test]
    fn compress_script_roundtrip() {
        // P2PKH roundtrip
        let mut p2pkh = vec![0x76, 0xa9, 0x14];
        p2pkh.extend_from_slice(&[0x11; 20]);
        p2pkh.push(0x88);
        p2pkh.push(0xac);
        let decompressed = decompress_script(&compress_script(&p2pkh));
        assert_eq!(decompressed, p2pkh);

        // P2SH roundtrip
        let mut p2sh = vec![0xa9, 0x14];
        p2sh.extend_from_slice(&[0x22; 20]);
        p2sh.push(0x87);
        let decompressed = decompress_script(&compress_script(&p2sh));
        assert_eq!(decompressed, p2sh);

        // Compressed pubkey P2PK roundtrip
        let mut p2pk_c = vec![0x21, 0x02];
        p2pk_c.extend_from_slice(&[0x33; 32]);
        p2pk_c.push(0xac);
        let decompressed = decompress_script(&compress_script(&p2pk_c));
        assert_eq!(decompressed, p2pk_c);

        // Uncompressed pubkey P2PK roundtrip (using a real EC point)
        // Use secp256k1 generator point G as a valid public key
        let mut compressed_bytes = [0u8; 33];
        compressed_bytes[0] = 0x02;
        compressed_bytes[1] = 0x79;
        compressed_bytes[2] = 0xbe;
        compressed_bytes[3] = 0x66;
        compressed_bytes[4] = 0x7e;
        compressed_bytes[5] = 0xf9;
        // Fill rest with the actual x-coordinate of G
        compressed_bytes[6..].copy_from_slice(&[
            0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
            0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d,
            0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
            0xf8, 0x17, 0x98,
        ]);
        let pk = PublicKey::from_slice(&compressed_bytes).unwrap();
        let uncompressed = pk.serialize_uncompressed();
        let mut p2pk_u = vec![0x41];
        p2pk_u.extend_from_slice(&uncompressed);
        p2pk_u.push(0xac);
        assert_eq!(p2pk_u.len(), 67);
        let decompressed = decompress_script(&compress_script(&p2pk_u));
        assert_eq!(decompressed, p2pk_u, "uncompressed P2PK roundtrip failed");

        // Also test via compress_script_parts / decompress_script_parts
        let (stype, payload) = compress_script_parts(&p2pk_u);
        assert!(stype == 0x04 || stype == 0x05, "uncompressed P2PK should have type 0x04 or 0x05");
        let decompressed2 = decompress_script_parts(stype, &payload);
        assert_eq!(decompressed2, p2pk_u, "uncompressed P2PK parts roundtrip failed");

        // Non-standard script roundtrip
        let raw = vec![0x51, 0x52, 0x93, 0x87]; // OP_1 OP_2 OP_ADD OP_EQUAL
        let decompressed = decompress_script(&compress_script(&raw));
        assert_eq!(decompressed, raw);
    }

    #[test]
    fn compress_script_p2pk_compressed() {
        // P2PK with compressed pubkey: <0x21> <02|03><32-byte x> <OP_CHECKSIG>
        let mut script = vec![0x21, 0x03];
        let x_coord = [0x44; 32];
        script.extend_from_slice(&x_coord);
        script.push(0xac);

        let compressed = compress_script(&script);
        assert_eq!(compressed.len(), 33);
        assert_eq!(compressed[0], 0x03);
        assert_eq!(&compressed[1..], &x_coord);
    }

    #[test]
    fn varint_core_roundtrip() {
        // Bitcoin Core base-128 VARINT encoding
        let test_values: &[u64] = &[
            0, 1, 127, 128, 255, 256, 16383, 16384, 65535,
            100_000, 1_000_000, 100_000_000, u32::MAX as u64,
            u64::MAX / 2, u64::MAX,
        ];
        for &v in test_values {
            let mut buf = Vec::new();
            write_varint(&mut buf, v);
            let (decoded, consumed) = read_varint(&buf);
            assert_eq!(decoded, v, "roundtrip failed for {v}");
            assert_eq!(consumed, buf.len(), "not all bytes consumed for {v}");
        }
    }

    #[test]
    fn varint_core_known_encodings() {
        // Verify specific encodings match Bitcoin Core
        let mut buf = Vec::new();
        write_varint(&mut buf, 0);
        assert_eq!(buf, vec![0x00]);

        buf.clear();
        write_varint(&mut buf, 127);
        assert_eq!(buf, vec![0x7F]);

        buf.clear();
        write_varint(&mut buf, 128);
        assert_eq!(buf, vec![0x80, 0x00]);

        buf.clear();
        write_varint(&mut buf, 255);
        assert_eq!(buf, vec![0x80, 0x7F]);

        buf.clear();
        write_varint(&mut buf, 256);
        assert_eq!(buf, vec![0x81, 0x00]);
    }

    #[test]
    fn varint_core_stream_roundtrip() {
        let values = [0u64, 1, 128, 65535, 100_000_000];
        let mut buf = Vec::new();
        for &v in &values {
            write_varint_to(&mut buf, v).unwrap();
        }
        let mut cursor = std::io::Cursor::new(&buf);
        for &v in &values {
            let decoded = read_varint_from(&mut cursor).unwrap();
            assert_eq!(decoded, v);
        }
    }

    #[test]
    fn compress_script_parts_p2pkh() {
        let mut script = vec![0x76, 0xa9, 0x14];
        let hash = [0xab; 20];
        script.extend_from_slice(&hash);
        script.push(0x88);
        script.push(0xac);

        let (stype, payload) = compress_script_parts(&script);
        assert_eq!(stype, 0x00);
        assert_eq!(payload, hash);

        let decompressed = decompress_script_parts(stype, &payload);
        assert_eq!(decompressed, script);
    }

    #[test]
    fn compress_script_parts_raw_roundtrip() {
        let raw = vec![0x51, 0x52, 0x93, 0x87];
        let (stype, payload) = compress_script_parts(&raw);
        assert_eq!(stype, raw.len() as u64 + 6);
        assert_eq!(payload, raw);

        let decompressed = decompress_script_parts(stype, &payload);
        assert_eq!(decompressed, raw);
    }

    #[test]
    fn compress_script_non_standard() {
        // Non-standard script should be stored as-is with type = len + 6
        let raw = vec![0x00, 0x14, 0xaa, 0xbb, 0xcc];
        let compressed = compress_script(&raw);
        // type byte should be 5 + 6 = 11
        assert_eq!(compressed[0], 11);
        assert_eq!(&compressed[1..], &raw);

        let decompressed = decompress_script(&compressed);
        assert_eq!(decompressed, raw);
    }
}
