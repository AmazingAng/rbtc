/// Bitcoin Script opcode constants.
///
/// Named constants for every opcode used in Bitcoin Script, matching
/// Bitcoin Core's `opcodetype` enum in `script/script.h`.

// ── Push values ──────────────────────────────────────────────────────────────

pub const OP_0: u8 = 0x00;
pub const OP_FALSE: u8 = OP_0;
pub const OP_PUSHDATA1: u8 = 0x4c;
pub const OP_PUSHDATA2: u8 = 0x4d;
pub const OP_PUSHDATA4: u8 = 0x4e;
pub const OP_1NEGATE: u8 = 0x4f;
pub const OP_RESERVED: u8 = 0x50;
pub const OP_1: u8 = 0x51;
pub const OP_TRUE: u8 = OP_1;
pub const OP_2: u8 = 0x52;
pub const OP_3: u8 = 0x53;
pub const OP_4: u8 = 0x54;
pub const OP_5: u8 = 0x55;
pub const OP_6: u8 = 0x56;
pub const OP_7: u8 = 0x57;
pub const OP_8: u8 = 0x58;
pub const OP_9: u8 = 0x59;
pub const OP_10: u8 = 0x5a;
pub const OP_11: u8 = 0x5b;
pub const OP_12: u8 = 0x5c;
pub const OP_13: u8 = 0x5d;
pub const OP_14: u8 = 0x5e;
pub const OP_15: u8 = 0x5f;
pub const OP_16: u8 = 0x60;

// ── Flow control ─────────────────────────────────────────────────────────────

pub const OP_NOP: u8 = 0x61;
pub const OP_VER: u8 = 0x62;
pub const OP_IF: u8 = 0x63;
pub const OP_NOTIF: u8 = 0x64;
pub const OP_VERIF: u8 = 0x65;
pub const OP_VERNOTIF: u8 = 0x66;
pub const OP_ELSE: u8 = 0x67;
pub const OP_ENDIF: u8 = 0x68;
pub const OP_VERIFY: u8 = 0x69;
pub const OP_RETURN: u8 = 0x6a;

// ── Stack ────────────────────────────────────────────────────────────────────

pub const OP_TOALTSTACK: u8 = 0x6b;
pub const OP_FROMALTSTACK: u8 = 0x6c;
pub const OP_2DROP: u8 = 0x6d;
pub const OP_2DUP: u8 = 0x6e;
pub const OP_3DUP: u8 = 0x6f;
pub const OP_2OVER: u8 = 0x70;
pub const OP_2ROT: u8 = 0x71;
pub const OP_2SWAP: u8 = 0x72;
pub const OP_IFDUP: u8 = 0x73;
pub const OP_DEPTH: u8 = 0x74;
pub const OP_DROP: u8 = 0x75;
pub const OP_DUP: u8 = 0x76;
pub const OP_NIP: u8 = 0x77;
pub const OP_OVER: u8 = 0x78;
pub const OP_PICK: u8 = 0x79;
pub const OP_ROLL: u8 = 0x7a;
pub const OP_ROT: u8 = 0x7b;
pub const OP_SWAP: u8 = 0x7c;
pub const OP_TUCK: u8 = 0x7d;

// ── Splice ───────────────────────────────────────────────────────────────────

pub const OP_CAT: u8 = 0x7e;
pub const OP_SUBSTR: u8 = 0x7f;
pub const OP_LEFT: u8 = 0x80;
pub const OP_RIGHT: u8 = 0x81;
pub const OP_SIZE: u8 = 0x82;

// ── Bitwise logic ────────────────────────────────────────────────────────────

pub const OP_INVERT: u8 = 0x83;
pub const OP_AND: u8 = 0x84;
pub const OP_OR: u8 = 0x85;
pub const OP_XOR: u8 = 0x86;
pub const OP_EQUAL: u8 = 0x87;
pub const OP_EQUALVERIFY: u8 = 0x88;
pub const OP_RESERVED1: u8 = 0x89;
pub const OP_RESERVED2: u8 = 0x8a;

// ── Arithmetic ───────────────────────────────────────────────────────────────

pub const OP_1ADD: u8 = 0x8b;
pub const OP_1SUB: u8 = 0x8c;
pub const OP_2MUL: u8 = 0x8d;
pub const OP_2DIV: u8 = 0x8e;
pub const OP_NEGATE: u8 = 0x8f;
pub const OP_ABS: u8 = 0x90;
pub const OP_NOT: u8 = 0x91;
pub const OP_0NOTEQUAL: u8 = 0x92;
pub const OP_ADD: u8 = 0x93;
pub const OP_SUB: u8 = 0x94;
pub const OP_MUL: u8 = 0x95;
pub const OP_DIV: u8 = 0x96;
pub const OP_MOD: u8 = 0x97;
pub const OP_LSHIFT: u8 = 0x98;
pub const OP_RSHIFT: u8 = 0x99;
pub const OP_BOOLAND: u8 = 0x9a;
pub const OP_BOOLOR: u8 = 0x9b;
pub const OP_NUMEQUAL: u8 = 0x9c;
pub const OP_NUMEQUALVERIFY: u8 = 0x9d;
pub const OP_NUMNOTEQUAL: u8 = 0x9e;
pub const OP_LESSTHAN: u8 = 0x9f;
pub const OP_GREATERTHAN: u8 = 0xa0;
pub const OP_LESSTHANOREQUAL: u8 = 0xa1;
pub const OP_GREATERTHANOREQUAL: u8 = 0xa2;
pub const OP_MIN: u8 = 0xa3;
pub const OP_MAX: u8 = 0xa4;
pub const OP_WITHIN: u8 = 0xa5;

// ── Crypto ───────────────────────────────────────────────────────────────────

pub const OP_RIPEMD160: u8 = 0xa6;
pub const OP_SHA1: u8 = 0xa7;
pub const OP_SHA256: u8 = 0xa8;
pub const OP_HASH160: u8 = 0xa9;
pub const OP_HASH256: u8 = 0xaa;
pub const OP_CODESEPARATOR: u8 = 0xab;
pub const OP_CHECKSIG: u8 = 0xac;
pub const OP_CHECKSIGVERIFY: u8 = 0xad;
pub const OP_CHECKMULTISIG: u8 = 0xae;
pub const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;

// ── Expansion (NOP1–NOP10, BIP65/BIP112 redefine NOP2/NOP3) ─────────────────

pub const OP_NOP1: u8 = 0xb0;
pub const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
pub const OP_NOP2: u8 = OP_CHECKLOCKTIMEVERIFY;
pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;
pub const OP_NOP3: u8 = OP_CHECKSEQUENCEVERIFY;
pub const OP_NOP4: u8 = 0xb3;
pub const OP_NOP5: u8 = 0xb4;
pub const OP_NOP6: u8 = 0xb5;
pub const OP_NOP7: u8 = 0xb6;
pub const OP_NOP8: u8 = 0xb7;
pub const OP_NOP9: u8 = 0xb8;
pub const OP_NOP10: u8 = 0xb9;

// ── Taproot (BIP342) ─────────────────────────────────────────────────────────

pub const OP_CHECKSIGADD: u8 = 0xba;

// ── Invalid ──────────────────────────────────────────────────────────────────

pub const OP_INVALIDOPCODE: u8 = 0xff;

/// Return a human-readable name for an opcode byte.
pub fn opcode_name(op: u8) -> &'static str {
    match op {
        0x00 => "OP_0",
        0x01..=0x4b => "OP_PUSHBYTES",
        0x4c => "OP_PUSHDATA1",
        0x4d => "OP_PUSHDATA2",
        0x4e => "OP_PUSHDATA4",
        0x4f => "OP_1NEGATE",
        0x50 => "OP_RESERVED",
        0x51 => "OP_1",
        0x52 => "OP_2",
        0x53 => "OP_3",
        0x54 => "OP_4",
        0x55 => "OP_5",
        0x56 => "OP_6",
        0x57 => "OP_7",
        0x58 => "OP_8",
        0x59 => "OP_9",
        0x5a => "OP_10",
        0x5b => "OP_11",
        0x5c => "OP_12",
        0x5d => "OP_13",
        0x5e => "OP_14",
        0x5f => "OP_15",
        0x60 => "OP_16",
        0x61 => "OP_NOP",
        0x62 => "OP_VER",
        0x63 => "OP_IF",
        0x64 => "OP_NOTIF",
        0x65 => "OP_VERIF",
        0x66 => "OP_VERNOTIF",
        0x67 => "OP_ELSE",
        0x68 => "OP_ENDIF",
        0x69 => "OP_VERIFY",
        0x6a => "OP_RETURN",
        0x6b => "OP_TOALTSTACK",
        0x6c => "OP_FROMALTSTACK",
        0x6d => "OP_2DROP",
        0x6e => "OP_2DUP",
        0x6f => "OP_3DUP",
        0x70 => "OP_2OVER",
        0x71 => "OP_2ROT",
        0x72 => "OP_2SWAP",
        0x73 => "OP_IFDUP",
        0x74 => "OP_DEPTH",
        0x75 => "OP_DROP",
        0x76 => "OP_DUP",
        0x77 => "OP_NIP",
        0x78 => "OP_OVER",
        0x79 => "OP_PICK",
        0x7a => "OP_ROLL",
        0x7b => "OP_ROT",
        0x7c => "OP_SWAP",
        0x7d => "OP_TUCK",
        0x7e => "OP_CAT",
        0x7f => "OP_SUBSTR",
        0x80 => "OP_LEFT",
        0x81 => "OP_RIGHT",
        0x82 => "OP_SIZE",
        0x83 => "OP_INVERT",
        0x84 => "OP_AND",
        0x85 => "OP_OR",
        0x86 => "OP_XOR",
        0x87 => "OP_EQUAL",
        0x88 => "OP_EQUALVERIFY",
        0x89 => "OP_RESERVED1",
        0x8a => "OP_RESERVED2",
        0x8b => "OP_1ADD",
        0x8c => "OP_1SUB",
        0x8d => "OP_2MUL",
        0x8e => "OP_2DIV",
        0x8f => "OP_NEGATE",
        0x90 => "OP_ABS",
        0x91 => "OP_NOT",
        0x92 => "OP_0NOTEQUAL",
        0x93 => "OP_ADD",
        0x94 => "OP_SUB",
        0x95 => "OP_MUL",
        0x96 => "OP_DIV",
        0x97 => "OP_MOD",
        0x98 => "OP_LSHIFT",
        0x99 => "OP_RSHIFT",
        0x9a => "OP_BOOLAND",
        0x9b => "OP_BOOLOR",
        0x9c => "OP_NUMEQUAL",
        0x9d => "OP_NUMEQUALVERIFY",
        0x9e => "OP_NUMNOTEQUAL",
        0x9f => "OP_LESSTHAN",
        0xa0 => "OP_GREATERTHAN",
        0xa1 => "OP_LESSTHANOREQUAL",
        0xa2 => "OP_GREATERTHANOREQUAL",
        0xa3 => "OP_MIN",
        0xa4 => "OP_MAX",
        0xa5 => "OP_WITHIN",
        0xa6 => "OP_RIPEMD160",
        0xa7 => "OP_SHA1",
        0xa8 => "OP_SHA256",
        0xa9 => "OP_HASH160",
        0xaa => "OP_HASH256",
        0xab => "OP_CODESEPARATOR",
        0xac => "OP_CHECKSIG",
        0xad => "OP_CHECKSIGVERIFY",
        0xae => "OP_CHECKMULTISIG",
        0xaf => "OP_CHECKMULTISIGVERIFY",
        0xb0 => "OP_NOP1",
        0xb1 => "OP_CHECKLOCKTIMEVERIFY",
        0xb2 => "OP_CHECKSEQUENCEVERIFY",
        0xb3 => "OP_NOP4",
        0xb4 => "OP_NOP5",
        0xb5 => "OP_NOP6",
        0xb6 => "OP_NOP7",
        0xb7 => "OP_NOP8",
        0xb8 => "OP_NOP9",
        0xb9 => "OP_NOP10",
        0xba => "OP_CHECKSIGADD",
        0xff => "OP_INVALIDOPCODE",
        _ => "OP_UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_values_match_bitcoin_core() {
        assert_eq!(OP_0, 0x00);
        assert_eq!(OP_DUP, 0x76);
        assert_eq!(OP_HASH160, 0xa9);
        assert_eq!(OP_EQUALVERIFY, 0x88);
        assert_eq!(OP_CHECKSIG, 0xac);
        assert_eq!(OP_CHECKMULTISIG, 0xae);
        assert_eq!(OP_RETURN, 0x6a);
        assert_eq!(OP_EQUAL, 0x87);
        assert_eq!(OP_CHECKLOCKTIMEVERIFY, 0xb1);
        assert_eq!(OP_CHECKSEQUENCEVERIFY, 0xb2);
        assert_eq!(OP_CHECKSIGADD, 0xba);
        assert_eq!(OP_16, 0x60);
        assert_eq!(OP_1, 0x51);
    }

    #[test]
    fn opcode_name_known_ops() {
        assert_eq!(opcode_name(OP_DUP), "OP_DUP");
        assert_eq!(opcode_name(OP_CHECKSIG), "OP_CHECKSIG");
        assert_eq!(opcode_name(OP_RETURN), "OP_RETURN");
        assert_eq!(opcode_name(OP_0), "OP_0");
        assert_eq!(opcode_name(OP_CHECKSIGADD), "OP_CHECKSIGADD");
    }

    #[test]
    fn opcode_name_push_bytes() {
        for op in 0x01..=0x4bu8 {
            assert_eq!(opcode_name(op), "OP_PUSHBYTES");
        }
    }

    #[test]
    fn opcode_name_unknown() {
        assert_eq!(opcode_name(0xbb), "OP_UNKNOWN");
        assert_eq!(opcode_name(0xfe), "OP_UNKNOWN");
    }

    #[test]
    fn nop_aliases() {
        assert_eq!(OP_NOP2, OP_CHECKLOCKTIMEVERIFY);
        assert_eq!(OP_NOP3, OP_CHECKSEQUENCEVERIFY);
        assert_eq!(OP_FALSE, OP_0);
        assert_eq!(OP_TRUE, OP_1);
    }
}
