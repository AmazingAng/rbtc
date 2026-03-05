use rbtc_primitives::{
    constants::{MAX_OPS_PER_SCRIPT, MAX_PUBKEYS_PER_MULTISIG, MAX_SCRIPT_ELEMENT_SIZE, MAX_SCRIPT_SIZE, MAX_STACK_SIZE},
    script::Script,
    transaction::{Transaction, TxOut},
};
use rbtc_crypto::{
    digest::{hash160, sha256, sha256d},
    sig::{verify_ecdsa_with_policy, verify_schnorr},
    sighash::{sighash_legacy_with_u32, sighash_segwit_v0_with_u32, sighash_taproot, SighashType},
};
use secp256k1;
use thiserror::Error;

use crate::opcode::Opcode;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ScriptError {
    #[error("script failed: {0}")]
    ScriptFailed(String),
    #[error("stack underflow")]
    StackUnderflow,
    #[error("stack overflow")]
    StackOverflow,
    #[error("disabled opcode")]
    DisabledOpcode,
    #[error("invalid opcode")]
    InvalidOpcode,
    #[error("OP_RETURN encountered")]
    OpReturn,
    #[error("push size exceeded")]
    PushSizeExceeded,
    #[error("op count exceeded")]
    OpCountExceeded,
    #[error("multisig pubkey count exceeded")]
    MultisigPubkeyCount,
    #[error("invalid signature encoding")]
    InvalidSigEncoding,
    #[error("invalid pubkey encoding")]
    InvalidPubkeyEncoding,
    #[error("signature check failed")]
    SigCheckFailed,
    #[error("locktime check failed")]
    LockTimeFailed,
    #[error("cleanstack violation")]
    CleanStack,
    #[error("witness program mismatch")]
    WitnessProgramMismatch,
    #[error("witness program wrong length")]
    WitnessProgramWrongLength,
    #[error("witness program witness empty")]
    WitnessProgramWitnessEmpty,
    #[error("witness malleated (scriptSig must be empty)")]
    WitnessMalleated,
    #[error("witness malleated p2sh (scriptSig must be exact redeemScript push)")]
    WitnessMalleatedP2sh,
    #[error("unexpected witness data for non-witness spend")]
    WitnessUnexpected,
    #[error("taproot validation error: {0}")]
    Taproot(String),
    #[error("invalid taproot sighash type")]
    TaprootInvalidSighashType,
    #[error("script too large")]
    ScriptTooLarge,
    #[error("unbalanced if")]
    UnbalancedIf,
    // ── New policy flags ─────────────────────────────────────────────────────
    #[error("signature has high S value (LOW_S violation)")]
    SigHighS,
    #[error("scriptSig is not push-only (SIGPUSHONLY violation)")]
    PushOnly,
    #[error("non-minimal data push (MINIMALDATA violation)")]
    MinimalData,
    #[error("discouraged upgradable NOP (DISCOURAGE_UPGRADABLE_NOPS violation)")]
    DiscourageUpgradableNops,
    #[error("discouraged upgradable witness program")]
    DiscourageUpgradableWitnessProgram,
    #[error("OP_IF/OP_NOTIF argument is not minimal (MINIMALIF violation)")]
    MinimalIf,
    #[error("failed signature must be empty (NULLFAIL violation)")]
    NullFail,
    #[error("witness pubkey must be compressed (WITNESS_PUBKEYTYPE violation)")]
    WitnessPubkeyType,
    #[error("invalid sighash type (STRICTENC violation)")]
    InvalidSigHashType,
    #[error("invalid pubkey type (STRICTENC violation)")]
    PubkeyType,
}

type Stack = Vec<Vec<u8>>;

#[derive(Clone, Copy)]
pub struct TaprootExecutionData<'a> {
    pub all_prevouts: &'a [TxOut],
    pub leaf_hash: &'a [u8; 32],
    pub annex: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigVersion {
    Base,
    WitnessV0,
    Taproot,
}

/// Execution flags – mirrors Bitcoin Core's SCRIPT_VERIFY_* flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScriptFlags {
    pub verify_p2sh: bool,
    pub verify_dersig: bool,
    pub verify_witness: bool,
    pub verify_nulldummy: bool,
    pub verify_cleanstack: bool,
    pub verify_checklocktimeverify: bool,
    pub verify_checksequenceverify: bool,
    pub verify_taproot: bool,
    // ── Additional policy flags ───────────────────────────────────────────────
    /// STRICTENC: sighash type must be known; pubkeys must be compressed or uncompressed.
    pub verify_strictenc: bool,
    /// LOW_S: signature S must be in the lower half of the curve order.
    pub verify_low_s: bool,
    /// SIGPUSHONLY: scriptSig may only contain data-push opcodes.
    pub verify_sigpushonly: bool,
    /// MINIMALDATA: data pushes must use the minimal encoding opcode.
    pub verify_minimaldata: bool,
    /// DISCOURAGE_UPGRADABLE_NOPS: OP_NOP1, OP_NOP4–OP_NOP10 must not appear.
    pub verify_discourage_upgradable_nops: bool,
    /// DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: unknown witness versions are rejected.
    pub verify_discourage_upgradable_witness_program: bool,
    /// MINIMALIF: OP_IF/OP_NOTIF argument in SegWit must be exactly 0 or 1.
    pub verify_minimalif: bool,
    /// NULLFAIL: if CHECKSIG/CHECKMULTISIG fails, the signature(s) must be empty.
    pub verify_nullfail: bool,
    /// WITNESS_PUBKEYTYPE: in witness v0, public keys must be compressed.
    pub verify_witness_pubkeytype: bool,
}

impl ScriptFlags {
    pub fn standard() -> Self {
        Self {
            verify_p2sh: true,
            verify_dersig: true,
            verify_witness: true,
            verify_nulldummy: true,
            verify_cleanstack: true,
            verify_checklocktimeverify: true,
            verify_checksequenceverify: true,
            verify_taproot: true,
            verify_strictenc: true,
            verify_low_s: true,
            verify_sigpushonly: false, // not part of standard relay policy
            verify_minimaldata: true,
            verify_discourage_upgradable_nops: true,
            verify_discourage_upgradable_witness_program: true,
            verify_minimalif: true,
            verify_nullfail: true,
            verify_witness_pubkeytype: true,
        }
    }

    /// Compute `standard() & ~excluded`: start from standard flags and clear
    /// any flag that appears in `excluded`.  Used by tx_valid.json harness.
    pub fn standard_minus(excluded: &Self) -> Self {
        let mut f = Self::standard();
        if excluded.verify_p2sh                            { f.verify_p2sh = false; }
        if excluded.verify_dersig                          { f.verify_dersig = false; }
        if excluded.verify_witness                         { f.verify_witness = false; }
        if excluded.verify_nulldummy                       { f.verify_nulldummy = false; }
        if excluded.verify_cleanstack                      { f.verify_cleanstack = false; }
        if excluded.verify_checklocktimeverify             { f.verify_checklocktimeverify = false; }
        if excluded.verify_checksequenceverify             { f.verify_checksequenceverify = false; }
        if excluded.verify_taproot                         { f.verify_taproot = false; }
        if excluded.verify_strictenc                       { f.verify_strictenc = false; }
        if excluded.verify_low_s                           { f.verify_low_s = false; }
        if excluded.verify_sigpushonly                     { f.verify_sigpushonly = false; }
        if excluded.verify_minimaldata                     { f.verify_minimaldata = false; }
        if excluded.verify_discourage_upgradable_nops      { f.verify_discourage_upgradable_nops = false; }
        if excluded.verify_discourage_upgradable_witness_program {
            f.verify_discourage_upgradable_witness_program = false;
        }
        if excluded.verify_minimalif                       { f.verify_minimalif = false; }
        if excluded.verify_nullfail                        { f.verify_nullfail = false; }
        if excluded.verify_witness_pubkeytype              { f.verify_witness_pubkeytype = false; }
        f
    }

    /// Parse a comma-separated flags string from Bitcoin Core test vectors.
    /// Recognised tokens: NONE, P2SH, STRICTENC, DERSIG, LOW_S, SIGPUSHONLY,
    /// MINIMALDATA, DISCOURAGE_UPGRADABLE_NOPS, CLEANSTACK,
    /// CHECKLOCKTIMEVERIFY, CHECKSEQUENCEVERIFY, WITNESS,
    /// DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, MINIMALIF, NULLDUMMY, NULLFAIL,
    /// WITNESS_PUBKEYTYPE, TAPROOT.
    pub fn from_test_str(s: &str) -> Self {
        let mut f = Self::default();
        for token in s.split(',') {
            match token.trim() {
                "NONE" => {}
                "P2SH" => f.verify_p2sh = true,
                "STRICTENC" => { f.verify_strictenc = true; f.verify_dersig = true; }
                "DERSIG" => f.verify_dersig = true,
                "LOW_S" => f.verify_low_s = true,
                "SIGPUSHONLY" => f.verify_sigpushonly = true,
                "MINIMALDATA" => f.verify_minimaldata = true,
                "DISCOURAGE_UPGRADABLE_NOPS" => f.verify_discourage_upgradable_nops = true,
                "CLEANSTACK" => f.verify_cleanstack = true,
                "CHECKLOCKTIMEVERIFY" => f.verify_checklocktimeverify = true,
                "CHECKSEQUENCEVERIFY" => f.verify_checksequenceverify = true,
                "WITNESS" => f.verify_witness = true,
                "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => {
                    f.verify_discourage_upgradable_witness_program = true;
                }
                "MINIMALIF" => f.verify_minimalif = true,
                "NULLDUMMY" => f.verify_nulldummy = true,
                "NULLFAIL" => f.verify_nullfail = true,
                "WITNESS_PUBKEYTYPE" => f.verify_witness_pubkeytype = true,
                "TAPROOT" => f.verify_taproot = true,
                "CONST_SCRIPTCODE" => {} // not yet enforced; accepted for compat
                _ => {}
            }
        }
        f
    }
}

/// Returns true if the byte slice is the minimal encoding of a script integer.
/// Mirrors Bitcoin Core's `CScriptNum` minimal-encoding check.
fn is_minimal_script_int(bytes: &[u8]) -> bool {
    if bytes.is_empty() { return true; }
    // If the last byte is 0x00 or 0x80 (high 7 bits all zero), check whether
    // it's a necessary sign byte or an unnecessary extra zero.
    if (bytes.last().unwrap() & 0x7f) == 0 {
        // A lone 0x00 or 0x80 byte is non-minimal (should be empty or 0x81).
        if bytes.len() <= 1 {
            return false;
        }
        // If the second-to-last byte's high bit is 0, the last byte is redundant.
        if (bytes[bytes.len() - 2] & 0x80) == 0 {
            return false;
        }
    }
    true
}

/// Convert a stack item to a script integer (little-endian, with sign bit).
/// If `require_minimal` is true, the encoding must be minimal (MINIMALDATA semantics).
pub fn decode_script_int_opts(bytes: &[u8], max_size: usize, require_minimal: bool) -> Result<i64, ScriptError> {
    if bytes.len() > max_size {
        return Err(ScriptError::ScriptFailed("script number overflow".into()));
    }
    if require_minimal && !is_minimal_script_int(bytes) {
        return Err(ScriptError::MinimalData);
    }
    if bytes.is_empty() {
        return Ok(0);
    }
    let mut result = 0i64;
    for (i, &b) in bytes.iter().enumerate() {
        result |= (b as i64) << (8 * i);
    }
    // Handle sign bit
    if bytes.last().unwrap() & 0x80 != 0 {
        result &= !(0x80i64 << (8 * (bytes.len() - 1)));
        result = -result;
    }
    Ok(result)
}

/// Convert a stack item to a script integer (little-endian, with sign bit)
pub fn decode_script_int(bytes: &[u8], max_size: usize) -> Result<i64, ScriptError> {
    decode_script_int_opts(bytes, max_size, false)
}

/// Encode an integer to script number format
pub fn encode_script_int(n: i64) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }
    let mut result = Vec::new();
    let neg = n < 0;
    let mut abs = n.unsigned_abs();
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

pub fn cast_to_bool_pub(bytes: &[u8]) -> bool {
    cast_to_bool(bytes)
}

fn cast_to_bool(bytes: &[u8]) -> bool {
    for (i, &b) in bytes.iter().enumerate() {
        if b != 0 {
            // Negative zero (only sign bit set in last byte) is false
            if i == bytes.len() - 1 && b == 0x80 {
                return false;
            }
            return true;
        }
    }
    false
}

// Legacy FindAndDelete: remove all pushed occurrences of a signature from
// scriptCode before CHECKSIG/CHECKMULTISIG hashing (Bitcoin Core BASE path).
fn find_and_delete_script_sig(script: &Script, sig: &[u8]) -> Script {
    let mut pattern = Vec::with_capacity(1 + sig.len());
    match sig.len() {
        0..=0x4b => pattern.push(sig.len() as u8),
        0x4c..=0xff => {
            pattern.push(0x4c);
            pattern.push(sig.len() as u8);
        }
        0x100..=0xffff => {
            pattern.push(0x4d);
            pattern.extend_from_slice(&(sig.len() as u16).to_le_bytes());
        }
        _ => {
            pattern.push(0x4e);
            pattern.extend_from_slice(&(sig.len() as u32).to_le_bytes());
        }
    }
    pattern.extend_from_slice(sig);

    let bytes = script.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if i + pattern.len() <= bytes.len() && &bytes[i..i + pattern.len()] == pattern.as_slice() {
            i += pattern.len();
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Script::from_bytes(out)
}

/// Core script execution engine
pub struct ScriptEngine {
    pub flags: ScriptFlags,
}

impl ScriptEngine {
    pub fn new(flags: ScriptFlags) -> Self {
        Self { flags }
    }

    /// Execute a script with a given initial stack.
    /// Returns the resulting stack on success.
    pub fn execute(
        &self,
        script: &Script,
        stack: &mut Stack,
        tx: &Transaction,
        input_index: usize,
        amount: u64,
        script_code: &Script,
        sig_version: SigVersion,
        taproot_data: Option<TaprootExecutionData<'_>>,
    ) -> Result<(), ScriptError> {
        let bytes = script.as_bytes();
        if bytes.len() > MAX_SCRIPT_SIZE {
            return Err(ScriptError::ScriptTooLarge);
        }
        let mut pc = 0usize;
        let mut altstack: Stack = Vec::new();
        let mut exec_stack: Vec<bool> = Vec::new(); // for OP_IF
        let mut op_count = 0usize;
        let mut codesep_pos: Option<usize> = None;
        let mut taproot_codesep_pos: Option<u32> = None;

        while pc < bytes.len() {
            let executing = exec_stack.iter().all(|&b| b);
            let op_pos = pc;
            let opcode_byte = bytes[pc];
            pc += 1;

            // BIP342: OP_SUCCESSx in tapscript causes immediate success.
            if sig_version == SigVersion::Taproot && is_op_successx(opcode_byte) {
                return Ok(());
            }

            // Handle data push opcodes (0x01–0x4b)
            let op = if opcode_byte >= 0x01 && opcode_byte <= 0x4b {
                let len = opcode_byte as usize;
                if pc + len > bytes.len() {
                    return Err(ScriptError::ScriptFailed("push past end".into()));
                }
                if executing {
                    let data = bytes[pc..pc + len].to_vec();
                    if data.len() > MAX_SCRIPT_ELEMENT_SIZE {
                        return Err(ScriptError::PushSizeExceeded);
                    }
                    if self.flags.verify_minimaldata {
                        check_minimal_push(opcode_byte, &data)?;
                    }
                    stack.push(data);
                }
                pc += len;
                continue;
            } else {
                Opcode::from_byte(opcode_byte)
            };

            // Count non-push ops (legacy/v0 path).
            // BIP342 tapscript does not enforce the legacy MAX_OPS_PER_SCRIPT limit.
            if sig_version != SigVersion::Taproot && opcode_byte > 0x60 {
                op_count += 1;
                if op_count > MAX_OPS_PER_SCRIPT {
                    return Err(ScriptError::OpCountExceeded);
                }
            }

            match op {
                // Flow control ops are always processed (for if/else tracking)
                Opcode::OpIf | Opcode::OpNotIf => {
                    let cond = if executing {
                        if stack.is_empty() {
                            return Err(ScriptError::StackUnderflow);
                        }
                        let top = stack.pop().unwrap();
                        // MINIMALIF (BIP141/342): in SegWit and Tapscript, OP_IF/OP_NOTIF
                        // argument must be exactly 0 (empty) or 1 (single byte 0x01).
                        if sig_version != SigVersion::Base && self.flags.verify_minimalif {
                            if top.len() > 1 || (top.len() == 1 && top[0] != 1) {
                                return Err(ScriptError::MinimalIf);
                            }
                        }
                        let mut val = cast_to_bool(&top);
                        if op == Opcode::OpNotIf {
                            val = !val;
                        }
                        val
                    } else {
                        false
                    };
                    exec_stack.push(cond);
                }
                Opcode::OpElse => {
                    if exec_stack.is_empty() {
                        return Err(ScriptError::UnbalancedIf);
                    }
                    let last = exec_stack.last_mut().unwrap();
                    *last = !*last;
                }
                Opcode::OpEndIf => {
                    if exec_stack.is_empty() {
                        return Err(ScriptError::UnbalancedIf);
                    }
                    exec_stack.pop();
                }

                // VerIf/VerNotIf are always invalid even in non-executing branches
                Opcode::OpVerIf | Opcode::OpVerNotIf => return Err(ScriptError::InvalidOpcode),
                // Disabled opcodes are always invalid even in non-executing branches
                op if op.is_disabled() => return Err(ScriptError::DisabledOpcode),

                _ if !executing => {
                    // Handle data pushes we need to skip.
                    // Push size limits are enforced even in non-executing branches
                    // (matching Bitcoin Core's script parser behavior).
                    match op {
                        Opcode::OpPushData1 => {
                            if pc < bytes.len() {
                                let l = bytes[pc] as usize;
                                pc += 1 + l;
                                // PUSHDATA1 max is 255 < MAX_SCRIPT_ELEMENT_SIZE, no check needed.
                            }
                        }
                        Opcode::OpPushData2 => {
                            if pc + 1 < bytes.len() {
                                let l = u16::from_le_bytes([bytes[pc], bytes[pc+1]]) as usize;
                                pc += 2;
                                if l > MAX_SCRIPT_ELEMENT_SIZE {
                                    return Err(ScriptError::PushSizeExceeded);
                                }
                                pc += l;
                            }
                        }
                        Opcode::OpPushData4 => {
                            if pc + 3 < bytes.len() {
                                let l = u32::from_le_bytes([bytes[pc], bytes[pc+1], bytes[pc+2], bytes[pc+3]]) as usize;
                                pc += 4;
                                if l > MAX_SCRIPT_ELEMENT_SIZE {
                                    return Err(ScriptError::PushSizeExceeded);
                                }
                                pc += l;
                            }
                        }
                        _ => {}
                    }
                    continue;
                }

                // ── Constants ────────────────────────────────────────────
                Opcode::Op0 => stack.push(Vec::new()),
                Opcode::Op1Negate => stack.push(encode_script_int(-1)),
                Opcode::Op1 => stack.push(encode_script_int(1)),
                Opcode::Op2 => stack.push(encode_script_int(2)),
                Opcode::Op3 => stack.push(encode_script_int(3)),
                Opcode::Op4 => stack.push(encode_script_int(4)),
                Opcode::Op5 => stack.push(encode_script_int(5)),
                Opcode::Op6 => stack.push(encode_script_int(6)),
                Opcode::Op7 => stack.push(encode_script_int(7)),
                Opcode::Op8 => stack.push(encode_script_int(8)),
                Opcode::Op9 => stack.push(encode_script_int(9)),
                Opcode::Op10 => stack.push(encode_script_int(10)),
                Opcode::Op11 => stack.push(encode_script_int(11)),
                Opcode::Op12 => stack.push(encode_script_int(12)),
                Opcode::Op13 => stack.push(encode_script_int(13)),
                Opcode::Op14 => stack.push(encode_script_int(14)),
                Opcode::Op15 => stack.push(encode_script_int(15)),
                Opcode::Op16 => stack.push(encode_script_int(16)),

                // ── Push data ────────────────────────────────────────────
                Opcode::OpPushData1 => {
                    if pc >= bytes.len() { return Err(ScriptError::ScriptFailed("truncated".into())); }
                    let len = bytes[pc] as usize; pc += 1;
                    if pc + len > bytes.len() { return Err(ScriptError::ScriptFailed("truncated".into())); }
                    let data = bytes[pc..pc+len].to_vec(); pc += len;
                    if data.len() > MAX_SCRIPT_ELEMENT_SIZE { return Err(ScriptError::PushSizeExceeded); }
                    // MINIMALDATA: PUSHDATA1 is only minimal when data.len() > 0x4b
                    if self.flags.verify_minimaldata && data.len() <= 0x4b {
                        return Err(ScriptError::MinimalData);
                    }
                    stack.push(data);
                }
                Opcode::OpPushData2 => {
                    if pc + 1 >= bytes.len() { return Err(ScriptError::ScriptFailed("truncated".into())); }
                    let len = u16::from_le_bytes([bytes[pc], bytes[pc+1]]) as usize; pc += 2;
                    if pc + len > bytes.len() { return Err(ScriptError::ScriptFailed("truncated".into())); }
                    let data = bytes[pc..pc+len].to_vec(); pc += len;
                    if data.len() > MAX_SCRIPT_ELEMENT_SIZE { return Err(ScriptError::PushSizeExceeded); }
                    // MINIMALDATA: PUSHDATA2 is only minimal when data.len() > 0xff
                    if self.flags.verify_minimaldata && data.len() <= 0xff {
                        return Err(ScriptError::MinimalData);
                    }
                    stack.push(data);
                }
                Opcode::OpPushData4 => {
                    if pc + 3 >= bytes.len() { return Err(ScriptError::ScriptFailed("truncated".into())); }
                    let len = u32::from_le_bytes([bytes[pc], bytes[pc+1], bytes[pc+2], bytes[pc+3]]) as usize;
                    pc += 4;
                    if len > MAX_SCRIPT_ELEMENT_SIZE { return Err(ScriptError::PushSizeExceeded); }
                    if pc + len > bytes.len() { return Err(ScriptError::ScriptFailed("truncated".into())); }
                    let data = bytes[pc..pc+len].to_vec(); pc += len;
                    // MINIMALDATA: PUSHDATA4 is only minimal when data.len() > 0xffff
                    if self.flags.verify_minimaldata && data.len() <= 0xffff {
                        return Err(ScriptError::MinimalData);
                    }
                    stack.push(data);
                }

                // ── NOP variants ─────────────────────────────────────────
                Opcode::OpNop => {}
                // OP_NOP1 and OP_NOP4–OP_NOP10 are upgradable NOPs; reject if flag set.
                Opcode::OpNop1 | Opcode::OpNop4 | Opcode::OpNop5
                | Opcode::OpNop6 | Opcode::OpNop7 | Opcode::OpNop8
                | Opcode::OpNop9 | Opcode::OpNop10 => {
                    if self.flags.verify_discourage_upgradable_nops {
                        return Err(ScriptError::DiscourageUpgradableNops);
                    }
                }

                // ── Return ───────────────────────────────────────────────
                Opcode::OpReturn => return Err(ScriptError::OpReturn),

                // ── Stack ops ────────────────────────────────────────────
                Opcode::OpDrop => { pop(stack)?; }
                Opcode::Op2Drop => { pop(stack)?; pop(stack)?; }
                Opcode::OpDup => {
                    let top = peek(stack)?.clone();
                    stack.push(top);
                }
                Opcode::Op2Dup => {
                    if stack.len() < 2 { return Err(ScriptError::StackUnderflow); }
                    let a = stack[stack.len()-2].clone();
                    let b = stack[stack.len()-1].clone();
                    stack.push(a); stack.push(b);
                }
                Opcode::Op3Dup => {
                    if stack.len() < 3 { return Err(ScriptError::StackUnderflow); }
                    let a = stack[stack.len()-3].clone();
                    let b = stack[stack.len()-2].clone();
                    let c = stack[stack.len()-1].clone();
                    stack.push(a); stack.push(b); stack.push(c);
                }
                Opcode::OpOver => {
                    if stack.len() < 2 { return Err(ScriptError::StackUnderflow); }
                    let val = stack[stack.len()-2].clone();
                    stack.push(val);
                }
                Opcode::Op2Over => {
                    if stack.len() < 4 { return Err(ScriptError::StackUnderflow); }
                    let a = stack[stack.len()-4].clone();
                    let b = stack[stack.len()-3].clone();
                    stack.push(a); stack.push(b);
                }
                Opcode::OpSwap => {
                    if stack.len() < 2 { return Err(ScriptError::StackUnderflow); }
                    let n = stack.len();
                    stack.swap(n-1, n-2);
                }
                Opcode::Op2Swap => {
                    if stack.len() < 4 { return Err(ScriptError::StackUnderflow); }
                    let n = stack.len();
                    stack.swap(n-1, n-3);
                    stack.swap(n-2, n-4);
                }
                Opcode::OpRot => {
                    if stack.len() < 3 { return Err(ScriptError::StackUnderflow); }
                    let val = stack.remove(stack.len()-3);
                    stack.push(val);
                }
                Opcode::Op2Rot => {
                    if stack.len() < 6 { return Err(ScriptError::StackUnderflow); }
                    let n = stack.len();
                    let a = stack.remove(n-6);
                    let b = stack.remove(n-6); // was n-5, now at n-6
                    stack.push(a); stack.push(b);
                }
                Opcode::OpNip => {
                    if stack.len() < 2 { return Err(ScriptError::StackUnderflow); }
                    let n = stack.len();
                    stack.remove(n-2);
                }
                Opcode::OpTuck => {
                    if stack.len() < 2 { return Err(ScriptError::StackUnderflow); }
                    let top = stack[stack.len()-1].clone();
                    let n = stack.len();
                    stack.insert(n-2, top);
                }
                Opcode::OpIfDup => {
                    let top = peek(stack)?.clone();
                    if cast_to_bool(&top) { stack.push(top); }
                }
                Opcode::OpDepth => {
                    let d = stack.len() as i64;
                    stack.push(encode_script_int(d));
                }
                Opcode::OpPick => {
                    let n = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)? as usize;
                    if n >= stack.len() { return Err(ScriptError::StackUnderflow); }
                    let val = stack[stack.len()-1-n].clone();
                    stack.push(val);
                }
                Opcode::OpRoll => {
                    let n = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)? as usize;
                    if n >= stack.len() { return Err(ScriptError::StackUnderflow); }
                    let idx = stack.len()-1-n;
                    let val = stack.remove(idx);
                    stack.push(val);
                }
                Opcode::OpToAltStack => {
                    let val = pop(stack)?;
                    altstack.push(val);
                }
                Opcode::OpFromAltStack => {
                    let val = altstack.pop().ok_or(ScriptError::StackUnderflow)?;
                    stack.push(val);
                }

                // ── Equality ─────────────────────────────────────────────
                Opcode::OpEqual | Opcode::OpEqualVerify => {
                    let b = pop(stack)?;
                    let a = pop(stack)?;
                    let equal = a == b;
                    if op == Opcode::OpEqualVerify {
                        if !equal { return Err(ScriptError::ScriptFailed("OP_EQUALVERIFY failed".into())); }
                    } else {
                        stack.push(if equal { vec![1u8] } else { Vec::new() });
                    }
                }

                // ── Size ─────────────────────────────────────────────────
                Opcode::OpSize => {
                    let top = peek(stack)?;
                    let len = top.len() as i64;
                    stack.push(encode_script_int(len));
                }

                // ── Arithmetic ───────────────────────────────────────────
                // When MINIMALDATA is set, stack integer values must be minimally encoded.
                Opcode::Op1Add => {
                    let a = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    stack.push(encode_script_int(a + 1));
                }
                Opcode::Op1Sub => {
                    let a = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    stack.push(encode_script_int(a - 1));
                }
                Opcode::OpNegate => {
                    let a = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    stack.push(encode_script_int(-a));
                }
                Opcode::OpAbs => {
                    let a = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    stack.push(encode_script_int(a.abs()));
                }
                Opcode::OpNot => {
                    let a = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    stack.push(encode_script_int(if a == 0 { 1 } else { 0 }));
                }
                Opcode::Op0NotEqual => {
                    let a = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    stack.push(encode_script_int(if a != 0 { 1 } else { 0 }));
                }
                Opcode::OpAdd => {
                    let b = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    let a = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    stack.push(encode_script_int(a + b));
                }
                Opcode::OpSub => {
                    let b = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    let a = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    stack.push(encode_script_int(a - b));
                }
                Opcode::OpBoolAnd => {
                    let b = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    let a = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    stack.push(encode_script_int(if a != 0 && b != 0 { 1 } else { 0 }));
                }
                Opcode::OpBoolOr => {
                    let b = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    let a = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    stack.push(encode_script_int(if a != 0 || b != 0 { 1 } else { 0 }));
                }
                Opcode::OpNumEqual | Opcode::OpNumEqualVerify => {
                    let b = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    let a = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    let eq = a == b;
                    if op == Opcode::OpNumEqualVerify {
                        if !eq { return Err(ScriptError::ScriptFailed("OP_NUMEQUALVERIFY failed".into())); }
                    } else {
                        stack.push(encode_script_int(if eq { 1 } else { 0 }));
                    }
                }
                Opcode::OpNumNotEqual => {
                    let b = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    let a = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    stack.push(encode_script_int(if a != b { 1 } else { 0 }));
                }
                Opcode::OpLessThan => {
                    let b = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    let a = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    stack.push(encode_script_int(if a < b { 1 } else { 0 }));
                }
                Opcode::OpGreaterThan => {
                    let b = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    let a = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    stack.push(encode_script_int(if a > b { 1 } else { 0 }));
                }
                Opcode::OpLessThanOrEqual => {
                    let b = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    let a = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    stack.push(encode_script_int(if a <= b { 1 } else { 0 }));
                }
                Opcode::OpGreaterThanOrEqual => {
                    let b = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    let a = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    stack.push(encode_script_int(if a >= b { 1 } else { 0 }));
                }
                Opcode::OpMin => {
                    let b = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    let a = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    stack.push(encode_script_int(a.min(b)));
                }
                Opcode::OpMax => {
                    let b = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    let a = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    stack.push(encode_script_int(a.max(b)));
                }
                Opcode::OpWithin => {
                    let max = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    let min = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    let x   = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    stack.push(encode_script_int(if x >= min && x < max { 1 } else { 0 }));
                }

                // ── Crypto ───────────────────────────────────────────────
                Opcode::OpRipemd160 => {
                    use ripemd::{Digest as _, Ripemd160};
                    let data = pop(stack)?;
                    stack.push(Ripemd160::digest(&data).to_vec());
                }
                Opcode::OpSha1 => {
                    use sha1::{Digest as _, Sha1};
                    let data = pop(stack)?;
                    stack.push(Sha1::digest(&data).to_vec());
                }
                Opcode::OpSha256 => {
                    let data = pop(stack)?;
                    stack.push(sha256(&data).0.to_vec());
                }
                Opcode::OpHash160 => {
                    let data = pop(stack)?;
                    stack.push(hash160(&data).0.to_vec());
                }
                Opcode::OpHash256 => {
                    let data = pop(stack)?;
                    stack.push(sha256d(&data).0.to_vec());
                }
                Opcode::OpCodeSeparator => {
                    if sig_version == SigVersion::Taproot {
                        taproot_codesep_pos = Some(op_pos as u32);
                    } else {
                        // Legacy/v0 uses scriptCode truncated after last OP_CODESEPARATOR.
                        codesep_pos = Some(pc);
                    }
                }

                Opcode::OpCheckSig | Opcode::OpCheckSigVerify => {
                    let pubkey = pop(stack)?;
                    let sig = pop(stack)?;
                    let ok = if sig_version == SigVersion::Taproot {
                        if sig.is_empty() {
                            false
                        } else {
                            let tap = taproot_data.ok_or_else(|| {
                                ScriptError::Taproot("missing tapscript execution context".into())
                            })?;
                            let (sig_bytes, sighash_type) = parse_taproot_sig_and_hashtype(&sig)?;
                            let hash = sighash_taproot(
                                tx,
                                input_index,
                                tap.all_prevouts,
                                sighash_type,
                                Some(tap.leaf_hash),
                                tap.annex,
                                0,
                                taproot_codesep_pos.unwrap_or(u32::MAX),
                            );
                            verify_schnorr(&pubkey, sig_bytes, &hash.0).is_ok()
                        }
                    } else {
                        if sig.is_empty() {
                            false
                        } else {
                            let sighash_byte = *sig.last().unwrap();
                            let sighash_u32 = sighash_byte as u32;
                            // STRICTENC: sighash type must be known.
                            if self.flags.verify_strictenc && !is_defined_hashtype(sighash_byte) {
                                return Err(ScriptError::InvalidSigHashType);
                            }
                            // STRICTENC: pubkey must be compressed or uncompressed.
                            if self.flags.verify_strictenc
                                && !is_valid_pubkey_encoding(&pubkey)
                            {
                                return Err(ScriptError::PubkeyType);
                            }
                            // WITNESS_PUBKEYTYPE: in SegWit v0, pubkeys must be compressed.
                            if sig_version == SigVersion::WitnessV0
                                && self.flags.verify_witness_pubkeytype
                                && !is_compressed_pubkey(&pubkey)
                            {
                                return Err(ScriptError::WitnessPubkeyType);
                            }
                            let sig_der = &sig[..sig.len() - 1];
                            let strict_der = self.flags.verify_dersig || self.flags.verify_strictenc;
                            if strict_der && !is_valid_der_signature_encoding(&sig) {
                                return Err(ScriptError::InvalidSigEncoding);
                            }
                            // DERSIG/STRICTENC: validate DER structure (fails for 1-byte sigs too).
                            if strict_der && !self.flags.verify_low_s {
                                secp256k1::ecdsa::Signature::from_der(sig_der)
                                    .map_err(|_| ScriptError::InvalidSigEncoding)?;
                            }
                            // LOW_S: S must be in the lower half of the curve order.
                            if self.flags.verify_low_s {
                                check_low_s(sig_der, strict_der)?;
                            }
                            let mut sc = if let Some(pos) = codesep_pos {
                                Script::from_bytes(script_code.as_bytes()[pos..].to_vec())
                            } else {
                                script_code.clone()
                            };
                            if sig_version == SigVersion::Base {
                                sc = find_and_delete_script_sig(&sc, &sig);
                            }
                            let hash = if sig_version == SigVersion::WitnessV0 {
                                sighash_segwit_v0_with_u32(tx, input_index, &sc, amount, sighash_u32)
                            } else {
                                sighash_legacy_with_u32(tx, input_index, &sc, sighash_u32)
                            };
                            verify_ecdsa_with_policy(&pubkey, sig_der, &hash.0, strict_der).is_ok()
                        }
                    };

                    // NULLFAIL: if verification failed, the sig must have been empty.
                    if !ok && self.flags.verify_nullfail && !sig.is_empty() {
                        return Err(ScriptError::NullFail);
                    }
                    if op == Opcode::OpCheckSigVerify {
                        if !ok { return Err(ScriptError::SigCheckFailed); }
                    } else {
                        stack.push(if ok { vec![1u8] } else { Vec::new() });
                    }
                }

                Opcode::OpCheckMultiSig | Opcode::OpCheckMultiSigVerify => {
                    if sig_version == SigVersion::Taproot {
                        return Err(ScriptError::InvalidOpcode);
                    }
                    let n_keys_i64 = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    if n_keys_i64 < 0 || n_keys_i64 as usize > MAX_PUBKEYS_PER_MULTISIG {
                        return Err(ScriptError::MultisigPubkeyCount);
                    }
                    let n_keys = n_keys_i64 as usize;
                    op_count += n_keys;
                    if op_count > MAX_OPS_PER_SCRIPT {
                        return Err(ScriptError::OpCountExceeded);
                    }

                    let mut pubkeys = Vec::with_capacity(n_keys);
                    for _ in 0..n_keys { pubkeys.push(pop(stack)?); }

                    let n_sigs_i64 = decode_script_int_opts(&pop(stack)?, 4, self.flags.verify_minimaldata)?;
                    if n_sigs_i64 < 0 || n_sigs_i64 as usize > n_keys {
                        return Err(ScriptError::MultisigPubkeyCount);
                    }
                    let n_sigs = n_sigs_i64 as usize;
                    let mut sigs = Vec::with_capacity(n_sigs);
                    for _ in 0..n_sigs { sigs.push(pop(stack)?); }

                    // BIP147 NULLDUMMY (activated with segwit).
                    let dummy = pop(stack)?;
                    if self.flags.verify_nulldummy && !dummy.is_empty() {
                        return Err(ScriptError::ScriptFailed(
                            "CHECKMULTISIG dummy argument must be empty".into(),
                        ));
                    }

                    let mut sc = if let Some(pos) = codesep_pos {
                        Script::from_bytes(script_code.as_bytes()[pos..].to_vec())
                    } else {
                        script_code.clone()
                    };
                    if sig_version == SigVersion::Base {
                        for sig in &sigs {
                            sc = find_and_delete_script_sig(&sc, sig);
                        }
                    }

                    let strict_der = self.flags.verify_dersig || self.flags.verify_strictenc;
                    let mut sig_idx = 0;
                    let mut key_idx = 0;
                    let mut all_ok = true;

                    // Single matching loop (Bitcoin Core algorithm):
                    // Key ALWAYS advances each iteration.
                    // Sig only advances on successful match.
                    // Sig encoding checks happen lazily when sig is actually tried against a key.
                    // Early exit fires when remaining keys < remaining sigs (before examining more keys).
                    while sig_idx < sigs.len() {
                        // Early exit: not enough keys remaining for remaining sigs.
                        if (sigs.len() - sig_idx) > (pubkeys.len() - key_idx) {
                            all_ok = false;
                            break;
                        }

                        let pk = &pubkeys[key_idx];
                        key_idx += 1; // ALWAYS advance key

                        // STRICTENC: check pubkey encoding for each key we examine.
                        if self.flags.verify_strictenc && !is_valid_pubkey_encoding(pk) {
                            return Err(ScriptError::PubkeyType);
                        }
                        // WITNESS_PUBKEYTYPE: compressed pubkeys only in SegWit v0.
                        if sig_version == SigVersion::WitnessV0
                            && self.flags.verify_witness_pubkeytype
                            && !is_compressed_pubkey(pk)
                        {
                            return Err(ScriptError::WitnessPubkeyType);
                        }

                        let sig = &sigs[sig_idx];
                        let matched = if sig.is_empty() {
                            false // empty sig never matches
                        } else {
                            if strict_der && !is_valid_der_signature_encoding(sig) {
                                return Err(ScriptError::InvalidSigEncoding);
                            }
                            let sighash_byte = *sig.last().unwrap();
                            let sighash_u32 = sighash_byte as u32;
                            // Sig encoding checks happen when the sig is actually tried.
                            if self.flags.verify_strictenc && !is_defined_hashtype(sighash_byte) {
                                return Err(ScriptError::InvalidSigHashType);
                            }
                            let sig_der = &sig[..sig.len() - 1];
                            if strict_der && !self.flags.verify_low_s {
                                secp256k1::ecdsa::Signature::from_der(sig_der)
                                    .map_err(|_| ScriptError::InvalidSigEncoding)?;
                            }
                            if self.flags.verify_low_s {
                                check_low_s(sig_der, strict_der)?;
                            }
                            let h = if sig_version == SigVersion::WitnessV0 {
                                sighash_segwit_v0_with_u32(tx, input_index, &sc, amount, sighash_u32)
                            } else {
                                sighash_legacy_with_u32(tx, input_index, &sc, sighash_u32)
                            };
                            let sig_der = &sig[..sig.len() - 1];
                            verify_ecdsa_with_policy(pk, sig_der, &h.0, strict_der).is_ok()
                        };

                        if matched {
                            sig_idx += 1; // advance sig only on successful match
                        }
                        // key always advances (done above)
                    }

                    // NULLFAIL: if result is false, all provided sigs must be empty.
                    if !all_ok && self.flags.verify_nullfail {
                        for sig in &sigs {
                            if !sig.is_empty() {
                                return Err(ScriptError::NullFail);
                            }
                        }
                    }
                    if op == Opcode::OpCheckMultiSigVerify {
                        if !all_ok { return Err(ScriptError::SigCheckFailed); }
                    } else {
                        stack.push(if all_ok { vec![1u8] } else { Vec::new() });
                    }
                }

                // ── Verify ───────────────────────────────────────────────
                Opcode::OpVerify => {
                    let top = pop(stack)?;
                    if !cast_to_bool(&top) {
                        return Err(ScriptError::ScriptFailed("OP_VERIFY failed".into()));
                    }
                }

                // ── Locktime ─────────────────────────────────────────────
                Opcode::OpCheckLockTimeVerify => {
                    if !self.flags.verify_checklocktimeverify { continue; }
                    let locktime = decode_script_int_opts(peek(stack)?, 5, self.flags.verify_minimaldata)?;
                    if locktime < 0 { return Err(ScriptError::LockTimeFailed); }
                    let tx_locktime = tx.lock_time as i64;
                    // Type mismatch (one is block height, other is time) is a failure
                    if (locktime < 500_000_000) != (tx_locktime < 500_000_000) {
                        return Err(ScriptError::LockTimeFailed);
                    }
                    if locktime > tx_locktime { return Err(ScriptError::LockTimeFailed); }
                    if tx.inputs[input_index].sequence == 0xffffffff {
                        return Err(ScriptError::LockTimeFailed);
                    }
                }
                Opcode::OpCheckSequenceVerify => {
                    if !self.flags.verify_checksequenceverify { continue; }
                    let seq = decode_script_int_opts(peek(stack)?, 5, self.flags.verify_minimaldata)?;
                    if seq < 0 { return Err(ScriptError::LockTimeFailed); }
                    if seq as u32 & (1 << 31) != 0 { continue; } // disabled flag
                    let tx_seq = tx.inputs[input_index].sequence;
                    // Bitcoin Core uses unsigned comparison: (uint32_t)nVersion < 2.
                    // This means version = -1 (0xffffffff) is treated as 4294967295 ≥ 2.
                    if (tx.version as u32) < 2 { return Err(ScriptError::LockTimeFailed); }
                    if tx_seq & (1 << 31) != 0 { return Err(ScriptError::LockTimeFailed); }
                    // Type match check
                    if (seq as u32 & (1 << 22)) != (tx_seq & (1 << 22)) {
                        return Err(ScriptError::LockTimeFailed);
                    }
                    if (seq as u32 & 0xffff) > (tx_seq & 0xffff) {
                        return Err(ScriptError::LockTimeFailed);
                    }
                }
                // OP_CHECKSIGADD is tapscript-only (BIP342).
                Opcode::OpCheckSigAdd => {
                    if sig_version != SigVersion::Taproot {
                        return Err(ScriptError::InvalidOpcode);
                    }
                    if stack.len() < 3 {
                        return Err(ScriptError::StackUnderflow);
                    }
                    let pubkey = stack.pop().unwrap();
                    let n_bytes = stack.pop().unwrap();
                    let sig = stack.pop().unwrap();
                    let n = decode_script_int(&n_bytes, 8)?;
                    let tap = taproot_data.ok_or_else(|| {
                        ScriptError::Taproot("missing tapscript execution context".into())
                    })?;

                    let ok = if sig.is_empty() {
                        false
                    } else {
                        let (sig_bytes, sighash_type) = parse_taproot_sig_and_hashtype(&sig)?;
                        let hash = sighash_taproot(
                            tx,
                            input_index,
                            tap.all_prevouts,
                            sighash_type,
                            Some(tap.leaf_hash),
                            tap.annex,
                            0,
                            taproot_codesep_pos.unwrap_or(u32::MAX),
                        );
                        verify_schnorr(&pubkey, sig_bytes, &hash.0).is_ok()
                    };
                    stack.push(encode_script_int(n + if ok { 1 } else { 0 }));
                }

                // ── Reserved/invalid ops (only fail when executing) ──────
                Opcode::OpInvalidOpcode | Opcode::OpVer => {
                    return Err(ScriptError::InvalidOpcode);
                }
                Opcode::OpReserved | Opcode::OpReserved1 | Opcode::OpReserved2 => {
                    return Err(ScriptError::InvalidOpcode);
                }

                _ => {}
            }

            if stack.len() + altstack.len() > MAX_STACK_SIZE {
                return Err(ScriptError::StackOverflow);
            }
        }

        if !exec_stack.is_empty() {
            return Err(ScriptError::UnbalancedIf);
        }

        Ok(())
    }

    /// Execute tapscript with BIP342 checks and Taproot sighash context.
    pub fn execute_tapscript(
        &self,
        tx: &Transaction,
        input_index: usize,
        all_prevouts: &[TxOut],
        script: &Script,
        stack: &mut Stack,
        leaf_hash: &[u8; 32],
        annex: Option<&[u8]>,
    ) -> Result<(), ScriptError> {
        // Preserve BIP342 OP_SUCCESSx behavior: as soon as an OP_SUCCESSx opcode
        // is encountered during parsing, script evaluation succeeds immediately.
        let bytes = script.as_bytes();
        let mut pc = 0usize;
        while pc < bytes.len() {
            let op = bytes[pc];
            pc += 1;
            if is_op_successx(op) {
                return Ok(());
            }
            match op {
                0x01..=0x4b => {
                    let len = op as usize;
                    if pc + len > bytes.len() {
                        return Err(ScriptError::ScriptFailed("truncated pushdata".into()));
                    }
                    pc += len;
                }
                0x4c => {
                    if pc >= bytes.len() {
                        return Err(ScriptError::ScriptFailed("truncated pushdata1".into()));
                    }
                    let len = bytes[pc] as usize;
                    pc += 1;
                    if pc + len > bytes.len() {
                        return Err(ScriptError::ScriptFailed("truncated pushdata1 body".into()));
                    }
                    pc += len;
                }
                0x4d => {
                    if pc + 1 >= bytes.len() {
                        return Err(ScriptError::ScriptFailed("truncated pushdata2".into()));
                    }
                    let len = u16::from_le_bytes([bytes[pc], bytes[pc + 1]]) as usize;
                    pc += 2;
                    if pc + len > bytes.len() {
                        return Err(ScriptError::ScriptFailed("truncated pushdata2 body".into()));
                    }
                    pc += len;
                }
                0x4e => {
                    if pc + 3 >= bytes.len() {
                        return Err(ScriptError::ScriptFailed("truncated pushdata4".into()));
                    }
                    let len = u32::from_le_bytes([
                        bytes[pc],
                        bytes[pc + 1],
                        bytes[pc + 2],
                        bytes[pc + 3],
                    ]) as usize;
                    pc += 4;
                    if pc + len > bytes.len() {
                        return Err(ScriptError::ScriptFailed("truncated pushdata4 body".into()));
                    }
                    pc += len;
                }
                _ => {}
            }
        }

        self.execute(
            script,
            stack,
            tx,
            input_index,
            all_prevouts[input_index].value,
            script,
            SigVersion::Taproot,
            Some(TaprootExecutionData {
                all_prevouts,
                leaf_hash,
                annex,
            }),
        )?;

        match stack.last() {
            None => Err(ScriptError::ScriptFailed("empty stack".into())),
            Some(top) if !cast_to_bool(top) => {
                Err(ScriptError::ScriptFailed("top of stack is false".into()))
            }
            Some(_) => Ok(()),
        }
    }
}

// ── Helper fns ───────────────────────────────────────────────────────────────

fn pop(stack: &mut Stack) -> Result<Vec<u8>, ScriptError> {
    stack.pop().ok_or(ScriptError::StackUnderflow)
}

fn peek(stack: &Stack) -> Result<&Vec<u8>, ScriptError> {
    stack.last().ok_or(ScriptError::StackUnderflow)
}

fn parse_taproot_sig_and_hashtype(sig: &[u8]) -> Result<(&[u8], SighashType), ScriptError> {
    match sig.len() {
        64 => Ok((sig, SighashType::TaprootDefault)),
        65 => {
            let hash_type = sig[64] as u32;
            if hash_type == 0 {
                return Err(ScriptError::TaprootInvalidSighashType);
            }
            let parsed =
                SighashType::from_u32(hash_type).ok_or(ScriptError::TaprootInvalidSighashType)?;
            Ok((&sig[..64], parsed))
        }
        _ => Err(ScriptError::SigCheckFailed),
    }
}

/// Check that a push opcode is the minimal one for the given data (MINIMALDATA).
/// Mirrors Bitcoin Core's `CheckMinimalPush`.
fn check_minimal_push(opcode_byte: u8, data: &[u8]) -> Result<(), ScriptError> {
    if data.is_empty() {
        // Empty push → should use OP_0 (0x00).
        return Err(ScriptError::MinimalData);
    }
    if data.len() == 1 {
        let v = data[0];
        if v >= 1 && v <= 16 {
            // Bytes 1–16 → should use OP_1–OP_16 (0x51–0x60).
            if opcode_byte != 0x50 + v {
                return Err(ScriptError::MinimalData);
            }
            return Ok(());
        }
        if v == 0x81 {
            // Negative one → should use OP_1NEGATE (0x4f).
            if opcode_byte != 0x4f {
                return Err(ScriptError::MinimalData);
            }
            return Ok(());
        }
    }
    // For all other data, a direct push opcode (opcode_byte == data.len()) is minimal.
    if data.len() <= 0x4b && opcode_byte as usize != data.len() {
        return Err(ScriptError::MinimalData);
    }
    Ok(())
}

/// Returns true if the sighash type byte is one of the known values
/// (SIGHASH_ALL, NONE, SINGLE, with or without ANYONECANPAY).
fn is_defined_hashtype(sighash_byte: u8) -> bool {
    let base = sighash_byte & !0x80;
    base >= 1 && base <= 3
}

/// Returns true if the pubkey is a valid compressed or uncompressed SEC encoding.
fn is_valid_pubkey_encoding(pk: &[u8]) -> bool {
    match pk.first() {
        Some(0x04) => pk.len() == 65,
        Some(0x02) | Some(0x03) => pk.len() == 33,
        _ => false,
    }
}

/// Returns true if the pubkey is compressed (33 bytes, 0x02 or 0x03 prefix).
pub fn is_compressed_pubkey(pk: &[u8]) -> bool {
    pk.len() == 33 && (pk[0] == 0x02 || pk[0] == 0x03)
}

/// Check that the DER-encoded signature (without sighash byte) has a low S value.
/// Returns Err(SigHighS) if S is in the upper half of the curve order.
fn check_low_s(sig_der: &[u8], strict_der: bool) -> Result<(), ScriptError> {
    use secp256k1::ecdsa::Signature as EcdsaSig;
    let mut sig = if strict_der {
        EcdsaSig::from_der(sig_der).map_err(|_| ScriptError::InvalidSigEncoding)?
    } else {
        EcdsaSig::from_der_lax(sig_der).map_err(|_| ScriptError::InvalidSigEncoding)?
    };
    let before = sig.serialize_compact();
    sig.normalize_s();
    let after = sig.serialize_compact();
    if before != after {
        return Err(ScriptError::SigHighS);
    }
    Ok(())
}

fn is_op_successx(op: u8) -> bool {
    op == 0x50
        || op == 0x62
        || (0x7e..=0x81).contains(&op)
        || (0x83..=0x86).contains(&op)
        || (0x89..=0x8a).contains(&op)
        || (0x8d..=0x8e).contains(&op)
        || (0x95..=0x99).contains(&op)
        || (0xbb..=0xfe).contains(&op)
}

/// BIP66 DER signature encoding check, including the trailing sighash byte.
/// Mirrors Bitcoin Core's `IsValidSignatureEncoding`.
fn is_valid_der_signature_encoding(sig: &[u8]) -> bool {
    if sig.len() < 9 || sig.len() > 73 {
        return false;
    }
    if sig[0] != 0x30 {
        return false;
    }
    if sig[1] as usize != sig.len() - 3 {
        return false;
    }
    let len_r = sig[3] as usize;
    if 5 + len_r >= sig.len() {
        return false;
    }
    let len_s = sig[5 + len_r] as usize;
    if len_r + len_s + 7 != sig.len() {
        return false;
    }
    if sig[2] != 0x02 || len_r == 0 {
        return false;
    }
    if sig[4] & 0x80 != 0 {
        return false;
    }
    if len_r > 1 && sig[4] == 0x00 && (sig[5] & 0x80) == 0 {
        return false;
    }
    if sig[len_r + 4] != 0x02 || len_s == 0 {
        return false;
    }
    if sig[len_r + 6] & 0x80 != 0 {
        return false;
    }
    if len_s > 1 && sig[len_r + 6] == 0x00 && (sig[len_r + 7] & 0x80) == 0 {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::transaction::{OutPoint, TxIn, TxOut};
    use rbtc_primitives::hash::Hash256;

    fn minimal_tx() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256::ZERO, vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![],
            lock_time: 0,
        }
    }

    #[test]
    fn decode_script_int_empty() {
        assert_eq!(decode_script_int(&[], 4).unwrap(), 0);
    }

    #[test]
    fn decode_script_int_overflow() {
        let big = vec![0xff; 5];
        assert!(decode_script_int(&big, 4).is_err());
    }

    #[test]
    fn encode_script_int_zero() {
        assert!(encode_script_int(0).is_empty());
    }

    #[test]
    fn encode_decode_roundtrip() {
        for n in [1i64, -1, 100, -100, 0x7fffffff] {
            let e = encode_script_int(n);
            let d = decode_script_int(&e, 4).unwrap();
            assert_eq!(d, n);
        }
    }

    #[test]
    fn cast_to_bool_pub_() {
        assert!(!cast_to_bool_pub(&[]));
        assert!(!cast_to_bool_pub(&[0x80]));
        assert!(cast_to_bool_pub(&[1]));
    }

    #[test]
    fn script_flags_standard() {
        let f = ScriptFlags::standard();
        assert!(f.verify_p2sh);
        assert!(f.verify_dersig);
        assert!(f.verify_witness);
    }

    #[test]
    fn execute_op0_op1() {
        let engine = ScriptEngine::new(ScriptFlags::default());
        let tx = minimal_tx();
        let script = Script::from_bytes(vec![0x00, 0x51]);
        let mut stack = vec![];
        engine.execute(&script, &mut stack, &tx, 0, 0, &script, SigVersion::Base, None).unwrap();
        assert_eq!(stack.len(), 2);
    }

    #[test]
    fn execute_op_return() {
        let engine = ScriptEngine::new(ScriptFlags::default());
        let tx = minimal_tx();
        let script = Script::from_bytes(vec![0x6a]);
        let mut stack = vec![];
        let r = engine.execute(&script, &mut stack, &tx, 0, 0, &script, SigVersion::Base, None);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ScriptError::OpReturn));
    }

    #[test]
    fn execute_stack_underflow() {
        let engine = ScriptEngine::new(ScriptFlags::default());
        let tx = minimal_tx();
        let script = Script::from_bytes(vec![0x75]);
        let mut stack = vec![];
        let r = engine.execute(&script, &mut stack, &tx, 0, 0, &script, SigVersion::Base, None);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ScriptError::StackUnderflow));
    }

    #[test]
    fn execute_op_dup_equal() {
        let engine = ScriptEngine::new(ScriptFlags::default());
        let tx = minimal_tx();
        let script = Script::from_bytes(vec![0x01, 0x01, 0x76, 0x87]);
        let mut stack = vec![];
        engine.execute(&script, &mut stack, &tx, 0, 0, &script, SigVersion::Base, None).unwrap();
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0], vec![1u8]);
    }

    #[test]
    fn execute_disabled_or_invalid_opcode() {
        let engine = ScriptEngine::new(ScriptFlags::default());
        let tx = minimal_tx();
        let script = Script::from_bytes(vec![0x01, 0x00, 0x01, 0x00, 0x7e]);
        let mut stack = vec![];
        let r = engine.execute(&script, &mut stack, &tx, 0, 0, &script, SigVersion::Base, None);
        assert!(r.is_err());
    }

    #[test]
    fn execute_invalid_opcode() {
        let engine = ScriptEngine::new(ScriptFlags::default());
        let tx = minimal_tx();
        let script = Script::from_bytes(vec![0x62]);
        let mut stack = vec![];
        let r = engine.execute(&script, &mut stack, &tx, 0, 0, &script, SigVersion::Base, None);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ScriptError::InvalidOpcode));
    }

    #[test]
    fn execute_unbalanced_if() {
        let engine = ScriptEngine::new(ScriptFlags::default());
        let tx = minimal_tx();
        let script = Script::from_bytes(vec![0x63]);
        let mut stack = vec![vec![1]];
        let r = engine.execute(&script, &mut stack, &tx, 0, 0, &script, SigVersion::Base, None);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ScriptError::UnbalancedIf));
    }

    #[test]
    fn execute_op_verify_fail() {
        let engine = ScriptEngine::new(ScriptFlags::default());
        let tx = minimal_tx();
        let script = Script::from_bytes(vec![0x00, 0x69]);
        let mut stack = vec![];
        let r = engine.execute(&script, &mut stack, &tx, 0, 0, &script, SigVersion::Base, None);
        assert!(r.is_err());
    }

    #[test]
    fn execute_op_if_else_endif() {
        let engine = ScriptEngine::new(ScriptFlags::default());
        let tx = minimal_tx();
        let script = Script::from_bytes(vec![0x51, 0x63, 0x51, 0x67, 0x00, 0x68]);
        let mut stack = vec![];
        engine.execute(&script, &mut stack, &tx, 0, 0, &script, SigVersion::Base, None).unwrap();
        assert_eq!(stack.len(), 1);
    }

    #[test]
    fn execute_op_hash160() {
        let engine = ScriptEngine::new(ScriptFlags::default());
        let tx = minimal_tx();
        let script = Script::from_bytes(vec![0x01, 0x61, 0xa9]);
        let mut stack = vec![];
        engine.execute(&script, &mut stack, &tx, 0, 0, &script, SigVersion::Base, None).unwrap();
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].len(), 20);
    }

    #[test]
    fn execute_op_sha1() {
        let engine = ScriptEngine::new(ScriptFlags::default());
        let tx = minimal_tx();
        let script = Script::from_bytes(vec![0x01, 0x61, 0xa7]);
        let mut stack = vec![];
        engine.execute(&script, &mut stack, &tx, 0, 0, &script, SigVersion::Base, None).unwrap();
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].len(), 20);
    }

    #[test]
    fn execute_op_checksigadd_invalid_in_legacy() {
        let engine = ScriptEngine::new(ScriptFlags::default());
        let tx = minimal_tx();
        let script = Script::from_bytes(vec![0xba]);
        let mut stack = vec![];
        let r = engine.execute(&script, &mut stack, &tx, 0, 0, &script, SigVersion::Base, None);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ScriptError::InvalidOpcode));
    }

    #[test]
    fn execute_push_past_end() {
        let engine = ScriptEngine::new(ScriptFlags::default());
        let tx = minimal_tx();
        let script = Script::from_bytes(vec![0x05, 0x00, 0x00]);
        let mut stack = vec![];
        let r = engine.execute(&script, &mut stack, &tx, 0, 0, &script, SigVersion::Base, None);
        assert!(r.is_err());
    }

    #[test]
    fn execute_op_checksig_empty_sig() {
        let engine = ScriptEngine::new(ScriptFlags::default());
        let tx = minimal_tx();
        let mut script = vec![0x21];
        script.extend_from_slice(&[0x02u8; 33]);
        script.push(0x00);
        script.push(0xac);
        let script = Script::from_bytes(script);
        let mut stack = vec![];
        engine.execute(&script, &mut stack, &tx, 0, 0, &script, SigVersion::Base, None).unwrap();
        assert_eq!(stack.len(), 1);
        assert!(stack[0].is_empty());
    }

    #[test]
    fn tapscript_ignores_legacy_opcount_limit() {
        let engine = ScriptEngine::new(ScriptFlags::standard());
        let tx = minimal_tx();
        let prevouts = vec![TxOut { value: 0, script_pubkey: Script::new() }];
        let leaf_hash = [0u8; 32];
        let mut script = vec![0x61; 220]; // OP_NOP repeated beyond legacy 201 limit
        script.push(0x51); // OP_1 so final stack is true
        let script = Script::from_bytes(script);
        let mut stack = vec![];

        let r = engine.execute_tapscript(
            &tx,
            0,
            &prevouts,
            &script,
            &mut stack,
            &leaf_hash,
            None,
        );
        assert!(r.is_ok());
    }
}
