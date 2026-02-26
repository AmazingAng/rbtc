use rbtc_primitives::{
    constants::{MAX_OPS_PER_SCRIPT, MAX_PUBKEYS_PER_MULTISIG, MAX_SCRIPT_ELEMENT_SIZE, MAX_STACK_SIZE},
    script::Script,
    transaction::Transaction,
};
use rbtc_crypto::{
    digest::{hash160, sha256, sha256d},
    sig::verify_ecdsa_with_policy,
    sighash::{sighash_legacy, SighashType},
};
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
    #[error("taproot validation error: {0}")]
    Taproot(String),
    #[error("script too large")]
    ScriptTooLarge,
    #[error("unbalanced if")]
    UnbalancedIf,
}

type Stack = Vec<Vec<u8>>;

/// Execution flags
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
        }
    }
}

/// Convert a stack item to a script integer (little-endian, with sign bit)
pub fn decode_script_int(bytes: &[u8], max_size: usize) -> Result<i64, ScriptError> {
    if bytes.len() > max_size {
        return Err(ScriptError::ScriptFailed("script number overflow".into()));
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
        _amount: u64,
        script_code: &Script,
    ) -> Result<(), ScriptError> {
        let bytes = script.as_bytes();
        let mut pc = 0usize;
        let mut altstack: Stack = Vec::new();
        let mut exec_stack: Vec<bool> = Vec::new(); // for OP_IF
        let mut op_count = 0usize;
        let mut codesep_pos: Option<usize> = None;

        while pc < bytes.len() {
            let executing = exec_stack.iter().all(|&b| b);
            let opcode_byte = bytes[pc];
            pc += 1;

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
                    stack.push(data);
                }
                pc += len;
                continue;
            } else {
                Opcode::from_byte(opcode_byte)
            };

            // Count non-push ops
            if opcode_byte > 0x60 {
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

                _ if !executing => {
                    // Handle data pushes we need to skip
                    match op {
                        Opcode::OpPushData1 => {
                            if pc < bytes.len() { let l = bytes[pc] as usize; pc += 1 + l; }
                        }
                        Opcode::OpPushData2 => {
                            if pc + 1 < bytes.len() {
                                let l = u16::from_le_bytes([bytes[pc], bytes[pc+1]]) as usize;
                                pc += 2 + l;
                            }
                        }
                        Opcode::OpPushData4 => {
                            if pc + 3 < bytes.len() {
                                let l = u32::from_le_bytes([bytes[pc], bytes[pc+1], bytes[pc+2], bytes[pc+3]]) as usize;
                                pc += 4 + l;
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
                    stack.push(data);
                }
                Opcode::OpPushData2 => {
                    if pc + 1 >= bytes.len() { return Err(ScriptError::ScriptFailed("truncated".into())); }
                    let len = u16::from_le_bytes([bytes[pc], bytes[pc+1]]) as usize; pc += 2;
                    if pc + len > bytes.len() { return Err(ScriptError::ScriptFailed("truncated".into())); }
                    let data = bytes[pc..pc+len].to_vec(); pc += len;
                    if data.len() > MAX_SCRIPT_ELEMENT_SIZE { return Err(ScriptError::PushSizeExceeded); }
                    stack.push(data);
                }
                Opcode::OpPushData4 => {
                    if pc + 3 >= bytes.len() { return Err(ScriptError::ScriptFailed("truncated".into())); }
                    let len = u32::from_le_bytes([bytes[pc], bytes[pc+1], bytes[pc+2], bytes[pc+3]]) as usize;
                    pc += 4;
                    if len > MAX_SCRIPT_ELEMENT_SIZE { return Err(ScriptError::PushSizeExceeded); }
                    if pc + len > bytes.len() { return Err(ScriptError::ScriptFailed("truncated".into())); }
                    let data = bytes[pc..pc+len].to_vec(); pc += len;
                    stack.push(data);
                }

                // ── NOP variants ─────────────────────────────────────────
                Opcode::OpNop | Opcode::OpNop1 | Opcode::OpNop4 | Opcode::OpNop5
                | Opcode::OpNop6 | Opcode::OpNop7 | Opcode::OpNop8
                | Opcode::OpNop9 | Opcode::OpNop10 => {}

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
                    let n = decode_script_int(&pop(stack)?, 4)? as usize;
                    if n >= stack.len() { return Err(ScriptError::StackUnderflow); }
                    let val = stack[stack.len()-1-n].clone();
                    stack.push(val);
                }
                Opcode::OpRoll => {
                    let n = decode_script_int(&pop(stack)?, 4)? as usize;
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
                Opcode::Op1Add => {
                    let a = decode_script_int(&pop(stack)?, 4)?;
                    stack.push(encode_script_int(a + 1));
                }
                Opcode::Op1Sub => {
                    let a = decode_script_int(&pop(stack)?, 4)?;
                    stack.push(encode_script_int(a - 1));
                }
                Opcode::OpNegate => {
                    let a = decode_script_int(&pop(stack)?, 4)?;
                    stack.push(encode_script_int(-a));
                }
                Opcode::OpAbs => {
                    let a = decode_script_int(&pop(stack)?, 4)?;
                    stack.push(encode_script_int(a.abs()));
                }
                Opcode::OpNot => {
                    let a = decode_script_int(&pop(stack)?, 4)?;
                    stack.push(encode_script_int(if a == 0 { 1 } else { 0 }));
                }
                Opcode::Op0NotEqual => {
                    let a = decode_script_int(&pop(stack)?, 4)?;
                    stack.push(encode_script_int(if a != 0 { 1 } else { 0 }));
                }
                Opcode::OpAdd => {
                    let b = decode_script_int(&pop(stack)?, 4)?;
                    let a = decode_script_int(&pop(stack)?, 4)?;
                    stack.push(encode_script_int(a + b));
                }
                Opcode::OpSub => {
                    let b = decode_script_int(&pop(stack)?, 4)?;
                    let a = decode_script_int(&pop(stack)?, 4)?;
                    stack.push(encode_script_int(a - b));
                }
                Opcode::OpBoolAnd => {
                    let b = decode_script_int(&pop(stack)?, 4)?;
                    let a = decode_script_int(&pop(stack)?, 4)?;
                    stack.push(encode_script_int(if a != 0 && b != 0 { 1 } else { 0 }));
                }
                Opcode::OpBoolOr => {
                    let b = decode_script_int(&pop(stack)?, 4)?;
                    let a = decode_script_int(&pop(stack)?, 4)?;
                    stack.push(encode_script_int(if a != 0 || b != 0 { 1 } else { 0 }));
                }
                Opcode::OpNumEqual | Opcode::OpNumEqualVerify => {
                    let b = decode_script_int(&pop(stack)?, 4)?;
                    let a = decode_script_int(&pop(stack)?, 4)?;
                    let eq = a == b;
                    if op == Opcode::OpNumEqualVerify {
                        if !eq { return Err(ScriptError::ScriptFailed("OP_NUMEQUALVERIFY failed".into())); }
                    } else {
                        stack.push(encode_script_int(if eq { 1 } else { 0 }));
                    }
                }
                Opcode::OpNumNotEqual => {
                    let b = decode_script_int(&pop(stack)?, 4)?;
                    let a = decode_script_int(&pop(stack)?, 4)?;
                    stack.push(encode_script_int(if a != b { 1 } else { 0 }));
                }
                Opcode::OpLessThan => {
                    let b = decode_script_int(&pop(stack)?, 4)?;
                    let a = decode_script_int(&pop(stack)?, 4)?;
                    stack.push(encode_script_int(if a < b { 1 } else { 0 }));
                }
                Opcode::OpGreaterThan => {
                    let b = decode_script_int(&pop(stack)?, 4)?;
                    let a = decode_script_int(&pop(stack)?, 4)?;
                    stack.push(encode_script_int(if a > b { 1 } else { 0 }));
                }
                Opcode::OpLessThanOrEqual => {
                    let b = decode_script_int(&pop(stack)?, 4)?;
                    let a = decode_script_int(&pop(stack)?, 4)?;
                    stack.push(encode_script_int(if a <= b { 1 } else { 0 }));
                }
                Opcode::OpGreaterThanOrEqual => {
                    let b = decode_script_int(&pop(stack)?, 4)?;
                    let a = decode_script_int(&pop(stack)?, 4)?;
                    stack.push(encode_script_int(if a >= b { 1 } else { 0 }));
                }
                Opcode::OpMin => {
                    let b = decode_script_int(&pop(stack)?, 4)?;
                    let a = decode_script_int(&pop(stack)?, 4)?;
                    stack.push(encode_script_int(a.min(b)));
                }
                Opcode::OpMax => {
                    let b = decode_script_int(&pop(stack)?, 4)?;
                    let a = decode_script_int(&pop(stack)?, 4)?;
                    stack.push(encode_script_int(a.max(b)));
                }
                Opcode::OpWithin => {
                    let max = decode_script_int(&pop(stack)?, 4)?;
                    let min = decode_script_int(&pop(stack)?, 4)?;
                    let x   = decode_script_int(&pop(stack)?, 4)?;
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
                    codesep_pos = Some(pc);
                }

                Opcode::OpCheckSig | Opcode::OpCheckSigVerify => {
                    let pubkey = pop(stack)?;
                    let sig = pop(stack)?;

                    let sighash_byte = sig.last().copied().unwrap_or(1);
                    let sighash_type = SighashType::from_u32(sighash_byte as u32)
                        .unwrap_or(SighashType::All);

                    let sc = if let Some(pos) = codesep_pos {
                        Script::from_bytes(script_code.as_bytes()[pos..].to_vec())
                    } else {
                        script_code.clone()
                    };

                    let hash = sighash_legacy(tx, input_index, &sc, sighash_type);
                    let ok = if sig.is_empty() {
                        false
                    } else {
                        verify_ecdsa_with_policy(
                            &pubkey,
                            &sig[..sig.len() - 1],
                            &hash.0,
                            self.flags.verify_dersig,
                        )
                        .is_ok()
                    };

                    if op == Opcode::OpCheckSigVerify {
                        if !ok { return Err(ScriptError::SigCheckFailed); }
                    } else {
                        stack.push(if ok { vec![1u8] } else { Vec::new() });
                    }
                }

                Opcode::OpCheckMultiSig | Opcode::OpCheckMultiSigVerify => {
                    let n_keys = decode_script_int(&pop(stack)?, 4)? as usize;
                    if n_keys > MAX_PUBKEYS_PER_MULTISIG {
                        return Err(ScriptError::MultisigPubkeyCount);
                    }
                    op_count += n_keys;
                    if op_count > MAX_OPS_PER_SCRIPT {
                        return Err(ScriptError::OpCountExceeded);
                    }

                    let mut pubkeys = Vec::with_capacity(n_keys);
                    for _ in 0..n_keys { pubkeys.push(pop(stack)?); }

                    let n_sigs = decode_script_int(&pop(stack)?, 4)? as usize;
                    let mut sigs = Vec::with_capacity(n_sigs);
                    for _ in 0..n_sigs { sigs.push(pop(stack)?); }

                    // BIP147 NULLDUMMY (activated with segwit).
                    let dummy = pop(stack)?;
                    if self.flags.verify_nulldummy && !dummy.is_empty() {
                        return Err(ScriptError::ScriptFailed(
                            "CHECKMULTISIG dummy argument must be empty".into(),
                        ));
                    }

                    let sc = if let Some(pos) = codesep_pos {
                        Script::from_bytes(script_code.as_bytes()[pos..].to_vec())
                    } else {
                        script_code.clone()
                    };
                    let mut sig_idx = 0;
                    let mut key_idx = 0;
                    let mut all_ok = true;

                    while sig_idx < sigs.len() && all_ok {
                        let sig = &sigs[sig_idx];
                        if sig.is_empty() { sig_idx += 1; continue; }
                        let sighash_type = SighashType::from_u32(*sig.last().unwrap() as u32)
                            .unwrap_or(SighashType::All);
                        let hash = sighash_legacy(tx, input_index, &sc, sighash_type);

                        let mut matched = false;
                        while key_idx < pubkeys.len() && !matched {
                            if verify_ecdsa_with_policy(
                                &pubkeys[key_idx],
                                &sig[..sig.len() - 1],
                                &hash.0,
                                self.flags.verify_dersig,
                            )
                            .is_ok()
                            {
                                matched = true;
                            }
                            key_idx += 1;
                        }
                        if !matched { all_ok = false; }
                        sig_idx += 1;
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
                    let locktime = decode_script_int(peek(stack)?, 5)?;
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
                    let seq = decode_script_int(peek(stack)?, 5)?;
                    if seq < 0 { return Err(ScriptError::LockTimeFailed); }
                    if seq as u32 & (1 << 31) != 0 { continue; } // disabled flag
                    let tx_seq = tx.inputs[input_index].sequence;
                    if tx.version < 2 { return Err(ScriptError::LockTimeFailed); }
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
                Opcode::OpCheckSigAdd => return Err(ScriptError::InvalidOpcode),

                // ── Disabled ops ─────────────────────────────────────────
                op if op.is_disabled() => return Err(ScriptError::DisabledOpcode),

                Opcode::OpInvalidOpcode | Opcode::OpVer | Opcode::OpVerIf | Opcode::OpVerNotIf => {
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
}

// ── Helper fns ───────────────────────────────────────────────────────────────

fn pop(stack: &mut Stack) -> Result<Vec<u8>, ScriptError> {
    stack.pop().ok_or(ScriptError::StackUnderflow)
}

fn peek(stack: &Stack) -> Result<&Vec<u8>, ScriptError> {
    stack.last().ok_or(ScriptError::StackUnderflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::transaction::{OutPoint, TxIn};
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
        engine.execute(&script, &mut stack, &tx, 0, 0, &script).unwrap();
        assert_eq!(stack.len(), 2);
    }

    #[test]
    fn execute_op_return() {
        let engine = ScriptEngine::new(ScriptFlags::default());
        let tx = minimal_tx();
        let script = Script::from_bytes(vec![0x6a]);
        let mut stack = vec![];
        let r = engine.execute(&script, &mut stack, &tx, 0, 0, &script);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ScriptError::OpReturn));
    }

    #[test]
    fn execute_stack_underflow() {
        let engine = ScriptEngine::new(ScriptFlags::default());
        let tx = minimal_tx();
        let script = Script::from_bytes(vec![0x75]);
        let mut stack = vec![];
        let r = engine.execute(&script, &mut stack, &tx, 0, 0, &script);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ScriptError::StackUnderflow));
    }

    #[test]
    fn execute_op_dup_equal() {
        let engine = ScriptEngine::new(ScriptFlags::default());
        let tx = minimal_tx();
        let script = Script::from_bytes(vec![0x01, 0x01, 0x76, 0x87]);
        let mut stack = vec![];
        engine.execute(&script, &mut stack, &tx, 0, 0, &script).unwrap();
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0], vec![1u8]);
    }

    #[test]
    fn execute_disabled_or_invalid_opcode() {
        let engine = ScriptEngine::new(ScriptFlags::default());
        let tx = minimal_tx();
        let script = Script::from_bytes(vec![0x01, 0x00, 0x01, 0x00, 0x7e]);
        let mut stack = vec![];
        let r = engine.execute(&script, &mut stack, &tx, 0, 0, &script);
        assert!(r.is_err());
    }

    #[test]
    fn execute_invalid_opcode() {
        let engine = ScriptEngine::new(ScriptFlags::default());
        let tx = minimal_tx();
        let script = Script::from_bytes(vec![0x62]);
        let mut stack = vec![];
        let r = engine.execute(&script, &mut stack, &tx, 0, 0, &script);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ScriptError::InvalidOpcode));
    }

    #[test]
    fn execute_unbalanced_if() {
        let engine = ScriptEngine::new(ScriptFlags::default());
        let tx = minimal_tx();
        let script = Script::from_bytes(vec![0x63]);
        let mut stack = vec![vec![1]];
        let r = engine.execute(&script, &mut stack, &tx, 0, 0, &script);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ScriptError::UnbalancedIf));
    }

    #[test]
    fn execute_op_verify_fail() {
        let engine = ScriptEngine::new(ScriptFlags::default());
        let tx = minimal_tx();
        let script = Script::from_bytes(vec![0x00, 0x69]);
        let mut stack = vec![];
        let r = engine.execute(&script, &mut stack, &tx, 0, 0, &script);
        assert!(r.is_err());
    }

    #[test]
    fn execute_op_if_else_endif() {
        let engine = ScriptEngine::new(ScriptFlags::default());
        let tx = minimal_tx();
        let script = Script::from_bytes(vec![0x51, 0x63, 0x51, 0x67, 0x00, 0x68]);
        let mut stack = vec![];
        engine.execute(&script, &mut stack, &tx, 0, 0, &script).unwrap();
        assert_eq!(stack.len(), 1);
    }

    #[test]
    fn execute_op_hash160() {
        let engine = ScriptEngine::new(ScriptFlags::default());
        let tx = minimal_tx();
        let script = Script::from_bytes(vec![0x01, 0x61, 0xa9]);
        let mut stack = vec![];
        engine.execute(&script, &mut stack, &tx, 0, 0, &script).unwrap();
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].len(), 20);
    }

    #[test]
    fn execute_op_sha1() {
        let engine = ScriptEngine::new(ScriptFlags::default());
        let tx = minimal_tx();
        let script = Script::from_bytes(vec![0x01, 0x61, 0xa7]);
        let mut stack = vec![];
        engine.execute(&script, &mut stack, &tx, 0, 0, &script).unwrap();
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].len(), 20);
    }

    #[test]
    fn execute_op_checksigadd_invalid_in_legacy() {
        let engine = ScriptEngine::new(ScriptFlags::default());
        let tx = minimal_tx();
        let script = Script::from_bytes(vec![0xba]);
        let mut stack = vec![];
        let r = engine.execute(&script, &mut stack, &tx, 0, 0, &script);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ScriptError::InvalidOpcode));
    }

    #[test]
    fn execute_push_past_end() {
        let engine = ScriptEngine::new(ScriptFlags::default());
        let tx = minimal_tx();
        let script = Script::from_bytes(vec![0x05, 0x00, 0x00]);
        let mut stack = vec![];
        let r = engine.execute(&script, &mut stack, &tx, 0, 0, &script);
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
        engine.execute(&script, &mut stack, &tx, 0, 0, &script).unwrap();
        assert_eq!(stack.len(), 1);
        assert!(stack[0].is_empty());
    }
}
