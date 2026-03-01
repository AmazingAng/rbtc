use rbtc_primitives::{
    codec::{Encodable, VarInt},
    hash::Hash256,
    script::Script,
    transaction::{Transaction, TxOut},
};
use sha2::{Digest, Sha256};

use crate::digest::{sha256, sha256d, tagged_hash};

fn strip_codeseparators(script: &Script) -> Script {
    let bytes = script.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let op = bytes[i];
        i += 1;
        match op {
            0x01..=0x4b => {
                let len = op as usize;
                out.push(op);
                if i + len > bytes.len() {
                    out.extend_from_slice(&bytes[i..]);
                    break;
                }
                out.extend_from_slice(&bytes[i..i + len]);
                i += len;
            }
            0x4c => {
                out.push(op);
                if i >= bytes.len() {
                    break;
                }
                let len = bytes[i] as usize;
                out.push(bytes[i]);
                i += 1;
                if i + len > bytes.len() {
                    out.extend_from_slice(&bytes[i..]);
                    break;
                }
                out.extend_from_slice(&bytes[i..i + len]);
                i += len;
            }
            0x4d => {
                out.push(op);
                if i + 1 >= bytes.len() {
                    out.extend_from_slice(&bytes[i..]);
                    break;
                }
                let len = u16::from_le_bytes([bytes[i], bytes[i + 1]]) as usize;
                out.push(bytes[i]);
                out.push(bytes[i + 1]);
                i += 2;
                if i + len > bytes.len() {
                    out.extend_from_slice(&bytes[i..]);
                    break;
                }
                out.extend_from_slice(&bytes[i..i + len]);
                i += len;
            }
            0x4e => {
                out.push(op);
                if i + 3 >= bytes.len() {
                    out.extend_from_slice(&bytes[i..]);
                    break;
                }
                let len = u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]) as usize;
                out.push(bytes[i]);
                out.push(bytes[i + 1]);
                out.push(bytes[i + 2]);
                out.push(bytes[i + 3]);
                i += 4;
                if i + len > bytes.len() {
                    out.extend_from_slice(&bytes[i..]);
                    break;
                }
                out.extend_from_slice(&bytes[i..i + len]);
                i += len;
            }
            // Bitcoin Core legacy sighash serializes scriptCode with OP_CODESEPARATOR removed.
            0xab => {}
            _ => out.push(op),
        }
    }
    Script::from_bytes(out)
}

/// Bitcoin sighash types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SighashType {
    All = 1,
    None = 2,
    Single = 3,
    AllAnyoneCanPay = 0x81,
    NoneAnyoneCanPay = 0x82,
    SingleAnyoneCanPay = 0x83,
    /// Taproot default (all)
    TaprootDefault = 0,
}

impl SighashType {
    pub fn from_u32(n: u32) -> Option<Self> {
        match n {
            0 => Some(Self::TaprootDefault),
            1 => Some(Self::All),
            2 => Some(Self::None),
            3 => Some(Self::Single),
            0x81 => Some(Self::AllAnyoneCanPay),
            0x82 => Some(Self::NoneAnyoneCanPay),
            0x83 => Some(Self::SingleAnyoneCanPay),
            _ => None,
        }
    }

    pub fn base_type(&self) -> u8 {
        (*self as u8) & 0x1f
    }

    pub fn anyone_can_pay(&self) -> bool {
        (*self as u8) & 0x80 != 0
    }
}

/// Compute legacy (pre-SegWit) sighash
pub fn sighash_legacy(
    tx: &Transaction,
    input_index: usize,
    script_code: &Script,
    sighash_type: SighashType,
) -> Hash256 {
    sighash_legacy_with_u32(tx, input_index, script_code, sighash_type as u32)
}

/// Compute legacy (pre-SegWit) sighash from a raw 32-bit sighash value.
/// Important for early historical signatures that use non-standard hashtype
/// bytes (e.g. 0x04) but are still consensus-valid.
pub fn sighash_legacy_with_u32(
    tx: &Transaction,
    input_index: usize,
    script_code: &Script,
    sighash_u32: u32,
) -> Hash256 {
    let base = sighash_u32 & 0x1f;
    let anyone_can_pay = sighash_u32 & 0x80 != 0;
    let cleaned_script_code = strip_codeseparators(script_code);

    // SIGHASH_SINGLE edge case: if input_index >= outputs.len(), return 1
    if base == 3 && input_index >= tx.outputs.len() {
        let mut result = [0u8; 32];
        result[0] = 1;
        return Hash256(result);
    }

    let mut buf = Vec::new();

    // version
    tx.version.encode(&mut buf).unwrap();

    // inputs
    let inputs_to_sign: Vec<_> = if anyone_can_pay {
        vec![input_index]
    } else {
        (0..tx.inputs.len()).collect()
    };

    VarInt(inputs_to_sign.len() as u64).encode(&mut buf).unwrap();

    for &i in &inputs_to_sign {
        let input = &tx.inputs[i];
        input.previous_output.encode(&mut buf).unwrap();

        // Only the current input gets the script_code
        if i == input_index {
            cleaned_script_code.encode(&mut buf).unwrap();
        } else {
            Script::new().encode(&mut buf).unwrap(); // empty script
        }

        // Sequence: zeroed for SIGHASH_NONE/SINGLE unless it's the current input
        let seq = if base == 2 || base == 3 {
            if i == input_index { input.sequence } else { 0 }
        } else {
            input.sequence
        };
        seq.encode(&mut buf).unwrap();
    }

    // outputs
    match base {
        1 => {
            // ALL: sign all outputs
            VarInt(tx.outputs.len() as u64).encode(&mut buf).unwrap();
            for output in &tx.outputs {
                output.encode(&mut buf).unwrap();
            }
        }
        2 => {
            // NONE: no outputs
            VarInt(0u64).encode(&mut buf).unwrap();
        }
        3 => {
            // SINGLE: sign only the output at input_index, others as empty
            VarInt((input_index + 1) as u64).encode(&mut buf).unwrap();
            for i in 0..input_index {
                let _ = i;
                // empty output: value = -1, script = empty
                (-1i64).encode(&mut buf).unwrap();
                Script::new().encode(&mut buf).unwrap();
            }
            tx.outputs[input_index].encode(&mut buf).unwrap();
        }
        _ => {
            // Unknown/non-standard sighash base type: treat as SIGHASH_ALL.
            // Early Bitcoin nodes had this behavior for unusual hashtype bytes.
            VarInt(tx.outputs.len() as u64).encode(&mut buf).unwrap();
            for output in &tx.outputs {
                output.encode(&mut buf).unwrap();
            }
        }
    }

    // locktime
    tx.lock_time.encode(&mut buf).unwrap();

    // append sighash type
    sighash_u32.encode(&mut buf).unwrap();

    sha256d(&buf)
}

/// BIP143 sighash for SegWit v0 inputs (P2WPKH and P2WSH)
pub fn sighash_segwit_v0(
    tx: &Transaction,
    input_index: usize,
    script_code: &Script,
    value: u64,
    sighash_type: SighashType,
) -> Hash256 {
    sighash_segwit_v0_with_u32(tx, input_index, script_code, value, sighash_type as u32)
}

/// Compute BIP143 sighash from a raw 32-bit sighash value.
pub fn sighash_segwit_v0_with_u32(
    tx: &Transaction,
    input_index: usize,
    script_code: &Script,
    value: u64,
    sighash_u32: u32,
) -> Hash256 {
    let base = sighash_u32 & 0x1f;
    let anyone_can_pay = sighash_u32 & 0x80 != 0;
    let is_single = base == 3;
    let is_none = base == 2;

    // hash_prevouts
    let hash_prevouts = if !anyone_can_pay {
        let mut data = Vec::new();
        for input in &tx.inputs {
            input.previous_output.encode(&mut data).unwrap();
        }
        sha256d(&data)
    } else {
        Hash256::ZERO
    };

    // hash_sequence
    // Core behavior: all non-NONE/non-SINGLE base types include hashSequence.
    // This covers non-standard but consensus-valid sighash base values too.
    let hash_sequence = if !anyone_can_pay && !is_single && !is_none {
        let mut data = Vec::new();
        for input in &tx.inputs {
            input.sequence.encode(&mut data).unwrap();
        }
        sha256d(&data)
    } else {
        Hash256::ZERO
    };

    // hash_outputs
    let hash_outputs = if !is_single && !is_none {
        let mut data = Vec::new();
        for output in &tx.outputs {
            output.encode(&mut data).unwrap();
        }
        sha256d(&data)
    } else if is_single && input_index < tx.outputs.len() {
        let mut data = Vec::new();
        tx.outputs[input_index].encode(&mut data).unwrap();
        sha256d(&data)
    } else {
        Hash256::ZERO
    };

    let mut buf = Vec::new();
    tx.version.encode(&mut buf).unwrap();
    hash_prevouts.0.encode(&mut buf).unwrap();
    hash_sequence.0.encode(&mut buf).unwrap();

    let input = &tx.inputs[input_index];
    input.previous_output.encode(&mut buf).unwrap();
    script_code.encode(&mut buf).unwrap();
    value.encode(&mut buf).unwrap();
    input.sequence.encode(&mut buf).unwrap();

    hash_outputs.0.encode(&mut buf).unwrap();
    tx.lock_time.encode(&mut buf).unwrap();
    sighash_u32.encode(&mut buf).unwrap();

    sha256d(&buf)
}

/// BIP341 sighash for Taproot (SegWit v1) inputs
pub fn sighash_taproot(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
    sighash_type: SighashType,
    leaf_hash: Option<&[u8; 32]>, // None = key path spend
    annex: Option<&[u8]>,
    key_version: u8,
    code_separator_pos: u32,
) -> Hash256 {
    let sighash_byte = sighash_type as u8;
    // BIP341: 0x00 (TaprootDefault) has SIGHASH_ALL semantics.
    let mut base = sighash_byte & 0x1f;
    if base == 0 {
        base = 1;
    }
    let anyone_can_pay = sighash_byte & 0x80 != 0;

    let mut buf = Vec::new();

    // epoch
    buf.push(0u8);

    // sighash type
    buf.push(sighash_byte);

    // version + locktime
    tx.version.encode(&mut buf).unwrap();
    tx.lock_time.encode(&mut buf).unwrap();

    if !anyone_can_pay {
        // hash_prevouts
        let mut data = Vec::new();
        for input in &tx.inputs {
            input.previous_output.encode(&mut data).unwrap();
        }
        let h = sha256(&data);
        buf.extend_from_slice(&h.0);

        // hash_amounts
        let mut data = Vec::new();
        for prevout in prevouts {
            prevout.value.encode(&mut data).unwrap();
        }
        let h = sha256(&data);
        buf.extend_from_slice(&h.0);

        // hash_scriptpubkeys
        let mut data = Vec::new();
        for prevout in prevouts {
            prevout.script_pubkey.encode(&mut data).unwrap();
        }
        let h = sha256(&data);
        buf.extend_from_slice(&h.0);

        // hash_sequences
        let mut data = Vec::new();
        for input in &tx.inputs {
            input.sequence.encode(&mut data).unwrap();
        }
        let h = sha256(&data);
        buf.extend_from_slice(&h.0);
    }

    if base == 1 {
        // hash_outputs (ALL)
        let mut data = Vec::new();
        for output in &tx.outputs {
            output.encode(&mut data).unwrap();
        }
        let h = sha256(&data);
        buf.extend_from_slice(&h.0);
    }

    // spend_type
    let have_annex = annex.is_some();
    let ext_flag: u8 = if leaf_hash.is_some() { 1 } else { 0 };
    let spend_type = ext_flag * 2 + if have_annex { 1 } else { 0 };
    buf.push(spend_type);

    // Input data
    if anyone_can_pay {
        let input = &tx.inputs[input_index];
        input.previous_output.encode(&mut buf).unwrap();
        prevouts[input_index].value.encode(&mut buf).unwrap();
        prevouts[input_index].script_pubkey.encode(&mut buf).unwrap();
        input.sequence.encode(&mut buf).unwrap();
    } else {
        (input_index as u32).encode(&mut buf).unwrap();
    }

    if let Some(annex_data) = annex {
        // BIP341 annex hash: SHA256(compact_size || annex), where annex
        // already includes the 0x50 tag byte in witness data.
        let mut annex_ser = Vec::new();
        VarInt(annex_data.len() as u64).encode(&mut annex_ser).unwrap();
        annex_ser.extend_from_slice(annex_data);
        let mut h = Sha256::new();
        h.update(&annex_ser);
        buf.extend_from_slice(&h.finalize());
    }

    if base == 3 && input_index < tx.outputs.len() {
        // BIP341: for SIGHASH_SINGLE, hash of the matching output is committed
        // after spend_type/input/annex data.
        let mut data = Vec::new();
        tx.outputs[input_index].encode(&mut data).unwrap();
        let h = sha256(&data);
        buf.extend_from_slice(&h.0);
    }

    if let Some(lh) = leaf_hash {
        buf.extend_from_slice(lh);
        buf.push(key_version);
        buf.extend_from_slice(&code_separator_pos.to_le_bytes());
    }

    tagged_hash(b"TapSighash", &buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sig::verify_schnorr;
    use rbtc_primitives::transaction::{OutPoint, TxIn, TxOut};
    use rbtc_primitives::hash::Hash256;
    use rbtc_primitives::codec::Decodable;
    use std::io::Cursor;

    fn decode_hex(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0, "hex string must have even length");
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        for i in (0..bytes.len()).step_by(2) {
            let hi = (bytes[i] as char).to_digit(16).expect("invalid hex") as u8;
            let lo = (bytes[i + 1] as char).to_digit(16).expect("invalid hex") as u8;
            out.push((hi << 4) | lo);
        }
        out
    }

    fn sample_tx() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![
                TxIn {
                    previous_output: OutPoint { txid: Hash256([0; 32]), vout: 0 },
                    script_sig: Script::new(),
                    sequence: 0xffffffff,
                    witness: vec![],
                },
            ],
            outputs: vec![TxOut {
                value: 1000,
                script_pubkey: Script::new(),
            }],
            lock_time: 0,
        }
    }

    #[test]
    fn sighash_type_from_u32() {
        assert_eq!(SighashType::from_u32(0), Some(SighashType::TaprootDefault));
        assert_eq!(SighashType::from_u32(1), Some(SighashType::All));
        assert_eq!(SighashType::from_u32(2), Some(SighashType::None));
        assert_eq!(SighashType::from_u32(3), Some(SighashType::Single));
        assert_eq!(SighashType::from_u32(0x81), Some(SighashType::AllAnyoneCanPay));
        assert_eq!(SighashType::from_u32(0x82), Some(SighashType::NoneAnyoneCanPay));
        assert_eq!(SighashType::from_u32(0x83), Some(SighashType::SingleAnyoneCanPay));
        assert_eq!(SighashType::from_u32(99), None);
    }

    #[test]
    fn sighash_type_base_and_anyone_can_pay() {
        assert_eq!(SighashType::All.base_type(), 1);
        assert!(!SighashType::All.anyone_can_pay());
        assert!(SighashType::AllAnyoneCanPay.anyone_can_pay());
        assert_eq!(SighashType::TaprootDefault.base_type(), 0);
    }

    #[test]
    fn sighash_legacy_all() {
        let tx = sample_tx();
        let script = Script::new();
        let h = sighash_legacy(&tx, 0, &script, SighashType::All);
        assert_eq!(h.0.len(), 32);
    }

    #[test]
    fn sighash_legacy_none() {
        let tx = sample_tx();
        let h = sighash_legacy(&tx, 0, &Script::new(), SighashType::None);
        assert_eq!(h.0.len(), 32);
    }

    #[test]
    fn sighash_legacy_single() {
        let tx = sample_tx();
        let h = sighash_legacy(&tx, 0, &Script::new(), SighashType::Single);
        assert_eq!(h.0.len(), 32);
    }

    #[test]
    fn sighash_legacy_single_index_out_of_range() {
        let tx = sample_tx();
        let h = sighash_legacy(&tx, 5, &Script::new(), SighashType::Single);
        assert_eq!(h.0[0], 1);
        assert!(h.0[1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn sighash_legacy_anyone_can_pay() {
        let tx = sample_tx();
        let h = sighash_legacy(&tx, 0, &Script::new(), SighashType::AllAnyoneCanPay);
        assert_eq!(h.0.len(), 32);
    }

    #[test]
    fn sighash_legacy_ignores_codeseparator() {
        let tx = sample_tx();
        let with_sep = Script::from_bytes(vec![0x51, 0xab, 0x52, 0xab, 0x53, 0xac]);
        let without_sep = Script::from_bytes(vec![0x51, 0x52, 0x53, 0xac]);
        let h_with = sighash_legacy(&tx, 0, &with_sep, SighashType::All);
        let h_without = sighash_legacy(&tx, 0, &without_sep, SighashType::All);
        assert_eq!(h_with, h_without);
    }

    #[test]
    fn test_sighash_segwit_v0() {
        let tx = sample_tx();
        let h = sighash_segwit_v0(&tx, 0, &Script::new(), 1000, SighashType::All);
        assert_eq!(h.0.len(), 32);
    }

    #[test]
    fn test_sighash_segwit_v0_none() {
        let tx = sample_tx();
        let h = sighash_segwit_v0(&tx, 0, &Script::new(), 1000, SighashType::None);
        assert_eq!(h.0.len(), 32);
    }

    #[test]
    fn test_sighash_segwit_v0_single() {
        let tx = sample_tx();
        let h = sighash_segwit_v0(&tx, 0, &Script::new(), 1000, SighashType::Single);
        assert_eq!(h.0.len(), 32);
    }

    #[test]
    fn sighash_taproot_default() {
        let tx = sample_tx();
        let prevouts = vec![TxOut { value: 1000, script_pubkey: Script::new() }];
        let h = sighash_taproot(
            &tx,
            0,
            &prevouts,
            SighashType::TaprootDefault,
            None,
            None,
            0,
            u32::MAX,
        );
        assert_eq!(h.0.len(), 32);
    }

    #[test]
    fn sighash_taproot_with_annex() {
        let tx = sample_tx();
        let prevouts = vec![TxOut { value: 1000, script_pubkey: Script::new() }];
        let annex = vec![0x50];
        let h = sighash_taproot(
            &tx,
            0,
            &prevouts,
            SighashType::All,
            None,
            Some(&annex),
            0,
            u32::MAX,
        );
        assert_eq!(h.0.len(), 32);
    }

    #[test]
    fn sighash_taproot_with_leaf_hash() {
        let tx = sample_tx();
        let prevouts = vec![TxOut { value: 1000, script_pubkey: Script::new() }];
        let leaf = [1u8; 32];
        let h = sighash_taproot(
            &tx,
            0,
            &prevouts,
            SighashType::All,
            Some(&leaf),
            None,
            0,
            u32::MAX,
        );
        assert_eq!(h.0.len(), 32);
    }

    #[test]
    fn sighash_taproot_anyone_can_pay() {
        let tx = sample_tx();
        let prevouts = vec![TxOut { value: 1000, script_pubkey: Script::new() }];
        let h = sighash_taproot(
            &tx,
            0,
            &prevouts,
            SighashType::AllAnyoneCanPay,
            None,
            None,
            0,
            u32::MAX,
        );
        assert_eq!(h.0.len(), 32);
    }

    #[test]
    fn sighash_taproot_single() {
        let tx = sample_tx();
        let prevouts = vec![TxOut { value: 1000, script_pubkey: Script::new() }];
        let h = sighash_taproot(
            &tx,
            0,
            &prevouts,
            SighashType::Single,
            None,
            None,
            0,
            u32::MAX,
        );
        assert_eq!(h.0.len(), 32);
    }

    #[test]
    fn sighash_taproot_scriptpath_codesep_affects_hash() {
        let tx = sample_tx();
        let prevouts = vec![TxOut { value: 1000, script_pubkey: Script::new() }];
        let leaf = [7u8; 32];
        let h1 = sighash_taproot(
            &tx,
            0,
            &prevouts,
            SighashType::All,
            Some(&leaf),
            None,
            0,
            0,
        );
        let h2 = sighash_taproot(
            &tx,
            0,
            &prevouts,
            SighashType::All,
            Some(&leaf),
            None,
            0,
            42,
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn sighash_taproot_uses_single_sha256_subhashes() {
        let tx = Transaction {
            version: 2,
            inputs: vec![
                TxIn {
                    previous_output: OutPoint { txid: Hash256([1; 32]), vout: 1 },
                    script_sig: Script::new(),
                    sequence: 0x11223344,
                    witness: vec![],
                },
                TxIn {
                    previous_output: OutPoint { txid: Hash256([2; 32]), vout: 2 },
                    script_sig: Script::new(),
                    sequence: 0x55667788,
                    witness: vec![],
                },
            ],
            outputs: vec![
                TxOut { value: 111, script_pubkey: Script::from_bytes(vec![0x51]) },
                TxOut { value: 222, script_pubkey: Script::from_bytes(vec![0x51, 0x51]) },
            ],
            lock_time: 3,
        };
        let prevouts = vec![
            TxOut { value: 777, script_pubkey: Script::from_bytes(vec![0x51, 0x21]) },
            TxOut { value: 888, script_pubkey: Script::from_bytes(vec![0x51, 0x22, 0x23]) },
        ];

        let got = sighash_taproot(
            &tx,
            1,
            &prevouts,
            SighashType::All,
            None,
            None,
            0,
            u32::MAX,
        );

        let mut msg = Vec::new();
        msg.push(0u8); // epoch
        msg.push(SighashType::All as u8);
        tx.version.encode(&mut msg).unwrap();
        tx.lock_time.encode(&mut msg).unwrap();

        let mut prevouts_ser = Vec::new();
        for input in &tx.inputs {
            input.previous_output.encode(&mut prevouts_ser).unwrap();
        }
        msg.extend_from_slice(&sha256(&prevouts_ser).0);

        let mut amounts_ser = Vec::new();
        for prevout in &prevouts {
            prevout.value.encode(&mut amounts_ser).unwrap();
        }
        msg.extend_from_slice(&sha256(&amounts_ser).0);

        let mut spk_ser = Vec::new();
        for prevout in &prevouts {
            prevout.script_pubkey.encode(&mut spk_ser).unwrap();
        }
        msg.extend_from_slice(&sha256(&spk_ser).0);

        let mut seq_ser = Vec::new();
        for input in &tx.inputs {
            input.sequence.encode(&mut seq_ser).unwrap();
        }
        msg.extend_from_slice(&sha256(&seq_ser).0);

        let mut outputs_ser = Vec::new();
        for output in &tx.outputs {
            output.encode(&mut outputs_ser).unwrap();
        }
        msg.extend_from_slice(&sha256(&outputs_ser).0);

        msg.push(0u8); // spend_type: key path, no annex
        (1u32).encode(&mut msg).unwrap(); // input_index

        let expected = tagged_hash(b"TapSighash", &msg);
        assert_eq!(got, expected);
    }

    #[test]
    fn sighash_taproot_default_commits_outputs() {
        let tx1 = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256([9; 32]), vout: 0 },
                script_sig: Script::new(),
                sequence: 0xabcdef01,
                witness: vec![],
            }],
            outputs: vec![
                TxOut { value: 100, script_pubkey: Script::from_bytes(vec![0x51]) },
                TxOut { value: 200, script_pubkey: Script::from_bytes(vec![0x51, 0x51]) },
            ],
            lock_time: 42,
        };
        let mut tx2 = tx1.clone();
        tx2.outputs[1].value = 201;
        let prevouts = vec![TxOut { value: 12345, script_pubkey: Script::from_bytes(vec![0x51, 0x20]) }];

        let h1 = sighash_taproot(
            &tx1,
            0,
            &prevouts,
            SighashType::TaprootDefault,
            None,
            None,
            0,
            u32::MAX,
        );
        let h2 = sighash_taproot(
            &tx2,
            0,
            &prevouts,
            SighashType::TaprootDefault,
            None,
            None,
            0,
            u32::MAX,
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn sighash_taproot_single_anyonecanpay_mainnet_776550_vin1() {
        // Real mainnet tx from block 776550 where vin=1 uses 0x83
        // (SIGHASH_SINGLE|ANYONECANPAY). This must verify under Core ordering.
        let tx_hex = "020000000001033521f3540acb413a3bb15e0e49749b31376f242a5c2cc653d5f5f0e51378269e0000000000ffffffff4b7f67adceab9bdc83fe639d2c96c6d43c483590789644f951d3fb4ee563ad190000000000ffffffff3521f3540acb413a3bb15e0e49749b31376f242a5c2cc653d5f5f0e51378269e0100000000ffffffff031027000000000000225120bb7e66771403f65424a570b6a4cdb3528f964204a2b72744d82f1002bfb1598b10270000000000002251208102001190c6aad9a015dff1540dc9a7bda31613b8ab05a58268c4bff53fae821027000000000000225120bb7e66771403f65424a570b6a4cdb3528f964204a2b72744d82f1002bfb1598b01408b516fc211670bc9ce5ecd128bc7b96974a4b88f7f035977edfade3f6ea2fef7aabfbe7a9022f9a2d0de6203edccfb414b457f4b7275cd9b242f72c8d95ef4c201410d41273b5b93ee77aaf41b3b558924e4cc545c81894cbf81684a89f09c1355f78de33d254d93d6109c9c8bb52f76521a702ea34d9802ed4e9944ee11395b69c7830140a1358aac56f96b1846b81de498e92128f1302bc5a7d9e486a71e3fd6792ad671dd22abd14421a738f631882f3491c2f66b5bd27495413e87df9e0f5bcdcf31cd00000000";
        let tx = Transaction::decode(&mut Cursor::new(decode_hex(tx_hex))).unwrap();

        let prevouts = vec![
            TxOut {
                value: 20_000,
                script_pubkey: Script::from_bytes(
                    decode_hex("5120bb7e66771403f65424a570b6a4cdb3528f964204a2b72744d82f1002bfb1598b"),
                ),
            },
            TxOut {
                value: 10_000,
                script_pubkey: Script::from_bytes(
                    decode_hex("51208102001190c6aad9a015dff1540dc9a7bda31613b8ab05a58268c4bff53fae82"),
                ),
            },
            TxOut {
                value: 5_928,
                script_pubkey: Script::from_bytes(
                    decode_hex("5120bb7e66771403f65424a570b6a4cdb3528f964204a2b72744d82f1002bfb1598b"),
                ),
            },
        ];

        let sig_with_hashtype = &tx.inputs[1].witness[0];
        assert_eq!(sig_with_hashtype.len(), 65);
        assert_eq!(sig_with_hashtype[64], 0x83);
        let sig = &sig_with_hashtype[..64];

        let h = sighash_taproot(
            &tx,
            1,
            &prevouts,
            SighashType::SingleAnyoneCanPay,
            None,
            None,
            0,
            u32::MAX,
        );

        // x-only output key from prevout scriptPubKey (OP_1 0x20 <32-byte key>)
        let output_key = decode_hex("8102001190c6aad9a015dff1540dc9a7bda31613b8ab05a58268c4bff53fae82");
        assert!(verify_schnorr(&output_key, sig, &h.0).is_ok());
    }
}
