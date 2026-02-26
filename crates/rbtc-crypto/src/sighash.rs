use rbtc_primitives::{
    codec::{Encodable, VarInt},
    hash::Hash256,
    script::Script,
    transaction::{Transaction, TxOut},
};
use sha2::{Digest, Sha256};

use crate::digest::{sha256d, tagged_hash};

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
            script_code.encode(&mut buf).unwrap();
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
    let hash_sequence = if !anyone_can_pay && base == 1 {
        let mut data = Vec::new();
        for input in &tx.inputs {
            input.sequence.encode(&mut data).unwrap();
        }
        sha256d(&data)
    } else {
        Hash256::ZERO
    };

    // hash_outputs
    let hash_outputs = match base {
        1 => {
            let mut data = Vec::new();
            for output in &tx.outputs {
                output.encode(&mut data).unwrap();
            }
            sha256d(&data)
        }
        3 if input_index < tx.outputs.len() => {
            let mut data = Vec::new();
            tx.outputs[input_index].encode(&mut data).unwrap();
            sha256d(&data)
        }
        _ => Hash256::ZERO,
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
) -> Hash256 {
    let sighash_byte = sighash_type as u8;
    let base = sighash_byte & 0x1f;
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
        buf.extend_from_slice(&sha256d(&data).0);

        // hash_amounts
        let mut data = Vec::new();
        for prevout in prevouts {
            prevout.value.encode(&mut data).unwrap();
        }
        buf.extend_from_slice(&sha256d(&data).0);

        // hash_scriptpubkeys
        let mut data = Vec::new();
        for prevout in prevouts {
            prevout.script_pubkey.encode(&mut data).unwrap();
        }
        buf.extend_from_slice(&sha256d(&data).0);

        // hash_sequences
        let mut data = Vec::new();
        for input in &tx.inputs {
            input.sequence.encode(&mut data).unwrap();
        }
        buf.extend_from_slice(&sha256d(&data).0);
    }

    if base == 1 {
        // hash_outputs (ALL)
        let mut data = Vec::new();
        for output in &tx.outputs {
            output.encode(&mut data).unwrap();
        }
        buf.extend_from_slice(&sha256d(&data).0);
    } else if base == 3 && input_index < tx.outputs.len() {
        // hash_outputs (SINGLE)
        let mut data = Vec::new();
        tx.outputs[input_index].encode(&mut data).unwrap();
        buf.extend_from_slice(&sha256d(&data).0);
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

    if let Some(lh) = leaf_hash {
        buf.extend_from_slice(lh);
        buf.push(0x00); // key_version
        buf.extend_from_slice(&0xffffffffu32.to_le_bytes()); // code_separator_pos = UINT_MAX
    }

    tagged_hash(b"TapSighash", &buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::transaction::{OutPoint, TxIn, TxOut};
    use rbtc_primitives::hash::Hash256;

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
        let h = sighash_taproot(&tx, 0, &prevouts, SighashType::TaprootDefault, None, None);
        assert_eq!(h.0.len(), 32);
    }

    #[test]
    fn sighash_taproot_with_annex() {
        let tx = sample_tx();
        let prevouts = vec![TxOut { value: 1000, script_pubkey: Script::new() }];
        let annex = vec![0x50];
        let h = sighash_taproot(&tx, 0, &prevouts, SighashType::All, None, Some(&annex));
        assert_eq!(h.0.len(), 32);
    }

    #[test]
    fn sighash_taproot_with_leaf_hash() {
        let tx = sample_tx();
        let prevouts = vec![TxOut { value: 1000, script_pubkey: Script::new() }];
        let leaf = [1u8; 32];
        let h = sighash_taproot(&tx, 0, &prevouts, SighashType::All, Some(&leaf), None);
        assert_eq!(h.0.len(), 32);
    }

    #[test]
    fn sighash_taproot_anyone_can_pay() {
        let tx = sample_tx();
        let prevouts = vec![TxOut { value: 1000, script_pubkey: Script::new() }];
        let h = sighash_taproot(&tx, 0, &prevouts, SighashType::AllAnyoneCanPay, None, None);
        assert_eq!(h.0.len(), 32);
    }

    #[test]
    fn sighash_taproot_single() {
        let tx = sample_tx();
        let prevouts = vec![TxOut { value: 1000, script_pubkey: Script::new() }];
        let h = sighash_taproot(&tx, 0, &prevouts, SighashType::Single, None, None);
        assert_eq!(h.0.len(), 32);
    }
}
