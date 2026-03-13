//! Signet block signing support.
//!
//! Implements the signet pseudo-transaction construction and solution
//! extraction from Bitcoin Core's `signet.cpp`. Signet blocks carry an
//! embedded signature in the coinbase witness commitment that proves the
//! block was authorised by the signet challenge key holders.

use rbtc_crypto::merkle::merkle_root;
use rbtc_primitives::{
    block::Block,
    codec::Encodable,
    hash::{Hash256, Txid},
    script::Script,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
};

use crate::template::compute_txid;

/// 4-byte signet header magic embedded in coinbase OP_RETURN outputs.
pub const SIGNET_HEADER: [u8; 4] = [0xec, 0xc7, 0xda, 0xa2];

/// BIP141 witness commitment header: 0xaa21a9ed
const WITNESS_COMMITMENT_HEADER: [u8; 4] = [0xaa, 0x21, 0xa9, 0xed];

/// Pair of pseudo-transactions used for signet block signature verification.
///
/// Mirrors Bitcoin Core's `SignetTxs` struct from `signet.cpp`.
#[derive(Debug, Clone)]
pub struct SignetTxs {
    /// The "to_spend" transaction whose output carries the signet challenge script.
    pub to_spend: Transaction,
    /// The "to_sign" transaction that spends `to_spend`'s output, carrying the solution.
    pub to_sign: Transaction,
}

impl SignetTxs {
    /// Construct the signet pseudo-transaction pair from a block and challenge script.
    ///
    /// This mirrors `SignetTxs::Create()` in Bitcoin Core's `signet.cpp`:
    /// 1. Build `to_spend`: version=0, input=(0:0xFFFFFFFF, scriptSig=OP_0, seq=0),
    ///    output=(value=0, scriptPubKey=challenge).
    /// 2. Build `to_sign`: version=0, input spending `to_spend` output 0, output=(value=0, OP_RETURN).
    /// 3. Extract signet solution from coinbase witness commitment (SIGNET_HEADER magic).
    /// 4. Compute modified merkle root (with signet data stripped from coinbase).
    /// 5. Prepend block header data to `to_spend`'s scriptSig.
    ///
    /// Returns `None` if the block has no coinbase or no witness commitment.
    pub fn create(block: &Block, challenge: &[u8]) -> Option<Self> {
        if block.transactions.is_empty() {
            return None;
        }

        let coinbase = &block.transactions[0];

        // Find the witness commitment output index (last OP_RETURN with 0xaa21a9ed header).
        let cidx = find_witness_commitment_index(coinbase)?;

        // Clone the coinbase's witness commitment output scriptPubKey to extract
        // and strip the signet solution from it.
        let commitment_script = coinbase.outputs[cidx].script_pubkey.as_bytes().to_vec();

        // Extract the signet solution from the witness commitment script and
        // produce a modified script with the solution stripped.
        let (signet_solution, modified_commitment_script) =
            fetch_and_clear_commitment_section(&SIGNET_HEADER, &commitment_script);

        // Parse solution into scriptSig and witness for to_sign.
        let (solution_script_sig, solution_witness) = if let Some(solution) = signet_solution {
            parse_signet_solution(&solution)?
        } else {
            // No signet solution — allow this for OP_TRUE trivial challenges.
            (Vec::new(), Vec::new())
        };

        // Build modified coinbase for merkle root computation: replace the
        // witness commitment output with the stripped version.
        let mut modified_coinbase_outputs = coinbase.outputs.clone();
        modified_coinbase_outputs[cidx] = TxOut {
            value: modified_coinbase_outputs[cidx].value,
            script_pubkey: Script::from_bytes(modified_commitment_script),
        };

        // Compute modified coinbase txid.
        let modified_coinbase = Transaction::from_parts(
            coinbase.version,
            coinbase.inputs.clone(),
            modified_coinbase_outputs,
            coinbase.lock_time,
        );
        let modified_coinbase_txid = compute_txid(&modified_coinbase);

        // Compute modified merkle root.
        let signet_merkle = compute_modified_merkle_root(&modified_coinbase_txid, block);

        // Build block_data: version || prev_block || signet_merkle || time
        let mut block_data = Vec::new();
        block.header.version.encode(&mut block_data).ok();
        block.header.prev_block.0 .0.encode(&mut block_data).ok();
        signet_merkle.0.encode(&mut block_data).ok();
        block.header.time.encode(&mut block_data).ok();

        // Build to_spend scriptSig: <block_data> OP_0
        let mut to_spend_script_sig = Vec::new();
        // Push block_data as a single push
        push_data(&mut to_spend_script_sig, &block_data);
        to_spend_script_sig.push(0x00); // OP_0

        let to_spend = Transaction::from_parts(
            0, // version = 0
            vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(to_spend_script_sig),
                sequence: 0,
                witness: vec![],
            }],
            vec![TxOut {
                value: 0,
                script_pubkey: Script::from_bytes(challenge.to_vec()),
            }],
            0, // locktime = 0
        );

        // Compute to_spend's txid for the to_sign input.
        let to_spend_txid = compute_txid(&to_spend);

        let to_sign = Transaction::from_parts(
            0, // version = 0
            vec![TxIn {
                previous_output: OutPoint::new(Txid(to_spend_txid), 0),
                script_sig: Script::from_bytes(solution_script_sig),
                sequence: 0,
                witness: solution_witness,
            }],
            vec![TxOut {
                value: 0,
                script_pubkey: Script::from_bytes(vec![0x6a]), // OP_RETURN
            }],
            0, // locktime = 0
        );

        Some(SignetTxs { to_spend, to_sign })
    }
}

/// Check the signet block solution.
///
/// Extracts the signet solution from the coinbase, constructs the
/// pseudo-transaction pair, and verifies structural validity.
///
/// Note: Full script verification (signature check) requires the script
/// engine which lives in `rbtc-script`. This function performs the
/// structural checks (solution extraction, transaction construction).
/// The actual `VerifyScript` call should be done by the caller with
/// access to the script interpreter.
///
/// Returns `true` if the signet transactions could be constructed
/// successfully (solution is structurally valid).
pub fn check_signet_solution(block: &Block, challenge: &[u8]) -> bool {
    SignetTxs::create(block, challenge).is_some()
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Find the witness commitment output index in a coinbase transaction.
///
/// Scans outputs from last to first for an OP_RETURN output whose
/// scriptPubKey starts with `0x6a 0x24 0xaa 0x21 0xa9 0xed`.
fn find_witness_commitment_index(coinbase: &Transaction) -> Option<usize> {
    for i in (0..coinbase.outputs.len()).rev() {
        let script = coinbase.outputs[i].script_pubkey.as_bytes();
        if script.len() >= 38
            && script[0] == 0x6a
            && script[1] == 0x24
            && script[2..6] == WITNESS_COMMITMENT_HEADER
        {
            return Some(i);
        }
    }
    None
}

/// Extract and strip a commitment section identified by `header` from a script.
///
/// Parses the script's push-data elements. When a push whose data starts
/// with `header` is found, the data after the header is returned as the
/// "solution", and the push in the script is truncated to just the header.
///
/// Returns `(Some(solution_bytes), modified_script)` if found, or
/// `(None, original_script)` if not.
fn fetch_and_clear_commitment_section(
    header: &[u8; 4],
    script: &[u8],
) -> (Option<Vec<u8>>, Vec<u8>) {
    // Parse the script to find push data elements.
    // The witness commitment script is: OP_RETURN <push N bytes>
    // We need to find a push data element that starts with the signet header.
    let mut result = None;
    let mut modified = Vec::new();
    let mut i = 0;

    while i < script.len() {
        let opcode = script[i];

        if opcode == 0x00 {
            // OP_0
            modified.push(opcode);
            i += 1;
        } else if opcode <= 0x4b {
            // Direct push: opcode bytes of data follow
            let len = opcode as usize;
            if i + 1 + len > script.len() {
                // Malformed, copy remaining
                modified.extend_from_slice(&script[i..]);
                break;
            }
            let data = &script[i + 1..i + 1 + len];
            if result.is_none() && data.len() > header.len() && data[..header.len()] == *header {
                // Found the signet commitment
                result = Some(data[header.len()..].to_vec());
                // Replace with truncated push (just the header)
                modified.push(header.len() as u8);
                modified.extend_from_slice(header);
            } else {
                modified.push(opcode);
                modified.extend_from_slice(data);
            }
            i += 1 + len;
        } else if opcode == 0x4c {
            // OP_PUSHDATA1
            if i + 1 >= script.len() {
                modified.extend_from_slice(&script[i..]);
                break;
            }
            let len = script[i + 1] as usize;
            if i + 2 + len > script.len() {
                modified.extend_from_slice(&script[i..]);
                break;
            }
            let data = &script[i + 2..i + 2 + len];
            if result.is_none() && data.len() > header.len() && data[..header.len()] == *header {
                result = Some(data[header.len()..].to_vec());
                // Replace with just header using direct push
                modified.push(header.len() as u8);
                modified.extend_from_slice(header);
            } else {
                modified.push(opcode);
                modified.push(script[i + 1]);
                modified.extend_from_slice(data);
            }
            i += 2 + len;
        } else if opcode == 0x4d {
            // OP_PUSHDATA2
            if i + 2 >= script.len() {
                modified.extend_from_slice(&script[i..]);
                break;
            }
            let len = u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize;
            if i + 3 + len > script.len() {
                modified.extend_from_slice(&script[i..]);
                break;
            }
            let data = &script[i + 3..i + 3 + len];
            if result.is_none() && data.len() > header.len() && data[..header.len()] == *header {
                result = Some(data[header.len()..].to_vec());
                modified.push(header.len() as u8);
                modified.extend_from_slice(header);
            } else {
                modified.push(opcode);
                modified.extend_from_slice(&script[i + 1..i + 3]);
                modified.extend_from_slice(data);
            }
            i += 3 + len;
        } else {
            // Non-push opcode
            modified.push(opcode);
            i += 1;
        }
    }

    (result, modified)
}

/// Parse the signet solution bytes into (scriptSig, witness).
///
/// The solution is serialized as: `<scriptSig_bytes> <witness_stack>`.
/// scriptSig is a CScript (compact-size length-prefixed byte vector).
/// witness stack is a vector of vectors (compact-size count, then each item
/// is compact-size length-prefixed).
///
/// Returns `None` if parsing fails or extraneous data remains.
fn parse_signet_solution(solution: &[u8]) -> Option<(Vec<u8>, Vec<Vec<u8>>)> {
    let mut cursor = 0;

    // Read scriptSig (compact-size prefixed byte vector).
    let (script_sig, consumed) = read_compact_bytes(solution, cursor)?;
    cursor += consumed;

    // Read witness stack.
    let (count, consumed) = read_compact_size(solution, cursor)?;
    cursor += consumed;

    let mut witness = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (item, consumed) = read_compact_bytes(solution, cursor)?;
        cursor += consumed;
        witness.push(item);
    }

    if cursor != solution.len() {
        return None; // Extraneous data
    }

    Some((script_sig, witness))
}

/// Read a compact-size encoded integer from `data` at `offset`.
fn read_compact_size(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    if offset >= data.len() {
        return None;
    }
    let first = data[offset];
    match first {
        0..=0xfc => Some((first as u64, 1)),
        0xfd => {
            if offset + 3 > data.len() {
                return None;
            }
            let v = u16::from_le_bytes([data[offset + 1], data[offset + 2]]);
            Some((v as u64, 3))
        }
        0xfe => {
            if offset + 5 > data.len() {
                return None;
            }
            let v = u32::from_le_bytes([
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
            ]);
            Some((v as u64, 5))
        }
        0xff => {
            if offset + 9 > data.len() {
                return None;
            }
            let v = u64::from_le_bytes([
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
                data[offset + 8],
            ]);
            Some((v, 9))
        }
    }
}

/// Read a compact-size-prefixed byte vector from `data` at `offset`.
fn read_compact_bytes(data: &[u8], offset: usize) -> Option<(Vec<u8>, usize)> {
    let (len, size_bytes) = read_compact_size(data, offset)?;
    let len = len as usize;
    let start = offset + size_bytes;
    if start + len > data.len() {
        return None;
    }
    Some((data[start..start + len].to_vec(), size_bytes + len))
}

/// Push data onto a script using the appropriate push opcode.
fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len <= 0x4b {
        script.push(len as u8);
    } else if len <= 0xff {
        script.push(0x4c); // OP_PUSHDATA1
        script.push(len as u8);
    } else if len <= 0xffff {
        script.push(0x4d); // OP_PUSHDATA2
        script.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        script.push(0x4e); // OP_PUSHDATA4
        script.extend_from_slice(&(len as u32).to_le_bytes());
    }
    script.extend_from_slice(data);
}

/// Compute the modified merkle root with a replacement coinbase txid.
fn compute_modified_merkle_root(modified_coinbase_txid: &Hash256, block: &Block) -> Hash256 {
    let mut txids = vec![*modified_coinbase_txid];
    for tx in block.transactions.iter().skip(1) {
        txids.push(compute_txid(tx));
    }
    merkle_root(&txids).0.unwrap_or(Hash256::ZERO)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::{
        block::BlockHeader,
        hash::BlockHash,
        script::Script,
        transaction::{OutPoint, Transaction, TxIn, TxOut},
    };

    /// Build a minimal signet-like block with a witness commitment that
    /// includes an embedded signet solution.
    fn make_signet_block(_challenge: &[u8], include_solution: bool) -> Block {
        // Build a trivial signet solution: empty scriptSig + empty witness
        // This works for an OP_TRUE (0x51) challenge.
        let mut signet_solution_data = Vec::new();
        if include_solution {
            // scriptSig = empty (compact-size 0)
            signet_solution_data.push(0x00);
            // witness stack count = 1
            signet_solution_data.push(0x01);
            // witness item = [0x01] (OP_TRUE pushes 1)
            signet_solution_data.push(0x01); // length
            signet_solution_data.push(0x01); // value = 1 (TRUE)
        }

        // Build witness commitment with signet data embedded.
        // The commitment script: OP_RETURN <push N> [aa21a9ed <32-byte commitment>] [ec c7 da a2 <solution>]
        let commitment_hash = [0u8; 32]; // dummy commitment hash
        let mut commitment_script = Vec::new();
        commitment_script.push(0x6a); // OP_RETURN
        // Push the witness commitment (36 bytes: header + hash)
        let mut wc_data = Vec::new();
        wc_data.extend_from_slice(&WITNESS_COMMITMENT_HEADER);
        wc_data.extend_from_slice(&commitment_hash);
        push_data(&mut commitment_script, &wc_data);

        if include_solution {
            // Push signet header + solution
            let mut signet_push = Vec::new();
            signet_push.extend_from_slice(&SIGNET_HEADER);
            signet_push.extend_from_slice(&signet_solution_data);
            push_data(&mut commitment_script, &signet_push);
        }

        // Build coinbase transaction.
        let coinbase = Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![0x01, 0x01]), // height=1
                sequence: 0xffff_ffff,
                witness: vec![[0u8; 32].to_vec()], // witness reserved value
            }],
            vec![
                TxOut {
                    value: 50_0000_0000,
                    script_pubkey: Script::new(),
                },
                TxOut {
                    value: 0,
                    script_pubkey: Script::from_bytes(commitment_script),
                },
            ],
            0,
        );

        Block::new(
            BlockHeader {
                version: 0x2000_0000,
                prev_block: BlockHash::ZERO,
                merkle_root: Hash256::ZERO, // will be wrong, but fine for structural tests
                time: 1_700_000_000,
                bits: 0x207f_ffff,
                nonce: 0,
            },
            vec![coinbase],
        )
    }

    #[test]
    fn signet_txs_create_produces_valid_pair() {
        let challenge = vec![0x51]; // OP_TRUE
        let block = make_signet_block(&challenge, true);
        let txs = SignetTxs::create(&block, &challenge);
        assert!(txs.is_some(), "SignetTxs::create should succeed");

        let txs = txs.unwrap();

        // to_spend has version 0
        assert_eq!(txs.to_spend.version, 0);
        // to_spend has one input (coinbase-like)
        assert_eq!(txs.to_spend.inputs.len(), 1);
        assert!(txs.to_spend.inputs[0].previous_output.is_null());
        assert_eq!(txs.to_spend.inputs[0].sequence, 0);
        // to_spend has one output with the challenge as scriptPubKey
        assert_eq!(txs.to_spend.outputs.len(), 1);
        assert_eq!(txs.to_spend.outputs[0].value, 0);
        assert_eq!(txs.to_spend.outputs[0].script_pubkey.as_bytes(), &challenge);

        // to_sign has version 0
        assert_eq!(txs.to_sign.version, 0);
        // to_sign has one input spending to_spend output 0
        assert_eq!(txs.to_sign.inputs.len(), 1);
        let to_spend_txid = compute_txid(&txs.to_spend);
        assert_eq!(txs.to_sign.inputs[0].previous_output.txid.0, to_spend_txid);
        assert_eq!(txs.to_sign.inputs[0].previous_output.vout, 0);
        assert_eq!(txs.to_sign.inputs[0].sequence, 0);
        // to_sign has one output: OP_RETURN
        assert_eq!(txs.to_sign.outputs.len(), 1);
        assert_eq!(txs.to_sign.outputs[0].value, 0);
        assert_eq!(txs.to_sign.outputs[0].script_pubkey.as_bytes(), &[0x6a]);

        // to_spend scriptSig should end with OP_0 (0x00)
        let sig_bytes = txs.to_spend.inputs[0].script_sig.as_bytes();
        assert_eq!(*sig_bytes.last().unwrap(), 0x00);
    }

    #[test]
    fn empty_signet_solution_fails() {
        let challenge = vec![0x51]; // OP_TRUE
        // Block without signet solution in witness commitment
        let block = make_signet_block(&challenge, false);
        // Should still return Some (Bitcoin Core allows missing solution for OP_TRUE challenges)
        // but check_signet_solution uses structural validity.
        let result = check_signet_solution(&block, &challenge);
        // With no solution data, create() still succeeds (for OP_TRUE).
        assert!(result, "OP_TRUE challenge should work without explicit solution");
    }

    #[test]
    fn missing_coinbase_fails() {
        let challenge = vec![0x51];
        let block = Block::new(
            BlockHeader {
                version: 0x2000_0000,
                prev_block: BlockHash::ZERO,
                merkle_root: Hash256::ZERO,
                time: 0,
                bits: 0x207f_ffff,
                nonce: 0,
            },
            vec![], // no transactions
        );
        assert!(!check_signet_solution(&block, &challenge));
    }

    #[test]
    fn missing_witness_commitment_fails() {
        let challenge = vec![0x51];
        // Block with coinbase but no witness commitment output
        let coinbase = Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![0x01, 0x01]),
                sequence: 0xffff_ffff,
                witness: vec![],
            }],
            vec![TxOut {
                value: 50_0000_0000,
                script_pubkey: Script::new(),
            }],
            0,
        );
        let block = Block::new(
            BlockHeader {
                version: 0x2000_0000,
                prev_block: BlockHash::ZERO,
                merkle_root: Hash256::ZERO,
                time: 0,
                bits: 0x207f_ffff,
                nonce: 0,
            },
            vec![coinbase],
        );
        assert!(!check_signet_solution(&block, &challenge));
    }

    #[test]
    fn fetch_and_clear_extracts_solution() {
        let header = SIGNET_HEADER;
        let solution_payload = vec![0xde, 0xad, 0xbe, 0xef];

        // Build a script: OP_RETURN <push witness commitment> <push signet data>
        let mut script = Vec::new();
        script.push(0x6a); // OP_RETURN

        // Witness commitment push
        let mut wc = Vec::new();
        wc.extend_from_slice(&WITNESS_COMMITMENT_HEADER);
        wc.extend_from_slice(&[0u8; 32]);
        push_data(&mut script, &wc);

        // Signet push
        let mut signet_data = Vec::new();
        signet_data.extend_from_slice(&header);
        signet_data.extend_from_slice(&solution_payload);
        push_data(&mut script, &signet_data);

        let (result, _modified) = fetch_and_clear_commitment_section(&header, &script);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), solution_payload);
    }

    #[test]
    fn signet_header_constant_matches_bitcoin_core() {
        // From Bitcoin Core signet.cpp: {0xec, 0xc7, 0xda, 0xa2}
        assert_eq!(SIGNET_HEADER, [0xec, 0xc7, 0xda, 0xa2]);
    }
}
