/// BIP341 wallet test vectors harness.
///
/// Tests:
/// 1. scriptPubKey: internal key + script tree → tweaked pubkey → scriptPubKey
/// 2. keyPathSpending: sighash computation for Taproot inputs
use serde_json::Value;

fn decode_hex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("bad hex '{s}': {e}"))
}

/// Compute TapTweak tagged hash
fn tap_tweak_hash(pubkey: &[u8; 32], merkle_root: Option<&[u8; 32]>) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let tag = Sha256::digest(b"TapTweak");
    let mut hasher = Sha256::new();
    hasher.update(&tag);
    hasher.update(&tag);
    hasher.update(pubkey);
    if let Some(root) = merkle_root {
        hasher.update(root);
    }
    hasher.finalize().into()
}

/// Compute TapLeaf tagged hash
fn tap_leaf_hash(leaf_version: u8, script: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let tag = Sha256::digest(b"TapLeaf");
    let mut hasher = Sha256::new();
    hasher.update(&tag);
    hasher.update(&tag);
    hasher.update([leaf_version]);
    // compact size encoding of script length
    let len = script.len();
    if len < 0xfd {
        hasher.update([len as u8]);
    } else if len <= 0xffff {
        hasher.update([0xfd]);
        hasher.update((len as u16).to_le_bytes());
    } else {
        hasher.update([0xfe]);
        hasher.update((len as u32).to_le_bytes());
    }
    hasher.update(script);
    hasher.finalize().into()
}

/// Compute TapBranch tagged hash from two children (sorted)
fn tap_branch_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let tag = Sha256::digest(b"TapBranch");
    let mut hasher = Sha256::new();
    hasher.update(&tag);
    hasher.update(&tag);
    // lexicographically sort
    if a <= b {
        hasher.update(a);
        hasher.update(b);
    } else {
        hasher.update(b);
        hasher.update(a);
    }
    hasher.finalize().into()
}

/// Recursively compute merkle root from a script tree JSON value
fn compute_tree_hash(node: &Value) -> [u8; 32] {
    if node.is_object() {
        // Leaf node
        let script_hex = node["script"].as_str().unwrap();
        let leaf_version = node["leafVersion"].as_u64().unwrap() as u8;
        let script = decode_hex(script_hex);
        tap_leaf_hash(leaf_version, &script)
    } else if node.is_array() {
        // Branch: [left, right]
        let arr = node.as_array().unwrap();
        assert_eq!(arr.len(), 2, "branch must have 2 children");
        let left = compute_tree_hash(&arr[0]);
        let right = compute_tree_hash(&arr[1]);
        tap_branch_hash(&left, &right)
    } else {
        panic!("unexpected script tree node type");
    }
}

#[test]
fn bip341_script_pubkey_vectors() {
    let json_text = include_str!("data/bip341_wallet_vectors.json");
    let data: Value = serde_json::from_str(json_text).expect("parse bip341");
    let cases = data["scriptPubKey"].as_array().unwrap();

    let mut failures = Vec::<String>::new();

    for (i, case) in cases.iter().enumerate() {
        let internal_key_hex = case["given"]["internalPubkey"].as_str().unwrap();
        let internal_key_bytes = decode_hex(internal_key_hex);

        // Compute merkle root from script tree
        let script_tree = &case["given"]["scriptTree"];
        let merkle_root = if script_tree.is_null() {
            None
        } else {
            Some(compute_tree_hash(script_tree))
        };

        // Verify intermediary merkle root
        let expected_merkle = &case["intermediary"]["merkleRoot"];
        if !expected_merkle.is_null() {
            let expected_root_hex = expected_merkle.as_str().unwrap();
            let expected_root = decode_hex(expected_root_hex);
            let got_root = merkle_root.unwrap();
            if got_root[..] != expected_root[..] {
                failures.push(format!(
                    "[{i}] merkle root mismatch: expected={expected_root_hex} got={}",
                    hex::encode(got_root)
                ));
                continue;
            }
        }

        // Verify tweak
        let expected_tweak_hex = case["intermediary"]["tweak"].as_str().unwrap();
        let internal_key: [u8; 32] = internal_key_bytes.try_into().unwrap();
        let merkle_root_ref = merkle_root.as_ref();
        let tweak = tap_tweak_hash(&internal_key, merkle_root_ref);
        if hex::encode(tweak) != expected_tweak_hex {
            failures.push(format!(
                "[{i}] tweak mismatch: expected={expected_tweak_hex} got={}",
                hex::encode(tweak)
            ));
            continue;
        }

        // Verify tweaked pubkey via secp256k1
        let expected_tweaked_hex = case["intermediary"]["tweakedPubkey"].as_str().unwrap();
        let secp = secp256k1::Secp256k1::new();
        let xonly = secp256k1::XOnlyPublicKey::from_byte_array(internal_key).unwrap();
        let scalar = secp256k1::Scalar::from_be_bytes(tweak).unwrap();
        let (tweaked, _parity) = xonly.add_tweak(&secp, &scalar).unwrap();
        let tweaked_hex = hex::encode(tweaked.serialize());
        if tweaked_hex != expected_tweaked_hex {
            failures.push(format!(
                "[{i}] tweakedPubkey mismatch: expected={expected_tweaked_hex} got={tweaked_hex}"
            ));
            continue;
        }

        // Verify scriptPubKey = OP_1 <32-byte tweaked key>
        let expected_spk_hex = case["expected"]["scriptPubKey"].as_str().unwrap();
        let mut spk = vec![0x51, 0x20]; // OP_1 PUSH32
        spk.extend_from_slice(&tweaked.serialize());
        let got_spk_hex = hex::encode(&spk);
        if got_spk_hex != expected_spk_hex {
            failures.push(format!(
                "[{i}] scriptPubKey mismatch: expected={expected_spk_hex} got={got_spk_hex}"
            ));
        }
    }

    if !failures.is_empty() {
        for f in &failures {
            eprintln!("  FAIL: {f}");
        }
        panic!(
            "{} / {} bip341 scriptPubKey cases failed",
            failures.len(),
            cases.len()
        );
    }

    println!("bip341 scriptPubKey: {} cases all passed", cases.len());
}

#[test]
fn bip341_key_path_sighash_vectors() {
    use rbtc_crypto::sighash::sighash_taproot;
    use rbtc_primitives::{
        codec::Decodable,
        script::Script,
        transaction::{Transaction, TxOut},
    };

    let json_text = include_str!("data/bip341_wallet_vectors.json");
    let data: Value = serde_json::from_str(json_text).expect("parse bip341");
    let kps = data["keyPathSpending"].as_array().unwrap();

    let mut total = 0usize;
    let mut failures = Vec::<String>::new();

    for kp_entry in kps {
        let given = &kp_entry["given"];
        let tx_hex = given["rawUnsignedTx"].as_str().unwrap();
        let tx_bytes = decode_hex(tx_hex);
        let tx = Transaction::decode(&mut std::io::Cursor::new(&tx_bytes)).unwrap();

        let utxos_spent: Vec<TxOut> = given["utxosSpent"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| TxOut {
                value: u["amountSats"].as_u64().unwrap() as i64,
                script_pubkey: Script::from_bytes(decode_hex(u["scriptPubKey"].as_str().unwrap())),
            })
            .collect();

        for input_case in kp_entry["inputSpending"].as_array().unwrap() {
            let input_given = &input_case["given"];
            let input_index = input_given["txinIndex"].as_u64().unwrap() as usize;
            let hash_type_raw = input_given["hashType"].as_u64().unwrap() as u8;

            let expected_sighash = input_case["intermediary"]["sigHash"].as_str().unwrap();

            // Determine sighash type
            let sighash_type = if hash_type_raw == 0 {
                rbtc_crypto::sighash::SighashType::TaprootDefault
            } else {
                rbtc_crypto::sighash::SighashType::from_u32(hash_type_raw as u32)
                    .unwrap_or_else(|| panic!("unknown sighash type {hash_type_raw}"))
            };

            let got = sighash_taproot(
                &tx,
                input_index,
                &utxos_spent,
                sighash_type,
                None,     // no leaf hash (key path)
                None,     // no annex
                0,        // key_version = 0 for key path
                u32::MAX, // no code separator
            );

            let got_hex = hex::encode(got.0);
            total += 1;
            if got_hex != expected_sighash {
                failures.push(format!(
                    "[input {input_index}] hashType={hash_type_raw}: expected={expected_sighash} got={got_hex}"
                ));
            }
        }
    }

    if !failures.is_empty() {
        for f in &failures {
            eprintln!("  FAIL: {f}");
        }
        panic!(
            "{} / {total} bip341 keyPathSpending sighash cases failed",
            failures.len()
        );
    }

    println!("bip341 keyPathSpending: {total} sighash cases all passed");
}
