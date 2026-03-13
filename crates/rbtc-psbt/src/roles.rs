//! BIP174 PSBT roles: Creator, Updater, Signer, Combiner, Finalizer, Extractor.

use rbtc_primitives::{
    script::Script,
    transaction::{Transaction, TxIn, TxOut},
};

use crate::{
    error::{PsbtError, Result},
    types::{Psbt, PsbtGlobal, PsbtInput, PsbtOutput},
};

// ── Creator ───────────────────────────────────────────────────────────────────

impl Psbt {
    /// **Creator**: build a brand-new unsigned PSBT from a template transaction.
    ///
    /// All scriptSigs and witnesses in `tx` are cleared to produce the unsigned
    /// transaction stored in the PSBT global map.
    pub fn create(tx: Transaction) -> Self {
        let input_count = tx.inputs.len();
        let output_count = tx.outputs.len();

        // Strip any scriptSig / witness (the tx stored in PSBT must be unsigned)
        let inputs = tx
            .inputs
            .into_iter()
            .map(|inp| TxIn {
                previous_output: inp.previous_output,
                script_sig: Script::new(),
                sequence: inp.sequence,
                witness: vec![],
            })
            .collect();
        let unsigned_tx = Transaction::from_parts(tx.version, inputs, tx.outputs, tx.lock_time);

        Psbt {
            global: PsbtGlobal {
                unsigned_tx: Some(unsigned_tx),
                version: 0,
                tx_version: None,
                fallback_locktime: None,
                input_count: None,
                output_count: None,
                tx_modifiable: None,
                xpub: Default::default(),
                proprietary: Default::default(),
                unknown: Default::default(),
            },
            inputs: vec![PsbtInput::default(); input_count],
            outputs: vec![PsbtOutput::default(); output_count],
        }
    }
}

// ── Updater ───────────────────────────────────────────────────────────────────

impl Psbt {
    /// **Updater**: attach a full previous transaction for input `index`.
    ///
    /// Used for legacy (non-SegWit) inputs.  Script verification during signing
    /// requires the full prevout transaction.
    pub fn add_non_witness_utxo(&mut self, index: usize, tx: Transaction) -> Result<()> {
        let n = self.inputs.len();
        self.inputs
            .get_mut(index)
            .ok_or(PsbtError::InputCountMismatch { tx: n, psbt: n })?
            .non_witness_utxo = Some(tx);
        Ok(())
    }

    /// **Updater**: attach a specific TxOut for input `index`.
    ///
    /// Used for SegWit (P2WPKH / P2WSH) and Taproot inputs.
    pub fn add_witness_utxo(&mut self, index: usize, txout: TxOut) -> Result<()> {
        let n = self.inputs.len();
        self.inputs
            .get_mut(index)
            .ok_or(PsbtError::InputCountMismatch { tx: n, psbt: n })?
            .witness_utxo = Some(txout);
        Ok(())
    }

    /// **Updater**: set the sighash type for input `index`.
    pub fn set_sighash_type(&mut self, index: usize, sighash_type: u32) -> Result<()> {
        let n = self.inputs.len();
        self.inputs
            .get_mut(index)
            .ok_or(PsbtError::InputCountMismatch { tx: n, psbt: n })?
            .sighash_type = Some(sighash_type);
        Ok(())
    }
}

// ── BIP370 v2 input/output modification ──────────────────────────────────────

impl Psbt {
    /// **Updater (v2)**: add a new input to a PSBTv2.
    ///
    /// Requires `TX_MODIFIABLE` bit 0 (inputs modifiable) to be set.
    /// If `HAS_SIGHASH_SINGLE` (bit 2) is set, a corresponding output must
    /// also be added to keep inputs and outputs in sync.
    pub fn add_input_v2(&mut self, input: PsbtInput) -> Result<()> {
        if !self.inputs_modifiable() {
            return Err(PsbtError::InputsNotModifiable);
        }
        self.inputs.push(input);
        if let Some(ref mut ic) = self.global.input_count {
            *ic = self.inputs.len() as u64;
        }
        Ok(())
    }

    /// **Updater (v2)**: remove an input from a PSBTv2 by index.
    ///
    /// Requires `TX_MODIFIABLE` bit 0 (inputs modifiable) to be set.
    pub fn remove_input_v2(&mut self, index: usize) -> Result<()> {
        if !self.inputs_modifiable() {
            return Err(PsbtError::InputsNotModifiable);
        }
        if index >= self.inputs.len() {
            return Err(PsbtError::InputCountMismatch {
                tx: self.inputs.len(),
                psbt: index,
            });
        }
        self.inputs.remove(index);
        if let Some(ref mut ic) = self.global.input_count {
            *ic = self.inputs.len() as u64;
        }
        Ok(())
    }

    /// **Updater (v2)**: add a new output to a PSBTv2.
    ///
    /// Requires `TX_MODIFIABLE` bit 1 (outputs modifiable) to be set.
    pub fn add_output_v2(&mut self, output: PsbtOutput) -> Result<()> {
        if !self.outputs_modifiable() {
            return Err(PsbtError::OutputsNotModifiable);
        }
        self.outputs.push(output);
        if let Some(ref mut oc) = self.global.output_count {
            *oc = self.outputs.len() as u64;
        }
        Ok(())
    }

    /// **Updater (v2)**: remove an output from a PSBTv2 by index.
    ///
    /// Requires `TX_MODIFIABLE` bit 1 (outputs modifiable) to be set.
    pub fn remove_output_v2(&mut self, index: usize) -> Result<()> {
        if !self.outputs_modifiable() {
            return Err(PsbtError::OutputsNotModifiable);
        }
        if index >= self.outputs.len() {
            return Err(PsbtError::OutputCountMismatch {
                tx: self.outputs.len(),
                psbt: index,
            });
        }
        self.outputs.remove(index);
        if let Some(ref mut oc) = self.global.output_count {
            *oc = self.outputs.len() as u64;
        }
        Ok(())
    }
}

// ── Validation ───────────────────────────────────────────────────────────────

impl PsbtInput {
    /// Validate consistency between `non_witness_utxo` and `witness_utxo`.
    ///
    /// If both are present, verifies that the `witness_utxo` matches the
    /// output in `non_witness_utxo` at the spent outpoint index.
    /// This prevents the "Yin-Yang" attack where a PSBT provides a
    /// `witness_utxo` with a different amount than the actual prevout.
    pub fn validate_utxo_consistency(&self, spent_vout: u32) -> Result<()> {
        if let (Some(ref full_tx), Some(ref witness_out)) =
            (&self.non_witness_utxo, &self.witness_utxo)
        {
            let vout = spent_vout as usize;
            if vout >= full_tx.outputs.len() {
                return Err(PsbtError::Signing(format!(
                    "non_witness_utxo has {} outputs but spent vout is {}",
                    full_tx.outputs.len(),
                    vout
                )));
            }
            let actual = &full_tx.outputs[vout];
            if actual.value != witness_out.value
                || actual.script_pubkey.as_bytes() != witness_out.script_pubkey.as_bytes()
            {
                return Err(PsbtError::Signing(
                    "witness_utxo does not match the output in non_witness_utxo".into(),
                ));
            }
        }
        Ok(())
    }
}

impl Psbt {
    /// Validate UTXO consistency for all inputs.
    ///
    /// Checks that when both `non_witness_utxo` and `witness_utxo` are present
    /// for an input, they agree on the spent output's value and script.
    pub fn validate_utxo_consistency(&self) -> Result<()> {
        let tx = self.unsigned_tx().ok_or(PsbtError::MissingField("unsigned_tx"))?;
        for (i, inp) in self.inputs.iter().enumerate() {
            let vout = tx.inputs.get(i).map(|ti| ti.previous_output.vout).unwrap_or(0);
            inp.validate_utxo_consistency(vout)?;
        }
        Ok(())
    }
}

// ── Combiner ──────────────────────────────────────────────────────────────────

impl Psbt {
    /// **Combiner**: merge another PSBT's per-input and per-output data into this one.
    ///
    /// Both PSBTs must describe the same unsigned transaction (verified by txid).
    pub fn combine(&mut self, other: Psbt) -> Result<()> {
        // Verify both PSBTs describe the same transaction by comparing txids.
        let self_tx = self.unsigned_tx().ok_or(PsbtError::MissingField("unsigned_tx"))?;
        let other_tx = other.unsigned_tx().ok_or(PsbtError::MissingField("unsigned_tx"))?;
        if self_tx.txid() != other_tx.txid() {
            return Err(PsbtError::TransactionMismatch);
        }
        if self.inputs.len() != other.inputs.len() {
            return Err(PsbtError::InputCountMismatch {
                tx: self.inputs.len(),
                psbt: other.inputs.len(),
            });
        }
        for (dst, src) in self.inputs.iter_mut().zip(other.inputs.into_iter()) {
            if dst.non_witness_utxo.is_none() {
                dst.non_witness_utxo = src.non_witness_utxo;
            }
            if dst.witness_utxo.is_none() {
                dst.witness_utxo = src.witness_utxo;
            }
            for (pk, sig) in src.partial_sigs {
                dst.partial_sigs.entry(pk).or_insert(sig);
            }
            if dst.sighash_type.is_none() {
                dst.sighash_type = src.sighash_type;
            }
            if dst.redeem_script.is_none() {
                dst.redeem_script = src.redeem_script;
            }
            if dst.witness_script.is_none() {
                dst.witness_script = src.witness_script;
            }
            // BIP32 derivation paths (M28)
            for (k, v) in src.bip32_derivation {
                dst.bip32_derivation.entry(k).or_insert(v);
            }
            // Preimage maps (M27 — matches Bitcoin Core PSBTInput::Merge)
            for (k, v) in src.ripemd160_preimages {
                dst.ripemd160_preimages.entry(k).or_insert(v);
            }
            for (k, v) in src.sha256_preimages {
                dst.sha256_preimages.entry(k).or_insert(v);
            }
            for (k, v) in src.hash160_preimages {
                dst.hash160_preimages.entry(k).or_insert(v);
            }
            for (k, v) in src.hash256_preimages {
                dst.hash256_preimages.entry(k).or_insert(v);
            }
            if dst.final_script_sig.is_none() {
                dst.final_script_sig = src.final_script_sig;
            }
            if dst.final_script_witness.is_none() {
                dst.final_script_witness = src.final_script_witness;
            }
            // BIP371 taproot input fields
            if dst.tap_key_sig.is_none() {
                dst.tap_key_sig = src.tap_key_sig;
            }
            for (k, v) in src.tap_script_sig {
                dst.tap_script_sig.entry(k).or_insert(v);
            }
            for (k, v) in src.tap_leaf_script {
                dst.tap_leaf_script.entry(k).or_insert(v);
            }
            for (k, v) in src.tap_bip32_derivation {
                dst.tap_bip32_derivation.entry(k).or_insert(v);
            }
            if dst.tap_internal_key.is_none() {
                dst.tap_internal_key = src.tap_internal_key;
            }
            if dst.tap_merkle_root.is_none() {
                dst.tap_merkle_root = src.tap_merkle_root;
            }
            // BIP373 MuSig2 fields
            for (k, v) in src.musig2_participant_pubkeys {
                dst.musig2_participant_pubkeys.entry(k).or_insert(v);
            }
            for (k, v) in src.musig2_pub_nonce {
                dst.musig2_pub_nonce.entry(k).or_insert(v);
            }
            for (k, v) in src.musig2_partial_sig {
                dst.musig2_partial_sig.entry(k).or_insert(v);
            }
            for (k, v) in src.proprietary {
                dst.proprietary.entry(k).or_insert(v);
            }
            for (k, v) in src.unknown {
                dst.unknown.entry(k).or_insert(v);
            }
        }
        for (dst, src) in self.outputs.iter_mut().zip(other.outputs.into_iter()) {
            if dst.redeem_script.is_none() {
                dst.redeem_script = src.redeem_script;
            }
            if dst.witness_script.is_none() {
                dst.witness_script = src.witness_script;
            }
            // BIP32 derivation paths (M28 — matches Bitcoin Core PSBTOutput::Merge)
            for (k, v) in src.bip32_derivation {
                dst.bip32_derivation.entry(k).or_insert(v);
            }
            // BIP371 taproot output fields
            if dst.tap_internal_key.is_none() {
                dst.tap_internal_key = src.tap_internal_key;
            }
            if dst.tap_tree.is_none() {
                dst.tap_tree = src.tap_tree;
            }
            for (k, v) in src.tap_bip32_derivation {
                dst.tap_bip32_derivation.entry(k).or_insert(v);
            }
            for (k, v) in src.musig2_participant_pubkeys {
                dst.musig2_participant_pubkeys.entry(k).or_insert(v);
            }
            for (k, v) in src.proprietary {
                dst.proprietary.entry(k).or_insert(v);
            }
            for (k, v) in src.unknown {
                dst.unknown.entry(k).or_insert(v);
            }
        }
        // ── BIP370: merge global tx_modifiable flags ──────────────────────────
        // Bits 0-1 (inputs/outputs modifiable) are ANDed: only keep modifiable
        // if both PSBTs agree.  Bit 2 (has SIGHASH_SINGLE) is ORed: once any
        // signer has used SIGHASH_SINGLE, it stays set.
        use crate::types::{PSBT_TXMOD_HAS_SIGHASH_SINGLE, PSBT_TXMOD_INPUTS, PSBT_TXMOD_OUTPUTS};
        match (self.global.tx_modifiable, other.global.tx_modifiable) {
            (Some(a), Some(b)) => {
                let io_mask = PSBT_TXMOD_INPUTS | PSBT_TXMOD_OUTPUTS;
                let merged = (a & b & io_mask)
                    | ((a | b) & PSBT_TXMOD_HAS_SIGHASH_SINGLE);
                self.global.tx_modifiable = Some(merged);
            }
            (None, Some(b)) => {
                self.global.tx_modifiable = Some(b);
            }
            _ => {} // keep self's value (or None)
        }
        // Merge global xpub entries
        for (k, v) in other.global.xpub {
            self.global.xpub.entry(k).or_insert(v);
        }
        for (k, v) in other.global.proprietary {
            self.global.proprietary.entry(k).or_insert(v);
        }
        for (k, v) in other.global.unknown {
            self.global.unknown.entry(k).or_insert(v);
        }
        Ok(())
    }
}

// ── Finalizer ─────────────────────────────────────────────────────────────────

/// Parse an M-of-N bare multisig script and return `(M, pubkeys)`.
///
/// Expected format: `OP_M <pubkey1> <pubkey2> ... <pubkeyN> OP_N OP_CHECKMULTISIG`
///
/// OP_1..OP_16 encode as 0x51..0x60.  Public keys are either 33 (compressed)
/// or 65 (uncompressed) bytes, pushed with a single-byte length prefix.
pub fn extract_multisig_params(script: &[u8]) -> Option<(usize, Vec<Vec<u8>>)> {
    if script.is_empty() {
        return None;
    }
    // Last byte must be OP_CHECKMULTISIG (0xae) or OP_CHECKMULTISIGVERIFY (0xaf)
    let last = *script.last()?;
    if last != 0xae && last != 0xaf {
        return None;
    }

    let mut i = 0;
    // OP_M (OP_1 = 0x51 .. OP_16 = 0x60)
    let op_m = script[i];
    if !(0x51..=0x60).contains(&op_m) {
        return None;
    }
    let m = (op_m - 0x50) as usize;
    i += 1;

    // Collect pubkeys
    let mut pubkeys = Vec::new();
    while i < script.len() {
        let op = script[i];
        // A push-data byte of 33 or 65 (compressed / uncompressed pubkey)
        if op == 0x21 || op == 0x41 {
            let len = op as usize;
            i += 1;
            if i + len > script.len() {
                return None;
            }
            pubkeys.push(script[i..i + len].to_vec());
            i += len;
        } else {
            break;
        }
    }

    // OP_N
    if i >= script.len() {
        return None;
    }
    let op_n = script[i];
    if !(0x51..=0x60).contains(&op_n) {
        return None;
    }
    let n = (op_n - 0x50) as usize;
    i += 1;

    // OP_CHECKMULTISIG
    if i + 1 != script.len() {
        return None;
    }

    if pubkeys.len() != n || m > n {
        return None;
    }

    Some((m, pubkeys))
}

/// Collect exactly `m` partial signatures, ordered by the pubkey order in the
/// given multisig script.  Returns `None` if fewer than `m` sigs are available.
fn collect_ordered_sigs(
    partial_sigs: &std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
    script_pubkeys: &[Vec<u8>],
    m: usize,
) -> Option<Vec<Vec<u8>>> {
    let mut sigs = Vec::new();
    for pk in script_pubkeys {
        if let Some(sig) = partial_sigs.get(pk) {
            sigs.push(sig.clone());
        }
        if sigs.len() == m {
            break;
        }
    }
    if sigs.len() == m {
        Some(sigs)
    } else {
        None
    }
}

/// Build a script that pushes a single data item with the proper length prefix.
fn script_push(data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + data.len());
    let len = data.len();
    if len < 0x4c {
        buf.push(len as u8);
    } else if len <= 0xff {
        buf.push(0x4c); // OP_PUSHDATA1
        buf.push(len as u8);
    } else {
        buf.push(0x4d); // OP_PUSHDATA2
        buf.push((len & 0xff) as u8);
        buf.push(((len >> 8) & 0xff) as u8);
    }
    buf.extend_from_slice(data);
    buf
}

/// Clear all signing-time metadata from a PSBT input after finalization.
///
/// As per BIP174 and Bitcoin Core behavior, clears:
/// - partial_sigs, bip32_derivation, redeem_script, witness_script, sighash_type
/// - non_witness_utxo, witness_utxo
/// - All BIP371 taproot fields (tap_key_sig, tap_script_sig, tap_leaf_script,
///   tap_bip32_derivation, tap_internal_key, tap_merkle_root)
/// - Preimage fields (ripemd160, sha256, hash160, hash256)
fn clear_signing_metadata(inp: &mut PsbtInput) {
    inp.partial_sigs.clear();
    inp.sighash_type = None;
    inp.redeem_script = None;
    inp.witness_script = None;
    inp.bip32_derivation.clear();
    inp.non_witness_utxo = None;
    inp.witness_utxo = None;
    // BIP371 Taproot fields
    inp.tap_key_sig = None;
    inp.tap_script_sig.clear();
    inp.tap_leaf_script.clear();
    inp.tap_bip32_derivation.clear();
    inp.tap_internal_key = None;
    inp.tap_merkle_root = None;
    // Preimage fields
    inp.ripemd160_preimages.clear();
    inp.sha256_preimages.clear();
    inp.hash160_preimages.clear();
    inp.hash256_preimages.clear();
}

impl Psbt {
    /// **Finalizer**: move partial signatures into `final_script_sig` /
    /// `final_script_witness` and clear signing-time metadata.
    ///
    /// Supports:
    /// - P2TR key-path (Taproot key-path spend via `tap_key_sig`)
    /// - P2TR script-path (Taproot script-path spend via `tap_script_sig` + `tap_leaf_script`)
    /// - P2WPKH (single-sig SegWit v0)
    /// - P2PKH (single-sig legacy)
    /// - P2SH multisig (bare multisig inside P2SH)
    /// - P2WSH multisig (bare multisig inside P2WSH, optionally wrapped in P2SH)
    /// - P2SH-P2WPKH (single-sig SegWit wrapped in P2SH)
    pub fn finalize(&mut self) -> Result<()> {
        for inp in &mut self.inputs {
            if inp.is_finalized() {
                continue;
            }

            // ── P2TR key-path: tap_key_sig present ──────────────────────────
            if let Some(ref sig) = inp.tap_key_sig.clone() {
                inp.final_script_witness = Some(vec![sig.clone()]);
                clear_signing_metadata(inp);
                continue;
            }

            // ── P2TR script-path: tap_script_sig + tap_leaf_script present ──
            // Match signatures to leaf scripts by computing the BIP341 leaf hash
            // and looking it up in tap_script_sig (keyed by xonly_pubkey || leaf_hash).
            if !inp.tap_script_sig.is_empty() && !inp.tap_leaf_script.is_empty() {
                let mut finalized = false;
                for (control_block, (leaf_script, leaf_version)) in &inp.tap_leaf_script {
                    let lh = rbtc_crypto::tap_leaf_hash(*leaf_version, leaf_script);
                    // Find a tap_script_sig entry whose leaf_hash (bytes 32..64) matches.
                    for (composite_key, sig) in &inp.tap_script_sig {
                        if composite_key.len() == 64 && composite_key[32..] == lh.0 {
                            // Witness stack for script-path spend: [sig, script, control_block]
                            inp.final_script_witness = Some(vec![
                                sig.clone(),
                                leaf_script.clone(),
                                control_block.clone(),
                            ]);
                            finalized = true;
                            break;
                        }
                    }
                    if finalized {
                        break;
                    }
                }
                if finalized {
                    clear_signing_metadata(inp);
                    continue;
                }
            }

            // ── P2SH-P2WPKH: redeem_script is a witness program (0x0014...) ─
            if let Some(ref rs) = inp.redeem_script {
                if rs.is_p2wpkh() && inp.witness_script.is_none() && inp.partial_sigs.len() == 1 {
                    let (pk, sig) = inp.partial_sigs.iter().next().unwrap();
                    // Witness: [sig, pubkey]
                    inp.final_script_witness = Some(vec![sig.clone(), pk.clone()]);
                    // scriptSig: push the redeem script
                    let rs_bytes = rs.as_bytes();
                    inp.final_script_sig = Some(Script::from_bytes(script_push(rs_bytes)));
                    clear_signing_metadata(inp);
                    continue;
                }
            }

            // ── P2WSH multisig: witness_script contains OP_CHECKMULTISIG ────
            if let Some(ref ws) = inp.witness_script.clone() {
                if let Some((m, pubkeys)) = extract_multisig_params(ws.as_bytes()) {
                    if let Some(sigs) = collect_ordered_sigs(&inp.partial_sigs, &pubkeys, m) {
                        // Build witness stack: [OP_0_dummy, sig1, ..., sigM, witness_script]
                        let mut witness: Vec<Vec<u8>> = Vec::with_capacity(m + 2);
                        witness.push(vec![]); // OP_0 dummy for CHECKMULTISIG bug
                        for sig in sigs {
                            witness.push(sig);
                        }
                        witness.push(ws.as_bytes().to_vec());
                        inp.final_script_witness = Some(witness);

                        // If wrapped in P2SH (redeem_script present), set scriptSig
                        // to push the witness program (the redeem_script).
                        if let Some(ref rs) = inp.redeem_script {
                            inp.final_script_sig =
                                Some(Script::from_bytes(script_push(rs.as_bytes())));
                        }

                        clear_signing_metadata(inp);
                        continue;
                    }
                }
            }

            // ── P2SH multisig: redeem_script contains OP_CHECKMULTISIG ──────
            if let Some(ref rs) = inp.redeem_script.clone() {
                if inp.witness_script.is_none() {
                    if let Some((m, pubkeys)) = extract_multisig_params(rs.as_bytes()) {
                        if let Some(sigs) = collect_ordered_sigs(&inp.partial_sigs, &pubkeys, m) {
                            // scriptSig: OP_0 <sig1> <sig2> ... <sigM> <redeem_script>
                            let mut script_sig = Vec::new();
                            script_sig.push(0x00); // OP_0 dummy
                            for sig in sigs {
                                script_sig.extend_from_slice(&script_push(&sig));
                            }
                            script_sig.extend_from_slice(&script_push(rs.as_bytes()));
                            inp.final_script_sig = Some(Script::from_bytes(script_sig));
                            clear_signing_metadata(inp);
                            continue;
                        }
                    }
                }
            }

            // ── P2WPKH: witness_utxo present, exactly one partial sig ───────
            if inp.witness_utxo.is_some() && inp.partial_sigs.len() == 1 {
                let (pk, sig) = inp.partial_sigs.iter().next().unwrap();
                inp.final_script_witness = Some(vec![sig.clone(), pk.clone()]);
                clear_signing_metadata(inp);
                continue;
            }
            // ── P2PKH: non_witness_utxo present, exactly one partial sig ────
            if inp.non_witness_utxo.is_some() && inp.partial_sigs.len() == 1 {
                let (pk, sig) = inp.partial_sigs.iter().next().unwrap();
                let mut script = Vec::new();
                // <sig_push>
                script.push(sig.len() as u8);
                script.extend_from_slice(sig);
                // <pk_push>
                script.push(pk.len() as u8);
                script.extend_from_slice(pk);
                inp.final_script_sig = Some(Script::from_bytes(script));
                clear_signing_metadata(inp);
                continue;
            }
        }
        Ok(())
    }
}

// ── Extractor ─────────────────────────────────────────────────────────────────

impl Psbt {
    /// **Extractor**: produce the final signed `Transaction`.
    ///
    /// Fails if any input has not been finalized.
    pub fn extract_tx(mut self) -> Result<Transaction> {
        for inp in &self.inputs {
            if !inp.is_finalized() {
                return Err(PsbtError::NotFullySigned);
            }
        }

        let mut tx = self.unsigned_tx().ok_or(PsbtError::MissingField("unsigned_tx"))?;
        for (tx_in, psbt_in) in tx.inputs.iter_mut().zip(self.inputs.iter_mut()) {
            if let Some(sig) = psbt_in.final_script_sig.take() {
                tx_in.script_sig = sig;
            }
            if let Some(witness) = psbt_in.final_script_witness.take() {
                tx_in.witness = witness;
            }
        }

        Ok(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::{
        hash::{Hash256, Txid},
        transaction::{OutPoint, TxIn},
    };

    fn simple_tx() -> Transaction {
        Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid(Hash256([0xaa; 32])),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut {
                value: 10_000,
                script_pubkey: Script::new(),
            }],
            0,
        )
    }

    #[test]
    fn creator_strips_witnesses() {
        let tx = Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid(Hash256::ZERO),
                    vout: 0,
                },
                script_sig: Script::from_bytes(vec![1, 2, 3]),
                sequence: 0,
                witness: vec![vec![4, 5]],
            }],
            vec![TxOut {
                value: 0,
                script_pubkey: Script::new(),
            }],
            0,
        );
        let psbt = Psbt::create(tx);
        let utx = psbt.global.unsigned_tx.as_ref().unwrap();
        assert!(utx.inputs[0].script_sig.is_empty());
        assert!(utx.inputs[0].witness.is_empty());
    }

    #[test]
    fn combiner_rejects_tx_mismatch() {
        let tx_a = simple_tx();
        // Build a different transaction (different locktime → different txid)
        let tx_b = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid(Hash256([0xbb; 32])),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut {
                value: 10_000,
                script_pubkey: Script::new(),
            }],
            0,
        );
        let mut a = Psbt::create(tx_a);
        let b = Psbt::create(tx_b);
        let err = a.combine(b).unwrap_err();
        assert!(
            matches!(err, PsbtError::TransactionMismatch),
            "expected TransactionMismatch, got: {err}"
        );
    }

    #[test]
    fn utxo_consistency_passes_when_matching() {
        let tx = simple_tx();
        let mut psbt = Psbt::create(tx);
        let witness_out = TxOut {
            value: 50_000,
            script_pubkey: Script::from_bytes(vec![0x00, 0x14, 0xaa, 0xbb, 0xcc, 0xdd]),
        };
        // Set both non_witness_utxo and matching witness_utxo
        let prev_tx = Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint { txid: Txid(Hash256([0x00; 32])), vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![witness_out.clone()], // output at vout=0
            0,
        );
        psbt.inputs[0].non_witness_utxo = Some(prev_tx);
        psbt.inputs[0].witness_utxo = Some(witness_out);
        psbt.inputs[0].validate_utxo_consistency(0).unwrap();
    }

    #[test]
    fn utxo_consistency_fails_when_mismatched() {
        let tx = simple_tx();
        let mut psbt = Psbt::create(tx);
        let prev_tx = Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint { txid: Txid(Hash256([0x00; 32])), vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut { value: 50_000, script_pubkey: Script::new() }],
            0,
        );
        // witness_utxo has different value (Yin-Yang attack simulation)
        let witness_out = TxOut { value: 1_000, script_pubkey: Script::new() };
        psbt.inputs[0].non_witness_utxo = Some(prev_tx);
        psbt.inputs[0].witness_utxo = Some(witness_out);
        assert!(psbt.inputs[0].validate_utxo_consistency(0).is_err());
    }

    #[test]
    fn utxo_consistency_ok_when_only_one_set() {
        let tx = simple_tx();
        let mut psbt = Psbt::create(tx);
        // Only witness_utxo set — no conflict possible
        psbt.inputs[0].witness_utxo = Some(TxOut { value: 50_000, script_pubkey: Script::new() });
        psbt.inputs[0].validate_utxo_consistency(0).unwrap();
        // Only non_witness_utxo set
        psbt.inputs[0].witness_utxo = None;
        psbt.inputs[0].non_witness_utxo = Some(simple_tx());
        psbt.inputs[0].validate_utxo_consistency(0).unwrap();
    }

    #[test]
    fn combiner_merges_partial_sigs() {
        let tx = simple_tx();
        let mut a = Psbt::create(tx.clone());
        let mut b = Psbt::create(tx);

        a.inputs[0].partial_sigs.insert(vec![0x01], vec![0xaa]);
        b.inputs[0].partial_sigs.insert(vec![0x02], vec![0xbb]);

        a.combine(b).unwrap();
        assert_eq!(a.inputs[0].partial_sigs.len(), 2);
    }

    #[test]
    fn extract_tx_fails_without_finalize() {
        let psbt = Psbt::create(simple_tx());
        assert!(psbt.extract_tx().is_err());
    }

    /// Build a 2-of-3 bare multisig script:
    /// OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG
    fn make_2of3_multisig_script(pk1: &[u8], pk2: &[u8], pk3: &[u8]) -> Vec<u8> {
        let mut s = vec![0x52]; // OP_2
        for pk in &[pk1, pk2, pk3] {
            s.push(pk.len() as u8); // push length (0x21 for 33-byte compressed)
            s.extend_from_slice(pk);
        }
        s.push(0x53); // OP_3
        s.push(0xae); // OP_CHECKMULTISIG
        s
    }

    /// Fake 33-byte compressed pubkey starting with 0x02
    fn fake_pubkey(seed: u8) -> Vec<u8> {
        let mut pk = vec![0x02];
        pk.extend_from_slice(&[seed; 32]);
        pk
    }

    #[test]
    fn extract_multisig_params_basic() {
        let pk1 = fake_pubkey(0x01);
        let pk2 = fake_pubkey(0x02);
        let pk3 = fake_pubkey(0x03);
        let script = make_2of3_multisig_script(&pk1, &pk2, &pk3);
        let (m, pubkeys) = super::extract_multisig_params(&script).unwrap();
        assert_eq!(m, 2);
        assert_eq!(pubkeys.len(), 3);
        assert_eq!(pubkeys[0], pk1);
        assert_eq!(pubkeys[1], pk2);
        assert_eq!(pubkeys[2], pk3);
    }

    #[test]
    fn extract_multisig_params_rejects_non_multisig() {
        assert!(super::extract_multisig_params(&[]).is_none());
        assert!(super::extract_multisig_params(&[0x76, 0xa9]).is_none());
        assert!(super::extract_multisig_params(&[0xae]).is_none());
    }

    #[test]
    fn finalize_p2wsh_2of3_multisig() {
        let pk1 = fake_pubkey(0x01);
        let pk2 = fake_pubkey(0x02);
        let pk3 = fake_pubkey(0x03);
        let witness_script_bytes = make_2of3_multisig_script(&pk1, &pk2, &pk3);

        let tx = simple_tx();
        let mut psbt = Psbt::create(tx);

        let inp = &mut psbt.inputs[0];
        inp.witness_utxo = Some(TxOut {
            value: 50_000,
            script_pubkey: Script::new(),
        });
        inp.witness_script = Some(Script::from_bytes(witness_script_bytes.clone()));
        // Add 2 partial sigs (for pk1 and pk3, skipping pk2)
        let sig1: Vec<u8> = std::iter::once(0x30).chain(std::iter::repeat(0xaa).take(70)).collect();
        let sig3: Vec<u8> = std::iter::once(0x30).chain(std::iter::repeat(0xcc).take(70)).collect();
        inp.partial_sigs.insert(pk1.clone(), sig1.clone());
        inp.partial_sigs.insert(pk3.clone(), sig3.clone());

        psbt.finalize().unwrap();

        let inp = &psbt.inputs[0];
        assert!(inp.final_script_witness.is_some());
        let witness = inp.final_script_witness.as_ref().unwrap();
        // witness = [OP_0_dummy, sig1, sig3, witness_script]
        assert_eq!(witness.len(), 4);
        assert_eq!(witness[0], Vec::<u8>::new()); // OP_0 dummy
        assert_eq!(witness[1], sig1);
        assert_eq!(witness[2], sig3);
        assert_eq!(witness[3], witness_script_bytes);

        // Signing metadata should be cleared
        assert!(inp.partial_sigs.is_empty());
        assert!(inp.sighash_type.is_none());
        assert!(inp.witness_script.is_none());
        assert!(inp.witness_utxo.is_none());
    }

    #[test]
    fn finalize_p2sh_p2wpkh() {
        let tx = simple_tx();
        let mut psbt = Psbt::create(tx);

        let pk = fake_pubkey(0x42);
        let sig = vec![0x30, 0x45, 0xaa, 0xbb];

        // Build a P2WPKH redeem script: OP_0 <20-byte-hash>
        let mut rs_bytes = vec![0x00, 0x14];
        rs_bytes.extend_from_slice(&[0x99; 20]);
        let redeem_script = Script::from_bytes(rs_bytes.clone());
        assert!(redeem_script.is_p2wpkh());

        let inp = &mut psbt.inputs[0];
        inp.witness_utxo = Some(TxOut {
            value: 10_000,
            script_pubkey: Script::new(),
        });
        inp.redeem_script = Some(redeem_script);
        inp.partial_sigs.insert(pk.clone(), sig.clone());

        psbt.finalize().unwrap();

        let inp = &psbt.inputs[0];

        // Should have witness [sig, pubkey]
        let witness = inp.final_script_witness.as_ref().unwrap();
        assert_eq!(witness.len(), 2);
        assert_eq!(witness[0], sig);
        assert_eq!(witness[1], pk);

        // Should have scriptSig that pushes the redeem script
        let script_sig = inp.final_script_sig.as_ref().unwrap();
        let script_sig_bytes = script_sig.as_bytes();
        assert_eq!(script_sig_bytes[0] as usize, rs_bytes.len());
        assert_eq!(&script_sig_bytes[1..], &rs_bytes[..]);

        // Signing metadata cleared
        assert!(inp.partial_sigs.is_empty());
        assert!(inp.redeem_script.is_none());
    }

    #[test]
    fn finalize_p2sh_multisig() {
        let pk1 = fake_pubkey(0x01);
        let pk2 = fake_pubkey(0x02);
        let pk3 = fake_pubkey(0x03);
        let redeem_script_bytes = make_2of3_multisig_script(&pk1, &pk2, &pk3);

        let tx = simple_tx();
        let mut psbt = Psbt::create(tx);

        let inp = &mut psbt.inputs[0];
        inp.non_witness_utxo = Some(simple_tx());
        inp.redeem_script = Some(Script::from_bytes(redeem_script_bytes.clone()));

        let sig1 = vec![0x30, 0x44, 0xaa];
        let sig2 = vec![0x30, 0x44, 0xbb];
        inp.partial_sigs.insert(pk1.clone(), sig1.clone());
        inp.partial_sigs.insert(pk2.clone(), sig2.clone());

        psbt.finalize().unwrap();

        let inp = &psbt.inputs[0];
        assert!(inp.final_script_sig.is_some());
        assert!(inp.final_script_witness.is_none());

        let script_sig = inp.final_script_sig.as_ref().unwrap().as_bytes().to_vec();
        // Should start with OP_0
        assert_eq!(script_sig[0], 0x00);

        // Signing metadata cleared
        assert!(inp.partial_sigs.is_empty());
        assert!(inp.redeem_script.is_none());
    }

    #[test]
    fn finalize_p2tr_key_path() {
        let tx = simple_tx();
        let mut psbt = Psbt::create(tx);

        // 64-byte Schnorr signature (no sighash suffix => SIGHASH_DEFAULT)
        let schnorr_sig: Vec<u8> = (0..64).collect();

        let inp = &mut psbt.inputs[0];
        inp.witness_utxo = Some(TxOut {
            value: 50_000,
            script_pubkey: Script::new(),
        });
        inp.tap_key_sig = Some(schnorr_sig.clone());
        inp.tap_internal_key = Some(vec![0x02; 32]);
        inp.tap_merkle_root = Some(vec![0xab; 32]);

        psbt.finalize().unwrap();

        let inp = &psbt.inputs[0];
        // Witness should be exactly [signature]
        let witness = inp.final_script_witness.as_ref().unwrap();
        assert_eq!(witness.len(), 1);
        assert_eq!(witness[0], schnorr_sig);

        // All tap signing metadata should be cleared
        assert!(inp.tap_key_sig.is_none());
        assert!(inp.tap_internal_key.is_none());
        assert!(inp.tap_merkle_root.is_none());
        assert!(inp.tap_script_sig.is_empty());
        assert!(inp.tap_leaf_script.is_empty());
        assert!(inp.tap_bip32_derivation.is_empty());
        assert!(inp.witness_utxo.is_none());
    }

    #[test]
    fn finalize_p2tr_key_path_65_byte_sig() {
        let tx = simple_tx();
        let mut psbt = Psbt::create(tx);

        // 65-byte Schnorr signature (with explicit sighash type byte)
        let schnorr_sig: Vec<u8> = (0..65).collect();

        let inp = &mut psbt.inputs[0];
        inp.witness_utxo = Some(TxOut {
            value: 50_000,
            script_pubkey: Script::new(),
        });
        inp.tap_key_sig = Some(schnorr_sig.clone());

        psbt.finalize().unwrap();

        let inp = &psbt.inputs[0];
        let witness = inp.final_script_witness.as_ref().unwrap();
        assert_eq!(witness.len(), 1);
        assert_eq!(witness[0], schnorr_sig);
        assert!(inp.tap_key_sig.is_none());
    }

    #[test]
    fn finalize_p2tr_script_path() {
        let tx = simple_tx();
        let mut psbt = Psbt::create(tx);

        // Fake leaf script (e.g. OP_CHECKSIG)
        let leaf_script = vec![0xac]; // OP_CHECKSIG
        let leaf_version: u8 = 0xc0;
        // Fake control block: leaf_version | internal_key(32) (33 bytes minimum)
        let mut control_block = vec![leaf_version];
        control_block.extend_from_slice(&[0x02; 32]); // internal key

        // Compute the real BIP341 leaf hash for correct matching
        let leaf_hash = rbtc_crypto::tap_leaf_hash(leaf_version, &leaf_script);
        let mut composite_key = vec![0x03; 32]; // x-only pubkey
        composite_key.extend_from_slice(&leaf_hash.0);

        // 64-byte Schnorr signature
        let schnorr_sig: Vec<u8> = (0..64).collect();

        let inp = &mut psbt.inputs[0];
        inp.witness_utxo = Some(TxOut {
            value: 50_000,
            script_pubkey: Script::new(),
        });
        inp.tap_script_sig.insert(composite_key, schnorr_sig.clone());
        inp.tap_leaf_script
            .insert(control_block.clone(), (leaf_script.clone(), leaf_version));
        inp.tap_internal_key = Some(vec![0x02; 32]);

        psbt.finalize().unwrap();

        let inp = &psbt.inputs[0];
        // Witness should be [sig, script, control_block]
        let witness = inp.final_script_witness.as_ref().unwrap();
        assert_eq!(witness.len(), 3);
        assert_eq!(witness[0], schnorr_sig);
        assert_eq!(witness[1], leaf_script);
        assert_eq!(witness[2], control_block);

        // All tap signing metadata should be cleared
        assert!(inp.tap_key_sig.is_none());
        assert!(inp.tap_internal_key.is_none());
        assert!(inp.tap_merkle_root.is_none());
        assert!(inp.tap_script_sig.is_empty());
        assert!(inp.tap_leaf_script.is_empty());
        assert!(inp.tap_bip32_derivation.is_empty());
        assert!(inp.witness_utxo.is_none());
    }

    #[test]
    fn finalize_p2tr_key_path_already_finalized_is_noop() {
        let tx = simple_tx();
        let mut psbt = Psbt::create(tx);

        let schnorr_sig: Vec<u8> = (0..64).collect();
        let inp = &mut psbt.inputs[0];
        inp.tap_key_sig = Some(schnorr_sig.clone());

        psbt.finalize().unwrap();

        // Finalize again -- should be a no-op since already finalized
        let sig_before = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .unwrap()
            .clone();
        psbt.finalize().unwrap();
        assert_eq!(
            psbt.inputs[0].final_script_witness.as_ref().unwrap(),
            &sig_before
        );
    }

    #[test]
    fn finalize_p2tr_extract_tx() {
        let tx = simple_tx();
        let mut psbt = Psbt::create(tx);

        let schnorr_sig: Vec<u8> = (0..64).collect();
        psbt.inputs[0].tap_key_sig = Some(schnorr_sig.clone());

        psbt.finalize().unwrap();
        let final_tx = psbt.extract_tx().unwrap();
        assert_eq!(final_tx.inputs[0].witness.len(), 1);
        assert_eq!(final_tx.inputs[0].witness[0], schnorr_sig);
    }

    #[test]
    fn finalize_clears_all_tap_and_signing_fields() {
        let tx = simple_tx();
        let mut psbt = Psbt::create(tx);

        let inp = &mut psbt.inputs[0];
        // Set up a taproot key-path spend
        let schnorr_sig: Vec<u8> = (0..64).collect();
        inp.tap_key_sig = Some(schnorr_sig);
        inp.tap_internal_key = Some(vec![0x02; 32]);
        inp.tap_merkle_root = Some(vec![0xab; 32]);
        inp.tap_script_sig.insert(vec![0x01; 64], vec![0xff; 64]);
        inp.tap_leaf_script.insert(vec![0xc0; 33], (vec![0xac], 0xc0));
        inp.tap_bip32_derivation.insert(
            vec![0x02; 32],
            ([vec![0xee; 32]].into_iter().collect(), vec![0xDE, 0xAD, 0xBE, 0xEF], vec![0]),
        );
        // Also set fields that Bitcoin Core clears
        inp.partial_sigs.insert(vec![0x02; 33], vec![0x30; 72]);
        inp.bip32_derivation.insert(
            vec![0x02; 33],
            (vec![0xAA, 0xBB, 0xCC, 0xDD], vec![44, 0, 0]),
        );
        inp.redeem_script = Some(Script::from_bytes(vec![0x51]));
        inp.witness_script = Some(Script::from_bytes(vec![0x52]));
        inp.sighash_type = Some(1);
        inp.witness_utxo = Some(TxOut {
            value: 50_000,
            script_pubkey: Script::new(),
        });
        // Set preimage fields
        inp.ripemd160_preimages.insert(vec![0x11; 20], vec![0x01]);
        inp.sha256_preimages.insert(vec![0x22; 32], vec![0x02]);
        inp.hash160_preimages.insert(vec![0x33; 20], vec![0x03]);
        inp.hash256_preimages.insert(vec![0x44; 32], vec![0x04]);

        psbt.finalize().unwrap();

        let inp = &psbt.inputs[0];
        // Verify finalization produced a witness
        assert!(inp.final_script_witness.is_some());

        // All taproot fields must be cleared
        assert!(inp.tap_key_sig.is_none(), "tap_key_sig not cleared");
        assert!(inp.tap_script_sig.is_empty(), "tap_script_sig not cleared");
        assert!(inp.tap_leaf_script.is_empty(), "tap_leaf_script not cleared");
        assert!(inp.tap_bip32_derivation.is_empty(), "tap_bip32_derivation not cleared");
        assert!(inp.tap_internal_key.is_none(), "tap_internal_key not cleared");
        assert!(inp.tap_merkle_root.is_none(), "tap_merkle_root not cleared");

        // Standard signing metadata must be cleared
        assert!(inp.partial_sigs.is_empty(), "partial_sigs not cleared");
        assert!(inp.bip32_derivation.is_empty(), "bip32_derivation not cleared");
        assert!(inp.redeem_script.is_none(), "redeem_script not cleared");
        assert!(inp.witness_script.is_none(), "witness_script not cleared");
        assert!(inp.sighash_type.is_none(), "sighash_type not cleared");

        // Preimage fields must be cleared
        assert!(inp.ripemd160_preimages.is_empty(), "ripemd160_preimages not cleared");
        assert!(inp.sha256_preimages.is_empty(), "sha256_preimages not cleared");
        assert!(inp.hash160_preimages.is_empty(), "hash160_preimages not cleared");
        assert!(inp.hash256_preimages.is_empty(), "hash256_preimages not cleared");
    }

    // ── BIP370 v2 TX_MODIFIABLE tests ──────────────────────────────────────

    use crate::types::{PSBT_TXMOD_INPUTS, PSBT_TXMOD_OUTPUTS, PSBT_TXMOD_HAS_SIGHASH_SINGLE};

    fn make_v2_psbt() -> Psbt {
        use rbtc_primitives::hash::Txid;
        Psbt {
            global: PsbtGlobal {
                unsigned_tx: None,
                version: 2,
                tx_version: Some(2),
                fallback_locktime: Some(0),
                input_count: Some(1),
                output_count: Some(1),
                tx_modifiable: Some(PSBT_TXMOD_INPUTS | PSBT_TXMOD_OUTPUTS),
                xpub: Default::default(),
                proprietary: Default::default(),
                unknown: Default::default(),
            },
            inputs: vec![PsbtInput {
                previous_txid: Some(Txid(Hash256([0xaa; 32]))),
                output_index: Some(0),
                sequence: Some(0xffffffff),
                ..PsbtInput::default()
            }],
            outputs: vec![PsbtOutput {
                amount: Some(10_000),
                script: Some(Script::new()),
                ..PsbtOutput::default()
            }],
        }
    }

    #[test]
    fn v2_modifiable_flag_helpers() {
        let mut psbt = make_v2_psbt();
        assert!(psbt.inputs_modifiable());
        assert!(psbt.outputs_modifiable());
        assert!(!psbt.has_sighash_single());

        psbt.set_tx_modifiable(PSBT_TXMOD_HAS_SIGHASH_SINGLE);
        assert!(!psbt.inputs_modifiable());
        assert!(!psbt.outputs_modifiable());
        assert!(psbt.has_sighash_single());
    }

    #[test]
    fn v2_add_input_respects_modifiable() {
        let mut psbt = make_v2_psbt();
        // With INPUTS flag set, adding should succeed
        let new_inp = PsbtInput {
            previous_txid: Some(rbtc_primitives::hash::Txid(Hash256([0xbb; 32]))),
            output_index: Some(1),
            sequence: Some(0xffffffff),
            ..PsbtInput::default()
        };
        psbt.add_input_v2(new_inp).unwrap();
        assert_eq!(psbt.inputs.len(), 2);
        assert_eq!(psbt.global.input_count, Some(2));
    }

    #[test]
    fn v2_add_input_rejected_when_not_modifiable() {
        let mut psbt = make_v2_psbt();
        psbt.global.tx_modifiable = Some(PSBT_TXMOD_OUTPUTS); // only outputs modifiable
        let err = psbt.add_input_v2(PsbtInput::default()).unwrap_err();
        assert!(matches!(err, PsbtError::InputsNotModifiable));
    }

    #[test]
    fn v2_add_output_respects_modifiable() {
        let mut psbt = make_v2_psbt();
        let new_out = PsbtOutput {
            amount: Some(5_000),
            script: Some(Script::new()),
            ..PsbtOutput::default()
        };
        psbt.add_output_v2(new_out).unwrap();
        assert_eq!(psbt.outputs.len(), 2);
        assert_eq!(psbt.global.output_count, Some(2));
    }

    #[test]
    fn v2_add_output_rejected_when_not_modifiable() {
        let mut psbt = make_v2_psbt();
        psbt.global.tx_modifiable = Some(PSBT_TXMOD_INPUTS); // only inputs modifiable
        let err = psbt.add_output_v2(PsbtOutput::default()).unwrap_err();
        assert!(matches!(err, PsbtError::OutputsNotModifiable));
    }

    #[test]
    fn v2_remove_input() {
        let mut psbt = make_v2_psbt();
        psbt.remove_input_v2(0).unwrap();
        assert!(psbt.inputs.is_empty());
        assert_eq!(psbt.global.input_count, Some(0));
    }

    #[test]
    fn v2_remove_output() {
        let mut psbt = make_v2_psbt();
        psbt.remove_output_v2(0).unwrap();
        assert!(psbt.outputs.is_empty());
        assert_eq!(psbt.global.output_count, Some(0));
    }

    #[test]
    fn v2_remove_input_out_of_range() {
        let mut psbt = make_v2_psbt();
        let err = psbt.remove_input_v2(5).unwrap_err();
        assert!(matches!(err, PsbtError::InputCountMismatch { .. }));
    }

    #[test]
    fn v2_modifiable_none_disallows_modification() {
        let mut psbt = make_v2_psbt();
        psbt.global.tx_modifiable = None;
        assert!(!psbt.inputs_modifiable());
        assert!(!psbt.outputs_modifiable());
        let err = psbt.add_input_v2(PsbtInput::default()).unwrap_err();
        assert!(matches!(err, PsbtError::InputsNotModifiable));
    }

    #[test]
    fn combiner_merges_tx_modifiable_and_or() {
        let mut a = make_v2_psbt();
        let mut b = make_v2_psbt();

        // a: inputs+outputs modifiable
        a.global.tx_modifiable = Some(PSBT_TXMOD_INPUTS | PSBT_TXMOD_OUTPUTS);
        // b: only inputs modifiable + has_sighash_single
        b.global.tx_modifiable = Some(PSBT_TXMOD_INPUTS | PSBT_TXMOD_HAS_SIGHASH_SINGLE);

        a.combine(b).unwrap();

        let flags = a.global.tx_modifiable.unwrap();
        // Inputs: both have it → AND → set
        assert_ne!(flags & PSBT_TXMOD_INPUTS, 0);
        // Outputs: only a has it → AND → cleared
        assert_eq!(flags & PSBT_TXMOD_OUTPUTS, 0);
        // SIGHASH_SINGLE: b has it → OR → set
        assert_ne!(flags & PSBT_TXMOD_HAS_SIGHASH_SINGLE, 0);
    }

    #[test]
    fn combiner_merges_tx_modifiable_none_to_some() {
        let mut a = make_v2_psbt();
        let b = make_v2_psbt();
        a.global.tx_modifiable = None;
        // b has Some(INPUTS|OUTPUTS)
        a.combine(b).unwrap();
        assert!(a.global.tx_modifiable.is_some());
        assert!(a.inputs_modifiable());
        assert!(a.outputs_modifiable());
    }

    // ── M27: Combiner merges preimage fields ─────────────────────────────

    #[test]
    fn combiner_merges_preimage_fields() {
        let tx = simple_tx();
        let mut a = Psbt::create(tx.clone());
        let mut b = Psbt::create(tx);

        // a has ripemd160 and sha256 preimages
        a.inputs[0]
            .ripemd160_preimages
            .insert(vec![0x11; 20], vec![0xaa]);
        a.inputs[0]
            .sha256_preimages
            .insert(vec![0x22; 32], vec![0xbb]);

        // b has hash160 and hash256 preimages, plus a different ripemd160
        b.inputs[0]
            .hash160_preimages
            .insert(vec![0x33; 20], vec![0xcc]);
        b.inputs[0]
            .hash256_preimages
            .insert(vec![0x44; 32], vec![0xdd]);
        b.inputs[0]
            .ripemd160_preimages
            .insert(vec![0x55; 20], vec![0xee]);

        a.combine(b).unwrap();

        assert_eq!(a.inputs[0].ripemd160_preimages.len(), 2);
        assert_eq!(a.inputs[0].sha256_preimages.len(), 1);
        assert_eq!(a.inputs[0].hash160_preimages.len(), 1);
        assert_eq!(a.inputs[0].hash256_preimages.len(), 1);
        assert_eq!(
            a.inputs[0].ripemd160_preimages.get(&vec![0x11; 20]).unwrap(),
            &vec![0xaa]
        );
        assert_eq!(
            a.inputs[0].ripemd160_preimages.get(&vec![0x55; 20]).unwrap(),
            &vec![0xee]
        );
    }

    // ── M28: Combiner merges BIP32 derivation maps ──────────────────────

    #[test]
    fn combiner_merges_bip32_derivation_inputs() {
        let tx = simple_tx();
        let mut a = Psbt::create(tx.clone());
        let mut b = Psbt::create(tx);

        let pk1 = vec![0x02; 33];
        let pk2 = vec![0x03; 33];
        let fp = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let path1 = vec![44 | 0x80000000, 0];
        let path2 = vec![84 | 0x80000000, 1];

        a.inputs[0]
            .bip32_derivation
            .insert(pk1.clone(), (fp.clone(), path1.clone()));
        b.inputs[0]
            .bip32_derivation
            .insert(pk2.clone(), (fp.clone(), path2.clone()));

        a.combine(b).unwrap();

        assert_eq!(a.inputs[0].bip32_derivation.len(), 2);
        assert_eq!(a.inputs[0].bip32_derivation.get(&pk1).unwrap().1, path1);
        assert_eq!(a.inputs[0].bip32_derivation.get(&pk2).unwrap().1, path2);
    }

    #[test]
    fn combiner_merges_bip32_derivation_outputs() {
        let tx = simple_tx();
        let mut a = Psbt::create(tx.clone());
        let mut b = Psbt::create(tx);

        let pk1 = vec![0x02; 33];
        let pk2 = vec![0x03; 33];
        let fp = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let path1 = vec![44 | 0x80000000, 0];
        let path2 = vec![84 | 0x80000000, 1];

        a.outputs[0]
            .bip32_derivation
            .insert(pk1.clone(), (fp.clone(), path1.clone()));
        b.outputs[0]
            .bip32_derivation
            .insert(pk2.clone(), (fp.clone(), path2.clone()));

        a.combine(b).unwrap();

        assert_eq!(a.outputs[0].bip32_derivation.len(), 2);
        assert_eq!(a.outputs[0].bip32_derivation.get(&pk1).unwrap().1, path1);
        assert_eq!(a.outputs[0].bip32_derivation.get(&pk2).unwrap().1, path2);
    }

    #[test]
    fn combiner_merges_tap_bip32_derivation_inputs() {
        let tx = simple_tx();
        let mut a = Psbt::create(tx.clone());
        let mut b = Psbt::create(tx);

        let xonly1 = vec![0x11; 32];
        let xonly2 = vec![0x22; 32];
        let lh: std::collections::BTreeSet<Vec<u8>> = [vec![0xaa; 32]].into_iter().collect();
        let fp = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let path = vec![86 | 0x80000000, 0];

        a.inputs[0]
            .tap_bip32_derivation
            .insert(xonly1.clone(), (lh.clone(), fp.clone(), path.clone()));
        b.inputs[0]
            .tap_bip32_derivation
            .insert(xonly2.clone(), (lh.clone(), fp.clone(), path.clone()));

        a.combine(b).unwrap();

        assert_eq!(a.inputs[0].tap_bip32_derivation.len(), 2);
        assert!(a.inputs[0].tap_bip32_derivation.contains_key(&xonly1));
        assert!(a.inputs[0].tap_bip32_derivation.contains_key(&xonly2));
    }
}
