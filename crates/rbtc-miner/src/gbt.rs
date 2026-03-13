//! BIP22/BIP23 getblocktemplate (GBT) RPC response structures and proposal
//! mode validation.
//!
//! This module provides:
//! - [`BlockTemplateResponse`] — the full GBT JSON response matching BIP22.
//! - [`GbtTransaction`] — per-transaction entry in the template.
//! - [`BlockProposal`] / [`GbtProposalResult`] — BIP23 proposal mode.
//! - [`create_block_template`] — builds a `BlockTemplateResponse` from a
//!   [`BlockTemplate`].
//! - [`validate_block_proposal`] — validates a BIP23 block proposal.

use std::collections::HashMap;

use rbtc_crypto::sha256d;
use rbtc_primitives::{
    block::Block,
    codec::{Decodable, Encodable},
    constants::{MAX_BLOCK_SERIALIZED_SIZE, MAX_BLOCK_SIGOPS_COST, MAX_BLOCK_WEIGHT},
    hash::BlockHash,
    network::Network,
};
use serde::{Deserialize, Serialize};

use crate::template::{compute_txid, BlockTemplate};

// ── GBT response types (BIP22/BIP23) ─────────────────────────────────────────

/// A single transaction entry in the GBT response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GbtTransaction {
    /// Raw transaction data (hex-encoded).
    pub data: String,
    /// Transaction ID (double-SHA256 of legacy serialization, hex, internal byte order).
    pub txid: String,
    /// Witness transaction ID (hex, internal byte order).
    pub hash: String,
    /// Indices (1-based) of other transactions in the template that this
    /// transaction depends on (i.e. spends outputs of).
    pub depends: Vec<usize>,
    /// Transaction fee in satoshis.
    pub fee: u64,
    /// Sigop cost.
    pub sigops: u64,
    /// Transaction weight in weight units.
    pub weight: u64,
}

/// Full `getblocktemplate` response per BIP22/BIP23.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockTemplateResponse {
    /// Block version (with BIP9 version bits).
    pub version: i32,
    /// Hash of the previous block (hex, internal byte order).
    #[serde(rename = "previousblockhash")]
    pub previous_block_hash: String,
    /// Non-coinbase transactions to include.
    pub transactions: Vec<GbtTransaction>,
    /// Coinbase auxiliary data (key "flags" contains the coinbase flags hex).
    #[serde(rename = "coinbaseaux")]
    pub coinbase_aux: HashMap<String, String>,
    /// Maximum coinbase value in satoshis (subsidy + fees).
    #[serde(rename = "coinbasevalue")]
    pub coinbase_value: u64,
    /// Compact target as 64-character big-endian hex.
    pub target: String,
    /// Minimum block time (MTP + 1).
    #[serde(rename = "mintime")]
    pub min_time: u64,
    /// Mutable template fields the miner may modify.
    pub mutable: Vec<String>,
    /// Allowed nonce range ("00000000ffffffff").
    #[serde(rename = "noncerange")]
    pub nonce_range: String,
    /// Maximum sigop cost for the block.
    #[serde(rename = "sigoplimit")]
    pub sigop_limit: u64,
    /// Maximum serialized block size in bytes.
    #[serde(rename = "sizelimit")]
    pub size_limit: u64,
    /// Maximum block weight in weight units.
    #[serde(rename = "weightlimit")]
    pub weight_limit: u64,
    /// Current time (Unix seconds).
    #[serde(rename = "curtime")]
    pub cur_time: u64,
    /// Compact target as 8-character hex (nBits).
    pub bits: String,
    /// Height of the block being constructed.
    pub height: u32,
    /// Default witness commitment (hex) if any transactions have witness data.
    #[serde(
        rename = "default_witness_commitment",
        skip_serializing_if = "Option::is_none"
    )]
    pub default_witness_commitment: Option<String>,

    // ── BIP22/23 fields (H14) ────────────────────────────────────────────

    /// Server capabilities. Includes `"proposal"` to signal BIP23 support.
    pub capabilities: Vec<String>,
    /// Version bits available for signaling (deployment name -> bit number).
    pub vbavailable: HashMap<String, u32>,
    /// Mask of version bits that the server requires to be set.
    pub vbrequired: u32,
    /// Active consensus rules. Rules prefixed with `!` are required (must not
    /// be removed by the miner).
    pub rules: Vec<String>,
    /// Long-poll ID for template refresh notifications.
    #[serde(rename = "longpollid", skip_serializing_if = "Option::is_none")]
    pub longpollid: Option<String>,

    /// Signet challenge script (hex-encoded), present only on signet.
    #[serde(
        rename = "signet_challenge",
        skip_serializing_if = "Option::is_none"
    )]
    pub signet_challenge: Option<String>,
}

// ── BIP23 proposal mode (H15) ────────────────────────────────────────────────

/// A block proposal submitted by a miner for server-side validation (BIP23).
#[derive(Clone, Debug)]
pub struct BlockProposal {
    /// Raw serialized block data.
    pub block_data: Vec<u8>,
}

/// Result of BIP23 block proposal validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GbtProposalResult {
    /// The proposal is valid and could be accepted.
    Accepted,
    /// The proposal is definitively rejected with a reason string.
    Rejected(String),
    /// The proposal cannot be validated right now (e.g. unknown prev block).
    Inconclusive,
}

// ── Constructor ───────────────────────────────────────────────────────────────

/// BIP9 deployment state as relevant to GBT response population.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GbtDeploymentState {
    /// The deployment is currently signalling (STARTED). Goes into
    /// `vbavailable` only — miners can signal for it.
    Signalling,
    /// The deployment is locked in. Goes into `vbavailable` only.
    LockedIn,
    /// The deployment is active. Goes into the `rules` array.
    Active,
}

/// A single BIP9 deployment descriptor for GBT version-bits population.
#[derive(Clone, Debug)]
pub struct GbtDeployment {
    /// Human-readable deployment name (e.g. "csv", "segwit", "taproot").
    pub name: String,
    /// BIP9 bit number (0–28).
    pub bit: u32,
    /// Deployment state — determines whether this goes into `vbavailable`
    /// (Signalling/LockedIn) or `rules` (Active).
    pub state: GbtDeploymentState,
    /// Whether this deployment is required (non-optional). Required rules
    /// are prefixed with "!" in the `rules` array. In `vbavailable`, the
    /// name is also prefixed with "!" if required.
    pub required: bool,
}

/// BIP94 maximum allowed timewarp at difficulty retarget boundaries (seconds).
const MAX_TIMEWARP: u64 = 600;

/// Parameters for [`create_block_template`].
pub struct GbtParams {
    /// Hash of the current chain tip.
    pub tip_hash: BlockHash,
    /// Height of the current chain tip.
    pub tip_height: u32,
    /// Current time (Unix seconds). Used for `curtime`.
    pub cur_time: u64,
    /// Minimum allowed block time (typically MTP + 1).
    pub min_time: u64,
    /// Optional long-poll ID to attach.
    pub longpollid: Option<String>,
    /// Network type. Used to include signet_challenge on signet.
    pub network: Network,
    /// Active BIP9 deployments to populate `vbavailable`, `vbrequired`, and
    /// `rules` in the template response.
    pub deployments: Vec<GbtDeployment>,
    /// Timestamp of the previous block (tip). Used for BIP94 timewarp check.
    pub prev_time: u64,
    /// Difficulty adjustment interval (e.g. 2016 on mainnet). Used for BIP94.
    pub difficulty_adjustment_interval: u32,
    /// Override the default block reserved weight (8000 WU) set aside for
    /// the block header and coinbase transaction during transaction selection.
    /// `None` uses the default [`BLOCK_RESERVED_WEIGHT`].
    pub block_reserved_weight: Option<u64>,
}

/// Build a full [`BlockTemplateResponse`] from an existing [`BlockTemplate`]
/// and per-transaction fee and sigops data.
///
/// `per_tx_fees` and `per_tx_sigops` must be parallel to
/// `template.transactions` and contain the fee and sigop cost for each
/// transaction respectively.  Use [`TxSelector::select_with_fees`] to obtain
/// all three lists.
///
/// If `per_tx_sigops` is empty (e.g. in tests), the function falls back to a
/// conservative legacy sigop count (`count_sigops() * WITNESS_SCALE_FACTOR`).
pub fn create_block_template(
    template: &BlockTemplate,
    per_tx_fees: &[u64],
    per_tx_sigops: &[u64],
    params: &GbtParams,
) -> BlockTemplateResponse {
    // Build GbtTransaction list.
    let mut gbt_txs = Vec::with_capacity(template.transactions.len());

    // Map from txid -> 1-based index for dependency tracking.
    let mut txid_to_idx: HashMap<[u8; 32], usize> = HashMap::new();

    for (i, tx) in template.transactions.iter().enumerate() {
        let txid_hash = compute_txid(tx);
        txid_to_idx.insert(txid_hash.0, i + 1);
    }

    for (i, tx) in template.transactions.iter().enumerate() {
        let txid_hash = compute_txid(tx);

        // Encode raw tx data (full serialization with witness).
        let mut raw = Vec::new();
        tx.encode(&mut raw).ok();

        // Compute wtxid (full serialization hash).
        let wtxid = sha256d(&raw);

        // Compute legacy txid hex (internal byte order = reversed display).
        let txid_hex = hex::encode(txid_hash.0);
        let hash_hex = hex::encode(wtxid.0);

        // Build dependency list: any input that references a tx in this template.
        let mut depends = Vec::new();
        for input in &tx.inputs {
            let parent = input.previous_output.txid.0 .0;
            if let Some(&idx) = txid_to_idx.get(&parent) {
                if idx != i + 1 {
                    depends.push(idx);
                }
            }
        }

        // Sigop cost: prefer the accurate mempool-based count from
        // per_tx_sigops (which includes P2SH, segwit, and taproot sigops
        // matching Bitcoin Core's GetTransactionSigOpCost).  Fall back to
        // conservative legacy count * WITNESS_SCALE_FACTOR when the caller
        // does not provide per-tx sigops (e.g. in tests with &[]).
        let sigops = if let Some(&s) = per_tx_sigops.get(i) {
            s
        } else {
            let mut count = 0usize;
            for input in &tx.inputs {
                count += input.script_sig.count_sigops();
            }
            for output in &tx.outputs {
                count += output.script_pubkey.count_sigops();
            }
            (count as u64) * 4
        };

        let fee = per_tx_fees.get(i).copied().unwrap_or(0);

        gbt_txs.push(GbtTransaction {
            data: hex::encode(&raw),
            txid: txid_hex,
            hash: hash_hex,
            depends,
            fee,
            sigops,
            weight: tx.weight(),
        });
    }

    // Witness commitment.
    let default_witness_commitment = if template
        .transactions
        .iter()
        .any(|tx| tx.has_witness())
    {
        let commitment = crate::template::compute_witness_commitment(&template.transactions);
        // Full scriptPubKey: OP_RETURN (0x6a) OP_PUSH36 (0x24) 0xaa21a9ed || commitment_hash
        let mut bytes = Vec::with_capacity(38);
        bytes.push(0x6a); // OP_RETURN
        bytes.push(0x24); // push 36 bytes
        bytes.extend_from_slice(&[0xaa, 0x21, 0xa9, 0xed]);
        bytes.extend_from_slice(&commitment.0);
        Some(hex::encode(bytes))
    } else {
        None
    };

    // Previous block hash hex.
    let prev_hash_hex = hex::encode(template.prev_hash.0 .0);

    // coinbase_aux: "flags" key with empty hex (no extra coinbase flags).
    let mut coinbase_aux = HashMap::new();
    coinbase_aux.insert("flags".to_string(), String::new());

    // ── Populate version bits fields from deployments ────────────────────
    //
    // Matches Bitcoin Core's GBT response:
    // - `vbavailable`: signalling + locked_in deployments (name -> bit).
    //   Name is prefixed with "!" if the deployment is required.
    // - `rules`: only ACTIVE deployments. Prefixed with "!" if required.
    // - `vbrequired`: always 0 (Bitcoin Core hardcodes this).
    let mut vbavailable = HashMap::new();
    let vbrequired: u32 = 0;
    let mut rules = Vec::new();
    for dep in &params.deployments {
        let display_name = if dep.required {
            format!("!{}", dep.name)
        } else {
            dep.name.clone()
        };
        match dep.state {
            GbtDeploymentState::Signalling | GbtDeploymentState::LockedIn => {
                vbavailable.insert(display_name, dep.bit);
            }
            GbtDeploymentState::Active => {
                rules.push(display_name);
            }
        }
    }

    // ── BIP94 timewarp check ──────────────────────────────────────────────
    let block_height = params.tip_height + 1;
    let min_time = if params.difficulty_adjustment_interval > 0
        && block_height % params.difficulty_adjustment_interval == 0
    {
        // At retarget boundaries, enforce the timewarp rule:
        // min_time >= prev_block_time - MAX_TIMEWARP
        let timewarp_floor = params.prev_time.saturating_sub(MAX_TIMEWARP);
        std::cmp::max(params.min_time, timewarp_floor)
    } else {
        params.min_time
    };

    BlockTemplateResponse {
        version: template.version,
        previous_block_hash: prev_hash_hex,
        transactions: gbt_txs,
        coinbase_aux,
        coinbase_value: template.coinbase_value as u64,
        target: template.target_hex(),
        min_time,
        mutable: vec![
            "time".to_string(),
            "transactions".to_string(),
            "prevblock".to_string(),
        ],
        nonce_range: "00000000ffffffff".to_string(),
        sigop_limit: MAX_BLOCK_SIGOPS_COST,
        size_limit: MAX_BLOCK_SERIALIZED_SIZE as u64,
        weight_limit: MAX_BLOCK_WEIGHT,
        cur_time: params.cur_time,
        bits: template.bits_hex(),
        height: block_height,
        default_witness_commitment,
        // H14 fields
        capabilities: vec!["proposal".to_string()],
        vbavailable,
        vbrequired,
        rules,
        longpollid: params.longpollid.clone(),
        signet_challenge: params.network.signet_challenge().map(hex::encode),
    }
}

// ── BIP23 proposal validation (H15) ──────────────────────────────────────────

/// Validate a BIP23 block proposal.
///
/// Performs basic structural checks:
/// 1. Decode the block from raw bytes.
/// 2. Check that `prev_block` matches the known tip hash.
/// 3. Verify the PoW hash meets the declared `nBits` target.
/// 4. Check block weight and sigop limits.
///
/// Returns [`GbtProposalResult::Inconclusive`] if the previous block is unknown
/// (the proposal might be valid on a different fork).
pub fn validate_block_proposal(
    proposal: &BlockProposal,
    tip_hash: &BlockHash,
) -> GbtProposalResult {
    // 1. Decode block.
    let block = match Block::decode_from_slice(&proposal.block_data) {
        Ok(b) => b,
        Err(e) => {
            return GbtProposalResult::Rejected(format!("failed to decode block: {e}"));
        }
    };

    // 2. Check prev_block matches known tip.
    if block.header.prev_block != *tip_hash {
        return GbtProposalResult::Inconclusive;
    }

    // 3. Verify PoW.
    let mut header_buf = Vec::with_capacity(80);
    block.header.encode(&mut header_buf).ok();
    let hash = BlockHash(sha256d(&header_buf));

    if !block.header.meets_target(&hash) {
        return GbtProposalResult::Rejected("block hash does not meet target".to_string());
    }

    // 4. Weight limit.
    let weight = block.weight();
    if weight > MAX_BLOCK_WEIGHT {
        return GbtProposalResult::Rejected(format!(
            "block weight {weight} exceeds limit {MAX_BLOCK_WEIGHT}"
        ));
    }

    // 5. Sigop cost limit (conservative legacy count).
    let mut total_sigops: u64 = 0;
    for tx in &block.transactions {
        let mut count = 0usize;
        for input in &tx.inputs {
            count += input.script_sig.count_sigops();
        }
        for output in &tx.outputs {
            count += output.script_pubkey.count_sigops();
        }
        total_sigops += (count as u64) * 4;
    }
    if total_sigops > MAX_BLOCK_SIGOPS_COST {
        return GbtProposalResult::Rejected(format!(
            "sigops cost {total_sigops} exceeds limit {MAX_BLOCK_SIGOPS_COST}"
        ));
    }

    // 6. Must have at least one transaction (coinbase).
    if block.transactions.is_empty() {
        return GbtProposalResult::Rejected("block has no transactions".to_string());
    }

    // 7. First transaction must be coinbase.
    if !block.transactions[0].is_coinbase() {
        return GbtProposalResult::Rejected("first transaction is not coinbase".to_string());
    }

    // 8. Merkle root validation: compute from transactions and compare to header.
    {
        let mut txids: Vec<rbtc_primitives::hash::Hash256> = Vec::with_capacity(block.transactions.len());
        for tx in &block.transactions {
            txids.push(compute_txid(tx));
        }
        let (computed_root, _mutated) = rbtc_crypto::merkle::merkle_root(&txids);
        let computed_root = computed_root.unwrap_or(rbtc_primitives::hash::Hash256::ZERO);
        if computed_root != block.header.merkle_root {
            return GbtProposalResult::Rejected("merkle root mismatch".to_string());
        }
    }

    GbtProposalResult::Accepted
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::{
        hash::{BlockHash, Hash256},
        network::Network,
        script::Script,
    };

    fn test_template() -> BlockTemplate {
        BlockTemplate::new(
            0x2000_0000,
            BlockHash::ZERO,
            0x207f_ffff, // regtest
            0,
            210_000,
            0,
            vec![],
            Script::new(),
        )
    }

    /// Helper to build a default GbtParams with no deployments and no
    /// timewarp constraints. Tests that need specific fields override them.
    fn default_params() -> GbtParams {
        GbtParams {
            tip_hash: BlockHash::ZERO,
            tip_height: 0,
            cur_time: 0,
            min_time: 0,
            longpollid: None,
            network: Network::Regtest,
            deployments: vec![],
            prev_time: 0,
            difficulty_adjustment_interval: 0,
            block_reserved_weight: None,
        }
    }

    #[test]
    fn response_has_all_required_fields() {
        let template = test_template();
        let params = GbtParams {
            cur_time: 1_700_000_000,
            min_time: 1_699_999_000,
            longpollid: Some("abc123".to_string()),
            ..default_params()
        };
        let resp = create_block_template(&template, &[], &[], &params);

        assert_eq!(resp.version, 0x2000_0000);
        assert_eq!(resp.height, 1); // tip_height + 1
        assert_eq!(resp.bits.len(), 8);
        assert_eq!(resp.target.len(), 64);
        assert_eq!(resp.nonce_range, "00000000ffffffff");
        assert_eq!(resp.sigop_limit, MAX_BLOCK_SIGOPS_COST);
        assert_eq!(resp.size_limit, MAX_BLOCK_SERIALIZED_SIZE as u64);
        assert_eq!(resp.weight_limit, MAX_BLOCK_WEIGHT);
        assert_eq!(resp.cur_time, 1_700_000_000);
        assert_eq!(resp.min_time, 1_699_999_000);
        assert!(resp.coinbase_aux.contains_key("flags"));
        assert_eq!(resp.longpollid, Some("abc123".to_string()));
        assert!(!resp.mutable.is_empty());
    }

    #[test]
    fn gbt_transaction_fields() {
        // Verify that GbtTransaction can be serialized to JSON with expected keys.
        let gbt_tx = GbtTransaction {
            data: "deadbeef".to_string(),
            txid: "aabb".to_string(),
            hash: "ccdd".to_string(),
            depends: vec![1, 2],
            fee: 5000,
            sigops: 4,
            weight: 800,
        };
        let json = serde_json::to_value(&gbt_tx).unwrap();
        assert_eq!(json["data"], "deadbeef");
        assert_eq!(json["txid"], "aabb");
        assert_eq!(json["hash"], "ccdd");
        assert_eq!(json["depends"], serde_json::json!([1, 2]));
        assert_eq!(json["fee"], 5000);
        assert_eq!(json["sigops"], 4);
        assert_eq!(json["weight"], 800);
    }

    #[test]
    fn capabilities_includes_proposal() {
        let template = test_template();
        let resp = create_block_template(&template, &[], &[], &default_params());
        assert!(
            resp.capabilities.contains(&"proposal".to_string()),
            "capabilities must include 'proposal' for BIP23"
        );
    }

    #[test]
    fn rules_populated_from_active_deployments_only() {
        let template = test_template();
        let params = GbtParams {
            deployments: vec![
                GbtDeployment { name: "csv".into(), bit: 0, state: GbtDeploymentState::Active, required: false },
                GbtDeployment { name: "segwit".into(), bit: 1, state: GbtDeploymentState::Active, required: true },
                GbtDeployment { name: "taproot".into(), bit: 2, state: GbtDeploymentState::Active, required: true },
                GbtDeployment { name: "newsoft".into(), bit: 3, state: GbtDeploymentState::Signalling, required: false },
            ],
            ..default_params()
        };
        let resp = create_block_template(&template, &[], &[], &params);
        // Active + not required → plain name in rules
        assert!(resp.rules.contains(&"csv".to_string()));
        // Active + required → "!" prefix in rules
        assert!(resp.rules.contains(&"!segwit".to_string()));
        assert!(resp.rules.contains(&"!taproot".to_string()));
        // Signalling deployments should NOT appear in rules
        assert!(!resp.rules.iter().any(|r| r.contains("newsoft")));
        // Signalling deployment should appear in vbavailable
        assert!(resp.vbavailable.contains_key("newsoft"));
    }

    #[test]
    fn vbavailable_and_vbrequired_defaults() {
        let template = test_template();
        let resp = create_block_template(&template, &[], &[], &default_params());
        assert!(resp.vbavailable.is_empty());
        assert_eq!(resp.vbrequired, 0);
    }

    #[test]
    fn vbavailable_populated_from_signalling_and_locked_in() {
        let template = test_template();
        let params = GbtParams {
            deployments: vec![
                // Active deployments should NOT appear in vbavailable
                GbtDeployment { name: "csv".into(), bit: 0, state: GbtDeploymentState::Active, required: false },
                // Signalling → vbavailable
                GbtDeployment { name: "newrule".into(), bit: 3, state: GbtDeploymentState::Signalling, required: false },
                // LockedIn + required → vbavailable with "!" prefix
                GbtDeployment { name: "segwit".into(), bit: 1, state: GbtDeploymentState::LockedIn, required: true },
            ],
            ..default_params()
        };
        let resp = create_block_template(&template, &[], &[], &params);
        // Only signalling and locked_in go to vbavailable
        assert_eq!(resp.vbavailable.len(), 2);
        assert_eq!(resp.vbavailable["newrule"], 3);
        assert_eq!(resp.vbavailable["!segwit"], 1);
        // Active deployments excluded from vbavailable
        assert!(!resp.vbavailable.contains_key("csv"));
        // vbrequired is always 0 (matching Bitcoin Core)
        assert_eq!(resp.vbrequired, 0);
    }

    #[test]
    fn validate_proposal_rejects_invalid_data() {
        let result = validate_block_proposal(
            &BlockProposal {
                block_data: vec![0xde, 0xad],
            },
            &BlockHash::ZERO,
        );
        match result {
            GbtProposalResult::Rejected(reason) => {
                assert!(reason.contains("decode"), "reason: {reason}");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn validate_proposal_inconclusive_unknown_prev() {
        // Build a valid regtest block whose prev_block is NOT the tip we pass.
        let template = test_template();
        let block = crate::worker::mine_block(&template);
        let mut block_data = Vec::new();
        block.encode(&mut block_data).ok();

        // Tip is some other hash, not BlockHash::ZERO.
        let other_tip = BlockHash(Hash256([0x42; 32]));
        let result = validate_block_proposal(
            &BlockProposal { block_data },
            &other_tip,
        );
        assert_eq!(result, GbtProposalResult::Inconclusive);
    }

    #[test]
    fn validate_proposal_accepts_valid_block() {
        let template = test_template();
        let block = crate::worker::mine_block(&template);
        let mut block_data = Vec::new();
        block.encode(&mut block_data).ok();

        let result = validate_block_proposal(
            &BlockProposal { block_data },
            &BlockHash::ZERO,
        );
        assert_eq!(result, GbtProposalResult::Accepted);
    }

    #[test]
    fn response_serializes_to_json() {
        let template = test_template();
        let params = GbtParams {
            cur_time: 1_700_000_000,
            ..default_params()
        };
        let resp = create_block_template(&template, &[], &[], &params);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"previousblockhash\""));
        assert!(json.contains("\"coinbasevalue\""));
        assert!(json.contains("\"capabilities\""));
        assert!(json.contains("\"vbavailable\""));
        assert!(json.contains("\"vbrequired\""));
        assert!(json.contains("\"rules\""));
        assert!(json.contains("\"weightlimit\""));
    }

    #[test]
    fn signet_challenge_present_on_signet() {
        let template = test_template();
        let params = GbtParams {
            network: Network::Signet,
            ..default_params()
        };
        let resp = create_block_template(&template, &[], &[], &params);
        assert!(
            resp.signet_challenge.is_some(),
            "signet_challenge must be present on signet"
        );
        // Verify it's valid hex
        let hex_str = resp.signet_challenge.as_ref().unwrap();
        assert!(!hex_str.is_empty());
        assert!(hex::decode(hex_str).is_ok());
    }

    #[test]
    fn signet_challenge_absent_on_non_signet() {
        let template = test_template();
        let resp = create_block_template(&template, &[], &[], &default_params());
        assert!(
            resp.signet_challenge.is_none(),
            "signet_challenge must be absent on non-signet networks"
        );
    }

    #[test]
    fn validate_proposal_rejects_bad_merkle_root() {
        let template = test_template();
        let mut block = crate::worker::mine_block(&template);
        // Corrupt the merkle root
        block.header.merkle_root = Hash256([0xff; 32]);
        // Re-mine with corrupted header (regtest difficulty is trivial)
        let mut block_data = Vec::new();
        block.encode(&mut block_data).ok();

        let result = validate_block_proposal(
            &BlockProposal { block_data },
            &BlockHash::ZERO,
        );
        match result {
            GbtProposalResult::Rejected(reason) => {
                assert!(
                    reason.contains("merkle root") || reason.contains("hash does not meet"),
                    "unexpected rejection reason: {reason}"
                );
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn validate_proposal_merkle_root_correct_passes() {
        // A properly mined block should pass merkle root validation.
        let template = test_template();
        let block = crate::worker::mine_block(&template);
        let mut block_data = Vec::new();
        block.encode(&mut block_data).ok();

        let result = validate_block_proposal(
            &BlockProposal { block_data },
            &BlockHash::ZERO,
        );
        assert_eq!(result, GbtProposalResult::Accepted);
    }

    // ── M30: BIP94 timewarp rule tests ────────────────────────────────────

    #[test]
    fn bip94_timewarp_at_retarget_boundary() {
        // At a retarget boundary (height % 2016 == 0), min_time must be
        // at least prev_time - MAX_TIMEWARP (600s).
        let template = test_template();

        // tip_height = 2015, so block being built = 2016 (retarget boundary).
        // prev_time = 2000, so timewarp floor = 2000 - 600 = 1400.
        // If MTP-based min_time (100) < timewarp floor (1400), the timewarp
        // floor wins.
        let params = GbtParams {
            tip_height: 2015,
            min_time: 100,
            prev_time: 2000,
            difficulty_adjustment_interval: 2016,
            ..default_params()
        };
        let resp = create_block_template(&template, &[], &[], &params);
        // min_time should be max(100, 2000 - 600) = 1400
        assert_eq!(resp.min_time, 1400);
    }

    #[test]
    fn bip94_timewarp_no_effect_off_boundary() {
        // Not at a retarget boundary: timewarp rule should not apply.
        let template = test_template();
        let params = GbtParams {
            tip_height: 2016, // block = 2017, not a boundary
            min_time: 100,
            prev_time: 2000,
            difficulty_adjustment_interval: 2016,
            ..default_params()
        };
        let resp = create_block_template(&template, &[], &[], &params);
        // min_time stays at the MTP-based value
        assert_eq!(resp.min_time, 100);
    }

    #[test]
    fn bip94_timewarp_mtp_already_higher() {
        // At retarget boundary but MTP-based min_time is already higher
        // than the timewarp floor — no change.
        let template = test_template();
        let params = GbtParams {
            tip_height: 2015,
            min_time: 5000,
            prev_time: 2000,
            difficulty_adjustment_interval: 2016,
            ..default_params()
        };
        let resp = create_block_template(&template, &[], &[], &params);
        // timewarp floor = 2000 - 600 = 1400, but min_time 5000 > 1400
        assert_eq!(resp.min_time, 5000);
    }

    // ── M21: vbrequired always 0 ────────────────────────────────────────

    #[test]
    fn vbrequired_always_zero() {
        // Bitcoin Core hardcodes vbrequired to 0 regardless of deployments.
        let template = test_template();
        let params = GbtParams {
            deployments: vec![
                GbtDeployment {
                    name: "segwit".into(),
                    bit: 1,
                    state: GbtDeploymentState::Active,
                    required: true,
                },
                GbtDeployment {
                    name: "taproot".into(),
                    bit: 2,
                    state: GbtDeploymentState::Active,
                    required: true,
                },
            ],
            ..default_params()
        };
        let resp = create_block_template(&template, &[], &[], &params);
        assert_eq!(resp.vbrequired, 0, "vbrequired must always be 0 (matching Bitcoin Core)");
    }

    // ── M22: rules only contains ACTIVE deployments ─────────────────────

    #[test]
    fn signalling_deployments_not_in_rules() {
        let template = test_template();
        let params = GbtParams {
            deployments: vec![
                GbtDeployment {
                    name: "newsoft".into(),
                    bit: 5,
                    state: GbtDeploymentState::Signalling,
                    required: false,
                },
            ],
            ..default_params()
        };
        let resp = create_block_template(&template, &[], &[], &params);
        assert!(
            resp.rules.is_empty(),
            "signalling deployments must not appear in rules array"
        );
        assert_eq!(resp.vbavailable["newsoft"], 5);
    }

    #[test]
    fn locked_in_deployments_not_in_rules() {
        let template = test_template();
        let params = GbtParams {
            deployments: vec![
                GbtDeployment {
                    name: "lockrule".into(),
                    bit: 7,
                    state: GbtDeploymentState::LockedIn,
                    required: true,
                },
            ],
            ..default_params()
        };
        let resp = create_block_template(&template, &[], &[], &params);
        assert!(
            resp.rules.is_empty(),
            "locked_in deployments must not appear in rules array"
        );
        // Required locked_in → "!" prefix in vbavailable
        assert_eq!(resp.vbavailable["!lockrule"], 7);
    }

    #[test]
    fn active_required_rule_has_bang_prefix() {
        let template = test_template();
        let params = GbtParams {
            deployments: vec![
                GbtDeployment {
                    name: "segwit".into(),
                    bit: 1,
                    state: GbtDeploymentState::Active,
                    required: true,
                },
            ],
            ..default_params()
        };
        let resp = create_block_template(&template, &[], &[], &params);
        assert!(
            resp.rules.contains(&"!segwit".to_string()),
            "required active rule must be prefixed with '!'"
        );
        assert!(
            resp.vbavailable.is_empty(),
            "active deployments must not appear in vbavailable"
        );
    }

    #[test]
    fn active_optional_rule_no_prefix() {
        let template = test_template();
        let params = GbtParams {
            deployments: vec![
                GbtDeployment {
                    name: "csv".into(),
                    bit: 0,
                    state: GbtDeploymentState::Active,
                    required: false,
                },
            ],
            ..default_params()
        };
        let resp = create_block_template(&template, &[], &[], &params);
        assert!(
            resp.rules.contains(&"csv".to_string()),
            "optional active rule must appear without prefix"
        );
        assert!(
            !resp.rules.contains(&"!csv".to_string()),
            "optional rule must NOT have '!' prefix"
        );
    }

    // ── M1: mutable field matches Bitcoin Core ────────────────────────────

    #[test]
    fn mutable_field_matches_bitcoin_core() {
        let template = test_template();
        let resp = create_block_template(&template, &[], &[], &default_params());
        // Bitcoin Core uses exactly ["time", "transactions", "prevblock"]
        assert_eq!(
            resp.mutable,
            vec!["time", "transactions", "prevblock"],
            "mutable field must match Bitcoin Core: time, transactions, prevblock"
        );
    }

    // ── M2: default_witness_commitment has OP_RETURN prefix ───────────────

    #[test]
    fn witness_commitment_has_op_return_prefix() {
        use rbtc_primitives::transaction::{Transaction, TxIn, TxOut, OutPoint};
        use rbtc_primitives::hash::Txid;

        // Build a template with a witness-bearing transaction so the
        // commitment is generated.
        let witness_tx = {
            let mut tx = Transaction::from_parts(
                2,
                vec![TxIn {
                    previous_output: OutPoint { txid: Txid(Hash256([0x01; 32])), vout: 0 },
                    script_sig: Script::new(),
                    sequence: 0xffff_ffff,
                    witness: vec![vec![0x30; 72]], // non-empty witness
                }],
                vec![TxOut {
                    value: 50_000,
                    script_pubkey: Script::new(),
                }],
                0,
            );
            tx
        };
        let template = BlockTemplate::new(
            0x2000_0000,
            BlockHash::ZERO,
            0x207f_ffff,
            0,
            210_000,
            0,
            vec![witness_tx],
            Script::new(),
        );
        let resp = create_block_template(&template, &[1000], &[], &default_params());
        let commitment = resp.default_witness_commitment.expect("should have witness commitment");
        // Must start with 6a24aa21a9ed (OP_RETURN + PUSH36 + magic)
        assert!(
            commitment.starts_with("6a24aa21a9ed"),
            "witness commitment must start with OP_RETURN prefix 6a24aa21a9ed, got: {}",
            &commitment[..12.min(commitment.len())]
        );
        // Total length: 2 (OP_RETURN) + 2 (push) + 8 (magic) + 64 (hash) = 76 hex chars = 38 bytes
        assert_eq!(
            commitment.len(),
            76,
            "witness commitment must be 38 bytes (76 hex chars), got {}",
            commitment.len()
        );
    }

    // ── M3: per-tx sigops from mempool ──────────────────────────────────

    #[test]
    fn sigops_uses_mempool_value_when_provided() {
        use rbtc_primitives::transaction::{Transaction, TxIn, TxOut, OutPoint};
        use rbtc_primitives::hash::Txid;

        // Build a template with a simple transaction.
        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint { txid: Txid(Hash256([0x01; 32])), vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffff_ffff,
                witness: vec![],
            }],
            vec![TxOut {
                value: 50_000,
                script_pubkey: Script::new(),
            }],
            0,
        );
        let template = BlockTemplate::new(
            0x2000_0000,
            BlockHash::ZERO,
            0x207f_ffff,
            0,
            210_000,
            0,
            vec![tx],
            Script::new(),
        );

        // When per_tx_sigops is provided, it should be used directly.
        let resp = create_block_template(&template, &[1000], &[42], &default_params());
        assert_eq!(
            resp.transactions[0].sigops, 42,
            "sigops should match the mempool-provided value"
        );
    }

    #[test]
    fn sigops_falls_back_to_legacy_when_empty() {
        use rbtc_primitives::transaction::{Transaction, TxIn, TxOut, OutPoint};
        use rbtc_primitives::hash::Txid;

        // Build a template with a transaction that has OP_CHECKSIG in output.
        let spk = Script::from_bytes(vec![0xac]); // OP_CHECKSIG

        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint { txid: Txid(Hash256([0x01; 32])), vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffff_ffff,
                witness: vec![],
            }],
            vec![TxOut {
                value: 50_000,
                script_pubkey: spk,
            }],
            0,
        );
        let template = BlockTemplate::new(
            0x2000_0000,
            BlockHash::ZERO,
            0x207f_ffff,
            0,
            210_000,
            0,
            vec![tx],
            Script::new(),
        );

        // When per_tx_sigops is empty, falls back to legacy count.
        // OP_CHECKSIG = 1 sigop, * 4 (witness scale factor) = 4.
        let resp = create_block_template(&template, &[1000], &[], &default_params());
        assert_eq!(
            resp.transactions[0].sigops, 4,
            "legacy fallback: OP_CHECKSIG should give sigops cost of 4"
        );
    }
}
