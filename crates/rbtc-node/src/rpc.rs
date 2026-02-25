//! JSON-RPC 1.1 server compatible with Bitcoin Core's HTTP interface.
//!
//! Exposes a subset of Bitcoin Core's RPC methods:
//!   getblockchaininfo, getblockcount, getblockhash, getblock,
//!   getrawtransaction, getrawmempool, sendrawtransaction,
//!   getnewaddress, getbalance, listunspent, sendtoaddress,
//!   signrawtransactionwithwallet, dumpprivkey, importprivkey,
//!   getwalletinfo, fundrawtransaction,
//!   getblocktemplate, submitblock, generatetoaddress, generate,
//!   getmininginfo, getnetworkhashps, estimatesmartfee.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use rbtc_consensus::chain::ChainState;
use rbtc_crypto::sha256d;
use rbtc_mempool::Mempool;
use rbtc_miner::{BlockTemplate, TxSelector, mine_block};
use rbtc_primitives::{
    block::{Block, nbits_to_target},
    codec::{Decodable, Encodable},
    hash::Hash256,
    transaction::{OutPoint, Transaction},
};
use rbtc_storage::{AddrIndexStore, BlockStore, Database, TxIndexStore};
use rbtc_wallet::{AddressType, Wallet, address::address_to_script};

// ── Shared state ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct RpcState {
    pub chain: Arc<RwLock<ChainState>>,
    pub mempool: Arc<RwLock<Mempool>>,
    pub db: Arc<Database>,
    pub network_name: String,
    /// Optional HD wallet; `None` when the node is started without `--wallet`.
    pub wallet: Option<Arc<RwLock<Wallet>>>,
    /// Channel to submit mined / external blocks into the node's event loop.
    pub submit_block_tx: mpsc::UnboundedSender<Block>,
}

// ── JSON-RPC envelope ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct RpcRequest {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

#[derive(Debug, Serialize)]
struct RpcResponse {
    id: Option<Value>,
    result: Option<Value>,
    error: Option<RpcError>,
}

#[derive(Debug, Serialize)]
struct RpcError {
    code: i32,
    message: String,
}

impl RpcResponse {
    fn ok(id: Option<Value>, result: Value) -> Self {
        Self { id, result: Some(result), error: None }
    }

    fn err(id: Option<Value>, code: i32, message: impl Into<String>) -> Self {
        Self {
            id,
            result: None,
            error: Some(RpcError { code, message: message.into() }),
        }
    }
}

// ── Router ───────────────────────────────────────────────────────────────────

pub fn rpc_router(state: RpcState) -> Router {
    Router::new()
        .route("/", post(handle_rpc))
        .with_state(Arc::new(state))
}

async fn handle_rpc(
    State(state): State<Arc<RpcState>>,
    Json(req): Json<RpcRequest>,
) -> impl IntoResponse {
    let id = req.id.clone();
    let params = req.params.unwrap_or(Value::Array(vec![]));

    debug!("rpc: method={} id={:?}", req.method, id);

    let result = match req.method.as_str() {
        // Chain
        "getblockchaininfo"          => rpc_getblockchaininfo(&state).await,
        "getblockcount"              => rpc_getblockcount(&state).await,
        "getblockhash"               => rpc_getblockhash(&state, &params).await,
        "getblock"                   => rpc_getblock(&state, &params).await,
        // Transactions
        "getrawtransaction"          => rpc_getrawtransaction(&state, &params).await,
        "getrawmempool"              => rpc_getrawmempool(&state).await,
        "sendrawtransaction"         => rpc_sendrawtransaction(&state, &params).await,
        // Wallet
        "getnewaddress"              => rpc_getnewaddress(&state, &params).await,
        "getbalance"                 => rpc_getbalance(&state).await,
        "listunspent"                => rpc_listunspent(&state, &params).await,
        "sendtoaddress"              => rpc_sendtoaddress(&state, &params).await,
        "fundrawtransaction"         => rpc_fundrawtransaction(&state, &params).await,
        "signrawtransactionwithwallet" => rpc_signrawtransactionwithwallet(&state, &params).await,
        "dumpprivkey"                => rpc_dumpprivkey(&state, &params).await,
        "importprivkey"              => rpc_importprivkey(&state, &params).await,
        "getwalletinfo"              => rpc_getwalletinfo(&state).await,
        // Address index
        "getaddresstxids"            => rpc_getaddresstxids(&state, &params).await,
        "getaddressutxos"            => rpc_getaddressutxos(&state, &params).await,
        "getaddressbalance"          => rpc_getaddressbalance(&state, &params).await,
        // Mining
        "getblocktemplate"           => rpc_getblocktemplate(&state, &params).await,
        "submitblock"                => rpc_submitblock(&state, &params).await,
        "generatetoaddress"          => rpc_generatetoaddress(&state, &params).await,
        "generate"                   => rpc_generate(&state, &params).await,
        "getmininginfo"              => rpc_getmininginfo(&state).await,
        "getnetworkhashps"           => rpc_getnetworkhashps(&state, &params).await,
        "estimatesmartfee"           => rpc_estimatesmartfee(&state, &params).await,
        method => {
            warn!("rpc: unknown method {method}");
            Err((-32601, format!("Method not found: {method}")))
        }
    };

    let response = match result {
        Ok(v) => RpcResponse::ok(id, v),
        Err((code, msg)) => RpcResponse::err(id, code, msg),
    };

    (StatusCode::OK, Json(response))
}

// ── RPC method implementations ───────────────────────────────────────────────

async fn rpc_getblockchaininfo(state: &RpcState) -> RpcResult {
    let chain = state.chain.read().await;
    let height = chain.height();
    let tip = chain.best_hash().map(|h| h.to_hex()).unwrap_or_default();
    let chainwork = chain
        .best_hash()
        .and_then(|h| chain.get_block_index(&h))
        .map(|bi| format!("{:064x}", bi.chainwork))
        .unwrap_or_default();
    Ok(json!({
        "chain": state.network_name,
        "blocks": height,
        "bestblockhash": tip,
        "chainwork": chainwork,
    }))
}

async fn rpc_getblockcount(state: &RpcState) -> RpcResult {
    let chain = state.chain.read().await;
    Ok(json!(chain.height()))
}

async fn rpc_getblockhash(state: &RpcState, params: &Value) -> RpcResult {
    let height = params
        .get(0)
        .and_then(Value::as_u64)
        .ok_or((-32602, "Invalid params: expected height (u32)".to_string()))?
        as u32;
    let chain = state.chain.read().await;
    match chain.get_ancestor_hash(height) {
        Some(hash) => Ok(json!(hash.to_hex())),
        None => Err((-8, format!("Block height {height} out of range"))),
    }
}

async fn rpc_getblock(state: &RpcState, params: &Value) -> RpcResult {
    let hash_hex = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "Invalid params: expected block hash".to_string()))?;
    let hash = Hash256::from_hex(hash_hex)
        .map_err(|_| (-8, "Invalid block hash".to_string()))?;

    let verbosity = params.get(1).and_then(Value::as_u64).unwrap_or(1);

    let block_store = BlockStore::new(&state.db);
    match block_store.get_block(&hash) {
        Ok(Some(block)) => {
            if verbosity == 0 {
                // Return raw hex
                let mut bytes = Vec::new();
                block.encode(&mut bytes).ok();
                Ok(json!(hex::encode(bytes)))
            } else {
                // Return decoded JSON
                let chain = state.chain.read().await;
                let bi = chain.get_block_index(&hash);
                Ok(json!({
                    "hash": hash.to_hex(),
                    "height": bi.map(|b| b.height),
                    "version": block.header.version,
                    "merkleroot": block.header.merkle_root.to_hex(),
                    "time": block.header.time,
                    "bits": format!("{:08x}", block.header.bits),
                    "nonce": block.header.nonce,
                    "tx": block.transactions.iter().map(|tx| {
                        let mut buf = Vec::new();
                        tx.encode_legacy(&mut buf).ok();
                        rbtc_crypto::sha256d(&buf).to_hex()
                    }).collect::<Vec<_>>(),
                    "ntx": block.transactions.len(),
                }))
            }
        }
        Ok(None) => Err((-5, "Block not found".to_string())),
        Err(e) => Err((-1, e.to_string())),
    }
}

async fn rpc_getrawtransaction(state: &RpcState, params: &Value) -> RpcResult {
    let txid_hex = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "Invalid params: expected txid".to_string()))?;
    let txid = Hash256::from_hex(txid_hex)
        .map_err(|_| (-8, "Invalid txid".to_string()))?;

    let verbose = params.get(1).and_then(Value::as_bool).unwrap_or(false);

    // Check mempool first
    {
        let mp = state.mempool.read().await;
        if let Some(entry) = mp.get(&txid) {
            if verbose {
                return Ok(json!({
                    "txid": txid.to_hex(),
                    "size": entry.tx.vsize(),
                    "vsize": entry.vsize,
                    "fee": entry.fee,
                    "confirmations": 0,
                }));
            } else {
                let mut buf = Vec::new();
                entry.tx.encode_segwit(&mut buf).ok();
                return Ok(json!(hex::encode(buf)));
            }
        }
    }

    // Look up confirmed transaction via the tx index
    let tx_idx = TxIndexStore::new(&state.db);
    let (block_hash, tx_offset) = match tx_idx.get(&txid) {
        Ok(Some(v)) => v,
        Ok(None) => return Err((-5, format!("No transaction found for txid {txid_hex}"))),
        Err(e) => return Err((-5, format!("tx index error: {e}"))),
    };

    let block_store = BlockStore::new(&state.db);
    let block = block_store
        .get_block(&block_hash)
        .map_err(|e| (-5, format!("block load error: {e}")))?
        .ok_or_else(|| (-5, format!("block {} not found", block_hash.to_hex())))?;

    let tx = block
        .transactions
        .get(tx_offset as usize)
        .ok_or_else(|| (-5, format!("tx offset {tx_offset} out of range")))?;

    if verbose {
        let chain = state.chain.read().await;
        let best_height = chain.height();
        let tx_height = chain
            .block_index
            .get(&block_hash)
            .map(|bi| bi.height)
            .unwrap_or(0);
        let confirmations = best_height.saturating_sub(tx_height) + 1;
        drop(chain);

        let mut txid_bytes = [0u8; 32];
        let mut buf = Vec::new();
        tx.encode_legacy(&mut buf).ok();
        let computed_txid = rbtc_crypto::sha256d(&buf);
        txid_bytes.copy_from_slice(&computed_txid.0);

        let vin: Vec<Value> = tx.inputs.iter().map(|inp| {
            json!({
                "txid": inp.previous_output.txid.to_hex(),
                "vout": inp.previous_output.vout,
                "sequence": inp.sequence,
            })
        }).collect();

        let vout: Vec<Value> = tx.outputs.iter().enumerate().map(|(n, out)| {
            json!({
                "n": n,
                "value": out.value,
                "scriptPubKey": { "hex": hex::encode(&out.script_pubkey.0) },
            })
        }).collect();

        Ok(json!({
            "txid": txid.to_hex(),
            "blockhash": block_hash.to_hex(),
            "confirmations": confirmations,
            "vin": vin,
            "vout": vout,
        }))
    } else {
        let mut buf = Vec::new();
        tx.encode_segwit(&mut buf).ok();
        Ok(json!(hex::encode(buf)))
    }
}

async fn rpc_getrawmempool(state: &RpcState) -> RpcResult {
    let mp = state.mempool.read().await;
    let txids: Vec<String> = mp.txids_by_fee_rate().iter().map(|t| t.to_hex()).collect();
    Ok(json!(txids))
}

async fn rpc_sendrawtransaction(state: &RpcState, params: &Value) -> RpcResult {
    let hex_str = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "Invalid params: expected raw transaction hex".to_string()))?;

    let raw = hex::decode(hex_str).map_err(|_| (-22, "TX decode failed".to_string()))?;
    let tx = Transaction::decode_from_slice(&raw)
        .map_err(|e| (-22, format!("TX decode failed: {e}")))?;

    let chain = state.chain.read().await;
    let mut mp = state.mempool.write().await;
    let height = chain.height();

    match mp.accept_tx(tx, &chain.utxos, height) {
        Ok(txid) => Ok(json!(txid.to_hex())),
        Err(e) => Err((-25, format!("Transaction rejected: {e}"))),
    }
}

type RpcResult = Result<Value, (i32, String)>;

// ── Wallet RPC helpers ────────────────────────────────────────────────────────

macro_rules! require_wallet {
    ($state:expr) => {
        match $state.wallet.as_ref() {
            Some(w) => w,
            None => return Err((-18, "No wallet loaded. Start with --wallet or --create-wallet.".into())),
        }
    };
}

async fn rpc_getnewaddress(state: &RpcState, params: &Value) -> RpcResult {
    let wallet_arc = require_wallet!(state);

    let addr_type_str = params.get(1).and_then(Value::as_str).unwrap_or("bech32");
    let addr_type = AddressType::from_str(addr_type_str)
        .unwrap_or(AddressType::SegWit);

    let mut w = wallet_arc.write().await;
    let address = w.new_address(addr_type)
        .map_err(|e| (-1, e.to_string()))?;
    Ok(json!(address))
}

async fn rpc_getbalance(state: &RpcState) -> RpcResult {
    let wallet_arc = require_wallet!(state);
    let w = wallet_arc.read().await;
    let (confirmed, unconfirmed) = w.balance();
    Ok(json!({
        "confirmed":   confirmed as f64 / 1e8,
        "unconfirmed": unconfirmed as f64 / 1e8,
        "total":       (confirmed + unconfirmed) as f64 / 1e8,
    }))
}

async fn rpc_listunspent(state: &RpcState, params: &Value) -> RpcResult {
    let wallet_arc = require_wallet!(state);
    let min_conf = params.get(0).and_then(Value::as_u64).unwrap_or(1) as u32;
    let w = wallet_arc.read().await;
    let utxos: Vec<Value> = w
        .list_unspent(min_conf)
        .iter()
        .map(|u| json!({
            "txid":          u.outpoint.txid.to_hex(),
            "vout":          u.outpoint.vout,
            "address":       u.address,
            "amount":        u.value as f64 / 1e8,
            "confirmations": u.height,
            "spendable":     true,
        }))
        .collect();
    Ok(json!(utxos))
}

async fn rpc_sendtoaddress(state: &RpcState, params: &Value) -> RpcResult {
    let wallet_arc = require_wallet!(state);

    let address = params.get(0).and_then(Value::as_str)
        .ok_or((-32602, "missing address".to_string()))?;
    let amount_btc = params.get(1).and_then(Value::as_f64)
        .ok_or((-32602, "missing amount".to_string()))?;
    let fee_rate = params.get(2).and_then(Value::as_f64).unwrap_or(1.0);

    let amount_sat = (amount_btc * 1e8) as u64;

    let (signed_tx, fee) = {
        let mut w = wallet_arc.write().await;
        w.create_transaction(address, amount_sat, fee_rate, AddressType::SegWit)
            .map_err(|e| (-6, e.to_string()))?
    };
    let _ = fee;

    // Encode and submit to mempool
    let mut raw = Vec::new();
    signed_tx.encode(&mut raw).map_err(|e| (-22, e.to_string()))?;
    let hex_tx = hex::encode(&raw);

    // Reuse sendrawtransaction logic
    let fake_params = json!([hex_tx]);
    rpc_sendrawtransaction(state, &fake_params).await
}

async fn rpc_fundrawtransaction(state: &RpcState, params: &Value) -> RpcResult {
    let wallet_arc = require_wallet!(state);

    let hex_str = params.get(0).and_then(Value::as_str)
        .ok_or((-32602, "missing raw transaction hex".to_string()))?;
    let fee_rate = params.get(1)
        .and_then(|p| p.get("feeRate"))
        .and_then(Value::as_f64)
        .unwrap_or(1.0);

    let raw = hex::decode(hex_str).map_err(|_| (-22, "TX decode failed".to_string()))?;
    let tx = Transaction::decode_from_slice(&raw)
        .map_err(|e| (-22, format!("TX decode failed: {e}")))?;

    // Estimate how much we need for the outputs + fee
    let output_total: u64 = tx.outputs.iter().map(|o| o.value).sum();

    let w = wallet_arc.read().await;
    let available: Vec<_> = w.list_unspent(1).into_iter().cloned().collect();
    drop(w);

    let (selected, actual_fee) = rbtc_wallet::CoinSelector::select(&available, output_total, fee_rate)
        .map_err(|e| (-6, e.to_string()))?;

    let total_in: u64 = selected.iter().map(|u| u.value).sum();
    let change = total_in.saturating_sub(output_total + actual_fee);

    let mut funded = tx.clone();
    for utxo in &selected {
        funded.inputs.push(rbtc_primitives::transaction::TxIn {
            previous_output: utxo.outpoint.clone(),
            script_sig: rbtc_primitives::script::Script::new(),
            sequence: 0xffff_fffe,
            witness: vec![],
        });
    }
    if change > 546 {
        let mut w = wallet_arc.write().await;
        let change_addr = w.new_address(AddressType::SegWit)
            .map_err(|e| (-1, e.to_string()))?;
        drop(w);
        let change_spk = rbtc_wallet::address::address_to_script(&change_addr)
            .map_err(|e| (-1, e.to_string()))?;
        funded.outputs.push(rbtc_primitives::transaction::TxOut {
            value: change,
            script_pubkey: change_spk,
        });
    }

    let mut buf = Vec::new();
    funded.encode(&mut buf).map_err(|e| (-22, e.to_string()))?;
    Ok(json!({
        "hex": hex::encode(buf),
        "fee": actual_fee as f64 / 1e8,
        "changepos": if change > 546 { funded.outputs.len() as i64 - 1 } else { -1 },
    }))
}

async fn rpc_signrawtransactionwithwallet(state: &RpcState, params: &Value) -> RpcResult {
    let wallet_arc = require_wallet!(state);

    let hex_str = params.get(0).and_then(Value::as_str)
        .ok_or((-32602, "missing raw transaction hex".to_string()))?;
    let raw = hex::decode(hex_str).map_err(|_| (-22, "TX decode failed".to_string()))?;
    let tx = Transaction::decode_from_slice(&raw)
        .map_err(|e| (-22, format!("TX decode failed: {e}")))?;

    let w = wallet_arc.read().await;
    let signed = w.sign_transaction(&tx).map_err(|e| (-1, e.to_string()))?;
    drop(w);

    let mut buf = Vec::new();
    signed.encode(&mut buf).map_err(|e| (-22, e.to_string()))?;
    Ok(json!({
        "hex": hex::encode(buf),
        "complete": true,
    }))
}

async fn rpc_dumpprivkey(state: &RpcState, params: &Value) -> RpcResult {
    let wallet_arc = require_wallet!(state);

    let address = params.get(0).and_then(Value::as_str)
        .ok_or((-32602, "missing address".to_string()))?;

    let w = wallet_arc.read().await;
    let wif = w.dump_privkey(address).map_err(|e| (-4, e.to_string()))?;
    Ok(json!(wif))
}

async fn rpc_importprivkey(state: &RpcState, params: &Value) -> RpcResult {
    let wallet_arc = require_wallet!(state);

    let wif = params.get(0).and_then(Value::as_str)
        .ok_or((-32602, "missing WIF private key".to_string()))?;
    let label = params.get(1).and_then(Value::as_str).unwrap_or("");

    let mut w = wallet_arc.write().await;
    let address = w.import_wif(wif, label).map_err(|e| (-5, e.to_string()))?;
    Ok(json!(address))
}

async fn rpc_getwalletinfo(state: &RpcState) -> RpcResult {
    let wallet_arc = require_wallet!(state);
    let w = wallet_arc.read().await;
    let (confirmed, unconfirmed) = w.balance();
    Ok(json!({
        "walletname":       "rbtc-wallet",
        "walletversion":    1,
        "balance":          confirmed as f64 / 1e8,
        "unconfirmed_balance": unconfirmed as f64 / 1e8,
        "txcount":          w.utxo_count(),
        "keypoolsize":      w.address_count(),
    }))
}

// ── Mining RPC implementations ────────────────────────────────────────────────

/// Build a `BlockTemplate` from the current chain/mempool state.
async fn build_template(state: &RpcState, output_script: rbtc_primitives::script::Script) -> BlockTemplate {
    let chain = state.chain.read().await;
    let mempool = state.mempool.read().await;

    let prev_hash = chain.best_hash().unwrap_or(Hash256::ZERO);
    let next_height = chain.height() + 1;
    let bits = chain.next_required_bits();

    let (transactions, fees) = TxSelector::select(&mempool);

    BlockTemplate::new(
        0x2000_0000, // version
        prev_hash,
        bits,
        next_height,
        fees,
        transactions,
        output_script,
    )
}

async fn rpc_getblocktemplate(state: &RpcState, _params: &Value) -> RpcResult {
    let chain = state.chain.read().await;
    let prev_hash = chain.best_hash().unwrap_or(Hash256::ZERO);
    let next_height = chain.height() + 1;
    let bits = chain.next_required_bits();
    let mtp = chain.median_time_past(chain.height());
    drop(chain);

    let mempool = state.mempool.read().await;
    let (transactions, fees) = TxSelector::select(&mempool);
    drop(mempool);

    let coinbase_value = rbtc_consensus::tx_verify::block_subsidy(next_height) + fees;

    // Build target hex (big-endian)
    let mut target_bytes = nbits_to_target(bits);
    target_bytes.reverse();
    let target_hex = hex::encode(target_bytes);

    // Encode each selected transaction
    let tx_entries: Vec<Value> = transactions.iter().map(|tx| {
        let mut buf = Vec::new();
        tx.encode(&mut buf).unwrap_or_default();
        let mut legacy_buf = Vec::new();
        tx.encode_legacy(&mut legacy_buf).unwrap_or_default();
        let txid = rbtc_crypto::sha256d(&legacy_buf).to_hex();
        json!({
            "data":   hex::encode(&buf),
            "txid":   txid,
            "fee":    0u64,   // fees per-tx not tracked in mempool entry here
            "weight": tx.weight(),
        })
    }).collect();

    let curtime = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u64;

    Ok(json!({
        "version":           0x2000_0000i64,
        "rules":             ["csv", "segwit"],
        "previousblockhash": prev_hash.to_hex(),
        "transactions":      tx_entries,
        "coinbaseaux":       {},
        "coinbasevalue":     coinbase_value,
        "longpollid":        prev_hash.to_hex(),
        "target":            target_hex,
        "mintime":           mtp,
        "mutable":           ["time", "transactions", "prevblock"],
        "noncerange":        "00000000ffffffff",
        "sigoplimit":        80_000u64,
        "sizelimit":         4_000_000u64,
        "weightlimit":       4_000_000u64,
        "curtime":           curtime,
        "bits":              format!("{:08x}", bits),
        "height":            next_height,
    }))
}

async fn rpc_submitblock(state: &RpcState, params: &Value) -> RpcResult {
    let hex_str = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "expected hex-encoded block".to_string()))?;

    let raw = hex::decode(hex_str).map_err(|_| (-22, "block decode failed".to_string()))?;
    let block = Block::decode_from_slice(&raw)
        .map_err(|e| (-22, format!("block decode failed: {e}")))?;

    state
        .submit_block_tx
        .send(block)
        .map_err(|_| (-1, "node channel closed".to_string()))?;

    Ok(json!(null))
}

async fn rpc_generatetoaddress(state: &RpcState, params: &Value) -> RpcResult {
    let nblocks = params
        .get(0)
        .and_then(Value::as_u64)
        .ok_or((-32602, "expected nblocks".to_string()))? as usize;
    let address = params
        .get(1)
        .and_then(Value::as_str)
        .ok_or((-32602, "expected address".to_string()))?;

    let output_script = address_to_script(address)
        .map_err(|e| (-5, format!("invalid address: {e}")))?;

    let mut block_hashes: Vec<String> = Vec::with_capacity(nblocks);

    for _ in 0..nblocks {
        let template = build_template(state, output_script.clone()).await;

        // Mine on a blocking thread so we don't stall the async runtime.
        let template_clone = template.clone();
        let block = tokio::task::spawn_blocking(move || mine_block(&template_clone))
            .await
            .map_err(|e| (-1, format!("mining task failed: {e}")))?;

        // Record the hash before moving block into the channel.
        let hash = {
            use rbtc_consensus::chain::header_hash;
            header_hash(&block.header).to_hex()
        };

        state
            .submit_block_tx
            .send(block)
            .map_err(|_| (-1, "node channel closed".to_string()))?;

        block_hashes.push(hash);
        info!("generatetoaddress: mined block {}", block_hashes.last().unwrap());

        // Brief yield so the node event loop can process the submitted block
        // and update its chain state before we build the next template.
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }

    Ok(json!(block_hashes))
}

async fn rpc_generate(state: &RpcState, params: &Value) -> RpcResult {
    let wallet_arc = require_wallet!(state);

    let nblocks = params
        .get(0)
        .and_then(Value::as_u64)
        .ok_or((-32602, "expected nblocks".to_string()))? as usize;

    // Get the wallet's default (most recent) P2WPKH address.
    let address = {
        let mut w = wallet_arc.write().await;
        w.new_address(AddressType::SegWit)
            .map_err(|e| (-1, e.to_string()))?
    };

    let fake_params = json!([nblocks, address]);
    rpc_generatetoaddress(state, &fake_params).await
}

async fn rpc_getmininginfo(state: &RpcState) -> RpcResult {
    let chain = state.chain.read().await;
    let height = chain.height();
    let bits = chain.next_required_bits();
    drop(chain);

    let mp = state.mempool.read().await;
    let pooledtx = mp.len();
    drop(mp);

    // Difficulty = difficulty_1_target / current_target
    // difficulty_1_target (for mainnet genesis) = 0x00000000ffff0000…00 (LE)
    let difficulty = bits_to_difficulty(bits);

    let networkhashps = estimate_network_hashps(state, 120).await;

    Ok(json!({
        "blocks":             height,
        "currentblockweight": 0u64,
        "currentblocktx":     0u64,
        "difficulty":         difficulty,
        "networkhashps":      networkhashps,
        "pooledtx":           pooledtx,
        "chain":              state.network_name,
    }))
}

async fn rpc_getnetworkhashps(state: &RpcState, params: &Value) -> RpcResult {
    let nblocks = params.get(0).and_then(Value::as_u64).unwrap_or(120) as u32;
    let hashps = estimate_network_hashps(state, nblocks).await;
    Ok(json!(hashps))
}

async fn rpc_estimatesmartfee(state: &RpcState, params: &Value) -> RpcResult {
    let _conf_target = params.get(0).and_then(Value::as_u64).unwrap_or(6);

    let mp = state.mempool.read().await;
    let txids = mp.txids_by_fee_rate();

    // Median fee rate across mempool transactions (sat/vB)
    let fee_rate = if txids.is_empty() {
        1.0f64 // default floor
    } else {
        let rates: Vec<f64> = txids
            .iter()
            .filter_map(|id| mp.get(id))
            .map(|e| e.fee_rate as f64)
            .collect();
        let median_idx = rates.len() / 2;
        rates[median_idx]
    };

    Ok(json!({
        "feerate": fee_rate / 1000.0,   // convert sat/vB to BTC/kB
        "blocks":  _conf_target,
    }))
}

// ── Mining helpers ─────────────────────────────────────────────────────────────

/// Approximate difficulty from nBits.
/// difficulty = 0x00000000FFFF0000…/current_target (big-endian comparison).
fn bits_to_difficulty(bits: u32) -> f64 {
    // difficulty_1 target mantissa for mainnet genesis bits 0x1d00ffff
    const DIFF1_MANTISSA: f64 = 0x00ff_ff00 as f64;

    let exp = (bits >> 24) as i32;
    let mantissa = (bits & 0x007f_ffff) as f64;
    if mantissa == 0.0 {
        return 0.0;
    }

    // difficulty ≈ diff1_mantissa / mantissa × 256^(diff1_exp - exp)
    // diff1_exp = 0x1d - 3 + 1 = 29 (index of MSB in LE target)
    let diff1_exp: i32 = 29;
    let cur_exp = exp - 3; // index of MSB
    let exp_diff = diff1_exp - cur_exp;
    let scale = 256f64.powi(exp_diff);
    DIFF1_MANTISSA / mantissa * scale
}

/// Estimate the network hashrate from the last `nblocks` blocks.
/// hashrate ≈ difficulty × 2^32 / avg_block_time_seconds
async fn estimate_network_hashps(state: &RpcState, nblocks: u32) -> f64 {
    let chain = state.chain.read().await;
    let height = chain.height();

    if height == 0 || nblocks == 0 {
        return 0.0;
    }

    let end_height = height;
    let start_height = end_height.saturating_sub(nblocks.min(height));

    let end_time = chain.get_ancestor_time(end_height).unwrap_or(0) as f64;
    let start_time = chain.get_ancestor_time(start_height).unwrap_or(0) as f64;
    let elapsed = end_time - start_time;

    if elapsed <= 0.0 {
        return 0.0;
    }

    let bits = chain.next_required_bits();
    let difficulty = bits_to_difficulty(bits);
    let blocks_in_period = (end_height - start_height) as f64;

    difficulty * 4_294_967_296.0 * blocks_in_period / elapsed
}

// ── Address index RPCs ────────────────────────────────────────────────────────

/// Resolve a Bitcoin address string to its scriptPubKey bytes.
/// Delegates to `rbtc-wallet`'s address_to_script; returns RPC error on failure.
fn resolve_script(address: &str) -> std::result::Result<Vec<u8>, (i32, String)> {
    address_to_script(address)
        .map(|s| s.0)
        .map_err(|e| (-8, format!("Invalid address: {e}")))
}

/// `getaddresstxids address [{"start":N,"end":M}]`
/// Returns a list of txids (hex strings) for all transactions that produced
/// an output to `address`, ordered by block height ascending.
async fn rpc_getaddresstxids(state: &RpcState, params: &Value) -> RpcResult {
    let address = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "Expected address string".to_string()))?;

    let script = resolve_script(address)?;

    let filter_start = params.get(1).and_then(|v| v.get("start")).and_then(Value::as_u64);
    let filter_end   = params.get(1).and_then(|v| v.get("end")).and_then(Value::as_u64);

    let addr_idx = AddrIndexStore::new(&state.db);
    let entries = addr_idx
        .iter_by_script(&script)
        .map_err(|e| (-5, format!("addr index error: {e}")))?;

    let txids: Vec<Value> = entries
        .into_iter()
        .filter(|e| {
            let h = e.height as u64;
            filter_start.map_or(true, |s| h >= s) && filter_end.map_or(true, |en| h <= en)
        })
        .map(|e| json!(e.txid.to_hex()))
        .collect();

    Ok(json!(txids))
}

/// `getaddressutxos address`
/// Returns all unspent outputs controlled by `address`:
/// `[{txid, vout, value, height, confirmations}, …]`
async fn rpc_getaddressutxos(state: &RpcState, params: &Value) -> RpcResult {
    let address = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "Expected address string".to_string()))?;

    let script = resolve_script(address)?;

    let addr_idx = AddrIndexStore::new(&state.db);
    let entries = addr_idx
        .iter_by_script(&script)
        .map_err(|e| (-5, format!("addr index error: {e}")))?;

    let block_store = BlockStore::new(&state.db);
    let chain = state.chain.read().await;
    let best_height = chain.height();

    let mut utxos = Vec::new();

    for entry in entries {
        // Load the block to read the specific output
        let block_hash = match chain.get_ancestor_hash(entry.height) {
            Some(h) => h,
            None => continue,
        };
        let block = match block_store.get_block(&block_hash).ok().flatten() {
            Some(b) => b,
            None => continue,
        };
        let tx = match block.transactions.get(entry.tx_offset as usize) {
            Some(t) => t,
            None => continue,
        };

        // Check each output of this tx against our script
        for (vout, output) in tx.outputs.iter().enumerate() {
            if output.script_pubkey.0 != script {
                continue;
            }
            // Build the OutPoint and check it's still in the UTXO set
            let mut txid_buf = Vec::new();
            tx.encode_legacy(&mut txid_buf).ok();
            let txid = sha256d(&txid_buf);
            let outpoint = OutPoint { txid, vout: vout as u32 };
            if chain.utxos.get(&outpoint).is_some() {
                let confirmations = best_height.saturating_sub(entry.height) + 1;
                utxos.push(json!({
                    "txid": txid.to_hex(),
                    "vout": vout,
                    "value": output.value,
                    "height": entry.height,
                    "confirmations": confirmations,
                }));
            }
        }
    }

    Ok(json!(utxos))
}

/// `getaddressbalance address`
/// Returns `{balance, received}` in satoshis.
/// `balance`  = sum of all unspent outputs.
/// `received` = sum of all outputs ever sent to this address (spent + unspent).
async fn rpc_getaddressbalance(state: &RpcState, params: &Value) -> RpcResult {
    let address = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "Expected address string".to_string()))?;

    let script = resolve_script(address)?;

    let addr_idx = AddrIndexStore::new(&state.db);
    let entries = addr_idx
        .iter_by_script(&script)
        .map_err(|e| (-5, format!("addr index error: {e}")))?;

    let block_store = BlockStore::new(&state.db);
    let chain = state.chain.read().await;

    let mut balance: u64 = 0;
    let mut received: u64 = 0;

    for entry in entries {
        let block_hash = match chain.get_ancestor_hash(entry.height) {
            Some(h) => h,
            None => continue,
        };
        let block = match block_store.get_block(&block_hash).ok().flatten() {
            Some(b) => b,
            None => continue,
        };
        let tx = match block.transactions.get(entry.tx_offset as usize) {
            Some(t) => t,
            None => continue,
        };

        let mut txid_buf = Vec::new();
        tx.encode_legacy(&mut txid_buf).ok();
        let txid = sha256d(&txid_buf);

        for (vout, output) in tx.outputs.iter().enumerate() {
            if output.script_pubkey.0 != script {
                continue;
            }
            received += output.value;
            let outpoint = OutPoint { txid, vout: vout as u32 };
            if chain.utxos.get(&outpoint).is_some() {
                balance += output.value;
            }
        }
    }

    Ok(json!({ "balance": balance, "received": received }))
}

// ── Server startup ────────────────────────────────────────────────────────────

/// Start the RPC server on the given address (e.g. "127.0.0.1:8332").
pub async fn start_rpc_server(addr: &str, state: RpcState) -> Result<()> {
    let app = rpc_router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("JSON-RPC server listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
