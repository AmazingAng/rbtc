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
use tokio::sync::{mpsc, oneshot, RwLock};
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
use rbtc_psbt::Psbt;
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
    /// Channel for node-management commands that must run on the node loop.
    pub control_tx: mpsc::UnboundedSender<RpcNodeCommand>,
}

pub enum RpcNodeCommand {
    InvalidateBlock {
        hash: Hash256,
        reply: oneshot::Sender<std::result::Result<(), String>>,
    },
    ReconsiderBlock {
        hash: Hash256,
        reply: oneshot::Sender<std::result::Result<(), String>>,
    },
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
        "invalidateblock"            => rpc_invalidateblock(&state, &params).await,
        "reconsiderblock"            => rpc_reconsiderblock(&state, &params).await,
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
        // PSBT (BIP174)
        "createpsbt"                 => rpc_createpsbt(&state, &params).await,
        "walletprocesspsbt"          => rpc_walletprocesspsbt(&state, &params).await,
        "finalizepsbt"               => rpc_finalizepsbt(&state, &params).await,
        "combinepsbt"                => rpc_combinepsbt(&state, &params).await,
        "decodepsbt"                 => rpc_decodepsbt(&state, &params).await,
        "analyzepsbt"                => rpc_analyzepsbt(&state, &params).await,
        // Chain (Phase D)
        "getchaintips"               => rpc_getchaintips(&state).await,
        "getblockstats"              => rpc_getblockstats(&state, &params).await,
        // Mempool (Phase D)
        "getmempoolentry"            => rpc_getmempoolentry(&state, &params).await,
        "getmempoolancestors"        => rpc_getmempoolancestors(&state, &params).await,
        "getmempooldescendants"      => rpc_getmempooldescendants(&state, &params).await,
        "testmempoolaccept"          => rpc_testmempoolaccept(&state, &params).await,
        // Utility (Phase D)
        "validateaddress"            => rpc_validateaddress(&state, &params).await,
        "decoderawtransaction"       => rpc_decoderawtransaction(&state, &params).await,
        "decodescript"               => rpc_decodescript(&state, &params).await,
        "createmultisig"             => rpc_createmultisig(&state, &params).await,
        "verifymessage"              => rpc_verifymessage(&state, &params).await,
        "signmessagewithprivkey"     => rpc_signmessagewithprivkey(&state, &params).await,
        // Wallet (Phase F)
        "dumpwallet"                 => rpc_dumpwallet(&state, &params).await,
        "importwallet"               => rpc_importwallet(&state, &params).await,
        "getdescriptorinfo"          => rpc_getdescriptorinfo(&state, &params).await,
        "deriveaddresses"            => rpc_deriveaddresses(&state, &params).await,
        // Network (Phase D)
        "getnetworkinfo"             => rpc_getnetworkinfo(&state).await,
        "getpeerinfo"                => rpc_getpeerinfo(&state).await,
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

async fn rpc_invalidateblock(state: &RpcState, params: &Value) -> RpcResult {
    let hash_hex = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "Invalid params: expected block hash".to_string()))?;
    let hash = Hash256::from_hex(hash_hex)
        .map_err(|_| (-8, "Invalid block hash".to_string()))?;

    let (reply_tx, reply_rx) = oneshot::channel();
    state
        .control_tx
        .send(RpcNodeCommand::InvalidateBlock { hash, reply: reply_tx })
        .map_err(|_| (-1, "node channel closed".to_string()))?;

    match reply_rx.await {
        Ok(Ok(())) => Ok(json!(null)),
        Ok(Err(e)) => Err((-1, e)),
        Err(_) => Err((-1, "node command dropped".to_string())),
    }
}

async fn rpc_reconsiderblock(state: &RpcState, params: &Value) -> RpcResult {
    let hash_hex = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "Invalid params: expected block hash".to_string()))?;
    let hash = Hash256::from_hex(hash_hex)
        .map_err(|_| (-8, "Invalid block hash".to_string()))?;

    let (reply_tx, reply_rx) = oneshot::channel();
    state
        .control_tx
        .send(RpcNodeCommand::ReconsiderBlock { hash, reply: reply_tx })
        .map_err(|_| (-1, "node channel closed".to_string()))?;

    match reply_rx.await {
        Ok(Ok(())) => Ok(json!(null)),
        Ok(Err(e)) => Err((-1, e)),
        Err(_) => Err((-1, "node command dropped".to_string())),
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

// ── PSBT RPC methods (BIP174) ─────────────────────────────────────────────────

/// `createpsbt` — Creator role.
///
/// Params: [ [{txid, vout, sequence?}, ...], [{address: amount_sats}, ...], locktime? ]
async fn rpc_createpsbt(_state: &RpcState, params: &Value) -> RpcResult {
    let inputs_raw = params.get(0)
        .and_then(|v| v.as_array())
        .ok_or((-8, "params[0] must be array of inputs".to_string()))?;
    let outputs_raw = params.get(1)
        .and_then(|v| v.as_object())
        .ok_or((-8, "params[1] must be object of {address: sats}".to_string()))?;
    let locktime = params.get(2).and_then(|v| v.as_u64()).unwrap_or(0) as u32;

    use rbtc_primitives::{hash::Hash256, transaction::{TxIn, TxOut}};
    let mut inputs = Vec::new();
    for inp in inputs_raw {
        let txid_hex = inp.get("txid").and_then(|v| v.as_str())
            .ok_or((-8, "input missing txid".to_string()))?;
        let vout = inp.get("vout").and_then(|v| v.as_u64())
            .ok_or((-8, "input missing vout".to_string()))? as u32;
        let sequence = inp.get("sequence").and_then(|v| v.as_u64())
            .unwrap_or(0xffffffff) as u32;
        let txid_bytes = hex::decode(txid_hex)
            .map_err(|_| (-8, "invalid txid hex".to_string()))?;
        if txid_bytes.len() != 32 {
            return Err((-8, "txid must be 32 bytes".to_string()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&txid_bytes);
        inputs.push(TxIn {
            previous_output: rbtc_primitives::transaction::OutPoint { txid: Hash256(arr), vout },
            script_sig: rbtc_primitives::script::Script::new(),
            sequence,
            witness: vec![],
        });
    }

    let mut txouts = Vec::new();
    for (addr, amount_val) in outputs_raw {
        let amount = amount_val.as_u64()
            .ok_or((-8, format!("amount for {addr} must be integer sats")))?;
        let script = address_to_script(addr)
            .map_err(|e| (-8, format!("invalid address {addr}: {e}")))?;
        txouts.push(TxOut { value: amount, script_pubkey: script });
    }

    let tx = rbtc_primitives::transaction::Transaction {
        version: 2, inputs, outputs: txouts, lock_time: locktime,
    };
    let psbt = Psbt::create(tx);
    Ok(json!(psbt.to_base64()))
}

/// `walletprocesspsbt` — Updater + Signer using the node's built-in wallet.
async fn rpc_walletprocesspsbt(state: &RpcState, params: &Value) -> RpcResult {
    let b64 = params.get(0).and_then(|v| v.as_str())
        .ok_or((-8, "params[0] must be PSBT base64 string".to_string()))?;
    let mut psbt = Psbt::from_base64(b64)
        .map_err(|e| (-8, format!("PSBT decode: {e}")))?;

    let wallet_arc = state.wallet.as_ref()
        .ok_or((-18, "Wallet not loaded".to_string()))?;
    let wallet = wallet_arc.read().await;

    // For each input, try to sign with a matching wallet key
    for i in 0..psbt.inputs.len() {
        // Determine the scriptPubKey to match
        let spk = if let Some(txout) = psbt.inputs[i].witness_utxo.as_ref() {
            txout.script_pubkey.as_bytes().to_vec()
        } else if let Some(tx) = psbt.inputs[i].non_witness_utxo.as_ref() {
            let vout = psbt.global.unsigned_tx.inputs[i].previous_output.vout as usize;
            tx.outputs.get(vout).map(|o| o.script_pubkey.as_bytes().to_vec())
                .unwrap_or_default()
        } else {
            continue;
        };

        // Check if we have a key that corresponds to this scriptPubKey
        if let Some(sk) = wallet.key_for_script(&spk) {
            psbt.sign_input(i, &sk)
                .map_err(|e| (-4, format!("signing error: {e}")))?;
        }
    }

    Ok(json!({
        "psbt": psbt.to_base64(),
        "complete": psbt.inputs.iter().all(|i| i.is_finalized() || !i.partial_sigs.is_empty())
    }))
}

/// `finalizepsbt` — Finalizer + Extractor.
async fn rpc_finalizepsbt(_state: &RpcState, params: &Value) -> RpcResult {
    let b64 = params.get(0).and_then(|v| v.as_str())
        .ok_or((-8, "params[0] must be PSBT base64 string".to_string()))?;
    let mut psbt = Psbt::from_base64(b64)
        .map_err(|e| (-8, format!("PSBT decode: {e}")))?;

    psbt.finalize().map_err(|e| (-8, format!("finalize error: {e}")))?;

    let complete = psbt.inputs.iter().all(|i| i.is_finalized());
    if complete {
        let tx = psbt.clone().extract_tx()
            .map_err(|e| (-8, format!("extract error: {e}")))?;
        let mut buf = Vec::new();
        tx.encode(&mut buf).ok();
        Ok(json!({ "hex": hex::encode(&buf), "complete": true }))
    } else {
        Ok(json!({ "psbt": psbt.to_base64(), "complete": false }))
    }
}

/// `combinepsbt` — Combiner.
async fn rpc_combinepsbt(_state: &RpcState, params: &Value) -> RpcResult {
    let psbts_raw = params.get(0)
        .and_then(|v| v.as_array())
        .ok_or((-8, "params[0] must be array of PSBT base64 strings".to_string()))?;

    if psbts_raw.is_empty() {
        return Err((-8, "at least one PSBT required".to_string()));
    }

    let mut combined = Psbt::from_base64(psbts_raw[0].as_str().unwrap_or(""))
        .map_err(|e| (-8, format!("PSBT[0] decode: {e}")))?;

    for (idx, val) in psbts_raw.iter().enumerate().skip(1) {
        let other = Psbt::from_base64(val.as_str().unwrap_or(""))
            .map_err(|e| (-8, format!("PSBT[{idx}] decode: {e}")))?;
        combined.combine(other)
            .map_err(|e| (-8, format!("combine error at [{idx}]: {e}")))?;
    }

    Ok(json!(combined.to_base64()))
}

/// `decodepsbt` — human-readable PSBT inspection.
async fn rpc_decodepsbt(_state: &RpcState, params: &Value) -> RpcResult {
    let b64 = params.get(0).and_then(|v| v.as_str())
        .ok_or((-8, "params[0] must be PSBT base64 string".to_string()))?;
    let psbt = Psbt::from_base64(b64)
        .map_err(|e| (-8, format!("PSBT decode: {e}")))?;

    let inputs: Vec<Value> = psbt.inputs.iter().enumerate().map(|(i, inp)| {
        let mut obj = json!({
            "has_non_witness_utxo": inp.non_witness_utxo.is_some(),
            "has_witness_utxo": inp.witness_utxo.is_some(),
            "partial_sigs": inp.partial_sigs.len(),
            "finalized": inp.is_finalized(),
        });
        if let Some(sh) = inp.sighash_type {
            obj["sighash_type"] = json!(sh);
        }
        let _ = i;
        obj
    }).collect();

    let unsigned_txid = {
        let mut buf = Vec::new();
        psbt.global.unsigned_tx.encode_legacy(&mut buf).ok();
        sha256d(&buf).to_hex()
    };

    Ok(json!({
        "tx": { "txid": unsigned_txid },
        "inputs": inputs,
        "output_count": psbt.outputs.len(),
        "version": psbt.global.version,
    }))
}

/// `analyzepsbt` — per-input signing status report.
async fn rpc_analyzepsbt(_state: &RpcState, params: &Value) -> RpcResult {
    let b64 = params.get(0).and_then(|v| v.as_str())
        .ok_or((-8, "params[0] must be PSBT base64 string".to_string()))?;
    let psbt = Psbt::from_base64(b64)
        .map_err(|e| (-8, format!("PSBT decode: {e}")))?;

    let inputs: Vec<Value> = psbt.inputs.iter().map(|inp| {
        let status = if inp.is_finalized() {
            "finalized"
        } else if !inp.partial_sigs.is_empty() {
            "partially_signed"
        } else if inp.witness_utxo.is_some() || inp.non_witness_utxo.is_some() {
            "ready_to_sign"
        } else {
            "missing_utxo"
        };
        json!({ "status": status, "partial_sigs": inp.partial_sigs.len() })
    }).collect();

    let all_finalized = psbt.inputs.iter().all(|i| i.is_finalized());
    Ok(json!({ "inputs": inputs, "estimated_complete": all_finalized }))
}

// ── Phase D: Chain RPCs ──────────────────────────────────────────────────────

async fn rpc_getchaintips(state: &RpcState) -> RpcResult {
    let chain = state.chain.read().await;
    // Collect all block hashes that are NOT parents of any other block (i.e. tips)
    let all_hashes: std::collections::HashSet<Hash256> =
        chain.block_index.keys().copied().collect();
    let parent_hashes: std::collections::HashSet<Hash256> = chain
        .block_index
        .values()
        .map(|bi| bi.header.prev_block)
        .collect();
    let tips: Vec<Hash256> = all_hashes
        .difference(&parent_hashes)
        .copied()
        .collect();
    let best = chain.best_tip;
    let best_height = chain.height();

    let mut result = Vec::new();
    for tip_hash in &tips {
        if let Some(bi) = chain.block_index.get(tip_hash) {
            let is_active = Some(*tip_hash) == best;
            let status = if is_active {
                "active"
            } else if bi.status == rbtc_consensus::chain::BlockStatus::Invalid {
                "invalid"
            } else if bi.height <= best_height {
                "valid-fork"
            } else {
                "valid-headers"
            };
            // Walk back to find the fork point with the active chain
            let mut branch_len = 0u32;
            if !is_active {
                let mut cur = *tip_hash;
                while let Some(idx) = chain.block_index.get(&cur) {
                    if idx.height < chain.active_chain.len() as u32
                        && chain.active_chain[idx.height as usize] == cur
                    {
                        break;
                    }
                    branch_len += 1;
                    cur = idx.header.prev_block;
                    if cur == Hash256::ZERO {
                        break;
                    }
                }
            }
            result.push(json!({
                "height": bi.height,
                "hash": bi.hash.to_hex(),
                "branchlen": branch_len,
                "status": status,
            }));
        }
    }
    Ok(json!(result))
}

async fn rpc_getblockstats(state: &RpcState, params: &Value) -> RpcResult {
    // Accept height (number) or hash (string)
    let chain = state.chain.read().await;
    let block_hash = if let Some(h) = params.get(0).and_then(Value::as_u64) {
        let height = h as u32;
        if (height as usize) >= chain.active_chain.len() {
            return Err((-8, format!("Block height {height} out of range")));
        }
        chain.active_chain[height as usize]
    } else if let Some(s) = params.get(0).and_then(Value::as_str) {
        Hash256::from_hex(s).map_err(|_| (-8, "Invalid hash".to_string()))?
    } else {
        return Err((-32602, "Expected height or hash".to_string()));
    };

    let bi = chain
        .block_index
        .get(&block_hash)
        .ok_or((-5, "Block not found".to_string()))?;
    let height = bi.height;
    let block_time = bi.header.time;
    drop(chain);

    let block_store = BlockStore::new(&state.db);
    let block = block_store
        .get_block(&block_hash)
        .map_err(|e| (-5, format!("block load error: {e}")))?
        .ok_or((-5, "Block data not found".to_string()))?;

    let txs = &block.transactions;
    let total_out: u64 = txs.iter().map(|t| t.output_value()).sum();
    let total_weight: u64 = txs.iter().map(|t| t.weight()).sum();
    let total_size: usize = txs
        .iter()
        .map(|t| {
            let mut buf = Vec::new();
            let _ = t.encode_segwit(&mut buf);
            buf.len()
        })
        .sum();
    let subsidy = if height < 64 * 210_000 {
        (50_0000_0000u64) >> (height / 210_000)
    } else {
        0
    };
    // We can't compute per-tx fees without UTXO lookups for inputs,
    // so we provide aggregate info and zero fee-rate stats.
    let total_fee = txs
        .first()
        .map(|cb| cb.output_value().saturating_sub(subsidy))
        .unwrap_or(0);

    Ok(json!({
        "avgfee": if txs.len() > 1 { total_fee / (txs.len() as u64 - 1) } else { 0 },
        "avgfeerate": if total_weight > 0 { total_fee * 4 / total_weight } else { 0 },
        "height": height,
        "blockhash": block_hash.to_hex(),
        "total_out": total_out,
        "total_size": total_size,
        "total_weight": total_weight,
        "totalfee": total_fee,
        "txs": txs.len(),
        "subsidy": subsidy,
        "time": block_time,
    }))
}

// ── Phase D: Mempool RPCs ────────────────────────────────────────────────────

async fn rpc_getmempoolentry(state: &RpcState, params: &Value) -> RpcResult {
    let txid_hex = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "Expected txid".to_string()))?;
    let txid =
        Hash256::from_hex(txid_hex).map_err(|_| (-8, "Invalid txid".to_string()))?;
    let mp = state.mempool.read().await;
    let entry = mp
        .get(&txid)
        .ok_or((-5, format!("Transaction not in mempool")))?;
    let (anc_fee, anc_vsize) = mp.ancestor_package(&txid);
    let anc_count = {
        // count ancestors by walking parents
        let mut count = 0u64;
        let mut stack = vec![txid];
        let mut visited = std::collections::HashSet::new();
        while let Some(tid) = stack.pop() {
            if !visited.insert(tid) {
                continue;
            }
            if let Some(e) = mp.get(&tid) {
                if tid != txid {
                    count += 1;
                }
                for inp in &e.tx.inputs {
                    if mp.contains(&inp.previous_output.txid) {
                        stack.push(inp.previous_output.txid);
                    }
                }
            }
        }
        count
    };
    Ok(json!({
        "vsize": entry.vsize,
        "weight": entry.tx.weight(),
        "fee": format!("{:.8}", entry.fee as f64 / 1e8),
        "ancestorcount": anc_count + 1,
        "ancestorsize": anc_vsize,
        "ancestorfees": anc_fee,
        "bip125-replaceable": entry.signals_rbf,
    }))
}

async fn rpc_getmempoolancestors(state: &RpcState, params: &Value) -> RpcResult {
    let txid_hex = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "Expected txid".to_string()))?;
    let txid =
        Hash256::from_hex(txid_hex).map_err(|_| (-8, "Invalid txid".to_string()))?;
    let mp = state.mempool.read().await;
    if !mp.contains(&txid) {
        return Err((-5, "Transaction not in mempool".to_string()));
    }
    // Collect ancestors (excluding self)
    let mut ancestors = Vec::new();
    let mut stack = vec![txid];
    let mut visited = std::collections::HashSet::new();
    while let Some(tid) = stack.pop() {
        if !visited.insert(tid) {
            continue;
        }
        if let Some(e) = mp.get(&tid) {
            if tid != txid {
                ancestors.push(tid.to_hex());
            }
            for inp in &e.tx.inputs {
                if mp.contains(&inp.previous_output.txid) {
                    stack.push(inp.previous_output.txid);
                }
            }
        }
    }
    Ok(json!(ancestors))
}

async fn rpc_getmempooldescendants(state: &RpcState, params: &Value) -> RpcResult {
    let txid_hex = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "Expected txid".to_string()))?;
    let txid =
        Hash256::from_hex(txid_hex).map_err(|_| (-8, "Invalid txid".to_string()))?;
    let mp = state.mempool.read().await;
    if !mp.contains(&txid) {
        return Err((-5, "Transaction not in mempool".to_string()));
    }
    // Find all txs that transitively spend outputs of txid
    let mut descendants = Vec::new();
    let mut queue = vec![txid];
    let mut visited = std::collections::HashSet::new();
    visited.insert(txid);
    while let Some(tid) = queue.pop() {
        // Look for any mempool tx that spends an output of `tid`
        for other_txid in mp.txids() {
            if visited.contains(&other_txid) {
                continue;
            }
            if let Some(e) = mp.get(&other_txid) {
                if e.tx
                    .inputs
                    .iter()
                    .any(|inp| inp.previous_output.txid == tid)
                {
                    visited.insert(other_txid);
                    descendants.push(other_txid.to_hex());
                    queue.push(other_txid);
                }
            }
        }
    }
    Ok(json!(descendants))
}

async fn rpc_testmempoolaccept(state: &RpcState, params: &Value) -> RpcResult {
    let raw_txs = params
        .get(0)
        .and_then(Value::as_array)
        .ok_or((-32602, "Expected array of hex strings".to_string()))?;

    let mut results = Vec::new();
    for raw in raw_txs {
        let hex_str = raw
            .as_str()
            .ok_or((-32602, "Expected hex string".to_string()))?;
        let bytes =
            hex::decode(hex_str).map_err(|_| (-22, "Invalid hex".to_string()))?;
        let tx = Transaction::decode(&mut &bytes[..])
            .map_err(|e| (-22, format!("TX decode failed: {e}")))?;

        let mut txid_buf = Vec::new();
        let _ = tx.encode_legacy(&mut txid_buf);
        let txid = rbtc_crypto::sha256d(&txid_buf);

        // Check basic acceptance without actually inserting
        let mp = state.mempool.read().await;
        if mp.contains(&txid) {
            results.push(json!({
                "txid": txid.to_hex(),
                "allowed": false,
                "reject-reason": "txn-already-in-mempool",
            }));
            continue;
        }

        if tx.is_coinbase() {
            results.push(json!({
                "txid": txid.to_hex(),
                "allowed": false,
                "reject-reason": "coinbase",
            }));
            continue;
        }

        // Check inputs exist
        let chain = state.chain.read().await;
        let mut all_inputs_found = true;
        for inp in &tx.inputs {
            let in_chain = chain.utxos.get(&inp.previous_output).is_some();
            let in_mempool = mp.contains(&inp.previous_output.txid);
            if !in_chain && !in_mempool {
                all_inputs_found = false;
                break;
            }
        }
        drop(chain);
        drop(mp);

        if !all_inputs_found {
            results.push(json!({
                "txid": txid.to_hex(),
                "allowed": false,
                "reject-reason": "missing-inputs",
            }));
        } else {
            let vsize = tx.vsize();
            let fees = {
                let chain = state.chain.read().await;
                let mp = state.mempool.read().await;
                let mut total_in = 0u64;
                for inp in &tx.inputs {
                    if let Some(utxo) = chain.utxos.get(&inp.previous_output) {
                        total_in += utxo.txout.value;
                    } else if let Some(parent) = mp.get(&inp.previous_output.txid) {
                        if let Some(out) =
                            parent.tx.outputs.get(inp.previous_output.vout as usize)
                        {
                            total_in += out.value;
                        }
                    }
                }
                total_in.saturating_sub(tx.output_value())
            };
            results.push(json!({
                "txid": txid.to_hex(),
                "allowed": true,
                "vsize": vsize,
                "fees": {
                    "base": format!("{:.8}", fees as f64 / 1e8),
                },
            }));
        }
    }
    Ok(json!(results))
}

// ── Phase D: Utility RPCs ────────────────────────────────────────────────────

fn classify_script(script: &rbtc_primitives::script::Script) -> &'static str {
    if script.is_p2pkh() {
        "pubkeyhash"
    } else if script.is_p2sh() {
        "scripthash"
    } else if script.is_p2wpkh() {
        "witness_v0_keyhash"
    } else if script.is_p2wsh() {
        "witness_v0_scripthash"
    } else if script.is_p2tr() {
        "witness_v1_taproot"
    } else if script.is_op_return() {
        "nulldata"
    } else if script.0.is_empty() {
        "nonstandard"
    } else {
        "nonstandard"
    }
}

async fn rpc_validateaddress(_state: &RpcState, params: &Value) -> RpcResult {
    let addr = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "Expected address".to_string()))?;

    match address_to_script(addr) {
        Ok(script) => {
            let is_witness = script.is_p2wpkh() || script.is_p2wsh() || script.is_p2tr();
            let witness_version = if script.is_p2wpkh() || script.is_p2wsh() {
                Some(0)
            } else if script.is_p2tr() {
                Some(1)
            } else {
                None
            };
            let mut result = json!({
                "isvalid": true,
                "address": addr,
                "scriptPubKey": hex::encode(&script.0),
                "isscript": script.is_p2sh(),
                "iswitness": is_witness,
            });
            if let Some(v) = witness_version {
                result["witness_version"] = json!(v);
            }
            Ok(result)
        }
        Err(_) => Ok(json!({
            "isvalid": false,
            "address": addr,
        })),
    }
}

async fn rpc_decoderawtransaction(_state: &RpcState, params: &Value) -> RpcResult {
    let hex_str = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "Expected hex string".to_string()))?;
    let bytes =
        hex::decode(hex_str).map_err(|_| (-22, "Invalid hex".to_string()))?;
    let tx = Transaction::decode(&mut &bytes[..])
        .map_err(|e| (-22, format!("TX decode failed: {e}")))?;

    let mut txid_buf = Vec::new();
    let _ = tx.encode_legacy(&mut txid_buf);
    let txid = rbtc_crypto::sha256d(&txid_buf);

    let vin: Vec<Value> = tx
        .inputs
        .iter()
        .map(|inp| {
            let mut v = json!({
                "txid": inp.previous_output.txid.to_hex(),
                "vout": inp.previous_output.vout,
                "scriptSig": {
                    "asm": "",
                    "hex": hex::encode(&inp.script_sig.0),
                },
                "sequence": inp.sequence,
            });
            if !inp.witness.is_empty() {
                v["txinwitness"] = json!(
                    inp.witness.iter().map(hex::encode).collect::<Vec<_>>()
                );
            }
            v
        })
        .collect();

    let vout: Vec<Value> = tx
        .outputs
        .iter()
        .enumerate()
        .map(|(n, out)| {
            json!({
                "value": format!("{:.8}", out.value as f64 / 1e8),
                "n": n,
                "scriptPubKey": {
                    "hex": hex::encode(&out.script_pubkey.0),
                    "type": classify_script(&out.script_pubkey),
                },
            })
        })
        .collect();

    Ok(json!({
        "txid": txid.to_hex(),
        "version": tx.version,
        "size": bytes.len(),
        "vsize": tx.vsize(),
        "weight": tx.weight(),
        "locktime": tx.lock_time,
        "vin": vin,
        "vout": vout,
    }))
}

async fn rpc_decodescript(_state: &RpcState, params: &Value) -> RpcResult {
    let hex_str = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "Expected hex string".to_string()))?;
    let bytes =
        hex::decode(hex_str).map_err(|_| (-22, "Invalid hex".to_string()))?;
    let script = rbtc_primitives::script::Script::from_bytes(bytes.clone());
    let script_type = classify_script(&script);

    // Compute P2SH address: hash160 of the script, then base58check
    let script_hash = rbtc_crypto::hash160(&bytes);
    let p2sh_hex = hex::encode(&script_hash.0);

    Ok(json!({
        "type": script_type,
        "p2sh": p2sh_hex,
        "hex": hex_str,
    }))
}

async fn rpc_createmultisig(_state: &RpcState, params: &Value) -> RpcResult {
    let nrequired = params
        .get(0)
        .and_then(Value::as_u64)
        .ok_or((-32602, "Expected nrequired".to_string()))? as u8;
    let keys = params
        .get(1)
        .and_then(Value::as_array)
        .ok_or((-32602, "Expected keys array".to_string()))?;

    if keys.is_empty() || keys.len() > 16 {
        return Err((-8, "Invalid number of keys".to_string()));
    }
    if nrequired == 0 || nrequired as usize > keys.len() {
        return Err((-8, "Invalid nrequired".to_string()));
    }

    // Build bare multisig script: OP_n <pubkey1> ... <pubkeyn> OP_m OP_CHECKMULTISIG
    let mut script_bytes = Vec::new();
    script_bytes.push(0x50 + nrequired); // OP_n
    for key_val in keys {
        let key_hex = key_val
            .as_str()
            .ok_or((-8, "Expected hex pubkey".to_string()))?;
        let key_bytes =
            hex::decode(key_hex).map_err(|_| (-8, "Invalid hex pubkey".to_string()))?;
        if key_bytes.len() != 33 && key_bytes.len() != 65 {
            return Err((-8, "Invalid pubkey length".to_string()));
        }
        script_bytes.push(key_bytes.len() as u8);
        script_bytes.extend_from_slice(&key_bytes);
    }
    script_bytes.push(0x50 + keys.len() as u8); // OP_m
    script_bytes.push(0xae); // OP_CHECKMULTISIG

    let script_hash = rbtc_crypto::hash160(&script_bytes);
    let redeem_script_hex = hex::encode(&script_bytes);

    Ok(json!({
        "address": hex::encode(&script_hash.0),
        "redeemScript": redeem_script_hex,
    }))
}

async fn rpc_verifymessage(_state: &RpcState, params: &Value) -> RpcResult {
    let _address = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "Expected address".to_string()))?;
    let _signature = params
        .get(1)
        .and_then(Value::as_str)
        .ok_or((-32602, "Expected signature".to_string()))?;
    let _message = params
        .get(2)
        .and_then(Value::as_str)
        .ok_or((-32602, "Expected message".to_string()))?;

    // Bitcoin message signing requires ECDSA recovery which needs
    // secp256k1 recovery feature. Return a stub for now.
    // Full implementation requires: hash the message with Bitcoin Signed Message
    // prefix, recover pubkey from compact sig, compare with address.
    Err((-1, "verifymessage not yet fully implemented".to_string()))
}

async fn rpc_signmessagewithprivkey(_state: &RpcState, params: &Value) -> RpcResult {
    let _privkey = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "Expected privkey".to_string()))?;
    let _message = params
        .get(1)
        .and_then(Value::as_str)
        .ok_or((-32602, "Expected message".to_string()))?;

    Err((-1, "signmessagewithprivkey not yet fully implemented".to_string()))
}

// ── Phase D: Network RPCs ────────────────────────────────────────────────────

async fn rpc_getnetworkinfo(_state: &RpcState) -> RpcResult {
    Ok(json!({
        "version": 270000,
        "subversion": "/rbtc:0.1.0/",
        "protocolversion": 70016,
        "localservices": "0000000000000409",
        "localrelay": true,
        "timeoffset": 0,
        "networkactive": true,
        "connections": 0,
        "networks": [
            { "name": "ipv4", "limited": false, "reachable": true },
            { "name": "ipv6", "limited": false, "reachable": true },
        ],
        "relayfee": 0.00001000,
        "incrementalfee": 0.00001000,
        "warnings": "",
    }))
}

async fn rpc_getpeerinfo(_state: &RpcState) -> RpcResult {
    // We don't have access to the peer manager from RpcState currently.
    // Return empty array; a future enhancement can pipe peer info through.
    Ok(json!([]))
}

// ── Phase F: Wallet descriptor & dump/import RPCs ────────────────────────────

/// `dumpwallet "filename"` — Dumps all wallet keys and addresses to a file.
async fn rpc_dumpwallet(state: &RpcState, params: &Value) -> RpcResult {
    let wallet = state.wallet.as_ref().ok_or((-18, "No wallet loaded".into()))?;
    let filename = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-1, "Missing filename parameter".into()))?;

    let w = wallet.read().await;
    let addresses = w.addresses();
    let mut lines = Vec::new();
    lines.push("# Wallet dump created by rbtc".to_string());
    lines.push(format!("# Addresses: {}", addresses.len()));

    for addr in &addresses {
        match w.dump_privkey(addr) {
            Ok(wif) => lines.push(format!("{wif} # addr={addr}")),
            Err(_) => lines.push(format!("# {addr} (imported, key not re-derivable)")),
        }
    }
    drop(w);

    std::fs::write(filename, lines.join("\n"))
        .map_err(|e| (-1, format!("Failed to write file: {e}")))?;

    Ok(json!({ "filename": filename }))
}

/// `importwallet "filename"` — Imports keys from a wallet dump file.
async fn rpc_importwallet(state: &RpcState, params: &Value) -> RpcResult {
    let wallet = state.wallet.as_ref().ok_or((-18, "No wallet loaded".into()))?;
    let filename = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-1, "Missing filename parameter".into()))?;

    let content = std::fs::read_to_string(filename)
        .map_err(|e| (-1, format!("Failed to read file: {e}")))?;

    let mut imported = 0usize;
    let mut w = wallet.write().await;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Format: WIF # optional comment
        let wif = line.split_whitespace().next().unwrap_or("");
        if !wif.is_empty() {
            match w.import_wif(wif, &format!("imported_{imported}")) {
                Ok(_) => imported += 1,
                Err(e) => {
                    warn!("rpc: importwallet: skipping key: {e}");
                }
            }
        }
    }

    Ok(json!({ "imported": imported }))
}

/// `getdescriptorinfo "descriptor"` — Analyse an output descriptor.
async fn rpc_getdescriptorinfo(_state: &RpcState, params: &Value) -> RpcResult {
    let desc_str = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-1, "Missing descriptor parameter".into()))?;

    let desc = rbtc_wallet::Descriptor::parse(desc_str)
        .map_err(|e| (-1, format!("Invalid descriptor: {e}")))?;

    Ok(json!({
        "descriptor": desc_str,
        "isrange": desc_str.contains('*'),
        "issolvable": true,
        "hasprivatekeys": false,
        "type": desc.descriptor_type(),
    }))
}

/// `deriveaddresses "descriptor" [range]` — Derive addresses from a descriptor.
async fn rpc_deriveaddresses(_state: &RpcState, params: &Value) -> RpcResult {
    let desc_str = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-1, "Missing descriptor parameter".into()))?;

    let desc = rbtc_wallet::Descriptor::parse(desc_str)
        .map_err(|e| (-1, format!("Invalid descriptor: {e}")))?;

    // Determine range
    let (start, end) = if let Some(range) = params.get(1) {
        if let Some(arr) = range.as_array() {
            let s = arr.first().and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let e = arr.get(1).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            (s, e)
        } else if let Some(n) = range.as_u64() {
            (0u32, n as u32)
        } else {
            (0u32, 0u32)
        }
    } else {
        (0u32, 0u32)
    };

    let mut addresses = Vec::new();
    for i in start..=end {
        let spk = desc
            .to_script(i)
            .map_err(|e| (-1, format!("Cannot derive at index {i}: {e}")))?;
        // Convert scriptPubKey to address string (best effort)
        let addr = script_to_address_string(&spk);
        addresses.push(json!(addr));
    }

    Ok(json!(addresses))
}

/// Best-effort conversion of a scriptPubKey to a hex representation.
/// For full address encoding, use the wallet's address module.
fn script_to_address_string(spk: &rbtc_primitives::script::Script) -> String {
    // Return the scriptPubKey hex — callers can decode as needed
    hex::encode(spk.as_bytes())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> (RpcState, tempfile::TempDir) {
        use rbtc_consensus::chain::ChainState;
        use rbtc_primitives::network::Network;

        let chain = ChainState::new(Network::Regtest);
        let mempool = rbtc_mempool::Mempool::new();
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let db = Database::open(tmpdir.path()).expect("open db");
        let (submit_tx, _submit_rx) = mpsc::unbounded_channel();
        let (control_tx, _control_rx) = mpsc::unbounded_channel();
        let state = RpcState {
            chain: Arc::new(RwLock::new(chain)),
            mempool: Arc::new(RwLock::new(mempool)),
            db: Arc::new(db),
            network_name: "regtest".to_string(),
            wallet: None,
            submit_block_tx: submit_tx,
            control_tx,
        };
        (state, tmpdir)
    }

    // ── classify_script ──────────────────────────────────────────────────

    #[test]
    fn classify_p2pkh() {
        // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        let mut s = vec![0x76, 0xa9, 0x14];
        s.extend_from_slice(&[0u8; 20]);
        s.extend_from_slice(&[0x88, 0xac]);
        let script = rbtc_primitives::script::Script::from_bytes(s);
        assert_eq!(classify_script(&script), "pubkeyhash");
    }

    #[test]
    fn classify_p2sh() {
        // OP_HASH160 <20 bytes> OP_EQUAL
        let mut s = vec![0xa9, 0x14];
        s.extend_from_slice(&[0u8; 20]);
        s.push(0x87);
        let script = rbtc_primitives::script::Script::from_bytes(s);
        assert_eq!(classify_script(&script), "scripthash");
    }

    #[test]
    fn classify_p2wpkh() {
        // OP_0 <20 bytes>
        let mut s = vec![0x00, 0x14];
        s.extend_from_slice(&[0u8; 20]);
        let script = rbtc_primitives::script::Script::from_bytes(s);
        assert_eq!(classify_script(&script), "witness_v0_keyhash");
    }

    #[test]
    fn classify_p2wsh() {
        // OP_0 <32 bytes>
        let mut s = vec![0x00, 0x20];
        s.extend_from_slice(&[0u8; 32]);
        let script = rbtc_primitives::script::Script::from_bytes(s);
        assert_eq!(classify_script(&script), "witness_v0_scripthash");
    }

    #[test]
    fn classify_p2tr() {
        // OP_1 <32 bytes>
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&[0u8; 32]);
        let script = rbtc_primitives::script::Script::from_bytes(s);
        assert_eq!(classify_script(&script), "witness_v1_taproot");
    }

    #[test]
    fn classify_op_return() {
        let script = rbtc_primitives::script::Script::from_bytes(vec![0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(classify_script(&script), "nulldata");
    }

    #[test]
    fn classify_empty() {
        let script = rbtc_primitives::script::Script::from_bytes(vec![]);
        assert_eq!(classify_script(&script), "nonstandard");
    }

    // ── decoderawtransaction ─────────────────────────────────────────────

    #[tokio::test]
    async fn decode_raw_transaction_coinbase() {
        let (state, _tmpdir) = test_state();
        // Minimal coinbase: version=1, 1 input (null outpoint), 1 output, locktime=0
        let hex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff03020000ffffffff0100f2052a010000000000000000";
        let result = rpc_decoderawtransaction(&state, &json!([hex])).await;
        assert!(result.is_ok(), "decode should succeed: {:?}", result);
        let val = result.unwrap();
        assert_eq!(val["version"], 1);
        assert_eq!(val["locktime"], 0);
        assert!(val["vin"].as_array().unwrap().len() >= 1);
        assert!(val["vout"].as_array().unwrap().len() >= 1);
        assert!(val["txid"].as_str().unwrap().len() == 64);
        assert!(val["weight"].as_u64().unwrap() > 0);
        assert!(val["vsize"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn decode_raw_transaction_invalid_hex() {
        let (state, _tmpdir) = test_state();
        let result = rpc_decoderawtransaction(&state, &json!(["zzzz"])).await;
        assert!(result.is_err());
    }

    // ── decodescript ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn decode_script_p2pkh() {
        let (state, _tmpdir) = test_state();
        // OP_DUP OP_HASH160 <20 zero bytes> OP_EQUALVERIFY OP_CHECKSIG
        let mut s = vec![0x76u8, 0xa9, 0x14];
        s.extend_from_slice(&[0u8; 20]);
        s.extend_from_slice(&[0x88, 0xac]);
        let hex = hex::encode(&s);
        let result = rpc_decodescript(&state, &json!([hex])).await.unwrap();
        assert_eq!(result["type"], "pubkeyhash");
        assert!(!result["p2sh"].as_str().unwrap().is_empty());
    }

    #[tokio::test]
    async fn decode_script_empty() {
        let (state, _tmpdir) = test_state();
        let result = rpc_decodescript(&state, &json!([""])).await.unwrap();
        assert_eq!(result["type"], "nonstandard");
    }

    // ── validateaddress ──────────────────────────────────────────────────

    #[tokio::test]
    async fn validate_address_invalid() {
        let (state, _tmpdir) = test_state();
        let result = rpc_validateaddress(&state, &json!(["not_an_address"])).await.unwrap();
        assert_eq!(result["isvalid"], false);
    }

    // ── createmultisig ───────────────────────────────────────────────────

    #[tokio::test]
    async fn create_multisig_1_of_2() {
        let (state, _tmpdir) = test_state();
        // Two dummy compressed pubkeys
        let pk1 = "02".to_string() + &"ab".repeat(32);
        let pk2 = "03".to_string() + &"cd".repeat(32);
        let result = rpc_createmultisig(&state, &json!([1, [pk1, pk2]])).await.unwrap();
        assert!(!result["redeemScript"].as_str().unwrap().is_empty());
        assert!(!result["address"].as_str().unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_multisig_invalid_nrequired() {
        let (state, _tmpdir) = test_state();
        let pk1 = "02".to_string() + &"ab".repeat(32);
        // nrequired=0 should fail
        let result = rpc_createmultisig(&state, &json!([0, [pk1]])).await;
        assert!(result.is_err());
        // nrequired > keys.len() should fail
        let result = rpc_createmultisig(&state, &json!([3, [pk1]])).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn create_multisig_bad_pubkey_length() {
        let (state, _tmpdir) = test_state();
        let result = rpc_createmultisig(&state, &json!([1, ["aabb"]])).await;
        assert!(result.is_err());
    }

    // ── testmempoolaccept ────────────────────────────────────────────────

    #[tokio::test]
    async fn testmempoolaccept_coinbase_rejected() {
        let (state, _tmpdir) = test_state();
        // Coinbase transaction hex
        let hex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff03020000ffffffff0100f2052a010000000000000000";
        let result = rpc_testmempoolaccept(&state, &json!([[hex]])).await.unwrap();
        let arr = result.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["allowed"], false);
        assert_eq!(arr[0]["reject-reason"], "coinbase");
    }

    #[tokio::test]
    async fn testmempoolaccept_missing_inputs() {
        let (state, _tmpdir) = test_state();
        // A normal tx spending a non-existent outpoint
        let hex = "0100000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000000000000000010000000000000000000000000000";
        let result = rpc_testmempoolaccept(&state, &json!([[hex]])).await;
        // Might fail to decode if hex is malformed, or reject with missing-inputs
        if let Ok(val) = result {
            let arr = val.as_array().unwrap();
            assert_eq!(arr[0]["allowed"], false);
        }
    }

    // ── getnetworkinfo ───────────────────────────────────────────────────

    #[tokio::test]
    async fn getnetworkinfo_fields() {
        let (state, _tmpdir) = test_state();
        let result = rpc_getnetworkinfo(&state).await.unwrap();
        assert!(result["version"].as_u64().is_some());
        assert!(result["subversion"].as_str().unwrap().contains("rbtc"));
        assert!(result["protocolversion"].as_u64().is_some());
        assert!(result["networks"].as_array().unwrap().len() >= 1);
    }

    // ── getpeerinfo ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn getpeerinfo_empty() {
        let (state, _tmpdir) = test_state();
        let result = rpc_getpeerinfo(&state).await.unwrap();
        assert!(result.as_array().unwrap().is_empty());
    }

    // ── getchaintips ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn getchaintips_empty_chain() {
        let (state, _tmpdir) = test_state();
        let result = rpc_getchaintips(&state).await.unwrap();
        // Empty chain → no tips or just genesis
        assert!(result.as_array().is_some());
    }

    // ── getmempoolentry ──────────────────────────────────────────────────

    #[tokio::test]
    async fn getmempoolentry_not_found() {
        let (state, _tmpdir) = test_state();
        let result = rpc_getmempoolentry(
            &state,
            &json!(["0000000000000000000000000000000000000000000000000000000000000000"]),
        ).await;
        assert!(result.is_err());
    }

    // ── getmempoolancestors / getmempooldescendants ──────────────────────

    #[tokio::test]
    async fn getmempoolancestors_not_in_mempool() {
        let (state, _tmpdir) = test_state();
        let result = rpc_getmempoolancestors(
            &state,
            &json!(["0000000000000000000000000000000000000000000000000000000000000000"]),
        ).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn getmempooldescendants_not_in_mempool() {
        let (state, _tmpdir) = test_state();
        let result = rpc_getmempooldescendants(
            &state,
            &json!(["0000000000000000000000000000000000000000000000000000000000000000"]),
        ).await;
        assert!(result.is_err());
    }

    // ── verifymessage / signmessagewithprivkey stubs ─────────────────────

    #[tokio::test]
    async fn verifymessage_stub_returns_error() {
        let (state, _tmpdir) = test_state();
        let result = rpc_verifymessage(
            &state,
            &json!(["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "sig", "msg"]),
        ).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn signmessagewithprivkey_stub_returns_error() {
        let (state, _tmpdir) = test_state();
        let result = rpc_signmessagewithprivkey(
            &state,
            &json!(["KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn", "hello"]),
        ).await;
        assert!(result.is_err());
    }
}
