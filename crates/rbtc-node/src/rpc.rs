//! JSON-RPC 1.1 server compatible with Bitcoin Core's HTTP interface.
//!
//! Exposes a subset of Bitcoin Core's RPC methods:
//!   getblockchaininfo, getblockcount, getblockhash, getblock,
//!   getrawtransaction, getrawmempool, sendrawtransaction,
//!   getnewaddress, getbalance, listunspent, sendtoaddress,
//!   signrawtransactionwithwallet, dumpprivkey, importprivkey,
//!   getwalletinfo, fundrawtransaction.

use std::sync::Arc;

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
use tokio::sync::RwLock;
use tracing::{debug, warn};

use rbtc_consensus::chain::ChainState;
use rbtc_mempool::Mempool;
use rbtc_primitives::{codec::{Decodable, Encodable}, hash::Hash256, transaction::Transaction};
use rbtc_storage::{BlockStore, Database};
use rbtc_wallet::{AddressType, Wallet};

// ── Shared state ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct RpcState {
    pub chain: Arc<RwLock<ChainState>>,
    pub mempool: Arc<RwLock<Mempool>>,
    pub db: Arc<Database>,
    pub network_name: String,
    /// Optional HD wallet; `None` when the node is started without `--wallet`.
    pub wallet: Option<Arc<RwLock<Wallet>>>,
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

    // TODO: scan the block index for this txid (requires a tx index)
    Err((-5, "No such mempool transaction. Use -txindex to look up confirmed transactions.".to_string()))
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

// ── Server startup ────────────────────────────────────────────────────────────

/// Start the RPC server on the given address (e.g. "127.0.0.1:8332").
pub async fn start_rpc_server(addr: &str, state: RpcState) -> Result<()> {
    let app = rpc_router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("JSON-RPC server listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
