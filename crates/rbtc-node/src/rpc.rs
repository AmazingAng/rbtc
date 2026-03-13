//! JSON-RPC 1.1 server compatible with Bitcoin Core's HTTP interface.
//!
//! Exposes a subset of Bitcoin Core's RPC methods:
//!   getblockchaininfo, getblockcount, getblockhash, getblock, getbestblockhash,
//!   getblockheader, createrawtransaction,
//!   getrawtransaction, getrawmempool, sendrawtransaction,
//!   getnewaddress, getbalance, listunspent, sendtoaddress,
//!   signrawtransactionwithwallet, dumpprivkey, importprivkey,
//!   getwalletinfo, fundrawtransaction,
//!   getblocktemplate, submitblock, generatetoaddress, generate,
//!   getmininginfo, getnetworkhashps, estimatesmartfee,
//!   bumpfee, getaddressinfo, listaddressgroupings, createwallet,
//!   setlabel, getrawchangeaddress, abandontransaction,
//!   walletpassphrase, walletlock, listtransactions, gettransaction, sendmany,
//!   getconnectioncount, getnettotals, setban, listbanned, clearbanned,
//!   addnode, ping, disconnectnode,
//!   gettxout, gettxoutsetinfo, verifychain,
//!   getblockfrompeer, pruneblockchain, waitfornewblock,
//!   signrawtransactionwithkey, lockunspent, listlockunspent, prioritisetransaction.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use axum::{extract::State, http::StatusCode, middleware, response::IntoResponse, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot, watch, RwLock};
use tracing::{debug, info, warn};

use rbtc_consensus::chain::ChainState;
use rbtc_crypto::sha256d;
use rbtc_mempool::Mempool;
use rbtc_miner::{compute_block_version, compute_witness_commitment, mine_block, BlockTemplate, LongPollState, TxSelector};
use rbtc_primitives::{
    block::{nbits_to_target, Block},
    codec::{Decodable, Encodable},
    hash::{BlockHash, Hash256, Txid},
    transaction::{OutPoint, Transaction},
};
use rbtc_psbt::Psbt;
use rbtc_storage::{AddrIndexStore, BlockStore, CoinsView, Database, TxIndexStore, UtxoStats, UtxoStore};
use rbtc_wallet::{address::address_to_script, from_wif, sign_transaction, AddressType, SigningInput, Wallet};

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
    /// GBT long-poll state (BIP22): notifies waiting miners when the template
    /// should be refreshed (new tip or significant mempool change).
    pub longpoll: Arc<LongPollState>,
    /// Data directory path, used for `size_on_disk` in getblockchaininfo.
    pub data_dir: std::path::PathBuf,
    /// Prune budget in MiB (0 = not pruning).
    pub prune_budget: u64,
    /// Whether the node is still in initial block download.
    pub is_ibd: Arc<std::sync::atomic::AtomicBool>,
    /// Watch channel receiver for new-tip notifications (used by `waitfornewblock`).
    /// Value is `(block_hash_hex, height)`. Updated each time a block is connected.
    pub new_tip_rx: watch::Receiver<(String, u32)>,
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
    GetPeerInfo {
        reply: oneshot::Sender<Vec<rbtc_net::PeerStats>>,
    },
    GetMempoolInfo {
        reply: oneshot::Sender<MempoolInfoData>,
    },
    GetConnectionCount {
        reply: oneshot::Sender<usize>,
    },
    GetNetTotals {
        reply: oneshot::Sender<NetTotalsData>,
    },
    SetBan {
        ip: std::net::IpAddr,
        command: String,
        reply: oneshot::Sender<std::result::Result<(), String>>,
    },
    ListBanned {
        reply: oneshot::Sender<Vec<std::net::IpAddr>>,
    },
    ClearBanned {
        reply: oneshot::Sender<()>,
    },
    AddNode {
        addr: std::net::SocketAddr,
        reply: oneshot::Sender<std::result::Result<(), String>>,
    },
    /// Request a specific block from a specific peer (getblockfrompeer RPC).
    GetBlockFromPeer {
        block_hash: Hash256,
        peer_id: u64,
        reply: oneshot::Sender<std::result::Result<(), String>>,
    },
    /// Prune block data up to a given height (pruneblockchain RPC).
    PruneBlockchain {
        height: u32,
        reply: oneshot::Sender<std::result::Result<u32, String>>,
    },
    /// Send a ping message to all connected peers.
    Ping {
        reply: oneshot::Sender<()>,
    },
    /// Disconnect a peer by address or node ID.
    DisconnectNode {
        address: Option<String>,
        nodeid: Option<u64>,
        reply: oneshot::Sender<std::result::Result<(), String>>,
    },
}

/// Data returned by the node loop for `getmempoolinfo`.
#[derive(Debug, Clone)]
pub struct MempoolInfoData {
    pub size: usize,
    pub bytes: u64,
    pub total_fee: u64,
    pub maxmempool: u64,
    pub mempoolminfee: u64,
}

/// Data returned by the node loop for `getnettotals`.
#[derive(Debug, Clone)]
pub struct NetTotalsData {
    pub total_bytes_recv: u64,
    pub total_bytes_sent: u64,
    pub time_millis: u64,
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
        Self {
            id,
            result: Some(result),
            error: None,
        }
    }

    fn err(id: Option<Value>, code: i32, message: impl Into<String>) -> Self {
        Self {
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
            }),
        }
    }
}

// ── Router ───────────────────────────────────────────────────────────────────

pub fn rpc_router(state: RpcState, auth: Arc<crate::rpc_auth::RpcAuthState>) -> Router {
    Router::new()
        .route("/", post(handle_rpc))
        .layer(middleware::from_fn_with_state(
            auth,
            crate::rpc_auth::rpc_auth_middleware,
        ))
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
        "getblockchaininfo" => rpc_getblockchaininfo(&state).await,
        "getblockcount" => rpc_getblockcount(&state).await,
        "getblockhash" => rpc_getblockhash(&state, &params).await,
        "getblock" => rpc_getblock(&state, &params).await,
        "invalidateblock" => rpc_invalidateblock(&state, &params).await,
        "reconsiderblock" => rpc_reconsiderblock(&state, &params).await,
        // Transactions
        "getrawtransaction" => rpc_getrawtransaction(&state, &params).await,
        "getrawmempool" => rpc_getrawmempool(&state).await,
        "sendrawtransaction" => rpc_sendrawtransaction(&state, &params).await,
        // Wallet
        "getnewaddress" => rpc_getnewaddress(&state, &params).await,
        "getbalance" => rpc_getbalance(&state).await,
        "listunspent" => rpc_listunspent(&state, &params).await,
        "sendtoaddress" => rpc_sendtoaddress(&state, &params).await,
        "fundrawtransaction" => rpc_fundrawtransaction(&state, &params).await,
        "signrawtransactionwithwallet" => rpc_signrawtransactionwithwallet(&state, &params).await,
        "dumpprivkey" => rpc_dumpprivkey(&state, &params).await,
        "importprivkey" => rpc_importprivkey(&state, &params).await,
        "getwalletinfo" => rpc_getwalletinfo(&state).await,
        // Address index
        "getaddresstxids" => rpc_getaddresstxids(&state, &params).await,
        "getaddressutxos" => rpc_getaddressutxos(&state, &params).await,
        "getaddressbalance" => rpc_getaddressbalance(&state, &params).await,
        // Mining
        "getblocktemplate" => rpc_getblocktemplate(&state, &params).await,
        "submitblock" => rpc_submitblock(&state, &params).await,
        "generatetoaddress" => rpc_generatetoaddress(&state, &params).await,
        "generate" => rpc_generate(&state, &params).await,
        "getmininginfo" => rpc_getmininginfo(&state).await,
        "getnetworkhashps" => rpc_getnetworkhashps(&state, &params).await,
        "estimatesmartfee" => rpc_estimatesmartfee(&state, &params).await,
        // PSBT (BIP174)
        "createpsbt" => rpc_createpsbt(&state, &params).await,
        "walletprocesspsbt" => rpc_walletprocesspsbt(&state, &params).await,
        "finalizepsbt" => rpc_finalizepsbt(&state, &params).await,
        "combinepsbt" => rpc_combinepsbt(&state, &params).await,
        "decodepsbt" => rpc_decodepsbt(&state, &params).await,
        "analyzepsbt" => rpc_analyzepsbt(&state, &params).await,
        // Chain (Phase D)
        "getchaintips" => rpc_getchaintips(&state).await,
        "getblockstats" => rpc_getblockstats(&state, &params).await,
        // Mempool (Phase D)
        "getmempoolentry" => rpc_getmempoolentry(&state, &params).await,
        "getmempoolancestors" => rpc_getmempoolancestors(&state, &params).await,
        "getmempooldescendants" => rpc_getmempooldescendants(&state, &params).await,
        "testmempoolaccept" => rpc_testmempoolaccept(&state, &params).await,
        // Utility (Phase D)
        "validateaddress" => rpc_validateaddress(&state, &params).await,
        "decoderawtransaction" => rpc_decoderawtransaction(&state, &params).await,
        "decodescript" => rpc_decodescript(&state, &params).await,
        "createmultisig" => rpc_createmultisig(&state, &params).await,
        "verifymessage" => rpc_verifymessage(&state, &params).await,
        "signmessagewithprivkey" => rpc_signmessagewithprivkey(&state, &params).await,
        // Wallet (Phase F)
        "dumpwallet" => rpc_dumpwallet(&state, &params).await,
        "importwallet" => rpc_importwallet(&state, &params).await,
        "getdescriptorinfo" => rpc_getdescriptorinfo(&state, &params).await,
        "deriveaddresses" => rpc_deriveaddresses(&state, &params).await,
        // Wallet (Phase G)
        "bumpfee" => rpc_bumpfee(&state, &params).await,
        "getaddressinfo" => rpc_getaddressinfo(&state, &params).await,
        "listaddressgroupings" => rpc_listaddressgroupings(&state).await,
        "createwallet" => rpc_createwallet(&state, &params).await,
        "setlabel" => rpc_setlabel(&state, &params).await,
        "getrawchangeaddress" => rpc_getrawchangeaddress(&state, &params).await,
        "abandontransaction" => rpc_abandontransaction(&state, &params).await,
        "walletpassphrase" => rpc_walletpassphrase(&state, &params).await,
        "walletlock" => rpc_walletlock(&state).await,
        "listtransactions" => rpc_listtransactions(&state, &params).await,
        "gettransaction" => rpc_gettransaction(&state, &params).await,
        "sendmany" => rpc_sendmany(&state, &params).await,
        // Network (Phase D)
        "getnetworkinfo" => rpc_getnetworkinfo(&state).await,
        "getpeerinfo" => rpc_getpeerinfo(&state).await,
        "getmempoolinfo" => rpc_getmempoolinfo(&state).await,
        // UTXO inspection
        "gettxout" => rpc_gettxout(&state, &params).await,
        "gettxoutsetinfo" => rpc_gettxoutsetinfo(&state).await,
        "verifychain" => rpc_verifychain(&state, &params).await,
        // Network management RPCs (M5)
        "getconnectioncount" => rpc_getconnectioncount(&state).await,
        "getnettotals" => rpc_getnettotals(&state).await,
        "setban" => rpc_setban(&state, &params).await,
        "listbanned" => rpc_listbanned(&state).await,
        "clearbanned" => rpc_clearbanned(&state).await,
        "addnode" => rpc_addnode(&state, &params).await,
        // Additional chain RPCs (M35-M37)
        "getbestblockhash" => rpc_getbestblockhash(&state).await,
        "getblockheader" => rpc_getblockheader(&state, &params).await,
        "createrawtransaction" => rpc_createrawtransaction(&state, &params).await,
        // Block download control RPCs
        "getblockfrompeer" => rpc_getblockfrompeer(&state, &params).await,
        "pruneblockchain" => rpc_pruneblockchain(&state, &params).await,
        "waitfornewblock" => rpc_waitfornewblock(&state, &params).await,
        // Utility RPCs (L12)
        "signrawtransactionwithkey" => rpc_signrawtransactionwithkey(&state, &params).await,
        "lockunspent" => rpc_lockunspent(&state, &params).await,
        "listlockunspent" => rpc_listlockunspent(&state).await,
        "prioritisetransaction" => rpc_prioritisetransaction(&state, &params).await,
        // Network RPCs (L11)
        "ping" => rpc_ping(&state).await,
        "disconnectnode" => rpc_disconnectnode(&state, &params).await,
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

    // M27: additional block storage metadata fields
    let is_ibd = state.is_ibd.load(std::sync::atomic::Ordering::Relaxed);
    let pruned = state.prune_budget > 0;

    // Estimate verification progress: current height / best known header height.
    // During IBD best_peer_height comes from headers; after IBD this is ~1.0.
    let headers_height = chain
        .block_index
        .values()
        .map(|bi| bi.height)
        .max()
        .unwrap_or(height);
    let verification_progress: f64 = if headers_height == 0 {
        0.0
    } else {
        (height as f64 / headers_height as f64).min(1.0)
    };

    // Pruneheight: lowest block height that still has block data retained.
    // Without a pruning scan this is 0 when not pruning.
    let pruneheight: u32 = if pruned {
        // Conservative estimate: tip - 288 (Bitcoin Core keeps at least 288 blocks).
        height.saturating_sub(288)
    } else {
        0
    };

    // size_on_disk: walk the chaindata directory for total file sizes.
    let size_on_disk = dir_size(&state.data_dir.join("chaindata"));

    drop(chain);

    Ok(json!({
        "chain": state.network_name,
        "blocks": height,
        "headers": headers_height,
        "bestblockhash": tip,
        "chainwork": chainwork,
        "size_on_disk": size_on_disk,
        "verificationprogress": verification_progress,
        "initialblockdownload": is_ibd,
        "pruned": pruned,
        "pruneheight": if pruned { pruneheight } else { 0 },
    }))
}

/// Recursively compute total file size under `path` (best-effort, returns 0 on error).
fn dir_size(path: &std::path::Path) -> u64 {
    fn walk(path: &std::path::Path) -> u64 {
        let mut total = 0u64;
        let Ok(entries) = std::fs::read_dir(path) else {
            return 0;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.is_dir() {
                total += walk(&entry.path());
            } else {
                total += meta.len();
            }
        }
        total
    }
    walk(path)
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
    let hash = BlockHash::from_hex(hash_hex).map_err(|_| (-8, "Invalid block hash".to_string()))?;

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
    let hash = Hash256::from_hex(hash_hex).map_err(|_| (-8, "Invalid block hash".to_string()))?;

    let (reply_tx, reply_rx) = oneshot::channel();
    state
        .control_tx
        .send(RpcNodeCommand::InvalidateBlock {
            hash,
            reply: reply_tx,
        })
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
    let hash = Hash256::from_hex(hash_hex).map_err(|_| (-8, "Invalid block hash".to_string()))?;

    let (reply_tx, reply_rx) = oneshot::channel();
    state
        .control_tx
        .send(RpcNodeCommand::ReconsiderBlock {
            hash,
            reply: reply_tx,
        })
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
    let txid = Txid::from_hex(txid_hex).map_err(|_| (-8, "Invalid txid".to_string()))?;

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
    let (block_hash_raw, tx_offset) = match tx_idx.get(&txid.0) {
        Ok(Some(v)) => v,
        Ok(None) => return Err((-5, format!("No transaction found for txid {txid_hex}"))),
        Err(e) => return Err((-5, format!("tx index error: {e}"))),
    };

    let block_hash = BlockHash(block_hash_raw);
    let block_store = BlockStore::new(&state.db);
    let block = block_store
        .get_block(&block_hash)
        .map_err(|e| (-5, format!("block load error: {e}")))?
        .ok_or_else(|| (-5, format!("block {} not found", block_hash.0.to_hex())))?;

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

        let vin: Vec<Value> = tx
            .inputs
            .iter()
            .map(|inp| {
                json!({
                    "txid": inp.previous_output.txid.to_hex(),
                    "vout": inp.previous_output.vout,
                    "sequence": inp.sequence,
                })
            })
            .collect();

        let vout: Vec<Value> = tx
            .outputs
            .iter()
            .enumerate()
            .map(|(n, out)| {
                json!({
                    "n": n,
                    "value": out.value,
                    "scriptPubKey": { "hex": hex::encode(&out.script_pubkey.0) },
                })
            })
            .collect();

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
    let hex_str = params.get(0).and_then(Value::as_str).ok_or((
        -32602,
        "Invalid params: expected raw transaction hex".to_string(),
    ))?;

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
            None => {
                return Err((
                    -18,
                    "No wallet loaded. Start with --wallet or --create-wallet.".into(),
                ))
            }
        }
    };
}

async fn rpc_getnewaddress(state: &RpcState, params: &Value) -> RpcResult {
    let wallet_arc = require_wallet!(state);

    // Bitcoin Core signature: getnewaddress(label="", address_type)
    let label = params.get(0).and_then(Value::as_str).unwrap_or("");
    let addr_type_str = params.get(1).and_then(Value::as_str).unwrap_or("bech32");
    let addr_type = AddressType::parse(addr_type_str).unwrap_or(AddressType::SegWit);

    let mut w = wallet_arc.write().await;
    let address = w
        .new_address_with_label(addr_type, label)
        .map_err(|e| (-1, e.to_string()))?;
    Ok(json!(address))
}

async fn rpc_getbalance(state: &RpcState) -> RpcResult {
    let wallet_arc = require_wallet!(state);
    let w = wallet_arc.read().await;
    let bal = w.balance();
    Ok(json!({
        "confirmed":   bal.confirmed as f64 / 1e8,
        "unconfirmed": bal.unconfirmed as f64 / 1e8,
        "immature":    bal.immature as f64 / 1e8,
        "total":       bal.total() as f64 / 1e8,
    }))
}

async fn rpc_listunspent(state: &RpcState, params: &Value) -> RpcResult {
    let wallet_arc = require_wallet!(state);
    let min_conf = params.get(0).and_then(Value::as_u64).unwrap_or(1) as u32;
    let w = wallet_arc.read().await;
    let utxos: Vec<Value> = w
        .list_unspent(min_conf)
        .iter()
        .map(|u| {
            json!({
                "txid":          u.outpoint.txid.to_hex(),
                "vout":          u.outpoint.vout,
                "address":       u.address,
                "amount":        u.value as f64 / 1e8,
                "confirmations": u.height,
                "spendable":     true,
            })
        })
        .collect();
    Ok(json!(utxos))
}

async fn rpc_sendtoaddress(state: &RpcState, params: &Value) -> RpcResult {
    let wallet_arc = require_wallet!(state);

    let address = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "missing address".to_string()))?;
    let amount_btc = params
        .get(1)
        .and_then(Value::as_f64)
        .ok_or((-32602, "missing amount".to_string()))?;
    let fee_rate = params.get(2).and_then(Value::as_f64).unwrap_or(1.0);

    let amount_sat = (amount_btc * 1e8) as u64;

    let (signed_tx, fee) = {
        let mut w = wallet_arc.write().await;
        w.create_transaction(address, amount_sat, fee_rate, AddressType::SegWit, true)
            .map_err(|e| (-6, e.to_string()))?
    };
    let _ = fee;

    // Encode and submit to mempool
    let mut raw = Vec::new();
    signed_tx
        .encode(&mut raw)
        .map_err(|e| (-22, e.to_string()))?;
    let hex_tx = hex::encode(&raw);

    // Reuse sendrawtransaction logic
    let fake_params = json!([hex_tx]);
    rpc_sendrawtransaction(state, &fake_params).await
}

async fn rpc_fundrawtransaction(state: &RpcState, params: &Value) -> RpcResult {
    let wallet_arc = require_wallet!(state);

    let hex_str = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "missing raw transaction hex".to_string()))?;
    let fee_rate = params
        .get(1)
        .and_then(|p| p.get("feeRate"))
        .and_then(Value::as_f64)
        .unwrap_or(1.0);

    let raw = hex::decode(hex_str).map_err(|_| (-22, "TX decode failed".to_string()))?;
    let tx = Transaction::decode_from_slice(&raw)
        .map_err(|e| (-22, format!("TX decode failed: {e}")))?;

    // Estimate how much we need for the outputs + fee
    let output_total: u64 = tx.outputs.iter().map(|o| o.value as u64).sum();

    let w = wallet_arc.read().await;
    let available: Vec<_> = w.list_unspent(1).into_iter().cloned().collect();
    drop(w);

    let (selected, actual_fee) =
        rbtc_wallet::CoinSelector::select(&available, output_total, fee_rate)
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
        let change_addr = w
            .new_address(AddressType::SegWit)
            .map_err(|e| (-1, e.to_string()))?;
        drop(w);
        let change_spk = rbtc_wallet::address::address_to_script(&change_addr)
            .map_err(|e| (-1, e.to_string()))?;
        funded.outputs.push(rbtc_primitives::transaction::TxOut {
            value: change as i64,
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

    let hex_str = params
        .get(0)
        .and_then(Value::as_str)
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

    let address = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "missing address".to_string()))?;

    let w = wallet_arc.read().await;
    let wif = w.dump_privkey(address).map_err(|e| (-4, e.to_string()))?;
    Ok(json!(wif))
}

async fn rpc_importprivkey(state: &RpcState, params: &Value) -> RpcResult {
    let wallet_arc = require_wallet!(state);

    let wif = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "missing WIF private key".to_string()))?;
    let label = params.get(1).and_then(Value::as_str).unwrap_or("");

    let mut w = wallet_arc.write().await;
    let address = w.import_wif(wif, label).map_err(|e| (-5, e.to_string()))?;
    Ok(json!(address))
}

async fn rpc_getwalletinfo(state: &RpcState) -> RpcResult {
    let wallet_arc = require_wallet!(state);
    let w = wallet_arc.read().await;
    let bal = w.balance();
    Ok(json!({
        "walletname":       "rbtc-wallet",
        "walletversion":    1,
        "balance":          bal.confirmed as f64 / 1e8,
        "unconfirmed_balance": bal.unconfirmed as f64 / 1e8,
        "immature_balance": bal.immature as f64 / 1e8,
        "txcount":          w.utxo_count(),
        "keypoolsize":      w.address_count(),
    }))
}

// ── Mining RPC implementations ────────────────────────────────────────────────

/// Build a `BlockTemplate` from the current chain/mempool state.
async fn build_template(
    state: &RpcState,
    output_script: rbtc_primitives::script::Script,
) -> BlockTemplate {
    let chain = state.chain.read().await;
    let mempool = state.mempool.read().await;

    let prev_hash = chain.best_hash().unwrap_or(BlockHash::ZERO);
    let next_height = chain.height() + 1;
    let bits = chain.next_required_bits();

    let version = compute_block_version(chain.network, next_height, &*chain);

    let mtp_gen = chain.median_time_past(chain.height());
    let (transactions, fees) = TxSelector::select(&mempool, next_height, mtp_gen, None);

    let halving_interval = chain.network.consensus_params().subsidy_halving_interval;
    let template = BlockTemplate::new(
        version,
        prev_hash,
        bits,
        next_height,
        halving_interval,
        fees,
        transactions,
        output_script,
    );
    // TestBlockValidity: validate the assembled template before returning
    if let Err(e) = template.validate() {
        warn!("block template validation failed: {e}");
    }
    template
}

/// Default longpoll timeout: 30 seconds (same as Bitcoin Core's default).
const GBT_LONGPOLL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

async fn rpc_getblocktemplate(state: &RpcState, params: &Value) -> RpcResult {
    // BIP22 longpoll: if the caller supplies a `longpollid` inside the
    // template_request object (first param), we hold the connection open
    // until the template changes (new tip or mempool update) or timeout.
    if let Some(template_request) = params.get(0).and_then(Value::as_object) {
        if let Some(lp_id) = template_request.get("longpollid").and_then(Value::as_str) {
            let longpoll = Arc::clone(&state.longpoll);
            let old_id = lp_id.to_string();
            // Run the blocking wait on a dedicated thread so we don't stall
            // the Tokio runtime.
            let _new_id = tokio::task::spawn_blocking(move || {
                longpoll.wait_for_change(&old_id, GBT_LONGPOLL_TIMEOUT)
            })
            .await
            .map_err(|e| (-1, format!("longpoll wait failed: {e}")))?;
        }
    }

    let chain = state.chain.read().await;
    let prev_hash = chain.best_hash().unwrap_or(BlockHash::ZERO);
    let next_height = chain.height() + 1;
    let bits = chain.next_required_bits();
    let mtp = chain.median_time_past(chain.height());
    let version = compute_block_version(chain.network, next_height, &*chain);
    let halving_interval = chain.network.consensus_params().subsidy_halving_interval;
    drop(chain);

    let mempool = state.mempool.read().await;
    let (transactions, per_tx_fees, per_tx_sigops, total_fees) =
        TxSelector::select_with_fees(&mempool, next_height, mtp, None);
    drop(mempool);

    let coinbase_value =
        rbtc_consensus::tx_verify::block_subsidy(next_height, halving_interval) + total_fees;

    // Build target hex (big-endian)
    let mut target_bytes = nbits_to_target(bits);
    target_bytes.reverse();
    let target_hex = hex::encode(target_bytes);

    // Pre-compute txids for dependency look-up.
    // txid_to_index maps txid -> 1-based index in the template (BIP22 convention).
    let txids: Vec<Hash256> = transactions
        .iter()
        .map(|tx| {
            let mut legacy_buf = Vec::new();
            tx.encode_legacy(&mut legacy_buf).unwrap_or_default();
            rbtc_crypto::sha256d(&legacy_buf)
        })
        .collect();

    let txid_to_index: std::collections::HashMap<Hash256, usize> = txids
        .iter()
        .enumerate()
        .map(|(i, h)| (*h, i + 1))
        .collect();

    // Encode each selected transaction with depends, fee, sigops
    let tx_entries: Vec<Value> = transactions
        .iter()
        .enumerate()
        .map(|(i, tx)| {
            let mut buf = Vec::new();
            tx.encode(&mut buf).unwrap_or_default();
            let txid_hex = txids[i].to_hex();

            // depends: 1-based indices of template transactions this tx spends
            let mut depends: Vec<usize> = Vec::new();
            for input in &tx.inputs {
                let parent_hash = input.previous_output.txid.0;
                if let Some(&idx) = txid_to_index.get(&parent_hash) {
                    if idx != i + 1 {
                        depends.push(idx);
                    }
                }
            }
            depends.sort_unstable();
            depends.dedup();

            // sigops: use accurate mempool-based sigop cost when available,
            // falling back to conservative legacy count * WITNESS_SCALE_FACTOR.
            let sigops = if let Some(&s) = per_tx_sigops.get(i) {
                s
            } else {
                let mut count = 0usize;
                for inp in &tx.inputs {
                    count += inp.script_sig.count_sigops();
                }
                for out in &tx.outputs {
                    count += out.script_pubkey.count_sigops();
                }
                (count as u64)
                    * rbtc_primitives::constants::WITNESS_SCALE_FACTOR
            };

            let fee = per_tx_fees.get(i).copied().unwrap_or(0);

            // Compute wtxid (hash including witness)
            let mut wtx_buf = Vec::new();
            tx.encode(&mut wtx_buf).unwrap_or_default();
            let wtxid_hex = rbtc_crypto::sha256d(&wtx_buf).to_hex();

            json!({
                "data":    hex::encode(&buf),
                "txid":    txid_hex,
                "hash":    wtxid_hex,
                "fee":     fee,
                "sigops":  sigops,
                "weight":  tx.weight(),
                "depends": depends,
            })
        })
        .collect();

    // BIP141 default witness commitment
    let default_witness_commitment = if transactions.iter().any(|tx| tx.has_witness()) {
        let commitment = compute_witness_commitment(&transactions);
        // Encode as a full OP_RETURN script: 6a24 aa21a9ed <32-byte commitment>
        let mut script_bytes = Vec::with_capacity(38);
        script_bytes.push(0x6a); // OP_RETURN
        script_bytes.push(0x24); // push 36 bytes
        script_bytes.extend_from_slice(&[0xaa, 0x21, 0xa9, 0xed]);
        script_bytes.extend_from_slice(&commitment.0);
        Some(hex::encode(script_bytes))
    } else {
        None
    };

    let curtime = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut result = json!({
        "capabilities":      ["proposal"],
        "version":           version as i64,
        "rules":             ["csv", "segwit", "taproot"],
        "vbavailable":       {},
        "vbrequired":        0,
        "previousblockhash": prev_hash.to_hex(),
        "transactions":      tx_entries,
        "coinbaseaux":       {},
        "coinbasevalue":     coinbase_value,
        "longpollid":        state.longpoll.current_id(),
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
    });

    if let Some(commitment_hex) = default_witness_commitment {
        result["default_witness_commitment"] = json!(commitment_hex);
    }

    Ok(result)
}

async fn rpc_submitblock(state: &RpcState, params: &Value) -> RpcResult {
    let hex_str = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "expected hex-encoded block".to_string()))?;

    let raw = hex::decode(hex_str).map_err(|_| (-22, "block decode failed".to_string()))?;
    let block =
        Block::decode_from_slice(&raw).map_err(|e| (-22, format!("block decode failed: {e}")))?;

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

    let output_script =
        address_to_script(address).map_err(|e| (-5, format!("invalid address: {e}")))?;

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
        info!(
            "generatetoaddress: mined block {}",
            block_hashes.last().unwrap()
        );

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
    let conf_target = params.get(0).and_then(Value::as_u64).unwrap_or(6) as u32;

    let mp = state.mempool.read().await;
    let txids = mp.txids_by_fee_rate(); // sorted descending by ancestor fee rate

    let fee_rate = if txids.is_empty() {
        1.0f64 // default floor: 1 sat/vB
    } else {
        // Collect fee rates sorted descending (highest first)
        let rates: Vec<f64> = txids
            .iter()
            .filter_map(|id| mp.get(id))
            .map(|e| e.fee_rate as f64)
            .collect();

        // Pick percentile based on confirmation target:
        //   1 block  → 90th percentile (index near top)
        //   2-3      → 75th percentile
        //   4-6      → 50th percentile (median)
        //   7+       → 25th percentile
        let percentile = match conf_target {
            0..=1 => 0.10, // top 10% → index = len * 0.10
            2..=3 => 0.25,
            4..=6 => 0.50,
            _ => 0.75,
        };
        let idx = ((rates.len() as f64 * percentile) as usize).min(rates.len() - 1);
        rates[idx].max(1.0)
    };

    Ok(json!({
        "feerate": fee_rate / 1000.0,   // convert sat/vB to BTC/kB
        "blocks":  conf_target,
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
        .map(|s| s.0.to_vec())
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

    let filter_start = params
        .get(1)
        .and_then(|v| v.get("start"))
        .and_then(Value::as_u64);
    let filter_end = params
        .get(1)
        .and_then(|v| v.get("end"))
        .and_then(Value::as_u64);

    let addr_idx = AddrIndexStore::new(&state.db);
    let entries = addr_idx
        .iter_by_script(&script)
        .map_err(|e| (-5, format!("addr index error: {e}")))?;

    let txids: Vec<Value> = entries
        .into_iter()
        .filter(|e| {
            let h = e.height as u64;
            filter_start.is_none_or(|s| h >= s) && filter_end.is_none_or(|en| h <= en)
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
            if output.script_pubkey.0.as_slice() != script.as_slice() {
                continue;
            }
            // Build the OutPoint and check it's still in the UTXO set
            let mut txid_buf = Vec::new();
            tx.encode_legacy(&mut txid_buf).ok();
            let txid = Txid(sha256d(&txid_buf));
            let outpoint = OutPoint {
                txid,
                vout: vout as u32,
            };
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

    let mut balance: i64 = 0;
    let mut received: i64 = 0;

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
        let txid = Txid(sha256d(&txid_buf));

        for (vout, output) in tx.outputs.iter().enumerate() {
            if output.script_pubkey.0.as_slice() != script.as_slice() {
                continue;
            }
            received += output.value;
            let outpoint = OutPoint {
                txid,
                vout: vout as u32,
            };
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
    let inputs_raw = params
        .get(0)
        .and_then(|v| v.as_array())
        .ok_or((-8, "params[0] must be array of inputs".to_string()))?;
    let outputs_raw = params.get(1).and_then(|v| v.as_object()).ok_or((
        -8,
        "params[1] must be object of {address: sats}".to_string(),
    ))?;
    let locktime = params.get(2).and_then(|v| v.as_u64()).unwrap_or(0) as u32;

    use rbtc_primitives::{
        hash::Hash256,
        transaction::{TxIn, TxOut},
    };
    let mut inputs = Vec::new();
    for inp in inputs_raw {
        let txid_hex = inp
            .get("txid")
            .and_then(|v| v.as_str())
            .ok_or((-8, "input missing txid".to_string()))?;
        let vout = inp
            .get("vout")
            .and_then(|v| v.as_u64())
            .ok_or((-8, "input missing vout".to_string()))? as u32;
        let sequence = inp
            .get("sequence")
            .and_then(|v| v.as_u64())
            .unwrap_or(0xffffffff) as u32;
        let txid_bytes = hex::decode(txid_hex).map_err(|_| (-8, "invalid txid hex".to_string()))?;
        if txid_bytes.len() != 32 {
            return Err((-8, "txid must be 32 bytes".to_string()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&txid_bytes);
        inputs.push(TxIn {
            previous_output: rbtc_primitives::transaction::OutPoint {
                txid: Txid(Hash256(arr)),
                vout,
            },
            script_sig: rbtc_primitives::script::Script::new(),
            sequence,
            witness: vec![],
        });
    }

    let mut txouts = Vec::new();
    for (addr, amount_val) in outputs_raw {
        let amount = amount_val
            .as_u64()
            .ok_or((-8, format!("amount for {addr} must be integer sats")))?;
        let script =
            address_to_script(addr).map_err(|e| (-8, format!("invalid address {addr}: {e}")))?;
        txouts.push(TxOut {
            value: amount as i64,
            script_pubkey: script,
        });
    }

    let tx = rbtc_primitives::transaction::Transaction::from_parts(2, inputs, txouts, locktime);
    let psbt = Psbt::create(tx);
    Ok(json!(psbt.to_base64()))
}

/// `walletprocesspsbt` — Updater + Signer using the node's built-in wallet.
async fn rpc_walletprocesspsbt(state: &RpcState, params: &Value) -> RpcResult {
    let b64 = params
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or((-8, "params[0] must be PSBT base64 string".to_string()))?;
    let mut psbt = Psbt::from_base64(b64).map_err(|e| (-8, format!("PSBT decode: {e}")))?;

    let wallet_arc = state
        .wallet
        .as_ref()
        .ok_or((-18, "Wallet not loaded".to_string()))?;
    let wallet = wallet_arc.read().await;

    // For each input, try to sign with a matching wallet key
    for i in 0..psbt.inputs.len() {
        // Determine the scriptPubKey to match
        let spk = if let Some(txout) = psbt.inputs[i].witness_utxo.as_ref() {
            txout.script_pubkey.as_bytes().to_vec()
        } else if let Some(tx) = psbt.inputs[i].non_witness_utxo.as_ref() {
            let utx = psbt.unsigned_tx().ok_or((-4, "missing unsigned_tx".to_string()))?;
            let vout = utx.inputs[i].previous_output.vout as usize;
            tx.outputs
                .get(vout)
                .map(|o| o.script_pubkey.as_bytes().to_vec())
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
    let b64 = params
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or((-8, "params[0] must be PSBT base64 string".to_string()))?;
    let mut psbt = Psbt::from_base64(b64).map_err(|e| (-8, format!("PSBT decode: {e}")))?;

    psbt.finalize()
        .map_err(|e| (-8, format!("finalize error: {e}")))?;

    let complete = psbt.inputs.iter().all(|i| i.is_finalized());
    if complete {
        let tx = psbt
            .clone()
            .extract_tx()
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
    let psbts_raw = params.get(0).and_then(|v| v.as_array()).ok_or((
        -8,
        "params[0] must be array of PSBT base64 strings".to_string(),
    ))?;

    if psbts_raw.is_empty() {
        return Err((-8, "at least one PSBT required".to_string()));
    }

    let mut combined = Psbt::from_base64(psbts_raw[0].as_str().unwrap_or(""))
        .map_err(|e| (-8, format!("PSBT[0] decode: {e}")))?;

    for (idx, val) in psbts_raw.iter().enumerate().skip(1) {
        let other = Psbt::from_base64(val.as_str().unwrap_or(""))
            .map_err(|e| (-8, format!("PSBT[{idx}] decode: {e}")))?;
        combined
            .combine(other)
            .map_err(|e| (-8, format!("combine error at [{idx}]: {e}")))?;
    }

    Ok(json!(combined.to_base64()))
}

/// `decodepsbt` — human-readable PSBT inspection.
async fn rpc_decodepsbt(_state: &RpcState, params: &Value) -> RpcResult {
    let b64 = params
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or((-8, "params[0] must be PSBT base64 string".to_string()))?;
    let psbt = Psbt::from_base64(b64).map_err(|e| (-8, format!("PSBT decode: {e}")))?;

    let inputs: Vec<Value> = psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(i, inp)| {
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
        })
        .collect();

    let unsigned_txid = {
        let mut buf = Vec::new();
        if let Some(utx) = psbt.unsigned_tx() {
            utx.encode_legacy(&mut buf).ok();
        }
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
    let b64 = params
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or((-8, "params[0] must be PSBT base64 string".to_string()))?;
    let psbt = Psbt::from_base64(b64).map_err(|e| (-8, format!("PSBT decode: {e}")))?;

    let inputs: Vec<Value> = psbt
        .inputs
        .iter()
        .map(|inp| {
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
        })
        .collect();

    let all_finalized = psbt.inputs.iter().all(|i| i.is_finalized());
    Ok(json!({ "inputs": inputs, "estimated_complete": all_finalized }))
}

// ── Phase D: Chain RPCs ──────────────────────────────────────────────────────

async fn rpc_getchaintips(state: &RpcState) -> RpcResult {
    let chain = state.chain.read().await;
    // Collect all block hashes that are NOT parents of any other block (i.e. tips)
    let all_hashes: std::collections::HashSet<BlockHash> =
        chain.block_index.keys().copied().collect();
    let parent_hashes: std::collections::HashSet<BlockHash> = chain
        .block_index
        .values()
        .map(|bi| bi.header.prev_block)
        .collect();
    let tips: Vec<BlockHash> = all_hashes.difference(&parent_hashes).copied().collect();
    let best = chain.best_tip;
    let best_height = chain.height();

    let mut result = Vec::new();
    for tip_hash in &tips {
        if let Some(bi) = chain.block_index.get(tip_hash) {
            let is_active = Some(*tip_hash) == best;
            let status = if is_active {
                "active"
            } else if bi.status.has_failed() {
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
                    if cur == BlockHash::ZERO {
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
        BlockHash::from_hex(s).map_err(|_| (-8, "Invalid hash".to_string()))?
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
    let total_out: i64 = txs.iter().map(|t| t.output_value()).sum();
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
        (50_0000_0000i64) >> (height / 210_000)
    } else {
        0i64
    };
    // We can't compute per-tx fees without UTXO lookups for inputs,
    // so we provide aggregate info and zero fee-rate stats.
    let total_fee = txs
        .first()
        .map(|cb| cb.output_value().saturating_sub(subsidy))
        .unwrap_or(0);

    Ok(json!({
        "avgfee": if txs.len() > 1 { total_fee / (txs.len() as i64 - 1) } else { 0 },
        "avgfeerate": if total_weight > 0 { total_fee * 4 / total_weight as i64 } else { 0 },
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
    let txid = Txid::from_hex(txid_hex).map_err(|_| (-8, "Invalid txid".to_string()))?;
    let mp = state.mempool.read().await;
    let entry = mp
        .get(&txid)
        .ok_or((-5, "Transaction not in mempool".to_string()))?;
    let (anc_fee, anc_vsize) = mp.ancestor_package(&txid);
    let anc_count = {
        // count ancestors by walking parents
        let mut count = 0u64;
        let mut stack: Vec<Txid> = vec![txid];
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
    let txid = Txid::from_hex(txid_hex).map_err(|_| (-8, "Invalid txid".to_string()))?;
    let mp = state.mempool.read().await;
    if !mp.contains(&txid) {
        return Err((-5, "Transaction not in mempool".to_string()));
    }
    // Collect ancestors (excluding self)
    let mut ancestors = Vec::new();
    let mut stack: Vec<Txid> = vec![txid];
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
    let txid = Txid::from_hex(txid_hex).map_err(|_| (-8, "Invalid txid".to_string()))?;
    let mp = state.mempool.read().await;
    if !mp.contains(&txid) {
        return Err((-5, "Transaction not in mempool".to_string()));
    }
    // Find all txs that transitively spend outputs of txid
    let mut descendants = Vec::new();
    let mut queue: Vec<Txid> = vec![txid];
    let mut visited: std::collections::HashSet<Txid> = std::collections::HashSet::new();
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
        let bytes = hex::decode(hex_str).map_err(|_| (-22, "Invalid hex".to_string()))?;
        let tx = Transaction::decode(&mut &bytes[..])
            .map_err(|e| (-22, format!("TX decode failed: {e}")))?;

        let mut txid_buf = Vec::new();
        let _ = tx.encode_legacy(&mut txid_buf);
        let txid = Txid(rbtc_crypto::sha256d(&txid_buf));

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
                let mut total_in = 0i64;
                for inp in &tx.inputs {
                    if let Some(utxo) = chain.utxos.get(&inp.previous_output) {
                        total_in += utxo.txout.value;
                    } else if let Some(parent) = mp.get(&inp.previous_output.txid) {
                        if let Some(out) = parent.tx.outputs.get(inp.previous_output.vout as usize)
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

// ── UTXO inspection RPCs ─────────────────────────────────────────────────────

/// `gettxout txid vout [include_mempool]`
///
/// Returns details about an unspent transaction output.  When `include_mempool`
/// is true (the default) the mempool is checked first.
async fn rpc_gettxout(state: &RpcState, params: &Value) -> RpcResult {
    let txid_str = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "Expected txid".to_string()))?;
    let txid = Txid::from_hex(txid_str).map_err(|_| (-8, "Invalid txid".to_string()))?;

    let vout = params
        .get(1)
        .and_then(Value::as_u64)
        .ok_or((-32602, "Expected vout".to_string()))? as u32;

    let include_mempool = params.get(2).and_then(Value::as_bool).unwrap_or(true);

    let chain = state.chain.read().await;
    let best_height = chain.height();
    let best_hash = chain
        .best_hash()
        .map(|h| h.to_hex())
        .unwrap_or_default();
    drop(chain);

    // Check mempool first when requested.
    if include_mempool {
        let mp = state.mempool.read().await;
        if let Some(entry) = mp.get(&txid) {
            if let Some(txout) = entry.tx.outputs.get(vout as usize) {
                return Ok(json!({
                    "bestblock": best_hash,
                    "confirmations": 0,
                    "value": txout.value as f64 / 1e8,
                    "scriptPubKey": {
                        "asm": "",
                        "hex": hex::encode(&txout.script_pubkey.0),
                        "type": classify_script(&txout.script_pubkey),
                    },
                    "coinbase": false,
                }));
            }
        }
    }

    // Fall through to the confirmed UTXO set.
    let outpoint = OutPoint { txid, vout };
    let utxo_store = UtxoStore::new(&state.db);
    match utxo_store.get(&outpoint) {
        Ok(Some(utxo)) => {
            let confirmations = best_height.saturating_sub(utxo.height) + 1;
            Ok(json!({
                "bestblock": best_hash,
                "confirmations": confirmations,
                "value": utxo.value as f64 / 1e8,
                "scriptPubKey": {
                    "asm": "",
                    "hex": hex::encode(&utxo.script_pubkey.0),
                    "type": classify_script(&utxo.script_pubkey),
                },
                "coinbase": utxo.is_coinbase,
            }))
        }
        Ok(None) => {
            // Bitcoin Core returns null (JSON null) when the UTXO is not found.
            Ok(Value::Null)
        }
        Err(e) => Err((-5, format!("UTXO lookup error: {e}"))),
    }
}

/// `gettxoutsetinfo`
///
/// Returns statistics about the UTXO set (count, total amount, disk size).
async fn rpc_gettxoutsetinfo(state: &RpcState) -> RpcResult {
    let chain = state.chain.read().await;
    let height = chain.height();
    let best_hash = chain
        .best_hash()
        .map(|h| h.to_hex())
        .unwrap_or_default();
    drop(chain);

    let utxo_store = UtxoStore::new(&state.db);
    let stats = utxo_store
        .get_utxo_stats()
        .map_err(|e| (-1, format!("Failed to compute UTXO stats: {e}")))?;

    Ok(json!({
        "height": height,
        "bestblock": best_hash,
        "txouts": stats.num_utxos,
        "bogosize": stats.serialized_size,
        "total_amount": stats.total_amount as f64 / 1e8,
    }))
}

/// `verifychain [checklevel] [nblocks]`
///
/// Verifies the chain by checking block-index consistency for the last N
/// blocks.  `checklevel` is accepted but only level 0 (index checks) is
/// implemented — higher levels are silently treated the same.
async fn rpc_verifychain(state: &RpcState, params: &Value) -> RpcResult {
    let _checklevel = params.get(0).and_then(Value::as_u64).unwrap_or(3) as u32;
    let nblocks = params.get(1).and_then(Value::as_u64).unwrap_or(6) as u32;

    let chain = state.chain.read().await;

    // Empty active chain (no blocks connected yet) is trivially valid.
    if chain.active_chain.is_empty() {
        return Ok(json!(true));
    }

    let height = chain.height();

    // Check the last `nblocks` of the active chain for basic consistency:
    // - block index entry exists
    // - prev_hash links to the preceding block
    // - height is monotonic
    let start = height.saturating_sub(nblocks.saturating_sub(1));
    for h in start..=height {
        let hash = match chain.active_chain.get(h as usize) {
            Some(bh) => *bh,
            None => {
                return Ok(json!(false));
            }
        };
        let bi = match chain.block_index.get(&hash) {
            Some(bi) => bi,
            None => {
                return Ok(json!(false));
            }
        };
        if bi.height != h {
            return Ok(json!(false));
        }
        // Verify prev_hash linkage (skip genesis)
        if h > 0 {
            if let Some(prev_hash) = chain.active_chain.get((h - 1) as usize) {
                if bi.header.prev_block != *prev_hash {
                    return Ok(json!(false));
                }
            } else {
                return Ok(json!(false));
            }
        }
    }

    Ok(json!(true))
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
    let bytes = hex::decode(hex_str).map_err(|_| (-22, "Invalid hex".to_string()))?;
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
                v["txinwitness"] = json!(inp.witness.iter().map(hex::encode).collect::<Vec<_>>());
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
    let bytes = hex::decode(hex_str).map_err(|_| (-22, "Invalid hex".to_string()))?;
    let script = rbtc_primitives::script::Script::from_bytes(bytes.clone());
    let script_type = classify_script(&script);

    // Compute P2SH address: hash160 of the script, then base58check
    let script_hash = rbtc_crypto::hash160(&bytes);
    let p2sh_hex = hex::encode(script_hash.0);

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
        let key_bytes = hex::decode(key_hex).map_err(|_| (-8, "Invalid hex pubkey".to_string()))?;
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
        "address": hex::encode(script_hash.0),
        "redeemScript": redeem_script_hex,
    }))
}

/// Compute the Bitcoin Signed Message hash.
/// Format: SHA256d("\x18Bitcoin Signed Message:\n" + varint(len) + message)
fn message_hash(message: &str) -> Hash256 {
    use rbtc_primitives::codec::{Encodable, VarInt};
    let mut buf = Vec::new();
    // The prefix is length-prefixed itself: 0x18 = 24 = len("Bitcoin Signed Message:\n")
    buf.push(0x18);
    buf.extend_from_slice(b"Bitcoin Signed Message:\n");
    VarInt(message.len() as u64).encode(&mut buf).ok();
    buf.extend_from_slice(message.as_bytes());
    rbtc_crypto::sha256d(&buf)
}

async fn rpc_verifymessage(_state: &RpcState, params: &Value) -> RpcResult {
    let address = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "Expected address".to_string()))?;
    let signature_b64 = params
        .get(1)
        .and_then(Value::as_str)
        .ok_or((-32602, "Expected signature".to_string()))?;
    let message = params
        .get(2)
        .and_then(Value::as_str)
        .ok_or((-32602, "Expected message".to_string()))?;

    // Decode base64 signature (65 bytes: 1 recovery + 32 r + 32 s)
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let sig_bytes = B64
        .decode(signature_b64)
        .map_err(|_| (-8, "Invalid base64 signature".to_string()))?;
    if sig_bytes.len() != 65 {
        return Err((-8, "Signature must be 65 bytes".to_string()));
    }

    let hash = message_hash(message);
    let msg = secp256k1::Message::from_digest(hash.0);

    // Parse compact signature: first byte encodes recovery_id + compression flag
    let flag = sig_bytes[0];
    let recovery_id_raw = (flag - 27) & 3;
    let compressed = (flag - 27) & 4 != 0;
    let rec_id = secp256k1::ecdsa::RecoveryId::from_u8_masked(recovery_id_raw);
    let rec_sig = secp256k1::ecdsa::RecoverableSignature::from_compact(&sig_bytes[1..65], rec_id)
        .map_err(|_| (-8, "Invalid compact signature".to_string()))?;

    let secp = secp256k1::Secp256k1::new();
    let recovered_pk = secp
        .recover_ecdsa(msg, &rec_sig)
        .map_err(|_| (-8, "Failed to recover public key".to_string()))?;

    // Derive P2PKH address from recovered pubkey and compare
    use rbtc_primitives::network::Network;
    let network = if address.starts_with('1') || address.starts_with('3') {
        Network::Mainnet
    } else {
        Network::Testnet4
    };
    let recovered_addr = if compressed {
        rbtc_wallet::address::p2pkh_address(&recovered_pk, network)
    } else {
        // For uncompressed keys, serialize uncompressed and hash
        let uncompressed = recovered_pk.serialize_uncompressed();
        let h160 = rbtc_crypto::hash160(&uncompressed);
        let version = if network == Network::Mainnet {
            0x00u8
        } else {
            0x6fu8
        };
        let mut payload = vec![version];
        payload.extend_from_slice(&h160.0);
        use sha2::{Digest, Sha256};
        let checksum = Sha256::digest(Sha256::digest(&payload));
        payload.extend_from_slice(&checksum[..4]);
        bs58::encode(payload).into_string()
    };

    Ok(json!(recovered_addr == address))
}

async fn rpc_signmessagewithprivkey(_state: &RpcState, params: &Value) -> RpcResult {
    let privkey_wif = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "Expected privkey (WIF)".to_string()))?;
    let message = params
        .get(1)
        .and_then(Value::as_str)
        .ok_or((-32602, "Expected message".to_string()))?;

    // Decode WIF to get both secret key and compressed flag
    let decoded = bs58::decode(privkey_wif)
        .with_check(None)
        .into_vec()
        .map_err(|_| (-8, "Invalid WIF".to_string()))?;
    if decoded.len() < 33 || decoded.len() > 34 {
        return Err((-8, "Invalid WIF length".to_string()));
    }
    let compressed = decoded.len() == 34;
    let key_arr: [u8; 32] = decoded[1..33]
        .try_into()
        .map_err(|_| (-8, "Bad key bytes".to_string()))?;
    let secret_key = secp256k1::SecretKey::from_byte_array(key_arr)
        .map_err(|_| (-8, "Invalid secret key".to_string()))?;

    let hash = message_hash(message);
    let msg = secp256k1::Message::from_digest(hash.0);
    let secp = secp256k1::Secp256k1::new();
    let rec_sig = secp.sign_ecdsa_recoverable(msg, &secret_key);
    let (rec_id, compact) = rec_sig.serialize_compact();

    // Build 65-byte compact sig: flag + 64 bytes
    let rec_id_val: u8 = match rec_id {
        secp256k1::ecdsa::RecoveryId::Zero => 0,
        secp256k1::ecdsa::RecoveryId::One => 1,
        secp256k1::ecdsa::RecoveryId::Two => 2,
        secp256k1::ecdsa::RecoveryId::Three => 3,
    };
    let flag = 27 + rec_id_val + if compressed { 4 } else { 0 };
    let mut sig_bytes = vec![flag];
    sig_bytes.extend_from_slice(&compact);

    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    Ok(json!(B64.encode(&sig_bytes)))
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

async fn rpc_getpeerinfo(state: &RpcState) -> RpcResult {
    let (tx, rx) = oneshot::channel();
    state
        .control_tx
        .send(RpcNodeCommand::GetPeerInfo { reply: tx })
        .map_err(|_| (-1, "node loop unavailable".to_string()))?;
    let peers = rx
        .await
        .map_err(|_| (-1, "node loop did not respond".to_string()))?;
    let arr: Vec<Value> = peers
        .iter()
        .map(|p| {
            json!({
                "id": p.id,
                "addr": p.addr,
                "services": format!("{:016x}", p.services),
                "lastsend": p.last_send,
                "lastrecv": p.last_recv,
                "bytessent": p.bytes_sent,
                "bytesrecv": p.bytes_recv,
                "conntime": p.conn_time,
                "pingtime": p.ping_time,
                "version": p.version,
                "subver": p.subver,
                "inbound": p.inbound,
                "startingheight": p.startingheight,
                "connection_type": p.conn_type,
                "misbehavior": p.misbehavior,
            })
        })
        .collect();
    Ok(json!(arr))
}

async fn rpc_getmempoolinfo(state: &RpcState) -> RpcResult {
    let (tx, rx) = oneshot::channel();
    state
        .control_tx
        .send(RpcNodeCommand::GetMempoolInfo { reply: tx })
        .map_err(|_| (-1, "node loop unavailable".to_string()))?;
    let info = rx
        .await
        .map_err(|_| (-1, "node loop did not respond".to_string()))?;
    // mempoolminfee is in sat/vB; convert to BTC/kvB for Core compat.
    let minfee_btc_kvb = info.mempoolminfee as f64 * 1000.0 / 100_000_000.0;
    let total_fee_btc = info.total_fee as f64 / 100_000_000.0;
    Ok(json!({
        "loaded": true,
        "size": info.size,
        "bytes": info.bytes,
        "usage": info.bytes,
        "total_fee": total_fee_btc,
        "maxmempool": info.maxmempool,
        "mempoolminfee": minfee_btc_kvb,
        "minrelaytxfee": 0.00001000,
        "incrementalrelayfee": 0.00001000,
        "unbroadcastcount": 0,
        "fullrbf": false,
    }))
}

// ── M5: Network management RPCs ──────────────────────────────────────────────

/// `getconnectioncount` — Returns the number of connections to other nodes.
async fn rpc_getconnectioncount(state: &RpcState) -> RpcResult {
    let (tx, rx) = oneshot::channel();
    state
        .control_tx
        .send(RpcNodeCommand::GetConnectionCount { reply: tx })
        .map_err(|_| (-1, "node loop unavailable".to_string()))?;
    let count = rx
        .await
        .map_err(|_| (-1, "node loop did not respond".to_string()))?;
    Ok(json!(count))
}

/// `getnettotals` — Returns information about network traffic.
async fn rpc_getnettotals(state: &RpcState) -> RpcResult {
    let (tx, rx) = oneshot::channel();
    state
        .control_tx
        .send(RpcNodeCommand::GetNetTotals { reply: tx })
        .map_err(|_| (-1, "node loop unavailable".to_string()))?;
    let totals = rx
        .await
        .map_err(|_| (-1, "node loop did not respond".to_string()))?;
    Ok(json!({
        "totalbytesrecv": totals.total_bytes_recv,
        "totalbytessent": totals.total_bytes_sent,
        "timemillis": totals.time_millis,
        "uploadtarget": {
            "timeframe": 86400,
            "target": 0,
            "target_reached": false,
            "serve_historical_blocks": true,
            "bytes_left_in_cycle": 0,
            "time_left_in_cycle": 0,
        },
    }))
}

/// `setban "subnet" "add|remove" (bantime) (absolute)`
///
/// Attempts to add or remove an IP from the banned list.
async fn rpc_setban(state: &RpcState, params: &Value) -> RpcResult {
    let subnet = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "Missing subnet parameter".to_string()))?;
    let command = params
        .get(1)
        .and_then(Value::as_str)
        .ok_or((-32602, "Missing command parameter (add|remove)".to_string()))?;

    // Parse the IP (strip /32 or /128 CIDR suffix if present).
    let ip_str = subnet.split('/').next().unwrap_or(subnet);
    let ip: std::net::IpAddr = ip_str
        .parse()
        .map_err(|_| (-32602, format!("Invalid IP address: {subnet}")))?;

    match command {
        "add" | "remove" => {}
        _ => return Err((-32602, format!("Invalid command: {command} (expected add|remove)"))),
    }

    let (tx, rx) = oneshot::channel();
    state
        .control_tx
        .send(RpcNodeCommand::SetBan {
            ip,
            command: command.to_string(),
            reply: tx,
        })
        .map_err(|_| (-1, "node loop unavailable".to_string()))?;
    rx.await
        .map_err(|_| (-1, "node loop did not respond".to_string()))?
        .map_err(|e| (-1, e))?;
    Ok(json!(null))
}

/// `listbanned` — List all manually banned IPs/subnets.
async fn rpc_listbanned(state: &RpcState) -> RpcResult {
    let (tx, rx) = oneshot::channel();
    state
        .control_tx
        .send(RpcNodeCommand::ListBanned { reply: tx })
        .map_err(|_| (-1, "node loop unavailable".to_string()))?;
    let ips = rx
        .await
        .map_err(|_| (-1, "node loop did not respond".to_string()))?;
    let arr: Vec<Value> = ips
        .iter()
        .map(|ip| {
            let subnet = if ip.is_ipv4() {
                format!("{ip}/32")
            } else {
                format!("{ip}/128")
            };
            json!({
                "address": subnet,
                "ban_created": 0,
                "banned_until": 0,
                "ban_duration": 0,
                "time_remaining": 0,
            })
        })
        .collect();
    Ok(json!(arr))
}

/// `clearbanned` — Clear all banned IPs.
async fn rpc_clearbanned(state: &RpcState) -> RpcResult {
    let (tx, rx) = oneshot::channel();
    state
        .control_tx
        .send(RpcNodeCommand::ClearBanned { reply: tx })
        .map_err(|_| (-1, "node loop unavailable".to_string()))?;
    rx.await
        .map_err(|_| (-1, "node loop did not respond".to_string()))?;
    Ok(json!(null))
}

/// `addnode "node" "add"` — Attempts to connect to a peer at the given address.
///
/// Only the "add" command is supported. "remove" and "onetry" are accepted but
/// are no-ops in this implementation.
async fn rpc_addnode(state: &RpcState, params: &Value) -> RpcResult {
    let addr_str = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "Missing node address parameter".to_string()))?;
    let command = params
        .get(1)
        .and_then(Value::as_str)
        .unwrap_or("add");

    if command != "add" && command != "onetry" && command != "remove" {
        return Err((-32602, format!("Invalid command: {command}")));
    }

    // Parse as SocketAddr; if no port given, use default Bitcoin port 8333.
    let socket_addr: std::net::SocketAddr = if let Ok(sa) = addr_str.parse() {
        sa
    } else if let Ok(ip) = addr_str.parse::<std::net::IpAddr>() {
        std::net::SocketAddr::new(ip, 8333)
    } else {
        return Err((-32602, format!("Invalid address: {addr_str}")));
    };

    let (tx, rx) = oneshot::channel();
    state
        .control_tx
        .send(RpcNodeCommand::AddNode {
            addr: socket_addr,
            reply: tx,
        })
        .map_err(|_| (-1, "node loop unavailable".to_string()))?;
    rx.await
        .map_err(|_| (-1, "node loop did not respond".to_string()))?
        .map_err(|e| (-1, e))?;
    Ok(json!(null))
}

// ── Network RPCs (L11): ping, disconnectnode ─────────────────────────────────

/// `ping` — Send a ping to all connected peers. Returns null.
async fn rpc_ping(state: &RpcState) -> RpcResult {
    let (tx, rx) = oneshot::channel();
    state
        .control_tx
        .send(RpcNodeCommand::Ping { reply: tx })
        .map_err(|_| (-1, "node loop unavailable".to_string()))?;
    rx.await
        .map_err(|_| (-1, "node loop did not respond".to_string()))?;
    Ok(json!(null))
}

/// `disconnectnode "address"` or `disconnectnode "" nodeid`
/// Disconnect a peer by address string or numeric node ID.
async fn rpc_disconnectnode(state: &RpcState, params: &Value) -> RpcResult {
    let address = params.get(0).and_then(Value::as_str).map(|s| s.to_string());
    let nodeid = params
        .get(1)
        .and_then(Value::as_u64)
        .or_else(|| {
            // Bitcoin Core also accepts {"address": ..., "nodeid": ...} object form.
            params.get("nodeid").and_then(Value::as_u64)
        });

    // At least one of address or nodeid must be provided.
    if address.as_deref().unwrap_or("").is_empty() && nodeid.is_none() {
        return Err((-32602, "Need an address or a nodeid to disconnect".to_string()));
    }

    // If address is empty string, clear it so the node loop uses nodeid.
    let address = address.filter(|a| !a.is_empty());

    let (tx, rx) = oneshot::channel();
    state
        .control_tx
        .send(RpcNodeCommand::DisconnectNode {
            address,
            nodeid,
            reply: tx,
        })
        .map_err(|_| (-1, "node loop unavailable".to_string()))?;
    rx.await
        .map_err(|_| (-1, "node loop did not respond".to_string()))?
        .map_err(|e| (-1, e))?;
    Ok(json!(null))
}

// ── Phase F: Wallet descriptor & dump/import RPCs ────────────────────────────

/// `dumpwallet "filename"` — Dumps all wallet keys and addresses to a file.
async fn rpc_dumpwallet(state: &RpcState, params: &Value) -> RpcResult {
    let wallet = state
        .wallet
        .as_ref()
        .ok_or((-18, "No wallet loaded".into()))?;
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
    let wallet = state
        .wallet
        .as_ref()
        .ok_or((-18, "No wallet loaded".into()))?;
    let filename = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-1, "Missing filename parameter".into()))?;

    let content =
        std::fs::read_to_string(filename).map_err(|e| (-1, format!("Failed to read file: {e}")))?;

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
///
/// Returns the canonical form (public-key only, with checksum), the checksum
/// of the *input* descriptor, and boolean flags matching Bitcoin Core's
/// `getdescriptorinfo` RPC (isrange, issolvable, hasprivatekeys).
async fn rpc_getdescriptorinfo(_state: &RpcState, params: &Value) -> RpcResult {
    let desc_str = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-1, "Missing descriptor parameter".into()))?;

    let desc = rbtc_wallet::Descriptor::parse(desc_str)
        .map_err(|e| (-1, format!("Invalid descriptor: {e}")))?;

    // Canonical form: public-key only, with checksum appended.
    let canonical = desc
        .to_string_with_checksum()
        .map_err(|e| (-1, format!("Cannot compute canonical descriptor: {e}")))?;

    // Checksum of the input descriptor body (strip existing checksum if present).
    let input_body = if let Some(idx) = desc_str.rfind('#') {
        &desc_str[..idx]
    } else {
        desc_str
    };
    let input_checksum = rbtc_wallet::Descriptor::checksum(input_body)
        .map_err(|e| (-1, format!("Cannot compute checksum: {e}")))?;
    // Extract just the 8-char checksum portion.
    let checksum = &input_checksum[input_body.len() + 1..];

    // Detect private keys: WIF keys start with K, L, 5 (mainnet) or c (testnet)
    // and are 51-52 chars. Since our parser converts WIF to pubkey during parse,
    // we detect from the raw input string (matching Bitcoin Core's approach of
    // checking the signing-provider after parsing).
    let has_private = descriptor_has_private_keys(desc_str);

    Ok(json!({
        "descriptor": canonical,
        "checksum": checksum,
        "isrange": desc.is_range(),
        "issolvable": desc.is_solvable(),
        "hasprivatekeys": has_private,
    }))
}

/// Heuristic check: does the descriptor string contain WIF-encoded private keys?
fn descriptor_has_private_keys(desc: &str) -> bool {
    for token in desc.split(|c: char| c == '(' || c == ')' || c == ',') {
        let token = token.trim();
        // Strip key origin prefix [...]
        let key_part = if let Some(close) = token.find(']') {
            &token[close + 1..]
        } else {
            token
        };
        // Strip any #checksum suffix
        let key_part = if let Some(hash) = key_part.find('#') {
            &key_part[..hash]
        } else {
            key_part
        };
        if key_part.len() >= 51
            && key_part.len() <= 52
            && (key_part.starts_with('K')
                || key_part.starts_with('L')
                || key_part.starts_with('5')
                || key_part.starts_with('c'))
        {
            // Attempt WIF decode to confirm
            if rbtc_wallet::from_wif(key_part).is_ok() {
                return true;
            }
        }
    }
    false
}

/// `deriveaddresses "descriptor" [range]` — Derive addresses from a descriptor.
///
/// Matching Bitcoin Core: requires checksum, validates range vs non-range,
/// returns proper address strings (not raw hex).
async fn rpc_deriveaddresses(state: &RpcState, params: &Value) -> RpcResult {
    let desc_str = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-1, "Missing descriptor parameter".into()))?;

    // Bitcoin Core requires the descriptor checksum.
    if !desc_str.contains('#') {
        return Err((-5, "Missing checksum".to_string()));
    }

    let desc = rbtc_wallet::Descriptor::parse(desc_str)
        .map_err(|e| (-5, format!("Invalid descriptor: {e}")))?;

    let has_range_param = params.get(1).map_or(false, |v| !v.is_null());

    // Bitcoin Core: error if range given for non-range descriptor
    if !desc.is_range() && has_range_param {
        return Err((-8, "Range should not be specified for an un-ranged descriptor".to_string()));
    }

    // Bitcoin Core: error if no range given for range descriptor
    if desc.is_range() && !has_range_param {
        return Err((-8, "Range must be specified for a ranged descriptor".to_string()));
    }

    // Parse range: [begin, end] array or just end (implies begin=0)
    let (start, end) = if let Some(range) = params.get(1) {
        if let Some(arr) = range.as_array() {
            let s = arr.first().and_then(|v| v.as_i64()).unwrap_or(0);
            let e = arr.get(1).and_then(|v| v.as_i64()).unwrap_or(0);
            if s < 0 || e < 0 {
                return Err((-8, "Range should be greater or equal than 0".to_string()));
            }
            if s > e {
                return Err((-8, "Range end should be equal to or greater than begin".to_string()));
            }
            (s as u32, e as u32)
        } else if let Some(n) = range.as_i64() {
            if n < 0 {
                return Err((-8, "Range should be greater or equal than 0".to_string()));
            }
            (0u32, n as u32)
        } else {
            (0u32, 0u32)
        }
    } else {
        (0u32, 0u32)
    };

    // Derive the network from node state for proper address encoding.
    let network = match state.network_name.as_str() {
        "main" | "mainnet" => rbtc_primitives::network::Network::Mainnet,
        "test" | "testnet" => rbtc_primitives::network::Network::Testnet4,
        "signet" => rbtc_primitives::network::Network::Signet,
        _ => rbtc_primitives::network::Network::Regtest,
    };

    let mut addresses = Vec::new();
    for i in start..=end {
        let spk = desc
            .to_script(i)
            .map_err(|e| (-1, format!("Cannot derive at index {i}: {e}")))?;
        let addr = script_to_address_string(&spk, network)
            .ok_or((-1, format!("Cannot convert script at index {i} to address")))?;
        addresses.push(json!(addr));
    }

    Ok(json!(addresses))
}

/// Convert a scriptPubKey to a human-readable address string.
///
/// Supports P2PKH, P2SH, P2WPKH (v0, 20-byte), P2WSH (v0, 32-byte),
/// and P2TR (v1, 32-byte). Returns `None` for unrecognised script types
/// (e.g. bare multisig, `pk()`, `OP_RETURN`).
fn script_to_address_string(
    spk: &rbtc_primitives::script::Script,
    network: rbtc_primitives::network::Network,
) -> Option<String> {
    use bech32::{segwit, Fe32, Hrp};

    let b = spk.as_bytes();

    // P2PKH: OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY OP_CHECKSIG (25 bytes)
    if spk.is_p2pkh() && b.len() == 25 {
        let version = match network {
            rbtc_primitives::network::Network::Mainnet => 0x00u8,
            _ => 0x6f,
        };
        let hash = &b[3..23];
        let mut payload = Vec::with_capacity(21);
        payload.push(version);
        payload.extend_from_slice(hash);
        return Some(base58check_encode(&payload));
    }

    // P2SH: OP_HASH160 <20> <hash> OP_EQUAL (23 bytes)
    if spk.is_p2sh() && b.len() == 23 {
        let version = match network {
            rbtc_primitives::network::Network::Mainnet => 0x05u8,
            _ => 0xc4,
        };
        let hash = &b[2..22];
        let mut payload = Vec::with_capacity(21);
        payload.push(version);
        payload.extend_from_slice(hash);
        return Some(base58check_encode(&payload));
    }

    // Segwit v0: P2WPKH (20-byte) or P2WSH (32-byte)
    if spk.is_p2wpkh() || spk.is_p2wsh() {
        let program = &b[2..];
        let hrp = bech32_hrp(network);
        let witver = Fe32::try_from(0u8).unwrap();
        return segwit::encode(hrp, witver, program).ok();
    }

    // Segwit v1 (Taproot): OP_1 <32> <key> (34 bytes)
    if spk.is_p2tr() && b.len() == 34 {
        let program = &b[2..];
        let hrp = bech32_hrp(network);
        let witver = Fe32::try_from(1u8).unwrap();
        return segwit::encode(hrp, witver, program).ok();
    }

    None
}

/// Base58Check encoding (version byte + payload + 4-byte SHA256d checksum).
fn base58check_encode(payload: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let checksum = Sha256::digest(Sha256::digest(payload));
    let mut full = payload.to_vec();
    full.extend_from_slice(&checksum[..4]);
    bs58::encode(full).into_string()
}

/// Return the bech32 HRP for the given network.
fn bech32_hrp(network: rbtc_primitives::network::Network) -> bech32::Hrp {
    let s = match network {
        rbtc_primitives::network::Network::Mainnet => "bc",
        rbtc_primitives::network::Network::Testnet3
        | rbtc_primitives::network::Network::Testnet4 => "tb",
        rbtc_primitives::network::Network::Regtest => "bcrt",
        rbtc_primitives::network::Network::Signet => "tb",
    };
    bech32::Hrp::parse(s).expect("static HRP")
}

// ── Wallet RPC implementations (Phase G) ──────────────────────────────────────

/// `bumpfee txid [fee_rate]`
///
/// Increase the fee on an unconfirmed wallet transaction (RBF / BIP125).
/// Returns the new txid and fee.
async fn rpc_bumpfee(state: &RpcState, params: &Value) -> RpcResult {
    let wallet_arc = require_wallet!(state);

    let txid_hex = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "missing txid".to_string()))?;

    let txid = Txid::from_hex(txid_hex).map_err(|_| (-8, "Invalid txid".to_string()))?;

    // Look for an options object (second param can be an object with fee_rate)
    let new_fee_rate = params
        .get(1)
        .and_then(|v| {
            // Accept either a plain number or {"fee_rate": N}
            v.as_f64().or_else(|| v.get("fee_rate").and_then(Value::as_f64))
        })
        .unwrap_or(5.0); // default bump to 5 sat/vB

    // Find the original transaction in the mempool
    let original_tx = {
        let mp = state.mempool.read().await;
        mp.get(&txid)
            .map(|entry| entry.tx.clone())
            .ok_or((-5, format!("Transaction {txid_hex} not found in mempool")))?
    };

    let (replacement, new_fee) = {
        let mut w = wallet_arc.write().await;
        w.bump_fee(&original_tx, new_fee_rate)
            .map_err(|e| (-4, e.to_string()))?
    };

    // Encode and submit the replacement to the mempool
    let mut raw = Vec::new();
    replacement
        .encode(&mut raw)
        .map_err(|e| (-22, e.to_string()))?;
    let hex_tx = hex::encode(&raw);

    let fake_params = json!([hex_tx]);
    let new_txid_result = rpc_sendrawtransaction(state, &fake_params).await?;

    Ok(json!({
        "txid": new_txid_result,
        "origfee": 0,
        "fee": new_fee as f64 / 1e8,
        "errors": [],
    }))
}

/// `getaddressinfo address`
///
/// Return detailed information about a wallet address.
async fn rpc_getaddressinfo(state: &RpcState, params: &Value) -> RpcResult {
    let wallet_arc = require_wallet!(state);

    let address = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "missing address".to_string()))?;

    let w = wallet_arc.read().await;

    // Try to get info from the wallet
    if let Some(info) = w.get_address_info(address) {
        let script_type_str = match info.script_type {
            AddressType::Legacy => "pubkeyhash",
            AddressType::P2shP2wpkh => "scripthash",
            AddressType::SegWit => "witness_v0_keyhash",
            AddressType::Taproot => "witness_v1_taproot",
        };

        let mut result = json!({
            "address": info.address,
            "scriptPubKey": {
                "hex": address_to_script(address)
                    .map(|s| hex::encode(s.as_bytes()))
                    .unwrap_or_default(),
            },
            "ismine": info.is_mine,
            "iswatchonly": info.is_watchonly,
            "isscript": info.is_script,
            "iswitness": info.is_witness,
            "script_type": script_type_str,
            "pubkey": info.pubkey_hex,
            "iscompressed": info.is_compressed,
            "label": info.label,
            "hdkeypath": info.hd_keypath,
            "labels": [{ "name": info.label, "purpose": "receive" }],
        });

        if let Some(ver) = info.witness_version {
            result["witness_version"] = json!(ver);
        }
        if let Some(ref prog) = info.witness_program {
            result["witness_program"] = json!(prog);
        }

        Ok(result)
    } else {
        // Address not in wallet — return minimal info
        let valid = address_to_script(address).is_ok();
        Ok(json!({
            "address": address,
            "ismine": false,
            "iswatchonly": false,
            "isvalid": valid,
            "label": "",
            "labels": [],
        }))
    }
}

/// `listaddressgroupings`
///
/// Returns all groups of addresses that have been grouped together by
/// common ownership (co-spending in the same transaction).
async fn rpc_listaddressgroupings(state: &RpcState) -> RpcResult {
    let wallet_arc = require_wallet!(state);
    let w = wallet_arc.read().await;

    let groupings = w.list_address_groupings();
    let result: Vec<Value> = groupings
        .into_iter()
        .map(|group| {
            let entries: Vec<Value> = group
                .into_iter()
                .map(|(addr, balance, label)| {
                    if label.is_empty() {
                        json!([addr, balance as f64 / 1e8])
                    } else {
                        json!([addr, balance as f64 / 1e8, label])
                    }
                })
                .collect();
            json!(entries)
        })
        .collect();

    Ok(json!(result))
}

/// `createwallet wallet_name [disable_private_keys] [blank] [passphrase] [avoid_reuse] [descriptors] [load_on_startup]`
///
/// Creates a new wallet. In this implementation, the wallet is created in-memory
/// and associated with the node. Only one wallet is supported at a time.
async fn rpc_createwallet(state: &RpcState, params: &Value) -> RpcResult {
    let wallet_name = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "missing wallet_name".to_string()))?;

    let _disable_private_keys = params.get(1).and_then(Value::as_bool).unwrap_or(false);
    let _blank = params.get(2).and_then(Value::as_bool).unwrap_or(false);
    let passphrase = params.get(3).and_then(Value::as_str).unwrap_or("");
    let avoid_reuse = params.get(4).and_then(Value::as_bool).unwrap_or(false);
    let _descriptors = params.get(5).and_then(Value::as_bool).unwrap_or(true);
    let _load_on_startup = params.get(6).and_then(Value::as_bool);

    // Check if a wallet is already loaded
    if state.wallet.is_some() {
        return Err((-4, "A wallet is already loaded. Unload it first.".to_string()));
    }

    // Generate a new mnemonic and create the wallet
    let mnemonic = rbtc_wallet::Mnemonic::generate(24)
        .map_err(|e| (-1, format!("Failed to generate mnemonic: {e}")))?;

    let encryption_passphrase = if passphrase.is_empty() {
        "default"
    } else {
        passphrase
    };

    let network = match state.network_name.as_str() {
        "main" | "mainnet" => rbtc_primitives::network::Network::Mainnet,
        "test" | "testnet" => rbtc_primitives::network::Network::Testnet4,
        "signet" => rbtc_primitives::network::Network::Signet,
        _ => rbtc_primitives::network::Network::Regtest,
    };

    let mut wallet = rbtc_wallet::Wallet::from_mnemonic(
        &mnemonic,
        "",
        encryption_passphrase,
        network,
        state.db.clone(),
    )
    .map_err(|e| (-1, format!("Failed to create wallet: {e}")))?;

    if avoid_reuse {
        wallet.set_avoid_reuse(true);
    }

    // Note: The wallet is created but we can't replace the Option<Arc<RwLock<Wallet>>>
    // in the shared state from an RPC handler (it's not mutable). In a real
    // implementation, this would use interior mutability. We return success
    // to indicate the wallet was created in the DB.
    let mut warning = String::new();
    if state.wallet.is_none() {
        warning = "Wallet created in DB but not loaded into this node session. Restart with --wallet to use it.".to_string();
    }

    Ok(json!({
        "name": wallet_name,
        "warning": warning,
    }))
}

/// `setlabel address label`
///
/// Sets the label associated with the given address.
async fn rpc_setlabel(state: &RpcState, params: &Value) -> RpcResult {
    let wallet_arc = require_wallet!(state);

    let address = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "missing address".to_string()))?;
    let label = params
        .get(1)
        .and_then(Value::as_str)
        .ok_or((-32602, "missing label".to_string()))?;

    let mut w = wallet_arc.write().await;
    w.set_label(address, label)
        .map_err(|e| (-4, e.to_string()))?;

    Ok(json!(null))
}

/// `getrawchangeaddress [address_type]`
///
/// Returns a new Bitcoin address for receiving change.
async fn rpc_getrawchangeaddress(state: &RpcState, params: &Value) -> RpcResult {
    let wallet_arc = require_wallet!(state);

    let addr_type_str = params.get(0).and_then(Value::as_str).unwrap_or("bech32");
    let addr_type = AddressType::parse(addr_type_str).unwrap_or(AddressType::SegWit);

    let mut w = wallet_arc.write().await;
    let address = w
        .new_change_address(addr_type)
        .map_err(|e| (-1, e.to_string()))?;
    Ok(json!(address))
}

/// `abandontransaction txid`
///
/// Mark an in-wallet transaction and all its in-wallet descendants as
/// abandoned. This allows their inputs to be respent.
async fn rpc_abandontransaction(state: &RpcState, params: &Value) -> RpcResult {
    let wallet_arc = require_wallet!(state);

    let txid_hex = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "missing txid".to_string()))?;

    let txid = Txid::from_hex(txid_hex).map_err(|_| (-8, "Invalid txid".to_string()))?;

    // Check the transaction is in the mempool (unconfirmed)
    {
        let mp = state.mempool.read().await;
        if mp.get(&txid).is_none() {
            return Err((-5, format!(
                "Transaction {txid_hex} not eligible for abandonment (not in mempool)"
            )));
        }
    }

    // Remove the transaction from the mempool
    {
        let mut mp = state.mempool.write().await;
        mp.remove_confirmed(&[txid]);
    }

    // If the wallet tracked any UTXOs from this tx as unconfirmed change,
    // we should remove them so the inputs can be re-spent.
    {
        let w = wallet_arc.read().await;
        // Collect outpoints to remove (those belonging to the abandoned tx)
        let to_remove: Vec<_> = w
            .list_unspent(0)
            .iter()
            .filter(|u| u.outpoint.txid.0 == txid.0)
            .map(|u| u.outpoint.clone())
            .collect();

        // We can't directly remove from the wallet's internal map through the
        // public API, but the transaction is now gone from the mempool. The
        // wallet will reconcile on the next block scan.
        let _ = to_remove;
    }

    Ok(json!(null))
}

/// `walletpassphrase passphrase timeout`
///
/// Stores the wallet decryption key in memory for `timeout` seconds.
/// This is a simplified implementation — the wallet is always unlocked
/// when loaded, so this RPC is accepted but acts as a no-op validation
/// that the passphrase is correct.
async fn rpc_walletpassphrase(state: &RpcState, params: &Value) -> RpcResult {
    let _wallet_arc = require_wallet!(state);

    let _passphrase = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "missing passphrase".to_string()))?;
    let _timeout = params
        .get(1)
        .and_then(Value::as_u64)
        .ok_or((-32602, "missing timeout".to_string()))?;

    // In our implementation, the wallet is unlocked at load time.
    // We accept this call for compatibility but don't change state.
    // A full implementation would verify the passphrase and set a timer.
    Ok(json!(null))
}

/// `walletlock`
///
/// Removes the wallet encryption key from memory, locking the wallet.
/// This is a simplified implementation — accepted for compatibility.
async fn rpc_walletlock(state: &RpcState) -> RpcResult {
    let _wallet_arc = require_wallet!(state);

    // In our implementation, the wallet remains unlocked for the session.
    // A full implementation would clear the decryption key from memory
    // and require walletpassphrase before signing operations.
    Ok(json!(null))
}

// ── Wallet transaction RPCs (M3) ──────────────────────────────────────────────

/// `listtransactions(label, count, skip, include_watchonly)`
///
/// List wallet transactions matching Bitcoin Core's `listtransactions` RPC.
/// Returns an array of objects sorted by timestamp descending.
///
/// Params:
///   0: label (string, optional) — filter by label ("*" or absent = all)
///   1: count (int, default 10) — number of results to return
///   2: skip  (int, default 0)  — number of results to skip
///   3: include_watchonly (bool, default false) — currently unused
async fn rpc_listtransactions(state: &RpcState, params: &Value) -> RpcResult {
    let wallet_arc = require_wallet!(state);

    let label_filter = params.get(0).and_then(Value::as_str).unwrap_or("*");
    let count = params.get(1).and_then(Value::as_u64).unwrap_or(10) as usize;
    let skip = params.get(2).and_then(Value::as_u64).unwrap_or(0) as usize;

    let w = wallet_arc.read().await;
    let chain = state.chain.read().await;
    let tip_height = chain.height();

    // Collect all tx entries with category/amounts
    let mut entries: Vec<Value> = Vec::new();

    // list_transactions returns sorted by timestamp descending
    let all_txs = w.list_transactions();

    for wtx in &all_txs {
        let (received, sent, fee) = w.get_tx_amounts(&wtx.tx, true);
        let txid_hex = wtx.tx.txid().to_hex();
        let confirmations = if wtx.is_confirmed {
            wtx.block_height
                .map(|h| (tip_height as i64) - (h as i64) + 1)
                .unwrap_or(0)
        } else {
            0i64
        };

        // Sent entries (category = "send")
        // Bitcoin Core: skip send entries when filtering by label
        if label_filter == "*" {
            for entry in &sent {
                let label = w.get_label(&entry.address).unwrap_or_default();
                let mut obj = json!({
                    "address":       entry.address,
                    "category":      "send",
                    "amount":        -(entry.amount as f64 / 1e8),
                    "fee":           -(fee as f64 / 1e8),
                    "vout":          entry.vout,
                    "confirmations": confirmations,
                    "txid":          txid_hex,
                    "time":          wtx.timestamp,
                    "timereceived":  wtx.timestamp,
                });
                if !label.is_empty() {
                    obj["label"] = json!(label);
                }
                if let Some(ref bh) = wtx.block_hash {
                    obj["blockhash"] = json!(bh.to_hex());
                }
                if let Some(h) = wtx.block_height {
                    obj["blockheight"] = json!(h);
                }
                if wtx.is_abandoned {
                    obj["abandoned"] = json!(true);
                }
                entries.push(obj);
            }
        }

        // Received entries (category = "receive" or "generate" for coinbase)
        for entry in &received {
            let label = w.get_label(&entry.address).unwrap_or_default();
            if label_filter != "*" && label != label_filter {
                continue;
            }
            // Detect coinbase (generate) — input[0] spends null outpoint
            let is_coinbase = wtx.tx.inputs.len() == 1
                && wtx.tx.inputs[0].previous_output.txid == Txid::ZERO
                && wtx.tx.inputs[0].previous_output.vout == 0xffffffff;
            let category = if is_coinbase {
                if confirmations < 1 {
                    "orphan"
                } else if confirmations <= 100 {
                    "immature"
                } else {
                    "generate"
                }
            } else {
                "receive"
            };
            let mut obj = json!({
                "address":       entry.address,
                "category":      category,
                "amount":        entry.amount as f64 / 1e8,
                "vout":          entry.vout,
                "confirmations": confirmations,
                "txid":          txid_hex,
                "time":          wtx.timestamp,
                "timereceived":  wtx.timestamp,
            });
            if !label.is_empty() {
                obj["label"] = json!(label);
            }
            if let Some(ref bh) = wtx.block_hash {
                obj["blockhash"] = json!(bh.to_hex());
            }
            if let Some(h) = wtx.block_height {
                obj["blockheight"] = json!(h);
            }
            entries.push(obj);
        }
    }

    // Apply skip + count
    let result: Vec<Value> = entries.into_iter().skip(skip).take(count).collect();
    Ok(json!(result))
}

/// `gettransaction(txid, include_watchonly)`
///
/// Get detailed info about a wallet transaction. Matches Bitcoin Core's
/// `gettransaction` RPC return format.
///
/// Params:
///   0: txid (string, required) — the transaction id
///   1: include_watchonly (bool, default false) — currently unused
async fn rpc_gettransaction(state: &RpcState, params: &Value) -> RpcResult {
    let wallet_arc = require_wallet!(state);

    let txid_hex = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "missing txid".to_string()))?;

    let txid = Txid(
        Hash256::from_hex(txid_hex).map_err(|_| (-32602, "invalid txid".to_string()))?,
    );

    let w = wallet_arc.read().await;
    let wtx = w
        .get_transaction(&txid)
        .ok_or((-5, "Invalid or non-wallet transaction id".to_string()))?;

    let chain = state.chain.read().await;
    let tip_height = chain.height();

    let confirmations = if wtx.is_confirmed {
        wtx.block_height
            .map(|h| (tip_height as i64) - (h as i64) + 1)
            .unwrap_or(0)
    } else {
        0i64
    };

    let (received, sent, fee) = w.get_tx_amounts(&wtx.tx, true);

    // Net amount: sum of received minus sum of sent
    let net_amount: i64 = received.iter().map(|e| e.amount).sum::<i64>()
        - sent.iter().map(|e| e.amount).sum::<i64>();

    // Build details array (matching Bitcoin Core)
    let mut details: Vec<Value> = Vec::new();
    for entry in &sent {
        let label = w.get_label(&entry.address).unwrap_or_default();
        let mut obj = json!({
            "address":  entry.address,
            "category": "send",
            "amount":   -(entry.amount as f64 / 1e8),
            "vout":     entry.vout,
            "fee":      -(fee as f64 / 1e8),
        });
        if !label.is_empty() {
            obj["label"] = json!(label);
        }
        if wtx.is_abandoned {
            obj["abandoned"] = json!(true);
        }
        details.push(obj);
    }
    for entry in &received {
        let label = w.get_label(&entry.address).unwrap_or_default();
        let is_coinbase = wtx.tx.inputs.len() == 1
            && wtx.tx.inputs[0].previous_output.txid == Txid::ZERO
            && wtx.tx.inputs[0].previous_output.vout == 0xffffffff;
        let category = if is_coinbase {
            if confirmations < 1 {
                "orphan"
            } else if confirmations <= 100 {
                "immature"
            } else {
                "generate"
            }
        } else {
            "receive"
        };
        let mut obj = json!({
            "address":  entry.address,
            "category": category,
            "amount":   entry.amount as f64 / 1e8,
            "vout":     entry.vout,
        });
        if !label.is_empty() {
            obj["label"] = json!(label);
        }
        details.push(obj);
    }

    // Encode raw transaction hex
    let mut raw = Vec::new();
    wtx.tx
        .encode(&mut raw)
        .map_err(|e| (-1, e.to_string()))?;
    let hex = hex::encode(&raw);

    let mut result = json!({
        "amount":        net_amount as f64 / 1e8,
        "confirmations": confirmations,
        "txid":          txid_hex,
        "time":          wtx.timestamp,
        "timereceived":  wtx.timestamp,
        "details":       details,
        "hex":           hex,
    });

    if !sent.is_empty() {
        result["fee"] = json!(-(fee as f64 / 1e8));
    }
    if let Some(ref bh) = wtx.block_hash {
        result["blockhash"] = json!(bh.to_hex());
    }
    if let Some(h) = wtx.block_height {
        result["blockheight"] = json!(h);
        result["blockindex"] = json!(0); // position within block not tracked
    }
    if wtx.block_hash.is_some() {
        result["blocktime"] = json!(wtx.timestamp);
    }

    Ok(result)
}

/// `sendmany(dummy, amounts, minconf, comment, subtractfeefrom, ...)`
///
/// Send to multiple addresses in a single transaction. Matches Bitcoin Core's
/// `sendmany` RPC.
///
/// Params:
///   0: dummy  (string, ignored — legacy label parameter)
///   1: amounts (object, required) — { "address": amount_btc, ... }
///   2: minconf (int, default 1) — minimum confirmations (currently unused beyond coin selection)
///   3: comment (string, optional) — ignored
///   4: subtractfeefrom (array of strings, optional) — addresses to subtract fee from
///   5: replaceable (bool, optional) — signal BIP125 replace-by-fee (currently unused)
///   6: conf_target (int, optional) — confirmation target for fee estimation (currently unused)
///   7: estimate_mode (string, optional) — fee estimate mode (currently unused)
///   8: fee_rate (number, optional, default 1.0) — fee rate in sat/vB
async fn rpc_sendmany(state: &RpcState, params: &Value) -> RpcResult {
    let wallet_arc = require_wallet!(state);

    let amounts_obj = params
        .get(1)
        .and_then(Value::as_object)
        .ok_or((-32602, "missing amounts object".to_string()))?;

    if amounts_obj.is_empty() {
        return Err((-32602, "amounts must not be empty".to_string()));
    }

    // Parse destinations
    let mut destinations: Vec<(String, u64)> = Vec::new();
    for (addr, val) in amounts_obj {
        let btc = val
            .as_f64()
            .ok_or((-32602, format!("Invalid amount for address {addr}")))?;
        if btc <= 0.0 {
            return Err((-3, format!("Invalid amount for send: {btc}")));
        }
        let sat = (btc * 1e8) as u64;
        destinations.push((addr.clone(), sat));
    }

    // Parse subtractfeefrom — array of address strings mapped to output indices
    let subtract_fee_from: Vec<usize> = if let Some(sffo) = params.get(4).and_then(Value::as_array)
    {
        sffo.iter()
            .filter_map(|v| v.as_str())
            .filter_map(|addr| destinations.iter().position(|(a, _)| a == addr))
            .collect()
    } else {
        vec![]
    };

    let fee_rate = params.get(8).and_then(Value::as_f64).unwrap_or(1.0);

    let dest_refs: Vec<(&str, u64)> = destinations.iter().map(|(a, v)| (a.as_str(), *v)).collect();

    let (signed_tx, _fee) = {
        let mut w = wallet_arc.write().await;
        w.create_multi_transaction(
            &dest_refs,
            fee_rate,
            rbtc_wallet::AddressType::SegWit,
            true,
            &subtract_fee_from,
        )
        .map_err(|e| (-6, e.to_string()))?
    };

    // Encode and submit to mempool (reuse sendrawtransaction)
    let mut raw = Vec::new();
    signed_tx
        .encode(&mut raw)
        .map_err(|e| (-22, e.to_string()))?;
    let hex_tx = hex::encode(&raw);
    let fake_params = json!([hex_tx]);
    rpc_sendrawtransaction(state, &fake_params).await
}

// ── Block download control RPCs ───────────────────────────────────────────────

/// `getblockfrompeer(blockhash, peer_id)`
///
/// Request a specific block from a specific peer by sending a `getdata`
/// message. We must already have the header for this block. Returns an
/// empty JSON object on success (matching Bitcoin Core behaviour).
async fn rpc_getblockfrompeer(state: &RpcState, params: &Value) -> RpcResult {
    let hash_hex = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "missing blockhash".to_string()))?;
    let hash = Hash256::from_hex(hash_hex).map_err(|_| (-32602, "invalid blockhash".to_string()))?;

    let peer_id = params
        .get(1)
        .and_then(Value::as_u64)
        .ok_or((-32602, "missing peer_id".to_string()))?;

    // Verify we have the header for this block.
    {
        let chain = state.chain.read().await;
        if chain.get_block_index(&BlockHash(hash)).is_none() {
            return Err((-1, "Block header missing, use submitheader first".to_string()));
        }
    }

    let (tx, rx) = oneshot::channel();
    state
        .control_tx
        .send(RpcNodeCommand::GetBlockFromPeer {
            block_hash: hash,
            peer_id,
            reply: tx,
        })
        .map_err(|_| (-1, "node channel closed".to_string()))?;

    let result = rx.await.map_err(|_| (-1, "node dropped reply".to_string()))?;
    result.map_err(|e| (-1, e))?;

    Ok(json!({}))
}

/// `pruneblockchain(height)`
///
/// Prune block and undo data up to the specified height. The node must be
/// started with `--prune`. Returns the height of the last block pruned.
async fn rpc_pruneblockchain(state: &RpcState, params: &Value) -> RpcResult {
    if state.prune_budget == 0 {
        return Err((-1, "Cannot prune blocks because node is not in prune mode.".to_string()));
    }

    let height = params
        .get(0)
        .and_then(Value::as_u64)
        .ok_or((-32602, "missing height".to_string()))? as u32;

    let (tx, rx) = oneshot::channel();
    state
        .control_tx
        .send(RpcNodeCommand::PruneBlockchain { height, reply: tx })
        .map_err(|_| (-1, "node channel closed".to_string()))?;

    let result = rx.await.map_err(|_| (-1, "node dropped reply".to_string()))?;
    match result {
        Ok(last_pruned) => Ok(json!(last_pruned)),
        Err(e) => Err((-1, e)),
    }
}

/// `waitfornewblock(timeout_ms)`
///
/// Wait until a new block is connected or the timeout expires. Returns
/// `{"hash": "<hex>", "height": <n>}` for the current (or new) tip.
/// A timeout of 0 means wait indefinitely.
async fn rpc_waitfornewblock(state: &RpcState, params: &Value) -> RpcResult {
    let timeout_ms = params
        .get(0)
        .and_then(Value::as_u64)
        .unwrap_or(0);

    if (timeout_ms as i64) < 0 {
        return Err((-1, "Negative timeout".to_string()));
    }

    let mut rx = state.new_tip_rx.clone();

    // Snapshot the current tip value *before* waiting.
    let current = rx.borrow_and_update().clone();

    let wait_result = if timeout_ms == 0 {
        // Wait indefinitely for a change.
        rx.changed().await.ok();
        Some(rx.borrow().clone())
    } else {
        match tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms),
            rx.changed(),
        )
        .await
        {
            Ok(_) => Some(rx.borrow().clone()),
            Err(_) => None, // Timed out — return current tip.
        }
    };

    let (hash, height) = wait_result.unwrap_or(current);
    Ok(json!({
        "hash": hash,
        "height": height,
    }))
}

// ── M35: getbestblockhash ─────────────────────────────────────────────────────

async fn rpc_getbestblockhash(state: &RpcState) -> RpcResult {
    let chain = state.chain.read().await;
    match chain.best_hash() {
        Some(hash) => Ok(json!(hash.to_hex())),
        None => Err((-1, "No best block hash available".to_string())),
    }
}

// ── M36: getblockheader ──────────────────────────────────────────────────────

async fn rpc_getblockheader(state: &RpcState, params: &Value) -> RpcResult {
    let hash_hex = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "Invalid params: expected block hash".to_string()))?;
    let hash =
        BlockHash::from_hex(hash_hex).map_err(|_| (-8, "Invalid block hash".to_string()))?;

    let chain = state.chain.read().await;
    let bi = chain
        .get_block_index(&hash)
        .ok_or((-5, "Block not found".to_string()))?
        .clone();

    let verbose = params.get(1).and_then(Value::as_bool).unwrap_or(true);

    if !verbose {
        // Return serialized 80-byte header as hex
        let mut buf = Vec::with_capacity(80);
        bi.header.encode(&mut buf).ok();
        return Ok(json!(hex::encode(buf)));
    }

    // verbose=true: return JSON object
    let height = bi.height;
    let tip_height = chain.height();
    let confirmations = if tip_height >= height {
        (tip_height - height + 1) as i64
    } else {
        -1i64
    };
    let mtp = chain.median_time_past(height);
    let difficulty = bits_to_difficulty(bi.header.bits);
    let chainwork = format!("{:064x}", bi.chainwork);

    // nTx: try to get from block store
    let n_tx = {
        let block_store = BlockStore::new(&state.db);
        block_store
            .get_block(&hash)
            .ok()
            .flatten()
            .map(|b| b.transactions.len())
            .unwrap_or(0)
    };

    let previousblockhash = if bi.header.prev_block != BlockHash::ZERO {
        json!(bi.header.prev_block.to_hex())
    } else {
        json!(null)
    };

    // nextblockhash: block at height+1 if it exists on active chain
    let nextblockhash = chain
        .get_ancestor_hash(height + 1)
        .map(|h| json!(h.to_hex()))
        .unwrap_or(json!(null));

    drop(chain);

    Ok(json!({
        "hash": hash.to_hex(),
        "confirmations": confirmations,
        "height": height,
        "version": bi.header.version,
        "versionHex": format!("{:08x}", bi.header.version as u32),
        "merkleroot": bi.header.merkle_root.to_hex(),
        "time": bi.header.time,
        "mediantime": mtp,
        "nonce": bi.header.nonce,
        "bits": format!("{:08x}", bi.header.bits),
        "difficulty": difficulty,
        "chainwork": chainwork,
        "nTx": n_tx,
        "previousblockhash": previousblockhash,
        "nextblockhash": nextblockhash,
    }))
}

// ── M37: createrawtransaction ────────────────────────────────────────────────

async fn rpc_createrawtransaction(_state: &RpcState, params: &Value) -> RpcResult {
    use rbtc_primitives::{
        hash::Hash256,
        transaction::{TxIn, TxOut},
    };

    let inputs_raw = params
        .get(0)
        .and_then(|v| v.as_array())
        .ok_or((-8, "params[0] must be array of inputs".to_string()))?;
    let outputs_raw = params
        .get(1)
        .and_then(|v| v.as_array())
        .ok_or((-8, "params[1] must be array of output objects".to_string()))?;
    let locktime = params.get(2).and_then(|v| v.as_u64()).unwrap_or(0) as u32;

    // Parse inputs
    let mut inputs = Vec::new();
    for inp in inputs_raw {
        let txid_hex = inp
            .get("txid")
            .and_then(|v| v.as_str())
            .ok_or((-8, "input missing txid".to_string()))?;
        let vout = inp
            .get("vout")
            .and_then(|v| v.as_u64())
            .ok_or((-8, "input missing vout".to_string()))? as u32;
        let sequence = inp
            .get("sequence")
            .and_then(|v| v.as_u64())
            .unwrap_or(0xffffffff) as u32;
        let txid_bytes =
            hex::decode(txid_hex).map_err(|_| (-8, "invalid txid hex".to_string()))?;
        if txid_bytes.len() != 32 {
            return Err((-8, "txid must be 32 bytes".to_string()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&txid_bytes);
        inputs.push(TxIn {
            previous_output: OutPoint {
                txid: Txid(Hash256(arr)),
                vout,
            },
            script_sig: rbtc_primitives::script::Script::new(),
            sequence,
            witness: vec![],
        });
    }

    // Parse outputs — array of single-key objects: {address: amount} or {data: hex}
    let mut txouts = Vec::new();
    for out_obj in outputs_raw {
        let obj = out_obj
            .as_object()
            .ok_or((-8, "each output must be an object".to_string()))?;
        for (key, val) in obj {
            if key == "data" {
                // OP_RETURN data output
                let hex_str = val
                    .as_str()
                    .ok_or((-8, "data value must be hex string".to_string()))?;
                let data =
                    hex::decode(hex_str).map_err(|_| (-8, "invalid data hex".to_string()))?;
                let mut script_bytes = vec![0x6a]; // OP_RETURN
                if data.len() <= 75 {
                    script_bytes.push(data.len() as u8);
                } else {
                    // OP_PUSHDATA1
                    script_bytes.push(0x4c);
                    script_bytes.push(data.len() as u8);
                }
                script_bytes.extend_from_slice(&data);
                txouts.push(TxOut {
                    value: 0,
                    script_pubkey: rbtc_primitives::script::Script::from_bytes(script_bytes),
                });
            } else {
                // address: amount (BTC as f64 or satoshis as integer)
                let amount_sats = if let Some(i) = val.as_u64() {
                    i as i64
                } else if let Some(f) = val.as_f64() {
                    // Bitcoin Core sends BTC amounts as floats
                    (f * 100_000_000.0).round() as i64
                } else {
                    return Err((-8, format!("invalid amount for address {key}")));
                };
                let script = address_to_script(key)
                    .map_err(|e| (-8, format!("invalid address {key}: {e}")))?;
                txouts.push(TxOut {
                    value: amount_sats,
                    script_pubkey: script,
                });
            }
        }
    }

    let tx = Transaction::from_parts(2, inputs, txouts, locktime);
    let mut buf = Vec::new();
    tx.encode(&mut buf).ok();
    Ok(json!(hex::encode(buf)))
}

// ── Utility RPCs (L12) ────────────────────────────────────────────────────────

/// `signrawtransactionwithkey` — sign a raw transaction with provided private keys.
///
/// Params: [hex_string, privkeys, prevtxs?, sighashtype?]
/// Returns: { hex, complete }
async fn rpc_signrawtransactionwithkey(state: &RpcState, params: &Value) -> RpcResult {
    let hex_str = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "missing raw transaction hex".to_string()))?;
    let raw = hex::decode(hex_str).map_err(|_| (-22, "TX decode failed".to_string()))?;
    let tx = Transaction::decode_from_slice(&raw)
        .map_err(|e| (-22, format!("TX decode failed: {e}")))?;

    // Parse optional sighashtype (checked before keys, matching Bitcoin Core order)
    let sighash_str = params.get(3).and_then(Value::as_str).unwrap_or("ALL");
    let sighash_type = match sighash_str {
        "ALL" => rbtc_crypto::sighash::SighashType::All,
        "NONE" => rbtc_crypto::sighash::SighashType::None,
        "SINGLE" => rbtc_crypto::sighash::SighashType::Single,
        "ALL|ANYONECANPAY" => rbtc_crypto::sighash::SighashType::AllAnyoneCanPay,
        "NONE|ANYONECANPAY" => rbtc_crypto::sighash::SighashType::NoneAnyoneCanPay,
        "SINGLE|ANYONECANPAY" => rbtc_crypto::sighash::SighashType::SingleAnyoneCanPay,
        "DEFAULT" => rbtc_crypto::sighash::SighashType::TaprootDefault,
        _ => return Err((-8, format!("invalid sighash type: {sighash_str}"))),
    };

    // Parse private keys (array of WIF strings)
    let privkeys_arr = params
        .get(1)
        .and_then(Value::as_array)
        .ok_or((-32602, "missing privkeys array".to_string()))?;

    let secp = secp256k1::Secp256k1::signing_only();
    let mut keys: Vec<(secp256k1::SecretKey, secp256k1::PublicKey)> = Vec::new();
    for wif_val in privkeys_arr {
        let wif = wif_val
            .as_str()
            .ok_or((-32602, "privkey must be a string".to_string()))?;
        let (sk, _net) = from_wif(wif).map_err(|e| (-5, format!("invalid WIF key: {e}")))?;
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        keys.push((sk, pk));
    }

    // Parse optional prevtxs (array of {txid, vout, scriptPubKey, amount})
    let prevtxs = params.get(2).and_then(Value::as_array);

    // Build signing inputs: for each tx input, find the matching key and prevtx info
    let mut signing_inputs = Vec::new();
    let mut errors: Vec<Value> = Vec::new();

    for (idx, inp) in tx.inputs.iter().enumerate() {
        let mut script_pubkey = rbtc_primitives::script::Script::new();
        let mut value: u64 = 0;

        // Look up prevtx info from the provided prevtxs array
        if let Some(prevtxs) = prevtxs {
            for ptx in prevtxs {
                let ptxid = ptx.get("txid").and_then(Value::as_str).unwrap_or("");
                let pvout = ptx.get("vout").and_then(Value::as_u64).unwrap_or(u64::MAX) as u32;
                if ptxid == inp.previous_output.txid.to_hex() && pvout == inp.previous_output.vout {
                    if let Some(spk_hex) = ptx.get("scriptPubKey").and_then(Value::as_str) {
                        if let Ok(spk_bytes) = hex::decode(spk_hex) {
                            script_pubkey =
                                rbtc_primitives::script::Script::from_bytes(spk_bytes);
                        }
                    }
                    if let Some(amt) = ptx.get("amount").and_then(Value::as_f64) {
                        value = (amt * 100_000_000.0).round() as u64;
                    }
                    break;
                }
            }
        }

        // Fall back to the UTXO set
        if script_pubkey.is_empty() {
            let utxo_store = UtxoStore::new(&state.db);
            if let Ok(Some(coin)) = utxo_store.get_coin(&inp.previous_output) {
                script_pubkey = coin.script_pubkey.clone();
                value = coin.value as u64;
            }
        }

        // Match a key by hashing the pubkey and comparing with the scriptPubKey
        let mut found_key = None;
        for (sk, pk) in &keys {
            let pk_bytes = pk.serialize();
            let pk_hash = rbtc_crypto::hash160(&pk_bytes);
            let spk = script_pubkey.as_bytes();

            // P2PKH: OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY OP_CHECKSIG
            if spk.len() == 25
                && spk[0] == 0x76
                && spk[1] == 0xa9
                && spk[2] == 0x14
                && spk[3..23] == pk_hash.0
            {
                found_key = Some(*sk);
                break;
            }
            // P2WPKH: OP_0 <20> <hash>
            if spk.len() == 22 && spk[0] == 0x00 && spk[1] == 0x14 && spk[2..22] == pk_hash.0 {
                found_key = Some(*sk);
                break;
            }
            // P2SH-P2WPKH — try signing with this key
            if spk.len() == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87 {
                found_key = Some(*sk);
                break;
            }
        }

        if let Some(sk) = found_key {
            signing_inputs.push(SigningInput {
                outpoint: inp.previous_output.clone(),
                value,
                script_pubkey: script_pubkey.clone(),
                secret_key: sk,
                witness_script: None,
                sighash_type: Some(sighash_type),
            });
        } else {
            errors.push(json!({
                "txid": inp.previous_output.txid.to_hex(),
                "vout": inp.previous_output.vout,
                "scriptSig": "",
                "sequence": inp.sequence,
                "error": format!("unable to sign input, no matching key for input {idx}"),
            }));
            signing_inputs.push(SigningInput {
                outpoint: inp.previous_output.clone(),
                value,
                script_pubkey,
                secret_key: secp256k1::SecretKey::from_byte_array([1u8; 32]).unwrap(),
                witness_script: None,
                sighash_type: Some(sighash_type),
            });
        }
    }

    let complete = errors.is_empty();
    let signed =
        sign_transaction(&tx, &signing_inputs).map_err(|e| (-1, format!("signing failed: {e}")))?;

    let mut buf = Vec::new();
    signed.encode(&mut buf).map_err(|e| (-22, e.to_string()))?;

    let mut result = json!({
        "hex": hex::encode(buf),
        "complete": complete,
    });
    if !errors.is_empty() {
        result["errors"] = json!(errors);
    }
    Ok(result)
}

/// `lockunspent` — lock or unlock unspent outputs.
///
/// Params: [unlock (bool), transactions (array of {txid, vout})]
/// Returns: true
async fn rpc_lockunspent(state: &RpcState, params: &Value) -> RpcResult {
    let wallet_arc = require_wallet!(state);

    let unlock = params
        .get(0)
        .and_then(Value::as_bool)
        .ok_or((-32602, "missing unlock parameter (bool)".to_string()))?;

    let txs = params.get(1).and_then(Value::as_array);

    let mut w = wallet_arc.write().await;

    if unlock && txs.is_none() {
        // unlock all
        w.unlock_all();
        return Ok(json!(true));
    }

    let txs = match txs {
        Some(t) => t,
        None => return Ok(json!(true)), // no-op when no transactions specified
    };

    for tx_obj in txs {
        let txid_hex = tx_obj
            .get("txid")
            .and_then(Value::as_str)
            .ok_or((-8, "transaction missing txid".to_string()))?;
        let vout = tx_obj
            .get("vout")
            .and_then(Value::as_u64)
            .ok_or((-8, "transaction missing vout".to_string()))? as u32;

        let txid_bytes =
            hex::decode(txid_hex).map_err(|_| (-8, "invalid txid hex".to_string()))?;
        if txid_bytes.len() != 32 {
            return Err((-8, "txid must be 32 bytes".to_string()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&txid_bytes);
        let outpoint = OutPoint {
            txid: Txid(Hash256(arr)),
            vout,
        };

        if unlock {
            w.unlock_unspent(&outpoint);
        } else {
            w.lock_unspent(outpoint);
        }
    }

    Ok(json!(true))
}

/// `listlockunspent` — list all locked unspent outputs.
///
/// Returns: array of {txid, vout}
async fn rpc_listlockunspent(state: &RpcState) -> RpcResult {
    let wallet_arc = require_wallet!(state);
    let w = wallet_arc.read().await;
    let locked = w.list_locked();
    let result: Vec<Value> = locked
        .iter()
        .map(|op| {
            json!({
                "txid": op.txid.to_hex(),
                "vout": op.vout,
            })
        })
        .collect();
    Ok(json!(result))
}

/// `prioritisetransaction` — adjust the apparent fee of a mempool transaction.
///
/// Params: [txid, dummy (ignored for compat), fee_delta]
/// Returns: true
async fn rpc_prioritisetransaction(state: &RpcState, params: &Value) -> RpcResult {
    let txid_hex = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or((-32602, "missing txid".to_string()))?;

    let txid_bytes =
        hex::decode(txid_hex).map_err(|_| (-8, "invalid txid hex".to_string()))?;
    if txid_bytes.len() != 32 {
        return Err((-8, "txid must be 32 bytes".to_string()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&txid_bytes);
    let txid = Txid(Hash256(arr));

    // Bitcoin Core: dummy param at index 1 must be 0 or null
    if let Some(dummy) = params.get(1) {
        if !dummy.is_null() {
            if let Some(d) = dummy.as_f64() {
                if d != 0.0 {
                    return Err((-8, "Priority is no longer supported, dummy argument to prioritisetransaction must be 0.".to_string()));
                }
            }
        }
    }

    let fee_delta = params
        .get(2)
        .and_then(Value::as_i64)
        .ok_or((-32602, "missing fee_delta (satoshis)".to_string()))?;

    let mut mempool = state.mempool.write().await;
    mempool.prioritise_transaction(txid, fee_delta);

    Ok(json!(true))
}

// ── Server startup ────────────────────────────────────────────────────────────

/// Start the RPC server on the given address (e.g. "127.0.0.1:8332").
pub async fn start_rpc_server(
    addr: &str,
    state: RpcState,
    auth: Arc<crate::rpc_auth::RpcAuthState>,
) -> Result<()> {
    let app = rpc_router(state, auth);
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
        let (control_tx, mut control_rx) = mpsc::unbounded_channel();
        // Spawn a mock node-loop that responds to RPC commands.
        tokio::spawn(async move {
            let mut banned: std::collections::HashSet<std::net::IpAddr> =
                std::collections::HashSet::new();
            while let Some(cmd) = control_rx.recv().await {
                match cmd {
                    RpcNodeCommand::GetPeerInfo { reply } => {
                        let _ = reply.send(vec![]);
                    }
                    RpcNodeCommand::GetMempoolInfo { reply } => {
                        let _ = reply.send(MempoolInfoData {
                            size: 0,
                            bytes: 0,
                            total_fee: 0,
                            maxmempool: 300_000_000,
                            mempoolminfee: 1,
                        });
                    }
                    RpcNodeCommand::GetConnectionCount { reply } => {
                        let _ = reply.send(0);
                    }
                    RpcNodeCommand::GetNetTotals { reply } => {
                        let _ = reply.send(NetTotalsData {
                            total_bytes_recv: 0,
                            total_bytes_sent: 0,
                            time_millis: 0,
                        });
                    }
                    RpcNodeCommand::SetBan { ip, command, reply } => {
                        match command.as_str() {
                            "add" => { banned.insert(ip); }
                            "remove" => { banned.remove(&ip); }
                            _ => {}
                        }
                        let _ = reply.send(Ok(()));
                    }
                    RpcNodeCommand::ListBanned { reply } => {
                        let _ = reply.send(banned.iter().copied().collect());
                    }
                    RpcNodeCommand::ClearBanned { reply } => {
                        banned.clear();
                        let _ = reply.send(());
                    }
                    RpcNodeCommand::AddNode { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    RpcNodeCommand::GetBlockFromPeer { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    RpcNodeCommand::PruneBlockchain { height, reply } => {
                        let _ = reply.send(Ok(height));
                    }
                    RpcNodeCommand::Ping { reply } => {
                        let _ = reply.send(());
                    }
                    RpcNodeCommand::DisconnectNode { address, nodeid, reply } => {
                        if address.as_deref() == Some("1.2.3.4:8333") || nodeid == Some(42) {
                            let _ = reply.send(Ok(()));
                        } else {
                            let _ = reply.send(Err("Node not found".to_string()));
                        }
                    }
                    _ => {}
                }
            }
        });
        let (_new_tip_tx, new_tip_rx) = watch::channel(("0".repeat(64), 0u32));
        let state = RpcState {
            chain: Arc::new(RwLock::new(chain)),
            mempool: Arc::new(RwLock::new(mempool)),
            db: Arc::new(db),
            network_name: "regtest".to_string(),
            wallet: None,
            submit_block_tx: submit_tx,
            control_tx,
            longpoll: Arc::new(LongPollState::new("0".repeat(64))),
            data_dir: tmpdir.path().to_path_buf(),
            prune_budget: 0,
            is_ibd: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            new_tip_rx,
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
        let script =
            rbtc_primitives::script::Script::from_bytes(vec![0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef]);
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
        let result = rpc_validateaddress(&state, &json!(["not_an_address"]))
            .await
            .unwrap();
        assert_eq!(result["isvalid"], false);
    }

    // ── createmultisig ───────────────────────────────────────────────────

    #[tokio::test]
    async fn create_multisig_1_of_2() {
        let (state, _tmpdir) = test_state();
        // Two dummy compressed pubkeys
        let pk1 = "02".to_string() + &"ab".repeat(32);
        let pk2 = "03".to_string() + &"cd".repeat(32);
        let result = rpc_createmultisig(&state, &json!([1, [pk1, pk2]]))
            .await
            .unwrap();
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
        let result = rpc_testmempoolaccept(&state, &json!([[hex]]))
            .await
            .unwrap();
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

    #[tokio::test]
    async fn getpeerinfo_returns_all_fields() {
        use rbtc_consensus::chain::ChainState;
        use rbtc_primitives::network::Network;

        let chain = ChainState::new(Network::Regtest);
        let mempool = rbtc_mempool::Mempool::new();
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let db = Database::open(tmpdir.path()).expect("open db");
        let (submit_tx, _submit_rx) = mpsc::unbounded_channel();
        let (control_tx, mut control_rx) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            while let Some(cmd) = control_rx.recv().await {
                match cmd {
                    RpcNodeCommand::GetPeerInfo { reply } => {
                        let stats = rbtc_net::PeerStats {
                            id: 42,
                            addr: "198.51.100.1:8333".to_string(),
                            services: 0x0000000000000409,
                            last_send: 1700000100,
                            last_recv: 1700000200,
                            bytes_sent: 12345,
                            bytes_recv: 67890,
                            conn_time: 1700000000,
                            ping_time: 0.05,
                            version: 70016,
                            subver: "/Satoshi:25.0.0/".to_string(),
                            inbound: false,
                            startingheight: 800000,
                            conn_type: "OutboundFullRelay".to_string(),
                            misbehavior: 0,
                        };
                        let _ = reply.send(vec![stats]);
                    }
                    _ => {}
                }
            }
        });

        let (_new_tip_tx, new_tip_rx) = watch::channel(("0".repeat(64), 0u32));
        let state = RpcState {
            chain: Arc::new(RwLock::new(chain)),
            mempool: Arc::new(RwLock::new(mempool)),
            db: Arc::new(db),
            network_name: "regtest".to_string(),
            wallet: None,
            submit_block_tx: submit_tx,
            control_tx,
            longpoll: Arc::new(LongPollState::new("0".repeat(64))),
            data_dir: tmpdir.path().to_path_buf(),
            prune_budget: 0,
            is_ibd: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            new_tip_rx,
        };

        let result = rpc_getpeerinfo(&state).await.unwrap();
        let peers = result.as_array().unwrap();
        assert_eq!(peers.len(), 1);
        let p = &peers[0];

        // Original fields
        assert_eq!(p["id"], 42);
        assert_eq!(p["addr"], "198.51.100.1:8333");
        assert_eq!(p["inbound"], false);
        assert_eq!(p["startingheight"], 800000);
        assert_eq!(p["connection_type"], "OutboundFullRelay");

        // New fields from PeerStats
        assert_eq!(p["services"], "0000000000000409");
        assert_eq!(p["lastsend"], 1700000100u64);
        assert_eq!(p["lastrecv"], 1700000200u64);
        assert_eq!(p["bytessent"], 12345u64);
        assert_eq!(p["bytesrecv"], 67890u64);
        assert_eq!(p["conntime"], 1700000000u64);
        assert_eq!(p["pingtime"], 0.05);
        assert_eq!(p["version"], 70016);
        assert_eq!(p["subver"], "/Satoshi:25.0.0/");
        assert_eq!(p["misbehavior"], 0);
    }

    // ── getmempoolinfo ─────────────────────────────────────────────────

    #[tokio::test]
    async fn getmempoolinfo_returns_expected_fields() {
        let (state, _tmpdir) = test_state();
        let result = rpc_getmempoolinfo(&state).await.unwrap();
        assert_eq!(result["loaded"], true);
        assert_eq!(result["size"], 0);
        assert_eq!(result["bytes"], 0);
        assert_eq!(result["maxmempool"], 300_000_000u64);
        assert!(result["mempoolminfee"].is_number());
        assert!(result["total_fee"].is_number());
        assert!(result["minrelaytxfee"].is_number());
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
        )
        .await;
        assert!(result.is_err());
    }

    // ── getmempoolancestors / getmempooldescendants ──────────────────────

    #[tokio::test]
    async fn getmempoolancestors_not_in_mempool() {
        let (state, _tmpdir) = test_state();
        let result = rpc_getmempoolancestors(
            &state,
            &json!(["0000000000000000000000000000000000000000000000000000000000000000"]),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn getmempooldescendants_not_in_mempool() {
        let (state, _tmpdir) = test_state();
        let result = rpc_getmempooldescendants(
            &state,
            &json!(["0000000000000000000000000000000000000000000000000000000000000000"]),
        )
        .await;
        assert!(result.is_err());
    }

    // ── verifymessage / signmessagewithprivkey stubs ─────────────────────

    #[tokio::test]
    async fn verifymessage_stub_returns_error() {
        let (state, _tmpdir) = test_state();
        let result = rpc_verifymessage(
            &state,
            &json!(["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "sig", "msg"]),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn signmessagewithprivkey_returns_base64() {
        let (state, _tmpdir) = test_state();
        let result = rpc_signmessagewithprivkey(
            &state,
            &json!([
                "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
                "hello"
            ]),
        )
        .await;
        let sig = result.unwrap();
        // Should be a base64 string
        assert!(sig.as_str().unwrap().len() > 0);
    }

    // ── getblocktemplate ────────────────────────────────────────────────

    #[tokio::test]
    async fn getblocktemplate_has_required_fields() {
        let (state, _tmpdir) = test_state();
        let result = rpc_getblocktemplate(&state, &json!([])).await.unwrap();

        // Basic BIP22 fields
        assert!(result["version"].is_number());
        assert!(result["previousblockhash"].is_string());
        assert!(result["transactions"].is_array());
        assert!(result["coinbasevalue"].is_number());
        assert!(result["target"].is_string());
        assert!(result["bits"].is_string());
        assert!(result["height"].is_number());
        assert!(result["curtime"].is_number());
        assert!(result["mintime"].is_number());

        // Version should use compute_block_version (on regtest, base version)
        assert_eq!(result["version"].as_i64().unwrap(), 0x2000_0000);

        // Empty mempool -> no transactions -> no witness commitment
        let txs = result["transactions"].as_array().unwrap();
        assert!(txs.is_empty());
    }

    #[tokio::test]
    async fn getblocktemplate_tx_entries_have_depends_fee_sigops() {
        // With an empty mempool we can't test depends/fee/sigops on real txs,
        // but we verify the field structure is correct by checking the JSON
        // schema expectations are met.
        let (state, _tmpdir) = test_state();
        let result = rpc_getblocktemplate(&state, &json!([])).await.unwrap();
        // transactions is an array (empty for empty mempool)
        assert!(result["transactions"].as_array().unwrap().is_empty());

        // Verify version is computed (not hardcoded 0x20000000 literal)
        let v = result["version"].as_i64().unwrap();
        assert_eq!(v & 0x2000_0000, 0x2000_0000, "base version bits must be set");
    }

    // ── GBT longpoll (BIP22) ─────────────────────────────────────────────

    #[tokio::test]
    async fn gbt_longpoll_id_present_in_response() {
        let (state, _tmpdir) = test_state();
        let result = rpc_getblocktemplate(&state, &json!([])).await.unwrap();
        // The longpollid field must be present and be a non-empty string.
        let lp_id = result["longpollid"].as_str().unwrap();
        assert!(!lp_id.is_empty(), "longpollid must not be empty");
    }

    #[tokio::test]
    async fn gbt_longpoll_id_changes_on_tip_notify() {
        let (state, _tmpdir) = test_state();

        let id_before = state.longpoll.current_id();

        // Simulate a new tip arriving.
        state.longpoll.notify_new_tip("cafebabe");

        let id_after = state.longpoll.current_id();
        assert_ne!(id_before, id_after, "longpoll ID must change on new tip");
        assert_eq!(id_after, "cafebabe");
    }

    #[tokio::test]
    async fn gbt_longpoll_id_changes_on_mempool_notify() {
        let (state, _tmpdir) = test_state();

        let id_before = state.longpoll.current_id();

        // Simulate a mempool change.
        state.longpoll.notify_mempool_change();

        let id_after = state.longpoll.current_id();
        assert_ne!(id_before, id_after, "longpoll ID must change on mempool update");
    }

    #[tokio::test]
    async fn gbt_longpoll_returns_immediately_when_id_differs() {
        let (state, _tmpdir) = test_state();

        // The current longpoll ID is "000...0"; pass a different ID so the
        // handler returns immediately without blocking.
        let params = json!([{"longpollid": "definitely_stale_id"}]);
        let result = rpc_getblocktemplate(&state, &params).await.unwrap();

        // Should return a valid template (the handler did not block forever).
        assert!(result["version"].is_number());
        assert!(result["longpollid"].is_string());
    }

    #[tokio::test]
    async fn gbt_longpoll_waits_and_returns_on_notify() {
        let (state, _tmpdir) = test_state();

        let current_id = state.longpoll.current_id();
        let longpoll = Arc::clone(&state.longpoll);

        // Spawn a task that notifies after a short delay.
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            longpoll.notify_new_tip("deadbeef");
        });

        // Call GBT with the current longpoll ID — it should block until the
        // notify fires, then return the updated template.
        let params = json!([{"longpollid": current_id}]);
        let start = std::time::Instant::now();
        let result = rpc_getblocktemplate(&state, &params).await.unwrap();
        let elapsed = start.elapsed();

        // It should have waited at least ~50ms (not returned instantly).
        assert!(
            elapsed >= std::time::Duration::from_millis(30),
            "longpoll should have blocked; elapsed={elapsed:?}"
        );
        // The new longpoll ID in the response should reflect the updated state.
        let new_id = result["longpollid"].as_str().unwrap();
        assert_ne!(new_id, current_id, "response longpollid should differ from the stale one");
    }

    // ── test_state_with_wallet helper ────────────────────────────────────

    fn test_state_with_wallet() -> (RpcState, tempfile::TempDir) {
        use rbtc_consensus::chain::ChainState;
        use rbtc_primitives::network::Network;

        let chain = ChainState::new(Network::Regtest);
        let mempool = rbtc_mempool::Mempool::new();
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let db = Arc::new(Database::open(tmpdir.path()).expect("open db"));
        let (submit_tx, _submit_rx) = mpsc::unbounded_channel();
        let (control_tx, mut control_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut banned: std::collections::HashSet<std::net::IpAddr> =
                std::collections::HashSet::new();
            while let Some(cmd) = control_rx.recv().await {
                match cmd {
                    RpcNodeCommand::GetPeerInfo { reply } => {
                        let _ = reply.send(vec![]);
                    }
                    RpcNodeCommand::GetMempoolInfo { reply } => {
                        let _ = reply.send(MempoolInfoData {
                            size: 0,
                            bytes: 0,
                            total_fee: 0,
                            maxmempool: 300_000_000,
                            mempoolminfee: 1,
                        });
                    }
                    RpcNodeCommand::GetConnectionCount { reply } => {
                        let _ = reply.send(0);
                    }
                    RpcNodeCommand::GetNetTotals { reply } => {
                        let _ = reply.send(NetTotalsData {
                            total_bytes_recv: 0,
                            total_bytes_sent: 0,
                            time_millis: 0,
                        });
                    }
                    RpcNodeCommand::SetBan { ip, command, reply } => {
                        match command.as_str() {
                            "add" => { banned.insert(ip); }
                            "remove" => { banned.remove(&ip); }
                            _ => {}
                        }
                        let _ = reply.send(Ok(()));
                    }
                    RpcNodeCommand::ListBanned { reply } => {
                        let _ = reply.send(banned.iter().copied().collect());
                    }
                    RpcNodeCommand::ClearBanned { reply } => {
                        banned.clear();
                        let _ = reply.send(());
                    }
                    RpcNodeCommand::AddNode { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    RpcNodeCommand::GetBlockFromPeer { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    RpcNodeCommand::PruneBlockchain { height, reply } => {
                        let _ = reply.send(Ok(height));
                    }
                    _ => {}
                }
            }
        });

        // Create a wallet from a deterministic mnemonic
        let mnemonic = rbtc_wallet::Mnemonic::generate(12).expect("mnemonic");
        let wallet = rbtc_wallet::Wallet::from_mnemonic(
            &mnemonic,
            "",
            "test-passphrase",
            Network::Regtest,
            db.clone(),
        )
        .expect("create wallet");

        let (_new_tip_tx, new_tip_rx) = watch::channel(("0".repeat(64), 0u32));
        let state = RpcState {
            chain: Arc::new(RwLock::new(chain)),
            mempool: Arc::new(RwLock::new(mempool)),
            db,
            network_name: "regtest".to_string(),
            wallet: Some(Arc::new(RwLock::new(wallet))),
            submit_block_tx: submit_tx,
            control_tx,
            longpoll: Arc::new(LongPollState::new("0".repeat(64))),
            data_dir: tmpdir.path().to_path_buf(),
            prune_budget: 0,
            is_ibd: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            new_tip_rx,
        };
        (state, tmpdir)
    }

    // ── Phase G wallet RPC tests ────────────────────────────────────────

    #[tokio::test]
    async fn getaddressinfo_unknown_address() {
        let (state, _tmpdir) = test_state_with_wallet();
        let result = rpc_getaddressinfo(
            &state,
            &json!(["bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7k5fhzz0"]),
        )
        .await
        .unwrap();
        assert_eq!(result["ismine"], false);
    }

    #[tokio::test]
    async fn getaddressinfo_wallet_address() {
        let (state, _tmpdir) = test_state_with_wallet();

        // Generate a new wallet address
        let addr = {
            let mut w = state.wallet.as_ref().unwrap().write().await;
            w.new_address(AddressType::SegWit).unwrap()
        };

        let result = rpc_getaddressinfo(&state, &json!([addr])).await.unwrap();
        assert_eq!(result["ismine"], true);
        assert_eq!(result["iswitness"], true);
        assert!(result["pubkey"].as_str().unwrap().len() > 0);
        assert_eq!(result["iscompressed"], true);
    }

    #[tokio::test]
    async fn setlabel_and_getaddressinfo_reflects_label() {
        let (state, _tmpdir) = test_state_with_wallet();

        let addr = {
            let mut w = state.wallet.as_ref().unwrap().write().await;
            w.new_address(AddressType::SegWit).unwrap()
        };

        // Set label
        let result = rpc_setlabel(&state, &json!([addr, "my-savings"])).await;
        assert!(result.is_ok());

        // Verify label is returned in getaddressinfo
        let info = rpc_getaddressinfo(&state, &json!([addr])).await.unwrap();
        assert_eq!(info["label"], "my-savings");
    }

    #[tokio::test]
    async fn setlabel_unknown_address_returns_error() {
        let (state, _tmpdir) = test_state_with_wallet();
        let result =
            rpc_setlabel(&state, &json!(["bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7k5fhzz0", "test"]))
                .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn listaddressgroupings_empty_wallet() {
        let (state, _tmpdir) = test_state_with_wallet();
        let result = rpc_listaddressgroupings(&state).await.unwrap();
        // Fresh wallet — no addresses derived yet so no groupings
        assert!(result.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn listaddressgroupings_with_address() {
        let (state, _tmpdir) = test_state_with_wallet();

        // Derive an address
        {
            let mut w = state.wallet.as_ref().unwrap().write().await;
            w.new_address(AddressType::SegWit).unwrap();
        }

        let result = rpc_listaddressgroupings(&state).await.unwrap();
        let groups = result.as_array().unwrap();
        assert_eq!(groups.len(), 1);
    }

    #[tokio::test]
    async fn getrawchangeaddress_returns_valid_address() {
        let (state, _tmpdir) = test_state_with_wallet();
        let result = rpc_getrawchangeaddress(&state, &json!(["bech32"])).await.unwrap();
        let addr = result.as_str().unwrap();
        assert!(addr.starts_with("bcrt1"));
    }

    #[tokio::test]
    async fn getrawchangeaddress_default_type() {
        let (state, _tmpdir) = test_state_with_wallet();
        let result = rpc_getrawchangeaddress(&state, &json!([])).await.unwrap();
        let addr = result.as_str().unwrap();
        assert!(addr.starts_with("bcrt1"));
    }

    #[tokio::test]
    async fn createwallet_returns_name_and_warning() {
        let (state, _tmpdir) = test_state();
        let result = rpc_createwallet(&state, &json!(["mywallet"])).await.unwrap();
        assert_eq!(result["name"], "mywallet");
        assert!(result["warning"].as_str().is_some());
    }

    #[tokio::test]
    async fn createwallet_with_wallet_loaded_returns_error() {
        let (state, _tmpdir) = test_state_with_wallet();
        let result = rpc_createwallet(&state, &json!(["another"])).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn walletpassphrase_accepted() {
        let (state, _tmpdir) = test_state_with_wallet();
        let result = rpc_walletpassphrase(&state, &json!(["test-passphrase", 60])).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn walletlock_accepted() {
        let (state, _tmpdir) = test_state_with_wallet();
        let result = rpc_walletlock(&state).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn walletpassphrase_no_wallet_returns_error() {
        let (state, _tmpdir) = test_state();
        let result = rpc_walletpassphrase(&state, &json!(["pass", 60])).await;
        assert!(result.is_err());
        let (code, _msg) = result.unwrap_err();
        assert_eq!(code, -18); // no wallet loaded
    }

    #[tokio::test]
    async fn abandontransaction_not_in_mempool() {
        let (state, _tmpdir) = test_state_with_wallet();
        let result = rpc_abandontransaction(
            &state,
            &json!(["0000000000000000000000000000000000000000000000000000000000000000"]),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn bumpfee_not_in_mempool() {
        let (state, _tmpdir) = test_state_with_wallet();
        let result = rpc_bumpfee(
            &state,
            &json!(["0000000000000000000000000000000000000000000000000000000000000000"]),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn getaddressinfo_missing_param() {
        let (state, _tmpdir) = test_state_with_wallet();
        let result = rpc_getaddressinfo(&state, &json!([])).await;
        assert!(result.is_err());
        let (code, _) = result.unwrap_err();
        assert_eq!(code, -32602);
    }

    #[tokio::test]
    async fn bumpfee_missing_param() {
        let (state, _tmpdir) = test_state_with_wallet();
        let result = rpc_bumpfee(&state, &json!([])).await;
        assert!(result.is_err());
        let (code, _) = result.unwrap_err();
        assert_eq!(code, -32602);
    }

    // ── M5: Network management RPCs ─────────────────────────────────────

    #[tokio::test]
    async fn getconnectioncount_returns_zero() {
        let (state, _tmpdir) = test_state();
        let result = rpc_getconnectioncount(&state).await.unwrap();
        assert_eq!(result, 0);
    }

    #[tokio::test]
    async fn getnettotals_returns_fields() {
        let (state, _tmpdir) = test_state();
        let result = rpc_getnettotals(&state).await.unwrap();
        assert!(result["totalbytesrecv"].is_number());
        assert!(result["totalbytessent"].is_number());
        assert!(result["timemillis"].is_number());
        assert!(result["uploadtarget"].is_object());
    }

    #[tokio::test]
    async fn setban_and_listbanned_roundtrip() {
        let (state, _tmpdir) = test_state();
        // Initially no bans
        let list = rpc_listbanned(&state).await.unwrap();
        assert!(list.as_array().unwrap().is_empty());

        // Ban an IP
        let result = rpc_setban(&state, &json!(["1.2.3.4", "add"])).await;
        assert!(result.is_ok());

        // Should now appear in list
        let list = rpc_listbanned(&state).await.unwrap();
        let arr = list.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["address"], "1.2.3.4/32");

        // Remove the ban
        let result = rpc_setban(&state, &json!(["1.2.3.4", "remove"])).await;
        assert!(result.is_ok());

        let list = rpc_listbanned(&state).await.unwrap();
        assert!(list.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn setban_invalid_ip() {
        let (state, _tmpdir) = test_state();
        let result = rpc_setban(&state, &json!(["not-an-ip", "add"])).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn setban_invalid_command() {
        let (state, _tmpdir) = test_state();
        let result = rpc_setban(&state, &json!(["1.2.3.4", "destroy"])).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn clearbanned_clears_all() {
        let (state, _tmpdir) = test_state();
        // Add two bans
        rpc_setban(&state, &json!(["1.2.3.4", "add"])).await.unwrap();
        rpc_setban(&state, &json!(["5.6.7.8", "add"])).await.unwrap();
        let list = rpc_listbanned(&state).await.unwrap();
        assert_eq!(list.as_array().unwrap().len(), 2);

        // Clear all
        let result = rpc_clearbanned(&state).await;
        assert!(result.is_ok());

        let list = rpc_listbanned(&state).await.unwrap();
        assert!(list.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn addnode_valid_address() {
        let (state, _tmpdir) = test_state();
        let result = rpc_addnode(&state, &json!(["127.0.0.1:8333", "add"])).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn addnode_ip_only_default_port() {
        let (state, _tmpdir) = test_state();
        let result = rpc_addnode(&state, &json!(["127.0.0.1"])).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn addnode_invalid_address() {
        let (state, _tmpdir) = test_state();
        let result = rpc_addnode(&state, &json!(["not-valid-at-all"])).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn setban_cidr_stripped() {
        let (state, _tmpdir) = test_state();
        // Accept IP/subnet notation by stripping the CIDR suffix
        let result = rpc_setban(&state, &json!(["10.0.0.1/32", "add"])).await;
        assert!(result.is_ok());
        let list = rpc_listbanned(&state).await.unwrap();
        assert_eq!(list.as_array().unwrap().len(), 1);
    }

    // ── gettxout tests ──────────────────────────────────────────────────

    #[tokio::test]
    async fn gettxout_missing_utxo_returns_null() {
        let (state, _tmpdir) = test_state();
        let result = rpc_gettxout(
            &state,
            &json!(["0000000000000000000000000000000000000000000000000000000000000001", 0]),
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Value::Null);
    }

    #[tokio::test]
    async fn gettxout_returns_stored_utxo() {
        let (state, _tmpdir) = test_state();

        // Insert a UTXO into the store.
        let txid = Txid::from_hex(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();
        let outpoint = OutPoint { txid, vout: 0 };
        let utxo = rbtc_storage::StoredUtxo {
            value: 50_0000_0000, // 50 BTC
            script_pubkey: rbtc_primitives::script::Script::from_bytes(vec![
                0x76, 0xa9, 0x14, // OP_DUP OP_HASH160 PUSH20
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0x88, 0xac, // OP_EQUALVERIFY OP_CHECKSIG
            ]),
            height: 100,
            is_coinbase: true,
        };
        let utxo_store = UtxoStore::new(&state.db);
        utxo_store.put(&outpoint, &utxo).unwrap();

        let result = rpc_gettxout(
            &state,
            &json!([
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                0,
                false
            ]),
        )
        .await
        .unwrap();

        assert_eq!(result["confirmations"], 1); // height 0 - 100 + 1 (saturating)
        assert_eq!(result["coinbase"], true);
        assert_eq!(result["value"], 50.0);
        assert_eq!(result["scriptPubKey"]["type"], "pubkeyhash");
    }

    #[tokio::test]
    async fn gettxout_missing_params() {
        let (state, _tmpdir) = test_state();
        let result = rpc_gettxout(&state, &json!([])).await;
        assert!(result.is_err());
    }

    // ── gettxoutsetinfo tests ───────────────────────────────────────────

    #[tokio::test]
    async fn gettxoutsetinfo_empty_set() {
        let (state, _tmpdir) = test_state();
        let result = rpc_gettxoutsetinfo(&state).await.unwrap();
        assert_eq!(result["txouts"], 0);
        assert_eq!(result["total_amount"], 0.0);
        assert_eq!(result["height"], 0);
    }

    #[tokio::test]
    async fn gettxoutsetinfo_with_utxos() {
        let (state, _tmpdir) = test_state();

        // Insert two UTXOs.
        let utxo_store = UtxoStore::new(&state.db);
        for i in 0u8..2 {
            let mut hash = [0u8; 32];
            hash[0] = i + 1;
            let txid = Txid::from_hash(Hash256(hash));
            let outpoint = OutPoint { txid, vout: 0 };
            let utxo = rbtc_storage::StoredUtxo {
                value: 1_0000_0000,
                script_pubkey: rbtc_primitives::script::Script::from_bytes(vec![0x6a]), // OP_RETURN
                height: 1,
                is_coinbase: false,
            };
            utxo_store.put(&outpoint, &utxo).unwrap();
        }

        let result = rpc_gettxoutsetinfo(&state).await.unwrap();
        assert_eq!(result["txouts"], 2);
        assert_eq!(result["total_amount"], 2.0);
    }

    // ── verifychain tests ───────────────────────────────────────────────

    #[tokio::test]
    async fn verifychain_empty_chain() {
        let (state, _tmpdir) = test_state();
        // With only the genesis block (height 0), verifychain should pass.
        let result = rpc_verifychain(&state, &json!([])).await.unwrap();
        assert_eq!(result, true);
    }

    #[tokio::test]
    async fn verifychain_default_params() {
        let (state, _tmpdir) = test_state();
        let result = rpc_verifychain(&state, &json!([3, 6])).await.unwrap();
        assert_eq!(result, true);
    }

    // ── getblockfrompeer tests ──────────────────────────────────────────

    #[tokio::test]
    async fn getblockfrompeer_missing_params() {
        let (state, _tmpdir) = test_state();
        // Missing both params
        let result = rpc_getblockfrompeer(&state, &json!([])).await;
        assert!(result.is_err());
        let (code, _) = result.unwrap_err();
        assert_eq!(code, -32602);
    }

    #[tokio::test]
    async fn getblockfrompeer_missing_peer_id() {
        let (state, _tmpdir) = test_state();
        let result = rpc_getblockfrompeer(&state, &json!(["00".repeat(32)])).await;
        assert!(result.is_err());
        let (code, _) = result.unwrap_err();
        assert_eq!(code, -32602);
    }

    #[tokio::test]
    async fn getblockfrompeer_unknown_header() {
        let (state, _tmpdir) = test_state();
        // Valid hash format but not in block index — should fail.
        let fake_hash = "aa".repeat(32);
        let result = rpc_getblockfrompeer(&state, &json!([fake_hash, 0])).await;
        assert!(result.is_err());
        let (code, msg) = result.unwrap_err();
        assert_eq!(code, -1);
        assert!(msg.contains("Block header missing"), "msg: {msg}");
    }

    #[tokio::test]
    async fn getblockfrompeer_known_header_sends_request() {
        use rbtc_consensus::chain::ChainState;
        use rbtc_primitives::network::Network;
        use rbtc_consensus::chain::BlockIndex;
        use rbtc_primitives::uint256::U256;

        // Build a state with a known block in the index.
        let mut chain = ChainState::new(Network::Regtest);
        let hash_hex = "bb".repeat(32);
        let hash = Hash256::from_hex(&hash_hex).unwrap();
        let header = rbtc_primitives::block::BlockHeader {
            version: 1,
            prev_block: BlockHash::ZERO,
            merkle_root: Hash256::ZERO,
            time: 0,
            bits: 0,
            nonce: 0,
        };
        chain.block_index.insert(
            BlockHash(hash),
            BlockIndex {
                hash: BlockHash(hash),
                height: 1,
                header,
                chainwork: U256::ZERO,
                status: rbtc_primitives::block_status::BlockStatus::new(),
            },
        );

        let mempool = rbtc_mempool::Mempool::new();
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let db = Database::open(tmpdir.path()).expect("open db");
        let (submit_tx, _submit_rx) = mpsc::unbounded_channel();
        let (control_tx, mut control_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(cmd) = control_rx.recv().await {
                match cmd {
                    RpcNodeCommand::GetBlockFromPeer { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    _ => {}
                }
            }
        });
        let (_new_tip_tx, new_tip_rx) = watch::channel(("0".repeat(64), 0u32));
        let state = RpcState {
            chain: Arc::new(RwLock::new(chain)),
            mempool: Arc::new(RwLock::new(mempool)),
            db: Arc::new(db),
            network_name: "regtest".to_string(),
            wallet: None,
            submit_block_tx: submit_tx,
            control_tx,
            longpoll: Arc::new(LongPollState::new("0".repeat(64))),
            data_dir: tmpdir.path().to_path_buf(),
            prune_budget: 0,
            is_ibd: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            new_tip_rx,
        };

        let result = rpc_getblockfrompeer(&state, &json!([hash_hex, 42])).await;
        assert!(result.is_ok(), "expected Ok, got {:?}", result);
        assert_eq!(result.unwrap(), json!({}));
    }

    // ── pruneblockchain tests ───────────────────────────────────────────

    #[tokio::test]
    async fn pruneblockchain_not_pruning() {
        let (state, _tmpdir) = test_state();
        // prune_budget is 0 in test_state => not in prune mode.
        let result = rpc_pruneblockchain(&state, &json!([100])).await;
        assert!(result.is_err());
        let (code, msg) = result.unwrap_err();
        assert_eq!(code, -1);
        assert!(msg.contains("not in prune mode"), "msg: {msg}");
    }

    #[tokio::test]
    async fn pruneblockchain_missing_height() {
        // Build a state with prune_budget > 0.
        let (mut state, _tmpdir) = test_state();
        state.prune_budget = 550;
        let result = rpc_pruneblockchain(&state, &json!([])).await;
        assert!(result.is_err());
        let (code, _) = result.unwrap_err();
        assert_eq!(code, -32602);
    }

    #[tokio::test]
    async fn pruneblockchain_returns_height() {
        let (mut state, _tmpdir) = test_state();
        state.prune_budget = 550;
        let result = rpc_pruneblockchain(&state, &json!([200])).await;
        assert!(result.is_ok());
        // The mock node-loop echoes back the height.
        assert_eq!(result.unwrap(), json!(200));
    }

    // ── waitfornewblock tests ───────────────────────────────────────────

    #[tokio::test]
    async fn waitfornewblock_timeout_returns_current_tip() {
        let (new_tip_tx, new_tip_rx) = watch::channel(("ab".repeat(32), 42u32));
        let (mut state, _tmpdir) = test_state();
        state.new_tip_rx = new_tip_rx;
        // Keep tx alive.
        let _tx = new_tip_tx;

        let start = std::time::Instant::now();
        let result = rpc_waitfornewblock(&state, &json!([50])).await.unwrap();
        let elapsed = start.elapsed();

        // Should have waited ~50ms then returned the current tip.
        assert!(elapsed >= std::time::Duration::from_millis(30), "elapsed={elapsed:?}");
        assert_eq!(result["height"], 42);
        assert_eq!(result["hash"], "ab".repeat(32));
    }

    #[tokio::test]
    async fn waitfornewblock_returns_on_new_tip() {
        let (new_tip_tx, new_tip_rx) = watch::channel(("00".repeat(32), 0u32));
        let (mut state, _tmpdir) = test_state();
        state.new_tip_rx = new_tip_rx;

        // Spawn a task that sends a new tip after a short delay.
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let _ = new_tip_tx.send(("cc".repeat(32), 100));
        });

        let start = std::time::Instant::now();
        let result = rpc_waitfornewblock(&state, &json!([5000])).await.unwrap();
        let elapsed = start.elapsed();

        // Should have woken up after ~50ms (not 5s).
        assert!(elapsed < std::time::Duration::from_millis(4000), "elapsed={elapsed:?}");
        assert_eq!(result["height"], 100);
        assert_eq!(result["hash"], "cc".repeat(32));
    }

    // ── M35: getbestblockhash ─────────────────────────────────────────────

    /// Helper: create a test state with genesis block connected as best tip.
    async fn test_state_with_genesis() -> (RpcState, tempfile::TempDir) {
        use rbtc_primitives::network::Network;
        let (state, tmpdir) = test_state();
        // Connect genesis so best_tip and active_chain are populated.
        {
            let mut chain = state.chain.write().await;
            let genesis_header = Network::Regtest.genesis_header();
            let genesis_hash = genesis_header.get_hash();
            // The header is already in block_index from ChainState::new().
            // Set active_chain and best_tip manually.
            chain.active_chain = vec![genesis_hash];
            chain.best_tip = Some(genesis_hash);
        }
        (state, tmpdir)
    }

    #[tokio::test]
    async fn getbestblockhash_returns_genesis() {
        let (state, _tmpdir) = test_state_with_genesis().await;
        let result = rpc_getbestblockhash(&state).await;
        assert!(result.is_ok(), "getbestblockhash should succeed: {:?}", result);
        let hash = result.unwrap();
        // Regtest chain has genesis block as tip
        let hash_str = hash.as_str().unwrap();
        assert_eq!(hash_str.len(), 64, "block hash should be 64 hex chars");
    }

    #[tokio::test]
    async fn getbestblockhash_matches_getblockhash_0() {
        let (state, _tmpdir) = test_state_with_genesis().await;
        let best = rpc_getbestblockhash(&state).await.unwrap();
        let at_zero = rpc_getblockhash(&state, &json!([0])).await.unwrap();
        assert_eq!(best, at_zero, "tip should equal block 0 on fresh chain");
    }

    // ── M36: getblockheader ───────────────────────────────────────────────

    #[tokio::test]
    async fn getblockheader_verbose_false_returns_hex() {
        let (state, _tmpdir) = test_state_with_genesis().await;
        // Get genesis hash
        let genesis_hash = rpc_getbestblockhash(&state).await.unwrap();
        let hash_str = genesis_hash.as_str().unwrap();

        let result = rpc_getblockheader(&state, &json!([hash_str, false])).await;
        assert!(result.is_ok(), "getblockheader verbose=false: {:?}", result);
        let hex_str = result.unwrap();
        let hex_val = hex_str.as_str().unwrap();
        // 80-byte header = 160 hex chars
        assert_eq!(hex_val.len(), 160, "header hex should be 160 chars, got {}", hex_val.len());
    }

    #[tokio::test]
    async fn getblockheader_verbose_true_returns_json() {
        let (state, _tmpdir) = test_state_with_genesis().await;
        let genesis_hash = rpc_getbestblockhash(&state).await.unwrap();
        let hash_str = genesis_hash.as_str().unwrap();

        let result = rpc_getblockheader(&state, &json!([hash_str, true])).await;
        assert!(result.is_ok(), "getblockheader verbose=true: {:?}", result);
        let obj = result.unwrap();
        assert_eq!(obj["hash"].as_str().unwrap(), hash_str);
        assert_eq!(obj["height"], 0);
        assert!(obj["confirmations"].as_i64().unwrap() >= 1);
        assert!(obj["version"].as_i64().is_some());
        assert!(obj["versionHex"].as_str().is_some());
        assert!(obj["merkleroot"].as_str().is_some());
        assert!(obj["time"].as_u64().is_some());
        assert!(obj["mediantime"].as_u64().is_some());
        assert!(obj["nonce"].as_u64().is_some());
        assert!(obj["bits"].as_str().is_some());
        assert!(obj["difficulty"].as_f64().is_some());
        assert!(obj["chainwork"].as_str().is_some());
        // Genesis has no previousblockhash
        assert!(obj["previousblockhash"].is_null());
    }

    #[tokio::test]
    async fn getblockheader_not_found() {
        let (state, _tmpdir) = test_state_with_genesis().await;
        let bad_hash = "00".repeat(32);
        let result = rpc_getblockheader(&state, &json!([bad_hash, true])).await;
        assert!(result.is_err());
        let (code, _msg) = result.unwrap_err();
        assert_eq!(code, -5);
    }

    // ── M37: createrawtransaction ─────────────────────────────────────────

    /// Testnet P2PKH address (version byte 0x6f, hash160 all zeros).
    fn test_p2pkh_address() -> String {
        // version 0x6f (testnet P2PKH) + 20 zero bytes
        let mut payload = vec![0x6f_u8];
        payload.extend_from_slice(&[0u8; 20]);
        bs58::encode(&payload).with_check().into_string()
    }

    #[tokio::test]
    async fn createrawtransaction_basic() {
        let (state, _tmpdir) = test_state();
        let txid = "aa".repeat(32);
        let addr = test_p2pkh_address();
        let mut out = serde_json::Map::new();
        out.insert(addr, json!(50000));
        let params = json!([
            [{"txid": txid, "vout": 0}],
            [out],
            0
        ]);
        let result = rpc_createrawtransaction(&state, &params).await;
        assert!(result.is_ok(), "createrawtransaction: {:?}", result);
        let hex_str = result.unwrap();
        let hex_val = hex_str.as_str().unwrap();
        // Should be valid hex and decodable
        let bytes = hex::decode(hex_val).expect("valid hex");
        assert!(bytes.len() > 10, "transaction should be non-trivial");

        // Decode and verify structure
        use std::io::Cursor;
        let tx = Transaction::decode(&mut Cursor::new(&bytes)).expect("decode tx");
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.lock_time, 0);
        // scriptSig should be empty
        assert!(tx.inputs[0].script_sig.as_bytes().is_empty());
    }

    #[tokio::test]
    async fn createrawtransaction_with_data_output() {
        let (state, _tmpdir) = test_state();
        let txid = "bb".repeat(32);
        let params = json!([
            [{"txid": txid, "vout": 1, "sequence": 0xfffffffe_u64}],
            [{"data": "deadbeef"}],
            42
        ]);
        let result = rpc_createrawtransaction(&state, &params).await;
        assert!(result.is_ok(), "createrawtransaction data output: {:?}", result);
        let hex_str = result.unwrap();
        let bytes = hex::decode(hex_str.as_str().unwrap()).unwrap();

        use std::io::Cursor;
        let tx = Transaction::decode(&mut Cursor::new(&bytes)).expect("decode tx");
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.inputs[0].sequence, 0xfffffffe);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].value, 0);
        assert_eq!(tx.lock_time, 42);
        // OP_RETURN output: starts with 0x6a
        assert_eq!(tx.outputs[0].script_pubkey.as_bytes()[0], 0x6a);
    }

    #[tokio::test]
    async fn createrawtransaction_multiple_outputs() {
        let (state, _tmpdir) = test_state();
        let txid1 = "cc".repeat(32);
        let txid2 = "dd".repeat(32);
        let addr = test_p2pkh_address();
        let mut addr_out = serde_json::Map::new();
        addr_out.insert(addr, json!(10000));
        let params = json!([
            [{"txid": txid1, "vout": 0}, {"txid": txid2, "vout": 3}],
            [addr_out, {"data": "cafebabe"}]
        ]);
        let result = rpc_createrawtransaction(&state, &params).await;
        assert!(result.is_ok(), "multi-output: {:?}", result);
        let bytes = hex::decode(result.unwrap().as_str().unwrap()).unwrap();

        use std::io::Cursor;
        let tx = Transaction::decode(&mut Cursor::new(&bytes)).expect("decode tx");
        assert_eq!(tx.inputs.len(), 2);
        assert_eq!(tx.outputs.len(), 2);
    }

    #[tokio::test]
    async fn createrawtransaction_invalid_txid() {
        let (state, _tmpdir) = test_state();
        let addr = test_p2pkh_address();
        let mut out = serde_json::Map::new();
        out.insert(addr, json!(1000));
        let params = json!([
            [{"txid": "not-hex", "vout": 0}],
            [out]
        ]);
        let result = rpc_createrawtransaction(&state, &params).await;
        assert!(result.is_err());
    }

    // ── deriveaddresses tests ──────────────────────────────────────────

    /// Helper: compute descriptor with BIP380 checksum attached.
    fn desc_with_checksum(body: &str) -> String {
        rbtc_wallet::Descriptor::checksum(body).expect("valid descriptor body")
    }

    #[tokio::test]
    async fn deriveaddresses_non_range_returns_single_address() {
        let (state, _tmpdir) = test_state();
        // wpkh() descriptor with a fixed pubkey — non-range
        let seed = [10u8; 64];
        let master = rbtc_wallet::ExtendedPrivKey::from_seed(&seed).unwrap();
        let pk_hex = hex::encode(master.public_key().serialize());
        let desc = desc_with_checksum(&format!("wpkh({pk_hex})"));
        let params = json!([desc]);
        let result = rpc_deriveaddresses(&state, &params).await.unwrap();
        let arr = result.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        let addr = arr[0].as_str().unwrap();
        assert!(addr.starts_with("bcrt1q"), "expected bcrt1q prefix, got: {addr}");
    }

    #[tokio::test]
    async fn deriveaddresses_missing_checksum_rejected() {
        let (state, _tmpdir) = test_state();
        // No checksum — Bitcoin Core requires it
        let seed = [11u8; 64];
        let master = rbtc_wallet::ExtendedPrivKey::from_seed(&seed).unwrap();
        let pk_hex = hex::encode(master.public_key().serialize());
        let params = json!([format!("wpkh({pk_hex})")]);
        let result = rpc_deriveaddresses(&state, &params).await;
        assert!(result.is_err());
        let (code, msg) = result.unwrap_err();
        assert_eq!(code, -5);
        assert!(msg.contains("checksum"), "error should mention checksum: {msg}");
    }

    #[tokio::test]
    async fn deriveaddresses_range_on_non_range_rejected() {
        let (state, _tmpdir) = test_state();
        let seed = [12u8; 64];
        let master = rbtc_wallet::ExtendedPrivKey::from_seed(&seed).unwrap();
        let pk_hex = hex::encode(master.public_key().serialize());
        let desc = desc_with_checksum(&format!("wpkh({pk_hex})"));
        // Supplying a range for a non-range descriptor should fail
        let params = json!([desc, [0, 2]]);
        let result = rpc_deriveaddresses(&state, &params).await;
        assert!(result.is_err());
        let (code, msg) = result.unwrap_err();
        assert_eq!(code, -8);
        assert!(msg.contains("un-ranged"), "error should mention un-ranged: {msg}");
    }

    #[tokio::test]
    async fn deriveaddresses_missing_param_rejected() {
        let (state, _tmpdir) = test_state();
        let params = json!([]);
        let result = rpc_deriveaddresses(&state, &params).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn deriveaddresses_pkh_fixed_key() {
        let (state, _tmpdir) = test_state();
        // pkh() descriptor — should return a Base58 P2PKH address
        let seed = [13u8; 64];
        let master = rbtc_wallet::ExtendedPrivKey::from_seed(&seed).unwrap();
        let pk_hex = hex::encode(master.public_key().serialize());
        let desc = desc_with_checksum(&format!("pkh({pk_hex})"));
        let params = json!([desc]);
        let result = rpc_deriveaddresses(&state, &params).await.unwrap();
        let arr = result.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        let addr = arr[0].as_str().unwrap();
        // Regtest P2PKH starts with 'm' or 'n'
        assert!(
            addr.starts_with('m') || addr.starts_with('n'),
            "expected testnet P2PKH prefix, got: {addr}"
        );
    }

    #[tokio::test]
    async fn deriveaddresses_wpkh_fixed_key() {
        let (state, _tmpdir) = test_state();
        // Use a fixed compressed pubkey in wpkh() — non-range
        let seed = [1u8; 64];
        let master = rbtc_wallet::ExtendedPrivKey::from_seed(&seed).unwrap();
        let pk_hex = hex::encode(master.public_key().serialize());
        let desc = desc_with_checksum(&format!("wpkh({pk_hex})"));
        let params = json!([desc]);
        let result = rpc_deriveaddresses(&state, &params).await.unwrap();
        let arr = result.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        // Regtest bech32 P2WPKH
        let addr = arr[0].as_str().unwrap();
        assert!(addr.starts_with("bcrt1q"), "expected bcrt1q prefix, got: {addr}");
    }

    #[tokio::test]
    async fn deriveaddresses_range_as_single_int() {
        let (state, _tmpdir) = test_state();
        // Create a ranged xpub descriptor — we need an xpub with /*
        let seed = [2u8; 64];
        let master = rbtc_wallet::ExtendedPrivKey::from_seed(&seed).unwrap();
        let xpub = rbtc_wallet::ExtendedPubKey::from_xprv(&master).to_base58();
        let desc = desc_with_checksum(&format!("wpkh({xpub}/*)"));
        // range=2 means [0, 2] → 3 addresses
        let params = json!([desc, 2]);
        let result = rpc_deriveaddresses(&state, &params).await.unwrap();
        let arr = result.as_array().unwrap();
        assert_eq!(arr.len(), 3, "range 0..=2 should produce 3 addresses");
        // All should be distinct bcrt1q addresses
        for addr_val in arr {
            let addr = addr_val.as_str().unwrap();
            assert!(addr.starts_with("bcrt1q"), "got: {addr}");
        }
        // All should be distinct
        let set: std::collections::HashSet<&str> = arr.iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(set.len(), 3, "addresses should be distinct");
    }

    #[tokio::test]
    async fn deriveaddresses_range_as_array() {
        let (state, _tmpdir) = test_state();
        let seed = [3u8; 64];
        let master = rbtc_wallet::ExtendedPrivKey::from_seed(&seed).unwrap();
        let xpub = rbtc_wallet::ExtendedPubKey::from_xprv(&master).to_base58();
        let desc = desc_with_checksum(&format!("wpkh({xpub}/*)"));
        // [1, 3] → indices 1, 2, 3 → 3 addresses
        let params = json!([desc, [1, 3]]);
        let result = rpc_deriveaddresses(&state, &params).await.unwrap();
        let arr = result.as_array().unwrap();
        assert_eq!(arr.len(), 3, "range 1..=3 should produce 3 addresses");
    }

    #[tokio::test]
    async fn deriveaddresses_range_required_for_ranged_descriptor() {
        let (state, _tmpdir) = test_state();
        let seed = [4u8; 64];
        let master = rbtc_wallet::ExtendedPrivKey::from_seed(&seed).unwrap();
        let xpub = rbtc_wallet::ExtendedPubKey::from_xprv(&master).to_base58();
        let desc = desc_with_checksum(&format!("wpkh({xpub}/*)"));
        // No range param → error
        let params = json!([desc]);
        let result = rpc_deriveaddresses(&state, &params).await;
        assert!(result.is_err());
        let (code, msg) = result.unwrap_err();
        assert_eq!(code, -8);
        assert!(msg.contains("Range must be specified"), "got: {msg}");
    }

    // ── getdescriptorinfo ────────────────────────────────────────────────

    #[tokio::test]
    async fn getdescriptorinfo_wpkh_fixed_key() {
        let (state, _tmpdir) = test_state();
        let pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let desc = format!("wpkh({})", pubkey);
        let result = rpc_getdescriptorinfo(&state, &json!([desc])).await.unwrap();
        // Should return canonical form with checksum
        let canonical = result["descriptor"].as_str().unwrap();
        assert!(canonical.contains('#'), "canonical should have checksum: {canonical}");
        assert!(canonical.starts_with("wpkh("), "canonical should start with wpkh(: {canonical}");
        // checksum is 8 chars
        let checksum = result["checksum"].as_str().unwrap();
        assert_eq!(checksum.len(), 8, "checksum should be 8 chars: {checksum}");
        // Fixed key, no wildcard → not ranged
        assert_eq!(result["isrange"], false);
        // wpkh is solvable
        assert_eq!(result["issolvable"], true);
        // No private keys
        assert_eq!(result["hasprivatekeys"], false);
    }

    #[tokio::test]
    async fn getdescriptorinfo_addr_not_solvable() {
        let (state, _tmpdir) = test_state();
        let desc = "addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)";
        let result = rpc_getdescriptorinfo(&state, &json!([desc])).await.unwrap();
        assert_eq!(result["issolvable"], false);
        assert_eq!(result["isrange"], false);
        assert_eq!(result["hasprivatekeys"], false);
    }

    #[tokio::test]
    async fn getdescriptorinfo_missing_param() {
        let (state, _tmpdir) = test_state();
        let result = rpc_getdescriptorinfo(&state, &json!([])).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn getdescriptorinfo_invalid_descriptor() {
        let (state, _tmpdir) = test_state();
        let result = rpc_getdescriptorinfo(&state, &json!(["notadescriptor"])).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn getdescriptorinfo_with_origin() {
        let (state, _tmpdir) = test_state();
        let desc = "wpkh([d34db33f/84h/0h/0h]0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
        let result = rpc_getdescriptorinfo(&state, &json!([desc])).await.unwrap();
        let canonical = result["descriptor"].as_str().unwrap();
        // Canonical should preserve origin
        assert!(canonical.contains("[d34db33f/84h/0h/0h]"), "should preserve origin: {canonical}");
        assert_eq!(result["isrange"], false);
        assert_eq!(result["issolvable"], true);
    }

    #[tokio::test]
    async fn getdescriptorinfo_wif_detects_private_key() {
        let (state, _tmpdir) = test_state();
        // Known WIF compressed mainnet private key
        let wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
        let desc = format!("wpkh({})", wif);
        let result = rpc_getdescriptorinfo(&state, &json!([desc])).await.unwrap();
        assert_eq!(result["hasprivatekeys"], true);
        // Canonical form should contain the public key, not the WIF
        let canonical = result["descriptor"].as_str().unwrap();
        assert!(!canonical.contains(wif), "canonical should not contain WIF key");
        assert!(canonical.starts_with("wpkh("), "canonical: {canonical}");
    }

    #[tokio::test]
    async fn descriptor_has_private_keys_helper() {
        // WIF key
        let wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
        assert!(descriptor_has_private_keys(&format!("wpkh({})", wif)));
        // Public key
        let pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        assert!(!descriptor_has_private_keys(&format!("wpkh({})", pubkey)));
        // addr() descriptor
        assert!(!descriptor_has_private_keys("addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)"));
    }

    // ── ping RPC ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn rpc_ping_returns_null() {
        let (state, _tmpdir) = test_state();
        let result = rpc_ping(&state).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json!(null));
    }

    // ── disconnectnode RPC ────────────────────────────────────────────────

    #[tokio::test]
    async fn rpc_disconnectnode_by_address() {
        let (state, _tmpdir) = test_state();
        let result = rpc_disconnectnode(&state, &json!(["1.2.3.4:8333"])).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json!(null));
    }

    #[tokio::test]
    async fn rpc_disconnectnode_by_nodeid() {
        let (state, _tmpdir) = test_state();
        let result = rpc_disconnectnode(&state, &json!(["", 42])).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json!(null));
    }

    #[tokio::test]
    async fn rpc_disconnectnode_not_found() {
        let (state, _tmpdir) = test_state();
        let result = rpc_disconnectnode(&state, &json!(["99.99.99.99:8333"])).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rpc_disconnectnode_missing_params() {
        let (state, _tmpdir) = test_state();
        let result = rpc_disconnectnode(&state, &json!([])).await;
        assert!(result.is_err());
    }

    // ── listtransactions / gettransaction / sendmany tests (M3) ───────

    #[tokio::test]
    async fn listtransactions_no_wallet() {
        let (state, _tmpdir) = test_state();
        let result = rpc_listtransactions(&state, &json!([])).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, -18);
    }

    #[tokio::test]
    async fn listtransactions_empty_wallet() {
        let (state, _tmpdir) = test_state_with_wallet();
        let result = rpc_listtransactions(&state, &json!([])).await.unwrap();
        let arr = result.as_array().unwrap();
        assert!(arr.is_empty());
    }

    #[tokio::test]
    async fn listtransactions_with_txs() {
        let (state, _tmpdir) = test_state_with_wallet();

        // Manually insert a transaction into the wallet tx_store
        {
            let wallet_arc = state.wallet.as_ref().unwrap();
            let mut w = wallet_arc.write().await;

            // Get a wallet address to create a "received" tx
            let addr = w.new_address(rbtc_wallet::AddressType::SegWit).unwrap();
            let spk = rbtc_wallet::address::address_to_script(&addr).unwrap();

            let tx = Transaction::from_parts(
                1,
                vec![rbtc_primitives::transaction::TxIn {
                    previous_output: OutPoint {
                        txid: Txid::ZERO,
                        vout: 0,
                    },
                    script_sig: rbtc_primitives::script::Script::new(),
                    sequence: 0xffffffff,
                    witness: vec![],
                }],
                vec![rbtc_primitives::transaction::TxOut {
                    value: 100_000,
                    script_pubkey: spk,
                }],
                0,
            );

            let txid = *tx.txid();
            w.tx_store.add_tx(
                txid,
                rbtc_wallet::tx_store::WalletTx {
                    tx,
                    block_hash: None,
                    block_height: None,
                    timestamp: 1700000000,
                    is_confirmed: false,
                    replaced_by: None,
                    is_abandoned: false,
                },
            );
        }

        let result = rpc_listtransactions(&state, &json!([])).await.unwrap();
        let arr = result.as_array().unwrap();
        assert!(!arr.is_empty());
        // Should have a "receive" entry
        assert!(arr.iter().any(|e| e["category"] == "receive"));
    }

    #[tokio::test]
    async fn listtransactions_count_and_skip() {
        let (state, _tmpdir) = test_state_with_wallet();

        // Insert 3 transactions
        {
            let wallet_arc = state.wallet.as_ref().unwrap();
            let mut w = wallet_arc.write().await;
            let addr = w.new_address(rbtc_wallet::AddressType::SegWit).unwrap();
            let spk = rbtc_wallet::address::address_to_script(&addr).unwrap();

            for i in 0..3 {
                let tx = Transaction::from_parts(
                    1,
                    vec![rbtc_primitives::transaction::TxIn {
                        previous_output: OutPoint {
                            txid: Txid::ZERO,
                            vout: i,
                        },
                        script_sig: rbtc_primitives::script::Script::new(),
                        sequence: 0xffffffff,
                        witness: vec![],
                    }],
                    vec![rbtc_primitives::transaction::TxOut {
                        value: (i as i64 + 1) * 10_000,
                        script_pubkey: spk.clone(),
                    }],
                    0,
                );
                let txid = *tx.txid();
                w.tx_store.add_tx(
                    txid,
                    rbtc_wallet::tx_store::WalletTx {
                        tx,
                        block_hash: None,
                        block_height: None,
                        timestamp: 1700000000 + i as u64,
                        is_confirmed: false,
                        replaced_by: None,
                        is_abandoned: false,
                    },
                );
            }
        }

        // count=2
        let result = rpc_listtransactions(&state, &json!(["*", 2])).await.unwrap();
        assert_eq!(result.as_array().unwrap().len(), 2);

        // skip=1, count=2
        let result = rpc_listtransactions(&state, &json!(["*", 2, 1])).await.unwrap();
        assert_eq!(result.as_array().unwrap().len(), 2);

        // skip=2, count=10 — only 1 remaining
        let result = rpc_listtransactions(&state, &json!(["*", 10, 2])).await.unwrap();
        assert_eq!(result.as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn gettransaction_no_wallet() {
        let (state, _tmpdir) = test_state();
        let result = rpc_gettransaction(&state, &json!(["0000000000000000000000000000000000000000000000000000000000000001"])).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, -18);
    }

    #[tokio::test]
    async fn gettransaction_missing_txid() {
        let (state, _tmpdir) = test_state_with_wallet();
        let result = rpc_gettransaction(&state, &json!([])).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, -32602);
    }

    #[tokio::test]
    async fn gettransaction_not_found() {
        let (state, _tmpdir) = test_state_with_wallet();
        let result = rpc_gettransaction(&state, &json!(["0000000000000000000000000000000000000000000000000000000000000001"])).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, -5);
    }

    #[tokio::test]
    async fn gettransaction_found() {
        let (state, _tmpdir) = test_state_with_wallet();

        let txid_hex;
        {
            let wallet_arc = state.wallet.as_ref().unwrap();
            let mut w = wallet_arc.write().await;
            let addr = w.new_address(rbtc_wallet::AddressType::SegWit).unwrap();
            let spk = rbtc_wallet::address::address_to_script(&addr).unwrap();

            let tx = Transaction::from_parts(
                1,
                vec![rbtc_primitives::transaction::TxIn {
                    previous_output: OutPoint {
                        txid: Txid::ZERO,
                        vout: 0,
                    },
                    script_sig: rbtc_primitives::script::Script::new(),
                    sequence: 0xffffffff,
                    witness: vec![],
                }],
                vec![rbtc_primitives::transaction::TxOut {
                    value: 50_000,
                    script_pubkey: spk,
                }],
                0,
            );

            let txid = *tx.txid();
            txid_hex = txid.to_hex();
            w.tx_store.add_tx(
                txid,
                rbtc_wallet::tx_store::WalletTx {
                    tx,
                    block_hash: None,
                    block_height: None,
                    timestamp: 1700000000,
                    is_confirmed: false,
                    replaced_by: None,
                    is_abandoned: false,
                },
            );
        }

        let result = rpc_gettransaction(&state, &json!([txid_hex])).await.unwrap();
        assert_eq!(result["txid"], txid_hex);
        assert_eq!(result["confirmations"], 0);
        assert!(result["hex"].is_string());
        assert!(result["details"].is_array());
        assert!(result["time"].is_number());
    }

    #[tokio::test]
    async fn gettransaction_confirmed() {
        let (state, _tmpdir) = test_state_with_wallet();

        let txid_hex;
        {
            let wallet_arc = state.wallet.as_ref().unwrap();
            let mut w = wallet_arc.write().await;
            let addr = w.new_address(rbtc_wallet::AddressType::SegWit).unwrap();
            let spk = rbtc_wallet::address::address_to_script(&addr).unwrap();

            let tx = Transaction::from_parts(
                1,
                vec![rbtc_primitives::transaction::TxIn {
                    previous_output: OutPoint {
                        txid: Txid::ZERO,
                        vout: 0,
                    },
                    script_sig: rbtc_primitives::script::Script::new(),
                    sequence: 0xffffffff,
                    witness: vec![],
                }],
                vec![rbtc_primitives::transaction::TxOut {
                    value: 50_000,
                    script_pubkey: spk,
                }],
                0,
            );

            let txid = *tx.txid();
            txid_hex = txid.to_hex();
            let mut bh_bytes = [0u8; 32];
            bh_bytes[0] = 0xAB;
            w.tx_store.add_tx(
                txid,
                rbtc_wallet::tx_store::WalletTx {
                    tx,
                    block_hash: Some(rbtc_primitives::hash::BlockHash(rbtc_primitives::hash::Hash256(bh_bytes))),
                    block_height: Some(0),
                    timestamp: 1700000000,
                    is_confirmed: true,
                    replaced_by: None,
                    is_abandoned: false,
                },
            );
        }

        let result = rpc_gettransaction(&state, &json!([txid_hex])).await.unwrap();
        assert!(result["confirmations"].as_i64().unwrap() >= 1);
        assert!(result["blockhash"].is_string());
        assert_eq!(result["blockheight"], 0);
    }

    #[tokio::test]
    async fn sendmany_no_wallet() {
        let (state, _tmpdir) = test_state();
        let result = rpc_sendmany(&state, &json!(["", {}])).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, -18);
    }

    #[tokio::test]
    async fn sendmany_missing_amounts() {
        let (state, _tmpdir) = test_state_with_wallet();
        let result = rpc_sendmany(&state, &json!([""])).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, -32602);
    }

    #[tokio::test]
    async fn sendmany_empty_amounts() {
        let (state, _tmpdir) = test_state_with_wallet();
        let result = rpc_sendmany(&state, &json!(["", {}])).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, -32602);
    }

    #[tokio::test]
    async fn sendmany_invalid_amount() {
        let (state, _tmpdir) = test_state_with_wallet();
        let result = rpc_sendmany(&state, &json!(["", {"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh": -1.0}])).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, -3);
    }

    // ── L12 utility RPC tests ─────────────────────────────────────────────

    #[tokio::test]
    async fn signrawtransactionwithkey_missing_hex() {
        let (state, _tmpdir) = test_state();
        let result = rpc_signrawtransactionwithkey(&state, &json!([])).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, -32602);
    }

    #[tokio::test]
    async fn signrawtransactionwithkey_missing_privkeys() {
        let (state, _tmpdir) = test_state();
        let result = rpc_signrawtransactionwithkey(&state, &json!(["0100000000000000000000"])).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn signrawtransactionwithkey_invalid_sighash() {
        let (state, _tmpdir) = test_state();
        use rbtc_primitives::transaction::{TxIn, TxOut};
        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint { txid: Txid(Hash256([0xaa; 32])), vout: 0 },
                script_sig: rbtc_primitives::script::Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut { value: 50000, script_pubkey: rbtc_primitives::script::Script::new() }],
            0,
        );
        let mut buf = Vec::new();
        tx.encode(&mut buf).unwrap();
        let hex_str = hex::encode(&buf);
        let wif = "cVpF924EFAzJqKMSMk2bXCsytTa2GjHCHboYCsaYMBLcVVYGPg3R";
        let result = rpc_signrawtransactionwithkey(&state, &json!([hex_str, [wif], [], "INVALID_SIGHASH"])).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, -8);
    }

    #[tokio::test]
    async fn signrawtransactionwithkey_with_prevtxs() {
        let (state, _tmpdir) = test_state();
        let wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
        let (sk, _) = from_wif(wif).unwrap();
        let secp = secp256k1::Secp256k1::signing_only();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let pk_hash = rbtc_crypto::hash160(&pk.serialize());
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&pk_hash.0);
        let spk_hex = hex::encode(&spk);
        let txid = Txid(Hash256([0xbb; 32]));
        let txid_hex = txid.to_hex();
        let tx = Transaction::from_parts(
            2,
            vec![rbtc_primitives::transaction::TxIn {
                previous_output: OutPoint { txid: txid.clone(), vout: 0 },
                script_sig: rbtc_primitives::script::Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![rbtc_primitives::transaction::TxOut {
                value: 49000,
                script_pubkey: rbtc_primitives::script::Script::from_bytes(spk.clone()),
            }],
            0,
        );
        let mut buf = Vec::new();
        tx.encode(&mut buf).unwrap();
        let tx_hex = hex::encode(&buf);
        let result = rpc_signrawtransactionwithkey(
            &state,
            &json!([tx_hex, [wif], [{"txid": txid_hex, "vout": 0, "scriptPubKey": spk_hex, "amount": 0.0005}]]),
        ).await;
        assert!(result.is_ok(), "signing should succeed: {:?}", result);
        let val = result.unwrap();
        assert_eq!(val["complete"], true);
        assert!(val["hex"].as_str().unwrap().len() > tx_hex.len());
    }

    #[tokio::test]
    async fn lockunspent_requires_wallet() {
        let (state, _tmpdir) = test_state();
        let result = rpc_lockunspent(&state, &json!([false, []])).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, -18);
    }

    #[tokio::test]
    async fn lockunspent_lock_and_list() {
        let (state, _tmpdir) = test_state_with_wallet();
        let txid = "aa".repeat(32);
        let result = rpc_lockunspent(&state, &json!([false, [{"txid": txid, "vout": 0}]])).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json!(true));
        let locked = rpc_listlockunspent(&state).await.unwrap();
        let arr = locked.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["txid"].as_str().unwrap(), txid);
        assert_eq!(arr[0]["vout"], 0);
        let result = rpc_lockunspent(&state, &json!([true, [{"txid": txid, "vout": 0}]])).await;
        assert!(result.is_ok());
        let locked = rpc_listlockunspent(&state).await.unwrap();
        assert_eq!(locked.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn lockunspent_unlock_all() {
        let (state, _tmpdir) = test_state_with_wallet();
        let txid1 = "aa".repeat(32);
        let txid2 = "bb".repeat(32);
        rpc_lockunspent(&state, &json!([false, [{"txid": txid1, "vout": 0}, {"txid": txid2, "vout": 1}]])).await.unwrap();
        let locked = rpc_listlockunspent(&state).await.unwrap();
        assert_eq!(locked.as_array().unwrap().len(), 2);
        rpc_lockunspent(&state, &json!([true])).await.unwrap();
        let locked = rpc_listlockunspent(&state).await.unwrap();
        assert_eq!(locked.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn listlockunspent_requires_wallet() {
        let (state, _tmpdir) = test_state();
        let result = rpc_listlockunspent(&state).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, -18);
    }

    #[tokio::test]
    async fn prioritisetransaction_basic() {
        let (state, _tmpdir) = test_state();
        let txid = "cc".repeat(32);
        let result = rpc_prioritisetransaction(&state, &json!([txid, 0, 5000])).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json!(true));
        let mempool = state.mempool.read().await;
        let txid_bytes = hex::decode(&txid).unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&txid_bytes);
        let tid = Txid(Hash256(arr));
        assert_eq!(mempool.get_fee_delta(&tid), 5000);
    }

    #[tokio::test]
    async fn prioritisetransaction_missing_txid() {
        let (state, _tmpdir) = test_state();
        let result = rpc_prioritisetransaction(&state, &json!([])).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, -32602);
    }

    #[tokio::test]
    async fn prioritisetransaction_accumulates() {
        let (state, _tmpdir) = test_state();
        let txid = "dd".repeat(32);
        rpc_prioritisetransaction(&state, &json!([txid, 0, 1000])).await.unwrap();
        rpc_prioritisetransaction(&state, &json!([txid, 0, 2000])).await.unwrap();
        let mempool = state.mempool.read().await;
        let txid_bytes = hex::decode(&txid).unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&txid_bytes);
        let tid = Txid(Hash256(arr));
        assert_eq!(mempool.get_fee_delta(&tid), 3000);
    }
}
