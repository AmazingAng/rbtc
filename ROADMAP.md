# rbtc Roadmap

This document tracks project milestones and deliverables from **Phase 1** to **Phase 8**.

## Phase 1 — Core Foundation
- **Full consensus rules**: PoW validation, difficulty adjustment (every 2016 blocks), transaction validation, block weight limits, sigops counting
- **SegWit support**: P2WPKH, P2WSH, witness commitment validation (BIP141/143)
- **Taproot support**: P2TR key path + script path verification (BIP340/341/342)
- **P2P protocol**: Complete Bitcoin wire protocol (version/verack/inv/getdata/block/tx/headers/getheaders/ping/pong)
- **Initial Block Download**: Headers-first IBD with batch block download (64 blocks in flight)
- **Persistent storage**: RocksDB-backed UTXO set, block index, and chain state
- **Multi-network**: mainnet, testnet4, regtest, signet

## Phase 2 — Full Node Features
- **Restart recovery**: Block index and UTXO set fully restored from RocksDB on startup — no re-sync needed after restart
- **Mempool**: Transaction validation, fee-rate ordering, relay to peers, chained-tx support (mempool UTXO view)
- **Transaction relay**: Unconfirmed transactions received, validated, and announced via `inv` to all peers
- **Inbound connections**: Listens on a configurable port; accepts inbound peers alongside outbound connections
- **JSON-RPC server**: HTTP/JSON-RPC endpoint (axum-based) compatible with Bitcoin Core's interface
- **Chain reorganization**: Per-block undo data persisted to `CF_UNDO`; full reorg support via `reorganize_to()`

## Phase 3 — Built-in HD Wallet
- **BIP39 mnemonics**: 12/24-word mnemonic generation from OS entropy; phrase import and BIP39 seed derivation (PBKDF2-HMAC-SHA512)
- **BIP32 HD derivation**: Full hierarchical deterministic key derivation with hardened and normal children; `DerivationPath` parser (`m/84'/0'/0'/0/3`)
- **Three address types**:
  - P2PKH (Legacy, BIP44 path `m/44'/coin'/…`) — `1…` / `m…` Base58Check addresses
  - P2WPKH (Native SegWit, BIP84 path `m/84'/coin'/…`) — `bc1q…` / `bcrt1q…` bech32 addresses
  - P2TR (Taproot, BIP86 path `m/86'/coin'/…`) — `bc1p…` / `bcrt1p…` bech32m addresses with proper TapTweak
- **WIF encoding/decoding**: Import/export private keys in Wallet Import Format
- **Incremental UTXO scanning**: `scan_block()` and `remove_spent()` hooks in `handle_block()` keep wallet UTXOs in sync with no full-rescan
- **Transaction building**: `CoinSelector` (greedy largest-first), `TxBuilder`, and `sign_transaction()` producing valid Legacy/SegWit/Taproot signatures
- **AES-256-GCM wallet encryption**: xprv encrypted with a PBKDF2-derived key; public keys and addresses stored in plaintext for scanning
- **Wallet RPC methods**: `getnewaddress`, `getbalance`, `listunspent`, `sendtoaddress`, `fundrawtransaction`, `signrawtransactionwithwallet`, `dumpprivkey`, `importprivkey`, `getwalletinfo`

## Phase 4 — Mining Support
- **Block template construction** (`rbtc-miner`): `BlockTemplate` assembles coinbase (BIP34 height encoding, extraNonce, miner tag), selects mempool transactions by fee-rate, and computes the Merkle root
- **CPU PoW miner**: `mine_block()` iterates over `nonce ∈ [0, 2³²)`, refreshes timestamps every 1 000 000 hashes, and increments `extra_nonce` when the nonce space is exhausted; trivially fast on regtest (`0x207fffff`)
- **BIP22 `getblocktemplate`**: returns `version`, `previousblockhash`, `target`, `bits`, `height`, `coinbasevalue`, and the full transaction list for external miners
- **`submitblock`**: deserialises a hex-encoded block and injects it into the node's event loop via an `UnboundedSender<Block>` channel — same path as peer-received blocks
- **`generatetoaddress` / `generate`**: CPU-mines N blocks to a given address (or the wallet's next address); each mining call runs in `spawn_blocking` so the async runtime stays responsive; broadcasts the resulting block hashes
- **Mining info RPCs**: `getmininginfo`, `getnetworkhashps` (estimated from recent-blocks difficulty and block-time), `estimatesmartfee` (mempool median fee-rate)

## Phase 5 — Transaction & Address Index
- **Transaction index** (`CF_TX_INDEX`): every confirmed transaction is indexed by txid → `(block_hash, tx_offset)`; populated atomically when a block is connected and cleaned up on reorg
- **Address index** (`CF_ADDR_INDEX`): every transaction output is indexed by scriptPubKey prefix → `(height, tx_offset, txid)`; prefix scan returns full history in block-height order
- **`getrawtransaction` (confirmed)**: `TxIndexStore::get(txid)` resolves confirmed transactions; verbose=false returns raw hex, verbose=true returns `{txid, blockhash, confirmations, vin, vout}`
- **`getaddresstxids`**: returns all txids (hex) that produced an output to a given address, with optional `{start, end}` height filter
- **`getaddressutxos`**: returns all currently unspent outputs for an address: `{txid, vout, value, height, confirmations}`
- **`getaddressbalance`**: returns `{balance, received}` in satoshis — `balance` = unspent, `received` = all-time total received

## Phase 6 — Protocol Completeness & Performance
- **Parallel script verification**: `verify_block()` uses `rayon::par_iter` for non-coinbase transactions, enabling 2–4× IBD speedup on multi-core machines; coinbase is verified sequentially before the parallel phase
- **Larger IBD batches**: `IBD_BATCH_SIZE` raised from 16 → 64; IBD progress-check timer reduced from 5 s → 1 s; UTXO + tx_index + addr_index + chain-tip all committed in a single atomic `WriteBatch` per block
- **Compact Blocks (BIP152)**: `crates/rbtc-net/src/compact.rs` implements `CompactBlock` / `GetBlockTxn` / `BlockTxn` wire types, SipHash-2-4 short TxID calculation, and a `reconstruct_block()` helper; peer_manager sends `sendcmpct(mode=1)` after handshake; node handles the full 3-message reconstruction flow
- **PSBT (BIP174)** — new `rbtc-psbt` crate:
  - `Psbt::create()` (Creator): strips scriptSig/witness and produces an unsigned PSBT
  - `add_witness_utxo()`, `add_non_witness_utxo()`, `set_sighash_type()` (Updater)
  - `sign_input()` (Signer): P2WPKH via BIP143 sighash + ECDSA; P2PKH via legacy sighash + ECDSA
  - `combine()` (Combiner): merges partial signatures and metadata from multiple PSBTs
  - `finalize()` (Finalizer): moves partial sigs into `final_script_witness` / `final_script_sig`
  - `extract_tx()` (Extractor): returns the final signed `Transaction`
  - Base64 serialize/deserialize; 6 new RPCs: `createpsbt`, `walletprocesspsbt`, `finalizepsbt`, `combinepsbt`, `decodepsbt`, `analyzepsbt`
- **Block Pruning**: `--prune <MiB>` CLI flag; `BlockStore::prune_blocks_below(height)` deletes `CF_BLOCK_DATA` for blocks > 288 confirmations deep; `BlockStatus::Pruned` (4) recorded in `block_index`; headers, UTXO set, and indexes are never pruned

## Phase 7 — Mempool Policy & P2P Robustness

### Mempool Policy
- **BIP125 Replace-by-Fee (RBF)**: `accept_tx()` detects double-spend conflicts; if all conflicting transactions signal RBF (`nSequence < 0xFFFFFFFE`), the replacement is accepted when `new_fee_rate ≥ max_conflict_rate + min_relay_fee`; enforces ≤ 100 replacement limit; new error variants: `RbfNotSignaling`, `RbfInsufficientFee`, `TooManyReplacements`
- **CPFP Ancestor Fee Rate**: `MempoolEntry::ancestor_fee_rate` captures the effective fee rate including all unconfirmed parents; `ancestor_package(txid)` recursively computes `(total_fee, total_vsize)` across the dependency graph; `txids_by_fee_rate()` and `TxSelector::select()` now sort by ancestor fee rate, enabling low-fee parents to be mined when a high-fee child is present
- **Mempool Size Cap & Eviction**: `Mempool::with_max_vsize(bytes)` caps the pool (default 300 MB); when the cap is exceeded after an insertion, `evict_below_fee_rate()` evicts the cheapest entries first; if the new transaction itself would be the cheapest, it is rejected with `MempoolError::MempoolFull`; `--mempool-size <MB>` CLI flag controls the limit
- **`feefilter` per-peer enforcement**: `ConnectedPeer::fee_filter` is set when a peer sends a `feefilter` message; `PeerManager::broadcast_tx_inv()` skips peers whose `fee_filter > tx_fee_rate_sat_kvb`, preventing relay of transactions they wouldn't accept

### P2P Robustness
- **Peer Misbehavior Scoring & Bans**: `ConnectedPeer::misbehavior` accumulates a score; `PeerManager::misbehave(peer_id, score)` disconnects and bans an IP when score ≥ 100; bans are persisted to `CF_PEER_BANS` (key = IP bytes, value = expiry Unix timestamp) via `PeerStore::ban()` / `is_banned()` / `expire_bans()`; inbound connections with banned IPs are rejected immediately after handshake; ban duration is 24 hours
- **`addr` Message Relay**: `PeerManager::handle_addr()` validates timestamp drift (≤ 10 minutes); valid addresses are added to `candidate_addrs` (capped at 1 000); up to 10 entries are trickling-forwarded to 2 randomly-chosen other peers; the node emits `NodeEvent::AddrReceived` for persistence; `getaddr` is sent to every peer after the handshake completes
- **Peer Address Persistence**: new `rbtc-storage/src/peer_store.rs` with `CF_PEER_ADDRS` column family (key = 18-byte IP:port, value = `last_seen u64` + `services u64`); `PeerStore::save_addrs()` / `load_addrs()` for bulk persistence; at startup, `load_addrs()` seeds `PeerManager::candidate_addrs`; every 5 minutes `persist_peer_addrs()` flushes the current candidate list to RocksDB
- **Connection Manager**: `PeerManager` tracks `outbound_count`, `connecting_addrs` (dedup guard), and `connected_addrs`; every 30 s the reconnect loop fills outbound slots from `candidate_addrs` up to `max_outbound`; banned IPs and already-connected/connecting addresses are skipped; inbound and outbound counts are decremented correctly on disconnect

## Phase 8 — IBD Parallelism & UTXO Cache

### IBD Multi-peer Parallel Download
- **Per-peer inflight tracking**: `IbdState` now tracks each peer's in-flight block requests independently via `peer_downloads: HashMap<u64, PeerDownload>`, replacing the single `sync_peer`; `PeerDownload.requested_at` enables per-peer stall detection
- **Per-peer stall detection**: `IbdState::stalled_peers(timeout)` returns all peers whose in-flight batch has not made progress within `STALL_TIMEOUT`; `check_ibd_progress` disconnects stalled peers and returns their ranges to the work queue via `release_peer()`
- **Height-range work queue**: when entering the Blocks phase, `partition_ranges(start, tip, SEGMENT_SIZE)` cuts the remaining header range into 512-block segments and fills `pending_ranges: VecDeque<(u32,u32)>`; `assigned_ranges` tracks which peer holds each segment
- **Multi-peer dispatch**: `assign_blocks_to_peers()` pops segments from `pending_ranges` and sends `getdata` to all idle peers simultaneously; called on `PeerConnected`, batch completion in `handle_block`, and every IBD timer tick; `PeerDisconnected` and `NotFound` call `release_peer()` to re-queue the affected segment
- **New peer-manager helper**: `peers_for_ibd(min_height) -> Vec<u64>` returns all connected peers whose reported best height meets the IBD target, enabling true multi-peer parallelism

### UTXO Cache
- **`UtxoLookup` trait** (`rbtc-consensus`): `verify_block` and `verify_transaction` now accept `&impl UtxoLookup` instead of `&UtxoSet`, decoupling consensus validation from the concrete storage back-end; `UtxoSet` implements the trait for backward compatibility
- **`CachedUtxoSet`** (new `crates/rbtc-node/src/utxo_cache.rs`): write-back cache with three layers — `dirty` (uncommitted block changes), `hot` (size-limited clean entries), and RocksDB fallback; `connect_block()` stages UTXO changes in `dirty`; `flush_dirty(batch)` writes dirty to the existing `WriteBatch` and promotes entries to `hot`, replacing the separate `utxo_store.connect_block_into_batch()` call; `evict_cold()` removes least-recently-promoted entries from `hot` when the cache exceeds `max_bytes`
- **`--utxo-cache <MB>` CLI flag** (default `0` = unlimited): when `0`, all UTXOs are pre-loaded into the hot cache at startup (previous behaviour); when `>0`, the hot cache starts empty and falls back to RocksDB on misses, capping memory usage
- **Unified write path**: every `handle_block` now routes UTXO writes through `utxo_cache.flush_dirty(batch)` so the cache and the database are always consistent
