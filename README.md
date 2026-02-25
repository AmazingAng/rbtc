# rbtc — Bitcoin Core in Rust

A from-scratch implementation of Bitcoin Core's consensus, P2P networking, HD wallet, CPU miner, compact blocks, PSBT, block pruning, mempool policy (RBF/CPFP/eviction), and P2P robustness (ban scoring, addr relay, peer persistence, connection manager), written in Rust. No `bitcoin` crate — all protocol types, encoding, validation, key derivation, and block template construction are implemented independently.

## Architecture

```
rbtc/
├── crates/
│   ├── rbtc-primitives/   # Core data types: Block, Transaction, Script, hashes, codec
│   ├── rbtc-crypto/       # SHA256d, RIPEMD-160, Merkle tree, ECDSA/Schnorr, sighash
│   ├── rbtc-script/       # Bitcoin Script interpreter (~180 opcodes, SegWit, Taproot)
│   ├── rbtc-consensus/    # PoW, difficulty adjustment, UTXO set, block/tx validation
│   ├── rbtc-storage/      # RocksDB: block index, UTXO store, undo data, chain state, wallet
│   ├── rbtc-mempool/      # Transaction pool: validation, fee rate, relay, chained txs
│   ├── rbtc-net/          # P2P: wire protocol, peer management (tokio), IBD
│   ├── rbtc-wallet/       # HD wallet: BIP32/39, address generation, UTXO tracking, signing
│   ├── rbtc-miner/        # Mining: block template, tx selection, CPU PoW worker
│   ├── rbtc-psbt/         # BIP174 PSBT: Creator/Updater/Signer/Combiner/Finalizer/Extractor
│   └── rbtc-node/         # Binary: node loop, JSON-RPC server, config
```

## Key Features

### Phase 1 — Core Foundation
- **Full consensus rules**: PoW validation, difficulty adjustment (every 2016 blocks), transaction validation, block weight limits, sigops counting
- **SegWit support**: P2WPKH, P2WSH, witness commitment validation (BIP141/143)
- **Taproot support**: P2TR key path + script path verification (BIP340/341/342)
- **P2P protocol**: Complete Bitcoin wire protocol (version/verack/inv/getdata/block/tx/headers/getheaders/ping/pong)
- **Initial Block Download**: Headers-first IBD with batch block download (64 blocks in flight)
- **Persistent storage**: RocksDB-backed UTXO set, block index, and chain state
- **Multi-network**: mainnet, testnet4, regtest, signet

### Phase 2 — Full Node Features
- **Restart recovery**: Block index and UTXO set fully restored from RocksDB on startup — no re-sync needed after restart
- **Mempool**: Transaction validation, fee-rate ordering, relay to peers, chained-tx support (mempool UTXO view)
- **Transaction relay**: Unconfirmed transactions received, validated, and announced via `inv` to all peers
- **Inbound connections**: Listens on a configurable port; accepts inbound peers alongside outbound connections
- **JSON-RPC server**: HTTP/JSON-RPC endpoint (axum-based) compatible with Bitcoin Core's interface
- **Chain reorganization**: Per-block undo data persisted to `CF_UNDO`; full reorg support via `reorganize_to()`

### Phase 3 — Built-in HD Wallet
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

### Phase 4 — Mining Support
- **Block template construction** (`rbtc-miner`): `BlockTemplate` assembles coinbase (BIP34 height encoding, extraNonce, miner tag), selects mempool transactions by fee-rate, and computes the Merkle root
- **CPU PoW miner**: `mine_block()` iterates over `nonce ∈ [0, 2³²)`, refreshes timestamps every 1 000 000 hashes, and increments `extra_nonce` when the nonce space is exhausted; trivially fast on regtest (`0x207fffff`)
- **BIP22 `getblocktemplate`**: returns `version`, `previousblockhash`, `target`, `bits`, `height`, `coinbasevalue`, and the full transaction list for external miners
- **`submitblock`**: deserialises a hex-encoded block and injects it into the node's event loop via an `UnboundedSender<Block>` channel — same path as peer-received blocks
- **`generatetoaddress` / `generate`**: CPU-mines N blocks to a given address (or the wallet's next address); each mining call runs in `spawn_blocking` so the async runtime stays responsive; broadcasts the resulting block hashes
- **Mining info RPCs**: `getmininginfo`, `getnetworkhashps` (estimated from recent-blocks difficulty and block-time), `estimatesmartfee` (mempool median fee-rate)

### Phase 5 — Transaction & Address Index
- **Transaction index** (`CF_TX_INDEX`): every confirmed transaction is indexed by txid → `(block_hash, tx_offset)`; populated atomically when a block is connected and cleaned up on reorg
- **Address index** (`CF_ADDR_INDEX`): every transaction output is indexed by scriptPubKey prefix → `(height, tx_offset, txid)`; prefix scan returns full history in block-height order
- **`getrawtransaction` (confirmed)**: `TxIndexStore::get(txid)` resolves confirmed transactions; verbose=false returns raw hex, verbose=true returns `{txid, blockhash, confirmations, vin, vout}`
- **`getaddresstxids`**: returns all txids (hex) that produced an output to a given address, with optional `{start, end}` height filter
- **`getaddressutxos`**: returns all currently unspent outputs for an address: `{txid, vout, value, height, confirmations}`
- **`getaddressbalance`**: returns `{balance, received}` in satoshis — `balance` = unspent, `received` = all-time total received


### Phase 6 — Protocol Completeness & Performance
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

### Phase 7 — Mempool Policy & P2P Robustness

#### Mempool Policy
- **BIP125 Replace-by-Fee (RBF)**: `accept_tx()` detects double-spend conflicts; if all conflicting transactions signal RBF (`nSequence < 0xFFFFFFFE`), the replacement is accepted when `new_fee_rate ≥ max_conflict_rate + min_relay_fee`; enforces ≤ 100 replacement limit; new error variants: `RbfNotSignaling`, `RbfInsufficientFee`, `TooManyReplacements`
- **CPFP Ancestor Fee Rate**: `MempoolEntry::ancestor_fee_rate` captures the effective fee rate including all unconfirmed parents; `ancestor_package(txid)` recursively computes `(total_fee, total_vsize)` across the dependency graph; `txids_by_fee_rate()` and `TxSelector::select()` now sort by ancestor fee rate, enabling low-fee parents to be mined when a high-fee child is present
- **Mempool Size Cap & Eviction**: `Mempool::with_max_vsize(bytes)` caps the pool (default 300 MB); when the cap is exceeded after an insertion, `evict_below_fee_rate()` evicts the cheapest entries first; if the new transaction itself would be the cheapest, it is rejected with `MempoolError::MempoolFull`; `--mempool-size <MB>` CLI flag controls the limit
- **`feefilter` per-peer enforcement**: `ConnectedPeer::fee_filter` is set when a peer sends a `feefilter` message; `PeerManager::broadcast_tx_inv()` skips peers whose `fee_filter > tx_fee_rate_sat_kvb`, preventing relay of transactions they wouldn't accept

#### P2P Robustness
- **Peer Misbehavior Scoring & Bans**: `ConnectedPeer::misbehavior` accumulates a score; `PeerManager::misbehave(peer_id, score)` disconnects and bans an IP when score ≥ 100; bans are persisted to `CF_PEER_BANS` (key = IP bytes, value = expiry Unix timestamp) via `PeerStore::ban()` / `is_banned()` / `expire_bans()`; inbound connections with banned IPs are rejected immediately after handshake; ban duration is 24 hours
- **`addr` Message Relay**: `PeerManager::handle_addr()` validates timestamp drift (≤ 10 minutes); valid addresses are added to `candidate_addrs` (capped at 1 000); up to 10 entries are trickling-forwarded to 2 randomly-chosen other peers; the node emits `NodeEvent::AddrReceived` for persistence; `getaddr` is sent to every peer after the handshake completes
- **Peer Address Persistence**: new `rbtc-storage/src/peer_store.rs` with `CF_PEER_ADDRS` column family (key = 18-byte IP:port, value = `last_seen u64` + `services u64`); `PeerStore::save_addrs()` / `load_addrs()` for bulk persistence; at startup, `load_addrs()` seeds `PeerManager::candidate_addrs`; every 5 minutes `persist_peer_addrs()` flushes the current candidate list to RocksDB
- **Connection Manager**: `PeerManager` tracks `outbound_count`, `connecting_addrs` (dedup guard), and `connected_addrs`; every 30 s the reconnect loop fills outbound slots from `candidate_addrs` up to `max_outbound`; banned IPs and already-connected/connecting addresses are skipped; inbound and outbound counts are decremented correctly on disconnect

### Phase 8 — IBD Parallelism & UTXO Cache

#### IBD Multi-peer Parallel Download
- **Per-peer inflight tracking**: `IbdState` now tracks each peer's in-flight block requests independently via `peer_downloads: HashMap<u64, PeerDownload>`, replacing the single `sync_peer`; `PeerDownload.requested_at` enables per-peer stall detection
- **Per-peer stall detection**: `IbdState::stalled_peers(timeout)` returns all peers whose in-flight batch has not made progress within `STALL_TIMEOUT`; `check_ibd_progress` disconnects stalled peers and returns their ranges to the work queue via `release_peer()`
- **Height-range work queue**: when entering the Blocks phase, `partition_ranges(start, tip, SEGMENT_SIZE)` cuts the remaining header range into 512-block segments and fills `pending_ranges: VecDeque<(u32,u32)>`; `assigned_ranges` tracks which peer holds each segment
- **Multi-peer dispatch**: `assign_blocks_to_peers()` pops segments from `pending_ranges` and sends `getdata` to all idle peers simultaneously; called on `PeerConnected`, batch completion in `handle_block`, and every IBD timer tick; `PeerDisconnected` and `NotFound` call `release_peer()` to re-queue the affected segment
- **New peer-manager helper**: `peers_for_ibd(min_height) -> Vec<u64>` returns all connected peers whose reported best height meets the IBD target, enabling true multi-peer parallelism

#### UTXO Cache
- **`UtxoLookup` trait** (`rbtc-consensus`): `verify_block` and `verify_transaction` now accept `&impl UtxoLookup` instead of `&UtxoSet`, decoupling consensus validation from the concrete storage back-end; `UtxoSet` implements the trait for backward compatibility
- **`CachedUtxoSet`** (new `crates/rbtc-node/src/utxo_cache.rs`): write-back cache with three layers — `dirty` (uncommitted block changes), `hot` (size-limited clean entries), and RocksDB fallback; `connect_block()` stages UTXO changes in `dirty`; `flush_dirty(batch)` writes dirty to the existing `WriteBatch` and promotes entries to `hot`, replacing the separate `utxo_store.connect_block_into_batch()` call; `evict_cold()` removes least-recently-promoted entries from `hot` when the cache exceeds `max_bytes`
- **`--utxo-cache <MB>` CLI flag** (default `0` = unlimited): when `0`, all UTXOs are pre-loaded into the hot cache at startup (previous behaviour); when `>0`, the hot cache starts empty and falls back to RocksDB on misses, capping memory usage
- **Unified write path**: every `handle_block` now routes UTXO writes through `utxo_cache.flush_dirty(batch)` so the cache and the database are always consistent

## Dependencies

| Crate | Purpose |
|-------|---------|
| `secp256k1 = "0.31"` | ECDSA + Schnorr (BIP340) signing and verification |
| `sha2 = "0.10"` | SHA-256 |
| `ripemd = "0.2.0-rc.5"` | RIPEMD-160 (hash160 for addresses) |
| `hmac = "0.12"` | HMAC-SHA512 for BIP32 child key derivation |
| `pbkdf2 = "0.12"` | PBKDF2-HMAC-SHA512 for BIP39 seeds; PBKDF2-HMAC-SHA256 for wallet key encryption |
| `bip39 = "2"` | BIP39 mnemonic phrase generation and parsing |
| `bech32 = "0.11"` | bech32 (P2WPKH) and bech32m (P2TR) address encoding |
| `bs58 = "0.5"` | Base58Check for P2PKH addresses and WIF private keys |
| `aes-gcm = "0.10"` | AES-256-GCM authenticated encryption for xprv storage |
| `rand = "0.8"` | OS randomness (entropy for mnemonics, Taproot aux_rand) |
| `rocksdb = "0.22"` | Persistent block index, UTXO store, undo data, wallet data |
| `tokio = "1"` | Async P2P networking and RPC server |
| `axum = "0.8"` | JSON-RPC HTTP server |
| `clap = "4"` | CLI argument parsing |
| `rayon = "1"` | Parallel script verification (IBD speedup) |
| `siphasher = "1"` | SipHash-2-4 for BIP152 compact block short TxIDs |
| `base64 = "0.22"` | PSBT Base64 encode/decode |
| `tracing` | Structured logging |

**Not used**: `bitcoin` crate — all protocol types, encoding, and key derivation are implemented from scratch.

## Usage

```bash
# Build
cargo build --release

# Run on mainnet (syncs from genesis, persists state to ~/.rbtc)
./target/release/rbtc --network mainnet

# Run on regtest (connect to a local bitcoind)
./target/release/rbtc --network regtest --no-dns-seeds --addnode 127.0.0.1:18444

# Listen for inbound connections on port 8333
./target/release/rbtc --listen-port 8333

# Custom data directory and RPC port
./target/release/rbtc --datadir /mnt/bitcoin --rpc-port 8332

# --- Wallet ---

# Create a new wallet (generates mnemonic, prints it, then runs the node)
./target/release/rbtc --network regtest --create-wallet --wallet-passphrase "my secret"

# Run node with an existing wallet (unlocked for RPC use)
./target/release/rbtc --network regtest --wallet --wallet-passphrase "my secret"

# --- Mining (regtest) ---

# Mine 101 blocks to a specific address (makes coinbase spendable)
curl -s -d '{"method":"generatetoaddress","params":[101,"bcrt1q..."]}' http://127.0.0.1:8332/

# Mine 1 block to the wallet's next address (requires --create-wallet / --wallet)
curl -s -d '{"method":"generate","params":[1]}' http://127.0.0.1:8332/

# Get a BIP22 block template for an external miner
curl -s -d '{"method":"getblocktemplate","params":[]}' http://127.0.0.1:8332/

# Submit a solved block (hex-encoded)
curl -s -d '{"method":"submitblock","params":["<hex>"]}' http://127.0.0.1:8332/

# Show all options
./target/release/rbtc --help
```

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--network` | `mainnet` | `mainnet`, `testnet4`, `regtest`, `signet` |
| `--datadir` | `~/.rbtc` | Data directory for blockchain storage |
| `--addnode` | — | Additional seed node (repeatable) |
| `--connect` | — | Connect only to these nodes (disables DNS seeds) |
| `--listen-port` | `0` | Port to accept inbound connections (`0` = disabled) |
| `--rpc-port` | `8332` | JSON-RPC server port (`0` = disabled) |
| `--no-dns-seeds` | — | Disable automatic DNS seed lookup |
| `--max-outbound` | `8` | Maximum outbound peer connections |
| `--log-level` | `info` | Log level: `trace`, `debug`, `info`, `warn`, `error` |
| `--wallet` | — | Enable wallet (loads from datadir DB) |
| `--wallet-passphrase` | `""` | AES-256-GCM passphrase for xprv encryption |
| `--create-wallet` | — | Generate a fresh wallet, print the mnemonic, then run |
| `--prune` | `0` | Target disk budget for block data in MiB (`0` = keep all; min 550 when enabled) |
| `--mempool-size` | `300` | Maximum mempool size in MB; cheapest transactions are evicted when exceeded |
| `--utxo-cache` | `0` | UTXO hot-cache size in MB (`0` = unlimited, all UTXOs pre-loaded; >0 = lazy mode with RocksDB fallback) |

### Environment Variables

```bash
# Set log level via environment
RUST_LOG=debug ./target/release/rbtc

# Show only specific crate logs
RUST_LOG=rbtc_consensus=debug,rbtc_net=info,rbtc_mempool=debug ./target/release/rbtc
```

## JSON-RPC API

The node exposes a JSON-RPC 1.1 server on `127.0.0.1:8332` (configurable with `--rpc-port`).

```bash
# Query chain info
curl -s -d '{"method":"getblockchaininfo","params":[]}' http://127.0.0.1:8332/

# Get block at height 0
HASH=$(curl -s -d '{"method":"getblockhash","params":[0]}' http://127.0.0.1:8332/ | python3 -c "import sys,json; print(json.load(sys.stdin)['result'])")
curl -s -d "{\"method\":\"getblock\",\"params\":[\"$HASH\",1]}" http://127.0.0.1:8332/

# Wallet: generate a new address (requires --wallet / --create-wallet)
curl -s -d '{"method":"getnewaddress","params":["","bech32"]}' http://127.0.0.1:8332/

# Wallet: check balance
curl -s -d '{"method":"getbalance","params":[]}' http://127.0.0.1:8332/

# Wallet: send to an address (builds, signs, and broadcasts)
curl -s -d '{"method":"sendtoaddress","params":["bc1q...","0.001"]}' http://127.0.0.1:8332/
```

### Chain & Mempool Methods

| Method | Parameters | Returns |
|--------|-----------|---------|
| `getblockchaininfo` | — | chain, blocks, bestblockhash, chainwork |
| `getblockcount` | — | Current block height |
| `getblockhash` | `height` | Block hash at given height |
| `getblock` | `hash`, `verbosity` (0=hex, 1=json) | Block data |
| `getrawtransaction` | `txid`, `verbose` (bool) | Transaction from mempool or confirmed block (hex or json) |
| `getrawmempool` | — | List of txids sorted by fee rate |
| `sendrawtransaction` | `hex` | Validates and relays a raw transaction |

### Wallet Methods (require `--wallet` or `--create-wallet`)

| Method | Parameters | Returns |
|--------|-----------|---------|
| `getnewaddress` | `[label, type]` `type` = `legacy` / `bech32` / `bech32m` | New address string |
| `getbalance` | — | `{confirmed, unconfirmed, total}` in BTC |
| `listunspent` | `[minconf]` | Array of wallet UTXOs |
| `sendtoaddress` | `address, amount, [fee_rate]` | txid of broadcast transaction |
| `fundrawtransaction` | `hex, [{"feeRate": N}]` | `{hex, fee, changepos}` |
| `signrawtransactionwithwallet` | `hex` | `{hex, complete}` |
| `dumpprivkey` | `address` | WIF private key |
| `importprivkey` | `wif, [label]` | Imported address string |
| `getwalletinfo` | — | `{balance, unconfirmed_balance, txcount, keypoolsize}` |
### Mining Methods

| Method | Parameters | Returns |
|--------|-----------|---------|
| `getblocktemplate` | — | BIP22 template: `{version, previousblockhash, target, bits, height, coinbasevalue, transactions, …}` |
| `submitblock` | `hex` | `null` on success; error on invalid block |
| `generatetoaddress` | `nblocks, address` | Array of mined block hashes |
| `generate` | `nblocks` | Array of mined block hashes (wallet's address; requires `--wallet`) |
| `getmininginfo` | — | `{blocks, difficulty, networkhashps, pooledtx, chain}` |
| `getnetworkhashps` | `[nblocks]` | Estimated network hash rate (H/s) |
| `estimatesmartfee` | `[conf_target]` | `{feerate, blocks}` — fee rate in BTC/kB |

### Address Index Methods

| Method | Parameters | Returns |
|--------|-----------|---------|
| `getaddresstxids` | `address`, `[{"start":N,"end":M}]` | Array of txid hex strings ordered by block height |
| `getaddressutxos` | `address` | `[{txid, vout, value, height, confirmations}, …]` |
| `getaddressbalance` | `address` | `{balance, received}` in satoshis |


### PSBT Methods (BIP174)

| Method | Parameters | Returns |
|--------|-----------|---------|
| `createpsbt` | `[{txid,vout,sequence?},...]`, `{address:sats,...}`, `[locktime]` | PSBT base64 string |
| `walletprocesspsbt` | `psbt_b64` | `{psbt, complete}` |
| `finalizepsbt` | `psbt_b64` | `{hex, complete}` or `{psbt, complete:false}` |
| `combinepsbt` | `[psbt_b64, ...]` | Combined PSBT base64 string |
| `decodepsbt` | `psbt_b64` | Human-readable PSBT fields (tx, inputs, outputs) |
| `analyzepsbt` | `psbt_b64` | `{inputs: [{status, partial_sigs},...], estimated_complete}` |

## Implementation Notes

### Consensus Layer (`rbtc-consensus`)

- Block header validation: PoW check (`hash < target`), timestamp MTP/future checks, nBits validation
- Transaction validation: UTXO existence, coinbase maturity, script execution via `rbtc-script`
- Block validation: Merkle root, BIP141 witness commitment, block weight ≤ 4,000,000, sigops cost ≤ 80,000
- **Parallel script verification**: non-coinbase transactions verified concurrently with `rayon::par_iter`; sigops counted in a second parallel pass; thread pool scales to available CPU cores
- Difficulty adjustment: every 2016 blocks, clamped to ±4× (Bitcoin's actual algorithm)
- Block subsidy: 50 BTC halving every 210,000 blocks

### Script Engine (`rbtc-script`)

- ~180 opcodes implemented (all enabled opcodes + disabled op detection)
- Legacy, P2SH (BIP16), SegWit v0 (BIP141), Taproot (BIP341/342) execution paths
- BIP65 (OP_CHECKLOCKTIMEVERIFY) and BIP112 (OP_CHECKSEQUENCEVERIFY) support
- Taproot: key path spend + script path spend with Merkle branch verification

### Mempool (`rbtc-mempool`)

- `accept_tx()`: full consensus validation + fee-rate gate (min 1 sat/vbyte)
- Chained transactions: a mempool UTXO view merges chain outputs + in-mempool outputs
- `remove_confirmed()`: prunes confirmed transactions when a block is connected
- **BIP125 RBF**: conflict detection, fee-rate sufficiency check, ≤ 100 replacement limit
- **CPFP**: `ancestor_fee_rate` field + `ancestor_package()` recursive computation; `txids_by_fee_rate()` sorts by ancestor fee rate
- **Size cap eviction**: `with_max_vsize()` / `evict_below_fee_rate()`; controlled by `--mempool-size`

### P2P Layer (`rbtc-net`)

- 24-byte message header: magic + command + length + checksum (SHA256d)
- Async per-peer I/O tasks via tokio (read/write split)
- Bitcoin handshake: version → verack → sendheaders
- IBD: getheaders → headers → getdata(block) pipeline
- Automatic ping/pong heartbeat with stale connection detection
- Inbound TCP listener: accepts peers up to `max_inbound` (default 125)
- Peer cmd_tx registration: command channel properly associated before first message
- **BIP152 Compact Blocks**: `sendcmpct(mode=1)` sent after every handshake; `cmpctblock` / `getblocktxn` / `blocktxn` messages handled; `pending_compact` map tracks partial reconstructions
- **`feefilter` enforcement**: per-peer `fee_filter` field stored; `broadcast_tx_inv()` skips peers whose filter exceeds the transaction's fee rate
- **Peer ban scoring**: `ConnectedPeer::misbehavior`; `misbehave(peer_id, score)` disconnects and bans at score ≥ 100; `BanPeer` event persists the ban to RocksDB
- **`addr` relay**: timestamp-validated, dedup'd, forwarded to 2 peers (trickling); `getaddr` sent post-handshake
- **Connection manager**: 30 s reconnect loop fills outbound slots from `candidate_addrs`; `connecting_addrs` dedup guard; correct inbound/outbound count tracking

### HD Wallet (`rbtc-wallet`)

- **BIP39**: `Mnemonic::generate(12|24)` uses OS entropy via `rand::rngs::OsRng`; `to_seed(passphrase)` runs PBKDF2-HMAC-SHA512 (2048 iterations)
- **BIP32**: `ExtendedPrivKey::from_seed()` seeds with HMAC-SHA512("Bitcoin seed", seed); child derivation via `add_tweak(il_scalar)` for private keys and `add_exp_tweak` for public keys
- **Addresses**: P2PKH via Base58Check; P2WPKH via `bech32::segwit::encode(hrp, v0, hash160)`; P2TR via TapTweak (`tagged_hash("TapTweak", xonly)`) + `bech32m::encode(hrp, v1, output_key)`
- **Signing**: ECDSA for P2PKH/P2WPKH via `secp.sign_ecdsa(msg, &sk)`; Schnorr for P2TR key-path via `secp.sign_schnorr_with_aux_rand(&sighash_bytes, &tweaked_keypair, &random_aux_rand)`
- **Encryption**: xprv bytes encrypted with AES-256-GCM; key = PBKDF2-SHA256(passphrase, 16-byte salt, 100,000 iterations); stored as `salt || nonce || ciphertext+tag` in `CF_WALLET`
- **Incremental UTXO scanning**: After each block is connected, `Wallet::scan_block()` checks every TxOut's scriptPubKey against the in-memory `script_to_addr` map (O(outputs)); `remove_spent()` checks TxIn outpoints against `wallet.utxos`

### PSBT (`rbtc-psbt`)

- **Encoding**: `psbt\xff` magic + global map + per-input maps + per-output maps; Base64 wrapper via `base64 = "0.22"`
- **Creator**: `Psbt::create(tx)` strips all scriptSig/witness fields, producing a fully unsigned PSBT global map
- **Signer**: BIP143 P2WPKH sighash (hashPrevouts + hashSequence + hashOutputs) computed locally; legacy P2PKH sighash using a cloned unsigned transaction; ECDSA signatures DER-encoded with sighash-type byte appended
- **Combiner**: `combine()` merges partial signatures, UTXOs, and unknown fields using `or_insert` semantics — no duplicates, no overwrite
- **Finalizer**: single-sig P2WPKH → `final_script_witness = [sig, pubkey]`; single-sig P2PKH → `final_script_sig = <sig><pk>`
- **Extractor**: `extract_tx()` fails if any input lacks `final_script_sig` or `final_script_witness`
- **Wallet integration**: `walletprocesspsbt` uses `Wallet::key_for_script()` to look up the private key by scriptPubKey for each input

### Mining (`rbtc-miner`)

- **Block template**: `BlockTemplate::new()` receives chain tip info + mempool-selected transactions. `build_block(extra_nonce, time, nonce)` rebuilds the coinbase, computes TXIDs, constructs the Merkle tree, and returns a full `Block` candidate
- **Coinbase construction**: `build_coinbase()` encodes block height via BIP34 CScriptNum push (1–4 bytes, little-endian with sign extension), appends a 4-byte `extra_nonce` push and a 5-byte `"rbtc\0"` coinbase tag; total scriptSig is always 2–100 bytes
- **Transaction selection**: `TxSelector::select()` iterates `mempool.txids_by_fee_rate()` (descending fee-rate) and greedily includes transactions up to 3,996,000 WU, leaving headroom for the coinbase
- **PoW loop**: `mine_block()` pre-computes the Merkle root once per `extra_nonce` value. The inner loop iterates nonce ∈ `[0, 2³²)`, serialises only the 80-byte header, runs `double_sha256`, and calls `BlockHeader::meets_target()`. Timestamp is refreshed every 1,000,000 iterations. On nonce exhaustion, `extra_nonce` increments and the Merkle root is recomputed
- **Node integration**: `generatetoaddress` / `submitblock` send completed blocks via an `mpsc::UnboundedSender<Block>` channel; the node's event loop drains this channel alongside peer events and feeds blocks into the existing `handle_block()` path (validation → UTXO connect → persistence → mempool prune → wallet scan)

### Transaction & Address Index (`rbtc-storage` Phase 5)

- **TxIndexStore**: key = txid (32 bytes); value = block_hash (32 bytes) + tx_offset (4 bytes LE). `put` is called for every transaction when a block is connected; `remove` is called during chain reorganization. Zero-copy lookup: `get(txid)` returns `(Hash256, u32)` decoded from a fixed 36-byte value.
- **AddrIndexStore**: key = `[script_len: 1B][scriptPubKey: N B][height: 4B BE][tx_offset: 4B BE]`; value = txid (32 bytes). Big-endian encoding for height and tx_offset ensures lexicographic order matches chronological order. `iter_by_script(script)` issues a RocksDB prefix scan over `[script_len][scriptPubKey]`, collecting all matching entries. `remove` reconstructs the exact key from script + height + tx_offset during reorgs.
- **`getrawtransaction` (confirmed)**: looks up txid in `CF_TX_INDEX` → loads the block from `CF_BLOCK_DATA` → returns `transactions[tx_offset]`. Verbose mode includes `{blockhash, confirmations, vin, vout}`.
- **Address RPCs**: all three (`getaddresstxids`, `getaddressutxos`, `getaddressbalance`) decode the input address to scriptPubKey via `rbtc-wallet::address::address_to_script`, then prefix-scan `CF_ADDR_INDEX`. For UTXO/balance queries each candidate output is cross-checked against the in-memory `UtxoSet` to determine if it is still unspent.

### Block Pruning (`rbtc-storage` + `rbtc-node`)

- **`BlockStatus::Pruned` (4)**: new enum variant in `rbtc-consensus`; persisted as `status = 4` in `block_index` CF
- **`BlockStore::prune_blocks_below(max_height)`**: iterates all indexed blocks, deletes `CF_BLOCK_DATA` entries at heights ≤ `max_height`, updates status; skips already-pruned and absent entries
- **`--prune <MiB>`**: CLI flag; node calls `maybe_prune(current_height)` after each block is connected; pruning depth = 288 blocks (~2 days); headers, UTXO, tx_index, addr_index are never pruned
- **Impact**: `getrawtransaction` returns an error for pruned blocks; `getaddressbalance` / `getaddressutxos` continue to work (they use the UTXO set, not block data)

### Storage Layer (`rbtc-storage`)

Column families in RocksDB:

| Column Family | Contents |
|--------------|---------|
| `block_index` | `StoredBlockIndex` per block hash (header + height + chainwork + status) |
| `block_data` | Full serialized `Block` per block hash |
| `utxo` | `StoredUtxo` per `OutPoint` (36-byte key: txid+vout) |
| `chain_state` | Best block hash, height, chainwork |
| `undo` | Per-block spent UTXO list (enables reorg without resync) |
| `tx_index` | txid (32 B) → block_hash (32 B) + tx_offset (4 B LE); populated on block connect |
| `addr_index` | `[script_len][scriptPubKey][height BE][tx_offset BE]` → txid; prefix-scannable per address |
| `wallet` | Encrypted xprv, address→pubkey map, wallet UTXOs (JSON-encoded) |

### Restart Recovery

On startup, `load_chain_state()`:
1. Reads all entries from `block_index` CF, sorts by height
2. Calls `ChainState::insert_block_index()` for each — rebuilds `block_index` map and `active_chain` vec
3. Reads all entries from `utxo` CF — rebuilds in-memory `UtxoSet`

Typical startup time: sub-second for regtest/testnet, O(UTXO count) for mainnet.

### Chain Reorganization

When a competing chain with more cumulative work is detected, `reorganize_to(new_tip)`:
1. Walks back from the current tip to the fork point
2. Disconnects old blocks in reverse: removes outputs added, restores inputs from `undo` data
3. Connects new blocks forward: applies UTXO changes and persists new undo data

## Testing

### Unit Tests

```bash
cargo test --workspace
```

288 tests across all crates — all pass.

| Crate | Tests |
|-------|-------|
| `rbtc-primitives` | 60 |
| `rbtc-crypto` | 33 |
| `rbtc-consensus` | 27 |
| `rbtc-script` | 25 |
| `rbtc-storage` | 35 |
| `rbtc-mempool` | 4 |
| `rbtc-net` | 14 |
| `rbtc-psbt` | 6 |
| `rbtc-wallet` | 35 |
| `rbtc-miner` | 14 |
| `rbtc-node` | 9 |

### Integration Tests Against Bitcoin Core

Five integration tests in `crates/rbtc-net/tests/bitcoin_core_integration.rs` exercise the full P2P stack against a live Bitcoin Core node (v30.2.0 tested):

| Test | What it verifies |
|------|-----------------|
| `test_handshake_with_bitcoin_core` | Full version/verack handshake; peer UA contains "Satoshi" |
| `test_ping_pong` | Ping with fixed nonce, receive matching pong |
| `test_getheaders_from_genesis` | `getheaders` returns ≥1 decodable `BlockHeader` |
| `test_getdata_genesis_block` | Fetch genesis block, verify 1 coinbase tx, correct header |
| `test_sync_first_10_blocks` | Fetch + decode 10 consecutive blocks; verify coinbase outputs |

```bash
# 1. Start Bitcoin Core in regtest
mkdir -p /tmp/rbtc-regtest
cat > /tmp/rbtc-regtest/bitcoin.conf <<EOF
[regtest]
server=1
rpcuser=rbtctest
rpcpassword=rbtctest123
EOF
bitcoind -datadir=/tmp/rbtc-regtest -regtest -daemon

# 2. Create wallet and mine some blocks
bitcoin-cli -datadir=/tmp/rbtc-regtest -regtest createwallet test
ADDR=$(bitcoin-cli -datadir=/tmp/rbtc-regtest -regtest getnewaddress)
bitcoin-cli -datadir=/tmp/rbtc-regtest -regtest generatetoaddress 10 "$ADDR"

# 3. Run integration tests
cargo test -p rbtc-net --test bitcoin_core_integration -- --nocapture

# 4. Stop bitcoind when done
bitcoin-cli -datadir=/tmp/rbtc-regtest -regtest stop
```

### Coverage

```bash
cargo install cargo-llvm-cov

# Run and report
cargo llvm-cov --workspace --all-features --tests

# HTML report (open target/llvm-cov/html/index.html)
cargo llvm-cov --workspace --all-features --tests --html

# LCOV for CI
cargo llvm-cov --workspace --all-features --tests --lcov --output-path lcov.info
```

## Known Limitations

- No BIP37 bloom filtering
- Compact Blocks (BIP152) implemented but only tested on regtest; mainnet relay may have edge-case short-ID collisions
- Signet challenge validation not implemented
- Mempool eviction policy not yet implemented (no size cap)
- `sendrawtransaction` relay requires script-valid inputs (P2PKH etc.); bare scripts that rely on policy flags may differ from Bitcoin Core behavior
- Wallet imported keys (via `importprivkey`) are cached only for the current session; WIF keys are not re-derived from the master xprv
- `fundrawtransaction` uses a greedy (largest-first) coin selector; Branch-and-Bound selection is a future improvement
- CPU miner is single-threaded; no multi-core parallelism — suitable for regtest only; mainnet would require ASIC hardware
- `generatetoaddress` waits 50 ms between blocks so the node event loop can process the previous block before the next template is built; rapid generation of many blocks may leave some unprocessed
