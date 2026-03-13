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

The detailed development roadmap has been moved to `ROADMAP.md`.

- See `ROADMAP.md` for **Phase 1 → Phase 8** milestones and technical deliverables.
- This README focuses on architecture, usage, API, and implementation notes.

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

- `accept_tx()`: full consensus validation + fee-rate gate (min 1 sat/vbyte) + BIP68 `CheckSequenceLocks` enforcement
- Chained transactions: a mempool UTXO view merges chain outputs + in-mempool outputs
- `remove_confirmed()`: prunes confirmed transactions when a block is connected
- **BIP125 RBF**: conflict detection, fee-rate sufficiency, Rules 1 (no new unconfirmed inputs) & 4 (≤ 100 eviction candidates), descendant eviction
- **CPFP**: `ancestor_fee_rate` field + `ancestor_package()` recursive computation; `txids_by_fee_rate()` sorts by ancestor fee rate
- **Size cap eviction**: `with_max_vsize()` / `evict_below_fee_rate()`; controlled by `--mempool-size`
- **Rolling minimum fee rate**: exponential decay (halving every 10 s) prevents re-admission of recently evicted low-fee transactions
- **wtxid tracking**: each `MempoolEntry` stores both txid and wtxid; `wtxid_index` provides O(1) witness-aware lookup
- **IsWitnessStandard**: P2WSH stack limits (100 items, 80 bytes each, 3600-byte script), P2WPKH witness count, taproot annex rejection
- **Fee estimation**: `CBlockPolicyEstimator`-style bucket-based estimator tracking confirmation targets

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
- **Finalizer**: P2WPKH → `final_script_witness = [sig, pubkey]`; P2PKH → `final_script_sig = <sig><pk>`; P2TR key-path → `final_script_witness = [schnorr_sig]`; P2TR script-path → `final_script_witness = [sig, script, control_block]`; P2WSH/P2SH multisig → ordered M-of-N signatures with `OP_0` dummy
- **BIP370 (PSBT v2)**: global fields `tx_version`, `fallback_locktime`, `input_count`, `output_count`, `tx_modifiable`; per-input `previous_txid`, `output_index`, `sequence`; per-output `amount`, `script`
- **BIP371 (Taproot)**: `TAP_KEY_SIG`, `TAP_SCRIPT_SIG`, `TAP_LEAF_SCRIPT`, `TAP_BIP32_DERIVATION`, `TAP_INTERNAL_KEY`, `TAP_MERKLE_ROOT` for inputs; `TAP_INTERNAL_KEY`, `TAP_TREE`, `TAP_BIP32_DERIVATION` for outputs
- **Extractor**: `extract_tx()` fails if any input lacks `final_script_sig` or `final_script_witness`
- **Wallet integration**: `walletprocesspsbt` uses `Wallet::key_for_script()` to look up the private key by scriptPubKey for each input

### Mining (`rbtc-miner`)

- **Block template**: `BlockTemplate::new()` receives chain tip info + mempool-selected transactions. `build_block(extra_nonce, time, nonce)` rebuilds the coinbase, computes TXIDs, constructs the Merkle tree, and returns a full `Block` candidate
- **Coinbase construction**: `build_coinbase()` encodes block height via BIP34 CScriptNum push (1–4 bytes, little-endian with sign extension), appends a 4-byte `extra_nonce` push and a 5-byte `"rbtc\0"` coinbase tag; total scriptSig is always 2–100 bytes
- **Transaction selection**: `TxSelector::select()` uses CPFP-aware ancestor-package scoring with a max-heap; enforces block weight limit (3,996,000 WU), sigop budget (80,000 - 400 reserved for coinbase), and `IsFinalTx()` locktime checks
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

569 tests across all crates — all pass.

| Crate | Tests |
|-------|-------|
| `rbtc-primitives` | 50 |
| `rbtc-crypto` | 17 |
| `rbtc-consensus` | 102 |
| `rbtc-script` | 27 |
| `rbtc-storage` | 39 |
| `rbtc-mempool` | 48 |
| `rbtc-net` | 15 |
| `rbtc-psbt` | 19 |
| `rbtc-wallet` | 72 |
| `rbtc-miner` | 2 |
| `rbtc-node` | 41 |

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

### Consensus / Validation

- **No automatic best-chain reorg**: the node follows the longest chain it receives sequentially but does not automatically switch to a higher-work alternative branch discovered later; reorgs only trigger via `invalidateblock`/`reconsiderblock` RPC
- **Block failure flags**: once a block is marked invalid it cannot be automatically reconsidered; no fine-grained `BLOCK_FAILED_VALID` / `BLOCK_FAILED_CHILD` tracking
- **BIP9 deployment not wired into validation**: `script_flags_for_block()` uses hardcoded activation heights rather than querying the BIP9 state machine at runtime
- **Pre-BIP141 block size limit**: only block weight is checked (post-SegWit); no explicit 1 MB serialized-size limit for legacy blocks
- **TestBlockValidity**: miner does not call a validation pass on the assembled template before returning it

### Networking

- **No address manager (addrman)**: peer addresses stored in a simple queue; no new/tried table bucketing or Sybil-resistance heuristics
- **No headers-first sync state machine**: IBD downloads headers then blocks linearly; no PRESYNC/SYNCING/DONE phases, no stall detection or peer reassignment
- **No block download stall detection**: no `mapBlocksInFlight` tracking; if a peer stops sending blocks the node waits indefinitely
- **BIP152 compact blocks**: only high-bandwidth mode 1; no low-bandwidth mode 2 announcement support
- **BIP324 v2 encrypted transport**: not implemented; all connections are plaintext v1
- **No connection type distinction**: no block-relay-only, feeler, or addr-fetch connection categories
- **Orphan DoS protections**: orphan pool exists but lacks per-peer scoring and ancestor limits

### Mempool

- **Ancestor/descendant vsize limits**: enforces count limits (25) but not cumulative vsize limits (101,025 vB)
- **Bare multisig policy**: `NonStandardReason::BareMultisig` enum defined but the check is never executed
- **PrioritiseTransaction / mapDeltas**: no RPC to override fee-rate priority for specific transactions
- **Coinbase maturity in mempool**: `spends_coinbase` flag is tracked but immature coinbase spends are not rejected at the mempool layer (relies on consensus)
- **nLockTime absolute check**: mempool validates BIP68 relative locks but does not check absolute `nLockTime` finality
- **Package vsize limits**: `accept_package()` has no per-package size cap (BIP331)

### Mining

- **GBT fields**: `getblocktemplate` is missing `default_witness_commitment`, `depends`, `vbrequired`, `vbavailable` fields (partial BIP22 compliance)
- **ComputeBlockVersion**: block version hardcoded to `0x20000000`; no softfork signaling via versionbits
- **Testnet4 20-min exception**: no minimum-difficulty fallback block after 20 minutes of inactivity
- **BIP94 timewarp check**: `GetMinimumTime` not enforced at difficulty adjustment boundaries
- **Long-poll**: GBT returns `longpollid` but does not implement server-side waiting
- CPU miner is single-threaded — suitable for regtest only

### Wallet

- **Watch-only mode**: no xpub-only wallet creation (needed for hardware wallet integration)
- **Unconfirmed UTXO spending**: coin selection only picks confirmed UTXOs; cannot spend own change in consecutive transactions
- **BIP49 (P2SH-P2WPKH)**: purpose-49 derivation path not supported
- **RBF / fee bumping**: no `bumpfee` RPC or replacement tracking
- **BIP44 accounts**: hardcoded to account index 0; no multi-account segregation
- **Coin selection**: BnB + greedy only; no Knapsack or Single Random Draw algorithms
- **Transaction rescan**: no `rescanblockchain` equivalent for imported keys
- **Multi-SIGHASH**: signing always uses `SIGHASH_ALL`

### PSBT

- **Taproot script-path signing**: signer handles P2TR key-path only; script-path signing must be done externally
- **Global XPUB field** (0x01): BIP174 recommended field not stored
- **Preimage fields**: RIPEMD160/SHA256/HASH160/HASH256 (0x0A–0x0D) not implemented
- **Duplicate key detection**: silently overwrites during deserialization
- **Combiner consistency**: checks input/output counts but not transaction hash match

### Storage

- **No flat-file block storage**: all block data in RocksDB (deliberate architectural choice); incompatible with Bitcoin Core's `blk*.dat` / `rev*.dat` format
- **Block status enum**: single `u8` status field; no `BLOCK_VALID_*` / `BLOCK_HAVE_*` flag decomposition
- **UTXO compression**: amounts and scripts stored uncompressed; no `CompressAmount` / `TxOutCompression`
- **Undo data checksums**: no framing or corruption detection on undo records
- **Reindex**: no mechanism to rebuild the block index from stored blocks
- **Process lock file**: multiple node instances can open the same datadir concurrently

### Crypto

- **Batch signature verification**: signatures verified one at a time; no libsecp256k1 batch API
- **Message signing (BIP191)**: no `SignMessage` / `VerifyMessage` support
- **Signature recovery / compact format**: no `SignCompact` / `RecoverCompact`

### Other

- No BIP37 bloom filtering
- Compact Blocks (BIP152) only tested on regtest; mainnet relay may have edge-case short-ID collisions
- `generatetoaddress` waits 50 ms between blocks so the node event loop can process each block before the next template is built
