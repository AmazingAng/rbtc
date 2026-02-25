# rbtc — Bitcoin Core in Rust

A from-scratch implementation of Bitcoin Core's consensus, P2P networking, and HD wallet, written in Rust. No `bitcoin` crate — all protocol types, encoding, validation, and key derivation are implemented independently.

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
│   └── rbtc-node/         # Binary: node loop, JSON-RPC server, config
```

## Key Features

### Phase 1 — Core Foundation
- **Full consensus rules**: PoW validation, difficulty adjustment (every 2016 blocks), transaction validation, block weight limits, sigops counting
- **SegWit support**: P2WPKH, P2WSH, witness commitment validation (BIP141/143)
- **Taproot support**: P2TR key path + script path verification (BIP340/341/342)
- **P2P protocol**: Complete Bitcoin wire protocol (version/verack/inv/getdata/block/tx/headers/getheaders/ping/pong)
- **Initial Block Download**: Headers-first IBD with batch block download (16 blocks in flight)
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
| `getrawtransaction` | `txid` | Transaction from mempool (hex or json) |
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

## Implementation Notes

### Consensus Layer (`rbtc-consensus`)

- Block header validation: PoW check (`hash < target`), timestamp MTP/future checks, nBits validation
- Transaction validation: UTXO existence, coinbase maturity, script execution via `rbtc-script`
- Block validation: Merkle root, BIP141 witness commitment, block weight ≤ 4,000,000, sigops cost ≤ 80,000
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
- `txids_by_fee_rate()`: sorted list for future block template construction

### P2P Layer (`rbtc-net`)

- 24-byte message header: magic + command + length + checksum (SHA256d)
- Async per-peer I/O tasks via tokio (read/write split)
- Bitcoin handshake: version → verack → sendheaders
- IBD: getheaders → headers → getdata(block) pipeline
- Automatic ping/pong heartbeat with stale connection detection
- Inbound TCP listener: accepts peers up to `max_inbound` (default 125)
- Peer cmd_tx registration: command channel properly associated before first message

### HD Wallet (`rbtc-wallet`)

- **BIP39**: `Mnemonic::generate(12|24)` uses OS entropy via `rand::rngs::OsRng`; `to_seed(passphrase)` runs PBKDF2-HMAC-SHA512 (2048 iterations)
- **BIP32**: `ExtendedPrivKey::from_seed()` seeds with HMAC-SHA512("Bitcoin seed", seed); child derivation via `add_tweak(il_scalar)` for private keys and `add_exp_tweak` for public keys
- **Addresses**: P2PKH via Base58Check; P2WPKH via `bech32::segwit::encode(hrp, v0, hash160)`; P2TR via TapTweak (`tagged_hash("TapTweak", xonly)`) + `bech32m::encode(hrp, v1, output_key)`
- **Signing**: ECDSA for P2PKH/P2WPKH via `secp.sign_ecdsa(msg, &sk)`; Schnorr for P2TR key-path via `secp.sign_schnorr_with_aux_rand(&sighash_bytes, &tweaked_keypair, &random_aux_rand)`
- **Encryption**: xprv bytes encrypted with AES-256-GCM; key = PBKDF2-SHA256(passphrase, 16-byte salt, 100,000 iterations); stored as `salt || nonce || ciphertext+tag` in `CF_WALLET`
- **Incremental UTXO scanning**: After each block is connected, `Wallet::scan_block()` checks every TxOut's scriptPubKey against the in-memory `script_to_addr` map (O(outputs)); `remove_spent()` checks TxIn outpoints against `wallet.utxos`

### Storage Layer (`rbtc-storage`)

Column families in RocksDB:

| Column Family | Contents |
|--------------|---------|
| `block_index` | `StoredBlockIndex` per block hash (header + height + chainwork + status) |
| `block_data` | Full serialized `Block` per block hash |
| `utxo` | `StoredUtxo` per `OutPoint` (36-byte key: txid+vout) |
| `chain_state` | Best block hash, height, chainwork |
| `undo` | Per-block spent UTXO list (enables reorg without resync) |
| `tx_index` | Reserved for future transaction index |
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

201 tests across all crates — all pass.

| Crate | Tests |
|-------|-------|
| `rbtc-primitives` | 60 |
| `rbtc-crypto` | 33 |
| `rbtc-consensus` | 27 |
| `rbtc-script` | 25 |
| `rbtc-storage` | 11 |
| `rbtc-mempool` | 4 |
| `rbtc-net` | 6 |
| `rbtc-wallet` | 35 |

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

- No transaction index (`tx_index` CF reserved but not populated; `getrawtransaction` only searches the mempool)
- No BIP37 bloom filtering
- No compact blocks (BIP152)
- Signet challenge validation not implemented
- Mempool eviction policy not yet implemented (no size cap)
- `sendrawtransaction` relay requires script-valid inputs (P2PKH etc.); bare scripts that rely on policy flags may differ from Bitcoin Core behavior
- Wallet imported keys (via `importprivkey`) are cached only for the current session; WIF keys are not re-derived from the master xprv
- `fundrawtransaction` uses a greedy (largest-first) coin selector; Branch-and-Bound selection is a future improvement
