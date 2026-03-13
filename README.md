# rbtc

A bit-by-bit Rust clone of [Bitcoin Core](https://github.com/bitcoin/bitcoin).

**No `bitcoin` crate** — every protocol type, encoding rule, validation check, and key derivation is re-implemented from scratch to match Bitcoin Core's exact behavior. The goal is byte-level compatibility: same UTXO serialization format, same P2P messages, same script interpreter semantics, same mempool policy.

**91k lines of Rust / 1,905 tests / syncs mainnet to 925k+ blocks.**

## Architecture

11 crates mirroring Bitcoin Core's module boundaries:

```
rbtc/
├── rbtc-primitives   # Block, Transaction, Script, Hash256, OutPoint, compact-size codec
├── rbtc-crypto       # SHA256d, RIPEMD160, HMAC, SipHash, MuHash, ECDSA/Schnorr, sighash
├── rbtc-script       # Script interpreter: ~180 opcodes, P2SH, SegWit v0, Taproot (BIP341/342)
├── rbtc-consensus    # PoW, difficulty, UTXO set, CheckBlock/CheckTransaction, BIP30/34/66/68
├── rbtc-storage      # RocksDB: block index, UTXO (compressed Coin format), undo, chain state
├── rbtc-mempool      # Policy: RBF (BIP125), CPFP, package relay, fee estimator, orphan pool
├── rbtc-net          # P2P: v1/v2 transport, AddrMan, compact blocks (BIP152), headers sync
├── rbtc-wallet       # HD wallet: BIP32/39/44, descriptors, coin selection (BnB/CoinGrinder/Knapsack/SRD)
├── rbtc-miner        # Block template (BIP22/23), tx selection, sigop budget, CPU PoW
├── rbtc-psbt         # BIP174/370/371: full role pipeline (Creator→Extractor), Taproot fields
└── rbtc-node         # Binary: node event loop, JSON-RPC server (60+ methods), config, IBD
```

### Bitcoin Core Alignment

The implementation is validated through 39 rounds of crate-by-crate audits comparing rbtc against Bitcoin Core's C++ source. Key areas of bit-level alignment:

| Area | Details |
|------|---------|
| **UTXO serialization** | Bitcoin Core's exact `Coin` format: `VARINT(height*2+coinbase) + CompressAmount + CompressScript` with base-128 MSB-first VARINTs |
| **Script interpreter** | All flag combinations (P2SH, DERSIG, WITNESS, NULLDUMMY, CLTV, CSV, TAPROOT); `OP_CODESEPARATOR` opcode index tracking matches Core's `for(; pc < pend; ++opcode_pos)` |
| **Sighash computation** | Legacy, BIP143 (SegWit v0), BIP341 (Taproot) — epoch byte, key_version, annex, ext_flag, codesep_pos |
| **Sigops cost** | Three-component: `legacy×4 + P2SH×4 + witness×1` (matching `GetTransactionSigOpCost()`) |
| **Mempool policy** | RBF rules 1-6, CPFP ancestor scoring, min relay fee 100 sat/kvB, orphan pool (100 max, 20min expire), rolling min fee with exponential decay |
| **P2P wire format** | 24-byte header, compact-size, all message types; BIP152 compact blocks (mode 1+2); BIP324 v2 transport (ChaCha20-Poly1305, HKDF key derivation, rekey at 2^24) |
| **AddrMan** | SipHash bucketing (new 1024×64, tried 256×64), ASMAP bytecode interpreter for AS-aware bucketing |
| **Difficulty** | `GetNextWorkRequired()` with 2016-block retarget, ±4× clamp, testnet4 20-min exception |
| **Block validation** | CVE-2012-2459 (duplicate tx mutation), CVE-2018-17144 (duplicate inputs), CVE-2010-5139 (negative output), BIP30/34 coinbase checks |
| **Coin selection** | BnB → CoinGrinder (high fee) → Knapsack → SRD → largest-first greedy; effective value filtering; per-type input weights |
| **PSBT** | v0 + v2 (BIP370), Taproot fields (BIP371), TAP_TREE depth/leaf validation, control block size check (33+32k) |

## Quick Start

```bash
# Build
cargo build --release

# Sync mainnet from genesis
./target/release/rbtc

# Regtest with local bitcoind
./target/release/rbtc --network regtest --no-dns-seeds --addnode 127.0.0.1:18444

# Create wallet and mine
./target/release/rbtc --network regtest --create-wallet --wallet-passphrase "secret"
curl -sd '{"method":"generatetoaddress","params":[101,"bcrt1q..."]}' http://127.0.0.1:8332/
```

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--network` | `mainnet` | `mainnet`, `testnet4`, `regtest`, `signet` |
| `--datadir` | `~/.rbtc` | Data directory |
| `--addnode` | — | Seed node (repeatable) |
| `--connect` | — | Connect only to these nodes |
| `--listen-port` | `0` | Inbound port (`0` = disabled) |
| `--rpc-port` | `8332` | JSON-RPC port (`0` = disabled) |
| `--no-dns-seeds` | — | Disable DNS seeds |
| `--max-outbound` | `8` | Max outbound peers |
| `--wallet` | — | Enable wallet |
| `--create-wallet` | — | Generate new wallet |
| `--wallet-passphrase` | `""` | AES-256-GCM encryption passphrase |
| `--prune` | `0` | Block data budget in MiB (min 550) |
| `--mempool-size` | `300` | Mempool cap in MB |
| `--utxo-cache` | `0` | UTXO cache in MB (`0` = unlimited) |
| `--reindex` | — | Full block re-validation from genesis |
| `--reindex-chainstate` | — | UTXO-only replay |
| `--no-persist-mempool` | — | Disable mempool.dat save/load |

## JSON-RPC API

60+ methods matching Bitcoin Core's RPC interface. All methods accept JSON-RPC 1.1 on `127.0.0.1:8332`.

### Blockchain

| Method | Description |
|--------|-------------|
| `getblockchaininfo` | Chain, blocks, bestblockhash, difficulty, chainwork, softfork status |
| `getblockcount` | Current tip height |
| `getblockhash` | Hash at height |
| `getblock` | Block data (verbosity 0=hex, 1=json) |
| `getblockheader` | Header data |
| `gettxout` | UTXO lookup by outpoint |
| `gettxoutsetinfo` | UTXO set statistics |
| `verifychain` | Verify chain integrity |
| `getdifficulty` | Current difficulty |
| `getbestblockhash` | Tip block hash |

### Mempool

| Method | Description |
|--------|-------------|
| `getrawmempool` | Txids sorted by fee rate |
| `getmempoolinfo` | Size, bytes, usage, fee stats |
| `getmempoolentry` | Entry details (fees, size, ancestors) |
| `sendrawtransaction` | Validate and relay raw tx |
| `testmempoolaccept` | Dry-run mempool acceptance |
| `prioritisetransaction` | Adjust fee delta |

### Transactions

| Method | Description |
|--------|-------------|
| `getrawtransaction` | Tx from mempool or chain (hex/json) |
| `decoderawtransaction` | Decode raw tx hex |
| `decodescript` | Decode script hex |
| `createrawtransaction` | Build unsigned tx |
| `signrawtransactionwithkey` | Sign with provided WIF keys |

### Wallet

| Method | Description |
|--------|-------------|
| `getnewaddress` | Generate address (legacy/bech32/bech32m) |
| `getbalance` | Confirmed + unconfirmed balance |
| `listunspent` | Wallet UTXOs |
| `sendtoaddress` | Build, sign, broadcast |
| `sendmany` | Multi-output send |
| `listtransactions` | Transaction history with pagination |
| `gettransaction` | Detailed tx info |
| `fundrawtransaction` | Add inputs + change |
| `signrawtransactionwithwallet` | Sign with wallet keys |
| `dumpprivkey` / `importprivkey` | WIF export/import |
| `getwalletinfo` | Balance, txcount, keypool |
| `walletlock` / `walletpassphrase` | Encryption control |
| `lockunspent` / `listlockunspent` | Coin lock management |
| `getaddressinfo` | Address metadata |

### Mining

| Method | Description |
|--------|-------------|
| `getblocktemplate` | BIP22/23 template |
| `submitblock` | Submit solved block |
| `generatetoaddress` / `generate` | Regtest mining |
| `getmininginfo` | Mining stats |
| `getnetworkhashps` | Network hash rate |
| `estimatesmartfee` | Fee rate estimation |

### Network

| Method | Description |
|--------|-------------|
| `getnetworkinfo` | Protocol version, connections, local addresses |
| `getpeerinfo` | Connected peer details |
| `getconnectioncount` | Peer count |
| `ping` | Request ping from all peers |
| `addnode` / `disconnectnode` | Peer management |

### PSBT

| Method | Description |
|--------|-------------|
| `createpsbt` | Create unsigned PSBT |
| `walletprocesspsbt` | Add wallet signatures |
| `finalizepsbt` | Finalize → raw tx |
| `combinepsbt` | Merge partial PSBTs |
| `decodepsbt` | Human-readable decode |
| `analyzepsbt` | Completion analysis |

### Descriptors

| Method | Description |
|--------|-------------|
| `getdescriptorinfo` | Parse descriptor, compute checksum |
| `deriveaddresses` | Derive addresses from descriptor |

### Address Index

| Method | Description |
|--------|-------------|
| `getaddresstxids` | Transaction history by address |
| `getaddressutxos` | UTXOs by address |
| `getaddressbalance` | Balance by address |

## Dependencies

| Crate | Purpose |
|-------|---------|
| `secp256k1` | ECDSA + Schnorr (BIP340) |
| `sha2` | SHA-256 |
| `ripemd` | RIPEMD-160 |
| `hmac` | HMAC-SHA512 (BIP32) |
| `pbkdf2` | BIP39 seeds + wallet encryption (100k iterations) |
| `bip39` | Mnemonic generation |
| `bech32` | bech32/bech32m address encoding |
| `bs58` | Base58Check (P2PKH, WIF) |
| `aes-gcm` | AES-256-GCM wallet encryption |
| `rocksdb` | Persistent storage |
| `tokio` | Async networking + RPC |
| `axum` | JSON-RPC HTTP server |
| `rayon` | Parallel script verification |
| `siphasher` | SipHash for BIP152 + AddrMan |

**Not used**: `bitcoin` crate — everything is implemented from scratch.

## Testing

```bash
cargo test --workspace    # 1,905 tests, all pass
```

| Crate | Tests |
|-------|------:|
| rbtc-primitives | 144 |
| rbtc-crypto | 139 |
| rbtc-script | 84 |
| rbtc-consensus | 133 |
| rbtc-storage | 101 |
| rbtc-mempool | 176 |
| rbtc-net | 257 |
| rbtc-wallet | 146 |
| rbtc-miner | 88 |
| rbtc-psbt | 240 |
| rbtc-node | 397 |

### Integration Tests

`crates/rbtc-net/tests/bitcoin_core_integration.rs` tests the full P2P stack against a live Bitcoin Core node:

```bash
# Start bitcoind in regtest
bitcoind -regtest -daemon
bitcoin-cli -regtest createwallet test
bitcoin-cli -regtest generatetoaddress 10 $(bitcoin-cli -regtest getnewaddress)

# Run integration tests
cargo test -p rbtc-net --test bitcoin_core_integration -- --nocapture
```

## Storage

RocksDB column families matching Bitcoin Core's LevelDB layout:

| CF | Contents |
|----|---------|
| `block_index` | `StoredBlockIndex` (header + height + chainwork + status as u32 bitflags) |
| `block_data` | Full serialized blocks |
| `utxo` | `StoredUtxo` in Bitcoin Core's compressed Coin format |
| `chain_state` | Best block, height, chainwork (U256) |
| `undo` | Per-block spent coins for reorg |
| `tx_index` | txid → (block_hash, offset) |
| `addr_index` | scriptPubKey prefix scan → txids |
| `wallet` | Encrypted xprv, addresses, UTXOs |

UTXO values are XOR-obfuscated with an 8-byte key (matching Bitcoin Core's `CDBWrapper`).

## License

MIT
