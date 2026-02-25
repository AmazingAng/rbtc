# rbtc — Bitcoin Core in Rust

A from-scratch implementation of Bitcoin Core's core consensus and P2P networking layer, written in Rust.

## Architecture

```
rbtc/
├── crates/
│   ├── rbtc-primitives/   # Core data types: Block, Transaction, Script, hashes
│   ├── rbtc-crypto/       # SHA256d, RIPEMD-160, Merkle tree, ECDSA/Schnorr verification
│   ├── rbtc-script/       # Bitcoin Script interpreter (all opcodes + SegWit/Taproot)
│   ├── rbtc-consensus/    # PoW validation, difficulty adjustment, UTXO set, block/tx rules
│   ├── rbtc-storage/      # RocksDB-backed block index, UTXO store, chain state
│   ├── rbtc-net/          # P2P: wire protocol, peer management (tokio), IBD
│   └── rbtc-node/         # Main binary: node startup, sync loop
```

## Key Features

- **Full consensus rules**: PoW validation, difficulty adjustment (every 2016 blocks), transaction validation, block weight limits, sigops counting
- **SegWit support**: P2WPKH, P2WSH, witness commitment validation (BIP141/143)
- **Taproot support**: P2TR key path + script path verification (BIP340/341/342)
- **P2P protocol**: Complete Bitcoin wire protocol (version/verack/inv/getdata/block/tx/headers/getheaders)
- **Initial Block Download**: Headers-first IBD with batch block download
- **Persistent storage**: RocksDB-backed UTXO set, block index, and chain state
- **Multi-network**: mainnet, testnet4, regtest, signet

## Dependencies

| Crate | Purpose |
|-------|---------|
| `secp256k1 = "0.31"` | ECDSA + Schnorr (BIP340) signature verification |
| `sha2 = "0.10"` | SHA-256 |
| `ripemd = "0.2.0-rc.5"` | RIPEMD-160 |
| `rocksdb = "0.22"` | Persistent block/UTXO storage |
| `tokio = "1"` | Async P2P networking |
| `bytes = "1"` | Byte buffer utilities |
| `clap = "4"` | CLI argument parsing |
| `tracing` | Structured logging |

**Not used**: `bitcoin` crate — all protocol types and encoding are implemented from scratch.

## Usage

```bash
# Build
cargo build --release

# Run on mainnet (syncs from genesis)
./target/release/rbtc --network mainnet --datadir ~/.rbtc

# Run on regtest (local testing)
./target/release/rbtc --network regtest --no-dns-seeds --addnode 127.0.0.1:18444

# Run on testnet4
./target/release/rbtc --network testnet4

# Show help
./target/release/rbtc --help
```

### Environment Variables

```bash
# Set log level
RUST_LOG=debug ./target/release/rbtc

# Show only consensus-related logs
RUST_LOG=rbtc_consensus=debug,rbtc_net=info ./target/release/rbtc
```

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

### P2P Layer (`rbtc-net`)

- 24-byte message header: magic + command + length + checksum (SHA256d)
- Async per-peer I/O tasks via tokio (read/write split)
- Bitcoin handshake: version → verack → sendheaders
- IBD: getheaders → headers → getdata(block) pipeline
- Automatic ping/pong heartbeat with stale connection detection

## Testing and Coverage

Unit tests and coverage are provided for all library crates. Coverage is measured with `cargo-llvm-cov`.

```bash
# Install coverage tool (once)
cargo install cargo-llvm-cov

# Run all tests
cargo test --workspace

# Run tests and generate coverage report
cargo llvm-cov --workspace --all-features --tests

# HTML report (open target/llvm-cov/html/index.html)
cargo llvm-cov --workspace --all-features --tests --html

# LCOV for CI
cargo llvm-cov --workspace --all-features --tests --lcov --output-path lcov.info
```

The binary crate `rbtc-node` only tests library logic (e.g. config parsing); `main.rs` is excluded from coverage goals.

## Testing Against Bitcoin Core

The best way to validate correctness is to run in `regtest` mode alongside Bitcoin Core:

```bash
# Start Bitcoin Core in regtest
bitcoind -regtest -daemon

# Connect rbtc to it
./target/release/rbtc --network regtest --connect 127.0.0.1:18444
```

## Known Limitations

- Mempool not yet implemented (no transaction relay, fee estimation)
- No inbound connection support (outbound only)
- Block undo data not persisted (reorg recovery requires resync)
- No BIP37 bloom filtering
- No compact blocks (BIP152)
- Signet challenge validation not implemented
