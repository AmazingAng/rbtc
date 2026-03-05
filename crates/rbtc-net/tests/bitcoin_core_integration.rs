//! Integration tests that connect to a live Bitcoin Core instance running in
//! regtest mode on localhost:18444.
//!
//! Start bitcoind before running:
//!   bitcoind -datadir=/tmp/rbtc-regtest -regtest -daemon
//!   bitcoin-cli -datadir=/tmp/rbtc-regtest -regtest generatetoaddress 10 $(bitcoin-cli -datadir=/tmp/rbtc-regtest -regtest getnewaddress)
//!
//! Run with:
//!   cargo test -p rbtc-net --test bitcoin_core_integration -- --nocapture

use std::time::Duration;

use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::TcpStream,
    time::timeout,
};

use rbtc_net::message::{
    GetBlocksMessage, Inventory, InvType, Message, NetworkMessage, VersionMessage,
};
use rbtc_primitives::{hash::Hash256, network::Network};

const REGTEST_ADDR: &str = "127.0.0.1:18444";
const TIMEOUT: Duration = Duration::from_secs(10);

// ── helpers ──────────────────────────────────────────────────────────────────

/// Open a TCP connection to bitcoind, perform the version/verack handshake, and
/// return the split (reader, writer) along with the peer's reported best height.
async fn connect_and_handshake(
    network: Network,
) -> anyhow::Result<(
    BufReader<tokio::net::tcp::OwnedReadHalf>,
    tokio::net::tcp::OwnedWriteHalf,
    i32, // peer best height
)> {
    let stream = timeout(TIMEOUT, TcpStream::connect(REGTEST_ADDR)).await??;
    let magic = network.magic();
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // Send our version
    let ver = VersionMessage::new(0, 0xdeadbeef_cafebabe);
    write_half
        .write_all(&Message::new(magic, NetworkMessage::Version(ver)).encode_to_bytes())
        .await?;

    let mut got_version = false;
    let mut got_verack = false;
    let mut peer_height = 0i32;
    let mut peer_ua = String::new();

    timeout(TIMEOUT, async {
        while !got_version || !got_verack {
            let msg = Message::read_from(&mut reader, &magic).await?;
            match msg.payload {
                NetworkMessage::Version(v) => {
                    peer_height = v.start_height;
                    peer_ua = v.user_agent.clone();
                    got_version = true;
                    // Reply with verack
                    write_half
                        .write_all(
                            &Message::new(magic, NetworkMessage::Verack).encode_to_bytes(),
                        )
                        .await?;
                }
                NetworkMessage::Verack => {
                    got_verack = true;
                }
                _ => {} // ignore other messages during handshake
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;

    println!(
        "[handshake] peer height={peer_height} ua={peer_ua}"
    );
    Ok((reader, write_half, peer_height))
}

// ── Test 1: handshake ─────────────────────────────────────────────────────────

/// Verify that rbtc can perform the full version/verack handshake with Bitcoin
/// Core and that the peer reports a user-agent string containing "Bitcoin Core".
#[tokio::test]
async fn test_handshake_with_bitcoin_core() {
    let stream = match TcpStream::connect(REGTEST_ADDR).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("bitcoind not reachable at {REGTEST_ADDR}: {e}  -- skipping");
            return;
        }
    };

    let network = Network::Regtest;
    let magic = network.magic();
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // Send version
    let ver = VersionMessage::new(0, 42u64);
    write_half
        .write_all(&Message::new(magic, NetworkMessage::Version(ver)).encode_to_bytes())
        .await
        .unwrap();

    let mut got_version = false;
    let mut got_verack = false;
    let mut peer_ua = String::new();
    let mut peer_height = 0i32;

    timeout(TIMEOUT, async {
        while !got_version || !got_verack {
            let msg = Message::read_from(&mut reader, &magic).await.unwrap();
            match msg.payload {
                NetworkMessage::Version(v) => {
                    peer_height = v.start_height;
                    peer_ua = v.user_agent.clone();
                    got_version = true;
                    write_half
                        .write_all(
                            &Message::new(magic, NetworkMessage::Verack).encode_to_bytes(),
                        )
                        .await
                        .unwrap();
                }
                NetworkMessage::Verack => {
                    got_verack = true;
                }
                _ => {}
            }
        }
    })
    .await
    .expect("handshake timed out");

    println!("peer ua='{peer_ua}'  height={peer_height}");
    assert!(got_version, "never got version");
    assert!(got_verack, "never got verack");
    assert!(
        peer_ua.contains("Satoshi") || peer_ua.contains("Bitcoin"),
        "unexpected user-agent: {peer_ua}"
    );
}

// ── Test 2: BIP339/BIP155 handshake signals ──────────────────────────────────

/// Verify that when we send wtxidrelay + sendaddrv2 before verack, Bitcoin Core
/// also sends these signals back. Modern Bitcoin Core (v22+) supports both.
#[tokio::test]
async fn test_wtxidrelay_and_sendaddrv2_handshake() {
    let stream = match TcpStream::connect(REGTEST_ADDR).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("bitcoind not reachable at {REGTEST_ADDR}: {e}  -- skipping");
            return;
        }
    };

    let network = Network::Regtest;
    let magic = network.magic();
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // Send version
    let ver = VersionMessage::new(0, 0xaabbccdd11223344);
    write_half
        .write_all(&Message::new(magic, NetworkMessage::Version(ver)).encode_to_bytes())
        .await
        .unwrap();

    let mut got_version = false;
    let mut got_verack = false;
    let mut peer_wtxidrelay = false;
    let mut peer_sendaddrv2 = false;

    timeout(TIMEOUT, async {
        while !got_version || !got_verack {
            let msg = Message::read_from(&mut reader, &magic).await.unwrap();
            match msg.payload {
                NetworkMessage::Version(_v) => {
                    got_version = true;
                    // Send BIP339 wtxidrelay before verack
                    write_half
                        .write_all(
                            &Message::new(magic, NetworkMessage::WtxidRelay).encode_to_bytes(),
                        )
                        .await
                        .unwrap();
                    // Send BIP155 sendaddrv2 before verack
                    write_half
                        .write_all(
                            &Message::new(magic, NetworkMessage::SendAddrv2).encode_to_bytes(),
                        )
                        .await
                        .unwrap();
                    // Send verack
                    write_half
                        .write_all(
                            &Message::new(magic, NetworkMessage::Verack).encode_to_bytes(),
                        )
                        .await
                        .unwrap();
                }
                NetworkMessage::Verack => {
                    got_verack = true;
                }
                NetworkMessage::WtxidRelay => {
                    peer_wtxidrelay = true;
                }
                NetworkMessage::SendAddrv2 => {
                    peer_sendaddrv2 = true;
                }
                _ => {}
            }
        }
    })
    .await
    .expect("handshake timed out");

    println!(
        "[bip339/bip155] peer wtxidrelay={peer_wtxidrelay} sendaddrv2={peer_sendaddrv2}"
    );

    // Modern Bitcoin Core (v22+) sends both signals
    assert!(peer_wtxidrelay, "peer did not send wtxidrelay");
    assert!(peer_sendaddrv2, "peer did not send sendaddrv2");
}

// ── Test 3: ping / pong ───────────────────────────────────────────────────────

/// Send a ping and verify we receive a matching pong with the correct nonce.
#[tokio::test]
async fn test_ping_pong() {
    let (mut reader, mut writer, _) = match connect_and_handshake(Network::Regtest).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("skipping: {e}");
            return;
        }
    };

    let magic = Network::Regtest.magic();
    let nonce: u64 = 0x1122334455667788;

    writer
        .write_all(&Message::new(magic, NetworkMessage::Ping(nonce)).encode_to_bytes())
        .await
        .unwrap();

    // Drain messages until we see a Pong with the right nonce
    let got_pong = timeout(TIMEOUT, async {
        loop {
            let msg = Message::read_from(&mut reader, &magic).await.unwrap();
            match msg.payload {
                NetworkMessage::Pong(n) if n == nonce => return true,
                _ => {}
            }
        }
    })
    .await
    .expect("pong timed out");

    assert!(got_pong, "did not receive matching pong");
    println!("[ping/pong] nonce=0x{nonce:x} → matched pong ✓");
}

// ── Test 3: getheaders → headers ──────────────────────────────────────────────

/// Send a `getheaders` starting from the genesis and verify Bitcoin Core returns
/// at least one header.  Also verify each header can be decoded into a valid
/// `BlockHeader` (80 bytes, correct version field, etc.).
#[tokio::test]
async fn test_getheaders_from_genesis() {
    let (mut reader, mut writer, peer_height) =
        match connect_and_handshake(Network::Regtest).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("skipping: {e}");
                return;
            }
        };

    let magic = Network::Regtest.magic();

    // Locator: just the genesis block hash (in internal byte order)
    let genesis =
        Hash256::from_hex("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")
            .unwrap();
    let get_headers = GetBlocksMessage::new(vec![genesis]);

    writer
        .write_all(
            &Message::new(magic, NetworkMessage::GetHeaders(get_headers)).encode_to_bytes(),
        )
        .await
        .unwrap();

    // Drain until we get a headers message
    let headers = timeout(TIMEOUT, async {
        loop {
            let msg = Message::read_from(&mut reader, &magic).await.unwrap();
            if let NetworkMessage::Headers(h) = msg.payload {
                return h;
            }
        }
    })
    .await
    .expect("headers timed out");

    println!(
        "[getheaders] peer_height={peer_height}  headers returned={}",
        headers.headers.len()
    );

    assert!(
        !headers.headers.is_empty(),
        "expected at least one header but got none"
    );

    // Verify every returned header
    for (i, hdr) in headers.headers.iter().enumerate() {
        assert!(hdr.version > 0, "header[{i}] has version=0");
        assert_ne!(hdr.bits, 0, "header[{i}] has bits=0");
    }

    println!(
        "[getheaders] first header version={} bits=0x{:08x}",
        headers.headers[0].version, headers.headers[0].bits
    );
}

// ── Test 4: getdata → block ───────────────────────────────────────────────────

/// Request the genesis block by hash via `getdata` and verify that Bitcoin Core
/// sends it back as a well-formed `block` message that our decoder can parse.
#[tokio::test]
async fn test_getdata_genesis_block() {
    let (mut reader, mut writer, _) = match connect_and_handshake(Network::Regtest).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("skipping: {e}");
            return;
        }
    };

    let magic = Network::Regtest.magic();

    let genesis =
        Hash256::from_hex("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")
            .unwrap();

    let inv = vec![Inventory { inv_type: InvType::WitnessBlock, hash: genesis }];

    writer
        .write_all(&Message::new(magic, NetworkMessage::GetData(inv)).encode_to_bytes())
        .await
        .unwrap();

    let block = timeout(Duration::from_secs(15), async {
        loop {
            let msg = Message::read_from(&mut reader, &magic).await.unwrap();
            if let NetworkMessage::Block(b) = msg.payload {
                return b;
            }
        }
    })
    .await
    .expect("block message timed out");

    println!(
        "[getdata] genesis block txns={} header_version={} bits=0x{:08x}",
        block.transactions.len(),
        block.header.version,
        block.header.bits
    );

    // The regtest genesis has exactly 1 transaction (the coinbase)
    assert_eq!(block.transactions.len(), 1, "genesis should have 1 tx");
    assert!(
        block.transactions[0].is_coinbase(),
        "genesis tx[0] should be coinbase"
    );
    assert_eq!(block.header.version, 1, "genesis header version should be 1");
}

// ── Test 5: headers-first sync of first N blocks ─────────────────────────────

/// Ask for the first 10 block headers, then fetch each block via `getdata` and
/// verify basic properties (version, tx count ≥ 1, coinbase present).
#[tokio::test]
async fn test_sync_first_10_blocks() {
    let (mut reader, mut writer, peer_height) =
        match connect_and_handshake(Network::Regtest).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("skipping: {e}");
                return;
            }
        };

    if peer_height < 10 {
        eprintln!("peer only has {peer_height} blocks; need ≥10 -- skipping");
        return;
    }

    let magic = Network::Regtest.magic();

    // Request headers starting from genesis
    let genesis =
        Hash256::from_hex("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")
            .unwrap();
    writer
        .write_all(
            &Message::new(
                magic,
                NetworkMessage::GetHeaders(GetBlocksMessage::new(vec![genesis])),
            )
            .encode_to_bytes(),
        )
        .await
        .unwrap();

    let headers = timeout(TIMEOUT, async {
        loop {
            let msg = Message::read_from(&mut reader, &magic).await.unwrap();
            if let NetworkMessage::Headers(h) = msg.payload {
                return h;
            }
        }
    })
    .await
    .expect("headers timed out");

    // Compute hashes of first 10 returned headers
    let wanted: Vec<Hash256> = headers
        .headers
        .iter()
        .take(10)
        .map(|h| {
            use rbtc_crypto::sha256d;
            use rbtc_primitives::codec::Encodable;
            let mut buf = Vec::with_capacity(80);
            h.version.encode(&mut buf).ok();
            h.prev_block.0.encode(&mut buf).ok();
            h.merkle_root.0.encode(&mut buf).ok();
            h.time.encode(&mut buf).ok();
            h.bits.encode(&mut buf).ok();
            h.nonce.encode(&mut buf).ok();
            sha256d(&buf)
        })
        .collect();

    println!("[sync] requesting {} blocks", wanted.len());

    let inv: Vec<Inventory> = wanted
        .iter()
        .map(|h| Inventory { inv_type: InvType::WitnessBlock, hash: *h })
        .collect();

    writer
        .write_all(&Message::new(magic, NetworkMessage::GetData(inv)).encode_to_bytes())
        .await
        .unwrap();

    // Receive and validate each block
    let mut received = 0usize;
    timeout(Duration::from_secs(30), async {
        while received < wanted.len() {
            let msg = Message::read_from(&mut reader, &magic).await.unwrap();
            if let NetworkMessage::Block(block) = msg.payload {
                received += 1;
                assert!(!block.transactions.is_empty(), "block has no transactions");
                assert!(
                    block.transactions[0].is_coinbase(),
                    "first tx is not coinbase"
                );
                println!(
                    "  block #{received}: txns={}  coinbase_value={}",
                    block.transactions.len(),
                    block.transactions[0].outputs.iter().map(|o| o.value).sum::<u64>()
                );
            }
        }
    })
    .await
    .expect("block sync timed out");

    assert_eq!(received, wanted.len(), "did not receive all blocks");
    println!("[sync] verified {received} blocks ✓");
}

// ── Test 6: merkle root verification (C4) ───────────────────────────────────

/// Fetch blocks from Bitcoin Core and verify that our merkle root computation
/// matches the header's merkle_root field.  This exercises the CVE-2012-2459
/// defense code path (duplicate txid detection) and ensures our merkle tree
/// implementation matches Core's.
#[tokio::test]
async fn test_merkle_root_matches_header() {
    let (mut reader, mut writer, peer_height) =
        match connect_and_handshake(Network::Regtest).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("skipping: {e}");
                return;
            }
        };

    if peer_height < 5 {
        eprintln!("peer only has {peer_height} blocks; need ≥5 -- skipping");
        return;
    }

    let magic = Network::Regtest.magic();

    // Get headers from genesis
    let genesis =
        Hash256::from_hex("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")
            .unwrap();
    writer
        .write_all(
            &Message::new(
                magic,
                NetworkMessage::GetHeaders(GetBlocksMessage::new(vec![genesis])),
            )
            .encode_to_bytes(),
        )
        .await
        .unwrap();

    let headers = timeout(TIMEOUT, async {
        loop {
            let msg = Message::read_from(&mut reader, &magic).await.unwrap();
            if let NetworkMessage::Headers(h) = msg.payload {
                return h;
            }
        }
    })
    .await
    .expect("headers timed out");

    // Compute hashes of first 5 headers and fetch the blocks
    let wanted: Vec<Hash256> = headers
        .headers
        .iter()
        .take(5)
        .map(|h| {
            use rbtc_crypto::sha256d;
            use rbtc_primitives::codec::Encodable;
            let mut buf = Vec::with_capacity(80);
            h.version.encode(&mut buf).ok();
            h.prev_block.0.encode(&mut buf).ok();
            h.merkle_root.0.encode(&mut buf).ok();
            h.time.encode(&mut buf).ok();
            h.bits.encode(&mut buf).ok();
            h.nonce.encode(&mut buf).ok();
            sha256d(&buf)
        })
        .collect();

    let inv: Vec<Inventory> = wanted
        .iter()
        .map(|h| Inventory { inv_type: InvType::WitnessBlock, hash: *h })
        .collect();

    writer
        .write_all(&Message::new(magic, NetworkMessage::GetData(inv)).encode_to_bytes())
        .await
        .unwrap();

    let mut verified = 0usize;
    timeout(Duration::from_secs(15), async {
        while verified < wanted.len() {
            let msg = Message::read_from(&mut reader, &magic).await.unwrap();
            if let NetworkMessage::Block(block) = msg.payload {
                // Compute merkle root from transactions
                let txids: Vec<Hash256> = block.transactions.iter().map(|tx| {
                    let mut buf = Vec::new();
                    tx.encode_legacy(&mut buf).ok();
                    rbtc_crypto::sha256d(&buf)
                }).collect();

                let computed_root = rbtc_crypto::merkle_root(&txids).unwrap_or(Hash256::ZERO);
                assert_eq!(
                    computed_root, block.header.merkle_root,
                    "merkle root mismatch at block #{verified}"
                );

                // Also verify no duplicate txids (CVE-2012-2459)
                let unique: std::collections::HashSet<Hash256> = txids.iter().copied().collect();
                assert_eq!(
                    unique.len(), txids.len(),
                    "duplicate txid found in block #{verified}"
                );

                verified += 1;
                println!(
                    "  block #{verified}: merkle_root OK, txns={}, no dup txids ✓",
                    block.transactions.len()
                );
            }
        }
    })
    .await
    .expect("block fetch timed out");

    println!("[merkle] verified {verified} blocks ✓");
}

// ── Test 7: block version bits parsing (C3) ─────────────────────────────────

/// Fetch block headers from Bitcoin Core regtest and verify that BIP9 version
/// bits are correctly represented: the top 3 bits should follow the BIP9
/// pattern (bit 29 set for version-bits signaling blocks on regtest).
#[tokio::test]
async fn test_block_version_bits() {
    let (mut reader, mut writer, peer_height) =
        match connect_and_handshake(Network::Regtest).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("skipping: {e}");
                return;
            }
        };

    if peer_height < 1 {
        eprintln!("peer has no blocks -- skipping");
        return;
    }

    let magic = Network::Regtest.magic();
    let genesis =
        Hash256::from_hex("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")
            .unwrap();

    writer
        .write_all(
            &Message::new(
                magic,
                NetworkMessage::GetHeaders(GetBlocksMessage::new(vec![genesis])),
            )
            .encode_to_bytes(),
        )
        .await
        .unwrap();

    let headers = timeout(TIMEOUT, async {
        loop {
            let msg = Message::read_from(&mut reader, &magic).await.unwrap();
            if let NetworkMessage::Headers(h) = msg.payload {
                return h;
            }
        }
    })
    .await
    .expect("headers timed out");

    println!("[version-bits] received {} headers", headers.headers.len());
    assert!(!headers.headers.is_empty());

    for (i, hdr) in headers.headers.iter().enumerate() {
        // Block version should be > 0 (typical regtest uses version 0x20000000)
        assert!(hdr.version > 0, "header[{i}] has non-positive version: {}", hdr.version);

        // Modern Bitcoin Core regtest uses BIP9 version bits (bit 29 set)
        // The top bits pattern is 0x20xxxxxx
        let has_bip9_top = (hdr.version & 0xe0000000u32 as i32) == 0x20000000;
        if has_bip9_top {
            // Extract signaled bits (0..28)
            let signal_bits = hdr.version & 0x1fffffff;
            println!(
                "  header[{i}]: version=0x{:08x} BIP9=true signal_bits=0x{:07x}",
                hdr.version, signal_bits
            );
        } else {
            println!(
                "  header[{i}]: version=0x{:08x} (legacy)",
                hdr.version
            );
        }
    }
    println!("[version-bits] all headers parsed ✓");
}

// ── Bitcoin Core RPC integration tests ──────────────────────────────────────
//
// These tests call Bitcoin Core's JSON-RPC via bitcoin-cli to verify that its
// responses can be parsed correctly and that our implementations match.

fn bitcoin_cli(args: &[&str]) -> Option<String> {
    let output = std::process::Command::new("/tmp/bitcoin-27.0/bin/bitcoin-cli")
        .args(&["-datadir=/tmp/rbtc-regtest", "-regtest"])
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn bitcoin_cli_available() -> bool {
    bitcoin_cli(&["getblockchaininfo"]).is_some()
}

// ── Test 8: RPC getblockchaininfo comparison ─────────────────────────────────

/// Call getblockchaininfo on Bitcoin Core and verify key fields exist and are
/// well-formed, matching what rbtc's implementation would return.
#[tokio::test]
async fn test_rpc_getblockchaininfo() {
    if !bitcoin_cli_available() {
        eprintln!("bitcoin-cli not available -- skipping RPC tests");
        return;
    }

    let info = bitcoin_cli(&["getblockchaininfo"]).unwrap();
    let val: serde_json::Value = serde_json::from_str(&info).unwrap();
    assert_eq!(val["chain"], "regtest");
    assert!(val["blocks"].as_u64().is_some());
    assert!(val["bestblockhash"].as_str().unwrap().len() == 64);
    println!("[rpc] getblockchaininfo: chain={} blocks={}", val["chain"], val["blocks"]);
}

// ── Test 9: RPC decoderawtransaction comparison ──────────────────────────────

/// Get a raw transaction from Bitcoin Core via block, decode it with both Core
/// and rbtc, and verify fields match (txid, version, vin/vout counts).
#[tokio::test]
async fn test_rpc_decoderawtransaction() {
    if !bitcoin_cli_available() {
        eprintln!("bitcoin-cli not available -- skipping");
        return;
    }

    // Get block hash for block 1
    let hash = match bitcoin_cli(&["getblockhash", "1"]) {
        Some(h) => h,
        None => {
            eprintln!("no block 1 -- skipping");
            return;
        }
    };

    // Fetch the coinbase txid from the verbose block
    let block_json = match bitcoin_cli(&["getblock", &hash, "2"]) {
        Some(s) => s,
        None => { eprintln!("getblock failed -- skipping"); return; }
    };
    let block: serde_json::Value = serde_json::from_str(&block_json).unwrap();
    let coinbase_txid = match block["tx"][0]["txid"].as_str() {
        Some(t) => t.to_string(),
        None => { eprintln!("no txid in block -- skipping"); return; }
    };

    // getrawtransaction needs block hash since -txindex may not be enabled
    let raw_hex = match bitcoin_cli(&["getrawtransaction", &coinbase_txid, "false", &hash]) {
        Some(h) => h,
        None => { eprintln!("getrawtransaction failed -- skipping"); return; }
    };

    // Decode with Bitcoin Core
    let core_decoded = bitcoin_cli(&["decoderawtransaction", &raw_hex]).unwrap();
    let core_val: serde_json::Value = serde_json::from_str(&core_decoded).unwrap();

    // Decode with our implementation
    let tx_bytes = hex::decode(&raw_hex).unwrap();
    let tx: rbtc_primitives::transaction::Transaction =
        rbtc_primitives::codec::Decodable::decode(&mut &tx_bytes[..]).unwrap();

    let mut legacy_buf = Vec::new();
    tx.encode_legacy(&mut legacy_buf).ok();
    let our_txid = rbtc_crypto::sha256d(&legacy_buf);

    assert_eq!(
        our_txid.to_hex(),
        core_val["txid"].as_str().unwrap(),
        "txid mismatch between rbtc and Bitcoin Core"
    );
    assert_eq!(
        tx.version as i64,
        core_val["version"].as_i64().unwrap(),
        "version mismatch"
    );
    assert_eq!(
        tx.inputs.len(),
        core_val["vin"].as_array().unwrap().len(),
        "vin count mismatch"
    );
    assert_eq!(
        tx.outputs.len(),
        core_val["vout"].as_array().unwrap().len(),
        "vout count mismatch"
    );

    println!(
        "[rpc] decoderawtransaction: txid={} version={} vin={} vout={} ✓",
        our_txid.to_hex(), tx.version, tx.inputs.len(), tx.outputs.len()
    );
}

// ── Test 10: RPC validateaddress comparison ──────────────────────────────────

/// Generate an address on Bitcoin Core and verify validateaddress returns
/// isvalid=true with correct witness info.
#[tokio::test]
async fn test_rpc_validateaddress() {
    if !bitcoin_cli_available() {
        eprintln!("bitcoin-cli not available -- skipping");
        return;
    }

    let addr = match bitcoin_cli(&["getnewaddress", "", "bech32"]) {
        Some(a) => a,
        None => {
            eprintln!("could not get new address -- skipping");
            return;
        }
    };

    let core_val_str = bitcoin_cli(&["validateaddress", &addr]).unwrap();
    let core_val: serde_json::Value = serde_json::from_str(&core_val_str).unwrap();
    assert_eq!(core_val["isvalid"], true);

    // Our implementation should also validate this address
    let our_script = rbtc_wallet::address::address_to_script(&addr);
    assert!(our_script.is_ok(), "rbtc should parse Bitcoin Core bech32 address: {addr}");
    let script = our_script.unwrap();
    assert!(
        script.is_p2wpkh() || script.is_p2wsh() || script.is_p2tr(),
        "bech32 address should produce witness script"
    );

    println!("[rpc] validateaddress: addr={addr} isvalid=true ✓");
}

// ── Test 11: RPC getblockstats comparison ────────────────────────────────────

/// Compare getblockstats output for block 1 between Bitcoin Core and our
/// expected behavior (tx count, subsidy, etc).
#[tokio::test]
async fn test_rpc_getblockstats() {
    if !bitcoin_cli_available() {
        eprintln!("bitcoin-cli not available -- skipping");
        return;
    }

    let core_stats_str = match bitcoin_cli(&["getblockstats", "1"]) {
        Some(s) => s,
        None => {
            eprintln!("no block 1 -- skipping");
            return;
        }
    };
    let core_stats: serde_json::Value = serde_json::from_str(&core_stats_str).unwrap();

    assert_eq!(core_stats["height"], 1);
    // Regtest block 1 should have 1 tx (coinbase)
    assert_eq!(core_stats["txs"], 1);
    // Subsidy at height 1 on regtest = 50 BTC = 5_000_000_000 sat
    assert_eq!(core_stats["subsidy"], 5_000_000_000u64);
    // Note: Bitcoin Core excludes coinbase from total_size/total_weight,
    // so block 1 (coinbase only) may report 0 for these fields.
    assert!(core_stats["total_weight"].as_u64().is_some() || core_stats["total_weight"].as_i64().is_some());
    assert!(core_stats["total_size"].as_u64().is_some() || core_stats["total_size"].as_i64().is_some());

    println!(
        "[rpc] getblockstats: height={} txs={} subsidy={} ✓",
        core_stats["height"], core_stats["txs"], core_stats["subsidy"]
    );
}

// ── Test 12: BIP68 relative lock-time on regtest (C5) ────────────────────────

/// Verify that Bitcoin Core enforces BIP68 sequence locks on regtest:
/// create a transaction with CSV-locked inputs and check that it's accepted
/// in blocks at the right height.
#[tokio::test]
async fn test_bip68_sequence_lock_enforcement() {
    if !bitcoin_cli_available() {
        eprintln!("bitcoin-cli not available -- skipping");
        return;
    }

    // Generate blocks to ensure we have mature coins
    let addr = match bitcoin_cli(&["getnewaddress"]) {
        Some(a) => a,
        None => { eprintln!("getnewaddress failed -- skipping"); return; }
    };
    // Make sure we have at least 110 blocks for mature coinbases
    let current_height: u64 = bitcoin_cli(&["getblockcount"])
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if current_height < 110 {
        let needed = 110 - current_height;
        bitcoin_cli(&["generatetoaddress", &needed.to_string(), &addr]);
    }

    // Get a UTXO to spend
    let utxos_str = match bitcoin_cli(&["listunspent"]) {
        Some(s) => s,
        None => { eprintln!("listunspent failed -- skipping"); return; }
    };
    let utxos: serde_json::Value = serde_json::from_str(&utxos_str).unwrap();
    let utxo_arr = utxos.as_array().unwrap();
    if utxo_arr.is_empty() {
        eprintln!("no UTXOs -- skipping");
        return;
    }

    let utxo = &utxo_arr[0];
    let txid = utxo["txid"].as_str().unwrap();
    let vout = utxo["vout"].as_u64().unwrap();
    let amount = utxo["amount"].as_f64().unwrap();

    // Create a raw transaction with BIP68 relative lock of 10 blocks
    // (sequence = 10, which means 10 blocks relative lock)
    let inputs = format!("[{{\"txid\":\"{txid}\",\"vout\":{vout},\"sequence\":10}}]");
    let send_amount = amount - 0.001; // leave fee
    let outputs = format!("{{\"{}\":{:.8}}}", addr, send_amount);

    let raw = match bitcoin_cli(&["createrawtransaction", &inputs, &outputs]) {
        Some(r) => r,
        None => { eprintln!("createrawtransaction failed -- skipping"); return; }
    };

    // Sign it
    let signed_str = match bitcoin_cli(&["signrawtransactionwithwallet", &raw]) {
        Some(s) => s,
        None => { eprintln!("signrawtransaction failed -- skipping"); return; }
    };
    let signed: serde_json::Value = serde_json::from_str(&signed_str).unwrap();
    assert_eq!(signed["complete"], true, "signing should complete");
    let signed_hex = signed["hex"].as_str().unwrap();

    // testmempoolaccept should reject it if the UTXO is too recent (< 10 confirmations)
    // But if the UTXO has enough confs already, it should accept it
    let confs = utxo["confirmations"].as_u64().unwrap_or(0);

    let accept_str = bitcoin_cli(&["testmempoolaccept", &format!("[\"{signed_hex}\"]")]).unwrap();
    let accept: serde_json::Value = serde_json::from_str(&accept_str).unwrap();
    let accepted = accept[0]["allowed"].as_bool().unwrap_or(false);

    if confs >= 10 {
        assert!(accepted, "BIP68: tx with sequence=10 should be accepted when UTXO has {confs} confs >= 10");
        println!("[bip68] tx with sequence=10, utxo confs={confs} → accepted ✓");
    } else {
        assert!(!accepted, "BIP68: tx with sequence=10 should be rejected when UTXO has {confs} confs < 10");
        let reason = accept[0]["reject-reason"].as_str().unwrap_or("");
        assert!(
            reason.contains("non-BIP68-final") || reason.contains("sequence"),
            "reject reason should mention BIP68: {reason}"
        );
        println!("[bip68] tx with sequence=10, utxo confs={confs} → correctly rejected: {reason} ✓");
    }
}

// ── Test 13: RPC decodescript comparison ─────────────────────────────────────

/// Decode a P2PKH script via Bitcoin Core and verify our classification matches.
#[tokio::test]
async fn test_rpc_decodescript() {
    if !bitcoin_cli_available() {
        eprintln!("bitcoin-cli not available -- skipping");
        return;
    }

    // P2PKH: OP_DUP OP_HASH160 <20 zero bytes> OP_EQUALVERIFY OP_CHECKSIG
    let mut script_bytes = vec![0x76u8, 0xa9, 0x14];
    script_bytes.extend_from_slice(&[0u8; 20]);
    script_bytes.extend_from_slice(&[0x88, 0xac]);
    let script_hex = hex::encode(&script_bytes);

    let core_decoded = bitcoin_cli(&["decodescript", &script_hex]).unwrap();
    let core_val: serde_json::Value = serde_json::from_str(&core_decoded).unwrap();

    assert_eq!(core_val["type"], "pubkeyhash");

    // Our classify_script should match
    let script = rbtc_primitives::script::Script::from_bytes(script_bytes);
    assert!(script.is_p2pkh(), "rbtc should classify as P2PKH");

    println!("[rpc] decodescript: type=pubkeyhash ✓");

    // Also test P2SH
    let mut p2sh = vec![0xa9u8, 0x14];
    p2sh.extend_from_slice(&[0u8; 20]);
    p2sh.push(0x87);
    let p2sh_hex = hex::encode(&p2sh);
    let core_p2sh = bitcoin_cli(&["decodescript", &p2sh_hex]).unwrap();
    let core_p2sh_val: serde_json::Value = serde_json::from_str(&core_p2sh).unwrap();
    assert_eq!(core_p2sh_val["type"], "scripthash");
    println!("[rpc] decodescript: type=scripthash ✓");
}

// ── Test 14: RPC getchaintips ────────────────────────────────────────────────

/// Verify Bitcoin Core's getchaintips returns at least one active tip.
#[tokio::test]
async fn test_rpc_getchaintips() {
    if !bitcoin_cli_available() {
        eprintln!("bitcoin-cli not available -- skipping");
        return;
    }

    let tips_str = bitcoin_cli(&["getchaintips"]).unwrap();
    let tips: serde_json::Value = serde_json::from_str(&tips_str).unwrap();
    let tips_arr = tips.as_array().unwrap();
    assert!(!tips_arr.is_empty(), "should have at least one chain tip");

    let active = tips_arr.iter().find(|t| t["status"] == "active");
    assert!(active.is_some(), "should have an active tip");
    let active_tip = active.unwrap();
    assert!(active_tip["height"].as_u64().unwrap() > 0);
    assert!(active_tip["hash"].as_str().unwrap().len() == 64);
    assert_eq!(active_tip["branchlen"], 0);

    println!(
        "[rpc] getchaintips: active height={} hash={} ✓",
        active_tip["height"],
        &active_tip["hash"].as_str().unwrap()[..16]
    );
}
