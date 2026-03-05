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
