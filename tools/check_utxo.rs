//! Quick tool to check if a specific UTXO exists in RocksDB.
//! Run: cargo run --bin check_utxo

use std::path::PathBuf;

fn main() {
    let db_path = PathBuf::from(std::env::var("RBTC_DATADIR").unwrap_or_else(|_| {
        dirs::home_dir()
            .unwrap()
            .join(".rbtc")
            .join("chaindata")
            .to_string_lossy()
            .to_string()
    }));

    let txid_hex = std::env::args().nth(1).unwrap_or_else(|| {
        "de1d826d7b3817e649d48bda1588f3901589992b6f10f71755643adbfc51fe3b".to_string()
    });
    let vout: u32 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    println!("Opening RocksDB at: {db_path:?}");
    println!("Looking up UTXO: {txid_hex}:{vout}");

    // Decode txid hex → reversed bytes (Bitcoin display order → internal order)
    let hex_bytes = hex::decode(&txid_hex).expect("invalid hex");
    assert_eq!(hex_bytes.len(), 32, "txid must be 32 bytes");
    let mut txid_bytes = [0u8; 32];
    txid_bytes.copy_from_slice(&hex_bytes);
    txid_bytes.reverse(); // display order → internal order

    // Build the UTXO key: txid (32 bytes) + vout (4 bytes LE)
    let mut key = Vec::with_capacity(36);
    key.extend_from_slice(&txid_bytes);
    key.extend_from_slice(&vout.to_le_bytes());

    println!("Key (hex): {}", hex::encode(&key));

    // Open RocksDB with the same column families
    let cf_names = vec![
        "default",
        "block_index",
        "block_data",
        "chain_state",
        "utxo",
        "tx_index",
        "addr_index",
        "peer_store",
        "undo",
        "wallet",
        "block_filters",
        "filter_headers",
    ];

    let mut opts = rocksdb::Options::default();
    opts.set_max_open_files(256);

    let cf_descriptors: Vec<rocksdb::ColumnFamilyDescriptor> = cf_names
        .iter()
        .map(|name| rocksdb::ColumnFamilyDescriptor::new(*name, rocksdb::Options::default()))
        .collect();

    let db = rocksdb::DB::open_cf_descriptors_read_only(&opts, &db_path, cf_descriptors, false)
        .expect("failed to open RocksDB");

    let cf = db.cf_handle("utxo").expect("utxo CF not found");

    match db.get_cf(cf, &key) {
        Ok(Some(value)) => {
            println!("FOUND! Value length: {} bytes", value.len());
            println!("Raw value (hex): {}", hex::encode(&value));
            // Try to decode: u64 (value) + varint+script + u32 (height) + u8 (is_coinbase)
            if value.len() >= 13 {
                let sat_value = u64::from_le_bytes(value[0..8].try_into().unwrap());
                println!("  Satoshis: {sat_value}");
            }
        }
        Ok(None) => {
            println!("NOT FOUND in utxo CF!");
            // Let's also scan for any key starting with this txid
            println!("\nScanning for any UTXO with this txid prefix...");
            let iter = db.prefix_iterator_cf(cf, &txid_bytes);
            let mut count = 0;
            for item in iter {
                match item {
                    Ok((k, v)) => {
                        if k.len() >= 32 && k[..32] == txid_bytes {
                            let vout_found = if k.len() >= 36 {
                                u32::from_le_bytes(k[32..36].try_into().unwrap())
                            } else {
                                u32::MAX
                            };
                            println!(
                                "  Found: {}:{} (value_len={})",
                                txid_hex,
                                vout_found,
                                v.len()
                            );
                            count += 1;
                        } else {
                            break;
                        }
                    }
                    Err(e) => {
                        println!("  Iterator error: {e}");
                        break;
                    }
                }
            }
            if count == 0 {
                println!("  No UTXOs found for this txid at all.");
            }
        }
        Err(e) => {
            println!("RocksDB error: {e}");
        }
    }

    // Also check chain tip
    let chain_cf = db.cf_handle("chain_state").expect("chain_state CF not found");
    if let Ok(Some(tip_data)) = db.get_cf(chain_cf, b"tip") {
        if tip_data.len() >= 36 {
            let mut tip_hash = [0u8; 32];
            tip_hash.copy_from_slice(&tip_data[..32]);
            tip_hash.reverse();
            let height = u32::from_le_bytes(tip_data[32..36].try_into().unwrap());
            println!("\nChain tip: height={height}, hash={}", hex::encode(tip_hash));
        }
    }
}
