use rbtc_primitives::hash::Hash256;
use rbtc_primitives::transaction::OutPoint;
use rbtc_storage::db::Database;
use rbtc_storage::UtxoStore;
use std::path::PathBuf;

fn main() {
    let default_path = PathBuf::from("/root/.rbtc/chaindata");
    let db_path = std::env::var("RBTC_DATADIR")
        .map(PathBuf::from)
        .unwrap_or(default_path);

    let txid_hex = std::env::args().nth(1).unwrap_or_else(|| {
        "de1d826d7b3817e649d48bda1588f3901589992b6f10f71755643adbfc51fe3b".to_string()
    });
    let vout: u32 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(0);

    println!("DB path: {db_path:?}");
    println!("Lookup: {txid_hex}:{vout}");

    let db = Database::open(&db_path).expect("failed to open DB");
    let store = UtxoStore::new(&db);

    let txid = Hash256::from_hex(&txid_hex).expect("invalid txid hex");
    let outpoint = OutPoint { txid, vout };

    println!("Internal txid bytes: {}", hex::encode(txid.0));

    match store.get(&outpoint) {
        Ok(Some(utxo)) => {
            println!("FOUND!");
            println!("  value: {} sat", utxo.value);
            println!("  height: {}", utxo.height);
            println!("  is_coinbase: {}", utxo.is_coinbase);
            println!("  script_pubkey: {}", hex::encode(utxo.script_pubkey.as_bytes()));
        }
        Ok(None) => {
            println!("NOT FOUND!");
            let chain_store = rbtc_storage::ChainStore::new(&db);
            if let Ok(Some(hash)) = chain_store.get_best_block() {
                println!("Best block: {}", hash.to_hex());
            }
            if let Ok(Some(h)) = chain_store.get_best_height() {
                println!("Best height: {h}");
            }
        }
        Err(e) => {
            println!("Error: {e}");
        }
    }
}
