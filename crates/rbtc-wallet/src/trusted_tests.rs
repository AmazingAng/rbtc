//! Tests for `Wallet::tx_is_trusted` (H4: CachedTxIsTrusted).

#[cfg(test)]
mod tests {
    use crate::address::AddressType;
    use crate::mnemonic::Mnemonic;
    use crate::tx_store::WalletTx;
    use crate::wallet::{Wallet, WalletUtxo};
    use rbtc_primitives::hash::{BlockHash, Hash256, Txid};
    use rbtc_primitives::network::Network;
    use rbtc_primitives::script::Script;
    use rbtc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
    use rbtc_storage::Database;
    use tempfile::TempDir;

    fn open_db() -> (TempDir, std::sync::Arc<Database>) {
        let dir = TempDir::new().unwrap();
        let db = std::sync::Arc::new(Database::open(dir.path()).unwrap());
        (dir, db)
    }

    fn test_wallet(db: std::sync::Arc<Database>) -> Wallet {
        let m = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        Wallet::from_mnemonic(&m, "", "testpassword", Network::Regtest, db).unwrap()
    }

    fn make_txid(n: u8) -> Txid {
        Txid(Hash256([n; 32]))
    }

    fn make_tx(inputs: Vec<OutPoint>, outputs: Vec<TxOut>) -> Transaction {
        let tx_inputs: Vec<TxIn> = inputs
            .into_iter()
            .map(|op| TxIn {
                previous_output: op,
                script_sig: Script::new(),
                sequence: 0xffff_ffff,
                witness: vec![],
            })
            .collect();
        Transaction::from_parts(2, tx_inputs, outputs, 0)
    }

    fn insert_utxo(w: &mut Wallet, op: &OutPoint, value: u64, spk: &Script, addr: &str, confirmed: bool) {
        w.utxos.insert(op.clone(), WalletUtxo {
            outpoint: op.clone(),
            value,
            script_pubkey: spk.clone(),
            height: if confirmed { 100 } else { 0 },
            address: addr.to_string(),
            confirmed,
            addr_type: AddressType::SegWit,
            is_own_change: false,
            is_coinbase: false,
        });
    }

    #[test]
    fn confirmed_tx_is_trusted() {
        let (_dir, db) = open_db();
        let mut w = test_wallet(db);
        let txid = make_txid(0x01);
        let tx = make_tx(
            vec![OutPoint { txid: make_txid(0xFF), vout: 0 }],
            vec![TxOut { value: 50_000, script_pubkey: Script::from_bytes(vec![0x51]) }],
        );
        w.tx_store.add_tx(txid, WalletTx {
            tx,
            block_hash: Some(BlockHash(Hash256([0xAB; 32]))),
            block_height: Some(100),
            timestamp: 1000,
            is_confirmed: true,
            replaced_by: None,
            is_abandoned: false,
        });
        assert!(w.tx_is_trusted(&txid));
    }

    #[test]
    fn unconfirmed_wallet_tx_with_confirmed_parent_is_trusted() {
        let (_dir, db) = open_db();
        let mut w = test_wallet(db);
        let addr = w.new_address(AddressType::SegWit).unwrap();
        let spk = w.addresses.get(&addr).unwrap().script_pubkey.clone();

        let parent_txid = make_txid(0x01);
        let parent_tx = make_tx(
            vec![OutPoint { txid: make_txid(0xFF), vout: 0 }],
            vec![TxOut { value: 50_000, script_pubkey: spk.clone() }],
        );
        w.tx_store.add_tx(parent_txid, WalletTx {
            tx: parent_tx,
            block_hash: Some(BlockHash(Hash256([0xAB; 32]))),
            block_height: Some(100),
            timestamp: 1000,
            is_confirmed: true,
            replaced_by: None,
            is_abandoned: false,
        });
        let parent_op = OutPoint { txid: parent_txid, vout: 0 };
        insert_utxo(&mut w, &parent_op, 50_000, &spk, &addr, true);

        let child_txid = make_txid(0x02);
        let child_tx = make_tx(
            vec![parent_op],
            vec![TxOut { value: 40_000, script_pubkey: Script::from_bytes(vec![0x51]) }],
        );
        w.tx_store.add_tx(child_txid, WalletTx {
            tx: child_tx,
            block_hash: None,
            block_height: None,
            timestamp: 2000,
            is_confirmed: false,
            replaced_by: None,
            is_abandoned: false,
        });

        assert!(w.tx_is_trusted(&child_txid));
    }

    #[test]
    fn unconfirmed_non_wallet_tx_is_not_trusted() {
        let (_dir, db) = open_db();
        let mut w = test_wallet(db);
        let txid = make_txid(0x03);
        let tx = make_tx(
            vec![OutPoint { txid: make_txid(0xCC), vout: 0 }],
            vec![TxOut { value: 50_000, script_pubkey: Script::from_bytes(vec![0x51]) }],
        );
        w.tx_store.add_tx(txid, WalletTx {
            tx,
            block_hash: None,
            block_height: None,
            timestamp: 1000,
            is_confirmed: false,
            replaced_by: None,
            is_abandoned: false,
        });
        assert!(!w.tx_is_trusted(&txid));
    }

    #[test]
    fn chain_of_unconfirmed_wallet_txs_is_trusted() {
        let (_dir, db) = open_db();
        let mut w = test_wallet(db);
        let addr = w.new_address(AddressType::SegWit).unwrap();
        let spk = w.addresses.get(&addr).unwrap().script_pubkey.clone();

        // Grandparent: confirmed
        let gp_txid = make_txid(0x10);
        let gp_tx = make_tx(
            vec![OutPoint { txid: make_txid(0xFF), vout: 0 }],
            vec![TxOut { value: 100_000, script_pubkey: spk.clone() }],
        );
        w.tx_store.add_tx(gp_txid, WalletTx {
            tx: gp_tx,
            block_hash: Some(BlockHash(Hash256([0xAB; 32]))),
            block_height: Some(100),
            timestamp: 1000,
            is_confirmed: true,
            replaced_by: None,
            is_abandoned: false,
        });
        let gp_op = OutPoint { txid: gp_txid, vout: 0 };
        insert_utxo(&mut w, &gp_op, 100_000, &spk, &addr, true);

        // Parent: unconfirmed, spends grandparent
        let parent_txid = make_txid(0x20);
        let parent_tx = make_tx(
            vec![gp_op],
            vec![TxOut { value: 90_000, script_pubkey: spk.clone() }],
        );
        w.tx_store.add_tx(parent_txid, WalletTx {
            tx: parent_tx,
            block_hash: None,
            block_height: None,
            timestamp: 2000,
            is_confirmed: false,
            replaced_by: None,
            is_abandoned: false,
        });
        let parent_op = OutPoint { txid: parent_txid, vout: 0 };
        insert_utxo(&mut w, &parent_op, 90_000, &spk, &addr, false);

        // Child: unconfirmed, spends parent
        let child_txid = make_txid(0x30);
        let child_tx = make_tx(
            vec![parent_op],
            vec![TxOut { value: 80_000, script_pubkey: Script::from_bytes(vec![0x51]) }],
        );
        w.tx_store.add_tx(child_txid, WalletTx {
            tx: child_tx,
            block_hash: None,
            block_height: None,
            timestamp: 3000,
            is_confirmed: false,
            replaced_by: None,
            is_abandoned: false,
        });

        assert!(w.tx_is_trusted(&child_txid));
        assert!(w.tx_is_trusted(&parent_txid));
        assert!(w.tx_is_trusted(&gp_txid));
    }

    #[test]
    fn tx_not_in_store_is_not_trusted() {
        let (_dir, db) = open_db();
        let w = test_wallet(db);
        assert!(!w.tx_is_trusted(&make_txid(0xEE)));
    }
}
