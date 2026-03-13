//! Tests for tx analysis methods: tx_get_credit, tx_get_debit, tx_get_change,
//! tx_get_fee, input_is_mine, all_inputs_mine.

#[cfg(test)]
mod tests {
    use crate::address::AddressType;
    use crate::mnemonic::Mnemonic;
    use crate::wallet::Wallet;
    use rbtc_primitives::block::{Block, BlockHeader};
    use rbtc_primitives::hash::{BlockHash, Hash256, Txid};
    use rbtc_primitives::network::Network;
    use rbtc_primitives::script::Script;
    use rbtc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
    use rbtc_storage::Database;
    use tempfile::TempDir;

    fn open_db() -> (TempDir, std::sync::Arc<Database>) {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        (dir, std::sync::Arc::new(db))
    }

    fn test_wallet(db: std::sync::Arc<Database>) -> Wallet {
        let m = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        Wallet::from_mnemonic(&m, "", "testpassword", Network::Regtest, db).unwrap()
    }

    fn dummy_header() -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block: BlockHash(Hash256([0u8; 32])),
            merkle_root: Hash256([0u8; 32]),
            time: 1_000_000,
            bits: 0x207fffff,
            nonce: 0,
        }
    }

    /// Set up a wallet with a receive address (labelled) and a change address,
    /// plus two UTXOs (50_000 sat each) on the receive address, created via
    /// scan_block. Returns (dir, wallet, recv_spk, change_spk).
    fn wallet_with_utxos() -> (TempDir, Wallet, Script, Script) {
        let (dir, db) = open_db();
        let mut w = test_wallet(db);

        // Derive receive address and label it so it is NOT considered change.
        let recv_addr = w.new_address(AddressType::SegWit).unwrap();
        w.set_label(&recv_addr, "payments").unwrap();

        // Get the script for the receive address by looking at list_unspent
        // after scanning. First we need to figure out the scriptPubKey.
        // Use the address module to derive it independently.
        // Actually, we'll scan a block and then grab the spk from list_unspent.

        // Derive a change address (chain 1).
        let change_addr = w.new_change_address(AddressType::SegWit).unwrap();

        // We need the scriptPubKeys. We can get them by scanning blocks and
        // inspecting what we got. Let's craft coinbase txs paying to our addresses.

        // To get spks, we use the address module. But we need the pubkey.
        // Simpler: use get_address_info to get pubkey, then derive spk.
        let recv_info = w.get_address_info(&recv_addr).unwrap();
        let change_info = w.get_address_info(&change_addr).unwrap();

        // SegWit (P2WPKH): OP_0 <20-byte-hash160(pubkey)>
        let recv_pubkey_bytes = hex::decode(&recv_info.pubkey_hex).unwrap();
        let recv_spk = crate::address::p2wpkh_script(
            &secp256k1::PublicKey::from_slice(&recv_pubkey_bytes).unwrap(),
        );
        let change_pubkey_bytes = hex::decode(&change_info.pubkey_hex).unwrap();
        let change_spk = crate::address::p2wpkh_script(
            &secp256k1::PublicKey::from_slice(&change_pubkey_bytes).unwrap(),
        );

        // Create two blocks, each with a coinbase paying 50_000 to recv_addr.
        for i in 0..2u32 {
            let coinbase_tx = Transaction::from_parts(
                2,
                vec![TxIn {
                    previous_output: OutPoint {
                        txid: Txid(Hash256([0u8; 32])),
                        vout: 0xffffffff,
                    },
                    script_sig: Script::from_bytes(vec![0x04, i as u8, 0x00, 0x00, 0x00]),
                    sequence: 0xffffffff,
                    witness: vec![],
                }],
                vec![TxOut {
                    value: 50_000,
                    script_pubkey: recv_spk.clone(),
                }],
                0,
            );
            let block = Block {
                header: dummy_header(),
                transactions: vec![coinbase_tx],
                checked: std::cell::Cell::new(false),
                checked_witness_commitment: std::cell::Cell::new(false),
                checked_merkle_root: std::cell::Cell::new(false),
            };
            w.scan_block(&block, 100 + i);
        }

        assert_eq!(w.list_unspent(0).len(), 2);
        (dir, w, recv_spk, change_spk)
    }

    #[test]
    fn tx_get_credit_sums_wallet_outputs() {
        let (_dir, w, recv_spk, _change_spk) = wallet_with_utxos();
        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::ZERO,
                    vout: 99,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![
                TxOut {
                    value: 30_000,
                    script_pubkey: recv_spk,
                },
                TxOut {
                    value: 20_000,
                    script_pubkey: Script::from_bytes(vec![0x6a, 0x04, 0xde, 0xad]),
                },
            ],
            0,
        );
        assert_eq!(w.tx_get_credit(&tx), 30_000);
    }

    #[test]
    fn tx_get_credit_zero_for_foreign_outputs() {
        let (_dir, w, _recv_spk, _change_spk) = wallet_with_utxos();
        let mut foreign_spk = vec![0x00, 0x14];
        foreign_spk.extend_from_slice(&[0xaa; 20]);
        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::ZERO,
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut {
                value: 50_000,
                script_pubkey: Script::from_bytes(foreign_spk),
            }],
            0,
        );
        assert_eq!(w.tx_get_credit(&tx), 0);
    }

    #[test]
    fn tx_get_debit_sums_spent_utxos() {
        let (_dir, w, _recv_spk, _change_spk) = wallet_with_utxos();
        // Get the outpoint of the first UTXO
        let utxos = w.list_unspent(0);
        let first_op = utxos[0].outpoint.clone();

        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: first_op,
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut {
                value: 49_000,
                script_pubkey: Script::new(),
            }],
            0,
        );
        assert_eq!(w.tx_get_debit(&tx), 50_000);
    }

    #[test]
    fn tx_get_debit_zero_for_foreign_inputs() {
        let (_dir, w, _recv_spk, _change_spk) = wallet_with_utxos();
        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::ZERO,
                    vout: 999,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut {
                value: 10_000,
                script_pubkey: Script::new(),
            }],
            0,
        );
        assert_eq!(w.tx_get_debit(&tx), 0);
    }

    #[test]
    fn tx_get_change_sums_change_outputs() {
        let (_dir, w, recv_spk, change_spk) = wallet_with_utxos();
        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::ZERO,
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![
                TxOut {
                    value: 30_000,
                    script_pubkey: recv_spk,
                },
                TxOut {
                    value: 19_000,
                    script_pubkey: change_spk,
                },
            ],
            0,
        );
        assert_eq!(w.tx_get_change(&tx), 19_000);
    }

    #[test]
    fn tx_get_fee_debit_minus_outputs() {
        let (_dir, w, _recv_spk, change_spk) = wallet_with_utxos();
        let utxos = w.list_unspent(0);
        assert!(utxos.len() >= 2, "expected at least 2 UTXOs");
        let op0 = utxos[0].outpoint.clone();
        let op1 = utxos[1].outpoint.clone();

        // Spend both UTXOs (100_000 total), send 95_000 out -> fee = 5_000.
        let tx = Transaction::from_parts(
            2,
            vec![
                TxIn {
                    previous_output: op0,
                    script_sig: Script::new(),
                    sequence: 0xffffffff,
                    witness: vec![],
                },
                TxIn {
                    previous_output: op1,
                    script_sig: Script::new(),
                    sequence: 0xffffffff,
                    witness: vec![],
                },
            ],
            vec![
                TxOut {
                    value: 80_000,
                    script_pubkey: Script::new(),
                },
                TxOut {
                    value: 15_000,
                    script_pubkey: change_spk,
                },
            ],
            0,
        );
        assert_eq!(w.tx_get_fee(&tx), 5_000);
    }

    #[test]
    fn tx_get_fee_zero_for_received_tx() {
        let (_dir, w, recv_spk, _change_spk) = wallet_with_utxos();
        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::ZERO,
                    vout: 999,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut {
                value: 50_000,
                script_pubkey: recv_spk,
            }],
            0,
        );
        assert_eq!(w.tx_get_fee(&tx), 0);
    }

    #[test]
    fn input_is_mine_and_all_inputs_mine() {
        let (_dir, w, _recv_spk, _change_spk) = wallet_with_utxos();
        let utxos = w.list_unspent(0);
        let mine_op = utxos[0].outpoint.clone();

        let mine_input = TxIn {
            previous_output: mine_op,
            script_sig: Script::new(),
            sequence: 0xffffffff,
            witness: vec![],
        };
        let foreign_input = TxIn {
            previous_output: OutPoint {
                txid: Txid::ZERO,
                vout: 999,
            },
            script_sig: Script::new(),
            sequence: 0xffffffff,
            witness: vec![],
        };
        assert!(w.input_is_mine(&mine_input));
        assert!(!w.input_is_mine(&foreign_input));

        let tx_all_mine = Transaction::from_parts(2, vec![mine_input.clone()], vec![], 0);
        assert!(w.all_inputs_mine(&tx_all_mine));

        let tx_mixed = Transaction::from_parts(2, vec![mine_input, foreign_input], vec![], 0);
        assert!(!w.all_inputs_mine(&tx_mixed));
    }
}
