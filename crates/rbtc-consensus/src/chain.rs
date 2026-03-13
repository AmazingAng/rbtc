use std::collections::HashMap;

use rbtc_crypto::sha256d;
use rbtc_primitives::codec::Encodable;
use rbtc_primitives::uint256::U256;
use rbtc_primitives::{
    block::{Block, BlockHeader},
    block_status::BLOCK_VALID_TREE,
    constants::{DIFFICULTY_ADJUSTMENT_INTERVAL, MEDIAN_TIME_SPAN},
    hash::BlockHash,
    network::Network,
};

use crate::{
    difficulty::{bits_to_work, is_adjustment_height, next_bits_bip94},
    error::ConsensusError,
    tx_verify::MedianTimeProvider,
    utxo::UtxoSet,
};

// BlockStatus is now the bitflags struct from rbtc_primitives::block_status.
pub use rbtc_primitives::block_status::BlockStatus;

/// An entry in the block index (in-memory block tree)
#[derive(Debug, Clone)]
pub struct BlockIndex {
    pub hash: BlockHash,
    pub header: BlockHeader,
    pub height: u32,
    /// Cumulative chainwork up to and including this block
    pub chainwork: U256,
    pub status: BlockStatus,
}

impl BlockIndex {
    pub fn median_time_past<F>(&self, get_ancestor: &F) -> u32
    where
        F: Fn(u32) -> Option<u32>, // height -> timestamp
    {
        let start = self.height.saturating_sub(MEDIAN_TIME_SPAN as u32 - 1);
        let mut times: Vec<u32> = (start..=self.height).filter_map(get_ancestor).collect();
        times.sort_unstable();
        times.get(times.len() / 2).copied().unwrap_or(0)
    }
}

/// Full chain state manager
pub struct ChainState {
    pub network: Network,
    /// All known block headers
    pub block_index: HashMap<BlockHash, BlockIndex>,
    /// Best (most work) chain tip
    pub best_tip: Option<BlockHash>,
    /// Height-to-hash mapping for the active chain
    pub active_chain: Vec<BlockHash>,
    /// UTXO set
    pub utxos: UtxoSet,
}

impl ChainState {
    pub fn new(network: Network) -> Self {
        let mut chain = Self {
            network,
            block_index: HashMap::new(),
            best_tip: None,
            active_chain: Vec::new(),
            utxos: UtxoSet::new(),
        };
        // Seed the block index with the genesis header so that the first
        // headers-message from peers (which starts at block 1) can find its
        // parent.
        let _ = chain.add_header(network.genesis_header());
        chain
    }

    pub fn height(&self) -> u32 {
        self.active_chain.len().saturating_sub(1) as u32
    }

    pub fn best_hash(&self) -> Option<BlockHash> {
        self.best_tip
    }

    pub fn get_block_index(&self, hash: &BlockHash) -> Option<&BlockIndex> {
        self.block_index.get(hash)
    }

    pub fn get_ancestor_hash(&self, height: u32) -> Option<BlockHash> {
        self.active_chain.get(height as usize).copied()
    }

    pub fn get_ancestor_time(&self, height: u32) -> Option<u32> {
        let hash = self.active_chain.get(height as usize)?;
        self.block_index.get(hash).map(|bi| bi.header.time)
    }

    /// Compute MTP for the block at the given height
    pub fn median_time_past(&self, height: u32) -> u32 {
        let start = height.saturating_sub(MEDIAN_TIME_SPAN as u32 - 1);
        let mut times: Vec<u32> = (start..=height)
            .filter_map(|h| self.get_ancestor_time(h))
            .collect();
        times.sort_unstable();
        times.get(times.len() / 2).copied().unwrap_or(0)
    }

    /// Determine the required nBits for the next block after our best tip
    pub fn next_required_bits(&self) -> u32 {
        let tip = match self.best_tip.and_then(|h| self.block_index.get(&h)) {
            Some(bi) => bi,
            None => return 0x1d00ffff, // genesis / mainnet initial target
        };

        let next_height = tip.height + 1;

        if !is_adjustment_height(next_height) {
            return tip.header.bits;
        }

        // Find the block at the start of the current period
        let period_start_height = next_height - DIFFICULTY_ADJUSTMENT_INTERVAL as u32;
        let period_start_hash = match self.active_chain.get(period_start_height as usize) {
            Some(h) => h,
            None => return tip.header.bits,
        };
        let period_start = match self.block_index.get(period_start_hash) {
            Some(bi) => bi,
            None => return tip.header.bits,
        };

        let params = self.network.consensus_params();
        next_bits_bip94(&period_start.header, &tip.header, params.enforce_bip94, params.pow_target_timespan)
    }

    /// Add a block header to the index (does not connect it to the chain)
    pub fn add_header(&mut self, header: BlockHeader) -> Result<BlockHash, ConsensusError> {
        let hash = header_hash(&header);

        if self.block_index.contains_key(&hash) {
            return Ok(hash);
        }

        // Validate prev_block is known
        let (height, chainwork) = if hash == genesis_hash(self.network) {
            (0, bits_to_work(header.bits))
        } else {
            let parent = self
                .block_index
                .get(&header.prev_block)
                .ok_or_else(|| ConsensusError::UnknownParent(header.prev_block.to_hex()))?;
            let work = parent.chainwork.saturating_add(bits_to_work(header.bits));
            (parent.height + 1, work)
        };

        self.block_index.insert(
            hash,
            BlockIndex {
                hash,
                header,
                height,
                chainwork,
                status: BlockStatus::new().with_validity(BLOCK_VALID_TREE),
            },
        );

        Ok(hash)
    }

    /// Connect a validated block to the chain (updates UTXO set and active chain)
    pub fn connect_block(
        &mut self,
        block: &Block,
        block_hash: BlockHash,
    ) -> Result<(), ConsensusError> {
        let index = self
            .block_index
            .get(&block_hash)
            .ok_or(ConsensusError::UnknownParent(block_hash.to_hex()))?;
        let height = index.height;

        // Compute txids
        let txids: Vec<_> = block
            .transactions
            .iter()
            .map(|tx| {
                let mut buf = Vec::new();
                tx.encode_legacy(&mut buf).ok();
                rbtc_primitives::hash::Txid(sha256d(&buf))
            })
            .collect();

        // Update UTXO set
        self.utxos
            .connect_block(&txids, &block.transactions, height);

        // Update active chain
        if height as usize >= self.active_chain.len() {
            self.active_chain.resize(height as usize + 1, BlockHash::ZERO);
        }
        self.active_chain[height as usize] = block_hash;

        // Update best tip if this has more work
        let new_work = self.block_index[&block_hash].chainwork;
        let current_work = self
            .best_tip
            .and_then(|h| self.block_index.get(&h))
            .map(|bi| bi.chainwork)
            .unwrap_or(U256::ZERO);

        if new_work > current_work {
            self.best_tip = Some(block_hash);
        }

        Ok(())
    }

    /// Directly insert a BlockIndex entry (used when rebuilding from persistent storage).
    /// If `in_chain` is true, also updates active_chain and best_tip.
    pub fn insert_block_index(&mut self, hash: BlockHash, index: BlockIndex, in_chain: bool) {
        if in_chain {
            let h = index.height as usize;
            if h >= self.active_chain.len() {
                self.active_chain.resize(h + 1, BlockHash::ZERO);
            }
            self.active_chain[h] = hash;
            let cur_work = self
                .best_tip
                .and_then(|t| self.block_index.get(&t))
                .map(|bi| bi.chainwork)
                .unwrap_or(U256::ZERO);
            if index.chainwork > cur_work {
                self.best_tip = Some(hash);
            }
        }
        self.block_index.insert(hash, index);
    }

    /// Check if a block is in the active chain.
    pub fn is_in_active_chain(&self, hash: &BlockHash) -> bool {
        self.block_index
            .get(hash)
            .map(|bi| {
                let h = bi.height as usize;
                h < self.active_chain.len() && self.active_chain[h] == *hash
            })
            .unwrap_or(false)
    }

    /// Disconnect the tip block (for reorg)
    pub fn disconnect_tip(&mut self) -> Result<(), ConsensusError> {
        let tip_hash = self.best_tip.ok_or(ConsensusError::GenesisMismatch)?;
        let tip = self
            .block_index
            .get(&tip_hash)
            .ok_or(ConsensusError::GenesisMismatch)?;

        if tip.height == 0 {
            return Err(ConsensusError::GenesisMismatch);
        }

        let prev_hash = tip.header.prev_block;
        let height = tip.height;

        // Trim active chain
        self.active_chain.truncate(height as usize);
        self.best_tip = Some(prev_hash);

        Ok(())
    }
}

impl MedianTimeProvider for ChainState {
    fn median_time_past_at_height(&self, height: u32) -> u32 {
        self.median_time_past(height)
    }
}

impl crate::versionbits::VersionBitsBlockInfo for ChainState {
    fn median_time_past(&self, height: u32) -> u32 {
        ChainState::median_time_past(self, height)
    }

    fn block_version(&self, height: u32) -> i32 {
        self.active_chain
            .get(height as usize)
            .and_then(|hash| self.block_index.get(hash))
            .map(|bi| bi.header.version)
            .unwrap_or(1)
    }
}

pub fn header_hash(header: &BlockHeader) -> BlockHash {
    let mut buf = Vec::with_capacity(80);
    header.version.encode(&mut buf).ok();
    header.prev_block.0.0.encode(&mut buf).ok();
    header.merkle_root.0.encode(&mut buf).ok();
    header.time.encode(&mut buf).ok();
    header.bits.encode(&mut buf).ok();
    header.nonce.encode(&mut buf).ok();
    BlockHash(sha256d(&buf))
}

fn genesis_hash(network: Network) -> BlockHash {
    let hex = network.genesis_hash();
    BlockHash::from_hex(hex).unwrap_or(BlockHash::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::block_status::*;
    use rbtc_primitives::hash::Hash256;
    use rbtc_primitives::uint256::U256;

    fn status_valid_scripts_data() -> BlockStatus {
        BlockStatus::new()
            .with_validity(BLOCK_VALID_SCRIPTS)
            .with_data()
            .with_undo()
    }

    #[test]
    fn insert_block_index_in_chain_updates_active_chain_and_best_tip() {
        let mut chain = ChainState::new(Network::Regtest);
        let hash = BlockHash(Hash256([1; 32]));
        let index = BlockIndex {
            hash,
            header: BlockHeader {
                version: 1,
                prev_block: BlockHash::ZERO,
                merkle_root: Hash256::ZERO,
                time: 0,
                bits: 0,
                nonce: 0,
            },
            height: 0,
            chainwork: U256::from_u64(100),
            status: status_valid_scripts_data(),
        };
        chain.insert_block_index(hash, index, true);
        assert_eq!(chain.best_hash(), Some(hash));
        assert_eq!(chain.height(), 0);
        assert_eq!(chain.get_ancestor_hash(0), Some(hash));

        let hash2 = BlockHash(Hash256([2; 32]));
        let index2 = BlockIndex {
            hash: hash2,
            header: BlockHeader {
                version: 1,
                prev_block: hash,
                merkle_root: Hash256::ZERO,
                time: 1,
                bits: 0,
                nonce: 0,
            },
            height: 1,
            chainwork: U256::from_u64(200),
            status: status_valid_scripts_data(),
        };
        chain.insert_block_index(hash2, index2, true);
        assert_eq!(chain.best_hash(), Some(hash2));
        assert_eq!(chain.get_ancestor_hash(1), Some(hash2));
    }

    #[test]
    fn insert_block_index_non_in_chain_does_not_update_tip() {
        let mut chain = ChainState::new(Network::Regtest);
        let hash = BlockHash(Hash256([3; 32]));
        let index = BlockIndex {
            hash,
            header: BlockHeader {
                version: 1,
                prev_block: BlockHash::ZERO,
                merkle_root: Hash256::ZERO,
                time: 0,
                bits: 0,
                nonce: 0,
            },
            height: 0,
            chainwork: U256::from_u64(100),
            status: BlockStatus::new().with_validity(BLOCK_VALID_TREE),
        };
        chain.insert_block_index(hash, index, false);
        assert!(chain.best_hash().is_none());
    }

    #[test]
    fn block_index_median_time_past() {
        let bi = BlockIndex {
            hash: BlockHash::ZERO,
            header: BlockHeader {
                version: 1,
                prev_block: BlockHash::ZERO,
                merkle_root: Hash256::ZERO,
                time: 100,
                bits: 0,
                nonce: 0,
            },
            height: 10,
            chainwork: U256::ZERO,
            status: BlockStatus::new().with_validity(BLOCK_VALID_TREE),
        };
        let get_ts = |h: u32| Some(100 + h);
        let mtp = bi.median_time_past(&get_ts);
        assert!(mtp >= 100);
    }

    #[test]
    fn chain_state_new_height_best() {
        let chain = ChainState::new(Network::Regtest);
        assert_eq!(chain.height(), 0);
        assert!(chain.best_hash().is_none());
        assert!(chain.get_block_index(&BlockHash::ZERO).is_none());
        assert!(chain.get_ancestor_hash(0).is_none());
        assert!(chain.next_required_bits() > 0);
    }

    #[test]
    fn add_header_genesis() {
        let mut chain = ChainState::new(Network::Regtest);
        let genesis_hash_hex = chain.network.genesis_hash();
        let gh = BlockHash::from_hex(genesis_hash_hex).unwrap();
        let header = BlockHeader {
            version: 1,
            prev_block: BlockHash::ZERO,
            merkle_root: Hash256::ZERO,
            time: 1231006505,
            bits: 0x1d00ffff,
            nonce: 2083236893,
        };
        let h = header_hash(&header);
        if h == gh {
            let r = chain.add_header(header);
            assert!(r.is_ok());
        }
    }

    #[test]
    fn add_header_unknown_parent() {
        let mut chain = ChainState::new(Network::Regtest);
        let header = BlockHeader {
            version: 1,
            prev_block: BlockHash(Hash256([1; 32])),
            merkle_root: Hash256::ZERO,
            time: 1231006506,
            bits: 0x1d00ffff,
            nonce: 0,
        };
        let r = chain.add_header(header);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ConsensusError::UnknownParent(_)));
    }

    #[test]
    fn header_hash_smoke() {
        let header = BlockHeader {
            version: 1,
            prev_block: BlockHash::ZERO,
            merkle_root: Hash256::ZERO,
            time: 0,
            bits: 0,
            nonce: 0,
        };
        let h = header_hash(&header);
        assert_eq!(h.0.0.len(), 32);
    }

    #[test]
    fn disconnect_tip_no_tip() {
        let mut chain = ChainState::new(Network::Regtest);
        let r = chain.disconnect_tip();
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ConsensusError::GenesisMismatch));
    }

    #[test]
    fn genesis_header_hash_matches_all_networks() {
        for net in [
            Network::Mainnet,
            Network::Testnet4,
            Network::Regtest,
            Network::Signet,
        ] {
            let header = net.genesis_header();
            let computed = header_hash(&header);
            let expected = genesis_hash(net);
            assert_eq!(
                computed,
                expected,
                "{net}: computed={} expected={}",
                computed.to_hex(),
                expected.to_hex()
            );
        }
    }

    #[test]
    fn get_ancestor_time_and_median_time_past() {
        let mut chain = ChainState::new(Network::Regtest);
        let h0 = BlockHash(Hash256([10; 32]));
        let h1 = BlockHash(Hash256([11; 32]));
        chain.insert_block_index(
            h0,
            BlockIndex {
                hash: h0,
                header: BlockHeader {
                    version: 1,
                    prev_block: BlockHash::ZERO,
                    merkle_root: Hash256::ZERO,
                    time: 100,
                    bits: 0x1d00ffff,
                    nonce: 0,
                },
                height: 0,
                chainwork: U256::from_u64(1),
                status: status_valid_scripts_data(),
            },
            true,
        );
        chain.insert_block_index(
            h1,
            BlockIndex {
                hash: h1,
                header: BlockHeader {
                    version: 1,
                    prev_block: h0,
                    merkle_root: Hash256::ZERO,
                    time: 200,
                    bits: 0x1d00ffff,
                    nonce: 0,
                },
                height: 1,
                chainwork: U256::from_u64(2),
                status: status_valid_scripts_data(),
            },
            true,
        );
        assert_eq!(chain.get_ancestor_time(0), Some(100));
        assert_eq!(chain.get_ancestor_time(1), Some(200));
        assert_eq!(chain.median_time_past(1), 200);
    }

    #[test]
    fn next_required_bits_with_tip() {
        let mut chain = ChainState::new(Network::Regtest);
        let h0 = BlockHash(Hash256([20; 32]));
        chain.insert_block_index(
            h0,
            BlockIndex {
                hash: h0,
                header: BlockHeader {
                    version: 1,
                    prev_block: BlockHash::ZERO,
                    merkle_root: Hash256::ZERO,
                    time: 0,
                    bits: 0x1d00ffff,
                    nonce: 0,
                },
                height: 0,
                chainwork: U256::from_u64(1),
                status: status_valid_scripts_data(),
            },
            true,
        );
        assert_eq!(chain.next_required_bits(), 0x1d00ffff);
    }

    #[test]
    fn add_header_duplicate_returns_ok() {
        let mut chain = ChainState::new(Network::Regtest);
        let genesis_hash_hex = chain.network.genesis_hash();
        let gh = BlockHash::from_hex(genesis_hash_hex).unwrap();
        let header = BlockHeader {
            version: 1,
            prev_block: BlockHash::ZERO,
            merkle_root: Hash256::ZERO,
            time: 1231006505,
            bits: 0x1d00ffff,
            nonce: 2083236893,
        };
        let h = header_hash(&header);
        if h != gh {
            return;
        }
        let r1 = chain.add_header(header.clone());
        assert!(r1.is_ok());
        let r2 = chain.add_header(header);
        assert!(r2.is_ok());
        assert_eq!(r2.unwrap(), h);
    }
}
