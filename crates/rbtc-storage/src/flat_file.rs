//! Flat file block storage (`blk*.dat` / `rev*.dat`), matching Bitcoin Core's
//! `FlatFilePos` and `BlockManager` layout.
//!
//! Each `blk*.dat` entry: `[network_magic:4][block_size:4][block_bytes:N]`
//! Each `rev*.dat` entry: `[undo_size:4][undo_bytes:N]`
//!
//! Files are rotated when they would exceed [`MAX_BLOCKFILE_SIZE`] (128 MiB).

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::{Result, StorageError};

/// Maximum size of a single block file before rotation (128 MiB).
pub const MAX_BLOCKFILE_SIZE: u64 = 0x0800_0000; // 128 MiB

/// Pre-allocation chunk size for block files (16 MiB).
pub const BLOCKFILE_CHUNK_SIZE: u64 = 0x0100_0000; // 16 MiB

/// Pre-allocation chunk size for undo files (1 MiB).
pub const UNDOFILE_CHUNK_SIZE: u64 = 0x0010_0000; // 1 MiB

/// 8-byte storage header before each block: 4-byte magic + 4-byte size.
pub const STORAGE_HEADER_BYTES: u64 = 8;

/// Position within the flat file set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlatFilePos {
    /// File number (0 → blk00000.dat, 1 → blk00001.dat, …)
    pub file: u32,
    /// Byte offset within the file where the data starts.
    /// For block files this points to the *block bytes* (after the 8-byte header).
    pub pos: u64,
}

impl FlatFilePos {
    pub const NULL: Self = Self {
        file: u32::MAX,
        pos: 0,
    };

    pub fn is_null(&self) -> bool {
        self.file == u32::MAX
    }

    /// Encode to 12 bytes: file(4 LE) + pos(8 LE).
    pub fn encode(&self) -> [u8; 12] {
        let mut buf = [0u8; 12];
        buf[0..4].copy_from_slice(&self.file.to_le_bytes());
        buf[4..12].copy_from_slice(&self.pos.to_le_bytes());
        buf
    }

    /// Decode from 12 bytes.
    pub fn decode(bytes: &[u8; 12]) -> Self {
        let file = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let pos = u64::from_le_bytes([
            bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
        ]);
        Self { file, pos }
    }
}

/// Per-file metadata tracking.
#[derive(Debug, Clone)]
pub struct BlockFileInfo {
    /// Number of blocks stored in this file.
    pub num_blocks: u32,
    /// Current size used in the block file (bytes).
    pub size: u64,
    /// Current size used in the corresponding undo file (bytes).
    pub undo_size: u64,
    /// Lowest block height in this file.
    pub height_first: u32,
    /// Highest block height in this file.
    pub height_last: u32,
}

impl BlockFileInfo {
    pub fn new() -> Self {
        Self {
            num_blocks: 0,
            size: 0,
            undo_size: 0,
            height_first: u32::MAX,
            height_last: 0,
        }
    }

    /// Encode to bytes for DB persistence.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(28);
        buf.extend_from_slice(&self.num_blocks.to_le_bytes());
        buf.extend_from_slice(&self.size.to_le_bytes());
        buf.extend_from_slice(&self.undo_size.to_le_bytes());
        buf.extend_from_slice(&self.height_first.to_le_bytes());
        buf.extend_from_slice(&self.height_last.to_le_bytes());
        buf
    }

    /// Decode from bytes.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 28 {
            return None;
        }
        Some(Self {
            num_blocks: u32::from_le_bytes(bytes[0..4].try_into().ok()?),
            size: u64::from_le_bytes(bytes[4..12].try_into().ok()?),
            undo_size: u64::from_le_bytes(bytes[12..20].try_into().ok()?),
            height_first: u32::from_le_bytes(bytes[20..24].try_into().ok()?),
            height_last: u32::from_le_bytes(bytes[24..28].try_into().ok()?),
        })
    }
}

/// Manages flat file block and undo storage.
pub struct FlatFileStore {
    /// Directory containing blk*.dat and rev*.dat files.
    blocks_dir: PathBuf,
    /// 4-byte network magic prepended to each block entry.
    network_magic: [u8; 4],
    /// Current block file number being written to.
    current_file: u32,
    /// Per-file metadata (indexed by file number).
    file_info: Vec<BlockFileInfo>,
}

impl FlatFileStore {
    /// Open or create a flat file store in `blocks_dir`.
    pub fn new(blocks_dir: &Path, network_magic: [u8; 4]) -> Result<Self> {
        fs::create_dir_all(blocks_dir)?;
        Ok(Self {
            blocks_dir: blocks_dir.to_path_buf(),
            network_magic,
            current_file: 0,
            file_info: vec![BlockFileInfo::new()],
        })
    }

    /// Restore state from previously persisted file info entries.
    pub fn restore(&mut self, file_infos: Vec<BlockFileInfo>, current_file: u32) {
        self.file_info = file_infos;
        self.current_file = current_file;
        // Ensure we have at least an entry for current_file
        while self.file_info.len() <= self.current_file as usize {
            self.file_info.push(BlockFileInfo::new());
        }
    }

    /// Current file number.
    pub fn current_file_number(&self) -> u32 {
        self.current_file
    }

    /// Get file info for a specific file number.
    pub fn file_info(&self, file: u32) -> Option<&BlockFileInfo> {
        self.file_info.get(file as usize)
    }

    /// All file info entries (for persistence).
    pub fn all_file_info(&self) -> &[BlockFileInfo] {
        &self.file_info
    }

    fn blk_path(&self, file_num: u32) -> PathBuf {
        self.blocks_dir.join(format!("blk{:05}.dat", file_num))
    }

    fn rev_path(&self, file_num: u32) -> PathBuf {
        self.blocks_dir.join(format!("rev{:05}.dat", file_num))
    }

    /// Find the next position for a block of `block_size` bytes.
    /// Rotates to a new file if the current one would exceed MAX_BLOCKFILE_SIZE.
    fn find_next_block_pos(&mut self, block_size: u64) -> FlatFilePos {
        let total_needed = STORAGE_HEADER_BYTES + block_size;
        let info = &self.file_info[self.current_file as usize];

        if info.size + total_needed > MAX_BLOCKFILE_SIZE && info.num_blocks > 0 {
            // Rotate to next file
            self.current_file += 1;
            if self.file_info.len() <= self.current_file as usize {
                self.file_info.push(BlockFileInfo::new());
            }
        }

        let pos = self.file_info[self.current_file as usize].size + STORAGE_HEADER_BYTES;
        FlatFilePos {
            file: self.current_file,
            pos,
        }
    }

    /// Write a block to the flat file store.
    /// Returns the `FlatFilePos` where the block data starts.
    pub fn write_block(&mut self, block_bytes: &[u8], height: u32) -> Result<FlatFilePos> {
        let block_size = block_bytes.len() as u64;
        let flat_pos = self.find_next_block_pos(block_size);

        let path = self.blk_path(flat_pos.file);
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(&path)?;

        // Seek to the write position (start of header = pos - STORAGE_HEADER_BYTES)
        let header_offset = flat_pos.pos - STORAGE_HEADER_BYTES;
        file.seek(SeekFrom::Start(header_offset))?;

        // Write: [magic:4][size:4][block_bytes:N]
        file.write_all(&self.network_magic)?;
        file.write_all(&(block_size as u32).to_le_bytes())?;
        file.write_all(block_bytes)?;
        file.flush()?;

        // Update file info
        let info = &mut self.file_info[flat_pos.file as usize];
        info.size = flat_pos.pos + block_size;
        info.num_blocks += 1;
        if height < info.height_first {
            info.height_first = height;
        }
        if height > info.height_last {
            info.height_last = height;
        }

        Ok(flat_pos)
    }

    /// Read a block from the flat file store.
    /// `pos` should point to the block data (after the 8-byte header).
    pub fn read_block(&self, pos: &FlatFilePos) -> Result<Vec<u8>> {
        let path = self.blk_path(pos.file);
        let mut file = File::open(&path).map_err(|e| {
            StorageError::Io(std::io::Error::new(
                e.kind(),
                format!("cannot open {}: {}", path.display(), e),
            ))
        })?;

        // Seek to the size field (4 bytes before data)
        let size_offset = pos.pos - 4; // skip magic, read size
        file.seek(SeekFrom::Start(size_offset))?;
        let mut size_buf = [0u8; 4];
        file.read_exact(&mut size_buf)?;
        let block_size = u32::from_le_bytes(size_buf) as usize;

        let mut block_bytes = vec![0u8; block_size];
        file.read_exact(&mut block_bytes)?;
        Ok(block_bytes)
    }

    /// Write undo data for a block.
    /// Returns the `FlatFilePos` in the undo file.
    pub fn write_undo(&mut self, file_num: u32, undo_bytes: &[u8]) -> Result<FlatFilePos> {
        while self.file_info.len() <= file_num as usize {
            self.file_info.push(BlockFileInfo::new());
        }

        let undo_size = undo_bytes.len() as u64;
        let info = &self.file_info[file_num as usize];
        let write_offset = info.undo_size;

        let path = self.rev_path(file_num);
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(&path)?;

        file.seek(SeekFrom::Start(write_offset))?;
        // Write: [size:4][undo_bytes:N]
        file.write_all(&(undo_size as u32).to_le_bytes())?;
        file.write_all(undo_bytes)?;
        file.flush()?;

        let data_pos = write_offset + 4; // position of actual undo data
        self.file_info[file_num as usize].undo_size = data_pos + undo_size;

        Ok(FlatFilePos {
            file: file_num,
            pos: data_pos,
        })
    }

    /// Read undo data from the flat file store.
    pub fn read_undo(&self, pos: &FlatFilePos) -> Result<Vec<u8>> {
        let path = self.rev_path(pos.file);
        let mut file = File::open(&path).map_err(|e| {
            StorageError::Io(std::io::Error::new(
                e.kind(),
                format!("cannot open {}: {}", path.display(), e),
            ))
        })?;

        // Read size (4 bytes before data)
        let size_offset = pos.pos - 4;
        file.seek(SeekFrom::Start(size_offset))?;
        let mut size_buf = [0u8; 4];
        file.read_exact(&mut size_buf)?;
        let undo_size = u32::from_le_bytes(size_buf) as usize;

        let mut undo_bytes = vec![0u8; undo_size];
        file.read_exact(&mut undo_bytes)?;
        Ok(undo_bytes)
    }

    /// Check if a block file exists on disk.
    pub fn has_block_file(&self, file_num: u32) -> bool {
        self.blk_path(file_num).exists()
    }

    /// Delete block files whose blocks are all below `below_height`.
    ///
    /// For each tracked file, if `height_last < below_height` the corresponding
    /// `blk*.dat` (and its `rev*.dat` undo file, if present) are removed from
    /// disk, the `BlockFileInfo` is zeroed out, and the file is counted as
    /// pruned.  The current write-file is never pruned.
    ///
    /// Returns the number of files deleted.
    pub fn prune_block_files(&mut self, below_height: u32) -> Result<usize> {
        let mut pruned = 0usize;
        for file_num in 0..self.file_info.len() as u32 {
            // Never prune the file we are currently writing to.
            if file_num == self.current_file {
                continue;
            }
            let info = &self.file_info[file_num as usize];
            // Skip empty / already-pruned files.
            if info.num_blocks == 0 {
                continue;
            }
            if info.height_last >= below_height {
                continue;
            }
            // All blocks in this file are below the target height — delete.
            let blk = self.blk_path(file_num);
            if blk.exists() {
                fs::remove_file(&blk)?;
            }
            let rev = self.rev_path(file_num);
            if rev.exists() {
                fs::remove_file(&rev)?;
            }
            // Reset the file info.
            self.file_info[file_num as usize] = BlockFileInfo::new();
            pruned += 1;
        }
        Ok(pruned)
    }

    /// Auto-prune oldest block files until total on-disk size is at or below
    /// `target_size_bytes`.
    ///
    /// Files are pruned in ascending order of `height_last` (oldest first).
    /// The current write-file is never pruned.  Returns the number of files
    /// deleted.
    pub fn auto_prune(&mut self, target_size_bytes: u64) -> Result<usize> {
        // Collect (file_num, height_last, file_size) for prunable files.
        let mut candidates: Vec<(u32, u32, u64)> = Vec::new();
        let mut total_size: u64 = 0;
        for (i, info) in self.file_info.iter().enumerate() {
            if info.num_blocks == 0 {
                continue;
            }
            total_size += info.size + info.undo_size;
            if i as u32 != self.current_file {
                candidates.push((i as u32, info.height_last, info.size + info.undo_size));
            }
        }
        if total_size <= target_size_bytes {
            return Ok(0);
        }
        // Sort by height_last ascending (oldest first).
        candidates.sort_by_key(|&(_, height_last, _)| height_last);

        let mut pruned = 0usize;
        for (file_num, _, file_size) in candidates {
            if total_size <= target_size_bytes {
                break;
            }
            let blk = self.blk_path(file_num);
            if blk.exists() {
                fs::remove_file(&blk)?;
            }
            let rev = self.rev_path(file_num);
            if rev.exists() {
                fs::remove_file(&rev)?;
            }
            total_size = total_size.saturating_sub(file_size);
            self.file_info[file_num as usize] = BlockFileInfo::new();
            pruned += 1;
        }
        Ok(pruned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_magic() -> [u8; 4] {
        [0xf9, 0xbe, 0xb4, 0xd9] // mainnet
    }

    #[test]
    fn flat_file_pos_encode_decode_roundtrip() {
        let pos = FlatFilePos { file: 42, pos: 1234567 };
        let encoded = pos.encode();
        let decoded = FlatFilePos::decode(&encoded);
        assert_eq!(decoded, pos);
    }

    #[test]
    fn flat_file_pos_null() {
        assert!(FlatFilePos::NULL.is_null());
        let pos = FlatFilePos { file: 0, pos: 0 };
        assert!(!pos.is_null());
    }

    #[test]
    fn block_file_info_encode_decode_roundtrip() {
        let info = BlockFileInfo {
            num_blocks: 100,
            size: 50_000_000,
            undo_size: 10_000_000,
            height_first: 0,
            height_last: 99,
        };
        let encoded = info.encode();
        let decoded = BlockFileInfo::decode(&encoded).unwrap();
        assert_eq!(decoded.num_blocks, 100);
        assert_eq!(decoded.size, 50_000_000);
        assert_eq!(decoded.undo_size, 10_000_000);
        assert_eq!(decoded.height_first, 0);
        assert_eq!(decoded.height_last, 99);
    }

    #[test]
    fn block_file_info_decode_too_short() {
        assert!(BlockFileInfo::decode(&[0; 10]).is_none());
    }

    #[test]
    fn write_and_read_block() {
        let dir = TempDir::new().unwrap();
        let mut store = FlatFileStore::new(dir.path(), test_magic()).unwrap();
        let block_data = b"fake block data for testing purposes";
        let pos = store.write_block(block_data, 0).unwrap();
        assert_eq!(pos.file, 0);
        assert_eq!(pos.pos, STORAGE_HEADER_BYTES); // first block starts right after header
        let read_back = store.read_block(&pos).unwrap();
        assert_eq!(read_back, block_data);
    }

    #[test]
    fn write_multiple_blocks_sequential() {
        let dir = TempDir::new().unwrap();
        let mut store = FlatFileStore::new(dir.path(), test_magic()).unwrap();

        let data1 = vec![0xAA; 100];
        let data2 = vec![0xBB; 200];
        let data3 = vec![0xCC; 50];

        let pos1 = store.write_block(&data1, 0).unwrap();
        let pos2 = store.write_block(&data2, 1).unwrap();
        let pos3 = store.write_block(&data3, 2).unwrap();

        assert_eq!(pos1.file, 0);
        assert_eq!(pos2.file, 0);
        assert_eq!(pos3.file, 0);

        // Positions should be sequential
        assert_eq!(pos1.pos, 8);
        assert_eq!(pos2.pos, 8 + 100 + 8); // after first block + next header
        assert_eq!(pos3.pos, 8 + 100 + 8 + 200 + 8);

        assert_eq!(store.read_block(&pos1).unwrap(), data1);
        assert_eq!(store.read_block(&pos2).unwrap(), data2);
        assert_eq!(store.read_block(&pos3).unwrap(), data3);
    }

    #[test]
    fn file_rotation_at_max_size() {
        let dir = TempDir::new().unwrap();
        let mut store = FlatFileStore::new(dir.path(), test_magic()).unwrap();

        // Write a block that nearly fills the file
        let big_block = vec![0xFF; (MAX_BLOCKFILE_SIZE - STORAGE_HEADER_BYTES - 1) as usize];
        let pos1 = store.write_block(&big_block, 0).unwrap();
        assert_eq!(pos1.file, 0);

        // Next block should go to file 1 since file 0 can't fit it
        let small_block = vec![0x11; 100];
        let pos2 = store.write_block(&small_block, 1).unwrap();
        assert_eq!(pos2.file, 1);
        assert_eq!(pos2.pos, STORAGE_HEADER_BYTES);

        // Verify both are readable
        assert_eq!(store.read_block(&pos1).unwrap(), big_block);
        assert_eq!(store.read_block(&pos2).unwrap(), small_block);
    }

    #[test]
    fn write_and_read_undo() {
        let dir = TempDir::new().unwrap();
        let mut store = FlatFileStore::new(dir.path(), test_magic()).unwrap();

        let undo_data = b"spent utxo undo data";
        let pos = store.write_undo(0, undo_data).unwrap();
        assert_eq!(pos.file, 0);
        assert_eq!(pos.pos, 4); // after 4-byte size prefix

        let read_back = store.read_undo(&pos).unwrap();
        assert_eq!(read_back, undo_data);
    }

    #[test]
    fn write_multiple_undo_entries() {
        let dir = TempDir::new().unwrap();
        let mut store = FlatFileStore::new(dir.path(), test_magic()).unwrap();

        let undo1 = vec![0x01; 64];
        let undo2 = vec![0x02; 128];

        let pos1 = store.write_undo(0, &undo1).unwrap();
        let pos2 = store.write_undo(0, &undo2).unwrap();

        assert_eq!(pos1.pos, 4);
        assert_eq!(pos2.pos, 4 + 64 + 4); // after first undo + size prefix

        assert_eq!(store.read_undo(&pos1).unwrap(), undo1);
        assert_eq!(store.read_undo(&pos2).unwrap(), undo2);
    }

    #[test]
    fn blk_file_naming() {
        let dir = TempDir::new().unwrap();
        let store = FlatFileStore::new(dir.path(), test_magic()).unwrap();
        assert_eq!(
            store.blk_path(0).file_name().unwrap().to_str().unwrap(),
            "blk00000.dat"
        );
        assert_eq!(
            store.blk_path(42).file_name().unwrap().to_str().unwrap(),
            "blk00042.dat"
        );
        assert_eq!(
            store.rev_path(7).file_name().unwrap().to_str().unwrap(),
            "rev00007.dat"
        );
    }

    #[test]
    fn has_block_file() {
        let dir = TempDir::new().unwrap();
        let mut store = FlatFileStore::new(dir.path(), test_magic()).unwrap();
        assert!(!store.has_block_file(0));
        store.write_block(b"data", 0).unwrap();
        assert!(store.has_block_file(0));
        assert!(!store.has_block_file(1));
    }

    #[test]
    fn restore_state() {
        let dir = TempDir::new().unwrap();
        let mut store = FlatFileStore::new(dir.path(), test_magic()).unwrap();

        // Write some blocks
        store.write_block(&vec![0xAA; 100], 0).unwrap();
        store.write_block(&vec![0xBB; 200], 1).unwrap();

        // Save state
        let saved_info: Vec<BlockFileInfo> = store.all_file_info().to_vec();
        let saved_file = store.current_file_number();

        // Create new store and restore
        let mut store2 = FlatFileStore::new(dir.path(), test_magic()).unwrap();
        store2.restore(saved_info, saved_file);

        // Next write should continue at correct offset
        let pos = store2.write_block(&vec![0xCC; 50], 2).unwrap();
        assert_eq!(pos.file, 0);
        // Should be after the two existing blocks
        assert_eq!(pos.pos, 8 + 100 + 8 + 200 + 8);

        // Should be readable
        assert_eq!(store2.read_block(&pos).unwrap(), vec![0xCC; 50]);
    }

    #[test]
    fn read_nonexistent_file_errors() {
        let dir = TempDir::new().unwrap();
        let store = FlatFileStore::new(dir.path(), test_magic()).unwrap();
        let pos = FlatFilePos { file: 99, pos: 8 };
        assert!(store.read_block(&pos).is_err());
    }

    #[test]
    fn file_info_height_tracking() {
        let dir = TempDir::new().unwrap();
        let mut store = FlatFileStore::new(dir.path(), test_magic()).unwrap();

        store.write_block(b"b1", 100).unwrap();
        store.write_block(b"b2", 50).unwrap();
        store.write_block(b"b3", 200).unwrap();

        let info = store.file_info(0).unwrap();
        assert_eq!(info.height_first, 50);
        assert_eq!(info.height_last, 200);
        assert_eq!(info.num_blocks, 3);
    }

    #[test]
    fn empty_block_data() {
        let dir = TempDir::new().unwrap();
        let mut store = FlatFileStore::new(dir.path(), test_magic()).unwrap();
        let pos = store.write_block(b"", 0).unwrap();
        let read_back = store.read_block(&pos).unwrap();
        assert!(read_back.is_empty());
    }

    // ── M13: Block pruning tests ─────────────────────────────────────

    #[test]
    fn prune_block_files_deletes_old_files() {
        let dir = TempDir::new().unwrap();
        let mut store = FlatFileStore::new(dir.path(), test_magic()).unwrap();

        // Fill file 0 so it rotates to file 1
        let big = vec![0xAA; (MAX_BLOCKFILE_SIZE - STORAGE_HEADER_BYTES - 1) as usize];
        store.write_block(&big, 10).unwrap(); // file 0, height 10
        store.write_block(b"new block", 200).unwrap(); // file 1, height 200

        assert!(store.has_block_file(0));
        assert!(store.has_block_file(1));
        assert_eq!(store.current_file_number(), 1);

        // Prune files with all blocks below height 100 — should remove file 0
        let pruned = store.prune_block_files(100).unwrap();
        assert_eq!(pruned, 1);
        assert!(!store.has_block_file(0));
        // file 1 (current, height_last=200) should survive
        assert!(store.has_block_file(1));
        // file_info for 0 should be reset
        let info0 = store.file_info(0).unwrap();
        assert_eq!(info0.num_blocks, 0);
    }

    #[test]
    fn prune_block_files_keeps_files_above_height() {
        let dir = TempDir::new().unwrap();
        let mut store = FlatFileStore::new(dir.path(), test_magic()).unwrap();

        let big = vec![0xBB; (MAX_BLOCKFILE_SIZE - STORAGE_HEADER_BYTES - 1) as usize];
        store.write_block(&big, 500).unwrap(); // file 0
        store.write_block(b"data", 600).unwrap(); // file 1

        // Prune below 100 — file 0 has height_last=500, so nothing should be pruned
        let pruned = store.prune_block_files(100).unwrap();
        assert_eq!(pruned, 0);
        assert!(store.has_block_file(0));
    }

    #[test]
    fn prune_block_files_also_removes_undo() {
        let dir = TempDir::new().unwrap();
        let mut store = FlatFileStore::new(dir.path(), test_magic()).unwrap();

        let big = vec![0xCC; (MAX_BLOCKFILE_SIZE - STORAGE_HEADER_BYTES - 1) as usize];
        store.write_block(&big, 5).unwrap(); // file 0
        store.write_undo(0, b"undo for file 0").unwrap();
        store.write_block(b"data", 100).unwrap(); // file 1

        assert!(store.rev_path(0).exists());
        let pruned = store.prune_block_files(50).unwrap();
        assert_eq!(pruned, 1);
        assert!(!store.blk_path(0).exists());
        assert!(!store.rev_path(0).exists());
    }

    #[test]
    fn auto_prune_removes_oldest_first() {
        let dir = TempDir::new().unwrap();
        let mut store = FlatFileStore::new(dir.path(), test_magic()).unwrap();

        // Create 3 files by forcing rotation
        let big = vec![0xDD; (MAX_BLOCKFILE_SIZE - STORAGE_HEADER_BYTES - 1) as usize];
        store.write_block(&big, 10).unwrap();  // file 0
        store.write_block(&big, 20).unwrap();  // file 1
        store.write_block(b"small", 30).unwrap(); // file 2 (current)

        assert_eq!(store.current_file_number(), 2);
        assert!(store.has_block_file(0));
        assert!(store.has_block_file(1));

        // Target size smaller than one big file — should prune file 0 (oldest)
        let pruned = store.auto_prune(MAX_BLOCKFILE_SIZE).unwrap();
        assert!(pruned >= 1);
        assert!(!store.has_block_file(0));
        // file 2 (current) always survives
        assert!(store.has_block_file(2));
    }

    #[test]
    fn auto_prune_noop_when_under_target() {
        let dir = TempDir::new().unwrap();
        let mut store = FlatFileStore::new(dir.path(), test_magic()).unwrap();
        store.write_block(b"tiny", 1).unwrap();
        // Target is huge — nothing to prune
        let pruned = store.auto_prune(u64::MAX).unwrap();
        assert_eq!(pruned, 0);
    }
}
