use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("RocksDB error: {0}")]
    Rocks(#[from] rocksdb::Error),
    #[error("key not found")]
    NotFound,
    #[error("decode error: {0}")]
    Decode(String),
    #[error("encode error: {0}")]
    Encode(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("corruption: {0}")]
    Corruption(String),
}

pub type Result<T> = std::result::Result<T, StorageError>;
