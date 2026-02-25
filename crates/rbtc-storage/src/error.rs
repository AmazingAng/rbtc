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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_error_display() {
        let _ = format!("{}", StorageError::NotFound);
        let _ = format!("{}", StorageError::Decode("bad".into()));
        let _ = format!("{}", StorageError::Encode("bad".into()));
        let _ = format!("{}", StorageError::Corruption("x".into()));
    }
}
