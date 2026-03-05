use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("message too large: {0} bytes")]
    MessageTooLarge(u32),
    #[error("invalid magic: expected {expected:#010x}, got {got:#010x}")]
    InvalidMagic { expected: u32, got: u32 },
    #[error("checksum mismatch")]
    ChecksumMismatch,
    #[error("unknown command: {0}")]
    UnknownCommand(String),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("connection closed")]
    ConnectionClosed,
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),
    #[error("peer misbehaving: {0}")]
    Misbehaving(String),
    #[error("DNS resolution failed: {0}")]
    DnsError(String),
    #[error("channel error")]
    ChannelError,
}

pub type Result<T> = std::result::Result<T, NetError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn net_error_display() {
        let _ = format!("{}", NetError::MessageTooLarge(100));
        let _ = format!(
            "{}",
            NetError::InvalidMagic {
                expected: 0,
                got: 1
            }
        );
        let _ = format!("{}", NetError::ChecksumMismatch);
        let _ = format!("{}", NetError::UnknownCommand("x".into()));
        let _ = format!("{}", NetError::Decode("x".into()));
        let _ = format!("{}", NetError::ConnectionClosed);
        let _ = format!("{}", NetError::HandshakeFailed("x".into()));
        let _ = format!("{}", NetError::Misbehaving("x".into()));
        let _ = format!("{}", NetError::DnsError("x".into()));
        let _ = format!("{}", NetError::ChannelError);
    }
}
