//! BIP330/BIP331 transaction reconciliation (Erlay) stub.
//!
//! **Status**: stub adequate — full minisketch-based set reconciliation is
//! deferred.  This module provides the message types and a per-peer
//! `ReconciliationState` so that the handshake signalling (`sendtxrcncl`)
//! can be wired up and the protocol can be completed incrementally.
//!
//! The `sendtxrcncl` message is parsed/serialized in `message.rs` and
//! acknowledged (but not acted upon) in `peer_manager.rs`.

/// BIP330 reconciliation protocol version we support.
pub const RECON_VERSION: u32 = 1;

/// Per-peer reconciliation state.
#[derive(Debug, Clone)]
pub struct ReconciliationState {
    /// Whether the peer signalled `sendtxrcncl` and we accepted.
    pub enabled: bool,
    /// Protocol version negotiated with the peer (min of ours and theirs).
    pub version: u32,
    /// The peer's reconciliation salt (from their `sendtxrcncl` message).
    pub peer_salt: u64,
    /// Our reconciliation salt sent to the peer.
    pub local_salt: u64,
}

impl Default for ReconciliationState {
    fn default() -> Self {
        Self {
            enabled: false,
            version: 0,
            peer_salt: 0,
            local_salt: 0,
        }
    }
}

impl ReconciliationState {
    /// Create a new state after receiving the peer's `sendtxrcncl`.
    pub fn from_peer_signal(peer_version: u32, peer_salt: u64, local_salt: u64) -> Self {
        let negotiated = peer_version.min(RECON_VERSION);
        Self {
            enabled: negotiated >= 1,
            version: negotiated,
            peer_salt,
            local_salt,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_disabled() {
        let s = ReconciliationState::default();
        assert!(!s.enabled);
        assert_eq!(s.version, 0);
    }

    #[test]
    fn from_peer_signal_enables() {
        let s = ReconciliationState::from_peer_signal(1, 0xdeadbeef, 0xcafebabe);
        assert!(s.enabled);
        assert_eq!(s.version, 1);
        assert_eq!(s.peer_salt, 0xdeadbeef);
        assert_eq!(s.local_salt, 0xcafebabe);
    }

    #[test]
    fn version_negotiation_takes_min() {
        let s = ReconciliationState::from_peer_signal(5, 0, 0);
        assert_eq!(s.version, RECON_VERSION); // min(5, 1) = 1
        assert!(s.enabled);
    }

    #[test]
    fn version_zero_disables() {
        let s = ReconciliationState::from_peer_signal(0, 0, 0);
        assert!(!s.enabled);
        assert_eq!(s.version, 0);
    }

    #[test]
    fn sendtxrcncl_message_roundtrip() {
        use crate::message::NetworkMessage;
        let msg = NetworkMessage::SendTxRcncl {
            version: 1,
            salt: 0x1234567890abcdef,
        };
        assert_eq!(msg.command(), "sendtxrcncl");
        let payload = msg.encode_payload();
        assert_eq!(payload.len(), 12);
        let decoded = NetworkMessage::decode_payload("sendtxrcncl", &payload).unwrap();
        match decoded {
            NetworkMessage::SendTxRcncl { version, salt } => {
                assert_eq!(version, 1);
                assert_eq!(salt, 0x1234567890abcdef);
            }
            _ => panic!("expected SendTxRcncl"),
        }
    }
}
