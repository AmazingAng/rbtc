//! CValidationInterface-style notification system.
//!
//! This module provides two complementary notification mechanisms, matching
//! Bitcoin Core's `CValidationInterface` / `CMainSignals` pattern:
//!
//! 1. **Trait-based** (`ValidationInterface` + `ValidationSignals`): synchronous
//!    dispatch to registered listeners. Useful for tightly-coupled subsystems
//!    such as the wallet and indexes.
//!
//! 2. **Event-based** (`ValidationEvent` + `ValidationNotifier`): uses
//!    `tokio::sync::broadcast` channels for loosely-coupled, async consumers.
//!    Subscribers receive a cloned `ValidationEvent` enum and can process them
//!    independently without blocking the sender.

use std::fmt;
use std::sync::Arc;

use tokio::sync::broadcast;

use rbtc_primitives::block::{Block, BlockHeader};
use rbtc_primitives::hash::{BlockHash, Txid};
use rbtc_primitives::transaction::Transaction;

// ---------------------------------------------------------------------------
// MempoolRemovalReason
// ---------------------------------------------------------------------------

/// Reason a transaction was removed from the mempool.
///
/// Mirrors Bitcoin Core's `MemPoolRemovalReason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MempoolRemovalReason {
    /// Transaction expired (exceeded `-mempoolexpiry`).
    Expiry,
    /// Evicted to enforce the mempool size limit.
    SizeLimit,
    /// Removed during a chain reorganization.
    Reorg,
    /// Confirmed in a block.
    Block,
    /// Conflicts with an in-block transaction.
    Conflict,
    /// Replaced by a higher-fee transaction (BIP125 RBF).
    Replaced,
}

impl fmt::Display for MempoolRemovalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expiry => write!(f, "expiry"),
            Self::SizeLimit => write!(f, "sizelimit"),
            Self::Reorg => write!(f, "reorg"),
            Self::Block => write!(f, "block"),
            Self::Conflict => write!(f, "conflict"),
            Self::Replaced => write!(f, "replaced"),
        }
    }
}

// ---------------------------------------------------------------------------
// ValidationEvent
// ---------------------------------------------------------------------------

/// Events emitted by the validation subsystem.
///
/// Sent over `tokio::sync::broadcast` channels so that multiple independent
/// consumers (wallet, ZMQ, REST, logging) can subscribe without coupling.
#[derive(Debug, Clone)]
pub enum ValidationEvent {
    /// A block has been connected to the active chain.
    BlockConnected {
        block: Arc<Block>,
        height: u32,
    },
    /// A block has been disconnected from the active chain (reorg).
    BlockDisconnected {
        block: Arc<Block>,
        height: u32,
    },
    /// A transaction has been accepted into the mempool.
    TransactionAddedToMempool {
        txid: Txid,
    },
    /// A transaction has been removed from the mempool.
    TransactionRemovedFromMempool {
        txid: Txid,
        reason: MempoolRemovalReason,
    },
    /// The active chain tip has been updated.
    UpdatedBlockTip {
        hash: BlockHash,
        height: u32,
        is_ibd: bool,
    },
    /// Chain state has been flushed to disk.
    ChainStateFlushed {
        best_hash: BlockHash,
    },
}

// ---------------------------------------------------------------------------
// ValidationNotifier (broadcast-based)
// ---------------------------------------------------------------------------

/// Default channel capacity for the broadcast channel.
const DEFAULT_CHANNEL_CAPACITY: usize = 256;

/// Broadcast-based notification hub.
///
/// Holds a `tokio::sync::broadcast::Sender` and hands out receivers via
/// `subscribe()`. Lagging receivers are silently skipped (the broadcast
/// channel handles this with `RecvError::Lagged`).
pub struct ValidationNotifier {
    sender: broadcast::Sender<ValidationEvent>,
}

impl ValidationNotifier {
    /// Create a new notifier with the default channel capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CHANNEL_CAPACITY)
    }

    /// Create a new notifier with a custom channel capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Subscribe to validation events.
    ///
    /// Returns a `broadcast::Receiver` that will receive all events published
    /// after this call. Dropping the receiver is safe and will not block the
    /// notifier.
    pub fn subscribe(&self) -> broadcast::Receiver<ValidationEvent> {
        self.sender.subscribe()
    }

    /// Broadcast an event to all current subscribers.
    ///
    /// If there are no subscribers, the event is silently dropped.
    /// If any subscriber has lagged, the broadcast channel handles it
    /// automatically.
    pub fn notify(&self, event: ValidationEvent) {
        // send() returns Err only when there are zero receivers, which is fine.
        let _ = self.sender.send(event);
    }

    /// Return the number of active receivers.
    pub fn receiver_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

impl Default for ValidationNotifier {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ValidationInterface trait (synchronous, trait-object based)
// ---------------------------------------------------------------------------

/// Notification events from the validation subsystem.
/// Matches Bitcoin Core's `CValidationInterface`.
///
/// All methods have default (no-op) implementations so that listeners only
/// need to override the events they care about.
pub trait ValidationInterface: Send + Sync {
    /// Called when a new block is connected to the active chain.
    fn block_connected(&self, _block: &Block, _height: u32) {}

    /// Called when a block is disconnected from the active chain (reorg).
    fn block_disconnected(&self, _block: &Block, _height: u32) {}

    /// Called when a transaction is added to the mempool.
    fn transaction_added_to_mempool(&self, _tx: &Transaction) {}

    /// Called when a transaction is removed from the mempool.
    fn transaction_removed_from_mempool(&self, _tx: &Transaction) {}

    /// Called when the chain tip is updated.
    fn updated_block_tip(&self, _new_tip: &BlockHash, _height: u32, _initial_download: bool) {}

    /// Called when a new best block header is known.
    fn new_pow_valid_block(&self, _height: u32, _header: &BlockHeader) {}
}

// ---------------------------------------------------------------------------
// ValidationSignals dispatcher (trait-object based)
// ---------------------------------------------------------------------------

/// Dispatcher that maintains a list of registered listeners and
/// broadcasts events to all of them.
///
/// Analogous to Bitcoin Core's `CMainSignals`.
pub struct ValidationSignals {
    listeners: Vec<Box<dyn ValidationInterface>>,
}

impl ValidationSignals {
    /// Create a new dispatcher with no listeners.
    pub fn new() -> Self {
        Self {
            listeners: Vec::new(),
        }
    }

    /// Register a new listener.  It will receive all subsequent notifications.
    pub fn register(&mut self, listener: Box<dyn ValidationInterface>) {
        self.listeners.push(listener);
    }

    /// Remove all registered listeners.
    pub fn unregister_all(&mut self) {
        self.listeners.clear();
    }

    /// Return the number of currently registered listeners.
    pub fn listener_count(&self) -> usize {
        self.listeners.len()
    }

    // -- Broadcast helpers --------------------------------------------------

    /// Notify all listeners that a block has been connected.
    pub fn block_connected(&self, block: &Block, height: u32) {
        for listener in &self.listeners {
            listener.block_connected(block, height);
        }
    }

    /// Notify all listeners that a block has been disconnected.
    pub fn block_disconnected(&self, block: &Block, height: u32) {
        for listener in &self.listeners {
            listener.block_disconnected(block, height);
        }
    }

    /// Notify all listeners that a transaction was added to the mempool.
    pub fn transaction_added_to_mempool(&self, tx: &Transaction) {
        for listener in &self.listeners {
            listener.transaction_added_to_mempool(tx);
        }
    }

    /// Notify all listeners that a transaction was removed from the mempool.
    pub fn transaction_removed_from_mempool(&self, tx: &Transaction) {
        for listener in &self.listeners {
            listener.transaction_removed_from_mempool(tx);
        }
    }

    /// Notify all listeners that the chain tip has been updated.
    pub fn updated_block_tip(&self, new_tip: &BlockHash, height: u32, initial_download: bool) {
        for listener in &self.listeners {
            listener.updated_block_tip(new_tip, height, initial_download);
        }
    }

    /// Notify all listeners about a new PoW-valid block header.
    pub fn new_pow_valid_block(&self, height: u32, header: &BlockHeader) {
        for listener in &self.listeners {
            listener.new_pow_valid_block(height, header);
        }
    }
}

impl Default for ValidationSignals {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::block::{Block, BlockHeader};
    use rbtc_primitives::hash::{BlockHash, Hash256};
    use rbtc_primitives::transaction::{MutableTransaction, Transaction};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Helper: build a minimal block for testing.
    fn test_block() -> Block {
        Block::new(
            BlockHeader {
                version: 1,
                prev_block: BlockHash::ZERO,
                merkle_root: Hash256::ZERO,
                time: 0,
                bits: 0x1d00ffff,
                nonce: 0,
            },
            vec![],
        )
    }

    /// Helper: build a minimal transaction for testing.
    fn test_tx() -> Transaction {
        Transaction::from_mutable(MutableTransaction {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
        })
    }

    // =====================================================================
    // ValidationSignals (trait-based) tests
    // =====================================================================

    /// A test listener that counts how many times `block_connected` is called.
    struct CountingListener {
        count: Arc<AtomicUsize>,
    }

    impl ValidationInterface for CountingListener {
        fn block_connected(&self, _block: &Block, _height: u32) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn empty_dispatcher_no_panic() {
        let signals = ValidationSignals::new();
        let block = test_block();
        let tx = test_tx();
        let hash = BlockHash::ZERO;
        let header = block.header.clone();

        signals.block_connected(&block, 0);
        signals.block_disconnected(&block, 0);
        signals.transaction_added_to_mempool(&tx);
        signals.transaction_removed_from_mempool(&tx);
        signals.updated_block_tip(&hash, 0, false);
        signals.new_pow_valid_block(0, &header);
    }

    #[test]
    fn register_listener_count() {
        let mut signals = ValidationSignals::new();
        assert_eq!(signals.listener_count(), 0);

        let counter = Arc::new(AtomicUsize::new(0));
        signals.register(Box::new(CountingListener {
            count: counter.clone(),
        }));
        assert_eq!(signals.listener_count(), 1);

        signals.register(Box::new(CountingListener {
            count: counter.clone(),
        }));
        assert_eq!(signals.listener_count(), 2);
    }

    #[test]
    fn block_connected_notifies_all() {
        let mut signals = ValidationSignals::new();
        let counter = Arc::new(AtomicUsize::new(0));

        signals.register(Box::new(CountingListener {
            count: counter.clone(),
        }));
        signals.register(Box::new(CountingListener {
            count: counter.clone(),
        }));

        let block = test_block();
        signals.block_connected(&block, 100);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn unregister_all_clears() {
        let mut signals = ValidationSignals::new();
        let counter = Arc::new(AtomicUsize::new(0));

        signals.register(Box::new(CountingListener {
            count: counter.clone(),
        }));
        signals.register(Box::new(CountingListener {
            count: counter.clone(),
        }));
        assert_eq!(signals.listener_count(), 2);

        signals.unregister_all();
        assert_eq!(signals.listener_count(), 0);

        let block = test_block();
        signals.block_connected(&block, 0);
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    // =====================================================================
    // ValidationNotifier (broadcast-based) tests
    // =====================================================================

    #[tokio::test]
    async fn notifier_subscribe_and_receive_block_connected() {
        let notifier = ValidationNotifier::new();
        let mut rx = notifier.subscribe();

        let block = Arc::new(test_block());
        notifier.notify(ValidationEvent::BlockConnected {
            block: Arc::clone(&block),
            height: 42,
        });

        let event = rx.recv().await.expect("should receive event");
        match event {
            ValidationEvent::BlockConnected { block: b, height } => {
                assert_eq!(height, 42);
                assert_eq!(b.header.version, 1);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn notifier_multiple_subscribers_receive_same_event() {
        let notifier = ValidationNotifier::new();
        let mut rx1 = notifier.subscribe();
        let mut rx2 = notifier.subscribe();
        let mut rx3 = notifier.subscribe();

        assert_eq!(notifier.receiver_count(), 3);

        notifier.notify(ValidationEvent::UpdatedBlockTip {
            hash: BlockHash::ZERO,
            height: 100,
            is_ibd: true,
        });

        for rx in [&mut rx1, &mut rx2, &mut rx3] {
            let event = rx.recv().await.expect("should receive event");
            match event {
                ValidationEvent::UpdatedBlockTip {
                    height, is_ibd, ..
                } => {
                    assert_eq!(height, 100);
                    assert!(is_ibd);
                }
                other => panic!("unexpected event: {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn notifier_dropped_receiver_does_not_block() {
        let notifier = ValidationNotifier::new();
        let rx1 = notifier.subscribe();
        let mut rx2 = notifier.subscribe();
        assert_eq!(notifier.receiver_count(), 2);

        // Drop rx1 — should not prevent notify() from working.
        drop(rx1);

        notifier.notify(ValidationEvent::ChainStateFlushed {
            best_hash: BlockHash::ZERO,
        });

        let event = rx2.recv().await.expect("should receive event");
        match event {
            ValidationEvent::ChainStateFlushed { best_hash } => {
                assert_eq!(best_hash, BlockHash::ZERO);
            }
            other => panic!("unexpected event: {other:?}"),
        }

        assert_eq!(notifier.receiver_count(), 1);
    }

    #[tokio::test]
    async fn notifier_no_subscribers_no_panic() {
        let notifier = ValidationNotifier::new();
        // No subscribers — notify should silently succeed.
        notifier.notify(ValidationEvent::BlockConnected {
            block: Arc::new(test_block()),
            height: 0,
        });
    }

    #[tokio::test]
    async fn notifier_tx_added_to_mempool() {
        let notifier = ValidationNotifier::new();
        let mut rx = notifier.subscribe();

        let txid = Txid(Hash256::ZERO);
        notifier.notify(ValidationEvent::TransactionAddedToMempool { txid });

        let event = rx.recv().await.expect("should receive event");
        match event {
            ValidationEvent::TransactionAddedToMempool { txid: id } => {
                assert_eq!(id, txid);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn notifier_tx_removed_from_mempool() {
        let notifier = ValidationNotifier::new();
        let mut rx = notifier.subscribe();

        let txid = Txid(Hash256::ZERO);
        notifier.notify(ValidationEvent::TransactionRemovedFromMempool {
            txid,
            reason: MempoolRemovalReason::Replaced,
        });

        let event = rx.recv().await.expect("should receive event");
        match event {
            ValidationEvent::TransactionRemovedFromMempool { txid: id, reason } => {
                assert_eq!(id, txid);
                assert_eq!(reason, MempoolRemovalReason::Replaced);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn notifier_block_disconnected() {
        let notifier = ValidationNotifier::new();
        let mut rx = notifier.subscribe();

        let block = Arc::new(test_block());
        notifier.notify(ValidationEvent::BlockDisconnected {
            block: Arc::clone(&block),
            height: 99,
        });

        let event = rx.recv().await.expect("should receive event");
        match event {
            ValidationEvent::BlockDisconnected { height, .. } => {
                assert_eq!(height, 99);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    // =====================================================================
    // MempoolRemovalReason display tests
    // =====================================================================

    #[test]
    fn mempool_removal_reason_display() {
        assert_eq!(MempoolRemovalReason::Expiry.to_string(), "expiry");
        assert_eq!(MempoolRemovalReason::SizeLimit.to_string(), "sizelimit");
        assert_eq!(MempoolRemovalReason::Reorg.to_string(), "reorg");
        assert_eq!(MempoolRemovalReason::Block.to_string(), "block");
        assert_eq!(MempoolRemovalReason::Conflict.to_string(), "conflict");
        assert_eq!(MempoolRemovalReason::Replaced.to_string(), "replaced");
    }

    #[test]
    fn mempool_removal_reason_debug() {
        // Verify Debug derive works
        let reason = MempoolRemovalReason::Expiry;
        let dbg = format!("{reason:?}");
        assert!(dbg.contains("Expiry"));
    }
}
