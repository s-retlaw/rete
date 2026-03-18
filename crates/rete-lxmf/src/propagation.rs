//! LXMF Propagation Node — store-and-forward message relay.
//!
//! A propagation node accepts LXMF messages via deposit (Link+Resource),
//! stores them keyed by destination hash, and delivers them when the
//! recipient connects to retrieve, or when the recipient announces and
//! the node can forward directly.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::vec::Vec;

use rete_core::TRUNCATED_HASH_LEN;

// ---------------------------------------------------------------------------
// MessageStore trait + InMemoryMessageStore
// ---------------------------------------------------------------------------

/// Trait for storing LXMF messages in a propagation node.
///
/// Implementations may use in-memory storage, file-backed storage,
/// or database-backed storage depending on the platform.
pub trait MessageStore {
    /// Store a message. Returns true if the message was newly stored,
    /// false if it was already present (dedup by message_hash).
    fn store(
        &mut self,
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        message_hash: [u8; 32],
        data: Vec<u8>,
        timestamp: u64,
    ) -> bool;

    /// Retrieve all pending messages for a destination.
    fn retrieve(&self, dest_hash: &[u8; TRUNCATED_HASH_LEN]) -> Vec<StoredMessage>;

    /// Mark a message as delivered (remove from store).
    fn mark_delivered(&mut self, message_hash: &[u8; 32]) -> bool;

    /// Remove messages older than `max_age_secs` from `now`.
    /// Returns the number of messages pruned.
    fn prune(&mut self, now: u64, max_age_secs: u64) -> usize;

    /// Return all destination hashes that have pending messages.
    fn destinations_with_messages(&self) -> Vec<[u8; TRUNCATED_HASH_LEN]>;

    /// Count of all stored messages.
    fn message_count(&self) -> usize;

    /// Count messages for a specific destination (without cloning).
    fn count_for(&self, dest_hash: &[u8; TRUNCATED_HASH_LEN]) -> usize;

    /// Look up a stored message's data by its hash. Returns a reference
    /// to the packed message bytes without cloning.
    fn get_data(&self, message_hash: &[u8; 32]) -> Option<&[u8]>;
}

/// A stored LXMF message.
#[derive(Debug, Clone)]
pub struct StoredMessage {
    /// Destination hash this message is addressed to.
    pub dest_hash: [u8; TRUNCATED_HASH_LEN],
    /// SHA-256 hash of the packed message.
    pub message_hash: [u8; 32],
    /// The full packed LXMF message bytes.
    pub data: Vec<u8>,
    /// Timestamp when the message was deposited (unix epoch seconds).
    pub timestamp: u64,
}

/// In-memory message store for propagation nodes.
///
/// Suitable for desktop/server nodes. Embedded targets may need
/// a flash-backed implementation.
#[derive(Debug, Default)]
pub struct InMemoryMessageStore {
    /// Messages indexed by message_hash for dedup.
    messages: HashMap<[u8; 32], StoredMessage>,
    /// Index: dest_hash -> set of message_hashes.
    by_dest: HashMap<[u8; TRUNCATED_HASH_LEN], Vec<[u8; 32]>>,
}

impl InMemoryMessageStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl MessageStore for InMemoryMessageStore {
    fn store(
        &mut self,
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        message_hash: [u8; 32],
        data: Vec<u8>,
        timestamp: u64,
    ) -> bool {
        if self.messages.contains_key(&message_hash) {
            return false; // Dedup: already stored
        }

        let msg = StoredMessage {
            dest_hash,
            message_hash,
            data,
            timestamp,
        };

        self.messages.insert(message_hash, msg);
        self.by_dest
            .entry(dest_hash)
            .or_default()
            .push(message_hash);
        true
    }

    fn retrieve(&self, dest_hash: &[u8; TRUNCATED_HASH_LEN]) -> Vec<StoredMessage> {
        match self.by_dest.get(dest_hash) {
            Some(hashes) => hashes
                .iter()
                .filter_map(|h| self.messages.get(h).cloned())
                .collect(),
            None => Vec::new(),
        }
    }

    fn mark_delivered(&mut self, message_hash: &[u8; 32]) -> bool {
        if let Some(msg) = self.messages.remove(message_hash) {
            if let Some(hashes) = self.by_dest.get_mut(&msg.dest_hash) {
                hashes.retain(|h| h != message_hash);
                if hashes.is_empty() {
                    self.by_dest.remove(&msg.dest_hash);
                }
            }
            true
        } else {
            false
        }
    }

    fn prune(&mut self, now: u64, max_age_secs: u64) -> usize {
        let cutoff = now.saturating_sub(max_age_secs);
        let before = self.messages.len();
        self.messages.retain(|_, msg| msg.timestamp >= cutoff);
        let count = before - self.messages.len();
        if count > 0 {
            // Rebuild by_dest index to remove stale hashes
            self.by_dest.retain(|_, hashes| {
                hashes.retain(|h| self.messages.contains_key(h));
                !hashes.is_empty()
            });
        }
        count
    }

    fn destinations_with_messages(&self) -> Vec<[u8; TRUNCATED_HASH_LEN]> {
        self.by_dest.keys().copied().collect()
    }

    fn message_count(&self) -> usize {
        self.messages.len()
    }

    fn count_for(&self, dest_hash: &[u8; TRUNCATED_HASH_LEN]) -> usize {
        self.by_dest.get(dest_hash).map_or(0, |v| v.len())
    }

    fn get_data(&self, message_hash: &[u8; 32]) -> Option<&[u8]> {
        self.messages.get(message_hash).map(|m| m.data.as_slice())
    }
}

// ---------------------------------------------------------------------------
// PropagationNode
// ---------------------------------------------------------------------------

/// An LXMF propagation node that stores and forwards messages.
pub struct PropagationNode<S: MessageStore> {
    store: S,
}

impl<S: MessageStore> PropagationNode<S> {
    /// Create a new propagation node with the given message store.
    pub fn new(store: S) -> Self {
        PropagationNode { store }
    }

    /// Deposit a message into the propagation store.
    ///
    /// The `data` should be the full packed LXMF message (dest_hash[16] ||
    /// source_hash[16] || signature[64] || msgpack_payload).
    ///
    /// Returns `Some((dest_hash, message_hash))` if newly stored,
    /// `None` if the message is a duplicate or too short to parse.
    pub fn deposit(
        &mut self,
        data: &[u8],
        now: u64,
    ) -> Option<([u8; TRUNCATED_HASH_LEN], [u8; 32])> {
        if data.len() < 96 {
            return None; // Too short to be a valid LXMF message
        }

        let mut dest_hash = [0u8; TRUNCATED_HASH_LEN];
        dest_hash.copy_from_slice(&data[..16]);

        let message_hash: [u8; 32] = Sha256::digest(data).into();

        if self
            .store
            .store(dest_hash, message_hash, data.to_vec(), now)
        {
            Some((dest_hash, message_hash))
        } else {
            None // Duplicate
        }
    }

    /// Retrieve all pending messages for a destination.
    pub fn retrieve(&self, dest_hash: &[u8; TRUNCATED_HASH_LEN]) -> Vec<StoredMessage> {
        self.store.retrieve(dest_hash)
    }

    /// Mark a message as delivered (remove from store).
    pub fn mark_delivered(&mut self, message_hash: &[u8; 32]) -> bool {
        self.store.mark_delivered(message_hash)
    }

    /// Prune messages older than `max_age_secs`.
    pub fn prune(&mut self, now: u64, max_age_secs: u64) -> usize {
        self.store.prune(now, max_age_secs)
    }

    /// Check if there are stored messages for a given destination.
    ///
    /// Used when an announce is received — if we have messages for the
    /// announcing destination, we should forward them.
    pub fn has_messages_for(&self, dest_hash: &[u8; TRUNCATED_HASH_LEN]) -> bool {
        self.store.count_for(dest_hash) > 0
    }

    /// Count messages for a destination without cloning.
    pub fn count_for(&self, dest_hash: &[u8; TRUNCATED_HASH_LEN]) -> usize {
        self.store.count_for(dest_hash)
    }

    /// Get all destination hashes that have pending messages.
    pub fn destinations_with_messages(&self) -> Vec<[u8; TRUNCATED_HASH_LEN]> {
        self.store.destinations_with_messages()
    }

    /// Get the total number of stored messages.
    pub fn message_count(&self) -> usize {
        self.store.message_count()
    }

    /// Look up a stored message's data by hash (O(1) via HashMap).
    pub fn get_data(&self, message_hash: &[u8; 32]) -> Option<&[u8]> {
        self.store.get_data(message_hash)
    }

    /// Get a reference to the underlying store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Get a mutable reference to the underlying store.
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fake_lxmf_data(dest_hash: [u8; 16], content_byte: u8) -> Vec<u8> {
        // Minimum valid LXMF: dest_hash[16] || source_hash[16] || signature[64] || payload
        let mut data = Vec::with_capacity(100);
        data.extend_from_slice(&dest_hash);
        data.extend_from_slice(&[0xAA; 16]); // source_hash
        data.extend_from_slice(&[content_byte; 64]); // signature (fake)
        data.extend_from_slice(&[content_byte; 4]); // minimal payload
        data
    }

    #[test]
    fn test_in_memory_store_basic() {
        let mut store = InMemoryMessageStore::new();
        let dest = [0x01; 16];
        let hash = [0x02; 32];

        assert!(store.store(dest, hash, vec![1, 2, 3], 1000));
        assert_eq!(store.message_count(), 1);

        let msgs = store.retrieve(&dest);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].data, vec![1, 2, 3]);
    }

    #[test]
    fn test_in_memory_store_dedup() {
        let mut store = InMemoryMessageStore::new();
        let dest = [0x01; 16];
        let hash = [0x02; 32];

        assert!(store.store(dest, hash, vec![1, 2, 3], 1000));
        assert!(!store.store(dest, hash, vec![1, 2, 3], 1001)); // duplicate
        assert_eq!(store.message_count(), 1);
    }

    #[test]
    fn test_in_memory_store_mark_delivered() {
        let mut store = InMemoryMessageStore::new();
        let dest = [0x01; 16];
        let hash = [0x02; 32];

        store.store(dest, hash, vec![1, 2, 3], 1000);
        assert!(store.mark_delivered(&hash));
        assert_eq!(store.message_count(), 0);
        assert!(store.retrieve(&dest).is_empty());
    }

    #[test]
    fn test_in_memory_store_prune() {
        let mut store = InMemoryMessageStore::new();
        let dest = [0x01; 16];

        store.store(dest, [0x01; 32], vec![1], 1000);
        store.store(dest, [0x02; 32], vec![2], 2000);
        store.store(dest, [0x03; 32], vec![3], 3000);

        // Prune messages older than 1500 seconds from now=4000
        let pruned = store.prune(4000, 1500);
        assert_eq!(pruned, 2); // messages at 1000 and 2000 are older than 2500
        assert_eq!(store.message_count(), 1);
    }

    #[test]
    fn test_in_memory_store_destinations_with_messages() {
        let mut store = InMemoryMessageStore::new();
        let dest1 = [0x01; 16];
        let dest2 = [0x02; 16];

        store.store(dest1, [0x01; 32], vec![1], 1000);
        store.store(dest2, [0x02; 32], vec![2], 1000);

        let dests = store.destinations_with_messages();
        assert_eq!(dests.len(), 2);
        assert!(dests.contains(&dest1));
        assert!(dests.contains(&dest2));
    }

    #[test]
    fn test_propagation_node_deposit() {
        let mut node = PropagationNode::new(InMemoryMessageStore::new());
        let dest = [0x42; 16];
        let data = make_fake_lxmf_data(dest, 0xBB);

        let result = node.deposit(&data, 1000);
        assert!(result.is_some());
        let (dep_dest, _msg_hash) = result.unwrap();
        assert_eq!(dep_dest, dest);
        assert_eq!(node.message_count(), 1);
    }

    #[test]
    fn test_propagation_node_deposit_dedup() {
        let mut node = PropagationNode::new(InMemoryMessageStore::new());
        let dest = [0x42; 16];
        let data = make_fake_lxmf_data(dest, 0xBB);

        assert!(node.deposit(&data, 1000).is_some());
        assert!(node.deposit(&data, 1001).is_none()); // duplicate
        assert_eq!(node.message_count(), 1);
    }

    #[test]
    fn test_propagation_node_deposit_too_short() {
        let mut node = PropagationNode::new(InMemoryMessageStore::new());
        assert!(node.deposit(&[0u8; 50], 1000).is_none());
    }

    #[test]
    fn test_propagation_node_retrieve() {
        let mut node = PropagationNode::new(InMemoryMessageStore::new());
        let dest = [0x42; 16];

        let data1 = make_fake_lxmf_data(dest, 0xAA);
        let data2 = make_fake_lxmf_data(dest, 0xBB);
        node.deposit(&data1, 1000);
        node.deposit(&data2, 1001);

        let msgs = node.retrieve(&dest);
        assert_eq!(msgs.len(), 2);
    }

    #[test]
    fn test_propagation_node_has_messages_for() {
        let mut node = PropagationNode::new(InMemoryMessageStore::new());
        let dest = [0x42; 16];
        let other = [0x99; 16];

        assert!(!node.has_messages_for(&dest));
        node.deposit(&make_fake_lxmf_data(dest, 0xAA), 1000);
        assert!(node.has_messages_for(&dest));
        assert!(!node.has_messages_for(&other));
    }

    #[test]
    fn test_propagation_node_mark_delivered() {
        let mut node = PropagationNode::new(InMemoryMessageStore::new());
        let dest = [0x42; 16];
        let data = make_fake_lxmf_data(dest, 0xCC);

        let (_, msg_hash) = node.deposit(&data, 1000).unwrap();
        assert!(node.mark_delivered(&msg_hash));
        assert_eq!(node.message_count(), 0);
        assert!(!node.has_messages_for(&dest));
    }

    #[test]
    fn test_propagation_node_prune() {
        let mut node = PropagationNode::new(InMemoryMessageStore::new());
        let dest = [0x42; 16];

        node.deposit(&make_fake_lxmf_data(dest, 0xAA), 1000);
        node.deposit(&make_fake_lxmf_data(dest, 0xBB), 5000);

        let pruned = node.prune(6000, 2000);
        assert_eq!(pruned, 1); // only the one at timestamp 1000
        assert_eq!(node.message_count(), 1);
    }
}
