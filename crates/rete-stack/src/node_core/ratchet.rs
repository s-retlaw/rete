//! Ratchet key storage trait and in-memory implementation.
//!
//! Ratchets provide forward secrecy by rotating X25519 keypairs. When an
//! identity announces with `context_flag=1`, the announce payload includes a
//! 32-byte ratchet public key. Peers store this key and use it (via
//! `encrypt_with_ratchet`) instead of the identity's static X25519 key.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Abstraction for ratchet key lifecycle and storage.
///
/// Keyed on `identity_hash` (16 bytes) because ratchets are per-identity,
/// not per-destination. One identity may have multiple destinations; all
/// share the same ratchet.
pub trait RatchetStore {
    /// Store a ratchet public key received in a peer's announce.
    fn store_peer_ratchet(&mut self, identity_hash: &[u8; 16], ratchet_pub: [u8; 32]);

    /// Recall the latest ratchet public key for a peer identity.
    fn recall_peer_ratchet(&self, identity_hash: &[u8; 16]) -> Option<[u8; 32]>;

    /// Set the local ratchet keypair. The previous current key (if any) is
    /// pushed to the "previous" list for in-flight decryption.
    /// Returns the old public key, if any.
    fn rotate_local_ratchet(
        &mut self,
        new_priv: [u8; 32],
        new_pub: [u8; 32],
    ) -> Option<[u8; 32]>;

    /// Current local ratchet public key (included in outbound announces).
    fn local_ratchet_public(&self) -> Option<[u8; 32]>;

    /// Current local ratchet private key (for inbound decryption).
    fn local_ratchet_private(&self) -> Option<[u8; 32]>;

    /// Previous local ratchet private keys for decrypting in-flight messages
    /// encrypted with an older ratchet. Most recent first.
    fn previous_ratchet_privates(&self) -> &[[u8; 32]];

    /// Mark a peer identity as requiring ratchet encryption.
    /// When enforced, non-ratcheted packets from this identity are rejected.
    fn set_ratchet_enforced(&mut self, identity_hash: &[u8; 16], enforced: bool);

    /// Query whether ratchet is enforced for a peer identity.
    fn is_ratchet_enforced(&self, identity_hash: &[u8; 16]) -> bool;
}

/// In-memory ratchet store using `BTreeMap`.
///
/// Suitable for both hosted and MCU targets (requires `alloc` only).
/// Previous ratchet private keys are bounded to prevent unbounded growth.
pub struct InMemoryRatchetStore {
    peer_ratchets: BTreeMap<[u8; 16], [u8; 32]>,
    current_priv: Option<[u8; 32]>,
    current_pub: Option<[u8; 32]>,
    /// Most recent first. Bounded by `max_previous`.
    previous_privs: Vec<[u8; 32]>,
    max_previous: usize,
    enforced: BTreeMap<[u8; 16], bool>,
}

impl InMemoryRatchetStore {
    /// Create a new in-memory ratchet store.
    ///
    /// `max_previous` controls how many old local ratchet private keys are
    /// retained for decrypting in-flight messages (default: 5).
    pub fn new(max_previous: usize) -> Self {
        Self {
            peer_ratchets: BTreeMap::new(),
            current_priv: None,
            current_pub: None,
            previous_privs: Vec::new(),
            max_previous,
            enforced: BTreeMap::new(),
        }
    }
}

impl Default for InMemoryRatchetStore {
    fn default() -> Self {
        Self::new(5)
    }
}

impl RatchetStore for InMemoryRatchetStore {
    fn store_peer_ratchet(&mut self, identity_hash: &[u8; 16], ratchet_pub: [u8; 32]) {
        self.peer_ratchets.insert(*identity_hash, ratchet_pub);
    }

    fn recall_peer_ratchet(&self, identity_hash: &[u8; 16]) -> Option<[u8; 32]> {
        self.peer_ratchets.get(identity_hash).copied()
    }

    fn rotate_local_ratchet(
        &mut self,
        new_priv: [u8; 32],
        new_pub: [u8; 32],
    ) -> Option<[u8; 32]> {
        let old_pub = self.current_pub;
        if let Some(old_priv) = self.current_priv.take() {
            self.previous_privs.insert(0, old_priv);
            self.previous_privs.truncate(self.max_previous);
        }
        self.current_priv = Some(new_priv);
        self.current_pub = Some(new_pub);
        old_pub
    }

    fn local_ratchet_public(&self) -> Option<[u8; 32]> {
        self.current_pub
    }

    fn local_ratchet_private(&self) -> Option<[u8; 32]> {
        self.current_priv
    }

    fn previous_ratchet_privates(&self) -> &[[u8; 32]] {
        &self.previous_privs
    }

    fn set_ratchet_enforced(&mut self, identity_hash: &[u8; 16], enforced: bool) {
        if enforced {
            self.enforced.insert(*identity_hash, true);
        } else {
            self.enforced.remove(identity_hash);
        }
    }

    fn is_ratchet_enforced(&self, identity_hash: &[u8; 16]) -> bool {
        self.enforced.get(identity_hash).copied().unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_and_recall_peer_ratchet() {
        let mut store = InMemoryRatchetStore::default();
        let id = [0xAA; 16];
        let ratchet = [0xBB; 32];

        assert!(store.recall_peer_ratchet(&id).is_none());
        store.store_peer_ratchet(&id, ratchet);
        assert_eq!(store.recall_peer_ratchet(&id), Some(ratchet));

        // Overwrite with new ratchet
        let ratchet2 = [0xCC; 32];
        store.store_peer_ratchet(&id, ratchet2);
        assert_eq!(store.recall_peer_ratchet(&id), Some(ratchet2));
    }

    #[test]
    fn test_rotate_local_ratchet() {
        let mut store = InMemoryRatchetStore::default();

        // First rotation — no previous key
        let old = store.rotate_local_ratchet([1u8; 32], [2u8; 32]);
        assert!(old.is_none());
        assert_eq!(store.local_ratchet_public(), Some([2u8; 32]));
        assert_eq!(store.local_ratchet_private(), Some([1u8; 32]));
        assert!(store.previous_ratchet_privates().is_empty());

        // Second rotation — first key moves to previous
        let old = store.rotate_local_ratchet([3u8; 32], [4u8; 32]);
        assert_eq!(old, Some([2u8; 32]));
        assert_eq!(store.local_ratchet_public(), Some([4u8; 32]));
        assert_eq!(store.local_ratchet_private(), Some([3u8; 32]));
        assert_eq!(store.previous_ratchet_privates(), &[[1u8; 32]]);
    }

    #[test]
    fn test_previous_keys_bounded() {
        let mut store = InMemoryRatchetStore::new(2);

        store.rotate_local_ratchet([1u8; 32], [10u8; 32]);
        store.rotate_local_ratchet([2u8; 32], [20u8; 32]);
        store.rotate_local_ratchet([3u8; 32], [30u8; 32]);
        store.rotate_local_ratchet([4u8; 32], [40u8; 32]);

        // Only the 2 most recent previous keys are retained
        let prev = store.previous_ratchet_privates();
        assert_eq!(prev.len(), 2);
        assert_eq!(prev[0], [3u8; 32]); // most recent previous
        assert_eq!(prev[1], [2u8; 32]);
    }

    #[test]
    fn test_enforcement() {
        let mut store = InMemoryRatchetStore::default();
        let id = [0xDD; 16];

        assert!(!store.is_ratchet_enforced(&id));
        store.set_ratchet_enforced(&id, true);
        assert!(store.is_ratchet_enforced(&id));
        store.set_ratchet_enforced(&id, false);
        assert!(!store.is_ratchet_enforced(&id));
    }
}
