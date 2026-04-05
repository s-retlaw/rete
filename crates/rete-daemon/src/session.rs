//! Client session registry for the shared daemon.
//!
//! Tracks active client connections and their destination ownership.
//! Used for cleanup on disconnect and future destination-based routing.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

/// A single client session in the shared daemon.
#[derive(Debug)]
pub struct ClientSession {
    /// When the client connected.
    pub attached_at: Instant,
    /// Destination hashes owned by this client (from announces).
    pub destinations: HashSet<[u8; 16]>,
}

/// Tracks active client sessions and their destination ownership.
#[derive(Debug, Default)]
pub struct SessionRegistry {
    sessions: HashMap<usize, ClientSession>,
    /// Reverse index: destination hash → client ID for O(1) lookup.
    dest_to_client: HashMap<[u8; 16], usize>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        SessionRegistry {
            sessions: HashMap::new(),
            dest_to_client: HashMap::new(),
        }
    }

    /// Register a new client session.
    pub fn register(&mut self, client_id: usize) {
        self.sessions.insert(
            client_id,
            ClientSession {
                attached_at: Instant::now(),
                destinations: HashSet::new(),
            },
        );
    }

    /// Unregister a client, returning its owned destination hashes.
    pub fn unregister(&mut self, client_id: usize) -> Vec<[u8; 16]> {
        match self.sessions.remove(&client_id) {
            Some(session) => {
                let dests: Vec<[u8; 16]> = session.destinations.into_iter().collect();
                for dest in &dests {
                    self.dest_to_client.remove(dest);
                }
                dests
            }
            None => Vec::new(),
        }
    }

    /// Record that a client owns a destination hash.
    ///
    /// If another client previously owned this destination, it is evicted
    /// from that client's forward set to keep the two maps in sync.
    pub fn register_destination(&mut self, client_id: usize, dest_hash: [u8; 16]) {
        if let Some(&prev) = self.dest_to_client.get(&dest_hash) {
            if prev != client_id {
                if let Some(prev_session) = self.sessions.get_mut(&prev) {
                    prev_session.destinations.remove(&dest_hash);
                }
            }
        }
        if let Some(session) = self.sessions.get_mut(&client_id) {
            session.destinations.insert(dest_hash);
            self.dest_to_client.insert(dest_hash, client_id);
        }
    }

    /// Look up which client owns a destination.
    pub fn lookup_owner(&self, dest_hash: &[u8; 16]) -> Option<usize> {
        self.dest_to_client.get(dest_hash).copied()
    }

    /// Number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Whether any sessions are active.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_registry_lifecycle() {
        let mut reg = SessionRegistry::new();
        assert!(reg.is_empty());

        reg.register(0);
        reg.register(1);
        reg.register(2);
        assert_eq!(reg.session_count(), 3);

        let removed = reg.unregister(1);
        assert!(removed.is_empty());
        assert_eq!(reg.session_count(), 2);

        reg.unregister(0);
        reg.unregister(2);
        assert!(reg.is_empty());
    }

    #[test]
    fn test_session_ownership_cleanup() {
        let mut reg = SessionRegistry::new();
        let dest_a = [0xAA; 16];
        let dest_b = [0xBB; 16];

        reg.register(10);
        reg.register(20);

        reg.register_destination(10, dest_a);
        reg.register_destination(20, dest_b);

        assert_eq!(reg.lookup_owner(&dest_a), Some(10));
        assert_eq!(reg.lookup_owner(&dest_b), Some(20));
        assert_eq!(reg.lookup_owner(&[0xCC; 16]), None);

        // Unregister client 10 — its destinations should be returned
        let removed = reg.unregister(10);
        assert_eq!(removed.len(), 1);
        assert!(removed.contains(&dest_a));

        // dest_a is no longer owned
        assert_eq!(reg.lookup_owner(&dest_a), None);
        // dest_b still owned by client 20
        assert_eq!(reg.lookup_owner(&dest_b), Some(20));
    }

    #[test]
    fn test_destination_re_registration_evicts_previous_owner() {
        let mut reg = SessionRegistry::new();
        let dest = [0xDD; 16];

        reg.register(10);
        reg.register(20);

        // Client 10 owns dest initially.
        reg.register_destination(10, dest);
        assert_eq!(reg.lookup_owner(&dest), Some(10));

        // Client 20 re-announces the same dest — evicts client 10.
        reg.register_destination(20, dest);
        assert_eq!(reg.lookup_owner(&dest), Some(20));

        // Unregister client 10 — must NOT remove dest from reverse index
        // (it now belongs to client 20).
        let removed_10 = reg.unregister(10);
        assert!(removed_10.is_empty(), "client 10 should have no destinations after eviction");
        assert_eq!(reg.lookup_owner(&dest), Some(20), "dest must still be owned by client 20");

        // Unregister client 20 — now dest is truly gone.
        let removed_20 = reg.unregister(20);
        assert_eq!(removed_20.len(), 1);
        assert!(removed_20.contains(&dest));
        assert_eq!(reg.lookup_owner(&dest), None);
    }

    #[test]
    fn test_unregister_unknown_client() {
        let mut reg = SessionRegistry::new();
        let removed = reg.unregister(999);
        assert!(removed.is_empty());
    }
}
