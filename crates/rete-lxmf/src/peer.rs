//! LXMF Peer management — state machine for propagation node peering.
//!
//! Peers are other propagation nodes that we synchronize messages with.
//! Each peer has a state machine tracking the link and sync process.

use std::vec::Vec;

use rete_core::TRUNCATED_HASH_LEN;

/// Peer sync state machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// Peer is idle, no sync in progress.
    Idle,
    /// Establishing link to peer.
    LinkEstablishing,
    /// Link is active and ready.
    LinkReady,
    /// Offer request sent, awaiting response.
    RequestSent,
    /// Offer response received, ready to transfer.
    ResponseReceived,
    /// Transferring messages via resource.
    ResourceTransferring,
}

/// Sync strategy for a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncStrategy {
    /// Lazy: only sync when asked.
    Lazy,
    /// Persistent: actively sync on schedule.
    Persistent,
}

/// An LXMF propagation peer.
#[derive(Debug, Clone)]
pub struct LxmPeer {
    /// Destination hash of the peer.
    pub dest_hash: [u8; TRUNCATED_HASH_LEN],
    /// Identity hash of the peer.
    pub identity_hash: [u8; TRUNCATED_HASH_LEN],
    /// Current state of the peering session.
    pub state: PeerState,
    /// Sync strategy for this peer.
    pub sync_strategy: SyncStrategy,
    /// Peering cost required by this peer (stamp difficulty).
    pub peering_cost: u8,
    /// Our peering key for this peer (32-byte PoW key + value).
    pub peering_key: Option<(Vec<u8>, u16)>,
    /// Stamp cost this peer requires for messages.
    pub stamp_cost: u8,
    /// Last successful sync timestamp (monotonic seconds).
    pub last_sync: u64,
    /// Sync interval in seconds.
    pub sync_interval: u64,
    /// Link ID if link is established.
    pub link_id: Option<[u8; TRUNCATED_HASH_LEN]>,
    /// Message hashes we've already synced to this peer.
    pub handled: Vec<[u8; 32]>,
}

impl LxmPeer {
    /// Create a new peer with default settings.
    pub fn new(
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        identity_hash: [u8; TRUNCATED_HASH_LEN],
    ) -> Self {
        LxmPeer {
            dest_hash,
            identity_hash,
            state: PeerState::Idle,
            sync_strategy: SyncStrategy::Lazy,
            peering_cost: 0,
            peering_key: None,
            stamp_cost: 0,
            last_sync: 0,
            sync_interval: 480, // 8 minutes default
            link_id: None,
            handled: Vec::new(),
        }
    }

    /// Check if this peer needs a sync (based on time and strategy).
    pub fn needs_sync(&self, now: u64) -> bool {
        if self.sync_strategy != SyncStrategy::Persistent {
            return false;
        }
        if self.state != PeerState::Idle {
            return false;
        }
        now.saturating_sub(self.last_sync) >= self.sync_interval
    }

    /// Transition state for link established.
    pub fn link_established(&mut self, link_id: [u8; TRUNCATED_HASH_LEN]) {
        self.link_id = Some(link_id);
        self.state = PeerState::LinkReady;
    }

    /// Transition state for offer sent.
    pub fn offer_sent(&mut self) {
        self.state = PeerState::RequestSent;
    }

    /// Transition state for response received.
    pub fn response_received(&mut self) {
        self.state = PeerState::ResponseReceived;
    }

    /// Transition state for resource transfer started.
    pub fn transfer_started(&mut self) {
        self.state = PeerState::ResourceTransferring;
    }

    /// Sync complete — return to idle.
    pub fn sync_complete(&mut self, now: u64) {
        self.state = PeerState::Idle;
        self.link_id = None;
        self.last_sync = now;
    }

    /// Sync failed — return to idle.
    pub fn sync_failed(&mut self) {
        self.state = PeerState::Idle;
        self.link_id = None;
    }

    /// Mark a message hash as handled (already synced to this peer).
    pub fn mark_handled(&mut self, message_hash: [u8; 32]) {
        if !self.handled.contains(&message_hash) {
            self.handled.push(message_hash);
        }
    }

    /// Check if a message has already been synced to this peer.
    pub fn is_handled(&self, message_hash: &[u8; 32]) -> bool {
        self.handled.contains(message_hash)
    }

    /// Get unhandled message hashes from a list.
    pub fn unhandled_from(&self, message_hashes: &[[u8; 32]]) -> Vec<[u8; 32]> {
        message_hashes
            .iter()
            .filter(|h| !self.is_handled(h))
            .copied()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_state_machine() {
        let mut peer = LxmPeer::new([0x11; TRUNCATED_HASH_LEN], [0x22; TRUNCATED_HASH_LEN]);
        assert_eq!(peer.state, PeerState::Idle);

        peer.link_established([0x33; TRUNCATED_HASH_LEN]);
        assert_eq!(peer.state, PeerState::LinkReady);

        peer.offer_sent();
        assert_eq!(peer.state, PeerState::RequestSent);

        peer.response_received();
        assert_eq!(peer.state, PeerState::ResponseReceived);

        peer.transfer_started();
        assert_eq!(peer.state, PeerState::ResourceTransferring);

        peer.sync_complete(1000);
        assert_eq!(peer.state, PeerState::Idle);
        assert_eq!(peer.last_sync, 1000);
    }

    #[test]
    fn test_peer_needs_sync() {
        let mut peer = LxmPeer::new([0x11; TRUNCATED_HASH_LEN], [0x22; TRUNCATED_HASH_LEN]);
        peer.sync_strategy = SyncStrategy::Persistent;
        peer.sync_interval = 60;
        peer.last_sync = 100;

        assert!(!peer.needs_sync(150)); // 50s < 60s interval
        assert!(peer.needs_sync(161)); // 61s >= 60s interval
    }

    #[test]
    fn test_handled_tracking() {
        let mut peer = LxmPeer::new([0x11; TRUNCATED_HASH_LEN], [0x22; TRUNCATED_HASH_LEN]);
        let hash1 = [0xAA; 32];
        let hash2 = [0xBB; 32];

        assert!(!peer.is_handled(&hash1));
        peer.mark_handled(hash1);
        assert!(peer.is_handled(&hash1));
        assert!(!peer.is_handled(&hash2));

        let unhandled = peer.unhandled_from(&[hash1, hash2]);
        assert_eq!(unhandled, vec![hash2]);
    }
}
