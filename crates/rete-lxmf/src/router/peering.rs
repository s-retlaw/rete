//! Peer registry + peer sync state machine.

use rete_core::TRUNCATED_HASH_LEN;
use rete_stack::{NodeCore, OutboundPacket};

use crate::peer::{LxmPeer, SyncStrategy};
use crate::propagation::MessageStore;

use super::codec::{
    bz2_compress, decode_offer_hashes, encode_offer_hashes, pack_sync_messages,
    parse_offer_response, unpack_sync_messages,
};
use super::{LxmfEvent, LxmfRouter, SyncJob, OFFER_PATH};

impl<S: MessageStore> LxmfRouter<S> {
    // -----------------------------------------------------------------------
    // Peer registry
    // -----------------------------------------------------------------------

    /// Manually add a peer to the registry.
    ///
    /// Returns `true` if the peer was added, `false` if already peered or
    /// the peer limit has been reached.
    pub fn peer(
        &mut self,
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        identity_hash: [u8; TRUNCATED_HASH_LEN],
    ) -> bool {
        if self.peers.contains_key(&dest_hash) {
            return false;
        }
        if self.peers.len() >= self.max_peers {
            return false;
        }
        let mut p = LxmPeer::new(dest_hash, identity_hash);
        p.sync_strategy = SyncStrategy::Persistent;
        self.peers.insert(dest_hash, p);
        true
    }

    /// Remove a peer from the registry.
    pub fn unpeer(&mut self, dest_hash: &[u8; TRUNCATED_HASH_LEN]) -> bool {
        self.peers.remove(dest_hash).is_some()
    }

    /// Number of peers in the registry.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Check if a destination is peered.
    pub fn is_peered(&self, dest_hash: &[u8; TRUNCATED_HASH_LEN]) -> bool {
        self.peers.contains_key(dest_hash)
    }

    /// Enable or disable auto-peering from propagation announces.
    pub fn set_autopeer(&mut self, enabled: bool, max_depth: u8) {
        self.autopeer = enabled;
        self.autopeer_maxdepth = max_depth;
    }

    /// Get a reference to a peer by dest hash.
    pub fn get_peer(&self, dest_hash: &[u8; TRUNCATED_HASH_LEN]) -> Option<&LxmPeer> {
        self.peers.get(dest_hash)
    }

    /// Get a mutable reference to a peer by dest hash.
    pub fn get_peer_mut(&mut self, dest_hash: &[u8; TRUNCATED_HASH_LEN]) -> Option<&mut LxmPeer> {
        self.peers.get_mut(dest_hash)
    }

    // -----------------------------------------------------------------------
    // Peer sync (propagation node <-> propagation node)
    // -----------------------------------------------------------------------

    /// Path hash for the peer offer request path.
    pub fn offer_path_hash() -> [u8; TRUNCATED_HASH_LEN] {
        rete_transport::request::path_hash(OFFER_PATH)
    }

    /// Check peers that need syncing and initiate links.
    ///
    /// Called from the tick handler. Returns outbound packets (link requests).
    pub fn check_peer_syncs<
        R: rand_core::RngCore + rand_core::CryptoRng,
        TS: rete_transport::TransportStorage,
    >(
        &mut self,
        core: &mut NodeCore<TS>,
        rng: &mut R,
        now: u64,
    ) -> Vec<OutboundPacket> {
        if !self.propagation_enabled() {
            return Vec::new();
        }

        let mut packets = Vec::new();

        // Collect peers that need sync (can't borrow mutably during iteration)
        let peers_to_sync: Vec<[u8; TRUNCATED_HASH_LEN]> = self
            .peers
            .iter()
            .filter(|(_, p)| p.needs_sync(now))
            .filter(|(dest, _)| !self.pending_syncs.iter().any(|s| s.peer_dest() == *dest))
            .map(|(dest, _)| *dest)
            .collect();

        for peer_dest in peers_to_sync {
            if let Ok((pkt, link_id)) = core.initiate_link(peer_dest, now, rng) {
                if let Some(p) = self.peers.get_mut(&peer_dest) {
                    p.state = crate::peer::PeerState::LinkEstablishing;
                    p.sync_attempted(now);
                }
                self.pending_syncs
                    .push(SyncJob::Linking { peer_dest, link_id });
                packets.push(pkt);
            }
        }

        packets
    }

    /// Advance a sync job when a link is established.
    ///
    /// Sends an identify packet and transitions to Identifying.
    pub fn advance_sync_on_link_established<
        R: rand_core::RngCore + rand_core::CryptoRng,
        TS: rete_transport::TransportStorage,
    >(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        core: &mut NodeCore<TS>,
        rng: &mut R,
        now: u64,
    ) -> Vec<OutboundPacket> {
        let idx = self
            .pending_syncs
            .iter()
            .position(|s| matches!(s, SyncJob::Linking { link_id: lid, .. } if lid == link_id));

        let Some(idx) = idx else {
            return Vec::new();
        };

        let peer_dest = *self.pending_syncs[idx].peer_dest();

        if let Some(p) = self.peers.get_mut(&peer_dest) {
            p.link_established(*link_id);
        }

        // Send identify on the link
        let mut packets = Vec::new();
        if let Ok(pkt) = core.link_identify(link_id, rng) {
            packets.push(pkt);
        }

        // Build offer immediately (don't wait for remote LinkIdentified —
        // identify is one-directional, we won't get a callback)
        let all_hashes = match &self.propagation {
            Some(prop) => prop.all_message_hashes(),
            None => {
                self.pending_syncs.remove(idx);
                return packets;
            }
        };

        let offered_hashes = match self.peers.get(&peer_dest) {
            Some(peer) => peer.unhandled_from(&all_hashes),
            None => all_hashes,
        };

        if offered_hashes.is_empty() {
            self.pending_syncs.remove(idx);
            if let Some(p) = self.peers.get_mut(&peer_dest) {
                p.sync_complete(now);
            }
            let _ = core.close_link(link_id, rng);
            return packets;
        }

        let offer_data = encode_offer_hashes(&offered_hashes);

        if let Ok((pkt, _request_id)) =
            core.send_request(link_id, OFFER_PATH, &offer_data, now, rng)
        {
            packets.push(pkt);
            if let Some(p) = self.peers.get_mut(&peer_dest) {
                p.offer_sent();
            }
            self.pending_syncs[idx] = SyncJob::OfferSent {
                peer_dest,
                link_id: *link_id,
                offered_hashes,
            };
        } else {
            self.pending_syncs.remove(idx);
            if let Some(p) = self.peers.get_mut(&peer_dest) {
                p.sync_failed();
            }
        }

        packets
    }

    /// Advance a sync job when the offer response is received.
    ///
    /// Parses the response (true=want all, false=want none, array=want subset)
    /// and packs + sends the wanted messages as a bz2-compressed Resource.
    pub fn advance_sync_on_response<
        R: rand_core::RngCore + rand_core::CryptoRng,
        TS: rete_transport::TransportStorage,
    >(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        response_data: &[u8],
        core: &mut NodeCore<TS>,
        rng: &mut R,
        now: u64,
    ) -> Vec<OutboundPacket> {
        let idx = self
            .pending_syncs
            .iter()
            .position(|s| matches!(s, SyncJob::OfferSent { link_id: lid, .. } if lid == link_id));

        let Some(idx) = idx else {
            return Vec::new();
        };

        // Remove the job to extract owned offered_hashes without cloning
        let job = self.pending_syncs.remove(idx);
        let (peer_dest, offered_hashes) = match job {
            SyncJob::OfferSent {
                peer_dest,
                offered_hashes,
                ..
            } => (peer_dest, offered_hashes),
            _ => unreachable!(),
        };

        if let Some(p) = self.peers.get_mut(&peer_dest) {
            p.response_received();
        }

        // Parse response
        let wanted = parse_offer_response(response_data, &offered_hashes);

        if wanted.is_empty() {
            if let Some(p) = self.peers.get_mut(&peer_dest) {
                for h in &offered_hashes {
                    p.mark_handled(*h);
                }
                p.sync_complete(now);
            }
            let _ = core.close_link(link_id, rng);
            return Vec::new();
        }

        // Pack wanted messages into a single bz2-compressed Resource
        let prop = match &self.propagation {
            Some(p) => p,
            None => return Vec::new(),
        };

        let message_data: Vec<Vec<u8>> = wanted
            .iter()
            .filter_map(|hash| prop.get_data(hash))
            .collect();

        if message_data.is_empty() {
            if let Some(p) = self.peers.get_mut(&peer_dest) {
                p.sync_complete(now);
            }
            let _ = core.close_link(link_id, rng);
            return Vec::new();
        }

        let packed = pack_sync_messages(now, &message_data);
        let compressed = bz2_compress(&packed);

        let mut packets = Vec::new();
        if let Ok(pkt) = core.start_resource(link_id, &compressed, rng) {
            if let Some(p) = self.peers.get_mut(&peer_dest) {
                p.transfer_started();
            }
            self.pending_syncs.push(SyncJob::Transferring {
                peer_dest,
                link_id: *link_id,
                offered_hashes: wanted,
            });
            packets.push(pkt);
        } else {
            if let Some(p) = self.peers.get_mut(&peer_dest) {
                p.sync_failed();
            }
        }

        packets
    }

    /// Advance a sync job when the resource transfer completes.
    ///
    /// Marks all transferred messages as handled and completes the sync.
    pub fn advance_sync_on_resource_complete<
        R: rand_core::RngCore + rand_core::CryptoRng,
        TS: rete_transport::TransportStorage,
    >(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        core: &mut NodeCore<TS>,
        rng: &mut R,
        now: u64,
    ) -> (Vec<OutboundPacket>, Option<LxmfEvent>) {
        let idx = self.pending_syncs.iter().position(
            |s| matches!(s, SyncJob::Transferring { link_id: lid, .. } if lid == link_id),
        );

        let Some(idx) = idx else {
            return (Vec::new(), None);
        };

        let job = self.pending_syncs.remove(idx);
        let (peer_dest, offered_hashes) = match job {
            SyncJob::Transferring {
                peer_dest,
                offered_hashes,
                ..
            } => (peer_dest, offered_hashes),
            _ => unreachable!(),
        };

        let messages_sent = offered_hashes.len();

        if let Some(p) = self.peers.get_mut(&peer_dest) {
            for h in &offered_hashes {
                p.mark_handled(*h);
            }
            p.sync_complete(now);
        }

        // Close the link
        let _ = core.close_link(link_id, rng);

        let event = LxmfEvent::PeerSyncComplete {
            dest_hash: peer_dest,
            messages_sent,
        };

        (Vec::new(), Some(event))
    }

    /// Handle an inbound offer request from a peer.
    ///
    /// Checks which of the offered message hashes we already have,
    /// and returns a response: `false` if we have all, `true` if we want all,
    /// or a list of the hashes we want.
    pub fn handle_offer_request(
        &self,
        path_hash: &[u8; TRUNCATED_HASH_LEN],
        data: &[u8],
    ) -> Option<Vec<u8>> {
        if *path_hash != Self::offer_path_hash() {
            return None;
        }
        if !self.propagation_enabled() {
            return None;
        }

        let offered = decode_offer_hashes(data)?;
        let prop = self.propagation.as_ref()?;

        // Check which messages we already have
        let wanted: Vec<[u8; 32]> = offered
            .iter()
            .filter(|h| !prop.has_message(h))
            .copied()
            .collect();

        if wanted.is_empty() {
            // We have all of them
            Some(vec![0xc2]) // msgpack false
        } else if wanted.len() == offered.len() {
            // We want all of them
            Some(vec![0xc3]) // msgpack true
        } else {
            // We want a subset — encode as array of hashes
            Some(encode_offer_hashes(&wanted))
        }
    }

    /// Deposit messages received from a peer sync resource.
    ///
    /// Unpacks the bz2-compressed msgpack `[timestamp, [msg1, msg2, ...]]`
    /// and deposits each message into the propagation store.
    pub fn deposit_sync_resource(
        &mut self,
        data: &[u8],
        now: u64,
    ) -> Vec<([u8; TRUNCATED_HASH_LEN], [u8; 32])> {
        let prop = match &mut self.propagation {
            Some(p) => p,
            None => return Vec::new(),
        };

        let messages = unpack_sync_messages(data);
        let mut deposited = Vec::new();

        for msg_data in messages {
            if let Some((dest, hash)) = prop.deposit(&msg_data, now) {
                deposited.push((dest, hash));
            }
        }

        deposited
    }

    /// Clean up sync jobs for a link that was closed.
    pub fn cleanup_sync_jobs_for_link(&mut self, link_id: &[u8; TRUNCATED_HASH_LEN]) {
        let removed: Vec<[u8; TRUNCATED_HASH_LEN]> = self
            .pending_syncs
            .iter()
            .filter(|s| s.link_id() == link_id)
            .map(|s| *s.peer_dest())
            .collect();

        self.pending_syncs.retain(|s| s.link_id() != link_id);

        for peer_dest in removed {
            if let Some(p) = self.peers.get_mut(&peer_dest) {
                p.sync_failed();
            }
        }
    }

    /// Check if a sync job exists for the given link_id.
    pub fn has_sync_job_for_link(&self, link_id: &[u8; TRUNCATED_HASH_LEN]) -> bool {
        self.pending_syncs.iter().any(|s| s.link_id() == link_id)
    }
}
