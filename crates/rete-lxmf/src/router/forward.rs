//! Auto-forward store-and-forward delivery.

use rete_core::{DestHash, LinkId, TRUNCATED_HASH_LEN};
use rete_stack::{NodeCore, OutboundPacket};

use crate::propagation::MessageStore;

use super::codec::bz2_compress;
use super::{ForwardJob, LxmfRouter, RetrievalJob};

impl<S: MessageStore> LxmfRouter<S> {
    // -----------------------------------------------------------------------
    // Propagation auto-forward (store-and-forward delivery)
    // -----------------------------------------------------------------------

    /// Check if there is already a forward job for the given destination.
    pub fn has_forward_job_for(&self, dest_hash: &DestHash) -> bool {
        self.pending_forwards.iter().any(|job| match job {
            ForwardJob::Linking { dest_hash: d, .. } => d == dest_hash,
            ForwardJob::Sending { dest_hash: d, .. } => d == dest_hash,
        })
    }

    /// Initiate propagation forwarding to a destination.
    ///
    /// Retrieves pending messages, initiates a link to the destination's
    /// `lxmf.delivery` destination, and creates a Linking job.
    ///
    /// Returns the outbound LINKREQUEST packet and link_id, or None if:
    /// - propagation is not enabled
    /// - no messages for this destination
    /// - no path to the destination (identity not cached)
    pub fn start_propagation_forward<
        R: rand_core::RngCore + rand_core::CryptoRng,
        TS: rete_transport::TransportStorage,
    >(
        &mut self,
        dest_hash: &DestHash,
        core: &mut NodeCore<TS>,
        rng: &mut R,
        now: u64,
    ) -> Option<(OutboundPacket, LinkId)> {
        // Check we have messages
        if self.propagation_count_for(dest_hash) == 0 {
            return None;
        }

        // Initiate link to the destination (this is the recipient's lxmf.delivery dest)
        let (pkt, link_id) = core.initiate_link(*dest_hash, now, rng).ok()?;

        self.pending_forwards.push(ForwardJob::Linking {
            dest_hash: *dest_hash,
            link_id,
        });

        Some((pkt, link_id))
    }

    /// Advance a forward job when a link is established.
    ///
    /// Transitions from Linking -> Sending and sends the first Resource.
    pub fn advance_forward_on_link_established<
        R: rand_core::RngCore + rand_core::CryptoRng,
        TS: rete_transport::TransportStorage,
    >(
        &mut self,
        link_id: &LinkId,
        core: &mut NodeCore<TS>,
        rng: &mut R,
    ) -> Vec<OutboundPacket> {
        // Find the Linking job for this link_id
        let idx = self.pending_forwards.iter().position(|job| {
            matches!(
                job,
                ForwardJob::Linking { link_id: lid, .. } if lid == link_id
            )
        });

        let Some(idx) = idx else {
            return Vec::new();
        };

        // Get the dest_hash from the Linking job
        let dest_hash = match &self.pending_forwards[idx] {
            ForwardJob::Linking { dest_hash, .. } => *dest_hash,
            _ => unreachable!(),
        };

        // Get all message hashes for this destination
        let message_hashes = self.propagation_hashes_for(&dest_hash);
        if message_hashes.is_empty() {
            self.pending_forwards.remove(idx);
            return Vec::new();
        }

        let first_hash = message_hashes[0];

        // Transition to Sending state (move the Vec, no clone)
        self.pending_forwards[idx] = ForwardJob::Sending {
            dest_hash,
            link_id: *link_id,
            message_hashes,
            idx: 0,
        };

        self.send_stored_message_resource(&first_hash, link_id, core, rng)
    }

    /// Advance a forward job when a resource transfer completes.
    ///
    /// Marks the delivered message and sends the next one, or cleans up if done.
    pub fn advance_forward_on_resource_complete<
        R: rand_core::RngCore + rand_core::CryptoRng,
        TS: rete_transport::TransportStorage,
    >(
        &mut self,
        link_id: &LinkId,
        _resource_hash: &[u8; TRUNCATED_HASH_LEN],
        core: &mut NodeCore<TS>,
        rng: &mut R,
    ) -> Vec<OutboundPacket> {
        // Find the Sending job for this link_id
        let job_idx = self.pending_forwards.iter().position(|job| {
            matches!(
                job,
                ForwardJob::Sending { link_id: lid, .. } if lid == link_id
            )
        });

        let Some(job_idx) = job_idx else {
            return Vec::new();
        };

        // Extract only the hashes we need (avoids cloning the entire Vec)
        let (current_hash, next_hash) = match &self.pending_forwards[job_idx] {
            ForwardJob::Sending {
                message_hashes,
                idx,
                ..
            } => {
                let current = message_hashes[*idx];
                let next = message_hashes.get(*idx + 1).copied();
                (current, next)
            }
            _ => unreachable!(),
        };

        self.propagation_mark_delivered(&current_hash);

        if let Some(next) = next_hash {
            if let ForwardJob::Sending { idx, .. } = &mut self.pending_forwards[job_idx] {
                *idx += 1;
            }
            self.send_stored_message_resource(&next, link_id, core, rng)
        } else {
            self.pending_forwards.remove(job_idx);
            Vec::new()
        }
    }

    /// Look up a stored message by hash and send it as a bz2-compressed Resource.
    pub(super) fn send_stored_message_resource<
        R: rand_core::RngCore + rand_core::CryptoRng,
        TS: rete_transport::TransportStorage,
    >(
        &self,
        message_hash: &[u8; 32],
        link_id: &LinkId,
        core: &mut NodeCore<TS>,
        rng: &mut R,
    ) -> Vec<OutboundPacket> {
        let prop = match &self.propagation {
            Some(p) => p,
            None => return Vec::new(),
        };

        let Some(data) = prop.get_data(message_hash) else {
            return Vec::new();
        };

        let compressed = bz2_compress(&data);

        match core.start_resource(link_id, &compressed, rng) {
            Ok(pkt) => vec![pkt],
            Err(_) => Vec::new(),
        }
    }

    /// Remove forward jobs for a link that was closed.
    pub fn cleanup_forward_jobs_for_link(&mut self, link_id: &LinkId) {
        self.pending_forwards.retain(|job| match job {
            ForwardJob::Linking { link_id: lid, .. } => lid != link_id,
            ForwardJob::Sending { link_id: lid, .. } => lid != link_id,
        });
        self.pending_retrievals.retain(|job| match job {
            RetrievalJob::Sending { link_id: lid, .. } => lid != link_id,
        });
    }
}
