//! Propagation store API, deposit, retrieval request handling, prune.

use rete_core::TRUNCATED_HASH_LEN;
use rete_stack::NodeCore;

use crate::propagation::{MessageStore, PropagationNode};

use super::codec::encode_msgpack_uint;
use super::{LxmfEvent, LxmfRouter, PropagationRetrievalResult};

impl<S: MessageStore> LxmfRouter<S> {
    // -----------------------------------------------------------------------
    // Propagation node support
    // -----------------------------------------------------------------------

    /// Register an `lxmf.propagation` destination and enable store-and-forward.
    ///
    /// Creates a SINGLE destination (identity-bound) for `lxmf.propagation`,
    /// sets ProveAll, and initializes the message store using `S::default()`.
    pub fn register_propagation<const P: usize, const A: usize, const D: usize, const L: usize>(
        &mut self,
        core: &mut NodeCore<P, A, D, L>,
    ) where
        S: Default,
    {
        self.register_propagation_with_store(core, S::default());
    }

    /// Register an `lxmf.propagation` destination with a specific store instance.
    pub fn register_propagation_with_store<
        const P: usize,
        const A: usize,
        const D: usize,
        const L: usize,
    >(
        &mut self,
        core: &mut NodeCore<P, A, D, L>,
        store: S,
    ) {
        let dest_hash = core.register_destination("lxmf", &["propagation"]);

        if let Some(dest) = core.get_destination_mut(&dest_hash) {
            dest.set_proof_strategy(rete_stack::ProofStrategy::ProveAll);
        }

        self.propagation_dest_hash = Some(dest_hash);
        self.propagation = Some(PropagationNode::new(store));
    }

    /// Returns the `lxmf.propagation` destination hash, if propagation is enabled.
    pub fn propagation_dest_hash(&self) -> Option<&[u8; TRUNCATED_HASH_LEN]> {
        self.propagation_dest_hash.as_ref()
    }

    /// Returns true if propagation is enabled.
    pub fn propagation_enabled(&self) -> bool {
        self.propagation.is_some()
    }

    /// Build propagation announce app_data.
    ///
    /// Format: msgpack array `[display_name_bytes, true]`
    /// The `true` boolean indicates propagation capability.
    pub fn build_propagation_announce_data(&self) -> Vec<u8> {
        self.build_announce_app_data_with_tag(0xc3) // msgpack true = propagation
    }

    /// Queue an LXMF propagation announce.
    ///
    /// Returns false if propagation is not enabled.
    pub fn queue_propagation_announce<
        R,
        const P: usize,
        const A: usize,
        const D: usize,
        const L: usize,
    >(
        &self,
        core: &mut NodeCore<P, A, D, L>,
        rng: &mut R,
        now: u64,
    ) -> bool
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        let Some(dest_hash) = self.propagation_dest_hash else {
            return false;
        };
        let app_data = self.build_propagation_announce_data();
        core.queue_announce_for(&dest_hash, Some(&app_data), rng, now)
    }

    /// Deposit a message into the propagation store.
    ///
    /// The `data` should be the full packed LXMF message.
    /// Returns `Some(LxmfEvent::PropagationDeposit)` if stored,
    /// `None` if propagation is not enabled or the message is a duplicate.
    pub fn propagation_deposit(&mut self, data: &[u8], now: u64) -> Option<LxmfEvent> {
        let prop = self.propagation.as_mut()?;
        let (dest_hash, message_hash) = prop.deposit(data, now)?;
        Some(LxmfEvent::PropagationDeposit {
            dest_hash,
            message_hash,
        })
    }

    /// Get message hashes for a destination from the propagation store.
    ///
    /// Returns hashes without loading message data.
    pub fn propagation_hashes_for(&self, dest_hash: &[u8; TRUNCATED_HASH_LEN]) -> Vec<[u8; 32]> {
        match &self.propagation {
            Some(prop) => prop.hashes_for(dest_hash),
            None => Vec::new(),
        }
    }

    /// Check if a specific message exists in the propagation store.
    pub fn propagation_has_message(&self, message_hash: &[u8; 32]) -> bool {
        match &self.propagation {
            Some(prop) => prop.has_message(message_hash),
            None => false,
        }
    }

    /// Count messages for a destination in the propagation store.
    pub fn propagation_count_for(&self, dest_hash: &[u8; TRUNCATED_HASH_LEN]) -> usize {
        match &self.propagation {
            Some(prop) => prop.count_for(dest_hash),
            None => 0,
        }
    }

    /// Mark a message as delivered in the propagation store.
    pub fn propagation_mark_delivered(&mut self, message_hash: &[u8; 32]) -> bool {
        match &mut self.propagation {
            Some(prop) => prop.mark_delivered(message_hash),
            None => false,
        }
    }

    /// Check if an announce triggers propagation forwarding.
    ///
    /// If propagation is enabled and we have stored messages for the
    /// announcing destination, returns `Some(LxmfEvent::PropagationForward)`.
    pub fn check_propagation_forward(
        &self,
        dest_hash: &[u8; TRUNCATED_HASH_LEN],
    ) -> Option<LxmfEvent> {
        let prop = self.propagation.as_ref()?;
        let count = prop.count_for(dest_hash);
        if count > 0 {
            Some(LxmfEvent::PropagationForward {
                dest_hash: *dest_hash,
                count,
            })
        } else {
            None
        }
    }

    /// Prune expired messages from the propagation store.
    ///
    /// Returns the number of messages pruned, or 0 if propagation is not enabled.
    pub fn prune_propagation(&mut self, now: u64, max_age_secs: u64) -> usize {
        match &mut self.propagation {
            Some(prop) => prop.prune(now, max_age_secs),
            None => 0,
        }
    }

    /// Get the number of messages currently in the propagation store.
    pub fn propagation_message_count(&self) -> usize {
        match &self.propagation {
            Some(prop) => prop.message_count(),
            None => 0,
        }
    }

    // -----------------------------------------------------------------------
    // Propagation retrieval (client-initiated pull via link.request)
    // -----------------------------------------------------------------------

    /// Path hash for the propagation retrieval path.
    pub fn propagation_retrieve_path_hash() -> [u8; TRUNCATED_HASH_LEN] {
        rete_transport::request::path_hash("/lxmf/propagation/retrieve")
    }

    /// Handle an incoming link.request on the propagation destination.
    ///
    /// If `path_hash` matches `/lxmf/propagation/retrieve`:
    ///   - `data` is the destination hash (16 bytes) of the requesting client
    ///   - Retrieves stored messages for that dest_hash
    ///   - Returns a `PropagationRetrievalResult` with:
    ///     - `response_data`: msgpack uint32 count of messages to send
    ///     - `messages`: packed LXMF messages (data, hash) to send as Resources
    ///
    /// Returns `None` if the path does not match or propagation is not enabled.
    pub fn handle_propagation_request(
        &self,
        path_hash: &[u8; TRUNCATED_HASH_LEN],
        data: &[u8],
    ) -> Option<PropagationRetrievalResult> {
        // Check that the path matches
        if *path_hash != Self::propagation_retrieve_path_hash() {
            return None;
        }

        // Propagation must be enabled
        if !self.propagation_enabled() {
            return None;
        }

        // The data should be a 16-byte dest_hash
        if data.len() < TRUNCATED_HASH_LEN {
            return None;
        }

        let mut dest_hash = [0u8; TRUNCATED_HASH_LEN];
        dest_hash.copy_from_slice(&data[..TRUNCATED_HASH_LEN]);

        let message_hashes = self.propagation_hashes_for(&dest_hash);

        // Build response data: msgpack uint32 with the count
        let count = message_hashes.len();
        let response_data = encode_msgpack_uint(count as u32);

        Some(PropagationRetrievalResult {
            response_data,
            message_hashes,
        })
    }

    /// Start sending retrieval messages as Resources on a link.
    ///
    /// Creates a `RetrievalJob` and sends the first Resource.
    /// Returns the outbound packets (resource advertisement).
    pub fn start_retrieval_send<
        R: rand_core::RngCore + rand_core::CryptoRng,
        const P: usize,
        const A: usize,
        const D: usize,
        const L: usize,
    >(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        message_hashes: Vec<[u8; 32]>,
        core: &mut NodeCore<P, A, D, L>,
        rng: &mut R,
    ) -> Vec<super::OutboundPacket> {
        use super::RetrievalJob;

        if message_hashes.is_empty() {
            return Vec::new();
        }

        let first_hash = message_hashes[0];

        self.pending_retrievals.push(RetrievalJob::Sending {
            link_id: *link_id,
            message_hashes,
            idx: 0,
        });

        self.send_stored_message_resource(&first_hash, link_id, core, rng)
    }

    /// Advance a retrieval job when a resource transfer completes.
    ///
    /// Marks the delivered message and sends the next one, or cleans up if done.
    pub fn advance_retrieval_on_resource_complete<
        R: rand_core::RngCore + rand_core::CryptoRng,
        const P: usize,
        const A: usize,
        const D: usize,
        const L: usize,
    >(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        _resource_hash: &[u8; TRUNCATED_HASH_LEN],
        core: &mut NodeCore<P, A, D, L>,
        rng: &mut R,
    ) -> Vec<super::OutboundPacket> {
        use super::RetrievalJob;

        // Find the Sending job for this link_id
        let job_idx = self.pending_retrievals.iter().position(|job| {
            matches!(
                job,
                RetrievalJob::Sending { link_id: lid, .. } if lid == link_id
            )
        });

        let Some(job_idx) = job_idx else {
            return Vec::new();
        };

        // Extract only the hashes we need (avoids cloning the entire Vec)
        let (current_hash, next_hash) = match &self.pending_retrievals[job_idx] {
            RetrievalJob::Sending {
                message_hashes,
                idx,
                ..
            } => {
                let current = message_hashes[*idx];
                let next = message_hashes.get(*idx + 1).copied();
                (current, next)
            }
        };

        self.propagation_mark_delivered(&current_hash);

        if let Some(next) = next_hash {
            let RetrievalJob::Sending { idx, .. } = &mut self.pending_retrievals[job_idx];
            *idx += 1;
            self.send_stored_message_resource(&next, link_id, core, rng)
        } else {
            self.pending_retrievals.remove(job_idx);
            Vec::new()
        }
    }

    /// Check if a retrieval job exists for the given link_id.
    pub fn has_retrieval_job_for_link(&self, link_id: &[u8; TRUNCATED_HASH_LEN]) -> bool {
        use super::RetrievalJob;

        self.pending_retrievals.iter().any(|job| {
            matches!(
                job,
                RetrievalJob::Sending { link_id: lid, .. } if lid == link_id
            )
        })
    }
}
