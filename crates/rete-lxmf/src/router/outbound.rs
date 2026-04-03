//! Outbound message queue — handle_outbound, process_outbound, delivery receipts.

use rete_core::{Packet, TRUNCATED_HASH_LEN};
use rete_stack::{NodeCore, OutboundPacket};

use crate::message::DeliveryMethod;
use crate::propagation::MessageStore;
use crate::LXMessage;

use super::{LxmfEvent, LxmfRouter};

/// Maximum delivery attempts before marking a message as failed.
pub const MAX_DELIVERY_ATTEMPTS: u32 = 5;

/// Seconds to wait between delivery retry attempts.
pub const DELIVERY_RETRY_WAIT: u64 = 10;

/// Maximum age (seconds) for stamp cost cache entries before pruning.
pub const STAMP_COST_MAX_AGE: u64 = 30 * 24 * 3600; // 30 days

/// Current state of an outbound message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OutboundState {
    /// Queued, not yet attempted.
    Queued,
    /// Actively being sent (link establishing or resource in flight).
    Sending,
    /// Delivered (proof received). Terminal.
    Delivered,
    /// Failed after max attempts. Terminal.
    Failed,
}

/// Tracking entry for an outbound message.
pub(super) struct OutboundEntry {
    /// The LXMF message being sent.
    pub message: LXMessage,
    /// SHA-256 hash of the packed message (for dedup and receipt tracking).
    pub message_hash: [u8; 32],
    /// Packet hash from the last send attempt (for ProofReceived correlation).
    pub packet_hash: Option<[u8; 32]>,
    /// Number of delivery attempts so far.
    pub delivery_attempts: u32,
    /// Monotonic timestamp of next allowed delivery attempt.
    pub next_delivery_attempt: u64,
    /// Current outbound state.
    pub state: OutboundState,
}

/// State machine for outbound direct delivery over a link.
pub(super) enum OutboundDirectJob {
    /// Link is being established to the destination.
    Linking {
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        link_id: [u8; TRUNCATED_HASH_LEN],
        message_hash: [u8; 32],
    },
    /// Link established, resource being sent.
    Sending {
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        link_id: [u8; TRUNCATED_HASH_LEN],
        message_hash: [u8; 32],
    },
}

impl OutboundDirectJob {
    pub fn link_id(&self) -> &[u8; TRUNCATED_HASH_LEN] {
        match self {
            Self::Linking { link_id, .. } | Self::Sending { link_id, .. } => link_id,
        }
    }

    pub fn message_hash(&self) -> &[u8; 32] {
        match self {
            Self::Linking { message_hash, .. } | Self::Sending { message_hash, .. } => {
                message_hash
            }
        }
    }

    pub fn dest_hash(&self) -> &[u8; TRUNCATED_HASH_LEN] {
        match self {
            Self::Linking { dest_hash, .. } | Self::Sending { dest_hash, .. } => dest_hash,
        }
    }
}

/// Compute packet hash from raw packet bytes.
fn compute_packet_hash(data: &[u8]) -> Option<[u8; 32]> {
    Packet::parse(data).ok().map(|p| p.compute_hash())
}

impl<S: MessageStore> LxmfRouter<S> {
    /// Queue an outbound LXMF message for delivery.
    ///
    /// Returns the message hash (SHA-256 of packed representation) for tracking.
    /// The message will be sent on the next `process_outbound()` call.
    ///
    /// If the destination has a cached stamp cost (from their announce),
    /// a stamp is auto-generated if the message doesn't already have one.
    /// A reply ticket is included in the message fields so the recipient
    /// can reply without performing proof-of-work.
    pub fn handle_outbound<R: rand_core::RngCore>(
        &mut self,
        mut message: LXMessage,
        now: u64,
        rng: &mut R,
    ) -> [u8; 32] {
        // Include a reply ticket so recipient can reply without PoW
        if !message.fields.contains_key(&crate::FIELD_TICKET) {
            let entry = self.tickets.generate_ticket(
                message.destination_hash,
                rng,
                now,
            );
            // Encode as msgpack [expires, ticket_bytes]
            let mut ticket_field = Vec::new();
            ticket_field.push(0x92); // fixarray(2)
            rete_core::msgpack::write_uint(&mut ticket_field, entry.expires);
            rete_core::msgpack::write_bin(&mut ticket_field, &entry.ticket);
            message.fields.insert(crate::FIELD_TICKET, ticket_field);
        }

        // Auto-assign stamp cost from cache if not already set on message
        if message.stamp.is_none() {
            if let Some(&(_, cost)) = self.outbound_stamp_costs.get(&message.destination_hash) {
                if cost > 0 {
                    if let Some(ticket) = self.tickets.get_outbound_ticket(
                        &message.destination_hash,
                        now,
                    ) {
                        let mid = message.message_id();
                        message.stamp =
                            Some(crate::stamp::ticket_stamp(&ticket, &mid));
                    } else {
                        message.generate_stamp(cost);
                    }
                }
            }
        }

        // Compute hash after all mutations (ticket field, stamp)
        let message_hash = message.hash();

        // Dedup: don't enqueue the same message twice
        if self
            .pending_outbound
            .iter()
            .any(|e| e.message_hash == message_hash)
        {
            return message_hash;
        }

        self.pending_outbound.push(OutboundEntry {
            message,
            message_hash,
            packet_hash: None,
            delivery_attempts: 0,
            next_delivery_attempt: now,
            state: OutboundState::Queued,
        });

        message_hash
    }

    /// Process the outbound queue — attempt delivery for pending messages.
    ///
    /// Should be called periodically from the application event loop.
    /// Returns outbound packets to send and events to emit.
    pub fn process_outbound<R, TS: rete_transport::TransportStorage>(
        &mut self,
        core: &mut NodeCore<TS>,
        rng: &mut R,
        now: u64,
    ) -> (Vec<OutboundPacket>, Vec<LxmfEvent>)
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        let mut packets = Vec::new();
        let mut events = Vec::new();

        // Collect indices to process (avoid borrow issues)
        let indices: Vec<usize> = (0..self.pending_outbound.len()).collect();

        for &i in indices.iter().rev() {
            if i >= self.pending_outbound.len() {
                continue;
            }

            let entry = &self.pending_outbound[i];

            // Remove delivered entries
            if entry.state == OutboundState::Delivered {
                let removed = self.pending_outbound.remove(i);
                events.push(LxmfEvent::MessageDelivered {
                    message_hash: removed.message_hash,
                    dest_hash: removed.message.destination_hash,
                });
                continue;
            }

            // Remove failed entries
            if entry.state == OutboundState::Failed {
                let removed = self.pending_outbound.remove(i);
                events.push(LxmfEvent::MessageFailed {
                    message_hash: removed.message_hash,
                    dest_hash: removed.message.destination_hash,
                });
                continue;
            }

            // Skip entries actively sending via direct link
            if entry.state == OutboundState::Sending {
                continue;
            }

            // Skip if not yet time for retry
            if now < entry.next_delivery_attempt {
                continue;
            }

            let entry = &mut self.pending_outbound[i];

            // Check max attempts
            if entry.delivery_attempts >= MAX_DELIVERY_ATTEMPTS {
                entry.state = OutboundState::Failed;
                continue;
            }

            // Attempt delivery based on method
            match entry.message.method {
                DeliveryMethod::Opportunistic => {
                    let payload = Self::pack_opportunistic(&entry.message);
                    match core.build_data_packet(
                        &entry.message.destination_hash,
                        &payload,
                        rng,
                        now,
                    ) {
                        Ok(pkt_data) => {
                            // Extract packet hash for receipt correlation
                            entry.packet_hash = compute_packet_hash(&pkt_data);
                            packets.push(OutboundPacket::broadcast(pkt_data));
                        }
                        Err(_) => {
                            // Identity not cached — can't send yet
                        }
                    }
                    entry.delivery_attempts += 1;
                    entry.next_delivery_attempt = now + DELIVERY_RETRY_WAIT;
                }
                DeliveryMethod::Direct => {
                    // Check if we already have an active direct job for this message
                    let has_job = self
                        .outbound_direct_jobs
                        .iter()
                        .any(|j| *j.message_hash() == entry.message_hash);

                    if !has_job {
                        // Try to establish a link
                        match core.initiate_link(entry.message.destination_hash, now, rng) {
                            Ok((pkt, link_id)) => {
                                self.outbound_direct_jobs.push(OutboundDirectJob::Linking {
                                    dest_hash: entry.message.destination_hash,
                                    link_id,
                                    message_hash: entry.message_hash,
                                });
                                entry.state = OutboundState::Sending;
                                packets.push(pkt);
                            }
                            Err(_) => {
                                // No path — can't initiate link
                            }
                        }
                        entry.delivery_attempts += 1;
                        entry.next_delivery_attempt = now + DELIVERY_RETRY_WAIT;
                    }
                }
                _ => {
                    // Propagation delivery not yet implemented in outbound queue
                    entry.delivery_attempts += 1;
                    entry.next_delivery_attempt = now + DELIVERY_RETRY_WAIT;
                }
            }
        }

        (packets, events)
    }

    /// Advance an outbound direct job when a link is established.
    ///
    /// Returns outbound packets (resource advertisement) if a job matches.
    pub fn advance_outbound_on_link_established<
        R: rand_core::RngCore + rand_core::CryptoRng,
        TS: rete_transport::TransportStorage,
    >(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        core: &mut NodeCore<TS>,
        rng: &mut R,
    ) -> Vec<OutboundPacket> {
        let mut packets = Vec::new();

        for job in &mut self.outbound_direct_jobs {
            if let OutboundDirectJob::Linking {
                dest_hash,
                link_id: job_link_id,
                message_hash,
            } = job
            {
                if job_link_id == link_id {
                    // Find the matching outbound entry and send it
                    if let Some(entry) = self
                        .pending_outbound
                        .iter()
                        .find(|e| e.message_hash == *message_hash)
                    {
                        let data = Self::pack_direct(&entry.message);
                        if let Ok(pkt) = core.start_resource(link_id, &data, rng) {
                            packets.push(pkt);
                        }
                    }
                    *job = OutboundDirectJob::Sending {
                        dest_hash: *dest_hash,
                        link_id: *link_id,
                        message_hash: *message_hash,
                    };
                }
            }
        }

        packets
    }

    /// Handle resource completion for an outbound direct delivery.
    pub fn advance_outbound_on_resource_complete(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
    ) {
        // Find and remove matching direct job
        if let Some(idx) = self
            .outbound_direct_jobs
            .iter()
            .position(|j| *j.link_id() == *link_id)
        {
            let job = self.outbound_direct_jobs.remove(idx);
            // Mark the outbound entry as delivered
            if let Some(entry) = self
                .pending_outbound
                .iter_mut()
                .find(|e| e.message_hash == *job.message_hash())
            {
                entry.state = OutboundState::Delivered;
            }
        }
    }

    /// Clean up outbound direct jobs when a link closes.
    pub fn cleanup_outbound_jobs_for_link(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
    ) {
        // Reset matching outbound entries back to Queued for retry
        let message_hashes: Vec<[u8; 32]> = self
            .outbound_direct_jobs
            .iter()
            .filter(|j| *j.link_id() == *link_id)
            .map(|j| *j.message_hash())
            .collect();

        for mh in &message_hashes {
            if let Some(entry) = self
                .pending_outbound
                .iter_mut()
                .find(|e| e.message_hash == *mh)
            {
                entry.state = OutboundState::Queued;
            }
        }

        self.outbound_direct_jobs
            .retain(|j| *j.link_id() != *link_id);
    }

    /// Prune expired stamp cost cache entries. Returns count removed.
    pub fn prune_stamp_costs(&mut self, now: u64) -> usize {
        let before = self.outbound_stamp_costs.len();
        self.outbound_stamp_costs
            .retain(|_, &mut (ts, _)| now.saturating_sub(ts) < STAMP_COST_MAX_AGE);
        before - self.outbound_stamp_costs.len()
    }

    // -----------------------------------------------------------------------
    // Serialization for persistence
    // -----------------------------------------------------------------------

    /// Export outbound stamp cost cache as msgpack bytes.
    pub fn export_stamp_costs(&self) -> Vec<u8> {
        use rete_core::msgpack;
        let mut buf = Vec::new();
        msgpack::write_array_header(&mut buf, self.outbound_stamp_costs.len());
        for (dh, &(ts, cost)) in &self.outbound_stamp_costs {
            buf.push(0x93); // fixarray(3)
            msgpack::write_bin(&mut buf, dh);
            msgpack::write_uint(&mut buf, ts);
            msgpack::write_uint(&mut buf, cost as u64);
        }
        buf
    }

    /// Import outbound stamp cost cache from msgpack bytes.
    pub fn import_stamp_costs(&mut self, data: &[u8]) {
        use rete_core::msgpack;
        let mut pos = 0;
        let count = match msgpack::read_array_len(data, &mut pos) {
            Ok(n) => n,
            Err(_) => return,
        };
        for _ in 0..count {
            if let Ok(arr_len) = msgpack::read_array_len(data, &mut pos) {
                if arr_len >= 3 {
                    if let Ok(dh_bytes) = msgpack::read_bin_or_str(data, &mut pos) {
                        if let Ok(ts) = msgpack::read_uint(data, &mut pos) {
                            if let Ok(cost) = msgpack::read_uint(data, &mut pos) {
                                if dh_bytes.len() >= TRUNCATED_HASH_LEN {
                                    let mut dh = [0u8; TRUNCATED_HASH_LEN];
                                    dh.copy_from_slice(&dh_bytes[..TRUNCATED_HASH_LEN]);
                                    self.outbound_stamp_costs.insert(dh, (ts, cost as u8));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Export ticket cache for persistence.
    pub fn export_tickets(&self) -> Vec<u8> {
        self.tickets.export()
    }

    /// Import ticket cache from persistence.
    pub fn import_tickets(&mut self, data: &[u8]) {
        self.tickets.import(data);
    }

    /// Export outbound queue for persistence.
    ///
    /// Returns a list of packed LXMF messages (only non-terminal entries).
    pub fn export_outbound_queue(&self) -> Vec<Vec<u8>> {
        self.pending_outbound
            .iter()
            .filter(|e| e.state != OutboundState::Delivered && e.state != OutboundState::Failed)
            .map(|e| e.message.pack())
            .collect()
    }

    /// Import outbound queue from persistence.
    ///
    /// Each entry is a packed LXMF message. Re-enqueues them with Queued state.
    pub fn import_outbound_queue(&mut self, entries: &[Vec<u8>], now: u64) {
        for packed in entries {
            if let Ok(msg) = LXMessage::unpack(packed, None) {
                let message_hash = msg.hash();
                // Skip if already in queue
                if self
                    .pending_outbound
                    .iter()
                    .any(|e| e.message_hash == message_hash)
                {
                    continue;
                }
                self.pending_outbound.push(OutboundEntry {
                    message: msg,
                    message_hash,
                    packet_hash: None,
                    delivery_attempts: 0,
                    next_delivery_attempt: now,
                    state: OutboundState::Queued,
                });
            }
        }
    }

    /// Check if a ProofReceived event corresponds to an outbound message.
    ///
    /// Returns an event if a match is found.
    pub fn check_delivery_receipt(
        &mut self,
        packet_hash: &[u8; 32],
    ) -> Option<LxmfEvent> {
        if let Some(entry) = self
            .pending_outbound
            .iter_mut()
            .find(|e| e.packet_hash.as_ref() == Some(packet_hash))
        {
            entry.state = OutboundState::Delivered;
            Some(LxmfEvent::MessageDelivered {
                message_hash: entry.message_hash,
                dest_hash: entry.message.destination_hash,
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::propagation::InMemoryMessageStore;
    use crate::router::codec::parse_lxmf_announce_data;
    use crate::LxmfRouter;
    use rete_core::Identity;
    use std::collections::BTreeMap;

    type TestNodeCore = NodeCore<rete_transport::HeaplessStorage<64, 16, 128, 4>>;

    fn make_core(seed: &[u8]) -> TestNodeCore {
        let id = Identity::from_seed(seed).unwrap();
        TestNodeCore::new(id, "testapp", &["aspect1"]).unwrap()
    }

    fn make_test_msg(dest_hash: [u8; 16]) -> LXMessage {
        let source = Identity::from_seed(b"outbound-test-source").unwrap();
        LXMessage::new(
            dest_hash,
            source.hash(),
            &source,
            b"Test",
            b"Hello",
            BTreeMap::new(),
            1700000000.0,
        )
        .unwrap()
    }

    #[test]
    fn test_handle_outbound_enqueues() {
        let mut core = make_core(b"outbound-enqueue");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        let msg = make_test_msg([0xAA; 16]);

        let hash = router.handle_outbound(msg, 1000, &mut rand::thread_rng());
        assert_eq!(hash.len(), 32);
        assert_eq!(router.pending_outbound.len(), 1);
        assert_eq!(router.pending_outbound[0].message_hash, hash);
        assert_eq!(router.pending_outbound[0].state, OutboundState::Queued);
    }

    #[test]
    fn test_handle_outbound_returns_message_hash() {
        let mut core = make_core(b"outbound-hash");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        let msg = make_test_msg([0xBB; 16]);

        let hash = router.handle_outbound(msg, 1000, &mut rand::thread_rng());
        assert_eq!(hash.len(), 32);
        // Hash should match the packed message (which now includes ticket field)
        let actual_hash = router.pending_outbound[0].message.hash();
        assert_eq!(hash, actual_hash);
    }

    #[test]
    fn test_handle_outbound_dedup() {
        let mut core = make_core(b"outbound-dedup");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        let msg1 = make_test_msg([0xCC; 16]);

        let h1 = router.handle_outbound(msg1, 1000, &mut rand::thread_rng());
        // Try to enqueue a message with the same hash (already in queue)
        // The ticket is random, so a new message won't dedup unless it's truly the same.
        // Instead, test dedup by trying to re-enqueue with the same hash manually.
        let msg2 = router.pending_outbound[0].message.pack();
        let msg2 = LXMessage::unpack(&msg2, None).unwrap();
        let h2 = router.handle_outbound(msg2, 1000, &mut rand::thread_rng());
        // The second enqueue finds the same hash already in queue → dedup
        assert_eq!(h1, h2);
        assert_eq!(router.pending_outbound.len(), 1);
    }

    #[test]
    fn test_handle_outbound_auto_assigns_stamp_cost() {
        let mut core = make_core(b"outbound-stamp");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);

        let dest_hash = [0xDD; 16];
        router.outbound_stamp_costs.insert(dest_hash, (1000, 1)); // cost=1

        let msg = make_test_msg(dest_hash);
        assert!(msg.stamp.is_none());

        router.handle_outbound(msg, 1000, &mut rand::thread_rng());
        // Stamp should have been generated
        assert!(router.pending_outbound[0].message.stamp.is_some());
    }

    #[test]
    fn test_handle_outbound_uses_ticket_when_available() {
        let mut core = make_core(b"outbound-ticket");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);

        let dest_hash = [0xEE; 16];
        router.outbound_stamp_costs.insert(dest_hash, (1000, 8)); // cost=8
        router
            .tickets
            .store_outbound(dest_hash, [0x42, 0x37], 5000);

        let msg = make_test_msg(dest_hash);
        router.handle_outbound(msg, 1000, &mut rand::thread_rng());

        // Should have a ticket-based stamp, not a PoW stamp
        let stamp = router.pending_outbound[0].message.stamp.unwrap();
        // Verify it's a ticket stamp (derived from ticket + message_id)
        let mid = router.pending_outbound[0].message.message_id();
        let expected = crate::stamp::ticket_stamp(&[0x42, 0x37], &mid);
        assert_eq!(stamp, expected);
    }

    #[test]
    fn test_process_outbound_skips_before_retry_time() {
        let mut core = make_core(b"outbound-skip");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        let msg = make_test_msg([0xFF; 16]);

        router.handle_outbound(msg, 1000, &mut rand::thread_rng());
        // Set next attempt in the future
        router.pending_outbound[0].next_delivery_attempt = 2000;
        router.pending_outbound[0].delivery_attempts = 1;

        let mut rng = rand::thread_rng();
        let (pkts, evts) = router.process_outbound(&mut core, &mut rng, 1500);
        assert!(pkts.is_empty());
        assert!(evts.is_empty());
        // Attempts unchanged
        assert_eq!(router.pending_outbound[0].delivery_attempts, 1);
    }

    #[test]
    fn test_process_outbound_increments_attempts() {
        let mut core = make_core(b"outbound-attempts");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        let msg = make_test_msg([0x11; 16]);

        router.handle_outbound(msg, 1000, &mut rand::thread_rng());
        assert_eq!(router.pending_outbound[0].delivery_attempts, 0);

        let mut rng = rand::thread_rng();
        let _ = router.process_outbound(&mut core, &mut rng, 1000);
        assert_eq!(router.pending_outbound[0].delivery_attempts, 1);
    }

    #[test]
    fn test_process_outbound_fails_after_max_attempts() {
        let mut core = make_core(b"outbound-maxfail");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        let msg = make_test_msg([0x22; 16]);

        router.handle_outbound(msg, 0, &mut rand::thread_rng());
        router.pending_outbound[0].delivery_attempts = MAX_DELIVERY_ATTEMPTS;

        let mut rng = rand::thread_rng();
        let (_, evts) = router.process_outbound(&mut core, &mut rng, 100);
        // Entry should be marked failed
        assert_eq!(router.pending_outbound[0].state, OutboundState::Failed);
        // Next process call should emit MessageFailed and remove
        let (_, evts) = router.process_outbound(&mut core, &mut rng, 100);
        assert_eq!(evts.len(), 1);
        assert!(matches!(evts[0], LxmfEvent::MessageFailed { .. }));
        assert!(router.pending_outbound.is_empty());
    }

    #[test]
    fn test_check_delivery_receipt_matches() {
        let mut core = make_core(b"receipt-match");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        let msg = make_test_msg([0x33; 16]);

        router.handle_outbound(msg, 1000, &mut rand::thread_rng());
        let pkt_hash = [0x99; 32];
        router.pending_outbound[0].packet_hash = Some(pkt_hash);

        let event = router.check_delivery_receipt(&pkt_hash);
        assert!(event.is_some());
        assert!(matches!(
            event.unwrap(),
            LxmfEvent::MessageDelivered { .. }
        ));
        assert_eq!(router.pending_outbound[0].state, OutboundState::Delivered);
    }

    #[test]
    fn test_check_delivery_receipt_unknown_hash() {
        let mut core = make_core(b"receipt-unknown");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        let msg = make_test_msg([0x44; 16]);

        router.handle_outbound(msg, 1000, &mut rand::thread_rng());
        let event = router.check_delivery_receipt(&[0xFF; 32]);
        assert!(event.is_none());
    }

    #[test]
    fn test_delivered_entry_removed_on_next_process() {
        let mut core = make_core(b"receipt-cleanup");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        let msg = make_test_msg([0x55; 16]);

        router.handle_outbound(msg, 1000, &mut rand::thread_rng());
        router.pending_outbound[0].state = OutboundState::Delivered;

        let mut rng = rand::thread_rng();
        let (_, evts) = router.process_outbound(&mut core, &mut rng, 2000);
        assert_eq!(evts.len(), 1);
        assert!(matches!(evts[0], LxmfEvent::MessageDelivered { .. }));
        assert!(router.pending_outbound.is_empty());
    }

    #[test]
    fn test_cleanup_outbound_jobs_for_link() {
        let mut core = make_core(b"outbound-cleanup");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        let msg = make_test_msg([0x66; 16]);

        let hash = router.handle_outbound(msg, 1000, &mut rand::thread_rng());
        let link_id = [0x77; 16];

        router.outbound_direct_jobs.push(OutboundDirectJob::Linking {
            dest_hash: [0x66; 16],
            link_id,
            message_hash: hash,
        });
        router.pending_outbound[0].state = OutboundState::Sending;

        router.cleanup_outbound_jobs_for_link(&link_id);
        assert!(router.outbound_direct_jobs.is_empty());
        assert_eq!(router.pending_outbound[0].state, OutboundState::Queued);
    }

    #[test]
    fn test_constants() {
        assert_eq!(MAX_DELIVERY_ATTEMPTS, 5);
        assert_eq!(DELIVERY_RETRY_WAIT, 10);
    }

    #[test]
    fn test_outbound_message_includes_ticket() {
        let mut core = make_core(b"outbound-ticket-issue");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        let msg = make_test_msg([0x77; 16]);
        assert!(!msg.fields.contains_key(&crate::FIELD_TICKET));

        router.handle_outbound(msg, 1000, &mut rand::thread_rng());

        // Message should now have a ticket field
        assert!(router.pending_outbound[0]
            .message
            .fields
            .contains_key(&crate::FIELD_TICKET));

        // Ticket should be stored in inbound cache for validation
        let tickets = router.tickets.get_inbound_tickets(&[0x77; 16], 1000);
        assert_eq!(tickets.len(), 1);
    }

    #[test]
    fn test_export_import_stamp_costs_roundtrip() {
        let mut core = make_core(b"export-stamp-costs");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);

        router.outbound_stamp_costs.insert([0x11; 16], (1000, 4));
        router.outbound_stamp_costs.insert([0x22; 16], (2000, 8));

        let exported = router.export_stamp_costs();

        let mut router2 = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        router2.import_stamp_costs(&exported);

        assert_eq!(router2.get_outbound_stamp_cost(&[0x11; 16]), Some(4));
        assert_eq!(router2.get_outbound_stamp_cost(&[0x22; 16]), Some(8));
    }

    #[test]
    fn test_export_import_tickets_roundtrip() {
        let mut core = make_core(b"export-tickets");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);

        router.tickets.store_inbound([0xAA; 16], [0x12, 0x34], 5000);
        router.tickets.store_outbound([0xBB; 16], [0x56, 0x78], 6000);

        let exported = router.export_tickets();

        let mut router2 = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        router2.import_tickets(&exported);

        assert_eq!(
            router2.tickets.get_inbound_tickets(&[0xAA; 16], 1000),
            vec![[0x12, 0x34]]
        );
        assert_eq!(
            router2.tickets.get_outbound_ticket(&[0xBB; 16], 1000),
            Some([0x56, 0x78])
        );
    }

    #[test]
    fn test_export_import_outbound_queue_roundtrip() {
        let mut core = make_core(b"export-queue");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);

        let msg = make_test_msg([0xCC; 16]);
        router.handle_outbound(msg, 1000, &mut rand::thread_rng());

        let exported = router.export_outbound_queue();
        assert_eq!(exported.len(), 1);

        let mut router2 = LxmfRouter::<InMemoryMessageStore>::register(&mut core);
        router2.import_outbound_queue(&exported, 2000);
        assert_eq!(router2.pending_outbound.len(), 1);
        assert_eq!(
            router2.pending_outbound[0].message.destination_hash,
            [0xCC; 16]
        );
    }

    #[test]
    fn test_announce_includes_stamp_cost() {
        let mut core = make_core(b"announce-stamp");
        let mut router = LxmfRouter::<InMemoryMessageStore>::register(&mut core);

        // Default: no cost
        let data = router.build_announce_app_data();
        let parsed = parse_lxmf_announce_data(&data).unwrap();
        assert_eq!(parsed.stamp_cost, None); // 0 = no cost

        // Set cost
        router.set_inbound_stamp_cost(Some(8));
        let data = router.build_announce_app_data();
        let parsed = parse_lxmf_announce_data(&data).unwrap();
        assert_eq!(parsed.stamp_cost, Some(8));
    }
}
