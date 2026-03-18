//! LxmfRouter — LXMF delivery plumbing on top of NodeCore.
//!
//! Registers an `lxmf.delivery` destination with NodeCore and provides
//! helpers for opportunistic/direct send and receive.
//!
//! When propagation is enabled, also registers an `lxmf.propagation`
//! destination and manages store-and-forward message handling.

use rete_core::TRUNCATED_HASH_LEN;
use rete_stack::{NodeCore, NodeEvent, OutboundPacket};

use crate::propagation::{InMemoryMessageStore, PropagationNode};
use crate::{DeliveryMethod, LXMessage};

/// LXMF delivery event, wrapping NodeEvent with LXMF-specific variants.
#[derive(Debug)]
pub enum LxmfEvent {
    /// An LXMF message was received (either opportunistic or direct).
    MessageReceived {
        /// The parsed LXMF message.
        message: LXMessage,
        /// How it was delivered.
        method: DeliveryMethod,
    },
    /// An LXMF peer announced (extracted display_name from app_data).
    PeerAnnounced {
        /// Destination hash of the LXMF peer.
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        /// Display name from announce app_data (if parseable).
        display_name: Option<Vec<u8>>,
    },
    /// A message was deposited into the propagation store.
    PropagationDeposit {
        /// Destination hash the message is addressed to.
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        /// SHA-256 hash of the deposited message.
        message_hash: [u8; 32],
    },
    /// An announce was received for a destination that has pending
    /// messages in the propagation store.
    PropagationForward {
        /// Destination hash that announced.
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        /// Number of messages pending for this destination.
        count: usize,
    },
    /// A non-LXMF NodeEvent (pass-through).
    Other(NodeEvent),
}

/// LXMF router — manages `lxmf.delivery` destination and message handling.
///
/// Does NOT own or wrap NodeCore. Holds only derived state and takes
/// `&mut NodeCore` as parameter to avoid lifetime issues.
pub struct LxmfRouter {
    /// The `lxmf.delivery` destination hash registered with NodeCore.
    delivery_dest_hash: [u8; TRUNCATED_HASH_LEN],
    /// Display name advertised in LXMF announces.
    display_name: Option<Vec<u8>>,
    /// Propagation node (store-and-forward), if enabled.
    propagation: Option<PropagationNode<InMemoryMessageStore>>,
    /// The `lxmf.propagation` destination hash, if propagation is enabled.
    propagation_dest_hash: Option<[u8; TRUNCATED_HASH_LEN]>,
}

impl LxmfRouter {
    /// Register an `lxmf.delivery` destination on the given NodeCore.
    ///
    /// Sets ProveAll strategy on the delivery destination (LXMF expects
    /// delivery proofs).
    pub fn register<const P: usize, const A: usize, const D: usize, const L: usize>(
        core: &mut NodeCore<P, A, D, L>,
    ) -> Self {
        let dest_hash = core.register_destination("lxmf", &["delivery"]);

        // LXMF delivery always proves received data
        if let Some(dest) = core.get_destination_mut(&dest_hash) {
            dest.set_proof_strategy(rete_stack::ProofStrategy::ProveAll);
        }

        LxmfRouter {
            delivery_dest_hash: dest_hash,
            display_name: None,
            propagation: None,
            propagation_dest_hash: None,
        }
    }

    /// Returns the `lxmf.delivery` destination hash.
    pub fn delivery_dest_hash(&self) -> &[u8; TRUNCATED_HASH_LEN] {
        &self.delivery_dest_hash
    }

    /// Set the display name advertised in LXMF announces.
    pub fn set_display_name(&mut self, name: Vec<u8>) {
        self.display_name = Some(name);
    }

    // -----------------------------------------------------------------------
    // Opportunistic send/receive
    // -----------------------------------------------------------------------

    /// Pack a message for opportunistic delivery.
    ///
    /// Strips the first 16 bytes (dest_hash) from the packed LXMF message,
    /// matching the Python LXMF protocol: the dest_hash is implicit in the
    /// Reticulum packet header.
    pub fn pack_opportunistic(msg: &LXMessage) -> Vec<u8> {
        let mut packed = msg.pack();
        if packed.len() > 16 {
            packed.drain(..16);
        }
        packed
    }

    /// Send an LXMF message opportunistically via encrypted DATA packet.
    ///
    /// Returns the outbound packet, or None if the recipient's identity
    /// is not cached (announce not yet received).
    pub fn send_opportunistic<R, const P: usize, const A: usize, const D: usize, const L: usize>(
        &self,
        core: &mut NodeCore<P, A, D, L>,
        msg: &LXMessage,
        rng: &mut R,
        now: u64,
    ) -> Option<OutboundPacket>
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        let payload = Self::pack_opportunistic(msg);
        let pkt_data = core.build_data_packet(&msg.destination_hash, &payload, rng, now)?;
        Some(OutboundPacket::broadcast(pkt_data))
    }

    /// Try to parse an LXMF message from a received DataReceived event.
    ///
    /// Checks that the dest_hash matches our delivery destination, prepends
    /// the dest_hash back to the payload, then unpacks.
    pub fn try_parse_lxmf(
        &self,
        dest_hash: &[u8; TRUNCATED_HASH_LEN],
        payload: &[u8],
    ) -> Option<LXMessage> {
        if *dest_hash != self.delivery_dest_hash {
            return None;
        }
        // Reconstruct full packed message: dest_hash[16] || payload
        let mut full = Vec::with_capacity(16 + payload.len());
        full.extend_from_slice(dest_hash);
        full.extend_from_slice(payload);
        LXMessage::unpack(&full, None).ok()
    }

    // -----------------------------------------------------------------------
    // Direct send/receive (over Link/Resource)
    // -----------------------------------------------------------------------

    /// Pack a message for direct delivery (full packed message).
    pub fn pack_direct(msg: &LXMessage) -> Vec<u8> {
        msg.pack()
    }

    /// Send an LXMF message directly via Resource over a Link.
    ///
    /// Returns the outbound resource advertisement packet.
    pub fn send_direct<R, const P: usize, const A: usize, const D: usize, const L: usize>(
        &self,
        core: &mut NodeCore<P, A, D, L>,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        msg: &LXMessage,
        rng: &mut R,
    ) -> Option<OutboundPacket>
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        let data = Self::pack_direct(msg);
        core.start_resource(link_id, &data, rng)
    }

    /// Try to parse an LXMF message from Resource data.
    ///
    /// For direct delivery, the resource data is the full packed message.
    pub fn try_parse_lxmf_resource(data: &[u8]) -> Option<LXMessage> {
        LXMessage::unpack(data, None).ok()
    }

    // -----------------------------------------------------------------------
    // Event handling
    // -----------------------------------------------------------------------

    /// Dispatch a NodeEvent through LXMF parsing.
    ///
    /// Returns an LxmfEvent — either a parsed LXMF message, a peer announce,
    /// a propagation event, or the original event wrapped as Other.
    ///
    /// Note: for propagation deposit handling, call `handle_event_mut` instead
    /// so that ResourceComplete events on the propagation link can be deposited
    /// into the store.
    pub fn handle_event(&self, event: NodeEvent) -> LxmfEvent {
        match event {
            NodeEvent::DataReceived {
                dest_hash,
                ref payload,
            } => {
                if let Some(msg) = self.try_parse_lxmf(&dest_hash, payload) {
                    LxmfEvent::MessageReceived {
                        message: msg,
                        method: DeliveryMethod::Opportunistic,
                    }
                } else {
                    LxmfEvent::Other(event)
                }
            }
            NodeEvent::LinkData { ref data, .. } => {
                // Direct delivery: small LXMF messages are sent as link data.
                // The data is the full packed LXMF message (same format as resource).
                if let Some(msg) = Self::try_parse_lxmf_resource(data) {
                    LxmfEvent::MessageReceived {
                        message: msg,
                        method: DeliveryMethod::Direct,
                    }
                } else {
                    LxmfEvent::Other(event)
                }
            }
            NodeEvent::ResourceComplete { ref data, .. } => {
                // Direct delivery: large LXMF messages are sent as resources.
                // Note: Python LXMF compresses resource data with bz2. The example
                // binary decompresses ResourceComplete data before it reaches here.
                // If you call handle_event() directly, decompress first.
                if let Some(msg) = Self::try_parse_lxmf_resource(data) {
                    LxmfEvent::MessageReceived {
                        message: msg,
                        method: DeliveryMethod::Direct,
                    }
                } else {
                    LxmfEvent::Other(event)
                }
            }
            NodeEvent::AnnounceReceived {
                dest_hash,
                ref app_data,
                ..
            } => {
                // Check if propagation has messages for this announcing dest
                if let Some(fwd) = self.check_propagation_forward(&dest_hash) {
                    return fwd;
                }
                // Try to parse announce app_data as LXMF format
                if let Some(ref data) = app_data {
                    if let Some(display_name) = try_parse_lxmf_announce_data(data) {
                        return LxmfEvent::PeerAnnounced {
                            dest_hash,
                            display_name: Some(display_name),
                        };
                    }
                }
                LxmfEvent::Other(event)
            }
            other => LxmfEvent::Other(other),
        }
    }

    /// Dispatch a NodeEvent through LXMF parsing, with mutable access for
    /// propagation deposit handling.
    ///
    /// This is the preferred method when propagation is enabled. When a
    /// ResourceComplete event is received and propagation is active, the
    /// resource data is deposited into the propagation store.
    pub fn handle_event_mut(&mut self, event: NodeEvent, now: u64) -> LxmfEvent {
        // For ResourceComplete: try propagation deposit first if enabled
        if self.propagation.is_some() {
            if let NodeEvent::ResourceComplete { ref data, .. } = event {
                // Try to deposit into propagation store
                if let Some(deposit_event) = self.propagation_deposit(data, now) {
                    return deposit_event;
                }
                // If deposit failed (not valid LXMF), fall through to normal parsing
            }
        }
        // Fall through to immutable handling
        self.handle_event(event)
    }

    // -----------------------------------------------------------------------
    // Announce helpers
    // -----------------------------------------------------------------------

    /// Build LXMF announce app_data in the format Python LXMF expects.
    ///
    /// Format: msgpack array `[display_name_bytes, stamp_cost_int]`
    pub fn build_announce_app_data(&self) -> Vec<u8> {
        self.build_announce_app_data_with_tag(0x00) // stamp_cost = 0
    }

    /// Build msgpack announce app_data: `[display_name, tag_byte]`.
    fn build_announce_app_data_with_tag(&self, tag_byte: u8) -> Vec<u8> {
        let name = self.display_name.as_deref().unwrap_or(b"");
        let mut buf = Vec::with_capacity(name.len() + 4);
        buf.push(0x92); // fixarray of 2
        crate::message::write_bin(&mut buf, name);
        buf.push(tag_byte);
        buf
    }

    /// Queue an LXMF delivery announce.
    pub fn queue_delivery_announce<
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
        let app_data = self.build_announce_app_data();
        core.queue_announce_for(&self.delivery_dest_hash, Some(&app_data), rng, now)
    }

    // -----------------------------------------------------------------------
    // Propagation node support
    // -----------------------------------------------------------------------

    /// Register an `lxmf.propagation` destination and enable store-and-forward.
    ///
    /// Creates a SINGLE destination (identity-bound) for `lxmf.propagation`,
    /// sets ProveAll, and initializes the in-memory message store.
    pub fn register_propagation<const P: usize, const A: usize, const D: usize, const L: usize>(
        &mut self,
        core: &mut NodeCore<P, A, D, L>,
    ) {
        let dest_hash = core.register_destination("lxmf", &["propagation"]);

        if let Some(dest) = core.get_destination_mut(&dest_hash) {
            dest.set_proof_strategy(rete_stack::ProofStrategy::ProveAll);
        }

        self.propagation_dest_hash = Some(dest_hash);
        self.propagation = Some(PropagationNode::new(InMemoryMessageStore::new()));
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

    /// Retrieve pending messages for a destination from the propagation store.
    ///
    /// Returns the packed LXMF message data for each pending message,
    /// or an empty Vec if propagation is not enabled or no messages are pending.
    pub fn propagation_retrieve(
        &self,
        dest_hash: &[u8; TRUNCATED_HASH_LEN],
    ) -> Vec<crate::propagation::StoredMessage> {
        match &self.propagation {
            Some(prop) => prop.retrieve(dest_hash),
            None => Vec::new(),
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
}

/// Try to parse LXMF announce app_data: msgpack `[display_name_bytes, stamp_cost]`
fn try_parse_lxmf_announce_data(data: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;
    let arr_len = crate::message::read_array_len(data, &mut pos).ok()?;
    if arr_len != 2 {
        return None;
    }
    let display_name = crate::message::read_bin(data, &mut pos).ok()?;
    Some(display_name)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rete_core::Identity;
    use std::collections::BTreeMap;

    type TestNodeCore = NodeCore<64, 16, 128, 4>;

    fn make_core(seed: &[u8]) -> TestNodeCore {
        let identity = Identity::from_seed(seed).unwrap();
        TestNodeCore::new(identity, "testapp", &["aspect1"])
    }

    fn make_test_msg(source_seed: &[u8], dest_hash: [u8; 16]) -> (LXMessage, Identity) {
        let source = Identity::from_seed(source_seed).unwrap();
        let source_hash = source.hash();
        let msg = LXMessage::new(
            dest_hash,
            source_hash,
            &source,
            b"Hello",
            b"World",
            BTreeMap::new(),
            1700000000.0,
        )
        .unwrap();
        (msg, source)
    }

    // -------------------------------------------------------------------
    // Step 2.1: LxmfRouter::register()
    // -------------------------------------------------------------------

    #[test]
    fn test_lxmf_router_creates_delivery_dest() {
        let mut core = make_core(b"lxmf-router-test");
        let router = LxmfRouter::register(&mut core);
        assert!(core.get_destination(router.delivery_dest_hash()).is_some());
    }

    #[test]
    fn test_lxmf_delivery_dest_hash_matches_manual_computation() {
        let seed = b"lxmf-hash-verify";
        let mut core = make_core(seed);
        let router = LxmfRouter::register(&mut core);

        let identity = Identity::from_seed(seed).unwrap();
        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name("lxmf", &["delivery"], &mut name_buf).unwrap();
        let expected = rete_core::destination_hash(expanded, Some(&identity.hash()));

        assert_eq!(*router.delivery_dest_hash(), expected);
    }

    #[test]
    fn test_lxmf_delivery_dest_has_prove_all() {
        let mut core = make_core(b"lxmf-prove-test");
        let router = LxmfRouter::register(&mut core);
        let dest = core.get_destination(router.delivery_dest_hash()).unwrap();
        assert_eq!(dest.proof_strategy, rete_stack::ProofStrategy::ProveAll);
    }

    // -------------------------------------------------------------------
    // Step 2.2: Opportunistic send
    // -------------------------------------------------------------------

    #[test]
    fn test_pack_for_opportunistic_strips_dest_hash() {
        let source = Identity::from_seed(b"pack-opp-test").unwrap();
        let source_hash = source.hash();
        let dest_hash = [0xAA; 16];
        let msg = LXMessage::new(
            dest_hash,
            source_hash,
            &source,
            b"Hi",
            b"OK",
            BTreeMap::new(),
            1700000000.0,
        )
        .unwrap();

        let full_packed = msg.pack();
        let opp_packed = LxmfRouter::pack_opportunistic(&msg);

        // Opportunistic should strip dest_hash (first 16 bytes)
        assert_eq!(opp_packed.len(), full_packed.len() - 16);
        assert_eq!(opp_packed, &full_packed[16..]);
    }

    #[test]
    fn test_send_opportunistic_builds_encrypted_data() {
        let mut core = make_core(b"send-opp-test");
        let router = LxmfRouter::register(&mut core);
        let mut rng = rand::thread_rng();

        // Create a recipient and register their identity
        let recipient = Identity::from_seed(b"opp-recipient").unwrap();
        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name("lxmf", &["delivery"], &mut name_buf).unwrap();
        let recipient_dest = rete_core::destination_hash(expanded, Some(&recipient.hash()));
        core.register_peer(&recipient, "lxmf", &["delivery"], 100);

        let (msg, _source) = make_test_msg(b"send-opp-test", recipient_dest);
        let result = router.send_opportunistic(&mut core, &msg, &mut rng, 100);
        assert!(result.is_some(), "should build encrypted data packet");
    }

    // -------------------------------------------------------------------
    // Step 2.3: Opportunistic receive
    // -------------------------------------------------------------------

    #[test]
    fn test_try_parse_lxmf_from_data_event() {
        let mut core = make_core(b"parse-opp-test");
        let router = LxmfRouter::register(&mut core);

        let (msg, _source) = make_test_msg(b"parse-opp-source", *router.delivery_dest_hash());
        let opp_payload = LxmfRouter::pack_opportunistic(&msg);

        let parsed = router
            .try_parse_lxmf(router.delivery_dest_hash(), &opp_payload)
            .expect("should parse LXMF from opportunistic payload");
        assert_eq!(parsed.title, b"Hello");
        assert_eq!(parsed.content, b"World");
    }

    #[test]
    fn test_try_parse_lxmf_prepends_dest_hash() {
        let mut core = make_core(b"prepend-test");
        let router = LxmfRouter::register(&mut core);

        let (msg, _) = make_test_msg(b"prepend-source", *router.delivery_dest_hash());
        let full_packed = msg.pack();
        let opp_payload = &full_packed[16..];

        let parsed = router
            .try_parse_lxmf(router.delivery_dest_hash(), opp_payload)
            .unwrap();
        assert_eq!(parsed.destination_hash, *router.delivery_dest_hash());
    }

    #[test]
    fn test_try_parse_lxmf_rejects_non_lxmf() {
        let mut core = make_core(b"reject-test");
        let router = LxmfRouter::register(&mut core);

        // Wrong dest hash
        let wrong_dest = [0xFF; 16];
        assert!(router.try_parse_lxmf(&wrong_dest, b"garbage").is_none());

        // Right dest hash but garbage payload
        assert!(router
            .try_parse_lxmf(router.delivery_dest_hash(), b"not lxmf")
            .is_none());
    }

    #[test]
    fn test_try_parse_lxmf_roundtrip() {
        let mut core = make_core(b"roundtrip-test");
        let router = LxmfRouter::register(&mut core);

        let (msg, _) = make_test_msg(b"roundtrip-source", *router.delivery_dest_hash());
        let opp_payload = LxmfRouter::pack_opportunistic(&msg);

        let parsed = router
            .try_parse_lxmf(router.delivery_dest_hash(), &opp_payload)
            .unwrap();
        assert_eq!(parsed.title, msg.title);
        assert_eq!(parsed.content, msg.content);
        assert_eq!(parsed.source_hash, msg.source_hash);
        assert!((parsed.timestamp - msg.timestamp).abs() < 0.001);
    }

    // -------------------------------------------------------------------
    // Step 2.4: Direct send/receive
    // -------------------------------------------------------------------

    #[test]
    fn test_pack_for_direct_keeps_full_message() {
        let (msg, _) = make_test_msg(b"direct-pack-test", [0xAA; 16]);
        let direct = LxmfRouter::pack_direct(&msg);
        let full = msg.pack();
        assert_eq!(direct, full);
    }

    #[test]
    fn test_try_parse_lxmf_resource_roundtrip() {
        let (msg, _) = make_test_msg(b"resource-rt-test", [0xBB; 16]);
        let packed = msg.pack();
        let parsed = LxmfRouter::try_parse_lxmf_resource(&packed).unwrap();
        assert_eq!(parsed.title, b"Hello");
        assert_eq!(parsed.content, b"World");
    }

    #[test]
    fn test_try_parse_lxmf_resource_rejects_garbage() {
        assert!(LxmfRouter::try_parse_lxmf_resource(b"not a message").is_none());
        assert!(LxmfRouter::try_parse_lxmf_resource(&[0u8; 50]).is_none());
    }

    // -------------------------------------------------------------------
    // Step 2.5: LxmfEvent + handle_event()
    // -------------------------------------------------------------------

    #[test]
    fn test_handle_event_data_received_lxmf() {
        let mut core = make_core(b"handle-event-test");
        let router = LxmfRouter::register(&mut core);

        let (msg, _) = make_test_msg(b"event-source", *router.delivery_dest_hash());
        let opp_payload = LxmfRouter::pack_opportunistic(&msg);

        let event = NodeEvent::DataReceived {
            dest_hash: *router.delivery_dest_hash(),
            payload: opp_payload,
        };

        match router.handle_event(event) {
            LxmfEvent::MessageReceived { message, method } => {
                assert_eq!(message.title, b"Hello");
                assert_eq!(method, DeliveryMethod::Opportunistic);
            }
            other => panic!("expected MessageReceived, got {:?}", other),
        }
    }

    #[test]
    fn test_handle_event_data_received_non_lxmf() {
        let mut core = make_core(b"handle-other-test");
        let router = LxmfRouter::register(&mut core);

        let event = NodeEvent::DataReceived {
            dest_hash: [0xFF; 16], // not our delivery dest
            payload: b"not lxmf".to_vec(),
        };

        assert!(matches!(router.handle_event(event), LxmfEvent::Other(_)));
    }

    #[test]
    fn test_handle_event_resource_complete_lxmf() {
        let mut core = make_core(b"handle-resource-test");
        let router = LxmfRouter::register(&mut core);

        let (msg, _) = make_test_msg(b"resource-source", *router.delivery_dest_hash());
        let packed = LxmfRouter::pack_direct(&msg);

        let event = NodeEvent::ResourceComplete {
            link_id: [0xAA; 16],
            resource_hash: [0xBB; 16],
            data: packed,
        };

        match router.handle_event(event) {
            LxmfEvent::MessageReceived { message, method } => {
                assert_eq!(message.title, b"Hello");
                assert_eq!(method, DeliveryMethod::Direct);
            }
            other => panic!("expected MessageReceived, got {:?}", other),
        }
    }

    #[test]
    fn test_handle_event_announce_other() {
        let mut core = make_core(b"handle-announce-test");
        let router = LxmfRouter::register(&mut core);

        let event = NodeEvent::AnnounceReceived {
            dest_hash: [0xCC; 16],
            identity_hash: [0xDD; 16],
            hops: 1,
            app_data: None,
        };

        assert!(matches!(router.handle_event(event), LxmfEvent::Other(_)));
    }

    // -------------------------------------------------------------------
    // Step 2.6: Announce helpers
    // -------------------------------------------------------------------

    #[test]
    fn test_announce_app_data_format_matches_python() {
        let mut core = make_core(b"announce-format-test");
        let mut router = LxmfRouter::register(&mut core);
        router.set_display_name(b"TestNode".to_vec());

        let data = router.build_announce_app_data();

        // Should be: fixarray(2) + bin8(8, "TestNode") + fixint(0)
        assert_eq!(data[0], 0x92); // fixarray of 2
        assert_eq!(data[1], 0xc4); // bin8
        assert_eq!(data[2], 8); // length
        assert_eq!(&data[3..11], b"TestNode");
        assert_eq!(data[11], 0x00); // stamp_cost = 0
    }

    #[test]
    fn test_queue_delivery_announce() {
        let mut core = make_core(b"queue-delivery-test");
        let router = LxmfRouter::register(&mut core);
        let mut rng = rand::thread_rng();

        assert!(router.queue_delivery_announce(&mut core, &mut rng, 1000));
        let pending = core.transport.pending_outbound(1000);
        assert_eq!(pending.len(), 1);

        let pkt = rete_core::Packet::parse(&pending[0]).unwrap();
        assert_eq!(pkt.packet_type, rete_core::PacketType::Announce);
        assert_eq!(pkt.destination_hash, router.delivery_dest_hash());
    }

    // -------------------------------------------------------------------
    // Phase 5: LXMF Announce parsing
    // -------------------------------------------------------------------

    #[test]
    fn test_parse_lxmf_announce_data_valid() {
        // Build valid LXMF announce app_data
        let mut data = Vec::new();
        data.push(0x92); // fixarray of 2
        data.push(0xc4); // bin8
        data.push(5); // length
        data.extend_from_slice(b"Alice");
        data.push(0x00); // stamp_cost

        let name = try_parse_lxmf_announce_data(&data).unwrap();
        assert_eq!(name, b"Alice");
    }

    #[test]
    fn test_parse_lxmf_announce_data_empty_name() {
        let mut data = Vec::new();
        data.push(0x92);
        data.push(0xc4);
        data.push(0);
        data.push(0x00);

        let name = try_parse_lxmf_announce_data(&data).unwrap();
        assert!(name.is_empty());
    }

    #[test]
    fn test_parse_lxmf_announce_data_garbage() {
        assert!(try_parse_lxmf_announce_data(b"not msgpack").is_none());
        assert!(try_parse_lxmf_announce_data(&[]).is_none());
    }

    #[test]
    fn test_handle_event_lxmf_peer_announced() {
        let mut core = make_core(b"peer-announce-test");
        let router = LxmfRouter::register(&mut core);

        // Build LXMF announce app_data
        let mut app_data = Vec::new();
        app_data.push(0x92);
        app_data.push(0xc4);
        app_data.push(3);
        app_data.extend_from_slice(b"Bob");
        app_data.push(0x00);

        let event = NodeEvent::AnnounceReceived {
            dest_hash: [0xEE; 16],
            identity_hash: [0xFF; 16],
            hops: 0,
            app_data: Some(app_data),
        };

        match router.handle_event(event) {
            LxmfEvent::PeerAnnounced {
                dest_hash,
                display_name,
            } => {
                assert_eq!(dest_hash, [0xEE; 16]);
                assert_eq!(display_name.unwrap(), b"Bob");
            }
            other => panic!("expected PeerAnnounced, got {:?}", other),
        }
    }

    // -------------------------------------------------------------------
    // Propagation tests
    // -------------------------------------------------------------------

    #[test]
    fn test_register_propagation_creates_dest() {
        let mut core = make_core(b"prop-register-test");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);

        assert!(router.propagation_enabled());
        let prop_hash = router.propagation_dest_hash().unwrap();
        assert!(core.get_destination(prop_hash).is_some());
    }

    #[test]
    fn test_register_propagation_dest_hash_matches_manual_computation() {
        let seed = b"prop-hash-verify";
        let mut core = make_core(seed);
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);

        let identity = Identity::from_seed(seed).unwrap();
        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name("lxmf", &["propagation"], &mut name_buf).unwrap();
        let expected = rete_core::destination_hash(expanded, Some(&identity.hash()));

        assert_eq!(*router.propagation_dest_hash().unwrap(), expected);
    }

    #[test]
    fn test_propagation_dest_has_prove_all() {
        let mut core = make_core(b"prop-prove-test");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);

        let prop_hash = router.propagation_dest_hash().unwrap();
        let dest = core.get_destination(prop_hash).unwrap();
        assert_eq!(dest.proof_strategy, rete_stack::ProofStrategy::ProveAll);
    }

    #[test]
    fn test_handle_propagation_deposit() {
        let mut core = make_core(b"prop-deposit-test");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);

        // Create a valid LXMF message to deposit
        let (msg, _) = make_test_msg(b"deposit-source", [0x42; 16]);
        let packed = msg.pack();

        let result = router.propagation_deposit(&packed, 1000);
        assert!(result.is_some());
        match result.unwrap() {
            LxmfEvent::PropagationDeposit {
                dest_hash,
                message_hash,
            } => {
                assert_eq!(dest_hash, [0x42; 16]);
                assert_ne!(message_hash, [0u8; 32]); // should be a real hash
            }
            other => panic!("expected PropagationDeposit, got {:?}", other),
        }
        assert_eq!(router.propagation_message_count(), 1);
    }

    #[test]
    fn test_handle_propagation_retrieve() {
        let mut core = make_core(b"prop-retrieve-test");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);

        let dest = [0x42; 16];
        let (msg, _) = make_test_msg(b"retrieve-source", dest);
        let packed = msg.pack();

        router.propagation_deposit(&packed, 1000);

        let msgs = router.propagation_retrieve(&dest);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].dest_hash, dest);
    }

    #[test]
    fn test_propagation_forward_on_announce() {
        let mut core = make_core(b"prop-forward-test");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);

        let dest = [0x42; 16];
        let (msg, _) = make_test_msg(b"forward-source", dest);
        let packed = msg.pack();
        router.propagation_deposit(&packed, 1000);

        // Simulate an announce from the destination we have messages for
        let event = NodeEvent::AnnounceReceived {
            dest_hash: dest,
            identity_hash: [0xAA; 16],
            hops: 0,
            app_data: None,
        };

        match router.handle_event(event) {
            LxmfEvent::PropagationForward { dest_hash, count } => {
                assert_eq!(dest_hash, dest);
                assert_eq!(count, 1);
            }
            other => panic!("expected PropagationForward, got {:?}", other),
        }
    }

    #[test]
    fn test_propagation_dedup() {
        let mut core = make_core(b"prop-dedup-test");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);

        let (msg, _) = make_test_msg(b"dedup-source", [0x42; 16]);
        let packed = msg.pack();

        assert!(router.propagation_deposit(&packed, 1000).is_some());
        assert!(router.propagation_deposit(&packed, 1001).is_none()); // duplicate
        assert_eq!(router.propagation_message_count(), 1);
    }

    #[test]
    fn test_propagation_prune() {
        let mut core = make_core(b"prop-prune-test");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);

        let (msg1, _) = make_test_msg(b"prune-source-1", [0x42; 16]);
        let (msg2, _) = make_test_msg(b"prune-source-2", [0x42; 16]);
        router.propagation_deposit(&msg1.pack(), 1000);
        router.propagation_deposit(&msg2.pack(), 5000);

        // Prune messages older than 2000 seconds from now=6000
        let pruned = router.prune_propagation(6000, 2000);
        assert_eq!(pruned, 1); // only the one at timestamp 1000
        assert_eq!(router.propagation_message_count(), 1);
    }

    #[test]
    fn test_propagation_not_enabled_returns_none() {
        let mut core = make_core(b"prop-disabled-test");
        let mut router = LxmfRouter::register(&mut core);
        // Propagation NOT registered

        assert!(!router.propagation_enabled());
        assert!(router.propagation_dest_hash().is_none());
        assert!(router.propagation_deposit(&[0u8; 100], 1000).is_none());
        assert!(router.propagation_retrieve(&[0x42; 16]).is_empty());
        assert!(!router.propagation_mark_delivered(&[0u8; 32]));
        assert_eq!(router.prune_propagation(1000, 100), 0);
        assert_eq!(router.propagation_message_count(), 0);
    }

    #[test]
    fn test_handle_event_mut_deposits_resource() {
        let mut core = make_core(b"prop-event-mut-test");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);

        // Create a valid LXMF message as resource data
        let (msg, _) = make_test_msg(b"event-mut-source", [0x42; 16]);
        let packed = msg.pack();

        let event = NodeEvent::ResourceComplete {
            link_id: [0xAA; 16],
            resource_hash: [0xBB; 16],
            data: packed,
        };

        match router.handle_event_mut(event, 1000) {
            LxmfEvent::PropagationDeposit { dest_hash, .. } => {
                assert_eq!(dest_hash, [0x42; 16]);
            }
            other => panic!("expected PropagationDeposit, got {:?}", other),
        }
        assert_eq!(router.propagation_message_count(), 1);
    }

    #[test]
    fn test_handle_event_mut_falls_through_when_not_lxmf() {
        let mut core = make_core(b"prop-fallthrough-test");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);

        // Resource with non-LXMF data (too short to be LXMF)
        let event = NodeEvent::ResourceComplete {
            link_id: [0xAA; 16],
            resource_hash: [0xBB; 16],
            data: b"not lxmf".to_vec(),
        };

        // Should fall through to Other since it's not valid LXMF
        assert!(matches!(
            router.handle_event_mut(event, 1000),
            LxmfEvent::Other(_)
        ));
    }

    #[test]
    fn test_propagation_announce_app_data_format() {
        let mut core = make_core(b"prop-announce-format");
        let mut router = LxmfRouter::register(&mut core);
        router.set_display_name(b"PropNode".to_vec());
        router.register_propagation(&mut core);

        let data = router.build_propagation_announce_data();

        // Should be: fixarray(2) + bin8(8, "PropNode") + true(0xc3)
        assert_eq!(data[0], 0x92); // fixarray of 2
        assert_eq!(data[1], 0xc4); // bin8
        assert_eq!(data[2], 8); // length
        assert_eq!(&data[3..11], b"PropNode");
        assert_eq!(data[11], 0xc3); // msgpack true
    }

    #[test]
    fn test_queue_propagation_announce() {
        let mut core = make_core(b"prop-announce-queue");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);
        let mut rng = rand::thread_rng();

        assert!(router.queue_propagation_announce(&mut core, &mut rng, 1000));
        let pending = core.transport.pending_outbound(1000);
        assert_eq!(pending.len(), 1);

        let pkt = rete_core::Packet::parse(&pending[0]).unwrap();
        assert_eq!(pkt.packet_type, rete_core::PacketType::Announce);
        assert_eq!(
            pkt.destination_hash,
            router.propagation_dest_hash().unwrap()
        );
    }

    #[test]
    fn test_queue_propagation_announce_fails_when_not_enabled() {
        let mut core = make_core(b"prop-announce-fail");
        let router = LxmfRouter::register(&mut core);
        let mut rng = rand::thread_rng();

        assert!(!router.queue_propagation_announce(&mut core, &mut rng, 1000));
    }

    #[test]
    fn test_propagation_mark_delivered() {
        let mut core = make_core(b"prop-mark-test");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);

        let dest = [0x42; 16];
        let (msg, _) = make_test_msg(b"mark-source", dest);
        let packed = msg.pack();

        let (_, msg_hash) = match router.propagation_deposit(&packed, 1000).unwrap() {
            LxmfEvent::PropagationDeposit {
                dest_hash,
                message_hash,
            } => (dest_hash, message_hash),
            _ => panic!("expected PropagationDeposit"),
        };

        assert!(router.propagation_mark_delivered(&msg_hash));
        assert_eq!(router.propagation_message_count(), 0);
        assert!(router.propagation_retrieve(&dest).is_empty());
    }
}
