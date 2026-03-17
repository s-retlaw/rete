//! LxmfRouter — LXMF delivery plumbing on top of NodeCore.
//!
//! Registers an `lxmf.delivery` destination with NodeCore and provides
//! helpers for opportunistic/direct send and receive.

use rete_core::TRUNCATED_HASH_LEN;
use rete_stack::{NodeCore, NodeEvent, OutboundPacket};

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
    /// or the original event wrapped as Other.
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

    // -----------------------------------------------------------------------
    // Announce helpers
    // -----------------------------------------------------------------------

    /// Build LXMF announce app_data in the format Python LXMF expects.
    ///
    /// Format: msgpack array `[display_name_bytes, stamp_cost_int]`
    pub fn build_announce_app_data(&self) -> Vec<u8> {
        let name = self.display_name.as_deref().unwrap_or(b"");
        let stamp_cost: u8 = 0; // Not enforced yet

        let mut buf = Vec::with_capacity(name.len() + 4);
        // fixarray of 2
        buf.push(0x92);
        crate::message::write_bin(&mut buf, name);
        // stamp_cost as positive fixint
        buf.push(stamp_cost);

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
}
