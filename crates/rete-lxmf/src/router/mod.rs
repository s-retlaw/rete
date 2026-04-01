//! LxmfRouter — LXMF delivery plumbing on top of NodeCore.
//!
//! Registers an `lxmf.delivery` destination with NodeCore and provides
//! helpers for opportunistic/direct send and receive.
//!
//! When propagation is enabled, also registers an `lxmf.propagation`
//! destination and manages store-and-forward message handling.

mod codec;
mod delivery;
mod event;
mod forward;
mod peering;
mod propagation;

use std::collections::HashMap;

use rete_core::TRUNCATED_HASH_LEN;
use rete_stack::{NodeCore, NodeEvent, OutboundPacket};

use crate::peer::LxmPeer;
use crate::propagation::{InMemoryMessageStore, MessageStore, PropagationNode};
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
    /// A retrieval request was received on the propagation destination.
    PropagationRetrievalRequest {
        /// The link_id the request came on.
        link_id: [u8; TRUNCATED_HASH_LEN],
        /// The request_id to respond to.
        request_id: [u8; TRUNCATED_HASH_LEN],
        /// The destination hash being retrieved.
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        /// Retrieval result (response data + messages to send).
        result: PropagationRetrievalResult,
    },
    /// A propagation peer was discovered via announce.
    PeerDiscovered {
        /// Destination hash of the discovered peer.
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        /// Identity hash of the discovered peer.
        identity_hash: [u8; TRUNCATED_HASH_LEN],
    },
    /// Peer sync completed successfully.
    PeerSyncComplete {
        /// Destination hash of the peer.
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        /// Number of messages sent to the peer.
        messages_sent: usize,
    },
    /// An inbound peer offer request was received and processed.
    /// The application should send the response via `core.send_response()`.
    PeerOfferReceived {
        /// Link the request came on.
        link_id: [u8; TRUNCATED_HASH_LEN],
        /// Request ID to respond to.
        request_id: [u8; TRUNCATED_HASH_LEN],
        /// Response data to send back (msgpack: false/true/[hashes]).
        response_data: Vec<u8>,
    },
    /// A non-LXMF NodeEvent (pass-through).
    Other(NodeEvent),
}

/// Result of handling a propagation retrieval request.
#[derive(Debug)]
pub struct PropagationRetrievalResult {
    /// Response data (msgpack-encoded count) to send via `send_response()`.
    pub response_data: Vec<u8>,
    /// Message hashes to send as Resources (data loaded on-demand).
    pub message_hashes: Vec<[u8; 32]>,
}

/// State machine for propagation auto-forward.
///
/// When an announce is received for a destination with pending messages,
/// we open a link to that destination and send each stored message as a
/// Resource (bz2-compressed LXMF packed data).
#[derive(Debug)]
pub(super) enum ForwardJob {
    /// Link being established to the destination.
    Linking {
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        link_id: [u8; TRUNCATED_HASH_LEN],
    },
    /// Sending stored messages one at a time via Resource.
    Sending {
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        link_id: [u8; TRUNCATED_HASH_LEN],
        message_hashes: Vec<[u8; 32]>,
        idx: usize,
    },
}

/// State machine for propagation retrieval (client-initiated pull).
///
/// When a client sends a `link.request("/lxmf/propagation/retrieve", dest_hash)`,
/// the propagation node responds with the count and then sends each stored
/// message as a Resource on the same link.
#[derive(Debug)]
pub(super) enum RetrievalJob {
    /// Sending stored messages one at a time via Resource.
    Sending {
        link_id: [u8; TRUNCATED_HASH_LEN],
        message_hashes: Vec<[u8; 32]>,
        idx: usize,
    },
}

/// State machine for peer-to-peer propagation sync.
///
/// When a peer's sync timer fires, we initiate a link, identify ourselves,
/// send an offer of message hashes we have, receive a response indicating
/// which ones the peer wants, then transfer those messages.
#[derive(Debug)]
pub(super) enum SyncJob {
    /// Establishing link to peer's propagation destination.
    Linking {
        peer_dest: [u8; TRUNCATED_HASH_LEN],
        link_id: [u8; TRUNCATED_HASH_LEN],
    },
    /// Offer request sent, awaiting response.
    OfferSent {
        peer_dest: [u8; TRUNCATED_HASH_LEN],
        link_id: [u8; TRUNCATED_HASH_LEN],
        offered_hashes: Vec<[u8; 32]>,
    },
    /// Transferring messages via resource.
    Transferring {
        peer_dest: [u8; TRUNCATED_HASH_LEN],
        link_id: [u8; TRUNCATED_HASH_LEN],
        offered_hashes: Vec<[u8; 32]>,
    },
}

impl SyncJob {
    pub(super) fn link_id(&self) -> &[u8; TRUNCATED_HASH_LEN] {
        match self {
            SyncJob::Linking { link_id, .. }
            | SyncJob::OfferSent { link_id, .. }
            | SyncJob::Transferring { link_id, .. } => link_id,
        }
    }

    pub(super) fn peer_dest(&self) -> &[u8; TRUNCATED_HASH_LEN] {
        match self {
            SyncJob::Linking { peer_dest, .. }
            | SyncJob::OfferSent { peer_dest, .. }
            | SyncJob::Transferring { peer_dest, .. } => peer_dest,
        }
    }
}

/// Path for peer sync offer requests.
pub(super) const OFFER_PATH: &str = "/lxmf/peering/offer";

/// LXMF router — manages `lxmf.delivery` destination and message handling.
///
/// Generic over `S: MessageStore` so different backends (in-memory, flash, DB)
/// can be used. See [`DefaultLxmfRouter`] for the common in-memory variant.
///
/// Does NOT own or wrap NodeCore. Holds only derived state and takes
/// `&mut NodeCore` as parameter to avoid lifetime issues.
pub struct LxmfRouter<S: MessageStore = InMemoryMessageStore> {
    /// The `lxmf.delivery` destination hash registered with NodeCore.
    pub(super) delivery_dest_hash: [u8; TRUNCATED_HASH_LEN],
    /// Display name advertised in LXMF announces.
    pub(super) display_name: Option<Vec<u8>>,
    /// Propagation node (store-and-forward), if enabled.
    pub(super) propagation: Option<PropagationNode<S>>,
    /// The `lxmf.propagation` destination hash, if propagation is enabled.
    pub(super) propagation_dest_hash: Option<[u8; TRUNCATED_HASH_LEN]>,
    /// Active propagation forward jobs (push delivery on announce).
    pub(super) pending_forwards: Vec<ForwardJob>,
    /// Active propagation retrieval jobs (pull delivery on request).
    pub(super) pending_retrievals: Vec<RetrievalJob>,
    /// Active peer sync jobs.
    pub(super) pending_syncs: Vec<SyncJob>,
    /// Peer registry: dest_hash → LxmPeer.
    pub(super) peers: HashMap<[u8; TRUNCATED_HASH_LEN], LxmPeer>,
    /// Auto-discover peers from propagation announces.
    pub(super) autopeer: bool,
    /// Maximum hops for auto-peering (default 4).
    pub(super) autopeer_maxdepth: u8,
    /// Maximum number of peers (default 20).
    pub(super) max_peers: usize,
}

/// Type alias for the common in-memory router variant.
pub type DefaultLxmfRouter = LxmfRouter<InMemoryMessageStore>;

impl LxmfRouter<InMemoryMessageStore> {
    /// Register an `lxmf.delivery` destination on the given NodeCore.
    ///
    /// Creates a router with the default in-memory message store.
    /// Sets ProveAll strategy on the delivery destination (LXMF expects
    /// delivery proofs).
    pub fn register<const P: usize, const A: usize, const D: usize, const L: usize>(
        core: &mut NodeCore<P, A, D, L>,
    ) -> Self {
        Self::register_with_store(core)
    }
}

impl<S: MessageStore> LxmfRouter<S> {
    /// Register an `lxmf.delivery` destination on the given NodeCore.
    ///
    /// Sets ProveAll strategy on the delivery destination (LXMF expects
    /// delivery proofs).
    pub fn register_with_store<const P: usize, const A: usize, const D: usize, const L: usize>(
        core: &mut NodeCore<P, A, D, L>,
    ) -> Self
    where
        S: Default,
    {
        let dest_hash = core
            .register_destination("lxmf", &["delivery"])
            .expect("lxmf.delivery fits in 128 bytes");

        // LXMF delivery always proves received data
        if let Some(dest) = core.get_destination_mut(&dest_hash) {
            dest.set_proof_strategy(rete_stack::ProofStrategy::ProveAll);
        }

        LxmfRouter {
            delivery_dest_hash: dest_hash,
            display_name: None,
            propagation: None,
            propagation_dest_hash: None,
            pending_forwards: Vec::new(),
            pending_retrievals: Vec::new(),
            pending_syncs: Vec::new(),
            peers: HashMap::new(),
            autopeer: false,
            autopeer_maxdepth: 4,
            max_peers: 20,
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
    // Announce helpers
    // -----------------------------------------------------------------------

    /// Build LXMF announce app_data in the format Python LXMF expects.
    ///
    /// Format: msgpack array `[display_name_bytes, stamp_cost_int]`
    pub fn build_announce_app_data(&self) -> Vec<u8> {
        self.build_announce_app_data_with_tag(0x00) // stamp_cost = 0
    }

    /// Build msgpack announce app_data: `[display_name, tag_byte]`.
    pub(super) fn build_announce_app_data_with_tag(&self, tag_byte: u8) -> Vec<u8> {
        let name = self.display_name.as_deref().unwrap_or(b"");
        let mut buf = Vec::with_capacity(name.len() + 4);
        buf.push(0x92); // fixarray of 2
        rete_core::msgpack::write_bin(&mut buf, name);
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
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use super::codec::{
        decode_offer_hashes, encode_msgpack_uint, encode_offer_hashes, pack_sync_messages,
        parse_offer_response, try_parse_lxmf_announce_data, unpack_sync_messages,
    };
    use crate::peer::SyncStrategy;
    use rete_core::Identity;
    use std::collections::BTreeMap;

    // Use the concrete type alias for static method calls in tests.
    type Router = DefaultLxmfRouter;
    type TestNodeCore = NodeCore<64, 16, 128, 4>;

    fn make_core(seed: &[u8]) -> TestNodeCore {
        let identity = Identity::from_seed(seed).unwrap();
        TestNodeCore::new(identity, "testapp", &["aspect1"]).unwrap()
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
        let opp_packed = Router::pack_opportunistic(&msg);

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
        core.register_peer(&recipient, "lxmf", &["delivery"], 100).unwrap();

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
        let opp_payload = Router::pack_opportunistic(&msg);

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
        let opp_payload = Router::pack_opportunistic(&msg);

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
        let direct = Router::pack_direct(&msg);
        let full = msg.pack();
        assert_eq!(direct, full);
    }

    #[test]
    fn test_try_parse_lxmf_resource_roundtrip() {
        let (msg, _) = make_test_msg(b"resource-rt-test", [0xBB; 16]);
        let packed = msg.pack();
        let parsed = Router::try_parse_lxmf_resource(&packed).unwrap();
        assert_eq!(parsed.title, b"Hello");
        assert_eq!(parsed.content, b"World");
    }

    #[test]
    fn test_try_parse_lxmf_resource_rejects_garbage() {
        assert!(Router::try_parse_lxmf_resource(b"not a message").is_none());
        assert!(Router::try_parse_lxmf_resource(&[0u8; 50]).is_none());
    }

    // -------------------------------------------------------------------
    // Step 2.5: LxmfEvent + handle_event()
    // -------------------------------------------------------------------

    #[test]
    fn test_handle_event_data_received_lxmf() {
        let mut core = make_core(b"handle-event-test");
        let router = LxmfRouter::register(&mut core);

        let (msg, _) = make_test_msg(b"event-source", *router.delivery_dest_hash());
        let opp_payload = Router::pack_opportunistic(&msg);

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
        let packed = Router::pack_direct(&msg);

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
        let pending = core.transport.pending_outbound(1000, &mut rng);
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

        let hashes = router.propagation_hashes_for(&dest);
        assert_eq!(hashes.len(), 1);
        assert!(router.propagation_has_message(&hashes[0]));
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
        assert!(router.propagation_hashes_for(&[0x42; 16]).is_empty());
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
        let pending = core.transport.pending_outbound(1000, &mut rng);
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
        assert!(router.propagation_hashes_for(&dest).is_empty());
    }

    // -------------------------------------------------------------------
    // Forward job tests
    // -------------------------------------------------------------------

    /// Helper: create a propagation-enabled router with a deposited message.
    /// Returns (core, router, dest_hash, message_hash).
    fn setup_forward_scenario(
        seed: &[u8],
        dest: [u8; 16],
    ) -> (TestNodeCore, LxmfRouter, [u8; 16], [u8; 32]) {
        let mut core = make_core(seed);
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);

        let (msg, _) = make_test_msg(b"fwd-msg-source", dest);
        let packed = msg.pack();

        let msg_hash = match router.propagation_deposit(&packed, 1000).unwrap() {
            LxmfEvent::PropagationDeposit { message_hash, .. } => message_hash,
            _ => panic!("expected PropagationDeposit"),
        };

        (core, router, dest, msg_hash)
    }

    #[test]
    fn test_forward_job_has_no_job_initially() {
        let (_, router, dest, _) = setup_forward_scenario(b"fwd-no-job", [0x42; 16]);
        assert!(!router.has_forward_job_for(&dest));
    }

    #[test]
    fn test_forward_job_initiates_link() {
        let (mut core, mut router, _dest, _) =
            setup_forward_scenario(b"fwd-initiate-link", [0x42; 16]);
        let mut rng = rand::thread_rng();

        // Register a peer for the destination so initiate_link has a path
        let recipient = Identity::from_seed(b"fwd-recipient-01").unwrap();
        // Compute the dest_hash that will match [0x42; 16]
        // For the test to work, we need the dest_hash to match the peer's
        // lxmf.delivery destination. Since we used [0x42; 16] as dest hash
        // in the message, we need to register the peer with matching hash.
        // In practice, the announce has already cached the identity. For
        // unit testing, we directly register.
        core.register_peer(&recipient, "lxmf", &["delivery"], 100).unwrap();

        // The dest_hash [0x42; 16] won't match the registered peer's
        // computed dest_hash. start_propagation_forward calls
        // core.initiate_link(dest_hash, ...) which needs a cached announce
        // path for that exact dest_hash. Without that, it returns None.
        //
        // So let's use the actual dest_hash of the registered peer.
        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name("lxmf", &["delivery"], &mut name_buf).unwrap();
        let peer_dest = rete_core::destination_hash(expanded, Some(&recipient.hash()));

        // Deposit a message for the peer's actual dest hash
        let (msg, _) = make_test_msg(b"fwd-msg-for-peer", peer_dest);
        router.propagation_deposit(&msg.pack(), 1001);

        let result = router.start_propagation_forward(&peer_dest, &mut core, &mut rng, 1000);
        assert!(result.is_some(), "should produce LINKREQUEST packet");

        let (_, link_id) = result.unwrap();
        assert!(router.has_forward_job_for(&peer_dest));

        // Verify the job is in Linking state
        let job = router.pending_forwards.iter().find(|j| {
            matches!(
                j, ForwardJob::Linking { dest_hash, .. } if *dest_hash == peer_dest
            )
        });
        assert!(job.is_some(), "should have a Linking job");

        // Verify the link_id matches
        match job.unwrap() {
            ForwardJob::Linking { link_id: lid, .. } => assert_eq!(*lid, link_id),
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_forward_no_duplicate_jobs() {
        let mut core = make_core(b"fwd-no-dup");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);
        let mut rng = rand::thread_rng();

        let recipient = Identity::from_seed(b"fwd-dup-recipient").unwrap();
        core.register_peer(&recipient, "lxmf", &["delivery"], 100).unwrap();

        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name("lxmf", &["delivery"], &mut name_buf).unwrap();
        let peer_dest = rete_core::destination_hash(expanded, Some(&recipient.hash()));

        let (msg, _) = make_test_msg(b"fwd-dup-msg", peer_dest);
        router.propagation_deposit(&msg.pack(), 1000);

        // First forward
        let result1 = router.start_propagation_forward(&peer_dest, &mut core, &mut rng, 1000);
        assert!(result1.is_some());
        assert!(router.has_forward_job_for(&peer_dest));

        // Second forward for same dest — should be prevented by has_forward_job_for
        assert!(router.has_forward_job_for(&peer_dest));
        assert_eq!(router.pending_forwards.len(), 1);
    }

    #[test]
    fn test_forward_link_established_transitions_to_sending() {
        let mut core = make_core(b"fwd-established");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);
        let mut rng = rand::thread_rng();

        let recipient = Identity::from_seed(b"fwd-est-rcpt").unwrap();
        core.register_peer(&recipient, "lxmf", &["delivery"], 100).unwrap();

        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name("lxmf", &["delivery"], &mut name_buf).unwrap();
        let peer_dest = rete_core::destination_hash(expanded, Some(&recipient.hash()));

        let (msg, _) = make_test_msg(b"fwd-est-msg", peer_dest);
        router.propagation_deposit(&msg.pack(), 1000);

        let (_, link_id) = router
            .start_propagation_forward(&peer_dest, &mut core, &mut rng, 1000)
            .unwrap();

        // Note: advance_forward_on_link_established will try to start_resource,
        // which requires an active link. Since in unit tests the link is Pending
        // (no LRPROOF handshake), start_resource returns None and no packets
        // are produced. However, the state machine should still transition to
        // Sending with idx=0.
        let _pkts = router.advance_forward_on_link_established(&link_id, &mut core, &mut rng);

        // The state should transition to Sending (even if resource send fails,
        // because the link is not yet active in unit test context).
        // In production, the link IS active when LinkEstablished fires.
        // Check that the job was transitioned or handled.
        // Since start_resource returns None (link not active in unit test),
        // the method returns empty packets. The job stays in Sending state.
        let is_sending = router
            .pending_forwards
            .iter()
            .any(|j| matches!(j, ForwardJob::Sending { .. }));
        assert!(is_sending, "should transition to Sending state");
    }

    #[test]
    fn test_forward_resource_complete_marks_delivered() {
        let mut core = make_core(b"fwd-rc-del");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);
        let mut rng = rand::thread_rng();

        let recipient = Identity::from_seed(b"fwd-rc-rcpt").unwrap();
        core.register_peer(&recipient, "lxmf", &["delivery"], 100).unwrap();

        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name("lxmf", &["delivery"], &mut name_buf).unwrap();
        let peer_dest = rete_core::destination_hash(expanded, Some(&recipient.hash()));

        let (msg, _) = make_test_msg(b"fwd-rc-msg", peer_dest);
        router.propagation_deposit(&msg.pack(), 1000);
        assert_eq!(router.propagation_message_count(), 1);

        let (_, link_id) = router
            .start_propagation_forward(&peer_dest, &mut core, &mut rng, 1000)
            .unwrap();

        // Transition to Sending state
        router.advance_forward_on_link_established(&link_id, &mut core, &mut rng);

        // Simulate resource complete
        let resource_hash = [0xAA; 16];
        router.advance_forward_on_resource_complete(&link_id, &resource_hash, &mut core, &mut rng);

        // Message should be marked delivered
        assert_eq!(router.propagation_message_count(), 0);

        // Forward job should be cleaned up
        assert!(!router.has_forward_job_for(&peer_dest));
    }

    #[test]
    fn test_forward_multiple_messages_sequential_delivery() {
        let mut core = make_core(b"fwd-multi-msg");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);
        let mut rng = rand::thread_rng();

        let recipient = Identity::from_seed(b"fwd-multi-rcpt").unwrap();
        core.register_peer(&recipient, "lxmf", &["delivery"], 100).unwrap();

        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name("lxmf", &["delivery"], &mut name_buf).unwrap();
        let peer_dest = rete_core::destination_hash(expanded, Some(&recipient.hash()));

        // Deposit 3 messages
        let (msg1, _) = make_test_msg(b"fwd-multi-1", peer_dest);
        let (msg2, _) = make_test_msg(b"fwd-multi-2", peer_dest);
        let (msg3, _) = make_test_msg(b"fwd-multi-3", peer_dest);
        router.propagation_deposit(&msg1.pack(), 1000);
        router.propagation_deposit(&msg2.pack(), 1001);
        router.propagation_deposit(&msg3.pack(), 1002);
        assert_eq!(router.propagation_message_count(), 3);

        // Start forward
        let (_, link_id) = router
            .start_propagation_forward(&peer_dest, &mut core, &mut rng, 1000)
            .unwrap();

        // Establish link -> transitions to Sending with idx=0
        router.advance_forward_on_link_established(&link_id, &mut core, &mut rng);

        // After establishing: job should have 3 message hashes
        let msg_count = router.pending_forwards.iter().find_map(|j| match j {
            ForwardJob::Sending { message_hashes, .. } => Some(message_hashes.len()),
            _ => None,
        });
        assert_eq!(msg_count, Some(3));

        // Complete first resource -> marks first message delivered, advances idx
        router.advance_forward_on_resource_complete(&link_id, &[0xAA; 16], &mut core, &mut rng);
        assert_eq!(router.propagation_message_count(), 2);

        // Complete second resource
        router.advance_forward_on_resource_complete(&link_id, &[0xBB; 16], &mut core, &mut rng);
        assert_eq!(router.propagation_message_count(), 1);

        // Complete third resource -> done
        router.advance_forward_on_resource_complete(&link_id, &[0xCC; 16], &mut core, &mut rng);
        assert_eq!(router.propagation_message_count(), 0);
        assert!(!router.has_forward_job_for(&peer_dest));
    }

    #[test]
    fn test_forward_cleanup_on_link_close() {
        let mut core = make_core(b"fwd-cleanup");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);
        let mut rng = rand::thread_rng();

        let recipient = Identity::from_seed(b"fwd-cleanup-rcpt").unwrap();
        core.register_peer(&recipient, "lxmf", &["delivery"], 100).unwrap();

        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name("lxmf", &["delivery"], &mut name_buf).unwrap();
        let peer_dest = rete_core::destination_hash(expanded, Some(&recipient.hash()));

        let (msg, _) = make_test_msg(b"fwd-cleanup-msg", peer_dest);
        router.propagation_deposit(&msg.pack(), 1000);

        let (_, link_id) = router
            .start_propagation_forward(&peer_dest, &mut core, &mut rng, 1000)
            .unwrap();
        assert!(router.has_forward_job_for(&peer_dest));

        // Simulate link closed
        router.cleanup_forward_jobs_for_link(&link_id);
        assert!(!router.has_forward_job_for(&peer_dest));

        // Message should still be in the store (not delivered)
        assert_eq!(router.propagation_message_count(), 1);
    }

    #[test]
    fn test_forward_broadcasts_linkrequest_without_path() {
        let mut core = make_core(b"fwd-no-path");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);
        let mut rng = rand::thread_rng();

        let dest = [0x42; 16];
        let (msg, _) = make_test_msg(b"fwd-no-path-msg", dest);
        router.propagation_deposit(&msg.pack(), 1000);

        // initiate_link always succeeds (broadcasts LINKREQUEST as HEADER_1),
        // even without a cached path. The link will timeout if no response.
        let result = router.start_propagation_forward(&dest, &mut core, &mut rng, 1000);
        assert!(result.is_some(), "should broadcast LINKREQUEST");
        assert!(router.has_forward_job_for(&dest));
    }

    #[test]
    fn test_forward_no_messages_returns_none() {
        let mut core = make_core(b"fwd-no-msgs");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);
        let mut rng = rand::thread_rng();

        let dest = [0x42; 16];
        // No messages deposited
        let result = router.start_propagation_forward(&dest, &mut core, &mut rng, 1000);
        assert!(result.is_none(), "should fail without messages");
    }

    // -------------------------------------------------------------------
    // Propagation retrieval tests
    // -------------------------------------------------------------------

    #[test]
    fn test_propagation_retrieve_path_hash() {
        let ph = Router::propagation_retrieve_path_hash();
        assert_eq!(ph.len(), 16);

        // Should be SHA-256("/lxmf/propagation/retrieve")[..16]
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest("/lxmf/propagation/retrieve".as_bytes());
        assert_eq!(&ph[..], &digest[..16]);

        // Should be deterministic
        let ph2 = Router::propagation_retrieve_path_hash();
        assert_eq!(ph, ph2);
    }

    #[test]
    fn test_propagation_retrieve_returns_messages() {
        let mut core = make_core(b"ret-returns-test");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);

        let dest = [0x42; 16];
        let (msg1, _) = make_test_msg(b"ret-msg-1", dest);
        let (msg2, _) = make_test_msg(b"ret-msg-2", dest);
        router.propagation_deposit(&msg1.pack(), 1000);
        router.propagation_deposit(&msg2.pack(), 1001);

        let path_hash = Router::propagation_retrieve_path_hash();
        let result = router.handle_propagation_request(&path_hash, &dest);
        assert!(result.is_some());

        let result = result.unwrap();
        assert_eq!(result.message_hashes.len(), 2);

        // response_data should encode the count 2
        // msgpack positive fixint for 2 is just [0x02]
        assert_eq!(result.response_data, vec![0x02]);

        // Each hash should be non-zero and resolvable via get_data
        for hash in &result.message_hashes {
            assert_ne!(hash, &[0u8; 32]);
            assert!(router.propagation_has_message(hash));
        }
    }

    #[test]
    fn test_propagation_retrieve_empty() {
        let mut core = make_core(b"ret-empty-test");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);

        let dest = [0x99; 16]; // no messages for this dest
        let path_hash = Router::propagation_retrieve_path_hash();
        let result = router.handle_propagation_request(&path_hash, &dest);
        assert!(result.is_some());

        let result = result.unwrap();
        assert_eq!(result.message_hashes.len(), 0);
        assert_eq!(result.response_data, vec![0x00]); // count = 0
    }

    #[test]
    fn test_propagation_retrieve_wrong_path() {
        let mut core = make_core(b"ret-wrong-path");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);

        let wrong_path_hash = [0xFF; 16];
        let dest = [0x42; 16];
        let result = router.handle_propagation_request(&wrong_path_hash, &dest);
        assert!(result.is_none());
    }

    #[test]
    fn test_propagation_retrieve_not_enabled() {
        let mut core = make_core(b"ret-not-enabled");
        let router = LxmfRouter::register(&mut core);
        // Propagation NOT enabled

        let path_hash = Router::propagation_retrieve_path_hash();
        let dest = [0x42; 16];
        let result = router.handle_propagation_request(&path_hash, &dest);
        assert!(result.is_none());
    }

    #[test]
    fn test_propagation_retrieve_data_too_short() {
        let mut core = make_core(b"ret-short-data");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);

        let path_hash = Router::propagation_retrieve_path_hash();
        // data is shorter than 16 bytes (TRUNCATED_HASH_LEN)
        let result = router.handle_propagation_request(&path_hash, &[0x42; 5]);
        assert!(result.is_none());
    }

    #[test]
    fn test_retrieval_job_resource_complete_marks_delivered() {
        let mut core = make_core(b"ret-rc-del");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);
        let mut rng = rand::thread_rng();

        let dest = [0x42; 16];
        let (msg, _) = make_test_msg(b"ret-rc-msg", dest);
        let packed = msg.pack();
        router.propagation_deposit(&packed, 1000);
        assert_eq!(router.propagation_message_count(), 1);

        // Get the messages via handle_propagation_request
        let path_hash = Router::propagation_retrieve_path_hash();
        let result = router
            .handle_propagation_request(&path_hash, &dest)
            .unwrap();
        let message_hashes = result.message_hashes;

        // Start retrieval send
        let link_id = [0xAA; 16];
        let _pkts = router.start_retrieval_send(&link_id, message_hashes, &mut core, &mut rng);

        assert!(router.has_retrieval_job_for_link(&link_id));

        // Simulate resource complete
        let resource_hash = [0xBB; 16];
        router.advance_retrieval_on_resource_complete(
            &link_id,
            &resource_hash,
            &mut core,
            &mut rng,
        );

        // Message should be marked delivered
        assert_eq!(router.propagation_message_count(), 0);

        // Retrieval job should be cleaned up
        assert!(!router.has_retrieval_job_for_link(&link_id));
    }

    #[test]
    fn test_retrieval_multiple_messages_sequential() {
        let mut core = make_core(b"ret-multi-seq");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);
        let mut rng = rand::thread_rng();

        let dest = [0x42; 16];
        let (msg1, _) = make_test_msg(b"ret-multi-1", dest);
        let (msg2, _) = make_test_msg(b"ret-multi-2", dest);
        router.propagation_deposit(&msg1.pack(), 1000);
        router.propagation_deposit(&msg2.pack(), 1001);
        assert_eq!(router.propagation_message_count(), 2);

        let path_hash = Router::propagation_retrieve_path_hash();
        let result = router
            .handle_propagation_request(&path_hash, &dest)
            .unwrap();
        let message_hashes = result.message_hashes;
        assert_eq!(message_hashes.len(), 2);

        let link_id = [0xAA; 16];
        let _pkts = router.start_retrieval_send(&link_id, message_hashes, &mut core, &mut rng);

        // Complete first resource
        router.advance_retrieval_on_resource_complete(&link_id, &[0xBB; 16], &mut core, &mut rng);
        assert_eq!(router.propagation_message_count(), 1);
        assert!(router.has_retrieval_job_for_link(&link_id));

        // Complete second resource
        router.advance_retrieval_on_resource_complete(&link_id, &[0xCC; 16], &mut core, &mut rng);
        assert_eq!(router.propagation_message_count(), 0);
        assert!(!router.has_retrieval_job_for_link(&link_id));
    }

    #[test]
    fn test_retrieval_cleanup_on_link_close() {
        let mut core = make_core(b"ret-cleanup-test");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);
        let mut rng = rand::thread_rng();

        let dest = [0x42; 16];
        let (msg, _) = make_test_msg(b"ret-cleanup-msg", dest);
        router.propagation_deposit(&msg.pack(), 1000);

        let path_hash = Router::propagation_retrieve_path_hash();
        let result = router
            .handle_propagation_request(&path_hash, &dest)
            .unwrap();
        let message_hashes = result.message_hashes;

        let link_id = [0xAA; 16];
        let _pkts = router.start_retrieval_send(&link_id, message_hashes, &mut core, &mut rng);
        assert!(router.has_retrieval_job_for_link(&link_id));

        // Simulate link closed
        router.cleanup_forward_jobs_for_link(&link_id);
        assert!(!router.has_retrieval_job_for_link(&link_id));

        // Message should still be in the store
        assert_eq!(router.propagation_message_count(), 1);
    }

    #[test]
    fn test_handle_event_mut_request_retrieval() {
        let mut core = make_core(b"ret-event-mut");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);

        let dest = [0x42; 16];
        let (msg, _) = make_test_msg(b"ret-event-msg", dest);
        router.propagation_deposit(&msg.pack(), 1000);

        let path_hash = Router::propagation_retrieve_path_hash();
        let request_id = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let link_id = [0xCC; 16];

        let event = NodeEvent::RequestReceived {
            link_id,
            request_id,
            path_hash,
            data: dest.to_vec(),
        };

        match router.handle_event_mut(event, 1000) {
            LxmfEvent::PropagationRetrievalRequest {
                link_id: lid,
                request_id: rid,
                dest_hash: dh,
                result,
            } => {
                assert_eq!(lid, link_id);
                assert_eq!(rid, request_id);
                assert_eq!(dh, dest);
                assert_eq!(result.message_hashes.len(), 1);
            }
            other => panic!("expected PropagationRetrievalRequest, got {:?}", other),
        }
    }

    #[test]
    fn test_encode_msgpack_uint_values() {
        // Values < 128 are positive fixint
        assert_eq!(encode_msgpack_uint(0), vec![0x00]);
        assert_eq!(encode_msgpack_uint(5), vec![0x05]);
        assert_eq!(encode_msgpack_uint(127), vec![0x7f]);

        // Values 128..255 are uint8
        assert_eq!(encode_msgpack_uint(128), vec![0xcc, 0x80]);
        assert_eq!(encode_msgpack_uint(255), vec![0xcc, 0xff]);

        // Values 256..65535 are uint16
        assert_eq!(encode_msgpack_uint(256), vec![0xcd, 0x01, 0x00]);
        assert_eq!(encode_msgpack_uint(65535), vec![0xcd, 0xff, 0xff]);

        // Values >= 65536 are uint32
        assert_eq!(
            encode_msgpack_uint(65536),
            vec![0xce, 0x00, 0x01, 0x00, 0x00]
        );
    }

    // -------------------------------------------------------------------
    // Step 3: Peer registry
    // -------------------------------------------------------------------

    #[test]
    fn test_peer_add_remove() {
        let mut core = make_core(b"peer-registry-test");
        let mut router = LxmfRouter::register(&mut core);

        let dest = [0x11; TRUNCATED_HASH_LEN];
        let identity = [0x22; TRUNCATED_HASH_LEN];

        assert!(!router.is_peered(&dest));
        assert!(router.peer(dest, identity));
        assert!(router.is_peered(&dest));
        assert_eq!(router.peer_count(), 1);

        // Adding same peer again fails
        assert!(!router.peer(dest, identity));
        assert_eq!(router.peer_count(), 1);

        // Remove
        assert!(router.unpeer(&dest));
        assert!(!router.is_peered(&dest));
        assert_eq!(router.peer_count(), 0);

        // Remove non-existent
        assert!(!router.unpeer(&dest));
    }

    #[test]
    fn test_peer_max_count() {
        let mut core = make_core(b"peer-max-test");
        let mut router = LxmfRouter::register(&mut core);
        // Set low max for testing
        router.max_peers = 2;

        assert!(router.peer([0x01; 16], [0xA1; 16]));
        assert!(router.peer([0x02; 16], [0xA2; 16]));
        // Third peer rejected
        assert!(!router.peer([0x03; 16], [0xA3; 16]));
        assert_eq!(router.peer_count(), 2);
    }

    #[test]
    fn test_autopeer_flag() {
        let mut core = make_core(b"autopeer-test");
        let mut router = LxmfRouter::register(&mut core);

        assert!(!router.autopeer);
        router.set_autopeer(true, 6);
        assert!(router.autopeer);
        assert_eq!(router.autopeer_maxdepth, 6);
    }

    // -------------------------------------------------------------------
    // Step 4: Peer discovery via announces
    // -------------------------------------------------------------------

    #[test]
    fn test_propagation_announce_creates_peer() {
        let mut core = make_core(b"peer-discovery-test");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);
        router.set_autopeer(true, 4);

        // Build a propagation announce app_data: [display_name, true]
        let app_data = {
            let mut buf = Vec::new();
            buf.push(0x92); // fixarray of 2
            rete_core::msgpack::write_bin(&mut buf, b"TestPeer");
            buf.push(0xc3); // msgpack true = propagation
            buf
        };

        let dest = [0x33; TRUNCATED_HASH_LEN];
        let identity = [0x44; TRUNCATED_HASH_LEN];
        let event = NodeEvent::AnnounceReceived {
            dest_hash: dest,
            identity_hash: identity,
            hops: 2,
            app_data: Some(app_data),
        };

        let result = router.handle_event_mut(event, 1000);
        assert!(matches!(result, LxmfEvent::PeerDiscovered { .. }));
        assert!(router.is_peered(&dest));
        assert_eq!(router.peer_count(), 1);
    }

    #[test]
    fn test_announce_beyond_maxdepth_ignored() {
        let mut core = make_core(b"maxdepth-test");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);
        router.set_autopeer(true, 2); // max 2 hops

        let app_data = {
            let mut buf = Vec::new();
            buf.push(0x92);
            rete_core::msgpack::write_bin(&mut buf, b"FarPeer");
            buf.push(0xc3);
            buf
        };

        let event = NodeEvent::AnnounceReceived {
            dest_hash: [0x55; TRUNCATED_HASH_LEN],
            identity_hash: [0x66; TRUNCATED_HASH_LEN],
            hops: 5, // beyond maxdepth
            app_data: Some(app_data),
        };

        let result = router.handle_event_mut(event, 1000);
        // Should fall through to PeerAnnounced, not PeerDiscovered
        assert!(!matches!(result, LxmfEvent::PeerDiscovered { .. }));
        assert_eq!(router.peer_count(), 0);
    }

    #[test]
    fn test_announce_non_propagation_ignored() {
        let mut core = make_core(b"non-prop-test");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);
        router.set_autopeer(true, 4);

        // Delivery announce: [display_name, stamp_cost=0]
        let app_data = {
            let mut buf = Vec::new();
            buf.push(0x92);
            rete_core::msgpack::write_bin(&mut buf, b"RegularNode");
            buf.push(0x00); // stamp_cost = 0, not propagation
            buf
        };

        let event = NodeEvent::AnnounceReceived {
            dest_hash: [0x77; TRUNCATED_HASH_LEN],
            identity_hash: [0x88; TRUNCATED_HASH_LEN],
            hops: 1,
            app_data: Some(app_data),
        };

        let result = router.handle_event_mut(event, 1000);
        assert!(!matches!(result, LxmfEvent::PeerDiscovered { .. }));
        assert_eq!(router.peer_count(), 0);
    }

    #[test]
    fn test_autopeer_disabled_ignores_announce() {
        let mut core = make_core(b"autopeer-off-test");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);
        // autopeer is false by default

        let app_data = {
            let mut buf = Vec::new();
            buf.push(0x92);
            rete_core::msgpack::write_bin(&mut buf, b"TestPeer");
            buf.push(0xc3);
            buf
        };

        let event = NodeEvent::AnnounceReceived {
            dest_hash: [0x33; TRUNCATED_HASH_LEN],
            identity_hash: [0x44; TRUNCATED_HASH_LEN],
            hops: 1,
            app_data: Some(app_data),
        };

        let result = router.handle_event_mut(event, 1000);
        assert!(!matches!(result, LxmfEvent::PeerDiscovered { .. }));
        assert_eq!(router.peer_count(), 0);
    }

    #[test]
    fn test_peer_has_persistent_strategy() {
        let mut core = make_core(b"peer-strategy-test");
        let mut router = LxmfRouter::register(&mut core);

        router.peer([0x11; 16], [0x22; 16]);
        let peer = router.get_peer(&[0x11; 16]).unwrap();
        assert_eq!(peer.sync_strategy, SyncStrategy::Persistent);
    }

    // -------------------------------------------------------------------
    // Step 5-8: SyncJob, outbound sync, inbound offer, integration
    // -------------------------------------------------------------------

    #[test]
    fn test_encode_decode_offer_hashes_roundtrip() {
        let hashes = vec![[0xAA; 32], [0xBB; 32], [0xCC; 32]];
        let encoded = encode_offer_hashes(&hashes);
        let decoded = decode_offer_hashes(&encoded).unwrap();
        assert_eq!(decoded, hashes);
    }

    #[test]
    fn test_parse_offer_response_false() {
        let offered = vec![[0xAA; 32], [0xBB; 32]];
        let response = vec![0xc2]; // msgpack false
        let wanted = parse_offer_response(&response, &offered);
        assert!(wanted.is_empty());
    }

    #[test]
    fn test_parse_offer_response_true() {
        let offered = vec![[0xAA; 32], [0xBB; 32]];
        let response = vec![0xc3]; // msgpack true
        let wanted = parse_offer_response(&response, &offered);
        assert_eq!(wanted, offered);
    }

    #[test]
    fn test_parse_offer_response_subset() {
        let offered = vec![[0xAA; 32], [0xBB; 32]];
        let subset = vec![[0xBB; 32]];
        let response = encode_offer_hashes(&subset);
        let wanted = parse_offer_response(&response, &offered);
        assert_eq!(wanted, subset);
    }

    #[test]
    fn test_pack_unpack_sync_messages_roundtrip() {
        let messages = vec![vec![1, 2, 3], vec![4, 5, 6, 7]];
        let packed = pack_sync_messages(1000, &messages);
        let unpacked = unpack_sync_messages(&packed);
        assert_eq!(unpacked, messages);
    }

    #[test]
    fn test_handle_offer_request_want_all() {
        let mut core = make_core(b"offer-want-all");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);

        // Offer hashes that we don't have
        let hashes = vec![[0xAA; 32], [0xBB; 32]];
        let offer_data = encode_offer_hashes(&hashes);
        let path_hash = Router::offer_path_hash();

        let response = router
            .handle_offer_request(&path_hash, &offer_data)
            .unwrap();
        assert_eq!(response, vec![0xc3]); // true = want all
    }

    #[test]
    fn test_handle_offer_request_want_none() {
        let mut core = make_core(b"offer-want-none");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);

        // Deposit messages first
        let data1 = make_fake_lxmf_data([0x42; 16], 0xAA);
        let data2 = make_fake_lxmf_data([0x42; 16], 0xBB);
        let (_, h1) = router
            .propagation_deposit(&data1, 1000)
            .map(|e| match e {
                LxmfEvent::PropagationDeposit {
                    dest_hash,
                    message_hash,
                } => (dest_hash, message_hash),
                _ => panic!("expected deposit"),
            })
            .unwrap();
        let (_, h2) = router
            .propagation_deposit(&data2, 1000)
            .map(|e| match e {
                LxmfEvent::PropagationDeposit {
                    dest_hash,
                    message_hash,
                } => (dest_hash, message_hash),
                _ => panic!("expected deposit"),
            })
            .unwrap();

        // Offer those same hashes — we already have them
        let hashes = vec![h1, h2];
        let offer_data = encode_offer_hashes(&hashes);
        let path_hash = Router::offer_path_hash();

        let response = router
            .handle_offer_request(&path_hash, &offer_data)
            .unwrap();
        assert_eq!(response, vec![0xc2]); // false = want none
    }

    #[test]
    fn test_handle_offer_request_want_subset() {
        let mut core = make_core(b"offer-want-subset");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);

        // Deposit one message
        let data1 = make_fake_lxmf_data([0x42; 16], 0xAA);
        let (_, h1) = router
            .propagation_deposit(&data1, 1000)
            .map(|e| match e {
                LxmfEvent::PropagationDeposit {
                    dest_hash,
                    message_hash,
                } => (dest_hash, message_hash),
                _ => panic!("expected deposit"),
            })
            .unwrap();

        // Offer h1 (which we have) and a new hash (which we don't)
        let h2 = [0xFF; 32];
        let hashes = vec![h1, h2];
        let offer_data = encode_offer_hashes(&hashes);
        let path_hash = Router::offer_path_hash();

        let response = router
            .handle_offer_request(&path_hash, &offer_data)
            .unwrap();
        // Should be an array with just h2
        let wanted = decode_offer_hashes(&response).unwrap();
        assert_eq!(wanted, vec![h2]);
    }

    #[test]
    fn test_deposit_sync_resource() {
        let mut core = make_core(b"deposit-sync-test");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);

        let msg1 = make_fake_lxmf_data([0x42; 16], 0xAA);
        let msg2 = make_fake_lxmf_data([0x42; 16], 0xBB);
        let messages = vec![msg1.clone(), msg2.clone()];
        let packed = pack_sync_messages(1000, &messages);

        let deposited = router.deposit_sync_resource(&packed, 2000);
        assert_eq!(deposited.len(), 2);
        assert_eq!(router.propagation_message_count(), 2);
    }

    #[test]
    fn test_sync_job_cleanup_on_link_closed() {
        let mut core = make_core(b"sync-cleanup-test");
        let mut router = LxmfRouter::register(&mut core);
        router.register_propagation(&mut core);

        let peer_dest = [0x11; TRUNCATED_HASH_LEN];
        let link_id = [0x22; TRUNCATED_HASH_LEN];
        router.peer(peer_dest, [0x33; TRUNCATED_HASH_LEN]);

        // Simulate an active sync job
        router
            .pending_syncs
            .push(SyncJob::Linking { peer_dest, link_id });

        // Close the link
        router.cleanup_sync_jobs_for_link(&link_id);

        assert!(router.pending_syncs.is_empty());
        // Peer should have been marked as failed (backoff increased)
        let peer = router.get_peer(&peer_dest).unwrap();
        assert_eq!(peer.state, crate::peer::PeerState::Idle);
        assert!(peer.sync_backoff > 0);
    }

    #[test]
    fn test_offer_path_hash_deterministic() {
        let h1 = Router::offer_path_hash();
        let h2 = Router::offer_path_hash();
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; TRUNCATED_HASH_LEN]);
    }

    fn make_fake_lxmf_data(dest_hash: [u8; 16], content_byte: u8) -> Vec<u8> {
        let mut data = Vec::with_capacity(100);
        data.extend_from_slice(&dest_hash);
        data.extend_from_slice(&[0xAA; 16]); // source_hash
        data.extend_from_slice(&[content_byte; 64]); // signature (fake)
        data.extend_from_slice(&[content_byte; 4]); // minimal payload
        data
    }
}
