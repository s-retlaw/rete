//! LxmfRouter — LXMF delivery plumbing on top of NodeCore.
//!
//! Registers an `lxmf.delivery` destination with NodeCore and provides
//! helpers for opportunistic/direct send and receive.
//!
//! When propagation is enabled, also registers an `lxmf.propagation`
//! destination and manages store-and-forward message handling.

use std::collections::HashMap;

use rete_core::TRUNCATED_HASH_LEN;
use rete_stack::{NodeCore, NodeEvent, OutboundPacket};

use crate::peer::{LxmPeer, SyncStrategy};
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
enum ForwardJob {
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
enum RetrievalJob {
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
enum SyncJob {
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
    fn link_id(&self) -> &[u8; TRUNCATED_HASH_LEN] {
        match self {
            SyncJob::Linking { link_id, .. }
            | SyncJob::OfferSent { link_id, .. }
            | SyncJob::Transferring { link_id, .. } => link_id,
        }
    }

    fn peer_dest(&self) -> &[u8; TRUNCATED_HASH_LEN] {
        match self {
            SyncJob::Linking { peer_dest, .. }
            | SyncJob::OfferSent { peer_dest, .. }
            | SyncJob::Transferring { peer_dest, .. } => peer_dest,
        }
    }
}

/// Path for peer sync offer requests.
const OFFER_PATH: &str = "/lxmf/peering/offer";

/// LXMF router — manages `lxmf.delivery` destination and message handling.
///
/// Generic over `S: MessageStore` so different backends (in-memory, flash, DB)
/// can be used. See [`DefaultLxmfRouter`] for the common in-memory variant.
///
/// Does NOT own or wrap NodeCore. Holds only derived state and takes
/// `&mut NodeCore` as parameter to avoid lifetime issues.
pub struct LxmfRouter<S: MessageStore = InMemoryMessageStore> {
    /// The `lxmf.delivery` destination hash registered with NodeCore.
    delivery_dest_hash: [u8; TRUNCATED_HASH_LEN],
    /// Display name advertised in LXMF announces.
    display_name: Option<Vec<u8>>,
    /// Propagation node (store-and-forward), if enabled.
    propagation: Option<PropagationNode<S>>,
    /// The `lxmf.propagation` destination hash, if propagation is enabled.
    propagation_dest_hash: Option<[u8; TRUNCATED_HASH_LEN]>,
    /// Active propagation forward jobs (push delivery on announce).
    pending_forwards: Vec<ForwardJob>,
    /// Active propagation retrieval jobs (pull delivery on request).
    pending_retrievals: Vec<RetrievalJob>,
    /// Active peer sync jobs.
    pending_syncs: Vec<SyncJob>,
    /// Peer registry: dest_hash → LxmPeer.
    peers: HashMap<[u8; TRUNCATED_HASH_LEN], LxmPeer>,
    /// Auto-discover peers from propagation announces.
    autopeer: bool,
    /// Maximum hops for auto-peering (default 4).
    autopeer_maxdepth: u8,
    /// Maximum number of peers (default 20).
    max_peers: usize,
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
        let pkt_data = core
            .build_data_packet(&msg.destination_hash, &payload, rng, now)
            .ok()?;
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
        core.start_resource(link_id, &data, rng).ok()
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
    ///
    /// Also handles `RequestReceived` events for propagation retrieval:
    /// if the path matches `/lxmf/propagation/retrieve`, returns
    /// `LxmfEvent::PropagationRetrievalRequest`.
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

        // For RequestReceived: check if this is a propagation retrieval request
        if self.propagation.is_some() {
            if let NodeEvent::RequestReceived {
                link_id,
                request_id,
                path_hash,
                ref data,
            } = event
            {
                if let Some(result) = self.handle_propagation_request(&path_hash, data) {
                    // Extract the dest_hash from data
                    let mut dest_hash = [0u8; TRUNCATED_HASH_LEN];
                    if data.len() >= TRUNCATED_HASH_LEN {
                        dest_hash.copy_from_slice(&data[..TRUNCATED_HASH_LEN]);
                    }
                    return LxmfEvent::PropagationRetrievalRequest {
                        link_id,
                        request_id,
                        dest_hash,
                        result,
                    };
                }
                // Check if this is a peer offer request
                if let Some(response_data) = self.handle_offer_request(&path_hash, data) {
                    return LxmfEvent::PeerOfferReceived {
                        link_id,
                        request_id,
                        response_data,
                    };
                }
                // If not a retrieval or offer request, fall through
            }
        }

        // For AnnounceReceived: check if this is a propagation peer announce
        if self.autopeer {
            if let NodeEvent::AnnounceReceived {
                dest_hash,
                identity_hash,
                hops,
                ref app_data,
            } = event
            {
                if let Some(ref data) = app_data {
                    if let Some(parsed) = parse_lxmf_announce_data(data) {
                        if parsed.is_propagation
                            && hops <= self.autopeer_maxdepth
                            && !self.peers.contains_key(&dest_hash)
                            && self.peers.len() < self.max_peers
                            // Don't peer with ourselves
                            && self.propagation_dest_hash.map_or(true, |h| h != dest_hash)
                        {
                            let mut p = LxmPeer::new(dest_hash, identity_hash);
                            p.sync_strategy = SyncStrategy::Persistent;
                            self.peers.insert(dest_hash, p);
                            return LxmfEvent::PeerDiscovered {
                                dest_hash,
                                identity_hash,
                            };
                        }
                    }
                }
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
        const P: usize,
        const A: usize,
        const D: usize,
        const L: usize,
    >(
        &mut self,
        core: &mut NodeCore<P, A, D, L>,
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
        const P: usize,
        const A: usize,
        const D: usize,
        const L: usize,
    >(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        core: &mut NodeCore<P, A, D, L>,
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
        const P: usize,
        const A: usize,
        const D: usize,
        const L: usize,
    >(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        response_data: &[u8],
        core: &mut NodeCore<P, A, D, L>,
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
        const P: usize,
        const A: usize,
        const D: usize,
        const L: usize,
    >(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        core: &mut NodeCore<P, A, D, L>,
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

    // -----------------------------------------------------------------------
    // Propagation auto-forward (store-and-forward delivery)
    // -----------------------------------------------------------------------

    /// Check if there is already a forward job for the given destination.
    pub fn has_forward_job_for(&self, dest_hash: &[u8; TRUNCATED_HASH_LEN]) -> bool {
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
        const P: usize,
        const A: usize,
        const D: usize,
        const L: usize,
    >(
        &mut self,
        dest_hash: &[u8; TRUNCATED_HASH_LEN],
        core: &mut NodeCore<P, A, D, L>,
        rng: &mut R,
        now: u64,
    ) -> Option<(OutboundPacket, [u8; TRUNCATED_HASH_LEN])> {
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
        const P: usize,
        const A: usize,
        const D: usize,
        const L: usize,
    >(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        core: &mut NodeCore<P, A, D, L>,
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
    fn send_stored_message_resource<
        R: rand_core::RngCore + rand_core::CryptoRng,
        const P: usize,
        const A: usize,
        const D: usize,
        const L: usize,
    >(
        &self,
        message_hash: &[u8; 32],
        link_id: &[u8; TRUNCATED_HASH_LEN],
        core: &mut NodeCore<P, A, D, L>,
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
    pub fn cleanup_forward_jobs_for_link(&mut self, link_id: &[u8; TRUNCATED_HASH_LEN]) {
        self.pending_forwards.retain(|job| match job {
            ForwardJob::Linking { link_id: lid, .. } => lid != link_id,
            ForwardJob::Sending { link_id: lid, .. } => lid != link_id,
        });
        self.pending_retrievals.retain(|job| match job {
            RetrievalJob::Sending { link_id: lid, .. } => lid != link_id,
        });
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
    ) -> Vec<OutboundPacket> {
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
    ) -> Vec<OutboundPacket> {
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
        self.pending_retrievals.iter().any(|job| {
            matches!(
                job,
                RetrievalJob::Sending { link_id: lid, .. } if lid == link_id
            )
        })
    }
}

/// Encode a u32 as a msgpack unsigned integer.
fn encode_msgpack_uint(val: u32) -> Vec<u8> {
    if val < 128 {
        vec![val as u8]
    } else if val < 256 {
        vec![0xcc, val as u8]
    } else if val < 65536 {
        let mut buf = vec![0xcd];
        buf.extend_from_slice(&(val as u16).to_be_bytes());
        buf
    } else {
        let mut buf = vec![0xce];
        buf.extend_from_slice(&val.to_be_bytes());
        buf
    }
}

/// Compress data with bz2 (matching Python LXMF Resource convention).
fn bz2_compress(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    encoder.write_all(data).unwrap_or_default();
    encoder.finish().unwrap_or_else(|_| data.to_vec())
}

/// Parsed LXMF announce app_data.
struct LxmfAnnounceData {
    display_name: Vec<u8>,
    /// True if this is a propagation node announce (second element is `true`).
    is_propagation: bool,
}

/// Try to parse LXMF announce app_data: msgpack `[display_name_bytes, tag]`
/// where tag is a stamp_cost int (delivery) or `true` boolean (propagation).
fn try_parse_lxmf_announce_data(data: &[u8]) -> Option<Vec<u8>> {
    let parsed = parse_lxmf_announce_data(data)?;
    Some(parsed.display_name)
}

/// Parse full LXMF announce app_data including propagation flag.
fn parse_lxmf_announce_data(data: &[u8]) -> Option<LxmfAnnounceData> {
    let mut pos = 0;
    let arr_len = crate::message::read_array_len(data, &mut pos).ok()?;
    if arr_len < 2 {
        return None;
    }
    let display_name = crate::message::read_bin(data, &mut pos).ok()?;
    // Second element: 0xc3 = true (propagation), integer = stamp_cost (delivery)
    let is_propagation = data.get(pos) == Some(&0xc3);
    Some(LxmfAnnounceData {
        display_name,
        is_propagation,
    })
}

/// Encode a list of message hashes as a msgpack array of bin32 elements.
/// Write a msgpack array header for the given length.
fn write_array_header(buf: &mut Vec<u8>, len: usize) {
    if len <= 15 {
        buf.push(0x90 | len as u8);
    } else if len <= 0xFFFF {
        buf.push(0xdc);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push(0xdd);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    }
}

fn encode_offer_hashes(hashes: &[[u8; 32]]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(5 + hashes.len() * 35);
    write_array_header(&mut buf, hashes.len());
    for h in hashes {
        crate::message::write_bin(&mut buf, h);
    }
    buf
}

/// Decode a msgpack array of bin elements into message hashes.
fn decode_offer_hashes(data: &[u8]) -> Option<Vec<[u8; 32]>> {
    let mut pos = 0;
    let arr_len = crate::message::read_array_len(data, &mut pos).ok()?;
    let mut hashes = Vec::with_capacity(arr_len);
    for _ in 0..arr_len {
        let bin = crate::message::read_bin(data, &mut pos).ok()?;
        if bin.len() != 32 {
            return None;
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&bin);
        hashes.push(h);
    }
    Some(hashes)
}

/// Parse an offer response: `false` (want none) → empty,
/// `true` (want all) → return offered, array → subset.
fn parse_offer_response(data: &[u8], offered: &[[u8; 32]]) -> Vec<[u8; 32]> {
    if data.is_empty() {
        return Vec::new();
    }
    match data[0] {
        0xc2 => Vec::new(),       // false: want none
        0xc3 => offered.to_vec(), // true: want all
        _ => {
            // Try to decode as array of hashes
            decode_offer_hashes(data).unwrap_or_default()
        }
    }
}

/// Pack sync messages: msgpack `[timestamp_f64, [msg1_bytes, msg2_bytes, ...]]`.
fn pack_sync_messages(now: u64, messages: &[Vec<u8>]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0x92); // fixarray(2)

    // timestamp as float64
    buf.push(0xcb);
    buf.extend_from_slice(&(now as f64).to_be_bytes());

    write_array_header(&mut buf, messages.len());
    for msg in messages {
        crate::message::write_bin(&mut buf, msg);
    }
    buf
}

/// Unpack sync messages from msgpack `[timestamp, [msg1, msg2, ...]]`.
fn unpack_sync_messages(data: &[u8]) -> Vec<Vec<u8>> {
    let mut pos = 0;
    // Outer array [timestamp, messages]
    let arr_len = match crate::message::read_array_len(data, &mut pos) {
        Ok(n) => n,
        Err(_) => return Vec::new(),
    };
    if arr_len < 2 {
        return Vec::new();
    }
    // Skip timestamp (float64 = 9 bytes: 0xcb + 8 bytes)
    if pos < data.len() && data[pos] == 0xcb {
        pos += 9;
    } else {
        // Try skipping other numeric types
        let _ = pos; // consumed
        return Vec::new();
    }
    // Messages array
    let msg_count = match crate::message::read_array_len(data, &mut pos) {
        Ok(n) => n,
        Err(_) => return Vec::new(),
    };
    let mut messages = Vec::with_capacity(msg_count);
    for _ in 0..msg_count {
        match crate::message::read_bin(data, &mut pos) {
            Ok(bin) => messages.push(bin),
            Err(_) => break,
        }
    }
    messages
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rete_core::Identity;
    use std::collections::BTreeMap;

    // Use the concrete type alias for static method calls in tests.
    type Router = DefaultLxmfRouter;
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
        core.register_peer(&recipient, "lxmf", &["delivery"], 100);

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
        core.register_peer(&recipient, "lxmf", &["delivery"], 100);

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
        core.register_peer(&recipient, "lxmf", &["delivery"], 100);

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
        core.register_peer(&recipient, "lxmf", &["delivery"], 100);

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
        core.register_peer(&recipient, "lxmf", &["delivery"], 100);

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
        core.register_peer(&recipient, "lxmf", &["delivery"], 100);

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
            crate::message::write_bin(&mut buf, b"TestPeer");
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
            crate::message::write_bin(&mut buf, b"FarPeer");
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
            crate::message::write_bin(&mut buf, b"RegularNode");
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
            crate::message::write_bin(&mut buf, b"TestPeer");
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
