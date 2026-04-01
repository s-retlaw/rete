//! NodeCore — shared node logic extracted from TokioNode and EmbassyNode.
//!
//! This struct owns the identity, transport state, and destination configuration.
//! Runtime wrappers (TokioNode, EmbassyNode) become thin shells that provide
//! async event loops and timer management, delegating all packet processing
//! to NodeCore.

mod announce;
mod destination;
mod ingest;
mod link;

extern crate alloc;

use alloc::vec::Vec;

use rand_core::{CryptoRng, RngCore};
use rete_core::{DestType, Identity, Packet, PacketBuilder, PacketType, MTU, TRUNCATED_HASH_LEN};
use rete_transport::{SendError, Transport, RECEIPT_TIMEOUT};

use crate::destination::{Destination, DestinationType, Direction};
use crate::{NodeEvent, ProofStrategy};

/// Callback type for data compression/decompression functions.
pub type TransformFn = fn(&[u8]) -> Option<Vec<u8>>;

/// Callback type for ProveApp per-packet proof decisions.
///
/// Arguments: (dest_hash, packet_hash, payload_data)
/// Return `true` to generate a proof, `false` to skip.
pub type ProveAppFn = fn(&[u8; TRUNCATED_HASH_LEN], &[u8; 32], &[u8]) -> bool;

/// Callback type for request handlers.
///
/// Arguments: (path, data, request_id, link_id)
/// Return `Some(response_data)` to send a response, or `None` to send no response.
pub type RequestHandlerFn = fn(
    &str,                      // path
    &[u8],                     // request data
    &[u8; TRUNCATED_HASH_LEN], // request_id
    &[u8; TRUNCATED_HASH_LEN], // link_id
) -> Option<Vec<u8>>;

/// Request access policy (matches Python ALLOW_NONE/ALL/LIST).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestPolicy {
    /// Reject all requests (default).
    AllowNone,
    /// Allow requests from any identity.
    AllowAll,
}

/// A registered request handler entry.
#[derive(Clone)]
pub struct RequestHandler {
    /// The path string this handler responds to.
    pub path: alloc::string::String,
    /// The handler function.
    pub handler: RequestHandlerFn,
    /// Access control policy.
    pub policy: RequestPolicy,
}

// ---------------------------------------------------------------------------
// OutboundPacket + PacketRouting
// ---------------------------------------------------------------------------

/// How to route an outbound packet across interfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketRouting {
    /// Send only on the interface the inbound packet arrived on.
    SourceInterface,
    /// Send on all interfaces except the source.
    AllExceptSource,
    /// Send on all interfaces.
    All,
}

/// A packet to be sent, with routing instructions.
#[derive(Debug, Clone)]
pub struct OutboundPacket {
    /// Raw packet bytes.
    pub data: Vec<u8>,
    /// How to route this packet.
    pub routing: PacketRouting,
}

impl OutboundPacket {
    /// Create a packet to be sent on all interfaces.
    pub fn broadcast(data: Vec<u8>) -> Self {
        OutboundPacket {
            data,
            routing: PacketRouting::All,
        }
    }
}

// ---------------------------------------------------------------------------
// IngestOutcome
// ---------------------------------------------------------------------------

/// Result of processing an inbound packet or tick through NodeCore.
#[derive(Debug)]
pub struct IngestOutcome {
    /// Event to emit to the application (if any).
    pub event: Option<NodeEvent>,
    /// Packets to send out.
    pub packets: Vec<OutboundPacket>,
}

impl IngestOutcome {
    /// Empty outcome — nothing to do.
    pub(super) fn empty() -> Self {
        IngestOutcome {
            event: None,
            packets: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// NodeStats
// ---------------------------------------------------------------------------

/// Aggregated node statistics, suitable for export to a dashboard or CLI tool.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct NodeStats {
    /// Transport-layer counters (packets, announces, links, paths, crypto).
    pub transport: rete_transport::TransportStats,
    /// Seconds since the node started receiving/sending traffic.
    pub uptime_secs: u64,
    /// Identity hash of this node, hex-encoded.
    pub identity_hash: alloc::string::String,
}

// ---------------------------------------------------------------------------
// NodeCore
// ---------------------------------------------------------------------------

/// Shared node logic, parameterized by Transport const generics.
///
/// `P` = max paths, `A` = max announces, `D` = dedup window size, `L` = max links.
pub struct NodeCore<const P: usize, const A: usize, const D: usize, const L: usize> {
    /// The local identity for this node.
    pub identity: Identity,
    /// Transport state (path table, announce queue, dedup).
    pub transport: Transport<P, A, D, L>,
    /// Primary destination (addressing metadata, proof strategy, app data).
    pub(super) primary_dest: Destination,
    /// Additional registered destinations (e.g. LXMF delivery).
    pub(super) additional_dests: Vec<Destination>,
    /// Optional auto-reply message sent after receiving an announce.
    pub(super) auto_reply: Option<Vec<u8>>,
    /// Optional decompressor for bz2-compressed resource data.
    /// Called when a received resource has the compressed flag set.
    /// Desktop: provide bz2 decompressor. MCUs without enough RAM: leave as None.
    pub(super) decompress_fn: Option<TransformFn>,
    /// Optional compressor for outbound resource data.
    /// When set, `start_resource` will try to compress data before sending.
    /// Only uses the compressed version if it is actually smaller.
    pub(super) compress_fn: Option<TransformFn>,
    /// Optional packet logging callback for diagnostics.
    /// Called with (raw_bytes, direction, iface_idx) on every inbound packet.
    /// direction is "IN".
    pub(super) packet_log_fn: Option<fn(&[u8], &str, u8)>,
    /// Optional ProveApp callback for per-packet proof decisions.
    pub(super) prove_app_fn: Option<ProveAppFn>,
    /// Buffer for partially-received split resources.
    /// Each entry holds decrypted+decompressed data from completed non-final segments,
    /// keyed by (link_id, original_hash). When the final segment arrives, all buffered
    /// segment data is concatenated and delivered as ResourceComplete.
    pub(super) split_recv_buf: Vec<SplitRecvEntry>,
}

/// Buffer entry for a partially-received split resource.
pub(super) struct SplitRecvEntry {
    pub(super) link_id: [u8; TRUNCATED_HASH_LEN],
    pub(super) original_hash: [u8; 32],
    /// Accumulated plaintext data from completed segments, in order.
    pub(super) data: Vec<u8>,
}

/// Compute (dest_hash, name_hash) for a given identity + app_name + aspects.
pub(super) fn compute_dest_hashes(
    identity: &Identity,
    app_name: &str,
    aspects: &[&str],
) -> ([u8; TRUNCATED_HASH_LEN], [u8; rete_core::NAME_HASH_LEN]) {
    use sha2::{Digest, Sha256};

    let mut name_buf = [0u8; 128];
    let expanded = rete_core::expand_name(app_name, aspects, &mut name_buf)
        .expect("app_name + aspects must fit in 128 bytes");
    let id_hash = identity.hash();
    let dest_hash = rete_core::destination_hash(expanded, Some(&id_hash));

    let name_hash_full = Sha256::digest(expanded.as_bytes());
    let mut name_hash = [0u8; rete_core::NAME_HASH_LEN];
    name_hash.copy_from_slice(&name_hash_full[..rete_core::NAME_HASH_LEN]);

    (dest_hash, name_hash)
}

impl<const P: usize, const A: usize, const D: usize, const L: usize> NodeCore<P, A, D, L> {
    /// Create a new NodeCore with the given identity and destination.
    pub fn new(identity: Identity, app_name: &str, aspects: &[&str]) -> Self {
        let (dest_hash, name_hash) = compute_dest_hashes(&identity, app_name, aspects);

        let primary_dest = Destination::from_hashes(
            DestinationType::Single,
            Direction::In,
            app_name,
            aspects,
            dest_hash,
            name_hash,
        );

        let mut transport = Transport::new();
        transport.add_local_destination(dest_hash);

        NodeCore {
            identity,
            transport,
            primary_dest,
            additional_dests: Vec::new(),
            auto_reply: None,
            decompress_fn: None,
            compress_fn: None,
            packet_log_fn: None,
            prove_app_fn: None,
            split_recv_buf: Vec::new(),
        }
    }

    /// Set the ProveApp callback for per-packet proof decisions.
    pub fn set_prove_app_fn(&mut self, f: Option<ProveAppFn>) {
        self.prove_app_fn = f;
    }

    /// Enable transport mode: forward HEADER_2 packets for other nodes.
    pub fn enable_transport(&mut self) {
        self.transport.set_local_identity(self.identity.hash());
    }

    /// Returns our destination hash.
    pub fn dest_hash(&self) -> &[u8; TRUNCATED_HASH_LEN] {
        self.primary_dest.hash()
    }

    /// Snapshot of current node statistics.
    ///
    /// `now` is the current time in seconds (same epoch as passed to `handle_ingest`
    /// and `handle_tick`). Used to compute `uptime_secs`.
    pub fn stats(&self, now: u64) -> NodeStats {
        let transport = self.transport.stats().clone();
        let uptime = now.saturating_sub(transport.started_at);
        let hash = self.identity.hash();
        use core::fmt::Write as _;
        let mut identity_hash = alloc::string::String::with_capacity(32);
        for byte in hash {
            let _ = write!(identity_hash, "{:02x}", byte);
        }
        NodeStats {
            transport,
            uptime_secs: uptime,
            identity_hash,
        }
    }

    /// Returns a reference to the node's identity (for signing, etc.).
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Set an auto-reply message sent to any peer that announces.
    pub fn set_auto_reply(&mut self, msg: Option<Vec<u8>>) {
        self.auto_reply = msg;
    }

    /// Set the decompression function for bz2-compressed resource data.
    pub fn set_decompress_fn(&mut self, f: Option<TransformFn>) {
        self.decompress_fn = f;
    }

    /// Set the compression function for outbound resource data.
    pub fn set_compress_fn(&mut self, f: Option<TransformFn>) {
        self.compress_fn = f;
    }

    /// Register a request handler on a destination.
    ///
    /// The handler will be auto-invoked when a matching request arrives on a link
    /// to the specified destination.
    pub fn register_request_handler(
        &mut self,
        dest_hash: &[u8; TRUNCATED_HASH_LEN],
        handler: RequestHandler,
    ) -> bool {
        if let Some(dest) = self.get_destination_mut(dest_hash) {
            dest.register_request_handler(handler);
            true
        } else {
            false
        }
    }

    /// Set a packet logging callback for diagnostics.
    /// Called with `(raw_bytes, "IN", iface_idx)` on every inbound packet.
    pub fn set_packet_log_fn(&mut self, f: Option<fn(&[u8], &str, u8)>) {
        self.packet_log_fn = f;
    }

    /// Number of learned paths in the transport table.
    pub fn path_count(&self) -> usize {
        self.transport.path_count()
    }

    /// Number of pending announces in the queue.
    pub fn announce_count(&self) -> usize {
        self.transport.announce_count()
    }

    /// Capture transport state into a snapshot for persistence.
    pub fn save_snapshot(
        &self,
        detail: rete_transport::SnapshotDetail,
    ) -> rete_transport::Snapshot {
        self.transport.save_snapshot(detail)
    }

    /// Restore transport state from a previously saved snapshot.
    pub fn load_snapshot(&mut self, snap: &rete_transport::Snapshot) {
        self.transport.load_snapshot(snap);
    }

    /// Returns a reference to the primary destination.
    pub fn primary_dest(&self) -> &Destination {
        &self.primary_dest
    }

    /// Returns a mutable reference to the primary destination.
    pub fn primary_dest_mut(&mut self) -> &mut Destination {
        &mut self.primary_dest
    }

    /// Set the proof generation strategy for incoming data packets.
    pub fn set_proof_strategy(&mut self, strategy: ProofStrategy) {
        self.primary_dest.set_proof_strategy(strategy);
    }

    /// Set default application data included in announces.
    pub fn set_default_app_data(&mut self, data: Option<Vec<u8>>) {
        self.primary_dest.set_default_app_data(data);
    }

    /// Build an encrypted DATA packet addressed to a known destination.
    ///
    /// Also registers a receipt for proof tracking. The `now` timestamp is
    /// used for receipt timeout calculation.
    pub fn build_data_packet<R: RngCore + CryptoRng>(
        &mut self,
        dest_hash: &[u8; TRUNCATED_HASH_LEN],
        plaintext: &[u8],
        rng: &mut R,
        now: u64,
    ) -> Result<Vec<u8>, SendError> {
        let pub_key = *self
            .transport
            .recall_identity(dest_hash)
            .ok_or(SendError::UnknownDestination)?;
        let recipient = Identity::from_public_key(&pub_key).map_err(SendError::Crypto)?;
        let mut ct_buf = [0u8; MTU];
        let ct_len = recipient
            .encrypt(plaintext, rng, &mut ct_buf)
            .map_err(SendError::Crypto)?;
        let via = self.transport.get_path(dest_hash).and_then(|p| p.via);
        self.transport.touch_path(dest_hash, now);
        let mut pkt_buf = [0u8; MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Single)
            .destination_hash(dest_hash)
            .context(0x00)
            .payload(&ct_buf[..ct_len])
            .via(via.as_ref())
            .build()
            .map_err(SendError::PacketBuild)?;

        // Register receipt for proof tracking
        if let Ok(parsed) = Packet::parse(&pkt_buf[..pkt_len]) {
            let pkt_hash = parsed.compute_hash();
            self.transport
                .register_receipt(pkt_hash, pub_key, now, RECEIPT_TIMEOUT);
        }

        Ok(pkt_buf[..pkt_len].to_vec())
    }

    /// Build a path request packet for a destination.
    pub fn request_path(&self, dest_hash: &[u8; TRUNCATED_HASH_LEN]) -> OutboundPacket {
        let raw = Transport::<P, A, D, L>::build_path_request(dest_hash);
        OutboundPacket::broadcast(raw)
    }

    /// Build a proof OutboundPacket for a received packet hash, if possible.
    ///
    /// Uses `dest_type=Single` — for non-link (DATA) proofs only.
    pub(super) fn proof_outbound(&self, packet_hash: &[u8; 32]) -> Option<OutboundPacket> {
        Transport::<P, A, D, L>::build_proof_packet(&self.identity, packet_hash).map(|data| {
            OutboundPacket {
                data,
                routing: PacketRouting::SourceInterface,
            }
        })
    }

    /// Build a link-destination proof OutboundPacket for a link-related packet.
    ///
    /// Uses `dest_type=Link` and `destination_hash=link_id` so transport relays
    /// (rnsd) can route the proof back through their link table.
    pub(super) fn link_proof_outbound(
        &self,
        packet_hash: &[u8; 32],
        link_id: &[u8; TRUNCATED_HASH_LEN],
    ) -> Option<OutboundPacket> {
        Transport::<P, A, D, L>::build_link_proof_packet(&self.identity, packet_hash, link_id).map(
            |data| OutboundPacket {
                data,
                routing: PacketRouting::SourceInterface,
            },
        )
    }

    /// Send plain data over an established link.
    pub fn send_link_data<R: RngCore + CryptoRng>(
        &self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        data: &[u8],
        rng: &mut R,
    ) -> Result<OutboundPacket, SendError> {
        let pkt =
            self.transport
                .build_link_data_packet(link_id, data, rete_core::CONTEXT_NONE, rng)?;
        Ok(OutboundPacket::broadcast(pkt))
    }

    /// Send a link.request() on an established link.
    ///
    /// Returns `(outbound_packet, request_id)` on success, or `Err` if the link
    /// is not active. The `request_id` can be used to correlate the eventual response.
    pub fn send_request<R: RngCore + CryptoRng>(
        &self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        path: &str,
        data: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<(OutboundPacket, [u8; TRUNCATED_HASH_LEN]), SendError> {
        let packed = rete_transport::build_request(path, data, now as f64);
        let pkt = self.transport.build_link_data_packet(
            link_id,
            &packed,
            rete_core::CONTEXT_REQUEST,
            rng,
        )?;
        // Compute request_id from the packet's truncated hash — must match
        // how the receiver computes it (transport.rs uses pkt_hash[..16]).
        // Python RNS Link.py: RequestReceipt uses packet_receipt.truncated_hash.
        let parsed = rete_core::Packet::parse(&pkt).map_err(SendError::PacketBuild)?;
        let pkt_hash = parsed.compute_hash();
        let mut req_id = [0u8; TRUNCATED_HASH_LEN];
        req_id.copy_from_slice(&pkt_hash[..TRUNCATED_HASH_LEN]);
        Ok((OutboundPacket::broadcast(pkt), req_id))
    }

    /// Send a link.response() on an established link.
    ///
    /// Returns the outbound packet on success, or `Err` if the link is not active.
    pub fn send_response<R: RngCore + CryptoRng>(
        &self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        request_id: &[u8; TRUNCATED_HASH_LEN],
        data: &[u8],
        rng: &mut R,
    ) -> Result<OutboundPacket, SendError> {
        let packed = rete_transport::build_response(request_id, data);
        let pkt = self.transport.build_link_data_packet(
            link_id,
            &packed,
            rete_core::CONTEXT_RESPONSE,
            rng,
        )?;
        Ok(OutboundPacket::broadcast(pkt))
    }

    /// Start a resource transfer on a link.
    ///
    /// If a `compress_fn` is set, tries to compress `data` and only uses the
    /// compressed version when it is actually smaller.  Returns the outbound
    /// advertisement packet.
    pub fn start_resource<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        data: &[u8],
        rng: &mut R,
    ) -> Result<OutboundPacket, SendError> {
        use alloc::borrow::Cow;
        use rete_transport::resource::MAX_EFFICIENT_SIZE;

        // For split resources (data > MAX_EFFICIENT_SIZE), skip whole-blob
        // compression. Each segment will be compressed independently by the
        // transport layer. Compressed data can't be split at arbitrary boundaries.
        if data.len() > MAX_EFFICIENT_SIZE {
            let pkt = self
                .transport
                .start_resource(link_id, data, data, false, rng)
                .ok_or(SendError::ResourceLimit)?;
            return Ok(OutboundPacket::broadcast(pkt));
        }

        let compressed = self
            .compress_fn
            .and_then(|f| f(data))
            .filter(|c| c.len() < data.len());

        let (send_data, is_compressed): (Cow<'_, [u8]>, bool) = match compressed {
            Some(c) => (Cow::Owned(c), true),
            None => (Cow::Borrowed(data), false),
        };

        let pkt = self
            .transport
            .start_resource(link_id, &send_data, data, is_compressed, rng)
            .ok_or(SendError::ResourceLimit)?;
        Ok(OutboundPacket::broadcast(pkt))
    }
}

/// Hosted node core (generous memory for desktop/gateway).
pub type HostedNodeCore = NodeCore<
    { rete_transport::HOSTED_MAX_PATHS },
    { rete_transport::HOSTED_MAX_ANNOUNCES },
    { rete_transport::HOSTED_DEDUP_WINDOW },
    { rete_transport::HOSTED_MAX_LINKS },
>;

/// Embedded node core (conservative memory for MCUs).
pub type EmbeddedNodeCore = NodeCore<
    { rete_transport::EMBEDDED_MAX_PATHS },
    { rete_transport::EMBEDDED_MAX_ANNOUNCES },
    { rete_transport::EMBEDDED_DEDUP_WINDOW },
    { rete_transport::EMBEDDED_MAX_LINKS },
>;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rete_core::{HeaderType, Packet, PacketType, TRANSPORT_TYPE_TRANSPORT};

    type TestNodeCore = NodeCore<64, 16, 128, 4>;

    fn make_core(seed: &[u8]) -> TestNodeCore {
        let identity = Identity::from_seed(seed).unwrap();
        TestNodeCore::new(identity, "testapp", &["aspect1"])
    }

    #[test]
    fn node_core_new_computes_dest_hash() {
        let core = make_core(b"dest-hash-test");
        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name("testapp", &["aspect1"], &mut name_buf).unwrap();
        let expected = rete_core::destination_hash(expanded, Some(&core.identity.hash()));
        assert_eq!(*core.dest_hash(), expected);
    }

    #[test]
    fn node_core_build_announce_valid() {
        let core = make_core(b"announce-test");
        let mut rng = rand::thread_rng();
        let raw = core.build_announce(None, &mut rng, 1000);
        let pkt = Packet::parse(&raw).unwrap();
        assert_eq!(pkt.packet_type, PacketType::Announce);
        assert_eq!(pkt.destination_hash, core.dest_hash());
    }

    #[test]
    fn node_core_build_data_packet_encrypted() {
        let mut sender = make_core(b"sender-node");
        let receiver = make_core(b"receiver-node");
        let mut rng = rand::thread_rng();

        // Register receiver's identity with sender
        let receiver_id = Identity::from_seed(b"receiver-node").unwrap();
        sender.register_peer(&receiver_id, "testapp", &["aspect1"], 100);

        let pkt = sender
            .build_data_packet(receiver.dest_hash(), b"hello", &mut rng, 100)
            .expect("should build data packet");

        let parsed = Packet::parse(&pkt).unwrap();
        assert_eq!(parsed.packet_type, PacketType::Data);

        // Recipient should be able to decrypt
        let mut dec_buf = [0u8; MTU];
        let n = receiver
            .identity
            .decrypt(parsed.payload, &mut dec_buf)
            .unwrap();
        assert_eq!(&dec_buf[..n], b"hello");
    }

    #[test]
    fn node_core_handle_ingest_announce() {
        let mut core = make_core(b"ingest-announce-node");
        let mut rng = rand::thread_rng();

        // Build an announce from a peer
        let _peer = Identity::from_seed(b"peer-announce").unwrap();
        let peer_core = make_core(b"peer-announce");
        let announce = peer_core.build_announce(None, &mut rng, 1000);

        let outcome = core.handle_ingest(&announce, 1000, 0, &mut rng);
        assert!(matches!(
            outcome.event,
            Some(NodeEvent::AnnounceReceived { .. })
        ));
    }

    #[test]
    fn node_core_handle_ingest_data() {
        let mut core = make_core(b"ingest-data-node");
        let mut rng = rand::thread_rng();

        // Build encrypted DATA addressed to this node
        let node_id = Identity::from_seed(b"ingest-data-node").unwrap();
        let recipient = Identity::from_public_key(&node_id.public_key()).unwrap();
        let plaintext = b"hello node";
        let mut ct_buf = [0u8; MTU];
        let ct_len = recipient.encrypt(plaintext, &mut rng, &mut ct_buf).unwrap();

        let mut pkt_buf = [0u8; MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Single)
            .destination_hash(core.dest_hash())
            .context(0x00)
            .payload(&ct_buf[..ct_len])
            .build()
            .unwrap();

        let outcome = core.handle_ingest(&pkt_buf[..pkt_len], 1000, 0, &mut rng);
        match outcome.event {
            Some(NodeEvent::DataReceived { payload, .. }) => {
                assert_eq!(payload, plaintext);
            }
            other => panic!("expected DataReceived, got {:?}", other),
        }
    }

    #[test]
    fn node_core_handle_ingest_data_with_proof() {
        let mut core = make_core(b"proof-node");
        core.set_proof_strategy(ProofStrategy::ProveAll);
        let mut rng = rand::thread_rng();

        // Build encrypted DATA
        let node_id = Identity::from_seed(b"proof-node").unwrap();
        let recipient = Identity::from_public_key(&node_id.public_key()).unwrap();
        let mut ct_buf = [0u8; MTU];
        let ct_len = recipient
            .encrypt(b"proof me", &mut rng, &mut ct_buf)
            .unwrap();

        let mut pkt_buf = [0u8; MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Single)
            .destination_hash(core.dest_hash())
            .context(0x00)
            .payload(&ct_buf[..ct_len])
            .build()
            .unwrap();

        let outcome = core.handle_ingest(&pkt_buf[..pkt_len], 1000, 0, &mut rng);
        // Should have a proof packet in outcome
        let proof_packets: Vec<_> = outcome
            .packets
            .iter()
            .filter(|p| {
                Packet::parse(&p.data)
                    .map(|pkt| pkt.packet_type == PacketType::Proof)
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(proof_packets.len(), 1, "should generate one proof packet");
        assert_eq!(proof_packets[0].routing, PacketRouting::SourceInterface);
    }

    #[test]
    fn node_core_handle_ingest_forward() {
        let mut core = make_core(b"forward-node");
        core.enable_transport();
        let mut rng = rand::thread_rng();

        let local_hash = core.identity.hash();
        let dest = [0xCC; TRUNCATED_HASH_LEN];
        let next_hop = [0xDD; TRUNCATED_HASH_LEN];
        let path = rete_transport::Path::via_repeater(next_hop, 3, 100);
        core.transport.insert_path(dest, path);

        // Build HEADER_2 DATA addressed through us
        let mut buf = [0u8; MTU];
        let n = PacketBuilder::new(&mut buf)
            .header_type(HeaderType::Header2)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Single)
            .transport_type(TRANSPORT_TYPE_TRANSPORT)
            .transport_id(&local_hash)
            .destination_hash(&dest)
            .context(0x00)
            .payload(b"forward me")
            .build()
            .unwrap();

        let outcome = core.handle_ingest(&buf[..n], 100, 0, &mut rng);
        assert!(
            outcome.event.is_none(),
            "forward should not produce an event"
        );
        assert_eq!(outcome.packets.len(), 1);
        assert_eq!(outcome.packets[0].routing, PacketRouting::AllExceptSource);
    }

    #[test]
    fn node_core_handle_tick() {
        let mut core = make_core(b"tick-node");
        let mut rng = rand::thread_rng();

        let outcome = core.handle_tick(1000, &mut rng);
        match outcome.event {
            Some(NodeEvent::Tick { expired_paths, .. }) => {
                assert_eq!(expired_paths, 0);
            }
            other => panic!("expected Tick, got {:?}", other),
        }
    }

    #[test]
    fn node_core_register_peer() {
        let mut core = make_core(b"register-node");
        let mut rng = rand::thread_rng();

        let peer = Identity::from_seed(b"known-peer").unwrap();
        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name("testapp", &["aspect1"], &mut name_buf).unwrap();
        let peer_dest = rete_core::destination_hash(expanded, Some(&peer.hash()));

        core.register_peer(&peer, "testapp", &["aspect1"], 100);

        // Should be able to build data packet to registered peer
        let pkt = core.build_data_packet(&peer_dest, b"hello peer", &mut rng, 100);
        assert!(pkt.is_ok(), "should build data packet to registered peer");
    }

    // -----------------------------------------------------------------------
    // Helper: full handshake between two NodeCores
    // -----------------------------------------------------------------------

    /// Set up two NodeCores and perform a full handshake.
    /// Returns (initiator, responder, link_id).
    fn two_core_handshake() -> (TestNodeCore, TestNodeCore, [u8; TRUNCATED_HASH_LEN]) {
        let mut rng = rand::thread_rng();

        // Responder
        let mut resp = make_core(b"resp-core");

        // Initiator — register responder's identity so proof can be verified
        let mut init = make_core(b"init-core");
        let resp_id = Identity::from_seed(b"resp-core").unwrap();
        init.register_peer(&resp_id, "testapp", &["aspect1"], 100);

        // Initiator sends LINKREQUEST
        let (outbound, link_id) = init
            .initiate_link(*resp.dest_hash(), 100, &mut rng)
            .expect("should produce LINKREQUEST");

        // Responder ingests LINKREQUEST → emits LinkEstablished + proof
        let resp_outcome = resp.handle_ingest(&outbound.data, 100, 0, &mut rng);
        assert!(
            matches!(resp_outcome.event, Some(NodeEvent::LinkEstablished { .. })),
            "responder should emit LinkEstablished"
        );
        assert!(
            !resp_outcome.packets.is_empty(),
            "responder should send LRPROOF"
        );
        let proof_pkt = &resp_outcome.packets[0];

        // Initiator ingests LRPROOF → emits LinkEstablished + auto-sends LRRTT
        let init_outcome = init.handle_ingest(&proof_pkt.data, 101, 0, &mut rng);
        assert!(
            matches!(init_outcome.event, Some(NodeEvent::LinkEstablished { .. })),
            "initiator should emit LinkEstablished"
        );

        // Find the LRRTT packet in initiator's outcome
        let lrrtt_pkt = init_outcome
            .packets
            .iter()
            .find(|p| {
                rete_core::Packet::parse(&p.data)
                    .map(|pkt| pkt.context == rete_core::CONTEXT_LRRTT)
                    .unwrap_or(false)
            })
            .expect("initiator should auto-send LRRTT");

        // Responder ingests LRRTT → activates
        let resp_outcome2 = resp.handle_ingest(&lrrtt_pkt.data, 102, 0, &mut rng);
        assert!(
            matches!(resp_outcome2.event, Some(NodeEvent::LinkEstablished { .. })),
            "responder should emit LinkEstablished on LRRTT"
        );

        (init, resp, link_id)
    }

    // -----------------------------------------------------------------------
    // Phase 1: LRRTT auto-send tests
    // -----------------------------------------------------------------------

    #[test]
    fn node_core_link_established_initiator_sends_lrrtt() {
        let mut rng = rand::thread_rng();

        let mut resp = make_core(b"lrrtt-resp");
        let mut init = make_core(b"lrrtt-init");
        let resp_id = Identity::from_seed(b"lrrtt-resp").unwrap();
        init.register_peer(&resp_id, "testapp", &["aspect1"], 100);

        let (outbound, _link_id) = init
            .initiate_link(*resp.dest_hash(), 100, &mut rng)
            .unwrap();

        // Responder ingests LINKREQUEST
        let resp_outcome = resp.handle_ingest(&outbound.data, 100, 0, &mut rng);
        let proof_pkt = &resp_outcome.packets[0];

        // Initiator ingests LRPROOF
        let init_outcome = init.handle_ingest(&proof_pkt.data, 101, 0, &mut rng);

        // Should have LRRTT in packets
        let has_lrrtt = init_outcome.packets.iter().any(|p| {
            rete_core::Packet::parse(&p.data)
                .map(|pkt| pkt.context == rete_core::CONTEXT_LRRTT)
                .unwrap_or(false)
        });
        assert!(has_lrrtt, "initiator should auto-send LRRTT after LRPROOF");
    }

    // -----------------------------------------------------------------------
    // Phase 2: Link initiation tests
    // -----------------------------------------------------------------------

    #[test]
    fn node_core_initiate_link_produces_request() {
        let mut core = make_core(b"init-link-test");
        let mut rng = rand::thread_rng();
        let dest_hash = [0xAA; TRUNCATED_HASH_LEN];

        let (outbound, link_id) = core
            .initiate_link(dest_hash, 100, &mut rng)
            .expect("should produce a link request");

        let parsed = Packet::parse(&outbound.data).unwrap();
        assert_eq!(parsed.packet_type, PacketType::LinkRequest);
        assert_eq!(outbound.routing, PacketRouting::All);
        assert!(core.transport.get_link(&link_id).is_some());
    }

    #[test]
    fn node_core_full_link_lifecycle_two_cores() {
        let (init, resp, link_id) = two_core_handshake();

        // Both links should be active
        let init_link = init.transport.get_link(&link_id).unwrap();
        assert_eq!(init_link.state, rete_transport::LinkState::Active);

        let resp_link = resp.transport.get_link(&link_id).unwrap();
        assert_eq!(resp_link.state, rete_transport::LinkState::Active);
    }

    // -----------------------------------------------------------------------
    // Phase 3: Keepalive tests
    // -----------------------------------------------------------------------

    #[test]
    fn node_core_tick_sends_keepalives() {
        let (mut init, _resp, link_id) = two_core_handshake();
        let mut rng = rand::thread_rng();

        let ka_interval = init
            .transport
            .get_link(&link_id)
            .unwrap()
            .keepalive_interval;

        // Tick with time well past half keepalive interval
        let outcome = init.handle_tick(101 + ka_interval / 2 + 1, &mut rng);
        let has_keepalive = outcome.packets.iter().any(|p| {
            rete_core::Packet::parse(&p.data)
                .map(|pkt| pkt.context == rete_core::CONTEXT_KEEPALIVE)
                .unwrap_or(false)
        });
        assert!(has_keepalive, "tick should produce keepalive packet");
    }

    // -----------------------------------------------------------------------
    // Phase 4: Channel through NodeCore tests
    // -----------------------------------------------------------------------

    #[test]
    fn node_core_channel_send_receive() {
        let (mut init, mut resp, link_id) = two_core_handshake();
        let mut rng = rand::thread_rng();

        // Send channel message from initiator
        let outbound = init
            .send_channel_message(&link_id, 0x42, b"core channel msg", 200, &mut rng)
            .expect("should send channel message");

        // Responder ingests
        let outcome = resp.handle_ingest(&outbound.data, 200, 0, &mut rng);
        match outcome.event {
            Some(NodeEvent::ChannelMessages {
                link_id: lid,
                messages,
            }) => {
                assert_eq!(lid, link_id);
                assert_eq!(messages.len(), 1);
                assert_eq!(messages[0].0, 0x42); // message_type
                assert_eq!(messages[0].1, b"core channel msg"); // payload
            }
            other => panic!("expected ChannelMessages, got {:?}", other),
        }
    }

    #[test]
    fn node_core_channel_in_tick_retransmit() {
        let (mut init, _resp, link_id) = two_core_handshake();
        let mut rng = rand::thread_rng();

        // Send a channel message (sent_at=200)
        let _outbound = init
            .send_channel_message(&link_id, 0x01, b"tick retx", 200, &mut rng)
            .unwrap();

        // Tick before timeout — no retransmit
        let outcome = init.handle_tick(210, &mut rng);
        let channel_pkts: Vec<_> = outcome
            .packets
            .iter()
            .filter(|p| {
                rete_core::Packet::parse(&p.data)
                    .map(|pkt| pkt.context == rete_core::CONTEXT_CHANNEL)
                    .unwrap_or(false)
            })
            .collect();
        assert!(channel_pkts.is_empty(), "no retransmit before timeout");

        // Tick after timeout (15s)
        let outcome = init.handle_tick(216, &mut rng);
        let channel_pkts: Vec<_> = outcome
            .packets
            .iter()
            .filter(|p| {
                rete_core::Packet::parse(&p.data)
                    .map(|pkt| pkt.context == rete_core::CONTEXT_CHANNEL)
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(channel_pkts.len(), 1, "should retransmit one channel msg");
    }

    // -----------------------------------------------------------------------
    // Phase 5: Stream convenience tests
    // -----------------------------------------------------------------------

    #[test]
    fn node_core_stream_data_round_trip() {
        let (mut init, mut resp, link_id) = two_core_handshake();
        let mut rng = rand::thread_rng();

        // Send stream data
        let outbound = init
            .send_stream_data(&link_id, 1, b"stream payload", false, 200, &mut rng)
            .expect("should send stream data");

        // Responder receives it
        let outcome = resp.handle_ingest(&outbound.data, 200, 0, &mut rng);
        match outcome.event {
            Some(NodeEvent::ChannelMessages { messages, .. }) => {
                assert_eq!(messages.len(), 1);
                assert_eq!(messages[0].0, rete_transport::MSG_TYPE_STREAM);
                // Unpack the stream message
                let sdm = rete_transport::StreamDataMessage::unpack(&messages[0].1).unwrap();
                assert_eq!(sdm.stream_id, 1);
                assert_eq!(sdm.data, b"stream payload");
                assert!(!sdm.eof);
            }
            other => panic!("expected ChannelMessages, got {:?}", other),
        }

        // Send EOF segment
        let outbound2 = init
            .send_stream_data(&link_id, 1, b"final", true, 201, &mut rng)
            .expect("should send stream EOF");

        let outcome2 = resp.handle_ingest(&outbound2.data, 201, 0, &mut rng);
        match outcome2.event {
            Some(NodeEvent::ChannelMessages { messages, .. }) => {
                let sdm = rete_transport::StreamDataMessage::unpack(&messages[0].1).unwrap();
                assert_eq!(sdm.stream_id, 1);
                assert!(sdm.eof);
                assert_eq!(sdm.data, b"final");
            }
            other => panic!("expected ChannelMessages, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Phase: Receipt wiring tests
    // -----------------------------------------------------------------------

    #[test]
    fn receipt_auto_registered_on_data_send() {
        let mut sender = make_core(b"receipt-sender");
        let receiver = make_core(b"receipt-receiver");
        let mut rng = rand::thread_rng();

        let receiver_id = Identity::from_seed(b"receipt-receiver").unwrap();
        sender.register_peer(&receiver_id, "testapp", &["aspect1"], 100);

        assert_eq!(sender.transport.receipt_count(), 0);
        let _pkt = sender
            .build_data_packet(receiver.dest_hash(), b"hello", &mut rng, 100)
            .expect("should build data packet");
        assert_eq!(sender.transport.receipt_count(), 1);
    }

    #[test]
    fn proof_for_sent_data_fires_event() {
        let mut sender = make_core(b"proof-fire-sender");
        let mut receiver = make_core(b"proof-fire-receiver");
        receiver.set_proof_strategy(ProofStrategy::ProveAll);
        let mut rng = rand::thread_rng();

        // Register each other
        let receiver_id = Identity::from_seed(b"proof-fire-receiver").unwrap();
        sender.register_peer(&receiver_id, "testapp", &["aspect1"], 100);

        // Sender builds data → receipt auto-registered
        let pkt = sender
            .build_data_packet(receiver.dest_hash(), b"prove me", &mut rng, 100)
            .expect("should build data packet");
        assert_eq!(sender.transport.receipt_count(), 1);

        // Receiver ingests → generates proof
        let outcome = receiver.handle_ingest(&pkt, 100, 0, &mut rng);
        let proof_pkt = outcome
            .packets
            .iter()
            .find(|p| {
                Packet::parse(&p.data)
                    .map(|pkt| pkt.packet_type == PacketType::Proof)
                    .unwrap_or(false)
            })
            .expect("receiver should generate proof");

        // Sender ingests proof → should fire ProofReceived
        let outcome = sender.handle_ingest(&proof_pkt.data, 101, 0, &mut rng);
        assert!(
            matches!(outcome.event, Some(NodeEvent::ProofReceived { .. })),
            "expected ProofReceived, got {:?}",
            outcome.event
        );
    }

    #[test]
    fn receipt_expires_on_tick() {
        let mut sender = make_core(b"receipt-expire");
        let receiver = make_core(b"receipt-expire-recv");
        let mut rng = rand::thread_rng();

        let receiver_id = Identity::from_seed(b"receipt-expire-recv").unwrap();
        sender.register_peer(&receiver_id, "testapp", &["aspect1"], 100);

        let _pkt = sender
            .build_data_packet(receiver.dest_hash(), b"hello", &mut rng, 100)
            .expect("should build data packet");
        assert_eq!(sender.transport.receipt_count(), 1);

        // Tick before timeout — receipt should still be there
        sender.handle_tick(120, &mut rng);
        assert_eq!(sender.transport.receipt_count(), 1);

        // Tick after timeout (30s) — receipt should be failed
        sender.handle_tick(131, &mut rng);
        // Receipt is still in the table but marked Failed
        assert_eq!(sender.transport.receipt_count(), 1);
    }

    // -----------------------------------------------------------------------
    // Phase: Path request origination tests
    // -----------------------------------------------------------------------

    #[test]
    fn path_request_produces_valid_packet() {
        let core = make_core(b"path-req-test");
        let dest = [0xBB; rete_core::TRUNCATED_HASH_LEN];
        let outbound = core.request_path(&dest);
        let parsed = Packet::parse(&outbound.data).unwrap();
        assert_eq!(parsed.packet_type, PacketType::Data);
        assert_eq!(parsed.dest_type, rete_core::DestType::Plain);
        assert_eq!(parsed.destination_hash, &rete_transport::PATH_REQUEST_DEST);
        assert_eq!(parsed.payload, &dest);
    }

    // -----------------------------------------------------------------------
    // Announce queue tests
    // -----------------------------------------------------------------------

    #[test]
    fn queue_announce_adds_to_transport() {
        let mut core = make_core(b"queue-announce");
        let mut rng = rand::thread_rng();

        assert_eq!(core.transport.announce_count(), 0);
        assert!(core.queue_announce(None, &mut rng, 1000));
        assert_eq!(core.transport.announce_count(), 1);
    }

    #[test]
    fn queue_announce_local_flushes_immediately() {
        let mut core = make_core(b"queue-flush");
        let mut rng = rand::thread_rng();

        core.queue_announce(None, &mut rng, 1000);
        let pending = core.transport.pending_outbound(1000, &mut rng);

        // local=true means it's sent immediately
        assert_eq!(pending.len(), 1);
        // The announce should be valid
        let pkt = Packet::parse(&pending[0]).unwrap();
        assert_eq!(pkt.packet_type, PacketType::Announce);
    }

    #[test]
    fn queue_announce_retransmits_once() {
        let mut core = make_core(b"queue-retx");
        let mut rng = rand::thread_rng();

        core.queue_announce(None, &mut rng, 1000);

        // First flush: immediate (local=true)
        let p1 = core.transport.pending_outbound(1000, &mut rng);
        assert_eq!(p1.len(), 1);

        // Still in queue (tx_count=1, PATHFINDER_R=1)
        assert_eq!(core.transport.announce_count(), 1);

        // Too early for retransmit (delay = PATHFINDER_G = 5s, timeout at 1005)
        let p2 = core.transport.pending_outbound(1004, &mut rng);
        assert_eq!(p2.len(), 0);

        // At timeout: retransmit (with jitter, timeout could be 1005 or 1006)
        let p3 = core.transport.pending_outbound(1006, &mut rng);
        assert_eq!(p3.len(), 1);

        // Now tx_count=2 > PATHFINDER_R=1, so dropped from queue
        assert_eq!(core.transport.announce_count(), 0);
    }

    // -----------------------------------------------------------------------
    // Channel proof (ACK) tests
    // -----------------------------------------------------------------------

    #[test]
    fn channel_receive_generates_proof() {
        let (mut init, mut resp, link_id) = two_core_handshake();
        let mut rng = rand::thread_rng();

        // Initiator sends channel message
        let outbound = init
            .send_channel_message(&link_id, 0x42, b"prove this", 200, &mut rng)
            .expect("should send");

        // Responder ingests — should generate a proof in the packets
        let outcome = resp.handle_ingest(&outbound.data, 200, 0, &mut rng);
        assert!(
            matches!(outcome.event, Some(NodeEvent::ChannelMessages { .. })),
            "expected ChannelMessages, got {:?}",
            outcome.event
        );
        let proof_pkt = outcome
            .packets
            .iter()
            .find(|p| {
                Packet::parse(&p.data)
                    .map(|pkt| pkt.packet_type == PacketType::Proof)
                    .unwrap_or(false)
            })
            .expect("responder should auto-prove channel packet");
        assert_eq!(
            proof_pkt.routing,
            PacketRouting::SourceInterface,
            "proof should route back to source"
        );
    }

    #[test]
    fn channel_proof_marks_delivered() {
        let (mut init, mut resp, link_id) = two_core_handshake();
        let mut rng = rand::thread_rng();

        // Initiator sends channel message
        let outbound = init
            .send_channel_message(&link_id, 0x42, b"ack me", 200, &mut rng)
            .expect("should send");

        // Confirm channel has 1 pending
        let init_link = init.transport.get_link(&link_id).unwrap();
        assert_eq!(init_link.channel().unwrap().pending_count(), 1);

        // Responder ingests → gets proof packet
        let outcome = resp.handle_ingest(&outbound.data, 200, 0, &mut rng);
        let proof_pkt = outcome
            .packets
            .iter()
            .find(|p| {
                Packet::parse(&p.data)
                    .map(|pkt| pkt.packet_type == PacketType::Proof)
                    .unwrap_or(false)
            })
            .expect("should have proof");

        // Verify channel receipt was registered
        assert_eq!(
            init.transport.channel_receipt_count(),
            1,
            "should have 1 channel receipt after send"
        );

        // Initiator ingests the proof → should fire ProofReceived + mark_delivered
        let init_outcome = init.handle_ingest(&proof_pkt.data, 201, 0, &mut rng);
        assert!(
            matches!(init_outcome.event, Some(NodeEvent::ProofReceived { .. })),
            "expected ProofReceived, got {:?}",
            init_outcome.event
        );

        // Channel should now have 0 pending
        let init_link = init.transport.get_link(&link_id).unwrap();
        assert_eq!(
            init_link.channel().unwrap().pending_count(),
            0,
            "proof should clear pending channel message"
        );
    }

    #[test]
    fn buffered_channel_packet_also_proved() {
        let (mut init, mut resp, link_id) = two_core_handshake();
        let mut rng = rand::thread_rng();

        // Send two messages — deliver seq 1 first (out of order)
        let _pkt0 = init
            .send_channel_message(&link_id, 0x01, b"msg0", 200, &mut rng)
            .unwrap();
        let pkt1 = init
            .send_channel_message(&link_id, 0x01, b"msg1", 201, &mut rng)
            .unwrap();

        // Deliver seq 1 first — should be buffered
        let outcome = resp.handle_ingest(&pkt1.data, 202, 0, &mut rng);
        assert!(outcome.event.is_none(), "buffered should not emit event");

        // But should still have a proof packet
        let has_proof = outcome.packets.iter().any(|p| {
            Packet::parse(&p.data)
                .map(|pkt| pkt.packet_type == PacketType::Proof)
                .unwrap_or(false)
        });
        assert!(has_proof, "buffered channel packet should still be proved");
    }

    // -----------------------------------------------------------------------
    // Edge-case tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ingest_oversized_packet() {
        // Pass a buffer larger than TCP_MAX_PKT (8292) to handle_ingest —
        // should not panic, should return empty outcome (no event).
        let mut core = make_core(b"oversized-test");
        let mut rng = rand::thread_rng();

        let oversized = [0u8; 8293];
        let outcome = core.handle_ingest(&oversized, 1000, 0, &mut rng);
        assert!(
            outcome.event.is_none(),
            "oversized packet should produce no event"
        );
        assert!(
            outcome.packets.is_empty(),
            "oversized packet should produce no outbound packets"
        );
    }

    #[test]
    fn test_ingest_undersized_packet() {
        // Pass a 1-byte buffer (< minimum 2 bytes for flags+hops).
        // Should not crash and should return empty outcome.
        let mut core = make_core(b"undersized-test");
        let mut rng = rand::thread_rng();

        let tiny = [0x08u8]; // just flags byte, no hops
        let outcome = core.handle_ingest(&tiny, 1000, 0, &mut rng);
        assert!(
            outcome.event.is_none(),
            "undersized packet should produce no event"
        );

        // Also try empty
        let empty: [u8; 0] = [];
        let outcome2 = core.handle_ingest(&empty, 1000, 0, &mut rng);
        assert!(
            outcome2.event.is_none(),
            "empty packet should produce no event"
        );
    }

    #[test]
    fn test_build_data_packet_no_cached_key() {
        // build_data_packet when no public key is cached for the destination.
        // Should return Err when no cached key.
        let mut core = make_core(b"no-key-test");
        let mut rng = rand::thread_rng();

        let unknown_dest = [0xFFu8; TRUNCATED_HASH_LEN];
        let result = core.build_data_packet(&unknown_dest, b"hello", &mut rng, 100);
        assert!(
            matches!(result, Err(rete_transport::SendError::UnknownDestination)),
            "should return Err(UnknownDestination) when no cached key"
        );
    }

    // -----------------------------------------------------------------------
    // Multi-destination tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_register_destination_adds_to_transport() {
        let mut core = make_core(b"register-dest-test");
        let hash = core.register_destination("lxmf", &["delivery"]);
        // Should be a valid 16-byte hash, different from primary
        assert_ne!(hash, *core.dest_hash());
        // Transport should have it as local
        assert!(core.get_destination(&hash).is_some());
    }

    #[test]
    fn test_register_destination_returns_correct_dest_hash() {
        let core_seed = b"dest-hash-verify";
        let mut core = make_core(core_seed);
        let hash = core.register_destination("lxmf", &["delivery"]);

        // Compute expected hash independently
        let identity = Identity::from_seed(core_seed).unwrap();
        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name("lxmf", &["delivery"], &mut name_buf).unwrap();
        let expected = rete_core::destination_hash(expanded, Some(&identity.hash()));
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_register_destination_multiple() {
        let mut core = make_core(b"multi-dest-test");
        let h1 = core.register_destination("lxmf", &["delivery"]);
        let h2 = core.register_destination("myapp", &["service"]);
        assert_ne!(h1, h2);
        assert!(core.get_destination(&h1).is_some());
        assert!(core.get_destination(&h2).is_some());
    }

    #[test]
    fn test_primary_dest_still_accessible_after_register() {
        let mut core = make_core(b"primary-access-test");
        let primary = *core.dest_hash();
        core.register_destination("lxmf", &["delivery"]);
        assert!(core.get_destination(&primary).is_some());
        assert_eq!(core.get_destination(&primary).unwrap().app_name, "testapp");
    }

    #[test]
    fn test_get_destination_mut() {
        let mut core = make_core(b"dest-mut-test");
        let hash = core.register_destination("lxmf", &["delivery"]);
        let dest = core.get_destination_mut(&hash).unwrap();
        dest.set_proof_strategy(ProofStrategy::ProveAll);
        assert_eq!(
            core.get_destination(&hash).unwrap().proof_strategy,
            ProofStrategy::ProveAll
        );
    }

    #[test]
    fn test_ingest_data_for_secondary_dest_decrypts() {
        let mut core = make_core(b"secondary-decrypt-test");
        let lxmf_hash = core.register_destination("lxmf", &["delivery"]);
        let mut rng = rand::thread_rng();

        // Build encrypted DATA addressed to the LXMF destination
        let node_id = Identity::from_seed(b"secondary-decrypt-test").unwrap();
        let recipient = Identity::from_public_key(&node_id.public_key()).unwrap();
        let plaintext = b"lxmf message";
        let mut ct_buf = [0u8; MTU];
        let ct_len = recipient.encrypt(plaintext, &mut rng, &mut ct_buf).unwrap();

        let mut pkt_buf = [0u8; MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Single)
            .destination_hash(&lxmf_hash)
            .context(0x00)
            .payload(&ct_buf[..ct_len])
            .build()
            .unwrap();

        let outcome = core.handle_ingest(&pkt_buf[..pkt_len], 1000, 0, &mut rng);
        match outcome.event {
            Some(NodeEvent::DataReceived { dest_hash, payload }) => {
                assert_eq!(dest_hash, lxmf_hash);
                assert_eq!(payload, plaintext);
            }
            other => panic!("expected DataReceived, got {:?}", other),
        }
    }

    #[test]
    fn test_ingest_data_for_secondary_dest_proves() {
        let mut core = make_core(b"secondary-prove-test");
        let lxmf_hash = core.register_destination("lxmf", &["delivery"]);
        // Set ProveAll on the secondary dest
        core.get_destination_mut(&lxmf_hash)
            .unwrap()
            .set_proof_strategy(ProofStrategy::ProveAll);
        let mut rng = rand::thread_rng();

        // Build encrypted DATA addressed to the LXMF destination
        let node_id = Identity::from_seed(b"secondary-prove-test").unwrap();
        let recipient = Identity::from_public_key(&node_id.public_key()).unwrap();
        let mut ct_buf = [0u8; MTU];
        let ct_len = recipient
            .encrypt(b"prove me", &mut rng, &mut ct_buf)
            .unwrap();

        let mut pkt_buf = [0u8; MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Single)
            .destination_hash(&lxmf_hash)
            .context(0x00)
            .payload(&ct_buf[..ct_len])
            .build()
            .unwrap();

        let outcome = core.handle_ingest(&pkt_buf[..pkt_len], 1000, 0, &mut rng);
        let proof_packets: Vec<_> = outcome
            .packets
            .iter()
            .filter(|p| {
                Packet::parse(&p.data)
                    .map(|pkt| pkt.packet_type == PacketType::Proof)
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(
            proof_packets.len(),
            1,
            "secondary dest should generate proof"
        );
    }

    #[test]
    fn test_queue_announce_for_secondary_dest() {
        let mut core = make_core(b"announce-secondary-test");
        let lxmf_hash = core.register_destination("lxmf", &["delivery"]);
        let mut rng = rand::thread_rng();

        assert!(core.queue_announce_for(&lxmf_hash, None, &mut rng, 1000));
        let pending = core.transport.pending_outbound(1000, &mut rng);
        assert_eq!(pending.len(), 1);

        let pkt = Packet::parse(&pending[0]).unwrap();
        assert_eq!(pkt.packet_type, PacketType::Announce);
        assert_eq!(pkt.destination_hash, &lxmf_hash);
    }

    #[test]
    fn test_queue_announce_for_with_app_data() {
        let mut core = make_core(b"announce-appdata-test");
        let lxmf_hash = core.register_destination("lxmf", &["delivery"]);
        let mut rng = rand::thread_rng();

        let app_data = b"some app data";
        assert!(core.queue_announce_for(&lxmf_hash, Some(app_data), &mut rng, 1000));
        let pending = core.transport.pending_outbound(1000, &mut rng);
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn test_queue_announce_for_unknown_dest_fails() {
        let mut core = make_core(b"announce-unknown-test");
        let mut rng = rand::thread_rng();
        let unknown = [0xFF; TRUNCATED_HASH_LEN];
        assert!(!core.queue_announce_for(&unknown, None, &mut rng, 1000));
    }

    #[test]
    fn test_queue_announce_when_full() {
        // Queue announces until the transport queue is full, then verify
        // the next queue attempt handles gracefully.
        type SmallNodeCore = NodeCore<64, 4, 128, 4>; // only 4 announce slots
        let identity = Identity::from_seed(b"queue-full-test").unwrap();
        let mut core = SmallNodeCore::new(identity, "testapp", &["aspect1"]);
        let mut rng = rand::thread_rng();

        // Queue 4 announces (filling the queue)
        for _ in 0..4 {
            assert!(core.queue_announce(None, &mut rng, 1000));
        }

        // 5th queue attempt should return false (not crash)
        let result = core.queue_announce(None, &mut rng, 1000);
        assert!(!result, "queue should be full, returning false");
    }

    // -----------------------------------------------------------------------
    // Channel through relay (3-node) test
    // -----------------------------------------------------------------------

    #[test]
    fn test_channel_through_relay() {
        let mut rng = rand::thread_rng();

        // -----------------------------------------------------------------
        // Step 1: Create 3 NodeCores
        // A = initiator, B = transport relay, C = responder
        // -----------------------------------------------------------------
        let mut node_a = make_core(b"relay-node-a");
        let mut node_b = make_core(b"relay-node-b");
        let mut node_c = make_core(b"relay-node-c");

        // -----------------------------------------------------------------
        // Step 2: Enable transport on B (makes it a relay)
        // -----------------------------------------------------------------
        node_b.enable_transport();

        // -----------------------------------------------------------------
        // Step 3: A knows C's identity (register_peer)
        // -----------------------------------------------------------------
        let id_c = Identity::from_seed(b"relay-node-c").unwrap();
        node_a.register_peer(&id_c, "testapp", &["aspect1"], 100);

        // Override A's direct path to C with a path via B's identity hash.
        // This causes initiate_link to build a HEADER_2 LINKREQUEST with
        // transport_id = B's identity hash.
        let id_b = Identity::from_seed(b"relay-node-b").unwrap();
        let c_dest = *node_c.dest_hash();
        node_a.transport.insert_path(
            c_dest,
            rete_transport::Path::via_repeater(id_b.hash(), 2, 100),
        );

        // -----------------------------------------------------------------
        // Step 4: B knows C's identity and has a direct path to C's dest.
        // This lets B forward the LINKREQUEST and strip the HEADER_2
        // transport header (converting back to HEADER_1 for C).
        // -----------------------------------------------------------------
        node_b.register_peer(&id_c, "testapp", &["aspect1"], 100);

        // -----------------------------------------------------------------
        // Step 5: Link handshake: A → B → C → B → A
        // -----------------------------------------------------------------

        // 5a. A initiates link to C's dest hash.
        // Because A has a path to C via B, this produces a HEADER_2 LINKREQUEST
        // with transport_id = B's identity hash.
        let (lr_outbound, link_id) = node_a
            .initiate_link(c_dest, 100, &mut rng)
            .expect("A should produce LINKREQUEST");
        let lr_parsed = Packet::parse(&lr_outbound.data).unwrap();
        assert_eq!(
            lr_parsed.header_type,
            HeaderType::Header2,
            "LINKREQUEST should be HEADER_2 (routed via relay B)"
        );
        assert_eq!(lr_parsed.packet_type, PacketType::LinkRequest);

        // 5b. Feed LINKREQUEST to B (arriving on iface 0 from A's direction).
        // B's transport sees transport_id == own identity hash, creates a
        // link_table entry for the link_id, and forwards (stripped to HEADER_1).
        let b_outcome = node_b.handle_ingest(&lr_outbound.data, 100, 0, &mut rng);
        assert!(
            b_outcome.event.is_none(),
            "relay B should not emit an event for forwarded LINKREQUEST"
        );
        assert_eq!(
            b_outcome.packets.len(),
            1,
            "relay B should forward exactly one packet"
        );
        assert_eq!(b_outcome.packets[0].routing, PacketRouting::AllExceptSource);

        let forwarded_lr = &b_outcome.packets[0].data;

        // 5c. Feed the forwarded LINKREQUEST to C (arriving on iface 1 from B's direction).
        // C is the local destination, so it accepts the link and produces LRPROOF.
        let c_outcome = node_c.handle_ingest(forwarded_lr, 101, 1, &mut rng);
        assert!(
            matches!(c_outcome.event, Some(NodeEvent::LinkEstablished { .. })),
            "C should emit LinkEstablished on receiving LINKREQUEST"
        );
        assert!(!c_outcome.packets.is_empty(), "C should produce LRPROOF");
        let lrproof_pkt = &c_outcome.packets[0].data;

        // 5d. Feed LRPROOF to B (arriving on iface 1 from C's direction).
        // LRPROOF has dest_type=Link, destination_hash=link_id.
        // B has link_id in its link_table, so it forwards the proof.
        let b_proof_outcome = node_b.handle_ingest(lrproof_pkt, 102, 1, &mut rng);
        assert!(
            b_proof_outcome.event.is_none(),
            "relay B should not emit an event for forwarded LRPROOF"
        );
        assert_eq!(
            b_proof_outcome.packets.len(),
            1,
            "relay B should forward the LRPROOF"
        );
        let forwarded_proof = &b_proof_outcome.packets[0].data;

        // 5e. Feed LRPROOF to A (arriving on iface 0).
        // A verifies the proof → emits LinkEstablished + auto-sends LRRTT.
        let a_proof_outcome = node_a.handle_ingest(forwarded_proof, 103, 0, &mut rng);
        assert!(
            matches!(
                a_proof_outcome.event,
                Some(NodeEvent::LinkEstablished { .. })
            ),
            "A should emit LinkEstablished after verifying LRPROOF"
        );

        // Find the LRRTT packet in A's outcome
        let lrrtt_pkt = a_proof_outcome
            .packets
            .iter()
            .find(|p| {
                rete_core::Packet::parse(&p.data)
                    .map(|pkt| pkt.context == rete_core::CONTEXT_LRRTT)
                    .unwrap_or(false)
            })
            .expect("A should auto-send LRRTT after link establishment");

        // 5f. Feed LRRTT to B → B forwards via link_table.
        let b_rtt_outcome = node_b.handle_ingest(&lrrtt_pkt.data, 104, 0, &mut rng);
        assert!(
            b_rtt_outcome.event.is_none(),
            "relay B should not emit an event for forwarded LRRTT"
        );
        assert_eq!(
            b_rtt_outcome.packets.len(),
            1,
            "relay B should forward the LRRTT"
        );
        let forwarded_rtt = &b_rtt_outcome.packets[0].data;

        // 5g. Feed LRRTT to C → C emits LinkEstablished (link activated).
        let c_rtt_outcome = node_c.handle_ingest(forwarded_rtt, 105, 1, &mut rng);
        assert!(
            matches!(c_rtt_outcome.event, Some(NodeEvent::LinkEstablished { .. })),
            "C should emit LinkEstablished on receiving LRRTT (link activated)"
        );

        // Verify both links are now Active
        let a_link = node_a.transport.get_link(&link_id).unwrap();
        assert_eq!(
            a_link.state,
            rete_transport::LinkState::Active,
            "A's link should be Active"
        );
        let c_link = node_c.transport.get_link(&link_id).unwrap();
        assert_eq!(
            c_link.state,
            rete_transport::LinkState::Active,
            "C's link should be Active"
        );

        // -----------------------------------------------------------------
        // Step 6: A sends channel message → B forwards → C receives
        // -----------------------------------------------------------------
        let a_ch_outbound = node_a
            .send_channel_message(&link_id, 0x42, b"relay-channel-test", 200, &mut rng)
            .expect("A should send channel message");

        // Feed channel message to B → B forwards via link_table
        let b_ch_outcome = node_b.handle_ingest(&a_ch_outbound.data, 200, 0, &mut rng);
        assert!(
            b_ch_outcome.event.is_none(),
            "relay B should not emit an event for forwarded channel message"
        );
        assert_eq!(
            b_ch_outcome.packets.len(),
            1,
            "relay B should forward channel message"
        );
        let forwarded_ch = &b_ch_outcome.packets[0].data;

        // Feed forwarded channel message to C
        let c_ch_outcome = node_c.handle_ingest(forwarded_ch, 201, 1, &mut rng);

        // -----------------------------------------------------------------
        // Step 7: Verify C receives the channel message correctly
        // -----------------------------------------------------------------
        match c_ch_outcome.event {
            Some(NodeEvent::ChannelMessages {
                link_id: lid,
                messages,
            }) => {
                assert_eq!(lid, link_id);
                assert_eq!(messages.len(), 1);
                assert_eq!(messages[0].0, 0x42, "message_type should be 0x42");
                assert_eq!(messages[0].1, b"relay-channel-test", "payload mismatch");
            }
            other => panic!("C expected ChannelMessages, got {:?}", other),
        }

        // -----------------------------------------------------------------
        // Step 8: C sends channel message back → B forwards → A receives
        // -----------------------------------------------------------------
        let c_reply_outbound = node_c
            .send_channel_message(&link_id, 0x43, b"relay-reply", 210, &mut rng)
            .expect("C should send channel message back");

        // Feed reply to B → B forwards via link_table
        let b_reply_outcome = node_b.handle_ingest(&c_reply_outbound.data, 210, 1, &mut rng);
        assert!(
            b_reply_outcome.event.is_none(),
            "relay B should not emit an event for forwarded reply"
        );
        assert_eq!(
            b_reply_outcome.packets.len(),
            1,
            "relay B should forward reply channel message"
        );
        let forwarded_reply = &b_reply_outcome.packets[0].data;

        // Feed forwarded reply to A
        let a_reply_outcome = node_a.handle_ingest(forwarded_reply, 211, 0, &mut rng);

        // -----------------------------------------------------------------
        // Step 9: Verify A receives the return channel message
        // -----------------------------------------------------------------
        match a_reply_outcome.event {
            Some(NodeEvent::ChannelMessages {
                link_id: lid,
                messages,
            }) => {
                assert_eq!(lid, link_id);
                assert_eq!(messages.len(), 1);
                assert_eq!(messages[0].0, 0x43, "reply message_type should be 0x43");
                assert_eq!(messages[0].1, b"relay-reply", "reply payload mismatch");
            }
            other => panic!("A expected ChannelMessages for reply, got {:?}", other),
        }
    }

    /// Reverse direction: C initiates link to A through relay B.
    /// Verifies both link initiation directions work through a relay.
    #[test]
    fn test_channel_through_relay_reverse() {
        let mut rng = rand::thread_rng();

        // C = initiator, B = transport relay, A = responder
        let mut node_a = make_core(b"rev-relay-a");
        let mut node_b = make_core(b"rev-relay-b");
        let mut node_c = make_core(b"rev-relay-c");

        node_b.enable_transport();

        // C knows A's identity and has a path via B
        let id_a = Identity::from_seed(b"rev-relay-a").unwrap();
        let id_b = Identity::from_seed(b"rev-relay-b").unwrap();
        node_c.register_peer(&id_a, "testapp", &["aspect1"], 100);
        let a_dest = *node_a.dest_hash();
        node_c.transport.insert_path(
            a_dest,
            rete_transport::Path::via_repeater(id_b.hash(), 2, 100),
        );

        // B knows A's identity (for LINKREQUEST forwarding)
        node_b.register_peer(&id_a, "testapp", &["aspect1"], 100);

        // --- Handshake: C → B → A → B → C ---

        // C initiates link to A
        let (lr_outbound, link_id) = node_c
            .initiate_link(a_dest, 100, &mut rng)
            .expect("C should produce LINKREQUEST");
        assert_eq!(
            Packet::parse(&lr_outbound.data).unwrap().header_type,
            HeaderType::Header2,
        );

        // B forwards LINKREQUEST
        let b_out = node_b.handle_ingest(&lr_outbound.data, 100, 0, &mut rng);
        assert!(b_out.event.is_none());
        assert_eq!(b_out.packets.len(), 1);

        // A receives LINKREQUEST → emits LinkEstablished + LRPROOF
        let a_out = node_a.handle_ingest(&b_out.packets[0].data, 101, 1, &mut rng);
        assert!(matches!(
            a_out.event,
            Some(NodeEvent::LinkEstablished { .. })
        ));
        assert!(!a_out.packets.is_empty());

        // B forwards LRPROOF
        let b_proof = node_b.handle_ingest(&a_out.packets[0].data, 102, 1, &mut rng);
        assert_eq!(b_proof.packets.len(), 1);

        // C receives LRPROOF → LinkEstablished + sends LRRTT
        let c_proof = node_c.handle_ingest(&b_proof.packets[0].data, 103, 0, &mut rng);
        assert!(matches!(
            c_proof.event,
            Some(NodeEvent::LinkEstablished { .. })
        ));
        let lrrtt_pkt = c_proof
            .packets
            .iter()
            .find(|p| {
                rete_core::Packet::parse(&p.data)
                    .map(|pkt| pkt.context == rete_core::CONTEXT_LRRTT)
                    .unwrap_or(false)
            })
            .expect("C should auto-send LRRTT");

        // B forwards LRRTT
        let b_rtt = node_b.handle_ingest(&lrrtt_pkt.data, 104, 0, &mut rng);
        assert_eq!(b_rtt.packets.len(), 1);

        // A receives LRRTT → link activated
        let a_rtt = node_a.handle_ingest(&b_rtt.packets[0].data, 105, 1, &mut rng);
        assert!(matches!(
            a_rtt.event,
            Some(NodeEvent::LinkEstablished { .. })
        ));

        // Verify both links Active
        assert_eq!(
            node_c.transport.get_link(&link_id).unwrap().state,
            rete_transport::LinkState::Active
        );
        assert_eq!(
            node_a.transport.get_link(&link_id).unwrap().state,
            rete_transport::LinkState::Active
        );

        // --- Channel message: C → B → A ---
        let c_msg = node_c
            .send_channel_message(&link_id, 0x42, b"reverse-relay-msg", 200, &mut rng)
            .expect("C should send channel message");
        let b_fwd = node_b.handle_ingest(&c_msg.data, 200, 0, &mut rng);
        assert_eq!(b_fwd.packets.len(), 1);
        let a_recv = node_a.handle_ingest(&b_fwd.packets[0].data, 201, 1, &mut rng);
        match a_recv.event {
            Some(NodeEvent::ChannelMessages { messages, .. }) => {
                assert_eq!(messages[0].0, 0x42);
                assert_eq!(messages[0].1, b"reverse-relay-msg");
            }
            other => panic!("A expected ChannelMessages, got {:?}", other),
        }

        // --- Channel reply: A → B → C ---
        let a_reply = node_a
            .send_channel_message(&link_id, 0x43, b"reverse-reply", 210, &mut rng)
            .expect("A should reply");
        let b_fwd2 = node_b.handle_ingest(&a_reply.data, 210, 1, &mut rng);
        assert_eq!(b_fwd2.packets.len(), 1);
        let c_recv = node_c.handle_ingest(&b_fwd2.packets[0].data, 211, 0, &mut rng);
        match c_recv.event {
            Some(NodeEvent::ChannelMessages { messages, .. }) => {
                assert_eq!(messages[0].0, 0x43);
                assert_eq!(messages[0].1, b"reverse-reply");
            }
            other => panic!("C expected ChannelMessages for reply, got {:?}", other),
        }
    }
}
