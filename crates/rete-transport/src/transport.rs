//! Core Transport struct — path table, announce queue, packet processing, links.

use crate::announce::validate_announce;
use crate::link::{compute_link_id, Link};
use crate::receipt::ReceiptTable;
use crate::{announce::PendingAnnounce, dedup::DedupWindow, path::Path};
use heapless::{FnvIndexMap, FnvIndexSet};
use rand_core::{CryptoRng, RngCore};
use crate::link::LINK_MDU;
use crate::resource::Resource;
use rete_core::{
    DestType, HeaderType, Identity, Packet, PacketBuilder, PacketType, CONTEXT_CHANNEL,
    CONTEXT_KEEPALIVE, CONTEXT_LINKCLOSE, CONTEXT_LRPROOF, CONTEXT_LRRTT, CONTEXT_RESOURCE,
    CONTEXT_RESOURCE_ADV, CONTEXT_RESOURCE_HMU, CONTEXT_RESOURCE_ICL, CONTEXT_RESOURCE_PRF,
    CONTEXT_RESOURCE_RCL, CONTEXT_RESOURCE_REQ, NAME_HASH_LEN, TRUNCATED_HASH_LEN,
};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Protocol constants (from Python Transport.py)
// ---------------------------------------------------------------------------

/// Announce retransmission delay base (seconds).
pub const PATHFINDER_G: u64 = 5;

/// Maximum retransmission count per announce.
pub const PATHFINDER_R: u8 = 1;

/// Maximum hop count for announce retransmission.
pub const PATHFINDER_M: u8 = 128;

/// Path expiry time in seconds (7 days).
pub const PATH_EXPIRES: u64 = 604800;

/// Reverse table entry timeout in seconds (8 minutes).
pub const REVERSE_TIMEOUT: u64 = 480;

/// Default receipt proof timeout in seconds.
pub const RECEIPT_TIMEOUT: u64 = 30;

/// A receipt for a channel message awaiting proof-of-delivery.
#[derive(Debug, Clone)]
pub struct ChannelReceipt {
    /// Link the channel message was sent on.
    pub link_id: [u8; TRUNCATED_HASH_LEN],
    /// Sequence number in the channel.
    pub sequence: u16,
    /// Monotonic timestamp when sent.
    pub sent_at: u64,
}

/// Destination hash for `rnstransport.path.request` (PLAIN, no identity).
///
/// Precomputed: `destination_hash("rnstransport.path.request", None)`.
pub const PATH_REQUEST_DEST: [u8; TRUNCATED_HASH_LEN] = [
    0x6b, 0x9f, 0x66, 0x01, 0x4d, 0x98, 0x53, 0xfa, 0xab, 0x22, 0x0f, 0xba, 0x47, 0xd0, 0x27, 0x61,
];

// ---------------------------------------------------------------------------
// ReverseEntry — tracks forwarded packets for reply routing
// ---------------------------------------------------------------------------

/// An entry in the reverse table, keyed by truncated packet hash.
///
/// Used to route replies back along the path the original packet traversed.
#[derive(Debug, Clone)]
pub struct ReverseEntry {
    /// Monotonic timestamp when this entry was created.
    pub timestamp: u64,
    /// Interface index the original packet was received on.
    pub received_on: u8,
    /// Interface index the packet was forwarded to (0 for broadcast).
    pub forwarded_to: u8,
}

// ---------------------------------------------------------------------------
// IngestResult — what to do after processing an inbound packet
// ---------------------------------------------------------------------------

/// Result of processing an inbound packet via [`Transport::ingest`].
#[derive(Debug)]
pub enum IngestResult<'a> {
    /// Data packet addressed to one of our destinations.
    LocalData {
        /// Destination hash the packet was addressed to.
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        /// Payload data.
        payload: &'a [u8],
        /// Full 32-byte packet hash (for proof generation).
        packet_hash: [u8; 32],
    },
    /// A valid announce was received and its path has been learned.
    AnnounceReceived {
        /// Destination hash of the announcing identity.
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        /// Identity hash of the announcer.
        identity_hash: [u8; TRUNCATED_HASH_LEN],
        /// Hop count at time of receipt.
        hops: u8,
        /// Optional application data from the announce.
        app_data: Option<&'a [u8]>,
    },
    /// Packet should be forwarded to other interfaces.
    Forward {
        /// Raw packet bytes (with hops incremented).
        raw: &'a [u8],
        /// Interface index the packet was received on (for exclusion).
        source_iface: u8,
    },
    /// A LINKREQUEST was received for one of our destinations.
    LinkRequestReceived {
        /// The computed link_id (16 bytes).
        link_id: [u8; TRUNCATED_HASH_LEN],
        /// The LRPROOF response to send back (raw packet bytes, owned).
        proof_raw: alloc::vec::Vec<u8>,
    },
    /// A link handshake completed (LRPROOF validated or LRRTT processed).
    LinkEstablished {
        /// The link_id.
        link_id: [u8; TRUNCATED_HASH_LEN],
    },
    /// Decrypted data received on an active link.
    LinkData {
        /// The link_id.
        link_id: [u8; TRUNCATED_HASH_LEN],
        /// Decrypted payload data (owned).
        data: alloc::vec::Vec<u8>,
        /// The context byte from the packet.
        context: u8,
    },
    /// Channel messages received on a link (reliable ordered delivery).
    ChannelMessages {
        /// The link_id.
        link_id: [u8; TRUNCATED_HASH_LEN],
        /// Delivered channel envelopes.
        messages: alloc::vec::Vec<crate::channel::ChannelEnvelope>,
        /// The packet hash of the DATA packet carrying these channel messages.
        packet_hash: [u8; 32],
    },
    /// A link was closed (teardown or timeout).
    LinkClosed {
        /// The link_id.
        link_id: [u8; TRUNCATED_HASH_LEN],
    },
    /// A proof was received for a packet we sent.
    ProofReceived {
        /// The full 32-byte packet hash the proof covers.
        packet_hash: [u8; 32],
    },
    /// A resource advertisement was received on a link.
    ResourceOffered {
        /// The link_id.
        link_id: [u8; TRUNCATED_HASH_LEN],
        /// Resource hash (truncated to 16 bytes for keying).
        resource_hash: [u8; TRUNCATED_HASH_LEN],
        /// Total size of the resource data.
        total_size: usize,
    },
    /// Resource transfer progress.
    ResourceProgress {
        /// The link_id.
        link_id: [u8; TRUNCATED_HASH_LEN],
        /// Resource hash (truncated to 16 bytes).
        resource_hash: [u8; TRUNCATED_HASH_LEN],
        /// Parts received so far.
        current: usize,
        /// Total parts.
        total: usize,
    },
    /// Resource transfer completed successfully.
    ResourceComplete {
        /// The link_id.
        link_id: [u8; TRUNCATED_HASH_LEN],
        /// Resource hash (truncated to 16 bytes).
        resource_hash: [u8; TRUNCATED_HASH_LEN],
        /// The assembled resource data.
        data: alloc::vec::Vec<u8>,
    },
    /// Resource transfer failed.
    ResourceFailed {
        /// The link_id.
        link_id: [u8; TRUNCATED_HASH_LEN],
        /// Resource hash (truncated to 16 bytes).
        resource_hash: [u8; TRUNCATED_HASH_LEN],
    },
    /// Packet was a duplicate and should be dropped.
    Duplicate,
    /// A channel message was accepted and buffered (out-of-order), not yet deliverable.
    Buffered {
        /// The packet hash of the DATA packet (receiver should prove it).
        packet_hash: [u8; 32],
    },
    /// Packet was malformed or invalid.
    Invalid,
}

// ---------------------------------------------------------------------------
// TickResult — output of periodic maintenance
// ---------------------------------------------------------------------------

/// Result of periodic transport maintenance via [`Transport::tick`].
pub struct TickResult {
    /// Number of paths that were expired and removed.
    pub expired_paths: usize,
    /// Number of links that were closed due to staleness.
    pub closed_links: usize,
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// The Reticulum transport layer — path table, announce queue, dedup window, links.
///
/// Generic over:
/// - `MAX_PATHS`      — max learned destination paths
/// - `MAX_ANNOUNCES`  — max pending outbound announces
/// - `DEDUP_WINDOW`   — duplicate-detection window size
/// - `MAX_LINKS`      — max concurrent link sessions
pub struct Transport<
    const MAX_PATHS: usize,
    const MAX_ANNOUNCES: usize,
    const DEDUP_WINDOW: usize,
    const MAX_LINKS: usize,
> {
    paths: FnvIndexMap<[u8; TRUNCATED_HASH_LEN], Path, MAX_PATHS>,
    announces: heapless::Deque<PendingAnnounce, MAX_ANNOUNCES>,
    dedup: DedupWindow<DEDUP_WINDOW>,
    known_identities: FnvIndexMap<[u8; TRUNCATED_HASH_LEN], [u8; 64], MAX_PATHS>,
    /// Identity hash of this node (enables HEADER_2 forwarding when set).
    local_identity_hash: Option<[u8; TRUNCATED_HASH_LEN]>,
    /// Reverse table: truncated packet hash → entry (for reply routing).
    reverse_table: FnvIndexMap<[u8; TRUNCATED_HASH_LEN], ReverseEntry, MAX_PATHS>,
    /// Dedup window for announce random_hashes (replay detection).
    announce_dedup: DedupWindow<DEDUP_WINDOW>,
    /// Destination hashes registered as local (self-announce filtering).
    local_destinations: FnvIndexSet<[u8; TRUNCATED_HASH_LEN], 8>,
    /// Active link sessions, keyed by link_id.
    links: FnvIndexMap<[u8; TRUNCATED_HASH_LEN], Link, MAX_LINKS>,
    /// Receipts for sent packets, awaiting delivery proofs.
    /// Fixed at 64 entries — receipts are short-lived, not proportional to path count.
    receipts: ReceiptTable<64>,
    /// Receipts for channel messages: truncated packet hash → ChannelReceipt.
    /// Used to match incoming PROOFs to channel sequences and call mark_delivered().
    channel_receipts: FnvIndexMap<[u8; TRUNCATED_HASH_LEN], ChannelReceipt, 64>,
    /// Active resource transfers.
    resources: alloc::vec::Vec<Resource>,
    /// Pending outbound resource packets (parts, HMU, etc.) built during ingest.
    resource_outbound: alloc::vec::Vec<alloc::vec::Vec<u8>>,
}

impl<const P: usize, const A: usize, const D: usize, const L: usize> Default
    for Transport<P, A, D, L>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const P: usize, const A: usize, const D: usize, const L: usize> Transport<P, A, D, L> {
    /// Create a new, empty transport.
    pub const fn new() -> Self {
        Transport {
            paths: FnvIndexMap::new(),
            announces: heapless::Deque::new(),
            dedup: DedupWindow::new(),
            known_identities: FnvIndexMap::new(),
            local_identity_hash: None,
            reverse_table: FnvIndexMap::new(),
            announce_dedup: DedupWindow::new(),
            local_destinations: FnvIndexSet::new(),
            links: FnvIndexMap::new(),
            receipts: ReceiptTable::new(),
            channel_receipts: FnvIndexMap::new(),
            resources: alloc::vec::Vec::new(),
            resource_outbound: alloc::vec::Vec::new(),
        }
    }

    /// Register a destination hash as belonging to this node.
    pub fn add_local_destination(&mut self, dest_hash: [u8; TRUNCATED_HASH_LEN]) {
        let _ = self.local_destinations.insert(dest_hash);
    }

    /// Check whether a destination hash is registered as local.
    pub fn is_local_destination(&self, dest_hash: &[u8; TRUNCATED_HASH_LEN]) -> bool {
        self.local_destinations.contains(dest_hash)
    }

    /// Look up a learned path to `dest`.
    pub fn get_path(&self, dest: &[u8; TRUNCATED_HASH_LEN]) -> Option<&Path> {
        self.paths.get(dest)
    }

    /// Store a learned path. Returns `false` if the path table is full.
    pub fn insert_path(&mut self, dest: [u8; TRUNCATED_HASH_LEN], path: Path) -> bool {
        self.paths.insert(dest, path).is_ok()
    }

    /// Remove a path entry (expiry or explicit reset).
    pub fn remove_path(&mut self, dest: &[u8; TRUNCATED_HASH_LEN]) {
        self.paths.remove(dest);
    }

    /// Check a packet hash for duplicates.
    pub fn is_duplicate(&mut self, hash: &[u8; 32]) -> bool {
        self.dedup.check_and_insert(hash)
    }

    /// Queue an announce for transmission. Returns `false` if queue is full.
    pub fn queue_announce(&mut self, ann: PendingAnnounce) -> bool {
        self.announces.push_back(ann).is_ok()
    }

    /// Pop the next announce ready for transmission.
    pub fn next_announce(&mut self) -> Option<PendingAnnounce> {
        self.announces.pop_front()
    }

    /// Number of known paths.
    pub fn path_count(&self) -> usize {
        self.paths.len()
    }

    /// Number of pending announces.
    pub fn announce_count(&self) -> usize {
        self.announces.len()
    }

    /// Look up a previously announced identity's public key by destination hash.
    pub fn recall_identity(&self, dest: &[u8; TRUNCATED_HASH_LEN]) -> Option<&[u8; 64]> {
        self.known_identities.get(dest)
    }

    /// Pre-register a peer's identity and path (for use with deterministic seeds).
    pub fn register_identity(
        &mut self,
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        pub_key: [u8; 64],
        now: u64,
    ) {
        let _ = self.known_identities.insert(dest_hash, pub_key);
        let _ = self.paths.insert(dest_hash, Path::direct(now));
    }

    /// Set the local identity hash, enabling HEADER_2 forwarding.
    pub fn set_local_identity(&mut self, hash: [u8; TRUNCATED_HASH_LEN]) {
        self.local_identity_hash = Some(hash);
    }

    /// Look up a reverse table entry by truncated packet hash.
    pub fn get_reverse(&self, hash: &[u8; TRUNCATED_HASH_LEN]) -> Option<&ReverseEntry> {
        self.reverse_table.get(hash)
    }

    /// Number of reverse table entries.
    pub fn reverse_count(&self) -> usize {
        self.reverse_table.len()
    }

    /// Look up an active link by link_id.
    pub fn get_link(&self, link_id: &[u8; TRUNCATED_HASH_LEN]) -> Option<&Link> {
        self.links.get(link_id)
    }

    /// Number of active links.
    pub fn link_count(&self) -> usize {
        self.links.len()
    }

    /// Register a receipt for a sent packet.
    pub fn register_receipt(
        &mut self,
        packet_hash: [u8; 32],
        dest_pub_key: [u8; 64],
        now: u64,
        timeout: u64,
    ) -> bool {
        self.receipts
            .register(packet_hash, dest_pub_key, now, timeout)
    }

    /// Number of tracked channel receipts (pending channel ACKs).
    pub fn channel_receipt_count(&self) -> usize {
        self.channel_receipts.len()
    }

    /// Number of tracked receipts.
    pub fn receipt_count(&self) -> usize {
        self.receipts.len()
    }

    // -----------------------------------------------------------------------
    // Link management
    // -----------------------------------------------------------------------

    /// Initiate a link to a destination.
    ///
    /// Returns the raw LINKREQUEST packet and the link_id.
    pub fn initiate_link<R: RngCore + CryptoRng>(
        &mut self,
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        identity: &Identity,
        rng: &mut R,
        now: u64,
    ) -> Option<(alloc::vec::Vec<u8>, [u8; TRUNCATED_HASH_LEN])> {
        let (mut link, request_payload) =
            Link::new_initiator(dest_hash, identity.ed25519_pub(), rng, now);

        // Build LINKREQUEST packet
        let mut pkt_buf = [0u8; rete_core::MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::LinkRequest)
            .dest_type(DestType::Link)
            .destination_hash(&dest_hash)
            .context(0x00)
            .payload(&request_payload)
            .build()
            .ok()?;

        let link_id = compute_link_id(&pkt_buf[..pkt_len]).ok()?;
        link.set_link_id(link_id);

        let _ = self.links.insert(link_id, link);
        Some((pkt_buf[..pkt_len].to_vec(), link_id))
    }

    /// Build an encrypted DATA packet for a link.
    pub fn build_link_data_packet<R: RngCore + CryptoRng>(
        &self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        plaintext: &[u8],
        context: u8,
        rng: &mut R,
    ) -> Option<alloc::vec::Vec<u8>> {
        let link = self.links.get(link_id)?;
        if !link.is_active() {
            return None;
        }
        Self::build_link_packet(link, link_id, plaintext, context, rng)
    }

    /// Build an LRRTT measurement packet for a link (initiator sends after proof).
    pub fn build_lrrtt_packet<R: RngCore + CryptoRng>(
        &self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        rtt_bytes: &[u8],
        rng: &mut R,
    ) -> Option<alloc::vec::Vec<u8>> {
        let link = self.links.get(link_id)?;
        Self::build_link_packet(link, link_id, rtt_bytes, CONTEXT_LRRTT, rng)
    }

    /// Build a keepalive request/response packet for a link.
    pub fn build_keepalive_packet<R: RngCore + CryptoRng>(
        &self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        request: bool,
        rng: &mut R,
    ) -> Option<alloc::vec::Vec<u8>> {
        let link = self.links.get(link_id)?;
        if !link.is_active() {
            return None;
        }
        let payload: &[u8] = if request { &[0xFF] } else { &[0xFE] };
        Self::build_link_packet(link, link_id, payload, CONTEXT_KEEPALIVE, rng)
    }

    /// Encrypt plaintext and build a link DATA packet. Shared by all link packet builders.
    fn build_link_packet<R: RngCore + CryptoRng>(
        link: &Link,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        plaintext: &[u8],
        context: u8,
        rng: &mut R,
    ) -> Option<alloc::vec::Vec<u8>> {
        let mut ct_buf = [0u8; rete_core::MTU];
        let ct_len = link.encrypt(plaintext, rng, &mut ct_buf).ok()?;
        let mut pkt_buf = [0u8; rete_core::MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Link)
            .destination_hash(link_id)
            .context(context)
            .payload(&ct_buf[..ct_len])
            .build()
            .ok()?;
        Some(pkt_buf[..pkt_len].to_vec())
    }

    /// Build a LINKCLOSE packet and remove the link.
    pub fn build_linkclose_packet<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        rng: &mut R,
    ) -> Option<alloc::vec::Vec<u8>> {
        let link = self.links.get(link_id)?;
        let mut close_buf = [0u8; rete_core::MTU];
        let close_len = link.build_close(rng, &mut close_buf).ok()?;

        let mut pkt_buf = [0u8; rete_core::MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Link)
            .destination_hash(link_id)
            .context(CONTEXT_LINKCLOSE)
            .payload(&close_buf[..close_len])
            .build()
            .ok()?;

        self.links.remove(link_id);
        Some(pkt_buf[..pkt_len].to_vec())
    }

    // -----------------------------------------------------------------------
    // Packet ingestion
    // -----------------------------------------------------------------------

    /// Process an inbound raw packet (single-interface convenience wrapper).
    ///
    /// Equivalent to `ingest_on(raw, now, 0, rng, identity)`.
    pub fn ingest<'a, R: RngCore + CryptoRng>(
        &mut self,
        raw: &'a mut [u8],
        now: u64,
        rng: &mut R,
        identity: &Identity,
    ) -> IngestResult<'a> {
        self.ingest_on(raw, now, 0, rng, identity)
    }

    /// Process an inbound raw packet received on interface `iface`.
    ///
    /// Parses the packet, checks for duplicates, and dispatches by type:
    /// - **ANNOUNCE**: validate signature + dest hash, learn path, queue retransmission
    /// - **DATA**: return for local delivery, handle path requests, link data, or forward
    /// - **PROOF**: route via reverse table, validate LRPROOF, or forward
    /// - **LINKREQUEST**: create link if local, else forward
    ///
    /// `now` is the current monotonic time in seconds.
    pub fn ingest_on<'a, R: RngCore + CryptoRng>(
        &mut self,
        raw: &'a mut [u8],
        now: u64,
        iface: u8,
        rng: &mut R,
        identity: &Identity,
    ) -> IngestResult<'a> {
        let len = raw.len();

        // Parse
        let pkt = match Packet::parse(raw) {
            Ok(p) => p,
            Err(_) => return IngestResult::Invalid,
        };

        // Compute packet hash for dedup
        let pkt_hash = pkt.compute_hash();

        // Dedup check
        if self.is_duplicate(&pkt_hash) {
            return IngestResult::Duplicate;
        }

        // Check HEADER_2 forwarding
        if pkt.header_type == HeaderType::Header2 {
            if let Some(local_id) = self.local_identity_hash {
                if let Some(tid) = pkt.transport_id {
                    let mut tid_arr = [0u8; TRUNCATED_HASH_LEN];
                    tid_arr.copy_from_slice(tid);

                    if tid_arr == local_id {
                        let mut dest = [0u8; TRUNCATED_HASH_LEN];
                        dest.copy_from_slice(pkt.destination_hash);

                        raw[1] = raw[1].saturating_add(1);

                        let mut trunc_hash = [0u8; TRUNCATED_HASH_LEN];
                        trunc_hash.copy_from_slice(&pkt_hash[..TRUNCATED_HASH_LEN]);
                        let _ = self.reverse_table.insert(
                            trunc_hash,
                            ReverseEntry {
                                timestamp: now,
                                received_on: iface,
                                forwarded_to: 0,
                            },
                        );

                        return match self.paths.get(&dest) {
                            Some(path) if path.hops > 1 => {
                                if let Some(via) = path.via {
                                    raw[2..18].copy_from_slice(&via);
                                }
                                IngestResult::Forward {
                                    raw: &raw[..len],
                                    source_iface: iface,
                                }
                            }
                            Some(path) if path.hops <= 1 => {
                                let new_flags = raw[0] & 0x0F;
                                raw[0] = new_flags;
                                raw.copy_within(18..len, 2);
                                IngestResult::Forward {
                                    raw: &raw[..len - TRUNCATED_HASH_LEN],
                                    source_iface: iface,
                                }
                            }
                            _ => IngestResult::Invalid,
                        };
                    }
                }
            }
        }

        // Increment hops
        raw[1] = raw[1].saturating_add(1);

        // Re-parse after hops increment
        let pkt = match Packet::parse(raw) {
            Ok(p) => p,
            Err(_) => return IngestResult::Invalid,
        };

        match pkt.packet_type {
            PacketType::Announce => self.handle_announce(&pkt, raw, now),
            PacketType::Data => {
                let mut dh = [0u8; TRUNCATED_HASH_LEN];
                dh.copy_from_slice(pkt.destination_hash);

                // Path request handling
                if self.local_identity_hash.is_some() && dh == PATH_REQUEST_DEST {
                    return self.handle_path_request(pkt.payload, now);
                }

                // Link data handling: dest_type == Link
                if pkt.dest_type == DestType::Link {
                    return self.handle_link_data(&dh, pkt.context, pkt.payload, now, pkt_hash, rng);
                }

                IngestResult::LocalData {
                    dest_hash: dh,
                    payload: pkt.payload,
                    packet_hash: pkt_hash,
                }
            }
            PacketType::Proof => {
                // Check for LRPROOF (link proof from responder to initiator)
                if pkt.context == CONTEXT_LRPROOF && pkt.dest_type == DestType::Link {
                    let mut dh = [0u8; TRUNCATED_HASH_LEN];
                    dh.copy_from_slice(pkt.destination_hash);
                    return self.handle_lrproof(&dh, pkt.payload, now);
                }

                let mut dh = [0u8; TRUNCATED_HASH_LEN];
                dh.copy_from_slice(pkt.destination_hash);

                // Check receipt table for delivery proof (DATA packets)
                if let Some(packet_hash) = self.receipts.validate_proof(&dh, pkt.payload) {
                    return IngestResult::ProofReceived { packet_hash };
                }

                // Check channel receipts for delivery proof (channel messages).
                // build_proof_packet creates explicit proofs: packet_hash[32] || sig[64].
                if pkt.payload.len() >= 96 {
                    if let Some(cr) = self.channel_receipts.get(&dh) {
                        let link_id = cr.link_id;
                        let sequence = cr.sequence;
                        let mut full_hash = [0u8; 32];
                        full_hash.copy_from_slice(&pkt.payload[..32]);
                        let sig = &pkt.payload[32..96];
                        // Verify using the link peer's node identity (not ephemeral keys).
                        // The proof is signed by the peer's Ed25519 identity key.
                        let verified = if let Some(link) = self.links.get(&link_id) {
                            self.known_identities
                                .get(&link.destination_hash)
                                .and_then(|pk| Identity::from_public_key(pk).ok())
                                .map(|id| id.verify(&full_hash, sig).is_ok())
                                .unwrap_or(false)
                        } else {
                            false
                        };
                        if verified {
                            self.channel_receipts.remove(&dh);
                            if let Some(link) = self.links.get_mut(&link_id) {
                                if let Some(channel) = link.channel.as_mut() {
                                    channel.mark_delivered(sequence);
                                }
                            }
                            return IngestResult::ProofReceived {
                                packet_hash: full_hash,
                            };
                        }
                    }
                }

                if self.local_identity_hash.is_some() {
                    if self.reverse_table.remove(&dh).is_some() {
                        IngestResult::Forward {
                            raw,
                            source_iface: iface,
                        }
                    } else {
                        IngestResult::Invalid
                    }
                } else {
                    IngestResult::Forward {
                        raw,
                        source_iface: iface,
                    }
                }
            }
            PacketType::LinkRequest => {
                let mut dh = [0u8; TRUNCATED_HASH_LEN];
                dh.copy_from_slice(pkt.destination_hash);
                if self.is_local_destination(&dh) {
                    self.handle_link_request(raw, &dh, pkt.payload, now, rng, identity)
                } else {
                    IngestResult::Forward {
                        raw,
                        source_iface: iface,
                    }
                }
            }
        }
    }

    fn handle_link_request<'a, R: RngCore + CryptoRng>(
        &mut self,
        raw: &'a [u8],
        dest_hash: &[u8; TRUNCATED_HASH_LEN],
        payload: &[u8],
        now: u64,
        rng: &mut R,
        identity: &Identity,
    ) -> IngestResult<'a> {
        let link_id = match compute_link_id(raw) {
            Ok(id) => id,
            Err(_) => return IngestResult::Invalid,
        };

        // Check for duplicate link request
        if self.links.contains_key(&link_id) {
            return IngestResult::Duplicate;
        }

        let mut link = match Link::from_request(link_id, payload, rng, now) {
            Ok(l) => l,
            Err(_) => return IngestResult::Invalid,
        };
        link.destination_hash = *dest_hash;

        // Build LRPROOF
        let proof_payload = match link.build_proof(identity) {
            Ok(p) => p,
            Err(_) => return IngestResult::Invalid,
        };

        // Build LRPROOF packet: Proof type, Link dest_type, dest=link_id, context=LRPROOF
        let mut proof_buf = [0u8; rete_core::MTU];
        let proof_len = match PacketBuilder::new(&mut proof_buf)
            .packet_type(PacketType::Proof)
            .dest_type(DestType::Link)
            .destination_hash(&link_id)
            .context(CONTEXT_LRPROOF)
            .payload(&proof_payload)
            .build()
        {
            Ok(n) => n,
            Err(_) => return IngestResult::Invalid,
        };

        let _ = self.links.insert(link_id, link);

        IngestResult::LinkRequestReceived {
            link_id,
            proof_raw: proof_buf[..proof_len].to_vec(),
        }
    }

    fn handle_lrproof<'a>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        proof_payload: &[u8],
        now: u64,
    ) -> IngestResult<'a> {
        // Look up the initiator link
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return IngestResult::Invalid,
        };

        // Need the destination identity to verify the proof
        let dest_hash = link.destination_hash;
        let pub_key = match self.known_identities.get(&dest_hash) {
            Some(pk) => *pk,
            None => return IngestResult::Invalid,
        };

        let dest_identity = match Identity::from_public_key(&pub_key) {
            Ok(id) => id,
            Err(_) => return IngestResult::Invalid,
        };

        if link.validate_proof(proof_payload, &dest_identity).is_err() {
            return IngestResult::Invalid;
        }

        // Initiator activates after proof validation (will send LRRTT next)
        link.activate(now);

        IngestResult::LinkEstablished { link_id: *link_id }
    }

    fn handle_link_data<'a, R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        context: u8,
        ciphertext: &[u8],
        now: u64,
        pkt_hash: [u8; 32],
        rng: &mut R,
    ) -> IngestResult<'a> {
        // For resource contexts, decrypt first in a sub-scope to release the link
        // borrow, then handle resources using self.resources separately.
        if matches!(
            context,
            CONTEXT_RESOURCE
                | CONTEXT_RESOURCE_ADV
                | CONTEXT_RESOURCE_REQ
                | CONTEXT_RESOURCE_HMU
                | CONTEXT_RESOURCE_PRF
                | CONTEXT_RESOURCE_ICL
                | CONTEXT_RESOURCE_RCL
        ) {
            // CONTEXT_RESOURCE (0x01) data parts are NOT link-encrypted in Python RNS.
            // The resource handles its own encryption. All other resource contexts
            // (ADV, REQ, HMU, PRF, ICL, RCL) ARE link-encrypted.
            if context == CONTEXT_RESOURCE {
                // Pass raw ciphertext payload directly (no link decryption).
                // Still need to verify link is active and touch inbound.
                {
                    let link = match self.links.get_mut(link_id) {
                        Some(l) => l,
                        None => return IngestResult::Invalid,
                    };
                    if !link.is_active() {
                        return IngestResult::Invalid;
                    }
                    link.touch_inbound(now);
                }
                return self.handle_resource_data(link_id, context, ciphertext, now, rng);
            }

            let mut dec_buf = [0u8; rete_core::MTU];
            let dec_len = {
                let link = match self.links.get_mut(link_id) {
                    Some(l) => l,
                    None => return IngestResult::Invalid,
                };
                if !link.is_active() {
                    return IngestResult::Invalid;
                }
                link.touch_inbound(now);
                match link.decrypt(ciphertext, &mut dec_buf) {
                    Ok(n) => n,
                    Err(_) => return IngestResult::Invalid,
                }
            };
            // self.links borrow is released. Now we can use self.resources.
            return self.handle_resource_data(link_id, context, &dec_buf[..dec_len], now, rng);
        }

        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return IngestResult::Invalid,
        };

        // Decrypt payload into stack buffer (heap alloc deferred to branches that need it)
        let mut dec_buf = [0u8; rete_core::MTU];
        let dec_len = match link.decrypt(ciphertext, &mut dec_buf) {
            Ok(n) => n,
            Err(_) => return IngestResult::Invalid,
        };

        match context {
            CONTEXT_LRRTT => {
                // RTT measurement — activates responder link (no data needed)
                link.activate(now);
                IngestResult::LinkEstablished { link_id: *link_id }
            }
            CONTEXT_KEEPALIVE => {
                if let Some(response_byte) = link.handle_keepalive(&dec_buf[..dec_len], now) {
                    IngestResult::LinkData {
                        link_id: *link_id,
                        data: alloc::vec![response_byte],
                        context: CONTEXT_KEEPALIVE,
                    }
                } else {
                    IngestResult::Duplicate
                }
            }
            CONTEXT_LINKCLOSE => {
                let lid = *link_id;
                if link.handle_close(&dec_buf[..dec_len]) {
                    self.links.remove(&lid);
                    IngestResult::LinkClosed { link_id: lid }
                } else {
                    IngestResult::Invalid
                }
            }
            CONTEXT_CHANNEL => {
                if !link.is_active() {
                    return IngestResult::Invalid;
                }
                link.touch_inbound(now);
                // Lazy-init channel
                let channel = link
                    .channel
                    .get_or_insert_with(crate::channel::Channel::new);
                channel.receive(&dec_buf[..dec_len]);
                let mut messages = alloc::vec::Vec::new();
                while let Some(env) = channel.next_received() {
                    messages.push(env);
                }
                if messages.is_empty() {
                    IngestResult::Buffered {
                        packet_hash: pkt_hash,
                    }
                } else {
                    IngestResult::ChannelMessages {
                        link_id: *link_id,
                        messages,
                        packet_hash: pkt_hash,
                    }
                }
            }
            _ => {
                // Regular link data — only this branch allocates
                if !link.is_active() {
                    return IngestResult::Invalid;
                }
                link.touch_inbound(now);
                IngestResult::LinkData {
                    link_id: *link_id,
                    data: dec_buf[..dec_len].to_vec(),
                    context,
                }
            }
        }
    }

    fn handle_resource_data<'a, R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        context: u8,
        decrypted: &[u8],
        _now: u64,
        _rng: &mut R,
    ) -> IngestResult<'a> {
        match context {
            CONTEXT_RESOURCE => {
                // A resource data part
                if let Some(res) = self
                    .resources
                    .iter_mut()
                    .find(|r| !r.is_sender && r.link_id == *link_id)
                {
                    let all_received = res.receive_part(decrypted);
                    let mut rh = [0u8; TRUNCATED_HASH_LEN];
                    rh.copy_from_slice(&res.resource_hash[..TRUNCATED_HASH_LEN]);
                    if all_received {
                        IngestResult::ResourceProgress {
                            link_id: *link_id,
                            resource_hash: rh,
                            current: res.total_segments,
                            total: res.total_segments,
                        }
                    } else {
                        let received_count = res.received.iter().filter(|&&r| r).count();
                        IngestResult::ResourceProgress {
                            link_id: *link_id,
                            resource_hash: rh,
                            current: received_count,
                            total: res.total_segments,
                        }
                    }
                } else {
                    IngestResult::Invalid
                }
            }
            CONTEXT_RESOURCE_ADV => {
                // Resource advertisement from sender
                match Resource::from_advertisement(decrypted, *link_id) {
                    Ok(res) => {
                        let mut rh = [0u8; TRUNCATED_HASH_LEN];
                        rh.copy_from_slice(&res.resource_hash[..TRUNCATED_HASH_LEN]);
                        let total_size = res.total_size;
                        self.resources.push(res);
                        IngestResult::ResourceOffered {
                            link_id: *link_id,
                            resource_hash: rh,
                            total_size,
                        }
                    }
                    Err(_) => IngestResult::Invalid,
                }
            }
            CONTEXT_RESOURCE_REQ => {
                // Resource request from receiver (we are sender).
                // Get the parts to send, then encrypt each via the link.
                let parts_to_send = {
                    if let Some(res) = self
                        .resources
                        .iter_mut()
                        .find(|r| r.is_sender && r.link_id == *link_id)
                    {
                        res.handle_request(decrypted)
                    } else {
                        return IngestResult::Invalid;
                    }
                };
                // resources borrow released. Send parts as CONTEXT_RESOURCE.
                // IMPORTANT: CONTEXT_RESOURCE parts are NOT link-encrypted in Python RNS.
                // The resource data segments go on the wire as raw payload.
                for (_idx, part_data) in parts_to_send {
                    let mut pkt_buf = [0u8; rete_core::MTU];
                    if let Ok(pkt_len) = PacketBuilder::new(&mut pkt_buf)
                        .packet_type(PacketType::Data)
                        .dest_type(DestType::Link)
                        .destination_hash(link_id)
                        .context(CONTEXT_RESOURCE)
                        .payload(&part_data)
                        .build()
                    {
                        self.resource_outbound.push(pkt_buf[..pkt_len].to_vec());
                    }
                }
                IngestResult::Duplicate // Parts queued in resource_outbound
            }
            CONTEXT_RESOURCE_HMU => {
                // Hashmap update from sender
                if let Some(res) = self
                    .resources
                    .iter_mut()
                    .find(|r| !r.is_sender && r.link_id == *link_id)
                {
                    let _ = res.apply_hashmap_update(decrypted);
                }
                IngestResult::Duplicate
            }
            CONTEXT_RESOURCE_PRF => {
                // Resource proof from receiver (we are sender)
                if let Some(res) = self
                    .resources
                    .iter_mut()
                    .find(|r| r.is_sender && r.link_id == *link_id)
                {
                    let mut rh = [0u8; TRUNCATED_HASH_LEN];
                    rh.copy_from_slice(&res.resource_hash[..TRUNCATED_HASH_LEN]);
                    if res.handle_proof(decrypted) {
                        IngestResult::ResourceComplete {
                            link_id: *link_id,
                            resource_hash: rh,
                            data: alloc::vec::Vec::new(), // sender doesn't return data
                        }
                    } else {
                        IngestResult::ResourceFailed {
                            link_id: *link_id,
                            resource_hash: rh,
                        }
                    }
                } else {
                    IngestResult::Invalid
                }
            }
            CONTEXT_RESOURCE_ICL | CONTEXT_RESOURCE_RCL => {
                // Cancel from either side
                if let Some(res) = self
                    .resources
                    .iter_mut()
                    .find(|r| r.link_id == *link_id)
                {
                    res.handle_cancel();
                    let mut rh = [0u8; TRUNCATED_HASH_LEN];
                    rh.copy_from_slice(&res.resource_hash[..TRUNCATED_HASH_LEN]);
                    IngestResult::ResourceFailed {
                        link_id: *link_id,
                        resource_hash: rh,
                    }
                } else {
                    IngestResult::Duplicate
                }
            }
            _ => IngestResult::Invalid,
        }
    }

    fn handle_announce<'a>(
        &mut self,
        pkt: &Packet<'a>,
        raw: &'a [u8],
        now: u64,
    ) -> IngestResult<'a> {
        // Self-announce filtering
        let mut dh_check = [0u8; TRUNCATED_HASH_LEN];
        dh_check.copy_from_slice(pkt.destination_hash);
        if self.is_local_destination(&dh_check) {
            return IngestResult::Duplicate;
        }

        match validate_announce(pkt.destination_hash, pkt.payload) {
            Ok(info) => {
                // Announce replay detection
                let mut replay_key = [0u8; 32];
                replay_key[..TRUNCATED_HASH_LEN].copy_from_slice(pkt.destination_hash);
                replay_key[TRUNCATED_HASH_LEN..TRUNCATED_HASH_LEN + 10]
                    .copy_from_slice(info.random_hash);
                let replay_hash: [u8; 32] = Sha256::digest(replay_key).into();
                if self.announce_dedup.check_and_insert(&replay_hash) {
                    return IngestResult::Duplicate;
                }
                let mut dh = [0u8; TRUNCATED_HASH_LEN];
                dh.copy_from_slice(pkt.destination_hash);

                let should_update = match self.paths.get(&dh) {
                    None => true,
                    Some(existing) => {
                        pkt.hops <= existing.hops
                            || now.saturating_sub(existing.learned_at) > PATH_EXPIRES
                    }
                };

                if should_update {
                    let mut path = match pkt.transport_id {
                        Some(tid) => {
                            let mut via = [0u8; TRUNCATED_HASH_LEN];
                            via.copy_from_slice(tid);
                            Path::via_repeater(via, pkt.hops, now)
                        }
                        None => Path {
                            hops: pkt.hops,
                            ..Path::direct(now)
                        },
                    };
                    path.announce_raw = Some(raw.to_vec());
                    let _ = self.insert_path(dh, path);
                }

                let mut pk = [0u8; 64];
                pk.copy_from_slice(info.pub_key);
                let _ = self.known_identities.insert(dh, pk);

                if pkt.hops < PATHFINDER_M {
                    let retransmit_raw = if let Some(local_id) = self.local_identity_hash {
                        let mut rebuild_buf = [0u8; rete_core::MTU];
                        let result = PacketBuilder::new(&mut rebuild_buf)
                            .header_type(HeaderType::Header2)
                            .transport_type(1)
                            .packet_type(pkt.packet_type)
                            .dest_type(pkt.dest_type)
                            .hops(pkt.hops)
                            .transport_id(&local_id)
                            .destination_hash(pkt.destination_hash)
                            .context(pkt.context)
                            .payload(pkt.payload)
                            .build();
                        match result {
                            Ok(n) => {
                                let mut v = heapless::Vec::new();
                                let _ = v.extend_from_slice(&rebuild_buf[..n]);
                                Some(v)
                            }
                            Err(_) => None,
                        }
                    } else {
                        None
                    };

                    let ann_raw = match retransmit_raw {
                        Some(v) => v,
                        None => {
                            let mut v = heapless::Vec::new();
                            let _ = v.extend_from_slice(raw);
                            v
                        }
                    };

                    if !ann_raw.is_empty() {
                        let pending = PendingAnnounce {
                            dest_hash: dh,
                            raw: ann_raw,
                            tx_count: 0,
                            last_tx_at: 0,
                            local: false,
                        };
                        let _ = self.queue_announce(pending);
                    }
                }

                IngestResult::AnnounceReceived {
                    dest_hash: dh,
                    identity_hash: info.identity_hash,
                    hops: pkt.hops,
                    app_data: info.app_data,
                }
            }
            Err(_) => IngestResult::Invalid,
        }
    }

    fn handle_path_request<'a>(&mut self, payload: &[u8], _now: u64) -> IngestResult<'a> {
        if payload.len() < TRUNCATED_HASH_LEN {
            return IngestResult::Invalid;
        }
        let mut requested = [0u8; TRUNCATED_HASH_LEN];
        requested.copy_from_slice(&payload[..TRUNCATED_HASH_LEN]);

        if let Some(path) = self.paths.get(&requested) {
            if let Some(ref cached) = path.announce_raw {
                let mut raw = heapless::Vec::new();
                if raw.extend_from_slice(cached).is_ok() {
                    let pending = PendingAnnounce {
                        dest_hash: requested,
                        raw,
                        tx_count: 0,
                        last_tx_at: 0,
                        local: true,
                    };
                    let _ = self.queue_announce(pending);
                }
            }
        }

        IngestResult::Duplicate
    }

    // -----------------------------------------------------------------------
    // Channel message send
    // -----------------------------------------------------------------------

    /// Send a channel message on a link.
    ///
    /// Lazy-inits the channel, enqueues the message, encrypts it, and returns
    /// the raw packet bytes. Returns `None` if the link is not active or the
    /// channel window is full.
    pub fn send_channel_message<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        message_type: u16,
        payload: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Option<alloc::vec::Vec<u8>> {
        let link = self.links.get_mut(link_id)?;
        if !link.is_active() {
            return None;
        }
        let channel = link
            .channel
            .get_or_insert_with(crate::channel::Channel::new);
        let sequence = channel.next_tx_sequence();
        let envelope_bytes = channel.send(message_type, payload)?;
        channel.mark_sent(now);
        link.last_outbound = now;
        let raw = Self::build_link_packet(link, link_id, &envelope_bytes, CONTEXT_CHANNEL, rng)?;

        // Register channel receipt: parse the built packet to get its hash
        if let Ok(parsed) = Packet::parse(&raw) {
            let pkt_hash = parsed.compute_hash();
            let mut trunc = [0u8; TRUNCATED_HASH_LEN];
            trunc.copy_from_slice(&pkt_hash[..TRUNCATED_HASH_LEN]);
            let _ = self.channel_receipts.insert(
                trunc,
                ChannelReceipt {
                    link_id: *link_id,
                    sequence,
                    sent_at: now,
                },
            );
        }

        Some(raw)
    }

    // -----------------------------------------------------------------------
    // Channel retransmission
    // -----------------------------------------------------------------------

    /// Build retransmit packets for all channels that have timed-out messages.
    ///
    /// Also checks for channel teardown (max retries exceeded) and closes
    /// the associated link.
    pub fn pending_channel_retransmits<R: RngCore + CryptoRng>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        let mut packets = alloc::vec::Vec::new();
        let mut teardown_links = heapless::Vec::<[u8; TRUNCATED_HASH_LEN], L>::new();

        // Collect link_ids with channels first (heapless to avoid heap alloc on MCU)
        let mut link_ids = heapless::Vec::<[u8; TRUNCATED_HASH_LEN], L>::new();
        for (lid, l) in self.links.iter() {
            if l.channel.is_some() && l.is_active() {
                let _ = link_ids.push(*lid);
            }
        }

        for lid in link_ids {
            let link = match self.links.get_mut(&lid) {
                Some(l) => l,
                None => continue,
            };
            let channel = match link.channel.as_mut() {
                Some(c) => c,
                None => continue,
            };
            let retransmits = channel.pending_retransmit(now);
            if channel.teardown {
                let _ = teardown_links.push(lid);
                continue;
            }
            for envelope_bytes in retransmits {
                if let Some(pkt) =
                    Self::build_link_packet(link, &lid, &envelope_bytes, CONTEXT_CHANNEL, rng)
                {
                    packets.push(pkt);
                }
            }
        }

        // Close links that hit max retries
        for lid in teardown_links {
            self.links.remove(&lid);
        }

        packets
    }

    // -----------------------------------------------------------------------
    // Keepalive generation
    // -----------------------------------------------------------------------

    /// Build keepalive request packets for links that need them.
    ///
    /// Iterates active links and generates a keepalive request for each
    /// that has been idle for more than half the keepalive interval.
    /// Updates `last_outbound` on each link that gets a keepalive.
    pub fn build_pending_keepalives<R: RngCore + CryptoRng>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        // Collect link_ids that need keepalive first (heapless to avoid heap alloc on MCU)
        let mut need_ka = heapless::Vec::<[u8; TRUNCATED_HASH_LEN], L>::new();
        for (lid, link) in self.links.iter() {
            if link.needs_keepalive(now) {
                let _ = need_ka.push(*lid);
            }
        }

        let mut packets = alloc::vec::Vec::new();
        for lid in need_ka {
            if let Some(pkt) = self.build_keepalive_packet(&lid, true, rng) {
                if let Some(link) = self.links.get_mut(&lid) {
                    link.last_outbound = now;
                }
                packets.push(pkt);
            }
        }
        packets
    }

    // -----------------------------------------------------------------------
    // Proof packet construction
    // -----------------------------------------------------------------------

    /// Build a PROOF packet for a received data packet.
    pub fn build_proof_packet(
        identity: &Identity,
        packet_hash: &[u8; 32],
    ) -> Option<alloc::vec::Vec<u8>> {
        let signature = identity.sign(packet_hash).ok()?;
        let mut payload = [0u8; 96];
        payload[..32].copy_from_slice(packet_hash);
        payload[32..96].copy_from_slice(&signature);

        let trunc: [u8; TRUNCATED_HASH_LEN] = packet_hash[..TRUNCATED_HASH_LEN].try_into().ok()?;

        let mut buf = [0u8; rete_core::MTU];
        let n = PacketBuilder::new(&mut buf)
            .packet_type(PacketType::Proof)
            .dest_type(DestType::Single)
            .destination_hash(&trunc)
            .context(0x00)
            .payload(&payload)
            .build()
            .ok()?;
        Some(buf[..n].to_vec())
    }

    // -----------------------------------------------------------------------
    // Path request origination
    // -----------------------------------------------------------------------

    /// Build a path request packet for a destination.
    ///
    /// Sends a DATA packet addressed to `PATH_REQUEST_DEST` (PLAIN) with
    /// `dest_hash` as the payload.
    pub fn build_path_request(dest_hash: &[u8; TRUNCATED_HASH_LEN]) -> alloc::vec::Vec<u8> {
        let mut buf = [0u8; rete_core::MTU];
        let n = PacketBuilder::new(&mut buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Plain)
            .destination_hash(&PATH_REQUEST_DEST)
            .context(0x00)
            .payload(dest_hash)
            .build()
            .expect("path request packet should always build");
        buf[..n].to_vec()
    }

    // -----------------------------------------------------------------------
    // Announce creation
    // -----------------------------------------------------------------------

    /// Create an announce packet for a local identity.
    pub fn create_announce<R: RngCore + CryptoRng>(
        identity: &Identity,
        app_name: &str,
        aspects: &[&str],
        app_data: Option<&[u8]>,
        rng: &mut R,
        now: u64,
        out: &mut [u8],
    ) -> Result<usize, rete_core::Error> {
        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name(app_name, aspects, &mut name_buf)?;

        let identity_hash = identity.hash();
        let dest_hash = rete_core::destination_hash(expanded, Some(&identity_hash));

        let name_digest = Sha256::digest(expanded.as_bytes());
        let mut name_hash = [0u8; NAME_HASH_LEN];
        name_hash.copy_from_slice(&name_digest[..NAME_HASH_LEN]);

        let mut random_hash = [0u8; 10];
        rng.fill_bytes(&mut random_hash[..5]);
        random_hash[5..10].copy_from_slice(&now.to_be_bytes()[3..8]);

        let pub_key = identity.public_key();
        let mut signed_data = [0u8; rete_core::MTU];
        let mut pos = 0;
        signed_data[pos..pos + TRUNCATED_HASH_LEN].copy_from_slice(&dest_hash);
        pos += TRUNCATED_HASH_LEN;
        signed_data[pos..pos + 64].copy_from_slice(&pub_key);
        pos += 64;
        signed_data[pos..pos + NAME_HASH_LEN].copy_from_slice(&name_hash);
        pos += NAME_HASH_LEN;
        signed_data[pos..pos + 10].copy_from_slice(&random_hash);
        pos += 10;
        if let Some(ad) = app_data {
            signed_data[pos..pos + ad.len()].copy_from_slice(ad);
            pos += ad.len();
        }

        let signature = identity.sign(&signed_data[..pos])?;

        let mut payload = [0u8; rete_core::MTU];
        let mut ppos = 0;
        payload[ppos..ppos + 64].copy_from_slice(&pub_key);
        ppos += 64;
        payload[ppos..ppos + NAME_HASH_LEN].copy_from_slice(&name_hash);
        ppos += NAME_HASH_LEN;
        payload[ppos..ppos + 10].copy_from_slice(&random_hash);
        ppos += 10;
        payload[ppos..ppos + 64].copy_from_slice(&signature);
        ppos += 64;
        if let Some(ad) = app_data {
            payload[ppos..ppos + ad.len()].copy_from_slice(ad);
            ppos += ad.len();
        }

        let n = PacketBuilder::new(out)
            .packet_type(PacketType::Announce)
            .dest_type(DestType::Single)
            .destination_hash(&dest_hash)
            .context(0x00)
            .payload(&payload[..ppos])
            .build()?;

        Ok(n)
    }

    // -----------------------------------------------------------------------
    // Resource management
    // -----------------------------------------------------------------------

    /// Start a new outbound resource transfer on a link.
    ///
    /// Returns the advertisement payload as raw packet bytes.
    pub fn start_resource<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        data: &[u8],
        rng: &mut R,
    ) -> Option<alloc::vec::Vec<u8>> {
        // Check link is active (immutable borrow scope)
        {
            let link = self.links.get(link_id)?;
            if !link.is_active() {
                return None;
            }
        }

        let mut resource = Resource::new_outbound(data, *link_id, LINK_MDU, rng);
        let adv = resource.build_advertisement();

        // Encrypt advertisement and build packet
        let link = self.links.get(link_id)?;
        let mut ct_buf = [0u8; rete_core::MTU];
        let ct_len = link.encrypt(&adv, rng, &mut ct_buf).ok()?;

        let mut pkt_buf = [0u8; rete_core::MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Link)
            .destination_hash(link_id)
            .context(CONTEXT_RESOURCE_ADV)
            .payload(&ct_buf[..ct_len])
            .build()
            .ok()?;

        self.resources.push(resource);
        Some(pkt_buf[..pkt_len].to_vec())
    }

    /// Accept a resource offer and build the first request.
    ///
    /// Returns the encrypted RESOURCE_REQ packet.
    pub fn accept_resource<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        resource_hash: &[u8; TRUNCATED_HASH_LEN],
        rng: &mut R,
    ) -> Option<alloc::vec::Vec<u8>> {
        let req = {
            let res = self.resources.iter().find(|r| {
                !r.is_sender
                    && r.link_id == *link_id
                    && r.resource_hash[..TRUNCATED_HASH_LEN] == *resource_hash
            })?;
            res.build_request()
        };

        let link = self.links.get(link_id)?;
        let mut ct_buf = [0u8; rete_core::MTU];
        let ct_len = link.encrypt(&req, rng, &mut ct_buf).ok()?;

        let mut pkt_buf = [0u8; rete_core::MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Link)
            .destination_hash(link_id)
            .context(CONTEXT_RESOURCE_REQ)
            .payload(&ct_buf[..ct_len])
            .build()
            .ok()?;

        Some(pkt_buf[..pkt_len].to_vec())
    }

    /// Drain pending resource outbound packets.
    pub fn drain_resource_outbound(&mut self) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        core::mem::take(&mut self.resource_outbound)
    }

    /// Get a resource by its truncated hash and link.
    pub fn get_resource(
        &self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        resource_hash: &[u8; TRUNCATED_HASH_LEN],
    ) -> Option<&Resource> {
        self.resources.iter().find(|r| {
            r.link_id == *link_id && r.resource_hash[..TRUNCATED_HASH_LEN] == *resource_hash
        })
    }

    /// Get a mutable resource by its truncated hash and link.
    pub fn get_resource_mut(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        resource_hash: &[u8; TRUNCATED_HASH_LEN],
    ) -> Option<&mut Resource> {
        self.resources.iter_mut().find(|r| {
            r.link_id == *link_id && r.resource_hash[..TRUNCATED_HASH_LEN] == *resource_hash
        })
    }

    /// Remove completed or failed resources.
    pub fn cleanup_resources(&mut self) {
        self.resources.retain(|r| {
            !matches!(
                r.state,
                crate::resource::ResourceState::Complete
                    | crate::resource::ResourceState::Failed
                    | crate::resource::ResourceState::Corrupt
            )
        });
    }

    // -----------------------------------------------------------------------
    // Periodic maintenance
    // -----------------------------------------------------------------------

    /// Expire old paths, reverse entries, and stale links.
    pub fn tick(&mut self, now: u64) -> TickResult {
        // Expire old paths
        let mut expired = heapless::Vec::<[u8; TRUNCATED_HASH_LEN], 32>::new();
        for (dest, path) in self.paths.iter() {
            if now.saturating_sub(path.learned_at) > PATH_EXPIRES {
                let _ = expired.push(*dest);
            }
        }
        let expired_count = expired.len();
        for dest in &expired {
            self.paths.remove(dest);
        }

        // Expire old reverse table entries
        let mut expired_reverse = heapless::Vec::<[u8; TRUNCATED_HASH_LEN], 32>::new();
        for (hash, entry) in self.reverse_table.iter() {
            if now.saturating_sub(entry.timestamp) > REVERSE_TIMEOUT {
                let _ = expired_reverse.push(*hash);
            }
        }
        for hash in &expired_reverse {
            self.reverse_table.remove(hash);
        }

        // Check for stale links
        let mut closed_links_list = heapless::Vec::<[u8; TRUNCATED_HASH_LEN], 32>::new();
        for (lid, link) in self.links.iter_mut() {
            if link.check_stale(now) {
                let _ = closed_links_list.push(*lid);
            }
        }
        let closed_count = closed_links_list.len();
        for lid in &closed_links_list {
            self.links.remove(lid);
        }

        // Expire timed-out receipts
        self.receipts.tick(now);

        // Expire stale channel receipts
        let mut expired_cr = heapless::Vec::<[u8; TRUNCATED_HASH_LEN], 32>::new();
        for (hash, cr) in self.channel_receipts.iter() {
            if now.saturating_sub(cr.sent_at) > RECEIPT_TIMEOUT {
                let _ = expired_cr.push(*hash);
            }
        }
        for hash in &expired_cr {
            self.channel_receipts.remove(hash);
        }

        TickResult {
            expired_paths: expired_count,
            closed_links: closed_count,
        }
    }

    /// Returns announces that are due for retransmission.
    pub fn pending_outbound(&mut self, now: u64) -> heapless::Vec<heapless::Vec<u8, 500>, 16> {
        let mut to_send: heapless::Vec<heapless::Vec<u8, 500>, 16> = heapless::Vec::new();
        let mut keep: heapless::Deque<PendingAnnounce, A> = heapless::Deque::new();

        while let Some(mut ann) = self.announces.pop_front() {
            let delay = PATHFINDER_G * (1u64 << ann.tx_count.min(8));
            if ann.local || now >= ann.last_tx_at + delay {
                let _ = to_send.push(ann.raw.clone());
                ann.tx_count += 1;
                ann.last_tx_at = now;
                ann.local = false;
                if ann.tx_count <= PATHFINDER_R {
                    let _ = keep.push_back(ann);
                }
            } else {
                let _ = keep.push_back(ann);
            }
        }

        self.announces = keep;
        to_send
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::path::Path;

    type TestTransport = Transport<64, 16, 128, 4>;

    #[test]
    fn test_path_expiry() {
        let mut transport = TestTransport::new();
        let dest = [0xAAu8; TRUNCATED_HASH_LEN];

        // Insert a path learned at timestamp 100
        let path = Path::direct(100);
        assert!(transport.insert_path(dest, path));
        assert_eq!(transport.path_count(), 1);

        // tick() before expiry — path should remain
        let result = transport.tick(100 + PATH_EXPIRES);
        assert_eq!(result.expired_paths, 0);
        assert_eq!(transport.path_count(), 1);

        // tick() after expiry — path should be cleared
        let result = transport.tick(100 + PATH_EXPIRES + 1);
        assert_eq!(result.expired_paths, 1);
        assert_eq!(transport.path_count(), 0);
    }

    #[test]
    fn test_announce_queue_at_capacity() {
        // Try to queue more announces than MAX_ANNOUNCES (16).
        let mut transport = TestTransport::new();

        for i in 0u8..16 {
            let mut raw = heapless::Vec::new();
            let _ = raw.push(i);
            let ann = PendingAnnounce {
                dest_hash: [i; TRUNCATED_HASH_LEN],
                raw,
                tx_count: 0,
                last_tx_at: 0,
                local: false,
            };
            assert!(transport.queue_announce(ann), "announce {} should be queued", i);
        }
        assert_eq!(transport.announce_count(), 16);

        // 17th announce should fail gracefully (returns false, no panic)
        let mut raw = heapless::Vec::new();
        let _ = raw.push(0xFF);
        let overflow = PendingAnnounce {
            dest_hash: [0xFF; TRUNCATED_HASH_LEN],
            raw,
            tx_count: 0,
            last_tx_at: 0,
            local: false,
        };
        assert!(!transport.queue_announce(overflow), "overflow announce should return false");
        assert_eq!(transport.announce_count(), 16);
    }

    #[test]
    fn test_tick_empty_tables() {
        // tick() with completely empty tables should not panic.
        let mut transport = TestTransport::new();
        assert_eq!(transport.path_count(), 0);
        assert_eq!(transport.announce_count(), 0);
        assert_eq!(transport.link_count(), 0);

        let result = transport.tick(1000);
        assert_eq!(result.expired_paths, 0);
        assert_eq!(result.closed_links, 0);
    }
}
