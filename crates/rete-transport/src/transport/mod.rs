//! Core Transport struct — path table, announce queue, packet processing, links.

mod announce;
mod link;
mod path;
mod receipt;
mod resource;

/// Relay debug logging — only available when the `relay-debug` feature is enabled.
macro_rules! relay_log {
    ($($arg:tt)*) => {
        #[cfg(feature = "relay-debug")]
        std::eprintln!($($arg)*);
    };
}

/// Format first 4 bytes of a hash as hex for compact logging.
#[cfg(feature = "relay-debug")]
pub(self) fn hex_short(h: &[u8]) -> alloc::string::String {
    use alloc::format;
    if h.len() >= 4 {
        format!("{:02x}{:02x}{:02x}{:02x}..", h[0], h[1], h[2], h[3])
    } else {
        format!("{:?}", h)
    }
}

use crate::dedup::DedupWindow;
use crate::link::compute_link_id;
use crate::path::Path;
use crate::receipt::ReceiptTable;
use crate::resource::Resource;
use crate::storage::{StorageMap, TransportStorage};
use rand_core::{CryptoRng, RngCore};
use rete_core::{
    DestHash, DestType, HeaderType, Identity, IdentityHash, LinkId, Packet, PacketType,
    CONTEXT_LRPROOF, CONTEXT_RESOURCE_PRF, TRUNCATED_HASH_LEN,
};

// ---------------------------------------------------------------------------
// Protocol constants (from Python Transport.py)
// ---------------------------------------------------------------------------

/// Announce retransmission delay base (seconds).
pub const PATHFINDER_G: u64 = 5;

/// Maximum retransmission count per announce.
pub const PATHFINDER_R: u8 = 1;

/// Announce retransmission random window (milliseconds, 0-500ms).
/// Python: `PATHFINDER_RW = 0.5` — we use millis for integer math.
pub const PATHFINDER_RW_MS: u64 = 500;

/// Maximum hop count for announce retransmission.
pub const PATHFINDER_M: u8 = 128;

/// Maximum local rebroadcasts heard before stopping retransmission.
/// Python: `LOCAL_REBROADCASTS_MAX = 2`
pub const LOCAL_REBROADCASTS_MAX: u8 = 2;

/// Grace period (seconds) before sending a path response.
/// Python: `PATH_REQUEST_GRACE = 0.4` — we use 1s since we work in integer seconds.
pub const PATH_REQUEST_GRACE: u64 = 1;

/// Minimum interval (seconds) between path requests for the same destination.
/// Python: `PATH_REQUEST_MI = 20`
pub const PATH_REQUEST_MI: u64 = 20;

/// Default announce rate target (seconds between announces per destination).
/// Python: interface-configurable, typically 3600s.
pub const ANNOUNCE_RATE_TARGET: u64 = 3600;

/// Number of rate violations allowed before blocking.
/// Python: interface-configurable, typically 10.
pub const ANNOUNCE_RATE_GRACE: u8 = 10;

/// Penalty duration (seconds) added when rate limit is exceeded.
/// Python: interface-configurable, typically 7200s.
pub const ANNOUNCE_RATE_PENALTY: u64 = 7200;

/// Path expiry time in seconds (7 days).
pub const PATH_EXPIRES: u64 = 604800;

/// Reverse table entry timeout in seconds (8 minutes).
pub const REVERSE_TIMEOUT: u64 = 480;

/// Default receipt proof timeout in seconds.
pub const RECEIPT_TIMEOUT: u64 = 30;

/// Minimum seconds between retry REQs for stalled receiver resources.
pub const RESOURCE_RETRY_THRESHOLD_SECS: u64 = 10;

/// Maximum pending outbound resource packets (parts + HMUs) queued per tick.
///
/// `resource_outbound` is drained to the caller after every ingest/tick call,
/// so this bounds a single burst, not steady-state queue depth.
const RESOURCE_OUTBOUND_MAX: usize = 256;

/// Errors from transport-layer send operations.
///
/// Returned by methods that build or encrypt outbound packets, where multiple
/// distinct failure modes were previously collapsed into `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    /// No known path or cached identity for the destination.
    UnknownDestination,
    /// Link not found in the link table.
    LinkNotFound,
    /// Link exists but is not in Active state (still Pending/Handshake/Stale/Closed).
    LinkNotActive,
    /// Channel send window is full (back-pressure).
    WindowFull,
    /// Cryptographic operation failed (encrypt, sign, ECDH).
    Crypto(rete_core::Error),
    /// Packet building failed (buffer too small, invalid fields).
    PacketBuild(rete_core::Error),
    /// Resource limit reached (resource table full).
    ResourceLimit,
}

impl core::fmt::Display for SendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SendError::UnknownDestination => write!(f, "unknown destination (no cached identity)"),
            SendError::LinkNotFound => write!(f, "link not found"),
            SendError::LinkNotActive => write!(f, "link not active"),
            SendError::WindowFull => write!(f, "channel window full"),
            SendError::Crypto(e) => write!(f, "crypto error: {e}"),
            SendError::PacketBuild(e) => write!(f, "packet build error: {e}"),
            SendError::ResourceLimit => write!(f, "resource table full"),
        }
    }
}

/// A receipt for a channel message awaiting proof-of-delivery.
#[derive(Debug, Clone)]
pub struct ChannelReceipt {
    /// Link the channel message was sent on.
    pub link_id: LinkId,
    /// Sequence number in the channel.
    pub sequence: u16,
    /// Monotonic timestamp when sent.
    pub sent_at: u64,
}

/// Destination hash for `rnstransport.path.request` (PLAIN, no identity).
///
/// Precomputed: `destination_hash("rnstransport.path.request", None)`.
pub const PATH_REQUEST_DEST: DestHash = DestHash::new([
    0x6b, 0x9f, 0x66, 0x01, 0x4d, 0x98, 0x53, 0xfa, 0xab, 0x22, 0x0f, 0xba, 0x47, 0xd0, 0x27, 0x61,
]);

// ---------------------------------------------------------------------------
// ReverseEntry — tracks forwarded packets for reply routing
// ---------------------------------------------------------------------------

/// An entry in the reverse table, keyed by truncated packet hash.
///
/// Used to route replies back along the path the original packet traversed.
#[derive(Debug, Clone, Copy)]
pub struct ReverseEntry {
    /// Monotonic timestamp when this entry was created.
    pub timestamp: u64,
    /// Interface index the original packet was received on.
    pub received_on: u8,
    /// Interface index the packet was forwarded to (0 for broadcast).
    pub forwarded_to: u8,
}

/// An entry in the link table, keyed by link_id.
///
/// Used to bidirectionally route link traffic (DATA, PROOF, etc.)
/// through a transport relay for the lifetime of the link.
/// Matches Python RNS `Transport.link_table`.
#[derive(Debug, Clone, Copy)]
pub struct LinkTableEntry {
    /// Monotonic timestamp when this entry was created.
    pub timestamp: u64,
    /// Interface the LINKREQUEST was received on (toward initiator).
    /// Matches Python `IDX_LT_RCVD_IF`.
    pub received_on: u8,
    /// Interface the LINKREQUEST was forwarded toward (toward responder).
    /// Matches Python `IDX_LT_NH_IF`.
    pub outbound_to: u8,
    /// Hop count from initiator side when LINKREQUEST arrived (post-increment).
    /// Matches Python `IDX_LT_HOPS`.
    pub inbound_hops: u8,
    /// Remaining hops toward responder (from path table).
    /// Matches Python `IDX_LT_REM_HOPS`.
    pub outbound_hops: u8,
    /// Destination hash of the link target.
    pub destination_hash: DestHash,
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
        dest_hash: DestHash,
        /// Payload data.
        payload: &'a [u8],
        /// Full 32-byte packet hash (for proof generation).
        packet_hash: [u8; 32],
    },
    /// A valid announce was received and its path has been learned.
    AnnounceReceived {
        /// Destination hash of the announcing identity.
        dest_hash: DestHash,
        /// Identity hash of the announcer.
        identity_hash: IdentityHash,
        /// Hop count at time of receipt.
        hops: u8,
        /// Optional application data from the announce.
        app_data: Option<&'a [u8]>,
        /// Optional ratchet public key (32 bytes, present when context_flag=1).
        ratchet: Option<[u8; 32]>,
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
        link_id: LinkId,
        /// The LRPROOF response to send back (raw packet bytes, owned).
        proof_raw: alloc::vec::Vec<u8>,
    },
    /// A link handshake completed (LRPROOF validated or LRRTT processed).
    LinkEstablished {
        /// The link_id.
        link_id: LinkId,
    },
    /// Decrypted data received on an active link.
    LinkData {
        /// The link_id.
        link_id: LinkId,
        /// Decrypted payload data (owned).
        data: alloc::vec::Vec<u8>,
        /// The context byte from the packet.
        context: u8,
    },
    /// Channel messages received on a link (reliable ordered delivery).
    ChannelMessages {
        /// The link_id.
        link_id: LinkId,
        /// Delivered channel envelopes.
        messages: alloc::vec::Vec<crate::channel::ChannelEnvelope>,
        /// The packet hash of the DATA packet carrying these channel messages.
        packet_hash: [u8; 32],
    },
    /// A link was closed (teardown or timeout).
    LinkClosed {
        /// The link_id.
        link_id: LinkId,
    },
    /// A proof was received for a packet we sent.
    ProofReceived {
        /// The full 32-byte packet hash the proof covers.
        packet_hash: [u8; 32],
    },
    /// A resource advertisement was received on a link.
    ResourceOffered {
        /// The link_id.
        link_id: LinkId,
        /// Resource hash (truncated to 16 bytes for keying).
        resource_hash: [u8; TRUNCATED_HASH_LEN],
        /// Total size of the resource data.
        total_size: usize,
        /// True if this resource is a request or response payload (auto-accept regardless of strategy).
        is_request_or_response: bool,
        /// True if this resource carries a response payload.
        is_response: bool,
    },
    /// Resource transfer progress.
    ResourceProgress {
        /// The link_id.
        link_id: LinkId,
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
        link_id: LinkId,
        /// Resource hash (truncated to 16 bytes).
        resource_hash: [u8; TRUNCATED_HASH_LEN],
        /// The assembled resource data.
        data: alloc::vec::Vec<u8>,
    },
    /// Resource transfer failed.
    ResourceFailed {
        /// The link_id.
        link_id: LinkId,
        /// Resource hash (truncated to 16 bytes).
        resource_hash: [u8; TRUNCATED_HASH_LEN],
    },
    /// A resource we sent was rejected by the receiver (RESOURCE_RCL received).
    ResourceRejected {
        /// The link_id.
        link_id: LinkId,
        /// Resource hash (truncated to 16 bytes).
        resource_hash: [u8; TRUNCATED_HASH_LEN],
    },
    /// A link.request() was received on a link.
    RequestReceived {
        /// The link_id.
        link_id: LinkId,
        /// The request_id (truncated packet hash for single-packet requests).
        request_id: rete_core::RequestId,
        /// The path_hash (SHA-256(path)[..16]).
        path_hash: rete_core::PathHash,
        /// The request data payload.
        data: alloc::vec::Vec<u8>,
        /// Timestamp from the wire format (seconds since epoch).
        requested_at: f64,
    },
    /// A link.response() was received on a link.
    ResponseReceived {
        /// The link_id.
        link_id: LinkId,
        /// The request_id this response is for.
        request_id: rete_core::RequestId,
        /// The response data payload.
        data: alloc::vec::Vec<u8>,
    },
    /// Packet was a duplicate and should be dropped.
    Duplicate,
    /// A channel message was accepted and buffered (out-of-order), not yet deliverable.
    Buffered {
        /// The packet hash of the DATA packet (receiver should prove it).
        packet_hash: [u8; 32],
        /// The link_id (used to build a link-destination proof).
        link_id: LinkId,
    },
    /// A path request for an unknown destination should be forwarded to other interfaces.
    PathRequestForward {
        /// The raw path request payload to forward.
        payload: alloc::vec::Vec<u8>,
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
// TransportStats
// ---------------------------------------------------------------------------

/// Cumulative counters for transport-layer activity.
///
/// All counters are monotonically increasing `u64` values. They are never
/// reset — callers can snapshot and diff to compute rates.
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct TransportStats {
    /// Total packets received and parsed (excludes parse failures).
    pub packets_received: u64,
    /// Total packets sent (announces via pending_outbound).
    pub packets_sent: u64,
    /// Packets forwarded on behalf of other nodes (relay traffic).
    pub packets_forwarded: u64,
    /// Packets dropped because they were seen before (dedup window).
    pub packets_dropped_dedup: u64,
    /// Packets dropped as invalid (parse failure, unknown dest, crypto error, etc.).
    pub packets_dropped_invalid: u64,
    /// Valid announces received and processed.
    pub announces_received: u64,
    /// Announces sent (first transmission of locally-queued announces).
    pub announces_sent: u64,
    /// Announce retransmissions (subsequent sends of the same announce).
    pub announces_retransmitted: u64,
    /// Announces suppressed by the announce rate limiter.
    pub announces_rate_limited: u64,
    /// Links that reached Active state (LRRTT or LRPROOF exchange completed).
    pub links_established: u64,
    /// Links closed (LINKCLOSE received or keepalive timeout).
    pub links_closed: u64,
    /// Link handshake failures (crypto errors during establishment).
    pub links_failed: u64,
    /// Link requests received (before LRPROOF sent).
    pub link_requests_received: u64,
    /// Paths learned or updated in the path table.
    pub paths_learned: u64,
    /// Paths expired and removed from the path table.
    pub paths_expired: u64,
    /// Cryptographic failures (decrypt/verify errors).
    pub crypto_failures: u64,
    /// Timestamp of first activity (seconds, caller-provided). 0 until first use.
    pub started_at: u64,
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// The Reticulum transport layer — path table, announce queue, dedup window, links.
///
/// Generic over `S: TransportStorage` — pluggable storage backend.
/// Use [`HeaplessStorage`](crate::HeaplessStorage) for embedded (fixed-size) or
/// [`StdStorage`](crate::storage_std::StdStorage) for hosted (heap-allocated).
pub struct Transport<S: TransportStorage> {
    pub(super) paths: S::PathMap,
    pub(super) announces: S::AnnounceDeque,
    pub(super) dedup: DedupWindow<S::DedupDeque>,
    pub(super) known_identities: S::IdentityMap,
    /// Identity hash of this node (enables HEADER_2 forwarding when set).
    pub(super) local_identity_hash: Option<IdentityHash>,
    /// Reverse table: truncated packet hash → entry (for reply routing).
    pub(super) reverse_table: S::ReverseMap,
    /// Dedup window for announce random_hashes (replay detection).
    pub(super) announce_dedup: DedupWindow<S::DedupDeque>,
    /// Destination hashes registered as local (self-announce filtering, local delivery routing).
    pub(super) local_destinations: alloc::vec::Vec<DestHash>,
    /// Active link sessions, keyed by link_id.
    pub(super) links: S::LinkMap,
    /// Receipts for sent packets, awaiting delivery proofs.
    pub(super) receipts: ReceiptTable<S::ReceiptMap>,
    /// Receipts for channel messages: truncated packet hash → ChannelReceipt.
    /// Used to match incoming PROOFs to channel sequences and call mark_delivered().
    pub(super) channel_receipts: S::ChannelReceiptMap,
    /// Active resource transfers.
    pub(super) resources: alloc::vec::Vec<Resource>,
    /// Pending outbound resource packets (parts, HMU, etc.) built during ingest.
    pub(super) resource_outbound: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    /// Link routing table: link_id → entry (for bidirectional relay of link traffic).
    /// Entries persist for the lifetime of the relayed link.
    pub(super) link_table: S::LinkTableMap,
    /// Announce rate limiting: dest_hash → (last_announce_time, violations, blocked_until).
    pub(super) announce_rate: S::AnnounceRateMap,
    /// Path request throttling: dest_hash → last_request_time.
    pub(super) path_request_times: S::PathRequestTimeMap,
    /// Pending split resource segments waiting to be advertised.
    pub(super) split_send_queue: alloc::vec::Vec<SplitSendEntry>,
    /// Cumulative transport-layer counters.
    pub(super) stats: TransportStats,
}

/// Queued data for a pending split resource segment.
/// Metadata for a split resource segment advertisement.
pub(super) struct SplitMeta {
    pub(super) split_index: usize,
    pub(super) split_total: usize,
    pub(super) original_hash: [u8; 32],
    pub(super) full_original_size: usize,
}

pub(super) struct SplitSendEntry {
    pub(super) link_id: LinkId,
    /// Group key: resource_hash of segment 1.
    pub(super) original_hash: [u8; 32],
    /// 1-based index of the next segment to send.
    pub(super) next_segment: usize,
    /// Total split segments.
    pub(super) split_total: usize,
    /// Full original plaintext size (all segments combined).
    pub(super) full_original_size: usize,
    /// Remaining plaintext data (after segment 1). Each segment reads its slice at send time.
    pub(super) data: alloc::vec::Vec<u8>,
}

/// Per-destination announce rate tracking entry.
#[derive(Debug, Clone, Copy)]
pub struct AnnounceRateEntry {
    pub(crate) last: u64,
    pub(crate) violations: u8,
    pub(crate) blocked_until: u64,
}

impl<S: TransportStorage> Default for Transport<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: TransportStorage> Transport<S> {
    /// Create a new, empty transport.
    pub fn new() -> Self {
        Transport {
            paths: Default::default(),
            announces: Default::default(),
            dedup: Default::default(),
            known_identities: Default::default(),
            local_identity_hash: None,
            reverse_table: Default::default(),
            announce_dedup: Default::default(),
            local_destinations: Default::default(),
            links: Default::default(),
            receipts: Default::default(),
            channel_receipts: Default::default(),
            resources: alloc::vec::Vec::new(),
            resource_outbound: alloc::vec::Vec::new(),
            link_table: Default::default(),
            announce_rate: Default::default(),
            path_request_times: Default::default(),
            split_send_queue: alloc::vec::Vec::new(),
            stats: TransportStats::default(),
        }
    }

    /// Return a reference to the cumulative transport counters.
    pub fn stats(&self) -> &TransportStats {
        &self.stats
    }

    /// Register a destination hash as belonging to this node.
    pub fn add_local_destination(&mut self, dest_hash: DestHash) {
        if !self.local_destinations.contains(&dest_hash) {
            self.local_destinations.push(dest_hash);
        }
    }

    /// Check whether a destination hash is registered as local.
    pub fn is_local_destination(&self, dest_hash: &DestHash) -> bool {
        self.local_destinations.contains(dest_hash)
    }

    /// Check a packet hash for duplicates.
    pub fn is_duplicate(&mut self, hash: &[u8; 32]) -> bool {
        self.dedup.check_and_insert(hash)
    }

    /// Set the local identity hash, enabling HEADER_2 forwarding.
    pub fn set_local_identity(&mut self, hash: IdentityHash) {
        self.local_identity_hash = Some(hash);
    }

    /// Get the local identity hash (transport node ID), if set.
    pub fn local_identity_hash(&self) -> Option<IdentityHash> {
        self.local_identity_hash
    }

    /// Look up a reverse table entry by truncated packet hash.
    pub fn get_reverse(&self, hash: &[u8; TRUNCATED_HASH_LEN]) -> Option<&ReverseEntry> {
        self.reverse_table.get(hash)
    }

    /// Number of reverse table entries.
    pub fn reverse_count(&self) -> usize {
        self.reverse_table.len()
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

        // Lazy-init started_at on first ingest
        if self.stats.started_at == 0 {
            self.stats.started_at = now;
        }

        // Parse
        let pkt = match Packet::parse(raw) {
            Ok(p) => p,
            Err(_) => {
                self.stats.packets_dropped_invalid += 1;
                return IngestResult::Invalid;
            }
        };

        self.stats.packets_received += 1;

        // Compute packet hash for dedup
        let pkt_hash = pkt.compute_hash();

        // Dedup check
        if self.is_duplicate(&pkt_hash) {
            relay_log!(
                "[relay] DEDUP pkt_hash={} type={:?} dest_type={:?}",
                hex_short(&pkt_hash),
                pkt.packet_type,
                pkt.dest_type,
            );
            self.stats.packets_dropped_dedup += 1;
            return IngestResult::Duplicate;
        }

        // Check HEADER_2 forwarding
        if pkt.header_type == HeaderType::Header2 {
            if let Some(local_id) = self.local_identity_hash {
                if let Some(tid) = pkt.transport_id {
                    let tid_hash = IdentityHash::from_slice(tid);

                    if tid_hash == local_id {
                        let dest = DestHash::from_slice(pkt.destination_hash);
                        let is_link_request = pkt.packet_type == PacketType::LinkRequest;
                        let is_link_dest = pkt.dest_type == DestType::Link;

                        // End pkt borrow on raw before mutating
                        #[allow(clippy::drop_non_drop)]
                        drop(pkt);

                        raw[1] = raw[1].saturating_add(1);
                        // Capture hops AFTER increment to match Python
                        // (Transport.py:1319 increments first, line 1488 stores).
                        let inbound_hops = raw[1];

                        let mut trunc_hash = [0u8; TRUNCATED_HASH_LEN];
                        trunc_hash.copy_from_slice(&pkt_hash[..TRUNCATED_HASH_LEN]);
                        let reverse_entry = ReverseEntry {
                            timestamp: now,
                            received_on: iface,
                            forwarded_to: 0,
                        };
                        let _ = self.reverse_table.insert(trunc_hash, reverse_entry);

                        // For LINKREQUEST: store a link_table entry keyed by link_id.
                        // This enables bidirectional routing of all link traffic
                        // (LRPROOF, LRRTT, DATA, keepalives, etc.) through this relay.
                        if is_link_request {
                            if let Ok(lid) = compute_link_id(raw) {
                                let path_entry = self.paths.get(&dest);
                                let remaining = path_entry.map(|p| p.hops).unwrap_or(1);
                                let outbound_iface =
                                    path_entry.and_then(|p| p.received_on).unwrap_or(0);
                                relay_log!(
                                    "[relay] H2 LINKREQUEST link_table INSERT lid={} dest={} in_hops={} out_hops={} rcvd={} out={}",
                                    hex_short(lid.as_ref()),
                                    hex_short(dest.as_ref()),
                                    inbound_hops,
                                    remaining,
                                    iface,
                                    outbound_iface,
                                );
                                let _ = self.link_table.insert(
                                    lid,
                                    LinkTableEntry {
                                        timestamp: now,
                                        received_on: iface,
                                        outbound_to: outbound_iface,
                                        inbound_hops,
                                        outbound_hops: remaining,
                                        destination_hash: dest,
                                    },
                                );
                            }
                        }

                        let h2_result = match self.paths.get(&dest) {
                            Some(Path { via: Some(via), .. }) => {
                                relay_log!(
                                    "[relay] H2 FWD via={} dest={} iface={}",
                                    hex_short(via.as_ref()),
                                    hex_short(dest.as_ref()),
                                    iface,
                                );
                                raw[2..18].copy_from_slice(via.as_ref());
                                IngestResult::Forward {
                                    raw: &raw[..len],
                                    source_iface: iface,
                                }
                            }
                            Some(_path) => {
                                relay_log!(
                                    "[relay] H2->H1 FWD direct dest={} iface={} len={}->{}",
                                    hex_short(dest.as_ref()),
                                    iface,
                                    len,
                                    len - TRUNCATED_HASH_LEN,
                                );
                                let new_flags = raw[0] & 0x0F;
                                raw[0] = new_flags;
                                raw.copy_within(18..len, 2);
                                IngestResult::Forward {
                                    raw: &raw[..len - TRUNCATED_HASH_LEN],
                                    source_iface: iface,
                                }
                            }
                            _ if is_link_dest => {
                                // No path for this dest, but dest_type=Link:
                                // route via link_table (dest = link_id).
                                // This handles H2 link DATA, channel, keepalive,
                                // etc. where the destination_hash is a link_id
                                // (not in path_table).
                                let dest_as_lid = LinkId::from_slice(dest.as_ref());
                                if let Some(lte) = self.link_table.get_mut(&dest_as_lid) {
                                    // Exact hop-count match (same as H1 link_table)
                                    let hops = raw[1];
                                    let hop_ok = if lte.outbound_to == lte.received_on {
                                        hops == lte.outbound_hops || hops == lte.inbound_hops
                                    } else if iface == lte.outbound_to {
                                        hops == lte.outbound_hops
                                    } else if iface == lte.received_on {
                                        hops == lte.inbound_hops
                                    } else {
                                        false
                                    };
                                    if hop_ok {
                                        lte.timestamp = now;
                                        relay_log!(
                                            "[relay] H2 link_table FWD lid={} iface={} hops={}",
                                            hex_short(dest.as_ref()),
                                            iface,
                                            hops,
                                        );
                                        // Convert H2→H1 and forward (link traffic
                                        // goes directly to the link endpoint)
                                        let new_flags = raw[0] & 0x0F;
                                        raw[0] = new_flags;
                                        raw.copy_within(18..len, 2);
                                        IngestResult::Forward {
                                            raw: &raw[..len - TRUNCATED_HASH_LEN],
                                            source_iface: iface,
                                        }
                                    } else {
                                        relay_log!(
                                            "[relay] H2 link_table HOP_EXCEED lid={} hops={}",
                                            hex_short(dest.as_ref()),
                                            raw[1],
                                        );
                                        IngestResult::Invalid
                                    }
                                } else {
                                    relay_log!(
                                        "[relay] H2 link_table MISS lid={}",
                                        hex_short(dest.as_ref()),
                                    );
                                    IngestResult::Invalid
                                }
                            }
                            _ => {
                                relay_log!("[relay] H2 NO_PATH dest={}", hex_short(dest.as_ref()),);
                                IngestResult::Invalid
                            }
                        };
                        match &h2_result {
                            IngestResult::Forward { .. } => self.stats.packets_forwarded += 1,
                            IngestResult::Invalid => self.stats.packets_dropped_invalid += 1,
                            _ => {}
                        }
                        return h2_result;
                    }
                }
            }
        }

        // Increment hops
        raw[1] = raw[1].saturating_add(1);

        // Re-parse after hops increment
        let pkt = match Packet::parse(raw) {
            Ok(p) => p,
            Err(_) => {
                self.stats.packets_dropped_invalid += 1;
                return IngestResult::Invalid;
            }
        };

        match pkt.packet_type {
            PacketType::Announce => self.handle_announce(&pkt, raw, now, iface),
            PacketType::Data => {
                let dh = DestHash::from_slice(pkt.destination_hash);

                // Path request handling
                if self.local_identity_hash.is_some() && dh == PATH_REQUEST_DEST {
                    return self.handle_path_request(pkt.payload, now);
                }

                // Link data handling: dest_type == Link
                if pkt.dest_type == DestType::Link {
                    let lid = LinkId::from_slice(dh.as_ref());
                    // If we own this link locally, handle it.
                    if self.links.contains_key(&lid) {
                        return self.handle_link_data(
                            &lid,
                            pkt.context,
                            pkt.payload,
                            now,
                            pkt_hash,
                            rng,
                        );
                    }
                    // Not our link — if we are a transport relay, check
                    // the link_table (keyed by link_id) to forward
                    // bidirectionally through this relay.
                    if self.local_identity_hash.is_some() {
                        if let Some(lte) = self.link_table.get_mut(&lid) {
                            // Exact hop-count match with direction awareness
                            // (Python Transport.py:1514-1549).
                            let hop_ok = if lte.outbound_to == lte.received_on {
                                // Same interface: accept either direction
                                pkt.hops == lte.outbound_hops || pkt.hops == lte.inbound_hops
                            } else if iface == lte.outbound_to {
                                // From responder side
                                pkt.hops == lte.outbound_hops
                            } else if iface == lte.received_on {
                                // From initiator side
                                pkt.hops == lte.inbound_hops
                            } else {
                                false
                            };
                            if hop_ok {
                                lte.timestamp = now; // refresh for expiry
                                relay_log!(
                                    "[relay] link_table FORWARD lid={} ctx={:#04x} iface={} hops={}",
                                    hex_short(lid.as_ref()),
                                    pkt.context,
                                    iface,
                                    pkt.hops,
                                );
                                self.stats.packets_forwarded += 1;
                                return IngestResult::Forward {
                                    raw,
                                    source_iface: iface,
                                };
                            } else {
                                relay_log!(
                                    "[relay] link_table HOP_FAIL lid={} ctx={:#04x} iface={} hops={} in_hops={} out_hops={} rcvd={} out={}",
                                    hex_short(lid.as_ref()),
                                    pkt.context,
                                    iface,
                                    pkt.hops,
                                    lte.inbound_hops,
                                    lte.outbound_hops,
                                    lte.received_on,
                                    lte.outbound_to,
                                );
                            }
                        } else {
                            relay_log!(
                                "[relay] link_table MISS lid={} ctx={:#04x} (no entry)",
                                hex_short(lid.as_ref()),
                                pkt.context,
                            );
                        }
                    }
                    // Fall through: non-transport node or no link_table entry.
                    // Try local handling (will return Invalid if link not found).
                    return self.handle_link_data(
                        &lid,
                        pkt.context,
                        pkt.payload,
                        now,
                        pkt_hash,
                        rng,
                    );
                }

                // Transport relay: if we're a transport node and this isn't
                // our own destination, forward to the next hop.
                if self.local_identity_hash.is_some()
                    && !self.is_local_destination(&dh)
                    && self.paths.contains_key(&dh)
                {
                    // Create reverse_table entry so the proof can route back.
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
                    relay_log!(
                        "[relay] H1 DATA FORWARD dest={} reverse={}",
                        hex_short(dh.as_ref()),
                        hex_short(&trunc_hash[..]),
                    );
                    self.stats.packets_forwarded += 1;
                    return IngestResult::Forward {
                        raw: &raw[..len],
                        source_iface: iface,
                    };
                }

                // Only treat as local if the destination is actually registered
                // as ours. Packets for unknown destinations are dropped — they
                // reached a dead end (no path, not local).
                if self.is_local_destination(&dh) {
                    IngestResult::LocalData {
                        dest_hash: dh,
                        payload: pkt.payload,
                        packet_hash: pkt_hash,
                    }
                } else {
                    self.stats.packets_dropped_invalid += 1;
                    IngestResult::Invalid
                }
            }
            PacketType::Proof => {
                // For proof packets, the destination_hash may be a link_id (Link type)
                // or a truncated packet hash (Single type). We use both typed forms below.
                // Proof dest_hash is overloaded: link_id for Link-typed, truncated
                // packet hash for Single-typed. Keep raw bytes for ReverseMap/ReceiptMap.
                let raw_dh: [u8; TRUNCATED_HASH_LEN] = pkt.destination_hash.try_into().unwrap();
                #[allow(unused_variables)]
                let dh = DestHash::from(raw_dh);
                let lid = LinkId::from(raw_dh);

                if pkt.context == CONTEXT_LRPROOF && pkt.dest_type == DestType::Link {
                    relay_log!(
                        "[relay] LRPROOF_IN lid={} hops={} plen={} local_link={} link_table={} reverse={}",
                        hex_short(lid.as_ref()),
                        pkt.hops,
                        pkt.payload.len(),
                        self.links.contains_key(&lid),
                        self.link_table.contains_key(&lid),
                        self.reverse_table.contains_key(&raw_dh),
                    );
                }

                // Check for LRPROOF (link proof from responder to initiator).
                // Only handle locally if we have a pending link for this link_id;
                // otherwise fall through to reverse-table forwarding (relay case).
                if pkt.context == CONTEXT_LRPROOF
                    && pkt.dest_type == DestType::Link
                    && self.links.contains_key(&lid)
                {
                    return self.handle_lrproof(&lid, pkt.payload, now);
                }

                // Check for RESOURCE_PRF (resource completion proof from receiver).
                // Like LRPROOF, handle locally when the link is ours; otherwise
                // fall through to relay forwarding.  Resource proofs are NOT
                // link-encrypted (Python: Packet.pack special-cases RESOURCE_PRF).
                if pkt.context == CONTEXT_RESOURCE_PRF
                    && pkt.dest_type == DestType::Link
                    && self.links.contains_key(&lid)
                {
                    if let Some(link) = self.links.get_mut(&lid) {
                        link.touch_inbound(now);
                    }
                    return self.handle_resource_data(&lid, pkt.context, pkt.payload, now, rng);
                }

                // Check receipt table for delivery proof (DATA packets)
                if let Some(packet_hash) = self.receipts.validate_proof(&raw_dh, pkt.payload) {
                    return IngestResult::ProofReceived { packet_hash };
                }

                // Check channel receipts for delivery proof (channel messages).
                // Proof payload format: packet_hash[32] || sig[64].
                // Link proofs use dest_type=Link with dest_hash=link_id, so we
                // extract the truncated packet hash from the payload for lookup.
                if pkt.payload.len() >= 96 {
                    let mut full_hash = [0u8; 32];
                    full_hash.copy_from_slice(&pkt.payload[..32]);
                    let mut receipt_key = [0u8; TRUNCATED_HASH_LEN];
                    receipt_key.copy_from_slice(&full_hash[..TRUNCATED_HASH_LEN]);

                    if let Some(cr) = self.channel_receipts.get(&receipt_key) {
                        let link_id = cr.link_id;
                        let sequence = cr.sequence;
                        let sig = &pkt.payload[32..96];
                        // Verify using the link peer's signing key (peer_ed25519_pub).
                        // Python initiators use an ephemeral Ed25519 key (not their
                        // node identity) for link signing, so we must use the key
                        // from the LINKREQUEST/LRPROOF handshake.
                        let verified = if let Some(link) = self.links.get(&link_id) {
                            Identity::verify_raw_ed25519(&link.peer_ed25519_pub, &full_hash, sig)
                                .is_ok()
                        } else {
                            false
                        };
                        if verified {
                            self.channel_receipts.remove(&receipt_key);
                            if let Some(link) = self.links.get_mut(&link_id) {
                                link.touch_inbound(now);
                                let rtt = link.rtt;
                                if let Some(channel) = link.channel.as_mut() {
                                    channel.mark_delivered(sequence, rtt);
                                }
                            }
                            return IngestResult::ProofReceived {
                                packet_hash: full_hash,
                            };
                        }
                    }
                }

                if self.local_identity_hash.is_some() {
                    if self.reverse_table.remove(&raw_dh).is_some() {
                        relay_log!(
                            "[relay] PROOF reverse_table FORWARD dest={} ctx={:#04x}",
                            hex_short(dh.as_ref()),
                            pkt.context,
                        );
                        self.stats.packets_forwarded += 1;
                        IngestResult::Forward {
                            raw,
                            source_iface: iface,
                        }
                    } else if let Some(lte) = self.link_table.get_mut(&lid) {
                        // Link-destined proof (LRPROOF or channel proof):
                        // route via the persistent link_table entry.
                        lte.timestamp = now; // refresh for expiry

                        // Validate LRPROOF signature before forwarding (matches Python relay).
                        // Python Transport.py drops invalid proofs silently.
                        if pkt.context == CONTEXT_LRPROOF {
                            let dest_hash_for_link = lte.destination_hash;
                            if let Some(pub_key) = self.known_identities.get(&dest_hash_for_link) {
                                if let Ok(dest_id) = Identity::from_public_key(pub_key) {
                                    relay_log!(
                                        "[relay] LRPROOF_VALIDATE lid={} dest={} has_identity={}",
                                        hex_short(lid.as_ref()),
                                        hex_short(dest_hash_for_link.as_ref()),
                                        true,
                                    );
                                    if !self.validate_lrproof_relay(pkt.payload, &lid, &dest_id) {
                                        relay_log!(
                                            "[relay] LRPROOF REJECTED lid={} dest={}",
                                            hex_short(lid.as_ref()),
                                            hex_short(dest_hash_for_link.as_ref()),
                                        );
                                        self.stats.packets_dropped_invalid += 1;
                                        return IngestResult::Invalid;
                                    }
                                    relay_log!(
                                        "[relay] LRPROOF_VALID lid={} dest={}",
                                        hex_short(lid.as_ref()),
                                        hex_short(dest_hash_for_link.as_ref()),
                                    );
                                }
                                // If identity can't be reconstructed, forward
                                // anyway (graceful fallback).
                            }
                            // If identity not known, forward anyway.
                        }

                        relay_log!(
                            "[relay] PROOF link_table FORWARD lid={} ctx={:#04x} raw[0..20]={:02x?}",
                            hex_short(lid.as_ref()),
                            pkt.context,
                            &raw[..core::cmp::min(20, raw.len())],
                        );
                        self.stats.packets_forwarded += 1;
                        IngestResult::Forward {
                            raw,
                            source_iface: iface,
                        }
                    } else {
                        self.stats.packets_dropped_invalid += 1;
                        IngestResult::Invalid
                    }
                } else {
                    self.stats.packets_forwarded += 1;
                    IngestResult::Forward {
                        raw,
                        source_iface: iface,
                    }
                }
            }
            PacketType::LinkRequest => {
                let dh = DestHash::from_slice(pkt.destination_hash);
                if self.is_local_destination(&dh) {
                    self.handle_link_request(raw, &dh, pkt.payload, now, rng, identity)
                } else {
                    // For HEADER_1 LINKREQUEST forwarding on a transport node:
                    // also create a link_table entry so link traffic can be
                    // routed bidirectionally (same as HEADER_2 handling above).
                    if self.local_identity_hash.is_some() {
                        if let Ok(lid) = compute_link_id(raw) {
                            let path_entry = self.paths.get(&dh);
                            let remaining = path_entry.map(|p| p.hops).unwrap_or(1);
                            let outbound_iface =
                                path_entry.and_then(|p| p.received_on).unwrap_or(0);
                            relay_log!(
                                "[relay] H1 LINKREQUEST link_table INSERT lid={} dest={} out_hops={} rcvd={} out={}",
                                hex_short(lid.as_ref()),
                                hex_short(dh.as_ref()),
                                remaining,
                                iface,
                                outbound_iface,
                            );
                            let _ = self.link_table.insert(
                                lid,
                                LinkTableEntry {
                                    timestamp: now,
                                    received_on: iface,
                                    outbound_to: outbound_iface,
                                    inbound_hops: pkt.hops,
                                    outbound_hops: remaining,
                                    destination_hash: dh,
                                },
                            );
                        }
                    }
                    self.stats.packets_forwarded += 1;
                    IngestResult::Forward {
                        raw,
                        source_iface: iface,
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Periodic maintenance
    // -----------------------------------------------------------------------

    /// Expire old paths, reverse entries, and stale links.
    pub fn tick(&mut self, now: u64) -> TickResult {
        // Lazy-init started_at on first tick
        if self.stats.started_at == 0 {
            self.stats.started_at = now;
        }

        // Expire old paths
        let prev_paths = self.paths.len();
        self.paths.retain(|_, path| now.saturating_sub(path.learned_at) <= path.expiry_time());
        let expired_count = prev_paths - self.paths.len();

        // Expire old reverse table entries
        self.reverse_table.retain(|_, entry| now.saturating_sub(entry.timestamp) <= REVERSE_TIMEOUT);

        // Expire old link table entries (stale relayed links)
        self.link_table.retain(|_, entry| {
            now.saturating_sub(entry.timestamp) <= crate::link::STALE_TIMEOUT_SECS
        });

        // Check for stale links
        let prev_links = self.links.len();
        self.links.retain(|_, link| !link.check_stale(now));
        let closed_count = prev_links - self.links.len();

        // Expire timed-out receipts
        self.receipts.tick(now);

        // Expire stale channel receipts
        self.channel_receipts.retain(|_, cr| now.saturating_sub(cr.sent_at) <= RECEIPT_TIMEOUT);

        self.stats.paths_expired += expired_count as u64;
        self.stats.links_closed += closed_count as u64;

        TickResult {
            expired_paths: expired_count,
            closed_links: closed_count,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::announce::PendingAnnounce;
    use crate::link::{compute_link_id, Link};
    use crate::path::Path;
    use rete_core::{
        DestType, HeaderType, Identity, PacketBuilder, PacketType, CONTEXT_CHANNEL,
        CONTEXT_KEEPALIVE, CONTEXT_LRPROOF, TRANSPORT_TYPE_TRANSPORT, TRUNCATED_HASH_LEN,
    };

    type TestTransport = Transport<crate::HeaplessStorage<64, 16, 128, 4>>;

    #[test]
    fn test_path_expiry() {
        let mut transport = TestTransport::new();
        let dest = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);

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
            let ann = PendingAnnounce {
                dest_hash: DestHash::from([i; TRUNCATED_HASH_LEN]),
                raw: alloc::vec![i],
                tx_count: 0,
                retransmit_timeout: 0,
                local: false,
                local_rebroadcasts: 0,
                block_rebroadcasts: false,
                received_hops: 0,
            };
            assert!(
                transport.queue_announce(ann),
                "announce {} should be queued",
                i
            );
        }
        assert_eq!(transport.announce_count(), 16);

        // 17th announce should fail gracefully (returns false, no panic)
        let overflow = PendingAnnounce {
            dest_hash: DestHash::from([0xFF; TRUNCATED_HASH_LEN]),
            raw: alloc::vec![0xFF],
            tx_count: 0,
            retransmit_timeout: 0,
            local: false,
            local_rebroadcasts: 0,
            block_rebroadcasts: false,
            received_hops: 0,
        };
        assert!(
            !transport.queue_announce(overflow),
            "overflow announce should return false"
        );
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

    #[test]
    fn test_build_link_proof_packet_format() {
        // Verify build_link_proof_packet produces dest_type=Link and dest_hash=link_id
        let identity = Identity::from_seed(b"link-proof-test").unwrap();
        let packet_hash = [0xAA; 32];
        let link_id = LinkId::from([0xBBu8; TRUNCATED_HASH_LEN]);

        let raw = TestTransport::build_link_proof_packet(&identity, &packet_hash, &link_id)
            .expect("should build link proof packet");

        let pkt = rete_core::Packet::parse(&raw).expect("should parse");
        assert_eq!(pkt.packet_type, PacketType::Proof);
        assert_eq!(pkt.dest_type, DestType::Link);
        assert_eq!(pkt.destination_hash, link_id.as_ref());
        assert_eq!(pkt.payload.len(), 96);
        assert_eq!(&pkt.payload[..32], &packet_hash);
        // Verify signature is valid
        let sig = &pkt.payload[32..96];
        assert!(identity.verify(&packet_hash, sig).is_ok());
    }

    #[test]
    fn test_build_proof_packet_still_uses_single() {
        // Verify build_proof_packet still produces dest_type=Single (non-link proofs)
        let identity = Identity::from_seed(b"single-proof-test").unwrap();
        let packet_hash = [0xCC; 32];

        let raw = TestTransport::build_proof_packet(&identity, &packet_hash)
            .expect("should build proof packet");

        let pkt = rete_core::Packet::parse(&raw).expect("should parse");
        assert_eq!(pkt.packet_type, PacketType::Proof);
        assert_eq!(pkt.dest_type, DestType::Single);
        assert_eq!(pkt.destination_hash, &packet_hash[..TRUNCATED_HASH_LEN]);
        assert_eq!(pkt.payload.len(), 96);
    }

    #[test]
    fn test_link_proof_vs_single_proof_differ() {
        // Link proof and single proof for the same packet_hash should differ
        // in dest_type and destination_hash
        let identity = Identity::from_seed(b"diff-proof-test").unwrap();
        let packet_hash = [0xDD; 32];
        let link_id = LinkId::from([0xEEu8; TRUNCATED_HASH_LEN]);

        let link_raw = TestTransport::build_link_proof_packet(&identity, &packet_hash, &link_id)
            .expect("link proof");
        let single_raw =
            TestTransport::build_proof_packet(&identity, &packet_hash).expect("single proof");

        let link_pkt = rete_core::Packet::parse(&link_raw).unwrap();
        let single_pkt = rete_core::Packet::parse(&single_raw).unwrap();

        assert_eq!(link_pkt.dest_type, DestType::Link);
        assert_eq!(single_pkt.dest_type, DestType::Single);
        assert_eq!(link_pkt.destination_hash, link_id.as_ref());
        assert_eq!(
            single_pkt.destination_hash,
            &packet_hash[..TRUNCATED_HASH_LEN]
        );
        // Payloads should be the same (packet_hash + signature)
        assert_eq!(link_pkt.payload, single_pkt.payload);
    }

    // -----------------------------------------------------------------------
    // Link relay forwarding via link_table
    // -----------------------------------------------------------------------

    /// Helper: build a HEADER_2 LINKREQUEST packet targeting a relay.
    fn build_h2_linkrequest(
        relay_id: &IdentityHash,
        dest_hash: &DestHash,
        payload: &[u8],
    ) -> ([u8; rete_core::MTU], usize) {
        let mut buf = [0u8; rete_core::MTU];
        let n = PacketBuilder::new(&mut buf)
            .header_type(HeaderType::Header2)
            .transport_type(TRANSPORT_TYPE_TRANSPORT)
            .packet_type(PacketType::LinkRequest)
            .dest_type(DestType::Single)
            .hops(0)
            .transport_id(relay_id.as_ref())
            .destination_hash(dest_hash.as_ref())
            .context(0x00)
            .payload(payload)
            .build()
            .unwrap();
        (buf, n)
    }

    /// Helper: set up a transport relay with a learned path for the destination.
    fn make_relay_transport(
        relay_hash: IdentityHash,
        dest_hash: DestHash,
    ) -> TestTransport {
        let mut t = TestTransport::new();
        t.set_local_identity(relay_hash);
        t.insert_path(dest_hash, Path::direct(0));
        t
    }

    #[test]
    fn test_h2_linkrequest_creates_link_table_entry() {
        let relay_hash = IdentityHash::from([0x11u8; TRUNCATED_HASH_LEN]);
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);
        let mut transport = make_relay_transport(relay_hash, dest_hash);
        let identity = Identity::from_seed(b"relay-lr-test").unwrap();
        let mut rng = rand_core::OsRng;

        // Build LINKREQUEST payload (x25519_pub[32] || ed25519_pub[32])
        let lr_payload = [0xBBu8; 64];
        let (mut buf, n) = build_h2_linkrequest(&relay_hash, &dest_hash, &lr_payload);

        // Before ingest, link_table should be empty
        assert_eq!(transport.link_table.len(), 0);

        let result = transport.ingest_on(&mut buf[..n], 100, 0, &mut rng, &identity);

        // Should forward (H2 -> H1 conversion since path is direct)
        assert!(
            matches!(result, IngestResult::Forward { .. }),
            "LINKREQUEST should be forwarded, got {:?}",
            core::mem::discriminant(&result)
        );

        // link_table should now have an entry
        assert_eq!(
            transport.link_table.len(),
            1,
            "link_table should have 1 entry after LINKREQUEST"
        );
    }

    #[test]
    fn test_link_data_forwarded_via_link_table() {
        let relay_hash = IdentityHash::from([0x11u8; TRUNCATED_HASH_LEN]);
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);
        let mut transport = make_relay_transport(relay_hash, dest_hash);
        let identity = Identity::from_seed(b"relay-data-test").unwrap();
        let mut rng = rand_core::OsRng;

        // Step 1: Forward a LINKREQUEST to create a link_table entry
        let lr_payload = [0xBBu8; 64];
        let (mut buf, n) = build_h2_linkrequest(&relay_hash, &dest_hash, &lr_payload);
        let link_id = compute_link_id(&buf[..n]).unwrap();
        transport.ingest_on(&mut buf[..n], 100, 0, &mut rng, &identity);

        assert_eq!(transport.link_table.len(), 1);

        // Step 2: Build a link DATA packet (HEADER_1, dest_type=Link, dest_hash=link_id)
        // This simulates LRRTT or other link traffic from the initiator side.
        let mut data_buf = [0u8; rete_core::MTU];
        let data_len = PacketBuilder::new(&mut data_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Link)
            .destination_hash(link_id.as_ref())
            .context(0x00)
            .payload(&[0x42; 16])
            .build()
            .unwrap();

        let result = transport.ingest_on(&mut data_buf[..data_len], 101, 0, &mut rng, &identity);

        assert!(
            matches!(result, IngestResult::Forward { .. }),
            "Link DATA should be forwarded via link_table, got {:?}",
            core::mem::discriminant(&result)
        );
    }

    #[test]
    fn test_link_proof_forwarded_via_link_table() {
        let relay_hash = IdentityHash::from([0x11u8; TRUNCATED_HASH_LEN]);
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);
        let mut transport = make_relay_transport(relay_hash, dest_hash);
        let identity = Identity::from_seed(b"relay-proof-test").unwrap();
        let mut rng = rand_core::OsRng;

        // Step 1: Forward a LINKREQUEST to create a link_table entry
        let lr_payload = [0xBBu8; 64];
        let (mut buf, n) = build_h2_linkrequest(&relay_hash, &dest_hash, &lr_payload);
        let link_id = compute_link_id(&buf[..n]).unwrap();
        transport.ingest_on(&mut buf[..n], 100, 0, &mut rng, &identity);

        // Step 2: Build a PROOF packet (HEADER_1, dest_type=Link, dest_hash=link_id)
        // This simulates the LRPROOF coming back from the responder.
        let mut proof_buf = [0u8; rete_core::MTU];
        let proof_len = PacketBuilder::new(&mut proof_buf)
            .packet_type(PacketType::Proof)
            .dest_type(DestType::Link)
            .destination_hash(link_id.as_ref())
            .context(CONTEXT_LRPROOF)
            .payload(&[0x42; 96])
            .build()
            .unwrap();

        let result = transport.ingest_on(&mut proof_buf[..proof_len], 101, 1, &mut rng, &identity);

        assert!(
            matches!(result, IngestResult::Forward { .. }),
            "Link PROOF should be forwarded via link_table, got {:?}",
            core::mem::discriminant(&result)
        );
    }

    #[test]
    fn test_link_data_without_link_table_entry_is_invalid() {
        let relay_hash = IdentityHash::from([0x11u8; TRUNCATED_HASH_LEN]);
        let mut transport = TestTransport::new();
        transport.set_local_identity(relay_hash);
        let identity = Identity::from_seed(b"relay-no-entry-test").unwrap();
        let mut rng = rand_core::OsRng;

        // Build a link DATA packet for a link_id we don't know about
        let unknown_link_id = [0xFFu8; TRUNCATED_HASH_LEN];
        let mut data_buf = [0u8; rete_core::MTU];
        let data_len = PacketBuilder::new(&mut data_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Link)
            .destination_hash(&unknown_link_id)
            .context(0x00)
            .payload(&[0x42; 16])
            .build()
            .unwrap();

        let result = transport.ingest_on(&mut data_buf[..data_len], 101, 0, &mut rng, &identity);

        assert!(
            matches!(result, IngestResult::Invalid),
            "Link DATA without link_table entry should be Invalid, got {:?}",
            core::mem::discriminant(&result)
        );
    }

    #[test]
    fn test_link_table_entry_refreshed_on_traffic() {
        let relay_hash = IdentityHash::from([0x11u8; TRUNCATED_HASH_LEN]);
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);
        let mut transport = make_relay_transport(relay_hash, dest_hash);
        let identity = Identity::from_seed(b"relay-refresh-test").unwrap();
        let mut rng = rand_core::OsRng;

        // Forward a LINKREQUEST at time=100
        let lr_payload = [0xBBu8; 64];
        let (mut buf, n) = build_h2_linkrequest(&relay_hash, &dest_hash, &lr_payload);
        let link_id = compute_link_id(&buf[..n]).unwrap();
        transport.ingest_on(&mut buf[..n], 100, 0, &mut rng, &identity);

        assert_eq!(transport.link_table.get(&link_id).unwrap().timestamp, 100);

        // Forward link DATA at time=500 — should refresh the timestamp
        let mut data_buf = [0u8; rete_core::MTU];
        let data_len = PacketBuilder::new(&mut data_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Link)
            .destination_hash(link_id.as_ref())
            .context(0x00)
            .payload(&[0x42; 16])
            .build()
            .unwrap();

        transport.ingest_on(&mut data_buf[..data_len], 500, 0, &mut rng, &identity);

        assert_eq!(
            transport.link_table.get(&link_id).unwrap().timestamp,
            500,
            "link_table timestamp should be refreshed on traffic"
        );
    }

    #[test]
    fn test_link_table_entry_expires_after_stale_timeout() {
        let relay_hash = IdentityHash::from([0x11u8; TRUNCATED_HASH_LEN]);
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);
        let mut transport = make_relay_transport(relay_hash, dest_hash);
        let identity = Identity::from_seed(b"relay-expiry-test").unwrap();
        let mut rng = rand_core::OsRng;

        // Forward a LINKREQUEST at time=100
        let lr_payload = [0xBBu8; 64];
        let (mut buf, n) = build_h2_linkrequest(&relay_hash, &dest_hash, &lr_payload);
        let _link_id = compute_link_id(&buf[..n]).unwrap();
        transport.ingest_on(&mut buf[..n], 100, 0, &mut rng, &identity);

        assert_eq!(transport.link_table.len(), 1);

        // tick() before stale timeout — entry should remain
        transport.tick(100 + crate::link::STALE_TIMEOUT_SECS);
        assert_eq!(transport.link_table.len(), 1, "should not expire yet");

        // tick() after stale timeout — entry should be removed
        transport.tick(100 + crate::link::STALE_TIMEOUT_SECS + 1);
        assert_eq!(
            transport.link_table.len(),
            0,
            "should expire after stale timeout"
        );
    }

    #[test]
    fn test_multiple_link_data_forwarded_via_link_table() {
        // Verify that multiple DATA packets can be forwarded (entry persists)
        let relay_hash = IdentityHash::from([0x11u8; TRUNCATED_HASH_LEN]);
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);
        let mut transport = make_relay_transport(relay_hash, dest_hash);
        let identity = Identity::from_seed(b"relay-multi-test").unwrap();
        let mut rng = rand_core::OsRng;

        // Forward LINKREQUEST
        let lr_payload = [0xBBu8; 64];
        let (mut buf, n) = build_h2_linkrequest(&relay_hash, &dest_hash, &lr_payload);
        let link_id = compute_link_id(&buf[..n]).unwrap();
        transport.ingest_on(&mut buf[..n], 100, 0, &mut rng, &identity);

        // Forward 5 DATA packets — all should succeed
        for i in 0u8..5 {
            let mut data_buf = [0u8; rete_core::MTU];
            let data_len = PacketBuilder::new(&mut data_buf)
                .packet_type(PacketType::Data)
                .dest_type(DestType::Link)
                .destination_hash(link_id.as_ref())
                .context(0x00)
                .payload(&[i; 16])
                .build()
                .unwrap();

            let result = transport.ingest_on(
                &mut data_buf[..data_len],
                101 + i as u64,
                0,
                &mut rng,
                &identity,
            );

            assert!(
                matches!(result, IngestResult::Forward { .. }),
                "DATA packet {} should be forwarded",
                i
            );
        }

        // link_table entry should still exist
        assert_eq!(transport.link_table.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Link relay correctness: hop counts, direction, interface tracking
    // (Bugs found via Python RNS reference comparison)
    // -----------------------------------------------------------------------

    #[test]
    fn test_h2_link_table_stores_post_increment_hops() {
        // Bug A: H2 handler captured inbound_hops BEFORE incrementing raw[1].
        // Python stores post-increment (Transport.py:1319,1488).
        let relay_hash = IdentityHash::from([0x11u8; TRUNCATED_HASH_LEN]);
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);
        let mut transport = make_relay_transport(relay_hash, dest_hash);
        let identity = Identity::from_seed(b"relay-hops-test").unwrap();
        let mut rng = rand_core::OsRng;

        // Build H2 LINKREQUEST with hops=0 (freshly sent by initiator)
        let lr_payload = [0xBBu8; 64];
        let (mut buf, n) = build_h2_linkrequest(&relay_hash, &dest_hash, &lr_payload);
        assert_eq!(buf[1], 0, "initial hops should be 0");

        let link_id = compute_link_id(&buf[..n]).unwrap();
        transport.ingest_on(&mut buf[..n], 100, 0, &mut rng, &identity);

        // After processing, the relay incremented hops (0 -> 1).
        // The stored inbound_hops must be the POST-increment value (1),
        // matching Python's behavior.
        let entry = transport
            .link_table
            .get(&link_id)
            .expect("link_table entry");
        assert_eq!(
            entry.inbound_hops, 1,
            "H2 link_table inbound_hops should be post-increment (1), not pre-increment (0)"
        );
    }

    #[test]
    fn test_link_data_rejected_with_wrong_hop_count() {
        // Bug B: Rust used hops <= max_hops (lax). Python uses exact match
        // (Transport.py:1530-1537). Wrong hop count must be rejected.
        let relay_hash = IdentityHash::from([0x11u8; TRUNCATED_HASH_LEN]);
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);
        let mut transport = make_relay_transport(relay_hash, dest_hash);
        let identity = Identity::from_seed(b"relay-exact-hops-test").unwrap();
        let mut rng = rand_core::OsRng;

        // Forward LINKREQUEST from iface 0 (initiator side)
        let lr_payload = [0xBBu8; 64];
        let (mut buf, n) = build_h2_linkrequest(&relay_hash, &dest_hash, &lr_payload);
        let link_id = compute_link_id(&buf[..n]).unwrap();
        transport.ingest_on(&mut buf[..n], 100, 0, &mut rng, &identity);

        let entry = transport.link_table.get(&link_id).expect("entry exists");
        let expected_inbound = entry.inbound_hops;
        let expected_outbound = entry.outbound_hops;

        // Send link DATA from initiator side (iface 0) with CORRECT hops.
        // After the global +1 at line 986, pkt.hops should match inbound_hops.
        // Build with hops = expected_inbound - 1 (pre-increment, since ingest adds 1).
        let correct_hops = expected_inbound.saturating_sub(1);
        let mut data_buf = [0u8; rete_core::MTU];
        let data_len = PacketBuilder::new(&mut data_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Link)
            .destination_hash(link_id.as_ref())
            .hops(correct_hops)
            .context(CONTEXT_CHANNEL)
            .payload(&[0x42; 16])
            .build()
            .unwrap();

        let result = transport.ingest_on(&mut data_buf[..data_len], 101, 0, &mut rng, &identity);
        assert!(
            matches!(result, IngestResult::Forward { .. }),
            "Link DATA with correct hops should be forwarded"
        );

        // Now send from responder side (iface 1) with WRONG hops.
        // Use a hops value that's within max_hops range but doesn't
        // match the exact expected value.
        let wrong_hops = expected_outbound.saturating_add(1); // off by 1
        let mut bad_buf = [0u8; rete_core::MTU];
        let bad_len = PacketBuilder::new(&mut bad_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Link)
            .destination_hash(link_id.as_ref())
            .hops(wrong_hops)
            .context(CONTEXT_CHANNEL)
            .payload(&[0x43; 16])
            .build()
            .unwrap();

        let result = transport.ingest_on(&mut bad_buf[..bad_len], 102, 1, &mut rng, &identity);
        assert!(
            !matches!(result, IngestResult::Forward { .. }),
            "Link DATA with wrong hop count should NOT be forwarded (exact match required)"
        );
    }

    #[test]
    fn test_link_table_tracks_outbound_interface() {
        // Bug C: LinkTableEntry must track the outbound interface (toward
        // responder) so bidirectional routing can validate packet direction,
        // matching Python's IDX_LT_NH_IF.
        let relay_hash = IdentityHash::from([0x11u8; TRUNCATED_HASH_LEN]);
        let dest_hash = DestHash::from([0xAAu8; TRUNCATED_HASH_LEN]);
        let mut transport = make_relay_transport(relay_hash, dest_hash);
        let identity = Identity::from_seed(b"relay-iface-test").unwrap();
        let mut rng = rand_core::OsRng;

        // Forward LINKREQUEST received on iface 0 (toward initiator)
        let lr_payload = [0xBBu8; 64];
        let (mut buf, n) = build_h2_linkrequest(&relay_hash, &dest_hash, &lr_payload);
        let link_id = compute_link_id(&buf[..n]).unwrap();
        transport.ingest_on(&mut buf[..n], 100, 0, &mut rng, &identity);

        let entry = transport.link_table.get(&link_id).expect("entry exists");

        // received_on should be 0 (the interface the LINKREQUEST arrived on)
        assert_eq!(entry.received_on, 0, "received_on should be iface 0");

        // outbound_to should be set (from Path.received_on which is set
        // during announce processing). In this test, the path was created
        // via make_relay_transport → Path::direct() which has received_on=None,
        // so outbound_to defaults to 0. In production, the announce handler
        // sets path.received_on = Some(iface) so outbound_to is correct.
        assert!(
            transport.link_table.get(&link_id).unwrap().outbound_to == 0
                || transport.link_table.get(&link_id).unwrap().outbound_to != entry.received_on,
            "outbound_to field should exist and be set"
        );
    }

    // -----------------------------------------------------------------------
    // Link lifecycle tests (keepalive, stale expiry)
    // -----------------------------------------------------------------------

    /// Helper: create a transport with one active link via the handshake flow.
    /// Returns (transport, link_id, responder_identity).
    fn make_transport_with_active_link(
        now: u64,
    ) -> (TestTransport, LinkId, Identity) {
        let mut transport = TestTransport::new();
        let mut rng = rand_core::OsRng;

        let initiator_identity = Identity::from_seed(b"transport-test-initiator").unwrap();
        let responder_identity = Identity::from_seed(b"transport-test-responder").unwrap();

        // Compute the destination hash for the responder
        let id_hash = responder_identity.hash();
        let dest_hash = rete_core::destination_hash("test.link.target", Some(&id_hash));

        // Register the responder's identity so validate_proof can look it up
        transport.register_identity(dest_hash, responder_identity.public_key(), now);

        // Initiate a link (creates a Pending/Handshake link)
        let (lr_raw, link_id) = transport
            .initiate_link(dest_hash, &initiator_identity, &mut rng, now)
            .expect("initiate_link should succeed");

        // Parse the LINKREQUEST to extract the initiator's payload
        let lr_pkt = rete_core::Packet::parse(&lr_raw).unwrap();
        // Determine raw payload offset: for HEADER_2 packets, strip the
        // transport_id prefix that PacketBuilder may have added.
        let request_payload = lr_pkt.payload;

        // Responder creates a link from the request
        let responder_link = Link::from_request(link_id, request_payload, &mut rng, now).unwrap();

        // Responder builds LRPROOF
        let proof_payload = responder_link.build_proof(&responder_identity).unwrap();

        // Build an LRPROOF packet and feed it through ingest to complete the handshake
        let mut proof_buf = [0u8; rete_core::MTU];
        let proof_len = PacketBuilder::new(&mut proof_buf)
            .packet_type(PacketType::Proof)
            .dest_type(DestType::Link)
            .destination_hash(link_id.as_ref())
            .context(CONTEXT_LRPROOF)
            .payload(&proof_payload)
            .build()
            .unwrap();

        let result = transport.ingest_on(
            &mut proof_buf[..proof_len],
            now,
            0,
            &mut rng,
            &initiator_identity,
        );
        assert!(
            matches!(result, IngestResult::LinkEstablished { .. }),
            "handshake should complete, got {:?}",
            core::mem::discriminant(&result)
        );

        // Verify link is active
        let link = transport.get_link(&link_id).unwrap();
        assert!(link.is_active());

        (transport, link_id, responder_identity)
    }

    #[test]
    fn test_tick_expires_stale_link() {
        let now = 1000u64;
        let (mut transport, link_id, _) = make_transport_with_active_link(now);
        assert_eq!(transport.link_count(), 1);

        let stale_time = transport.get_link(&link_id).unwrap().stale_time;

        // tick before stale_time — link should remain
        let result = transport.tick(now + stale_time);
        assert_eq!(result.closed_links, 0);
        assert_eq!(transport.link_count(), 1);

        // tick after stale_time — link should be closed and removed
        let result = transport.tick(now + stale_time + 1);
        assert_eq!(result.closed_links, 1);
        assert_eq!(transport.link_count(), 0);
    }

    #[test]
    fn test_keepalive_updates_last_outbound() {
        let now = 1000u64;
        let (mut transport, link_id, _) = make_transport_with_active_link(now);
        let mut rng = rand_core::OsRng;

        let keepalive_interval = transport.get_link(&link_id).unwrap().keepalive_interval;

        // At now + keepalive/2 + 1, the link should need a keepalive
        let ka_time = now + keepalive_interval / 2 + 1;
        let packets = transport.build_pending_keepalives(ka_time, &mut rng);
        assert!(
            !packets.is_empty(),
            "should produce at least one keepalive packet"
        );

        // Verify last_outbound was updated
        let link = transport.get_link(&link_id).unwrap();
        assert_eq!(
            link.last_outbound, ka_time,
            "last_outbound should be updated to keepalive time"
        );
    }

    #[test]
    fn test_build_keepalive_request_vs_response() {
        let now = 1000u64;
        let (mut transport, link_id, _) = make_transport_with_active_link(now);
        let mut rng = rand_core::OsRng;

        // Build a keepalive request
        let request_raw = transport
            .build_keepalive_packet(&link_id, true, &mut rng)
            .expect("should build keepalive request");

        // Build a keepalive response
        let response_raw = transport
            .build_keepalive_packet(&link_id, false, &mut rng)
            .expect("should build keepalive response");

        // Parse both and verify they are CONTEXT_KEEPALIVE link packets
        let req_pkt = rete_core::Packet::parse(&request_raw).expect("should parse request");
        assert_eq!(req_pkt.dest_type, DestType::Link);
        assert_eq!(req_pkt.context, CONTEXT_KEEPALIVE);
        assert_eq!(req_pkt.destination_hash, link_id.as_ref());

        let resp_pkt = rete_core::Packet::parse(&response_raw).expect("should parse response");
        assert_eq!(resp_pkt.dest_type, DestType::Link);
        assert_eq!(resp_pkt.context, CONTEXT_KEEPALIVE);
        assert_eq!(resp_pkt.destination_hash, link_id.as_ref());
    }

    #[test]
    fn test_transport_stats_announce_ingest() {
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let mut rng = StdRng::seed_from_u64(42);

        // Sender identity — builds the announce
        let sender = Identity::from_seed(b"stats-test-sender").unwrap();

        // Build a raw announce packet
        let mut announce_buf = [0u8; rete_core::MTU];
        let announce_len = TestTransport::create_announce(
            &sender,
            "test",
            &["stats"],
            None,
            None,
            &mut rng,
            1000,
            &mut announce_buf,
        )
        .expect("should build announce");

        // Receiver transport — receives the announce
        let receiver_identity = Identity::from_seed(b"stats-test-receiver").unwrap();
        let mut transport = TestTransport::new();

        // Before any ingest, all stats should be zero
        assert_eq!(transport.stats().packets_received, 0);
        assert_eq!(transport.stats().announces_received, 0);
        assert_eq!(transport.stats().paths_learned, 0);
        assert_eq!(transport.stats().packets_dropped_dedup, 0);
        assert_eq!(transport.stats().packets_dropped_invalid, 0);

        // Ingest the announce
        let result = transport.ingest(
            &mut announce_buf[..announce_len],
            1000,
            &mut rng,
            &receiver_identity,
        );
        assert!(
            matches!(result, IngestResult::AnnounceReceived { .. }),
            "expected AnnounceReceived, got {:?}",
            result,
        );

        // Verify counters were incremented
        assert_eq!(transport.stats().packets_received, 1, "packets_received");
        assert_eq!(
            transport.stats().announces_received,
            1,
            "announces_received"
        );
        assert_eq!(transport.stats().paths_learned, 1, "paths_learned");
        assert_eq!(transport.stats().packets_dropped_dedup, 0, "no dedup yet");
        assert_eq!(transport.stats().packets_dropped_invalid, 0, "no invalid");
        assert_eq!(transport.stats().started_at, 1000, "started_at");

        // Rebuild the same announce (same raw bytes) and ingest again — should be dedup
        let mut announce_buf2 = announce_buf;
        let result2 = transport.ingest(
            &mut announce_buf2[..announce_len],
            1001,
            &mut rng,
            &receiver_identity,
        );
        assert!(
            matches!(result2, IngestResult::Duplicate),
            "expected Duplicate on second ingest",
        );

        // Parse succeeds before the dedup check, so packets_received increments; then dedup fires.
        assert_eq!(transport.stats().packets_dropped_dedup, 1, "dedup counter");
        // announces_received should stay at 1 (dedup fires before announce processing)
        assert_eq!(transport.stats().announces_received, 1, "still 1 announce");
    }

    #[test]
    fn test_create_announce_with_ratchet() {
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let mut rng = StdRng::seed_from_u64(99);
        let sender = Identity::from_seed(b"ratchet-announce-sender").unwrap();
        let ratchet_pub = [0x42u8; 32];

        let mut buf = [0u8; rete_core::MTU];
        let n = TestTransport::create_announce(
            &sender,
            "test",
            &["ratchet"],
            None,
            Some(&ratchet_pub),
            &mut rng,
            1000,
            &mut buf,
        )
        .expect("should build ratchet announce");

        // Parse and verify context_flag is set
        let pkt = rete_core::Packet::parse(&buf[..n]).expect("should parse");
        assert!(pkt.context_flag, "context_flag should be set for ratchet announce");
        assert_eq!(pkt.packet_type, rete_core::PacketType::Announce);

        // Validate the announce and check ratchet is extracted
        let info = crate::announce::validate_announce(
            pkt.destination_hash,
            pkt.payload,
            pkt.context_flag,
        )
        .expect("should validate");
        assert!(info.ratchet.is_some(), "ratchet should be present");
        assert_eq!(info.ratchet.unwrap(), &ratchet_pub[..]);
    }

    #[test]
    fn test_announce_without_ratchet_has_none() {
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let mut rng = StdRng::seed_from_u64(100);
        let sender = Identity::from_seed(b"no-ratchet-sender").unwrap();

        let mut buf = [0u8; rete_core::MTU];
        let n = TestTransport::create_announce(
            &sender,
            "test",
            &["noratchet"],
            None,
            None,
            &mut rng,
            1000,
            &mut buf,
        )
        .expect("should build announce");

        let pkt = rete_core::Packet::parse(&buf[..n]).expect("should parse");
        assert!(!pkt.context_flag, "context_flag should NOT be set");

        let info = crate::announce::validate_announce(
            pkt.destination_hash,
            pkt.payload,
            pkt.context_flag,
        )
        .expect("should validate");
        assert!(info.ratchet.is_none(), "ratchet should be None");
    }

    #[test]
    fn test_ingest_ratchet_announce_returns_ratchet() {
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let mut rng = StdRng::seed_from_u64(101);
        let sender = Identity::from_seed(b"ratchet-ingest-sender").unwrap();
        let receiver = Identity::from_seed(b"ratchet-ingest-receiver").unwrap();
        let ratchet_pub = [0xAB; 32];

        let mut buf = [0u8; rete_core::MTU];
        let n = TestTransport::create_announce(
            &sender,
            "test",
            &["ratchet"],
            None,
            Some(&ratchet_pub),
            &mut rng,
            1000,
            &mut buf,
        )
        .expect("should build");

        let mut transport = TestTransport::new();
        let result = transport.ingest(&mut buf[..n], 1000, &mut rng, &receiver);

        match result {
            IngestResult::AnnounceReceived { ratchet, .. } => {
                assert_eq!(ratchet, Some(ratchet_pub), "ratchet should be passed through");
            }
            other => panic!("expected AnnounceReceived, got {:?}", other),
        }
    }
}
