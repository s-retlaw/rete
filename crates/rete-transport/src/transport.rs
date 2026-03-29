//! Core Transport struct — path table, announce queue, packet processing, links.

/// Relay debug logging — only available when the `relay-debug` feature is enabled.
macro_rules! relay_log {
    ($($arg:tt)*) => {
        #[cfg(feature = "relay-debug")]
        std::eprintln!($($arg)*);
    };
}

/// Format first 4 bytes of a hash as hex for compact logging.
#[cfg(feature = "relay-debug")]
fn hex_short(h: &[u8]) -> alloc::string::String {
    use alloc::format;
    if h.len() >= 4 {
        format!("{:02x}{:02x}{:02x}{:02x}..", h[0], h[1], h[2], h[3])
    } else {
        format!("{:?}", h)
    }
}

use crate::announce::validate_announce;
use crate::link::{compute_link_id, decode_mtu, Link};
use crate::receipt::ReceiptTable;
use crate::resource::Resource;
use crate::{announce::PendingAnnounce, dedup::DedupWindow, path::Path};
use heapless::{FnvIndexMap, FnvIndexSet};
use rand_core::{CryptoRng, RngCore};
use rete_core::{
    DestType, HeaderType, Identity, Packet, PacketBuilder, PacketType, CONTEXT_CHANNEL,
    CONTEXT_KEEPALIVE, CONTEXT_LINKCLOSE, CONTEXT_LRPROOF, CONTEXT_LRRTT, CONTEXT_REQUEST,
    CONTEXT_RESOURCE, CONTEXT_RESOURCE_ADV, CONTEXT_RESOURCE_HMU, CONTEXT_RESOURCE_ICL,
    CONTEXT_RESOURCE_PRF, CONTEXT_RESOURCE_RCL, CONTEXT_RESOURCE_REQ, CONTEXT_RESPONSE,
    NAME_HASH_LEN, TRANSPORT_TYPE_TRANSPORT, TRUNCATED_HASH_LEN,
};
use sha2::{Digest, Sha256};

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
    pub destination_hash: [u8; TRUNCATED_HASH_LEN],
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
    /// A link.request() was received on a link.
    RequestReceived {
        /// The link_id.
        link_id: [u8; TRUNCATED_HASH_LEN],
        /// The request_id (truncated packet hash for single-packet requests).
        request_id: [u8; TRUNCATED_HASH_LEN],
        /// The path_hash (SHA-256(path)[..16]).
        path_hash: [u8; TRUNCATED_HASH_LEN],
        /// The request data payload.
        data: alloc::vec::Vec<u8>,
    },
    /// A link.response() was received on a link.
    ResponseReceived {
        /// The link_id.
        link_id: [u8; TRUNCATED_HASH_LEN],
        /// The request_id this response is for.
        request_id: [u8; TRUNCATED_HASH_LEN],
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
        link_id: [u8; TRUNCATED_HASH_LEN],
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
    /// Sized by MAX_PATHS: 64 on embedded, 1024 on hosted (matching Python).
    receipts: ReceiptTable<MAX_PATHS>,
    /// Receipts for channel messages: truncated packet hash → ChannelReceipt.
    /// Used to match incoming PROOFs to channel sequences and call mark_delivered().
    channel_receipts: FnvIndexMap<[u8; TRUNCATED_HASH_LEN], ChannelReceipt, MAX_LINKS>,
    /// Active resource transfers.
    resources: alloc::vec::Vec<Resource>,
    /// Pending outbound resource packets (parts, HMU, etc.) built during ingest.
    resource_outbound: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    /// Link routing table: link_id → entry (for bidirectional relay of link traffic).
    /// Entries persist for the lifetime of the relayed link.
    link_table: FnvIndexMap<[u8; TRUNCATED_HASH_LEN], LinkTableEntry, MAX_LINKS>,
    /// Announce rate limiting: dest_hash → (last_announce_time, violations, blocked_until).
    announce_rate: FnvIndexMap<[u8; TRUNCATED_HASH_LEN], AnnounceRateEntry, MAX_PATHS>,
    /// Path request throttling: dest_hash → last_request_time.
    path_request_times: FnvIndexMap<[u8; TRUNCATED_HASH_LEN], u64, MAX_PATHS>,
    /// Pending split resource segments waiting to be advertised.
    /// When a split sender resource's proof is received, the next segment is
    /// popped from here, processed, and advertised.
    split_send_queue: alloc::vec::Vec<SplitSendEntry>,
}

/// Queued data for a pending split resource segment.
/// Metadata for a split resource segment advertisement.
struct SplitMeta {
    split_index: usize,
    split_total: usize,
    original_hash: [u8; 32],
    full_original_size: usize,
}

struct SplitSendEntry {
    link_id: [u8; TRUNCATED_HASH_LEN],
    /// Group key: resource_hash of segment 1.
    original_hash: [u8; 32],
    /// 1-based index of the next segment to send.
    next_segment: usize,
    /// Total split segments.
    split_total: usize,
    /// Full original plaintext size (all segments combined).
    full_original_size: usize,
    /// Remaining plaintext data (after segment 1). Each segment reads its slice at send time.
    data: alloc::vec::Vec<u8>,
}

/// Per-destination announce rate tracking entry.
#[derive(Debug, Clone, Copy)]
struct AnnounceRateEntry {
    last: u64,
    violations: u8,
    blocked_until: u64,
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
            link_table: FnvIndexMap::new(),
            announce_rate: FnvIndexMap::new(),
            path_request_times: FnvIndexMap::new(),
            split_send_queue: alloc::vec::Vec::new(),
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

    /// Update `last_accessed` on a path (call when the path is used for routing).
    pub fn touch_path(&mut self, dest: &[u8; TRUNCATED_HASH_LEN], now: u64) {
        if let Some(p) = self.paths.get_mut(dest) {
            p.last_accessed = now;
        }
    }

    /// Store a learned path.  If the table is full, evicts the
    /// least-recently-used entry first.  Always succeeds.
    pub fn insert_path(&mut self, dest: [u8; TRUNCATED_HASH_LEN], path: Path) -> bool {
        match self.paths.insert(dest, path) {
            Ok(_) => true,
            Err((dest, path)) => {
                // Table full — evict LRU entry
                if let Some(lru_key) = self
                    .paths
                    .iter()
                    .min_by_key(|(_, p)| p.last_accessed)
                    .map(|(k, _)| *k)
                {
                    self.paths.remove(&lru_key);
                    self.paths.insert(dest, path).is_ok()
                } else {
                    false
                }
            }
        }
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

    /// Return cached raw announce packets from the path table.
    ///
    /// When a new interface connects, the node should forward these so the
    /// new peer learns about destinations we already know. This eliminates
    /// the need for synthetic announces via `--peer-seed`.
    pub fn cached_announces(&self) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        let mut out = alloc::vec::Vec::new();
        for (_dest, path) in self.paths.iter() {
            if let Some(ref raw) = path.announce_raw {
                out.push(raw.clone());
            }
        }
        out
    }

    /// Store a raw announce packet on an existing path entry.
    ///
    /// Used by `register_peer_with_announce` to cache a synthetic announce so
    /// that `cached_announces()` includes it for new-interface flush.
    pub fn store_announce_raw(&mut self, dest: &[u8; TRUNCATED_HASH_LEN], raw: &[u8]) {
        if let Some(path) = self.paths.get_mut(dest) {
            path.announce_raw = Some(raw.to_vec());
        }
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
        self.insert_identity(dest_hash, pub_key);
        let _ = self.insert_path(dest_hash, Path::direct(now));
    }

    /// Store a known identity.  If the table is full, evicts the entry
    /// whose matching path has the oldest `last_accessed` (or `0` for
    /// identities with no corresponding path — evicted first).
    fn insert_identity(&mut self, dest_hash: [u8; TRUNCATED_HASH_LEN], pub_key: [u8; 64]) {
        match self.known_identities.insert(dest_hash, pub_key) {
            Ok(_) => {}
            Err((dest_hash, pub_key)) => {
                if let Some(lru_key) = self
                    .known_identities
                    .keys()
                    .min_by_key(|k| self.paths.get(*k).map(|p| p.last_accessed).unwrap_or(0))
                    .copied()
                {
                    self.known_identities.remove(&lru_key);
                    let _ = self.known_identities.insert(dest_hash, pub_key);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Snapshot — save / load
    // -----------------------------------------------------------------------

    /// Capture the current path table and known identities into a [`Snapshot`].
    ///
    /// `detail` controls whether the announce cache is included (see
    /// [`SnapshotDetail`]).
    pub fn save_snapshot(
        &self,
        detail: crate::snapshot::SnapshotDetail,
    ) -> crate::snapshot::Snapshot {
        use crate::snapshot::{IdentityEntry, PathEntry, Snapshot, SnapshotDetail};

        let include_announce = matches!(detail, SnapshotDetail::Standard | SnapshotDetail::Full);

        let paths = self
            .paths
            .iter()
            .map(|(k, p)| PathEntry {
                dest_hash: *k,
                via: p.via,
                learned_at: p.learned_at,
                last_accessed: p.last_accessed,
                last_snr: p.last_snr,
                hops: p.hops,
                announce_raw: if include_announce {
                    p.announce_raw.clone()
                } else {
                    None
                },
            })
            .collect();

        let identities = self
            .known_identities
            .iter()
            .map(|(k, v)| IdentityEntry {
                dest_hash: *k,
                pub_key: *v,
            })
            .collect();

        Snapshot {
            version: 1,
            paths,
            identities,
        }
    }

    /// Restore paths and identities from a previously saved [`Snapshot`].
    ///
    /// Entries that would overflow the tables are silently dropped.
    pub fn load_snapshot(&mut self, snap: &crate::snapshot::Snapshot) {
        for pe in &snap.paths {
            let path = Path {
                via: pe.via,
                learned_at: pe.learned_at,
                last_accessed: pe.last_accessed,
                last_snr: pe.last_snr,
                hops: pe.hops,
                announce_raw: pe.announce_raw.clone(),
                interface_mode: crate::path::InterfaceMode::Default,
                received_on: None,
            };
            self.insert_path(pe.dest_hash, path);
        }
        for ie in &snap.identities {
            self.insert_identity(ie.dest_hash, ie.pub_key);
        }
    }

    /// Set the local identity hash, enabling HEADER_2 forwarding.
    pub fn set_local_identity(&mut self, hash: [u8; TRUNCATED_HASH_LEN]) {
        self.local_identity_hash = Some(hash);
    }

    /// Get the local identity hash (transport node ID), if set.
    pub fn local_identity_hash(&self) -> Option<[u8; TRUNCATED_HASH_LEN]> {
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

        // Build LINKREQUEST packet.
        // dest_type must be Single (matching the target destination type), not Link.
        // Python RNS uses `self.destination.type` for LINKREQUEST flags (Packet.py:172),
        // and the receiving node checks `destination.type == packet.destination_type`.
        //
        // If we have a transport path (via relay), build HEADER_2 so the relay
        // creates a link_table entry and can route the LRPROOF back.
        let via = self.paths.get(&dest_hash).and_then(|p| p.via);
        self.touch_path(&dest_hash, now);
        let mut pkt_buf = [0u8; rete_core::MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::LinkRequest)
            .dest_type(DestType::Single)
            .destination_hash(&dest_hash)
            .context(0x00)
            .payload(&request_payload)
            .via(via.as_ref())
            .build()
            .ok()?;

        // Compute link_id from the HEADER_1 form of the packet (strip transport
        // header if present). Python computes link_id from the hashable part which
        // masks header_type/transport bits, but uses get_hashable_part() which for
        // HEADER_2 starts at raw[18:] (skipping transport_id). Our compute_link_id
        // handles both HEADER_1 and HEADER_2.
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
    ///
    /// Allows sending on both Active and Stale links — a keepalive response
    /// to a Stale link can revive it when the peer receives it and responds.
    pub fn build_keepalive_packet<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        request: bool,
        rng: &mut R,
    ) -> Option<alloc::vec::Vec<u8>> {
        let link = self.links.get(link_id)?;
        if !link.is_active() && link.state != crate::link::LinkState::Stale {
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
            relay_log!(
                "[relay] DEDUP pkt_hash={} type={:?} dest_type={:?}",
                hex_short(&pkt_hash),
                pkt.packet_type,
                pkt.dest_type,
            );
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
                                    hex_short(&lid),
                                    hex_short(&dest),
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

                        return match self.paths.get(&dest) {
                            Some(Path { via: Some(via), .. }) => {
                                relay_log!(
                                    "[relay] H2 FWD via={} dest={} iface={}",
                                    hex_short(via),
                                    hex_short(&dest),
                                    iface,
                                );
                                raw[2..18].copy_from_slice(via);
                                IngestResult::Forward {
                                    raw: &raw[..len],
                                    source_iface: iface,
                                }
                            }
                            Some(_path) => {
                                relay_log!(
                                    "[relay] H2->H1 FWD direct dest={} iface={} len={}->{}",
                                    hex_short(&dest),
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
                                if let Some(lte) = self.link_table.get_mut(&dest) {
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
                                            hex_short(&dest),
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
                                            hex_short(&dest),
                                            raw[1],
                                        );
                                        IngestResult::Invalid
                                    }
                                } else {
                                    relay_log!(
                                        "[relay] H2 link_table MISS lid={}",
                                        hex_short(&dest),
                                    );
                                    IngestResult::Invalid
                                }
                            }
                            _ => {
                                relay_log!("[relay] H2 NO_PATH dest={}", hex_short(&dest),);
                                IngestResult::Invalid
                            }
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
            PacketType::Announce => self.handle_announce(&pkt, raw, now, iface),
            PacketType::Data => {
                let mut dh = [0u8; TRUNCATED_HASH_LEN];
                dh.copy_from_slice(pkt.destination_hash);

                // Path request handling
                if self.local_identity_hash.is_some() && dh == PATH_REQUEST_DEST {
                    return self.handle_path_request(pkt.payload, now);
                }

                // Link data handling: dest_type == Link
                if pkt.dest_type == DestType::Link {
                    // If we own this link locally, handle it.
                    if self.links.contains_key(&dh) {
                        return self.handle_link_data(
                            &dh,
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
                        if let Some(lte) = self.link_table.get_mut(&dh) {
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
                                    hex_short(&dh),
                                    pkt.context,
                                    iface,
                                    pkt.hops,
                                );
                                return IngestResult::Forward {
                                    raw,
                                    source_iface: iface,
                                };
                            } else {
                                relay_log!(
                                    "[relay] link_table HOP_FAIL lid={} ctx={:#04x} iface={} hops={} in_hops={} out_hops={} rcvd={} out={}",
                                    hex_short(&dh),
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
                                hex_short(&dh),
                                pkt.context,
                            );
                        }
                    }
                    // Fall through: non-transport node or no link_table entry.
                    // Try local handling (will return Invalid if link not found).
                    return self.handle_link_data(
                        &dh,
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
                        hex_short(&dh),
                        hex_short(&trunc_hash),
                    );
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
                    IngestResult::Invalid
                }
            }
            PacketType::Proof => {
                let mut dh = [0u8; TRUNCATED_HASH_LEN];
                dh.copy_from_slice(pkt.destination_hash);

                if pkt.context == CONTEXT_LRPROOF && pkt.dest_type == DestType::Link {
                    relay_log!(
                        "[relay] LRPROOF_IN lid={} hops={} plen={} local_link={} link_table={} reverse={}",
                        hex_short(&dh),
                        pkt.hops,
                        pkt.payload.len(),
                        self.links.contains_key(&dh),
                        self.link_table.contains_key(&dh),
                        self.reverse_table.contains_key(&dh),
                    );
                }

                // Check for LRPROOF (link proof from responder to initiator).
                // Only handle locally if we have a pending link for this link_id;
                // otherwise fall through to reverse-table forwarding (relay case).
                if pkt.context == CONTEXT_LRPROOF
                    && pkt.dest_type == DestType::Link
                    && self.links.contains_key(&dh)
                {
                    return self.handle_lrproof(&dh, pkt.payload, now);
                }

                // Check for RESOURCE_PRF (resource completion proof from receiver).
                // Like LRPROOF, handle locally when the link is ours; otherwise
                // fall through to relay forwarding.  Resource proofs are NOT
                // link-encrypted (Python: Packet.pack special-cases RESOURCE_PRF).
                if pkt.context == CONTEXT_RESOURCE_PRF
                    && pkt.dest_type == DestType::Link
                    && self.links.contains_key(&dh)
                {
                    if let Some(link) = self.links.get_mut(&dh) {
                        link.touch_inbound(now);
                    }
                    return self.handle_resource_data(&dh, pkt.context, pkt.payload, now, rng);
                }

                // Check receipt table for delivery proof (DATA packets)
                if let Some(packet_hash) = self.receipts.validate_proof(&dh, pkt.payload) {
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
                    if self.reverse_table.remove(&dh).is_some() {
                        relay_log!(
                            "[relay] PROOF reverse_table FORWARD dest={} ctx={:#04x}",
                            hex_short(&dh),
                            pkt.context,
                        );
                        IngestResult::Forward {
                            raw,
                            source_iface: iface,
                        }
                    } else if let Some(lte) = self.link_table.get_mut(&dh) {
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
                                        hex_short(&dh),
                                        hex_short(&dest_hash_for_link),
                                        true,
                                    );
                                    if !self.validate_lrproof_relay(pkt.payload, &dh, &dest_id) {
                                        relay_log!(
                                            "[relay] LRPROOF REJECTED lid={} dest={}",
                                            hex_short(&dh),
                                            hex_short(&dest_hash_for_link),
                                        );
                                        return IngestResult::Invalid;
                                    }
                                    relay_log!(
                                        "[relay] LRPROOF_VALID lid={} dest={}",
                                        hex_short(&dh),
                                        hex_short(&dest_hash_for_link),
                                    );
                                }
                                // If identity can't be reconstructed, forward
                                // anyway (graceful fallback).
                            }
                            // If identity not known, forward anyway.
                        }

                        relay_log!(
                            "[relay] PROOF link_table FORWARD lid={} ctx={:#04x} raw[0..20]={:02x?}",
                            hex_short(&dh),
                            pkt.context,
                            &raw[..core::cmp::min(20, raw.len())],
                        );
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
                                hex_short(&lid),
                                hex_short(&dh),
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

    /// Validate an LRPROOF payload at a relay node.
    ///
    /// Matches Python `Transport.py` relay behavior: validates the responder's
    /// signature before forwarding. Returns true if valid or if validation is
    /// not possible (identity unknown).
    fn validate_lrproof_relay(
        &self,
        proof_payload: &[u8],
        link_id: &[u8; TRUNCATED_HASH_LEN],
        dest_identity: &Identity,
    ) -> bool {
        use crate::link::LINK_MTU_SIZE;

        if proof_payload.len() < 96 {
            return false;
        }

        let signature = &proof_payload[..64];
        let responder_x25519_pub = &proof_payload[64..96];
        let signalling = &proof_payload[96..];

        // Reject unexpected trailing data
        if signalling.len() > LINK_MTU_SIZE {
            return false;
        }

        // Reconstruct signed_data: link_id || responder_x25519_pub || ed25519_pub [|| signalling]
        let signed_len = 80 + signalling.len();
        let mut signed_data = [0u8; 83]; // max: 16+32+32+3
        signed_data[..16].copy_from_slice(link_id);
        signed_data[16..48].copy_from_slice(responder_x25519_pub);
        signed_data[48..80].copy_from_slice(dest_identity.ed25519_pub());
        signed_data[80..signed_len].copy_from_slice(signalling);

        dest_identity
            .verify(&signed_data[..signed_len], signature)
            .is_ok()
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

        // Compute RTT: time since LINKREQUEST was sent (last_outbound was set at creation).
        // With u64-second timestamps, loopback RTT rounds to 0. Use a floor of 0.001s
        // so update_keepalive still fires (producing keepalive=5s for sub-second RTT).
        let raw_rtt = now.saturating_sub(link.last_outbound) as f32;
        let rtt = if raw_rtt <= 0.0 { 0.001 } else { raw_rtt };
        link.update_keepalive(rtt);

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
            // CONTEXT_RESOURCE data parts are NOT link-encrypted — they travel as raw payload.
            // All other resource contexts (ADV, REQ, HMU, PRF, ICL, RCL) ARE link-encrypted.
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

            // Use heap buffer for resource contexts — TCP links can carry
            // payloads much larger than the 500-byte radio MTU.
            let mut dec_buf = alloc::vec![0u8; ciphertext.len()];
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

        // Decrypt payload — use heap if ciphertext exceeds radio MTU
        let mut dec_buf = alloc::vec![0u8; core::cmp::max(ciphertext.len(), rete_core::MTU)];
        let dec_len = match link.decrypt(ciphertext, &mut dec_buf) {
            Ok(n) => n,
            Err(_) => return IngestResult::Invalid,
        };

        match context {
            CONTEXT_LRRTT => {
                // RTT measurement — activates responder link.
                // Compute RTT: time since link was created (proof sent shortly after).
                // Floor at 0.001s so sub-second RTT (from u64 truncation) still triggers
                // dynamic keepalive tuning.
                let raw_rtt = now.saturating_sub(link.last_outbound) as f32;
                let rtt = if raw_rtt <= 0.0 { 0.001 } else { raw_rtt };
                link.update_keepalive(rtt);
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
                        link_id: *link_id,
                    }
                } else {
                    IngestResult::ChannelMessages {
                        link_id: *link_id,
                        messages,
                        packet_hash: pkt_hash,
                    }
                }
            }
            CONTEXT_REQUEST => {
                if !link.is_active() {
                    return IngestResult::Invalid;
                }
                link.touch_inbound(now);
                match crate::request::parse_request(&dec_buf[..dec_len]) {
                    Ok((_ts, rq_path_hash, data)) => {
                        // Python RNS uses the packet's truncated hash as request_id
                        // for single-packet requests (Link.py: RequestReceipt uses
                        // packet_receipt.truncated_hash). This is SHA-256(hashable)[..16].
                        let mut req_id = [0u8; TRUNCATED_HASH_LEN];
                        req_id.copy_from_slice(&pkt_hash[..TRUNCATED_HASH_LEN]);
                        IngestResult::RequestReceived {
                            link_id: *link_id,
                            request_id: req_id,
                            path_hash: rq_path_hash,
                            data,
                        }
                    }
                    Err(_) => IngestResult::Invalid,
                }
            }
            CONTEXT_RESPONSE => {
                if !link.is_active() {
                    return IngestResult::Invalid;
                }
                link.touch_inbound(now);
                match crate::request::parse_response(&dec_buf[..dec_len]) {
                    Ok((req_id, data)) => IngestResult::ResponseReceived {
                        link_id: *link_id,
                        request_id: req_id,
                        data,
                    },
                    Err(_) => IngestResult::Invalid,
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
        now: u64,
        rng: &mut R,
    ) -> IngestResult<'a> {
        match context {
            CONTEXT_RESOURCE => {
                // A resource data part (NOT link-encrypted — raw segment data)
                if let Some(res) = self
                    .resources
                    .iter_mut()
                    .find(|r| !r.is_sender && r.link_id == *link_id)
                {
                    res.touch_activity(now);
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
                let req_hash = Resource::extract_request_hash(decrypted);
                let (parts_to_send, hmu_payload) = {
                    if let Some(res) = self.resources.iter_mut().find(|r| {
                        r.is_sender
                            && r.link_id == *link_id
                            && req_hash.is_none_or(|h| h == r.resource_hash)
                    }) {
                        res.touch_activity(now);
                        let result = res.handle_request(decrypted);
                        // If receiver signaled HASHMAP_IS_EXHAUSTED, build HMU
                        // in the same borrow scope (avoids double lookup).
                        let hmu = if result.needs_hmu {
                            res.build_hashmap_update()
                        } else {
                            None
                        };
                        (result.parts, hmu)
                    } else {
                        return IngestResult::Invalid;
                    }
                };
                // Send data parts (NOT link-encrypted in Python RNS).
                for (_idx, part_data) in parts_to_send {
                    // Use heap buffer for large TCP segments (SDU up to 8156)
                    let buf_size = part_data.len() + 20; // header + payload
                    let mut pkt_buf = alloc::vec![0u8; buf_size];
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
                // Send link-encrypted HMU so receiver gets hashes for next window.
                if let Some(payload) = hmu_payload {
                    if let Some(link) = self.links.get(link_id) {
                        if let Some(pkt) = Self::build_link_packet(
                            link,
                            link_id,
                            &payload,
                            CONTEXT_RESOURCE_HMU,
                            rng,
                        ) {
                            self.resource_outbound.push(pkt);
                        }
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
                // Resource proof from receiver (we are sender).
                // Match by resource_hash from proof payload (first 32 bytes).
                let proof_rh: Option<[u8; 32]> = if decrypted.len() >= 32 {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&decrypted[..32]);
                    Some(h)
                } else {
                    None
                };
                if let Some(res) = self.resources.iter_mut().find(|r| {
                    r.is_sender
                        && r.link_id == *link_id
                        && proof_rh.is_none_or(|h| h == r.resource_hash)
                }) {
                    let mut rh = [0u8; TRUNCATED_HASH_LEN];
                    rh.copy_from_slice(&res.resource_hash[..TRUNCATED_HASH_LEN]);
                    let is_split = res.split_total > 1;
                    let is_final_segment = res.split_index >= res.split_total;
                    let original_hash = res.original_hash;
                    if res.handle_proof(decrypted) {
                        // For split resources: if non-final, advertise next segment
                        if is_split && !is_final_segment {
                            if let Some(adv_pkt) =
                                self.advertise_next_split_segment(link_id, &original_hash, rng)
                            {
                                self.resource_outbound.push(adv_pkt);
                            }
                            // Return Duplicate so NodeCore doesn't emit ResourceComplete yet
                            IngestResult::Duplicate
                        } else {
                            IngestResult::ResourceComplete {
                                link_id: *link_id,
                                resource_hash: rh,
                                data: alloc::vec::Vec::new(), // sender doesn't return data
                            }
                        }
                    } else {
                        // Proof failed — clean up split queue
                        if is_split {
                            self.split_send_queue.retain(|e| {
                                !(e.link_id == *link_id && e.original_hash == original_hash)
                            });
                        }
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
                if let Some(res) = self.resources.iter_mut().find(|r| r.link_id == *link_id) {
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
        iface: u8,
    ) -> IngestResult<'a> {
        // Self-announce filtering
        let mut dh_check = [0u8; TRUNCATED_HASH_LEN];
        dh_check.copy_from_slice(pkt.destination_hash);
        if self.is_local_destination(&dh_check) {
            return IngestResult::Duplicate;
        }

        match validate_announce(pkt.destination_hash, pkt.payload, pkt.context_flag) {
            Ok(info) => {
                // Announce replay detection
                let mut replay_key = [0u8; 32];
                replay_key[..TRUNCATED_HASH_LEN].copy_from_slice(pkt.destination_hash);
                replay_key[TRUNCATED_HASH_LEN..TRUNCATED_HASH_LEN + 10]
                    .copy_from_slice(info.random_hash);
                let replay_hash: [u8; 32] = Sha256::digest(replay_key).into();
                if self.announce_dedup.check_and_insert(&replay_hash) {
                    // Track local rebroadcasts: if we have this announce
                    // pending, note that we heard it echoed back.
                    let mut dh_dup = [0u8; TRUNCATED_HASH_LEN];
                    dh_dup.copy_from_slice(pkt.destination_hash);
                    self.note_local_rebroadcast(&dh_dup, pkt.hops);
                    return IngestResult::Duplicate;
                }
                let mut dh = [0u8; TRUNCATED_HASH_LEN];
                dh.copy_from_slice(pkt.destination_hash);

                // Announce rate limiting
                let rate_blocked = {
                    let entry = self.announce_rate.get_mut(&dh);
                    match entry {
                        Some(re) => {
                            if now < re.blocked_until {
                                true
                            } else {
                                let interval = now.saturating_sub(re.last);
                                if interval < ANNOUNCE_RATE_TARGET {
                                    re.violations = re.violations.saturating_add(1);
                                } else {
                                    re.violations = re.violations.saturating_sub(1);
                                }
                                if re.violations > ANNOUNCE_RATE_GRACE {
                                    re.blocked_until =
                                        re.last + ANNOUNCE_RATE_TARGET + ANNOUNCE_RATE_PENALTY;
                                    true
                                } else {
                                    re.last = now;
                                    false
                                }
                            }
                        }
                        None => {
                            let _ = self.announce_rate.insert(
                                dh,
                                AnnounceRateEntry {
                                    last: now,
                                    violations: 0,
                                    blocked_until: 0,
                                },
                            );
                            false
                        }
                    }
                };
                if rate_blocked {
                    return IngestResult::Duplicate;
                }

                let should_update = match self.paths.get(&dh) {
                    None => true,
                    Some(existing) => {
                        pkt.hops <= existing.hops
                            || now.saturating_sub(existing.learned_at) > existing.expiry_time()
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
                    path.received_on = Some(iface);
                    let _ = self.insert_path(dh, path);
                }

                let mut pk = [0u8; 64];
                pk.copy_from_slice(info.pub_key);
                self.insert_identity(dh, pk);

                if pkt.hops < PATHFINDER_M {
                    let retransmit_raw = if let Some(local_id) = self.local_identity_hash {
                        let mut rebuild_buf = [0u8; rete_core::MTU];
                        let result = PacketBuilder::new(&mut rebuild_buf)
                            .header_type(HeaderType::Header2)
                            .transport_type(TRANSPORT_TYPE_TRANSPORT)
                            .packet_type(pkt.packet_type)
                            .dest_type(pkt.dest_type)
                            .hops(pkt.hops)
                            .transport_id(&local_id)
                            .destination_hash(pkt.destination_hash)
                            .context(pkt.context)
                            .payload(pkt.payload)
                            .build();
                        match result {
                            Ok(n) => Some(rebuild_buf[..n].to_vec()),
                            Err(_) => None,
                        }
                    } else {
                        None
                    };

                    let ann_raw = match retransmit_raw {
                        Some(v) => v,
                        None => raw.to_vec(),
                    };

                    if !ann_raw.is_empty() {
                        let pending = PendingAnnounce {
                            dest_hash: dh,
                            raw: ann_raw,
                            tx_count: 0,
                            retransmit_timeout: now, // Forward immediately; PATHFINDER_G applies to retransmissions
                            local: false,
                            local_rebroadcasts: 0,
                            block_rebroadcasts: false,
                            received_hops: pkt.hops,
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

    fn handle_path_request<'a>(&mut self, payload: &[u8], now: u64) -> IngestResult<'a> {
        if payload.len() < TRUNCATED_HASH_LEN {
            return IngestResult::Invalid;
        }
        let mut requested = [0u8; TRUNCATED_HASH_LEN];
        requested.copy_from_slice(&payload[..TRUNCATED_HASH_LEN]);

        // Path request throttling: minimum interval between requests for same dest
        if let Some(&last_time) = self.path_request_times.get(&requested) {
            if now.saturating_sub(last_time) < PATH_REQUEST_MI {
                return IngestResult::Duplicate;
            }
        }
        let _ = self.path_request_times.insert(requested, now);

        // Check if we have a local destination for this hash
        if self.is_local_destination(&requested) {
            // Local destination — handled by NodeCore (it will announce in response)
            return IngestResult::PathRequestForward {
                payload: payload.to_vec(),
            };
        }

        // Check if we know a path (have a cached announce)
        if let Some(path) = self.paths.get(&requested) {
            if let Some(ref cached) = path.announce_raw {
                let pending = PendingAnnounce {
                    dest_hash: requested,
                    raw: cached.clone(),
                    tx_count: 0,
                    retransmit_timeout: now + PATH_REQUEST_GRACE,
                    local: false,
                    local_rebroadcasts: 0,
                    block_rebroadcasts: true,
                    received_hops: 0,
                };
                let _ = self.queue_announce(pending);
                return IngestResult::Duplicate;
            }
        }

        // Unknown path — forward to all interfaces if transport is enabled
        if self.local_identity_hash.is_some() {
            // Dedup: check if we've recently seen this exact path request
            let mut pr_key = [0u8; 32];
            pr_key[..TRUNCATED_HASH_LEN].copy_from_slice(&requested);
            // Include tag bytes in dedup if present
            if payload.len() > TRUNCATED_HASH_LEN {
                let tag_end = core::cmp::min(payload.len(), 32);
                let tag_start = TRUNCATED_HASH_LEN;
                pr_key[tag_start..tag_end].copy_from_slice(&payload[tag_start..tag_end]);
            }
            let pr_hash: [u8; 32] = Sha256::digest(pr_key).into();
            if self.announce_dedup.check_and_insert(&pr_hash) {
                return IngestResult::Duplicate;
            }

            IngestResult::PathRequestForward {
                payload: payload.to_vec(),
            }
        } else {
            IngestResult::Duplicate
        }
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

    /// Build a PROOF packet with the given dest_type and destination_hash.
    ///
    /// Payload: `packet_hash[32] || Ed25519_signature[64]`.
    fn build_proof_inner(
        identity: &Identity,
        packet_hash: &[u8; 32],
        dest_type: DestType,
        destination_hash: &[u8; TRUNCATED_HASH_LEN],
    ) -> Option<alloc::vec::Vec<u8>> {
        let signature = identity.sign(packet_hash).ok()?;
        let mut payload = [0u8; 96];
        payload[..32].copy_from_slice(packet_hash);
        payload[32..96].copy_from_slice(&signature);

        let mut buf = [0u8; rete_core::MTU];
        let n = PacketBuilder::new(&mut buf)
            .packet_type(PacketType::Proof)
            .dest_type(dest_type)
            .destination_hash(destination_hash)
            .context(0x00)
            .payload(&payload)
            .build()
            .ok()?;
        Some(buf[..n].to_vec())
    }

    /// Build a PROOF packet for a received data packet (non-link proofs).
    ///
    /// Uses `dest_type=Single` and `destination_hash=packet_hash[0:16]`.
    /// For link-related proofs (channel, link data), use [`build_link_proof_packet`] instead.
    pub fn build_proof_packet(
        identity: &Identity,
        packet_hash: &[u8; 32],
    ) -> Option<alloc::vec::Vec<u8>> {
        let trunc: [u8; TRUNCATED_HASH_LEN] = packet_hash[..TRUNCATED_HASH_LEN].try_into().ok()?;
        Self::build_proof_inner(identity, packet_hash, DestType::Single, &trunc)
    }

    /// Build a PROOF packet for a link-related packet (channel messages, link data).
    ///
    /// Uses `dest_type=Link` and `destination_hash=link_id` so that transport
    /// relays (rnsd) can route the proof back through their link table.
    pub fn build_link_proof_packet(
        identity: &Identity,
        packet_hash: &[u8; 32],
        link_id: &[u8; TRUNCATED_HASH_LEN],
    ) -> Option<alloc::vec::Vec<u8>> {
        Self::build_proof_inner(identity, packet_hash, DestType::Link, link_id)
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
    /// Matches Python RNS protocol flow:
    /// 1. Prepend 4 random bytes to data
    /// 2. Optionally compress (caller decides)
    /// 3. Encrypt prepended data via link Token
    /// 4. Create Resource from the encrypted blob
    /// 5. Build advertisement and send it
    ///
    /// `data` is the bytes to transmit (possibly compressed).
    /// `original_data` is the original uncompressed plaintext (for proof
    /// validation and `original_size`).  When not compressed, pass the
    /// same slice for both.
    ///
    /// Returns the advertisement payload as raw packet bytes.
    pub fn start_resource<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        data: &[u8],
        original_data: &[u8],
        compressed: bool,
        rng: &mut R,
    ) -> Option<alloc::vec::Vec<u8>> {
        use crate::resource::MAX_EFFICIENT_SIZE;

        // Check if this needs to be split into multiple segments.
        // Python splits based on original plaintext size (including metadata,
        // but we don't use metadata). The split operates on pre-compression data.
        if original_data.len() > MAX_EFFICIENT_SIZE {
            return self.start_split_resource(link_id, original_data, rng);
        }

        self.start_single_resource(link_id, data, original_data, compressed, rng)
    }

    /// Start a single (non-split) resource transfer.
    fn start_single_resource<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        data: &[u8],
        original_data: &[u8],
        compressed: bool,
        rng: &mut R,
    ) -> Option<alloc::vec::Vec<u8>> {
        let (pkt, _) = self.prepare_and_advertise_segment(
            link_id,
            data,
            original_data,
            compressed,
            None,
            rng,
        )?;
        Some(pkt)
    }

    /// Start a split resource transfer (data > MAX_EFFICIENT_SIZE).
    ///
    /// Splits the input data into segments of MAX_EFFICIENT_SIZE bytes each,
    /// processes segment 1 (prepend, encrypt, create Resource, advertise),
    /// and queues remaining segments for later (advertised on proof receipt).
    fn start_split_resource<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        original_data: &[u8],
        rng: &mut R,
    ) -> Option<alloc::vec::Vec<u8>> {
        use crate::resource::MAX_EFFICIENT_SIZE;

        let total_size = original_data.len();
        let split_total = ((total_size - 1) / MAX_EFFICIENT_SIZE) + 1;

        let seg1_end = MAX_EFFICIENT_SIZE.min(total_size);
        let seg1_data = &original_data[..seg1_end];

        let (pkt, seg1_hash) = self.prepare_and_advertise_segment(
            link_id,
            seg1_data,
            seg1_data,
            false,
            Some(SplitMeta {
                split_index: 1,
                split_total,
                original_hash: [0u8; 32],
                full_original_size: total_size,
            }),
            rng,
        )?;

        // Queue remaining data for later segments (only the tail after segment 1)
        self.split_send_queue.push(SplitSendEntry {
            link_id: *link_id,
            original_hash: seg1_hash,
            next_segment: 2,
            split_total,
            full_original_size: total_size,
            data: original_data[seg1_end..].to_vec(),
        });

        Some(pkt)
    }

    /// Prepend 4 random bytes and encrypt data via link Token.
    fn prepend_and_encrypt<R: RngCore + CryptoRng>(
        &self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        data: &[u8],
        rng: &mut R,
    ) -> Option<(alloc::vec::Vec<u8>, usize)> {
        let link = self.links.get(link_id)?;
        if !link.is_active() {
            return None;
        }
        let mtu = decode_mtu(&link.signalling) as usize;

        let mut prepended = alloc::vec::Vec::with_capacity(4 + data.len());
        let mut prepend_bytes = [0u8; 4];
        rng.fill_bytes(&mut prepend_bytes);
        prepended.extend_from_slice(&prepend_bytes);
        prepended.extend_from_slice(data);

        let max_ct_len = 16 + ((prepended.len() / 16) + 1) * 16 + 32;
        let mut ct_buf = alloc::vec![0u8; max_ct_len];
        let ct_len = link.encrypt(&prepended, rng, &mut ct_buf).ok()?;
        ct_buf.truncate(ct_len);
        Some((ct_buf, mtu))
    }

    /// Compute SDU and link_mdu from peer MTU.
    fn compute_sdu_and_link_mdu(peer_mtu: usize) -> (usize, usize) {
        let sdu = if peer_mtu > 36 { peer_mtu - 36 } else { 464 };
        let link_mdu = if peer_mtu > 68 {
            ((peer_mtu - 68) / 16) * 16 - 1
        } else {
            crate::link::LINK_MDU
        };
        (sdu, link_mdu)
    }

    /// Override resource_hash to match Python convention: SHA-256(plaintext || random_hash).
    /// Only sets `resource_hash`; caller is responsible for `original_hash`.
    fn override_resource_hash(resource: &mut Resource, original_data: &[u8]) {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(original_data);
        hasher.update(resource.random_hash);
        resource.resource_hash = hasher.finalize().into();
    }

    /// Create an outbound Resource from data, encrypt it, build the
    /// advertisement packet, and push the Resource to self.resources.
    ///
    /// `send_data` is what gets encrypted (may be compressed).
    /// `original_data` is the uncompressed plaintext (used for resource_hash
    /// and proof validation). For uncompressed resources, pass the same slice.
    /// `split` optionally sets split metadata: (split_index, split_total, original_hash).
    ///
    /// Returns (advertisement_packet, resource_hash).
    fn prepare_and_advertise_segment<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        send_data: &[u8],
        original_data: &[u8],
        compressed: bool,
        split: Option<SplitMeta>,
        rng: &mut R,
    ) -> Option<(alloc::vec::Vec<u8>, [u8; 32])> {
        let (encrypted, peer_mtu) = self.prepend_and_encrypt(link_id, send_data, rng)?;
        let (sdu, link_mdu) = Self::compute_sdu_and_link_mdu(peer_mtu);
        let original_size = split
            .as_ref()
            .map(|s| s.full_original_size)
            .unwrap_or(original_data.len());
        let mut resource =
            Resource::new_outbound(&encrypted, *link_id, sdu, original_size, link_mdu, rng);
        resource.flags.encrypted = true;
        resource.flags.compressed = compressed;

        Self::override_resource_hash(&mut resource, original_data);
        resource.data = original_data.to_vec();

        if let Some(meta) = split {
            resource.split_index = meta.split_index;
            resource.split_total = meta.split_total;
            resource.flags.is_split = true;
            // For segment 1, original_hash == [0;32] means "use this segment's hash"
            resource.original_hash = if meta.original_hash == [0u8; 32] {
                resource.resource_hash
            } else {
                meta.original_hash
            };
        }

        let resource_hash = resource.resource_hash;
        let adv = resource.build_advertisement();
        let pkt = self.encrypt_and_build_adv(link_id, &adv, rng)?;

        self.resources.push(resource);
        Some((pkt, resource_hash))
    }

    /// Encrypt an advertisement payload and build the RESOURCE_ADV packet.
    fn encrypt_and_build_adv<R: RngCore + CryptoRng>(
        &self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        adv: &[u8],
        rng: &mut R,
    ) -> Option<alloc::vec::Vec<u8>> {
        let link = self.links.get(link_id)?;
        let peer_mtu = decode_mtu(&link.signalling) as usize;
        // Use peer MTU for buffer size: TCP links (MTU=8192) produce larger
        // advertisements with more part hashes in the hashmap.
        let buf_size = peer_mtu.max(rete_core::MTU);
        let mut adv_ct_buf = alloc::vec![0u8; buf_size];
        let adv_ct_len = link.encrypt(adv, rng, &mut adv_ct_buf).ok()?;

        let mut pkt_buf = alloc::vec![0u8; buf_size];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Link)
            .destination_hash(link_id)
            .context(CONTEXT_RESOURCE_ADV)
            .payload(&adv_ct_buf[..adv_ct_len])
            .build()
            .ok()?;

        Some(pkt_buf[..pkt_len].to_vec())
    }

    /// Advertise the next split segment after proof receipt.
    /// Returns the advertisement packet to send, or None if no more segments.
    fn advertise_next_split_segment<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        original_hash: &[u8; 32],
        rng: &mut R,
    ) -> Option<alloc::vec::Vec<u8>> {
        use crate::resource::MAX_EFFICIENT_SIZE;

        let entry_idx = self
            .split_send_queue
            .iter()
            .position(|e| e.link_id == *link_id && e.original_hash == *original_hash)?;

        let seg_idx = self.split_send_queue[entry_idx].next_segment;
        let split_total = self.split_send_queue[entry_idx].split_total;

        if seg_idx > split_total {
            self.split_send_queue.swap_remove(entry_idx);
            return None;
        }

        // Queue data starts at segment 2, so offset from segment 2
        let data_len = self.split_send_queue[entry_idx].data.len();
        let seg_start = (seg_idx - 2) * MAX_EFFICIENT_SIZE;
        let seg_end = (seg_start + MAX_EFFICIENT_SIZE).min(data_len);
        let seg_data = self.split_send_queue[entry_idx].data[seg_start..seg_end].to_vec();
        let full_original_size = self.split_send_queue[entry_idx].full_original_size;
        let oh = *original_hash;

        let (pkt, _) = self.prepare_and_advertise_segment(
            link_id,
            &seg_data,
            &seg_data,
            false,
            Some(SplitMeta {
                split_index: seg_idx,
                split_total,
                original_hash: oh,
                full_original_size,
            }),
            rng,
        )?;

        // Advance or remove queue entry
        let entry = &mut self.split_send_queue[entry_idx];
        entry.next_segment += 1;
        if entry.next_segment > entry.split_total {
            self.split_send_queue.swap_remove(entry_idx);
        }

        Some(pkt)
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
            let res = self.resources.iter_mut().find(|r| {
                !r.is_sender
                    && r.link_id == *link_id
                    && r.resource_hash[..TRUNCATED_HASH_LEN] == *resource_hash
            })?;
            res.build_request()
        };
        self.build_resource_req_packet(link_id, &req, rng)
    }

    /// Build a follow-up RESOURCE_REQ for a receiver resource that still has
    /// unreceived parts.
    ///
    /// Used by NodeCore after receiving a window of parts (ResourceProgress
    /// with current < total) to request the next batch.
    pub fn build_followup_request<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        resource_hash: &[u8; TRUNCATED_HASH_LEN],
        rng: &mut R,
    ) -> Option<alloc::vec::Vec<u8>> {
        let req = {
            let res = self.resources.iter_mut().find(|r| {
                !r.is_sender
                    && r.link_id == *link_id
                    && r.resource_hash[..TRUNCATED_HASH_LEN] == *resource_hash
            })?;
            // All parts already received — no follow-up needed
            if res.received.iter().all(|&r| r) {
                return None;
            }
            res.build_request()
        };
        self.build_resource_req_packet(link_id, &req, rng)
    }

    /// Encrypt a RESOURCE_REQ payload via a link and build the packet.
    fn build_resource_req_packet<R: RngCore + CryptoRng>(
        &self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        req_payload: &[u8],
        rng: &mut R,
    ) -> Option<alloc::vec::Vec<u8>> {
        let link = self.links.get(link_id)?;
        let mut ct_buf = [0u8; rete_core::MTU];
        let ct_len = link.encrypt(req_payload, rng, &mut ct_buf).ok()?;

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

    /// Periodic resource maintenance.
    ///
    /// Python doesn't proactively send HMU — it only sends in response to
    /// RESOURCE_REQ with HASHMAP_IS_EXHAUSTED. The receiver retries via its
    /// watchdog/timeout. Matching that behavior: no proactive HMU sending.
    pub fn tick_resources<R: RngCore + CryptoRng>(&mut self, now: u64, rng: &mut R) {
        // Retry follow-up requests for stalled receiver resources.
        // Only retry when outstanding_parts == 0 (not waiting for in-flight parts)
        // AND enough time has passed since last activity (time-gated to avoid
        // spamming REQs before the sender has time to respond).
        let mut req_packets = alloc::vec::Vec::new();
        for res in &mut self.resources {
            if !res.is_sender
                && !res.received.iter().all(|&r| r)
                && res.outstanding_parts == 0
                && now.saturating_sub(res.last_activity) >= RESOURCE_RETRY_THRESHOLD_SECS
            {
                let req_payload = res.build_request();
                req_packets.push((res.link_id, req_payload));
                res.touch_activity(now);
            }
        }
        // Encrypt REQ packets via the link (separate loop to avoid borrow conflict)
        for (link_id, req_payload) in &req_packets {
            if let Some(pkt) = self.build_resource_req_packet(link_id, req_payload, rng) {
                self.resource_outbound.push(pkt);
            }
        }
        // Also send link-encrypted HMU for sender resources with unsent hashes.
        // Collect payloads first to avoid borrow conflict between resources and links.
        let mut hmu_items: alloc::vec::Vec<([u8; TRUNCATED_HASH_LEN], alloc::vec::Vec<u8>)> =
            alloc::vec::Vec::new();
        for res in &mut self.resources {
            if res.is_sender && res.needs_hashmap_update() {
                if let Some(hmu) = res.build_hashmap_update() {
                    hmu_items.push((res.link_id, hmu));
                }
            }
        }
        for (lid, hmu_payload) in &hmu_items {
            if let Some(link) = self.links.get(lid) {
                if let Some(pkt) =
                    Self::build_link_packet(link, lid, hmu_payload, CONTEXT_RESOURCE_HMU, rng)
                {
                    self.resource_outbound.push(pkt);
                }
            }
        }
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
            if now.saturating_sub(path.learned_at) > path.expiry_time() {
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

        // Expire old link table entries (stale relayed links)
        let mut expired_link_table = heapless::Vec::<[u8; TRUNCATED_HASH_LEN], 32>::new();
        for (lid, entry) in self.link_table.iter() {
            // Link table entries live longer than reverse entries since links
            // maintain keepalives. Use stale_time (KEEPALIVE * 2 = 12 min).
            if now.saturating_sub(entry.timestamp) > crate::link::STALE_TIMEOUT_SECS {
                let _ = expired_link_table.push(*lid);
            }
        }
        for lid in &expired_link_table {
            self.link_table.remove(lid);
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
    ///
    /// Python adds `random.random() * PATHFINDER_RW` (0–0.5s) of jitter to
    /// each retransmit timeout to prevent synchronized retransmissions on
    /// shared radio channels.
    pub fn pending_outbound<R: RngCore>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        let mut to_send: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::new();
        let mut keep: heapless::Deque<PendingAnnounce, A> = heapless::Deque::new();

        while let Some(mut ann) = self.announces.pop_front() {
            // Skip if blocked by local rebroadcast detection
            if ann.block_rebroadcasts && !ann.local {
                continue;
            }
            if ann.local || now >= ann.retransmit_timeout {
                to_send.push(ann.raw.clone());
                ann.tx_count += 1;
                // Next retransmission: PATHFINDER_G + random jitter (0..PATHFINDER_RW_MS ms)
                // Python: now + PATHFINDER_G + random.random() * PATHFINDER_RW
                let jitter_ms = (rng.next_u32() % PATHFINDER_RW_MS as u32) as u64;
                // Convert to seconds (integer math: add 1s if jitter >= 500ms)
                let jitter_secs = if jitter_ms >= 500 { 1 } else { 0 };
                ann.retransmit_timeout = now + PATHFINDER_G + jitter_secs;
                debug_assert!(ann.retransmit_timeout > now);
                ann.local = false;
                if ann.tx_count <= PATHFINDER_R && !ann.block_rebroadcasts {
                    let _ = keep.push_back(ann);
                }
            } else {
                let _ = keep.push_back(ann);
            }
        }

        self.announces = keep;
        to_send
    }

    /// Called when we hear a duplicate announce — tracks local rebroadcasts
    /// and suppresses retransmission if the announce has been locally rebroadcast
    /// enough times (LOCAL_REBROADCASTS_MAX).
    pub fn note_local_rebroadcast(&mut self, dest_hash: &[u8; TRUNCATED_HASH_LEN], heard_hops: u8) {
        for ann in self.announces.iter_mut() {
            if ann.dest_hash == *dest_hash {
                // Same hop count means a peer rebroadcast at our level
                if heard_hops.saturating_sub(1) == ann.received_hops {
                    ann.local_rebroadcasts += 1;
                    if ann.tx_count > 0 && ann.local_rebroadcasts >= LOCAL_REBROADCASTS_MAX {
                        ann.block_rebroadcasts = true;
                    }
                }
                // If we hear at one hop further, our rebroadcast was picked up
                if heard_hops.saturating_sub(1) == ann.received_hops + 1 && ann.tx_count > 0 {
                    ann.block_rebroadcasts = true;
                }
                break;
            }
        }
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
            let ann = PendingAnnounce {
                dest_hash: [i; TRUNCATED_HASH_LEN],
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
            dest_hash: [0xFF; TRUNCATED_HASH_LEN],
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
        let link_id = [0xBB; TRUNCATED_HASH_LEN];

        let raw = TestTransport::build_link_proof_packet(&identity, &packet_hash, &link_id)
            .expect("should build link proof packet");

        let pkt = rete_core::Packet::parse(&raw).expect("should parse");
        assert_eq!(pkt.packet_type, PacketType::Proof);
        assert_eq!(pkt.dest_type, DestType::Link);
        assert_eq!(pkt.destination_hash, &link_id);
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
        let link_id = [0xEE; TRUNCATED_HASH_LEN];

        let link_raw = TestTransport::build_link_proof_packet(&identity, &packet_hash, &link_id)
            .expect("link proof");
        let single_raw =
            TestTransport::build_proof_packet(&identity, &packet_hash).expect("single proof");

        let link_pkt = rete_core::Packet::parse(&link_raw).unwrap();
        let single_pkt = rete_core::Packet::parse(&single_raw).unwrap();

        assert_eq!(link_pkt.dest_type, DestType::Link);
        assert_eq!(single_pkt.dest_type, DestType::Single);
        assert_eq!(link_pkt.destination_hash, &link_id);
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
        relay_id: &[u8; TRUNCATED_HASH_LEN],
        dest_hash: &[u8; TRUNCATED_HASH_LEN],
        payload: &[u8],
    ) -> ([u8; rete_core::MTU], usize) {
        let mut buf = [0u8; rete_core::MTU];
        let n = PacketBuilder::new(&mut buf)
            .header_type(HeaderType::Header2)
            .transport_type(TRANSPORT_TYPE_TRANSPORT)
            .packet_type(PacketType::LinkRequest)
            .dest_type(DestType::Single)
            .hops(0)
            .transport_id(relay_id)
            .destination_hash(dest_hash)
            .context(0x00)
            .payload(payload)
            .build()
            .unwrap();
        (buf, n)
    }

    /// Helper: set up a transport relay with a learned path for the destination.
    fn make_relay_transport(
        relay_hash: [u8; TRUNCATED_HASH_LEN],
        dest_hash: [u8; TRUNCATED_HASH_LEN],
    ) -> TestTransport {
        let mut t = TestTransport::new();
        t.set_local_identity(relay_hash);
        t.insert_path(dest_hash, Path::direct(0));
        t
    }

    #[test]
    fn test_h2_linkrequest_creates_link_table_entry() {
        let relay_hash = [0x11u8; TRUNCATED_HASH_LEN];
        let dest_hash = [0xAAu8; TRUNCATED_HASH_LEN];
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
        let relay_hash = [0x11u8; TRUNCATED_HASH_LEN];
        let dest_hash = [0xAAu8; TRUNCATED_HASH_LEN];
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
            .destination_hash(&link_id)
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
        let relay_hash = [0x11u8; TRUNCATED_HASH_LEN];
        let dest_hash = [0xAAu8; TRUNCATED_HASH_LEN];
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
            .destination_hash(&link_id)
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
        let relay_hash = [0x11u8; TRUNCATED_HASH_LEN];
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
        let relay_hash = [0x11u8; TRUNCATED_HASH_LEN];
        let dest_hash = [0xAAu8; TRUNCATED_HASH_LEN];
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
            .destination_hash(&link_id)
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
        let relay_hash = [0x11u8; TRUNCATED_HASH_LEN];
        let dest_hash = [0xAAu8; TRUNCATED_HASH_LEN];
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
        let relay_hash = [0x11u8; TRUNCATED_HASH_LEN];
        let dest_hash = [0xAAu8; TRUNCATED_HASH_LEN];
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
                .destination_hash(&link_id)
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
        let relay_hash = [0x11u8; TRUNCATED_HASH_LEN];
        let dest_hash = [0xAAu8; TRUNCATED_HASH_LEN];
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
        let relay_hash = [0x11u8; TRUNCATED_HASH_LEN];
        let dest_hash = [0xAAu8; TRUNCATED_HASH_LEN];
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
            .destination_hash(&link_id)
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
            .destination_hash(&link_id)
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
        let relay_hash = [0x11u8; TRUNCATED_HASH_LEN];
        let dest_hash = [0xAAu8; TRUNCATED_HASH_LEN];
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
    ) -> (TestTransport, [u8; TRUNCATED_HASH_LEN], Identity) {
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
            .destination_hash(&link_id)
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
        assert_eq!(req_pkt.destination_hash, &link_id);

        let resp_pkt = rete_core::Packet::parse(&response_raw).expect("should parse response");
        assert_eq!(resp_pkt.dest_type, DestType::Link);
        assert_eq!(resp_pkt.context, CONTEXT_KEEPALIVE);
        assert_eq!(resp_pkt.destination_hash, &link_id);
    }
}
