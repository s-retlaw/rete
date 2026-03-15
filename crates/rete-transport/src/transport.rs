//! Core Transport struct — path table, announce queue, packet processing.

use crate::announce::validate_announce;
use crate::{announce::PendingAnnounce, dedup::DedupWindow, path::Path};
use heapless::{FnvIndexMap, FnvIndexSet};
use rand_core::{CryptoRng, RngCore};
use rete_core::{
    DestType, HeaderType, Identity, Packet, PacketBuilder, PacketType, NAME_HASH_LEN,
    TRUNCATED_HASH_LEN,
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

/// Destination hash for `rnstransport.path.request` (PLAIN, no identity).
///
/// Precomputed: `destination_hash("rnstransport.path.request", None)`.
pub const PATH_REQUEST_DEST: [u8; TRUNCATED_HASH_LEN] = [
    0x6b, 0x9f, 0x66, 0x01, 0x4d, 0x98, 0x53, 0xfa, 0xab, 0x22, 0x0f, 0xba, 0x47, 0xd0, 0x27,
    0x61,
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
        /// The LRPROOF response to send back (raw packet bytes).
        proof_raw: &'a [u8],
    },
    /// A link handshake completed (LRRTT processed).
    LinkEstablished {
        /// The link_id.
        link_id: [u8; TRUNCATED_HASH_LEN],
    },
    /// Decrypted data received on an active link.
    LinkData {
        /// The link_id.
        link_id: [u8; TRUNCATED_HASH_LEN],
        /// Decrypted payload data.
        data: &'a [u8],
        /// The context byte from the packet.
        context: u8,
    },
    /// A link was closed (teardown or timeout).
    LinkClosed {
        /// The link_id.
        link_id: [u8; TRUNCATED_HASH_LEN],
    },
    /// Packet was a duplicate and should be dropped.
    Duplicate,
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
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// The Reticulum transport layer — path table, announce queue, dedup window.
///
/// Generic over:
/// - `MAX_PATHS`      — max learned destination paths
/// - `MAX_ANNOUNCES`  — max pending outbound announces
/// - `DEDUP_WINDOW`   — duplicate-detection window size
pub struct Transport<const MAX_PATHS: usize, const MAX_ANNOUNCES: usize, const DEDUP_WINDOW: usize>
{
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
}

impl<const P: usize, const A: usize, const D: usize> Default for Transport<P, A, D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const P: usize, const A: usize, const D: usize> Transport<P, A, D> {
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
        }
    }

    /// Register a destination hash as belonging to this node.
    ///
    /// Announces for local destinations will be filtered (self-announce).
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
    ///
    /// Returns `true` if already seen — drop the packet.
    /// Returns `false` if new — process it.
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
    ///
    /// This allows sending encrypted DATA to a peer whose announce hasn't been
    /// received yet — useful for point-to-point links with known identities.
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
    ///
    /// When set, packets with `transport_id == local_identity_hash` will be
    /// forwarded to their destination via the path table.
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

    // -----------------------------------------------------------------------
    // Packet ingestion
    // -----------------------------------------------------------------------

    /// Process an inbound raw packet (single-interface convenience wrapper).
    ///
    /// Equivalent to `ingest_on(raw, now, 0)`.
    pub fn ingest<'a>(&mut self, raw: &'a mut [u8], now: u64) -> IngestResult<'a> {
        self.ingest_on(raw, now, 0)
    }

    /// Process an inbound raw packet received on interface `iface`.
    ///
    /// Parses the packet, checks for duplicates, and dispatches by type:
    /// - **ANNOUNCE**: validate signature + dest hash, learn path, queue retransmission
    /// - **DATA**: return for local delivery, handle path requests, or forward
    /// - **PROOF**: route via reverse table or forward
    ///
    /// `now` is the current monotonic time in seconds.
    pub fn ingest_on<'a>(&mut self, raw: &'a mut [u8], now: u64, iface: u8) -> IngestResult<'a> {
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

        // Check HEADER_2 forwarding: only if we're a transport node and
        // transport_id matches our identity. Non-matching HEADER_2 packets
        // fall through to normal processing (announces, local DATA delivery).
        if pkt.header_type == HeaderType::Header2 {
            if let Some(local_id) = self.local_identity_hash {
                if let Some(tid) = pkt.transport_id {
                    let mut tid_arr = [0u8; TRUNCATED_HASH_LEN];
                    tid_arr.copy_from_slice(tid);

                    if tid_arr == local_id {
                        // This packet is addressed to us as relay — forward it
                        let mut dest = [0u8; TRUNCATED_HASH_LEN];
                        dest.copy_from_slice(pkt.destination_hash);

                        // Increment hops
                        raw[1] = raw[1].saturating_add(1);

                        // Record in reverse table (truncated packet hash)
                        let mut trunc_hash = [0u8; TRUNCATED_HASH_LEN];
                        trunc_hash.copy_from_slice(&pkt_hash[..TRUNCATED_HASH_LEN]);
                        let _ = self
                            .reverse_table
                            .insert(trunc_hash, ReverseEntry { timestamp: now, received_on: iface, forwarded_to: 0 });

                        // Look up path to destination
                        return match self.paths.get(&dest) {
                            Some(path) if path.hops > 1 => {
                                // Multi-hop: overwrite transport_id with next-hop
                                if let Some(via) = path.via {
                                    raw[2..18].copy_from_slice(&via);
                                }
                                IngestResult::Forward { raw: &raw[..len], source_iface: iface }
                            }
                            Some(path) if path.hops <= 1 => {
                                // Last hop: convert HEADER_2 → HEADER_1
                                // Clear header_type and transport_type, keep lower nibble
                                let new_flags = raw[0] & 0x0F;
                                raw[0] = new_flags;
                                // Shift dest_hash + context + payload left by 16 bytes
                                // (removing the transport_id field)
                                raw.copy_within(18..len, 2);
                                IngestResult::Forward {
                                    raw: &raw[..len - TRUNCATED_HASH_LEN],
                                    source_iface: iface,
                                }
                            }
                            _ => {
                                // No path to destination
                                IngestResult::Invalid
                            }
                        };
                    }
                    // transport_id doesn't match us — fall through to normal processing
                }
            }
            // Not a transport node, or transport_id doesn't match — fall through
        }

        // Increment hops
        raw[1] = raw[1].saturating_add(1);

        // Re-parse after hops increment (cheap, zero-copy)
        let pkt = match Packet::parse(raw) {
            Ok(p) => p,
            Err(_) => return IngestResult::Invalid,
        };

        match pkt.packet_type {
            PacketType::Announce => self.handle_announce(&pkt, raw, now),
            PacketType::Data => {
                let mut dh = [0u8; TRUNCATED_HASH_LEN];
                dh.copy_from_slice(pkt.destination_hash);
                // Path request handling: transport nodes respond with cached announces
                if self.local_identity_hash.is_some() && dh == PATH_REQUEST_DEST {
                    return self.handle_path_request(pkt.payload, now);
                }
                IngestResult::LocalData {
                    dest_hash: dh,
                    payload: pkt.payload,
                    packet_hash: pkt_hash,
                }
            }
            PacketType::Proof => {
                if self.local_identity_hash.is_some() {
                    // Route proof via reverse table (one-shot: consume entry).
                    // The proof goes to all interfaces except where it arrived,
                    // which includes the interface the original DATA came from.
                    let mut dh = [0u8; TRUNCATED_HASH_LEN];
                    dh.copy_from_slice(pkt.destination_hash);
                    if self.reverse_table.remove(&dh).is_some() {
                        IngestResult::Forward { raw, source_iface: iface }
                    } else {
                        IngestResult::Invalid
                    }
                } else {
                    IngestResult::Forward { raw, source_iface: iface }
                }
            }
            PacketType::LinkRequest => IngestResult::Forward { raw, source_iface: iface },
        }
    }

    fn handle_announce<'a>(
        &mut self,
        pkt: &Packet<'a>,
        raw: &'a [u8],
        now: u64,
    ) -> IngestResult<'a> {
        // Self-announce filtering: drop announces for our own destinations
        let mut dh_check = [0u8; TRUNCATED_HASH_LEN];
        dh_check.copy_from_slice(pkt.destination_hash);
        if self.is_local_destination(&dh_check) {
            return IngestResult::Duplicate;
        }

        match validate_announce(pkt.destination_hash, pkt.payload) {
            Ok(info) => {
                // Announce replay detection: check dest_hash + random_hash combo
                let mut replay_key = [0u8; 32];
                replay_key[..TRUNCATED_HASH_LEN].copy_from_slice(pkt.destination_hash);
                replay_key[TRUNCATED_HASH_LEN..TRUNCATED_HASH_LEN + 10]
                    .copy_from_slice(info.random_hash);
                // Hash the replay key to get a stable 32-byte dedup key
                let replay_hash: [u8; 32] = Sha256::digest(replay_key).into();
                if self.announce_dedup.check_and_insert(&replay_hash) {
                    return IngestResult::Duplicate;
                }
                let mut dh = [0u8; TRUNCATED_HASH_LEN];
                dh.copy_from_slice(pkt.destination_hash);

                // Learn path if: new, or fewer/equal hops, or existing expired
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
                    // Cache announce raw bytes for path request responses
                    path.announce_raw = Some(raw.to_vec());
                    let _ = self.insert_path(dh, path);
                }

                // Store identity for later recall (encrypt outbound data)
                let mut pk = [0u8; 64];
                pk.copy_from_slice(info.pub_key);
                let _ = self.known_identities.insert(dh, pk);

                // Queue for retransmission if hops within max range
                if pkt.hops < PATHFINDER_M {
                    // When transport mode is on, rebuild as HEADER_2 with our
                    // transport_id so downstream nodes learn the relay path.
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

    /// Handle a path request: if we have a cached announce for the requested
    /// destination, queue it for immediate retransmission.
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
                        local: true, // immediate send
                    };
                    let _ = self.queue_announce(pending);
                }
            }
        }

        // Consumed — no further processing needed
        IngestResult::Duplicate
    }

    // -----------------------------------------------------------------------
    // Proof packet construction
    // -----------------------------------------------------------------------

    /// Build a PROOF packet for a received data packet.
    ///
    /// The proof payload is `packet_hash[32] || signature[64]` (explicit proof).
    /// Destination hash of the PROOF is `packet_hash[0:16]`.
    ///
    /// This is a static method — runtime-agnostic, usable from both TokioNode
    /// and EmbassyNode.
    pub fn build_proof_packet(
        identity: &Identity,
        packet_hash: &[u8; 32],
    ) -> Option<alloc::vec::Vec<u8>> {
        let signature = identity.sign(packet_hash).ok()?;
        let mut payload = [0u8; 96];
        payload[..32].copy_from_slice(packet_hash);
        payload[32..96].copy_from_slice(&signature);

        let trunc: [u8; TRUNCATED_HASH_LEN] =
            packet_hash[..TRUNCATED_HASH_LEN].try_into().ok()?;

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
    // Announce creation
    // -----------------------------------------------------------------------

    /// Create an announce packet for a local identity.
    ///
    /// Returns the number of bytes written to `out`.
    ///
    /// # Arguments
    /// - `identity` — the local identity to announce
    /// - `app_name` — application name (e.g. "rete")
    /// - `aspects` — destination aspects (e.g. &["example", "v1"])
    /// - `app_data` — optional application data to include
    /// - `rng` — cryptographic RNG for random_hash generation
    /// - `now` — current monotonic time in seconds (used in random_hash)
    /// - `out` — output buffer (must be >= MTU bytes)
    pub fn create_announce<R: RngCore + CryptoRng>(
        identity: &Identity,
        app_name: &str,
        aspects: &[&str],
        app_data: Option<&[u8]>,
        rng: &mut R,
        now: u64,
        out: &mut [u8],
    ) -> Result<usize, rete_core::Error> {
        // Compute expanded name and destination hash
        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name(app_name, aspects, &mut name_buf)?;

        let identity_hash = identity.hash();
        let dest_hash = rete_core::destination_hash(expanded, Some(&identity_hash));

        // Compute name_hash: SHA-256(expanded_name)[0:10]
        let name_digest = Sha256::digest(expanded.as_bytes());
        let mut name_hash = [0u8; NAME_HASH_LEN];
        name_hash.copy_from_slice(&name_digest[..NAME_HASH_LEN]);

        // random_hash: 5 random bytes + 5 timestamp bytes
        let mut random_hash = [0u8; 10];
        rng.fill_bytes(&mut random_hash[..5]);
        random_hash[5..10].copy_from_slice(&now.to_be_bytes()[3..8]); // 5 bytes of timestamp

        // Build signed_data: dest_hash || pub_key || name_hash || random_hash [|| app_data]
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

        // Sign
        let signature = identity.sign(&signed_data[..pos])?;

        // Build announce payload: pub_key || name_hash || random_hash || signature [|| app_data]
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

        // Build packet
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
    // Periodic maintenance
    // -----------------------------------------------------------------------

    /// Expire old paths and manage announce retransmission.
    ///
    /// Call this periodically (e.g. every 60 seconds).
    ///
    /// `now` is the current monotonic time in seconds.
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

        TickResult {
            expired_paths: expired_count,
        }
    }

    /// Returns announces that are due for retransmission.
    ///
    /// Removes retransmitted announces that have exceeded their tx_count.
    /// Updates timestamps for announces being sent.
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
