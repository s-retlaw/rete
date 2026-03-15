//! Core Transport struct — path table, announce queue, packet processing.

use heapless::FnvIndexMap;
use rand_core::{RngCore, CryptoRng};
use rete_core::{TRUNCATED_HASH_LEN, NAME_HASH_LEN, Packet, PacketType, PacketBuilder, DestType, Identity};
use crate::{path::Path, announce::PendingAnnounce, dedup::DedupWindow};
use crate::announce::validate_announce;
use sha2::{Sha256, Digest};

// ---------------------------------------------------------------------------
// Protocol constants (from Python Transport.py)
// ---------------------------------------------------------------------------

/// Announce retransmission delay base (seconds).
pub const PATHFINDER_G: u64 = 5;

/// Maximum retransmission count.
pub const PATHFINDER_R: u8 = 1;

/// Path expiry time in seconds (7 days).
pub const PATH_EXPIRES: u64 = 604800;

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
pub struct Transport<
    const MAX_PATHS:     usize,
    const MAX_ANNOUNCES: usize,
    const DEDUP_WINDOW:  usize,
> {
    paths:     FnvIndexMap<[u8; TRUNCATED_HASH_LEN], Path, MAX_PATHS>,
    announces: heapless::Deque<PendingAnnounce, MAX_ANNOUNCES>,
    dedup:     DedupWindow<DEDUP_WINDOW>,
    known_identities: FnvIndexMap<[u8; TRUNCATED_HASH_LEN], [u8; 64], MAX_PATHS>,
}

impl<const P: usize, const A: usize, const D: usize> Transport<P, A, D> {
    /// Create a new, empty transport.
    pub const fn new() -> Self {
        Transport {
            paths:     FnvIndexMap::new(),
            announces: heapless::Deque::new(),
            dedup:     DedupWindow::new(),
            known_identities: FnvIndexMap::new(),
        }
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
    pub fn path_count(&self) -> usize { self.paths.len() }

    /// Number of pending announces.
    pub fn announce_count(&self) -> usize { self.announces.len() }

    /// Look up a previously announced identity's public key by destination hash.
    pub fn recall_identity(&self, dest: &[u8; TRUNCATED_HASH_LEN]) -> Option<&[u8; 64]> {
        self.known_identities.get(dest)
    }

    // -----------------------------------------------------------------------
    // Packet ingestion
    // -----------------------------------------------------------------------

    /// Process an inbound raw packet.
    ///
    /// Parses the packet, checks for duplicates, and dispatches by type:
    /// - **ANNOUNCE**: validate signature + dest hash, learn path
    /// - **DATA**: return for local delivery
    ///
    /// `now` is the current monotonic time in seconds.
    pub fn ingest<'a>(&mut self, raw: &'a mut [u8], now: u64) -> IngestResult<'a> {
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
                IngestResult::LocalData {
                    dest_hash: dh,
                    payload: pkt.payload,
                }
            }
            _ => {
                // LinkRequest, Proof — treat as forward for now
                IngestResult::Forward { raw }
            }
        }
    }

    fn handle_announce<'a>(&mut self, pkt: &Packet<'a>, raw: &'a [u8], now: u64) -> IngestResult<'a> {
        match validate_announce(pkt.destination_hash, pkt.payload) {
            Ok(info) => {
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
                    let path = match pkt.transport_id {
                        Some(tid) => {
                            let mut via = [0u8; TRUNCATED_HASH_LEN];
                            via.copy_from_slice(tid);
                            Path::via_repeater(via, pkt.hops, now)
                        }
                        None => Path { hops: pkt.hops, ..Path::direct(now) },
                    };
                    let _ = self.insert_path(dh, path);
                }

                // Store identity for later recall (encrypt outbound data)
                let mut pk = [0u8; 64];
                pk.copy_from_slice(info.pub_key);
                let _ = self.known_identities.insert(dh, pk);

                // Queue for retransmission if hops < threshold
                if pkt.hops <= PATHFINDER_R {
                    let mut ann_raw = heapless::Vec::new();
                    if ann_raw.extend_from_slice(raw).is_ok() {
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
        aspects:  &[&str],
        app_data: Option<&[u8]>,
        rng:      &mut R,
        now:      u64,
        out:      &mut [u8],
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
        let mut signed_data = [0u8; 500];
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
        let mut payload = [0u8; 500];
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
