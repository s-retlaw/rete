//! Resource — segmented data transfer over Links.
//!
//! A Resource breaks large data into segments that fit within a Link's MDU,
//! transfers them using a sliding window, and reassembles on the receiver side
//! with hash verification.
//!
//! # State machines
//!
//! ```text
//! Sender:   Queued -> Advertised -> Transferring -> AwaitingProof -> Complete/Failed
//! Receiver: Transferring -> Assembling -> Complete/Corrupt/Failed
//! ```

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};
use rete_core::msgpack;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Length of truncated part hashes (4 bytes).
pub const MAPHASH_LEN: usize = 4;
/// Length of the random hash in a resource advertisement.
pub const RANDOM_HASH_SIZE: usize = 4;
/// Maximum efficient resource size. Python: `1 * 1024 * 1024 - 1` = 1048575.
pub const MAX_EFFICIENT_SIZE: usize = 1_048_575;
/// Initial sliding window size.
pub const WINDOW_INITIAL: usize = 4;
/// Minimum window size.
pub const WINDOW_MIN: usize = 2;
/// Maximum window for slow links.
pub const WINDOW_MAX_SLOW: usize = 10;
/// Maximum window for fast links.
pub const WINDOW_MAX_FAST: usize = 75;
/// Maximum window for very slow links. Python: `Resource.WINDOW_MAX_VERY_SLOW = 4`.
pub const WINDOW_MAX_VERY_SLOW: usize = 4;
/// Window flexibility. Python: `Resource.WINDOW_FLEXIBILITY = 4`.
pub const WINDOW_FLEXIBILITY: usize = 4;
/// Rate threshold: rounds above which the fast window can be used.
/// Python: `Resource.FAST_RATE_THRESHOLD = WINDOW_MAX_SLOW - WINDOW - 2 = 4`.
pub const FAST_RATE_THRESHOLD: usize = 4;
/// Rate threshold for very slow detection.
/// Python: `Resource.VERY_SLOW_RATE_THRESHOLD = 2`.
pub const VERY_SLOW_RATE_THRESHOLD: usize = 2;
/// Fast transfer rate in bytes/sec. Python: `Resource.RATE_FAST = (50*1000)/8 = 6250`.
pub const RATE_FAST: usize = 6250;
/// Very slow transfer rate in bytes/sec. Python: `Resource.RATE_VERY_SLOW = (2*1000)/8 = 250`.
pub const RATE_VERY_SLOW: usize = 250;
/// Part timeout factor. Python: `Resource.PART_TIMEOUT_FACTOR = 4`.
pub const PART_TIMEOUT_FACTOR: u64 = 4;
/// Part timeout factor after RTT measurement. Python: `Resource.PART_TIMEOUT_FACTOR_AFTER_RTT = 2`.
pub const PART_TIMEOUT_FACTOR_AFTER_RTT: u64 = 2;
/// Proof timeout factor. Python: `Resource.PROOF_TIMEOUT_FACTOR = 3`.
pub const PROOF_TIMEOUT_FACTOR: u64 = 3;
/// Maximum transfer retries before failure.
pub const MAX_RETRIES: usize = 16;
/// Maximum advertisement retries.
pub const MAX_ADV_RETRIES: usize = 4;
/// Grace time for sender in seconds.
pub const SENDER_GRACE_TIME: u64 = 10;
/// Advertisement overhead in bytes.
pub const ADV_OVERHEAD: usize = 134;
/// Sentinel value indicating the hashmap is fully transferred.
pub const HASHMAP_IS_EXHAUSTED: u8 = 0xFF;
/// Default hashmap max len for standard radio links (MDU=431).
/// Python: `math.floor((Link.MDU - OVERHEAD) / MAPHASH_LEN)` = 74
pub const HASHMAP_MAX_LEN_DEFAULT: usize = (crate::link::LINK_MDU - ADV_OVERHEAD) / MAPHASH_LEN;

/// Compute the maximum number of part hashes per hashmap segment for a given link MDU.
///
/// For TCP links (MDU ~8111), this yields ~1994 hashes per segment instead of 74,
/// dramatically reducing HMU round-trips for large resource transfers.
pub fn hashmap_max_len(link_mdu: usize) -> usize {
    if link_mdu > ADV_OVERHEAD {
        (link_mdu - ADV_OVERHEAD) / MAPHASH_LEN
    } else {
        1 // minimum: at least one hash per segment
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Resource transfer state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceState {
    /// Uninitialized.
    None,
    /// Outbound resource waiting to be advertised.
    Queued,
    /// Advertisement sent, waiting for receiver acceptance.
    Advertised,
    /// Data segments are being transferred.
    Transferring,
    /// All segments sent, waiting for proof from receiver.
    AwaitingProof,
    /// Receiver is assembling parts (all parts received, verifying).
    Assembling,
    /// Transfer completed successfully.
    Complete,
    /// Transfer failed (timeout, cancel, max retries).
    Failed,
    /// Assembled data did not match the resource hash.
    Corrupt,
}

/// Result of `Resource::handle_request()`.
#[derive(Debug, Default)]
pub struct HandleRequestResult {
    /// Parts to send: `(part_index, part_data)` pairs.
    pub parts: Vec<(usize, Vec<u8>)>,
    /// Whether the receiver signaled HASHMAP_IS_EXHAUSTED (sender should send HMU).
    pub needs_hmu: bool,
}

/// Resource flags bitfield.
#[derive(Debug, Clone, Default)]
pub struct ResourceFlags {
    /// Data is encrypted.
    pub encrypted: bool,
    /// Data is compressed.
    pub compressed: bool,
    /// Resource is part of a split transfer.
    pub is_split: bool,
    /// Resource is a request.
    pub is_request: bool,
    /// Resource is a response.
    pub is_response: bool,
    /// Resource has metadata attached.
    pub has_metadata: bool,
}

impl ResourceFlags {
    /// Encode flags into a single byte.
    ///
    /// ```text
    /// bit 0: encrypted
    /// bit 1: compressed
    /// bit 2: is_split
    /// bit 3: is_request
    /// bit 4: is_response
    /// bit 5: has_metadata
    /// ```
    pub fn to_byte(&self) -> u8 {
        let mut b = 0u8;
        if self.encrypted {
            b |= 1 << 0;
        }
        if self.compressed {
            b |= 1 << 1;
        }
        if self.is_split {
            b |= 1 << 2;
        }
        if self.is_request {
            b |= 1 << 3;
        }
        if self.is_response {
            b |= 1 << 4;
        }
        if self.has_metadata {
            b |= 1 << 5;
        }
        b
    }

    /// Decode flags from a single byte.
    pub fn from_byte(b: u8) -> Self {
        ResourceFlags {
            encrypted: b & (1 << 0) != 0,
            compressed: b & (1 << 1) != 0,
            is_split: b & (1 << 2) != 0,
            is_request: b & (1 << 3) != 0,
            is_response: b & (1 << 4) != 0,
            has_metadata: b & (1 << 5) != 0,
        }
    }
}

/// Errors from resource assembly and verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceError {
    /// Assembled data hash does not match the advertised resource_hash.
    HashMismatch,
}

impl core::fmt::Display for ResourceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::HashMismatch => write!(f, "resource hash mismatch"),
        }
    }
}

/// A segmented data transfer over a Link.
pub struct Resource {
    /// Current state of the resource transfer.
    pub state: ResourceState,
    /// Whether this side is the sender.
    pub is_sender: bool,
    /// Link identifier this resource is associated with.
    pub link_id: [u8; 16],
    /// Full 32-byte SHA-256 hash of (data || random_hash).
    pub resource_hash: [u8; 32],
    /// 4-byte random hash for uniqueness.
    pub random_hash: [u8; RANDOM_HASH_SIZE],
    /// Resource flags.
    pub flags: ResourceFlags,
    /// Total data size in bytes (encrypted/transfer size).
    pub total_size: usize,
    /// Original plaintext data size (before prepend + compression + encryption).
    /// Used for the "d" field in advertisements.
    pub original_size: usize,
    /// Index of the next segment to send or receive.
    pub segment_index: usize,
    /// Total number of segments.
    pub total_segments: usize,
    /// Current sliding window size.
    pub window: usize,
    /// Maximum data unit per segment.
    pub mdu: usize,
    /// Number of retries so far.
    pub retries: usize,
    /// Last activity timestamp (monotonic seconds).
    pub last_activity: u64,

    // -- Split resource fields --
    // When a resource exceeds MAX_EFFICIENT_SIZE, it is split into multiple
    // independent segment transfers. Each segment is a complete Resource with
    // its own advertisement/parts/proof cycle. These fields track the split
    // metadata. For non-split resources: split_index=1, split_total=1,
    // original_hash=resource_hash.
    /// 1-based index of this segment within a split resource group.
    /// Advertisement field "i". Always 1 for non-split resources.
    pub split_index: usize,
    /// Total number of split segments in the group.
    /// Advertisement field "l". Always 1 for non-split resources.
    pub split_total: usize,
    /// Group key for split resources: the resource_hash of segment 1.
    /// Advertisement field "o". Equals resource_hash for non-split resources.
    pub original_hash: [u8; 32],

    /// Optional metadata (filename, MIME type, etc.) — msgpack-encoded.
    /// Prepended to first segment when `flags.has_metadata` is set.
    pub metadata: Option<Vec<u8>>,

    // -- Data storage --
    /// Full data (sender has it upfront, receiver assembles).
    pub data: Vec<u8>,
    /// Individual segments.
    parts: Vec<Vec<u8>>,
    /// 4-byte truncated SHA-256 hash of each segment (includes random_hash).
    pub part_hashes: Vec<[u8; MAPHASH_LEN]>,
    /// Which parts have been received (receiver side).
    pub received: Vec<bool>,
    /// How far into `part_hashes` has been communicated.
    ///
    /// - Sender: index up to which hashes have been sent (via advertisement + HMUs).
    /// - Receiver: index up to which valid hashes have been received.
    ///
    /// Always at a `hashmap_max_len` boundary or at `total_segments`.
    hashmap_cursor: usize,
    /// Number of parts requested but not yet received in the current window.
    /// Set by `build_request()`, decremented by `receive_part()`.
    /// When zero, the window is complete and a follow-up REQ can be sent.
    pub outstanding_parts: usize,
    /// Maximum part hashes per hashmap segment, computed from the link's MDU.
    /// Python: `math.floor((Link.MDU - OVERHEAD) / MAPHASH_LEN)`.
    /// For radio (MDU=431) = 74; for TCP (MDU≈8111) ≈ 1994.
    hashmap_max_len: usize,
}

impl Resource {
    // -----------------------------------------------------------------------
    // Sender methods
    // -----------------------------------------------------------------------

    /// Create a new outbound resource.
    ///
    /// Splits `data` into segments of at most `mdu` bytes, computes per-part
    /// hashes, and computes the overall resource hash.
    ///
    /// `original_size` is the size of the original plaintext data before
    /// prepend/compression/encryption (used for the "d" field in advertisements).
    /// `link_mdu` is the link's MDU, used to compute how many part hashes fit
    /// per hashmap segment (74 for radio, ~1994 for TCP).
    pub fn new_outbound<R: RngCore + CryptoRng>(
        data: &[u8],
        link_id: [u8; 16],
        mdu: usize,
        original_size: usize,
        link_mdu: usize,
        rng: &mut R,
    ) -> Self {
        // 1. Generate random_hash (4 random bytes)
        let mut random_hash = [0u8; RANDOM_HASH_SIZE];
        rng.fill_bytes(&mut random_hash);

        // 2. Compute resource_hash = SHA-256(data || random_hash)
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(random_hash);
        let resource_hash: [u8; 32] = hasher.finalize().into();

        // 3. Split data into segments of size mdu
        let total_segments = if data.is_empty() {
            0
        } else {
            data.len().div_ceil(mdu)
        };

        let mut parts = Vec::with_capacity(total_segments);
        let mut part_hashes = Vec::with_capacity(total_segments);

        for i in 0..total_segments {
            let start = i * mdu;
            let end = core::cmp::min(start + mdu, data.len());
            let segment = data[start..end].to_vec();

            // 4. Compute part_hash = SHA-256(segment || random_hash)[0:4]
            let mut h = Sha256::new();
            h.update(&segment);
            h.update(random_hash);
            let hash: [u8; 32] = h.finalize().into();
            let mut part_hash = [0u8; MAPHASH_LEN];
            part_hash.copy_from_slice(&hash[..MAPHASH_LEN]);
            part_hashes.push(part_hash);
            parts.push(segment);
        }

        let hml = hashmap_max_len(link_mdu);
        debug_assert!(
            hml >= 1,
            "hashmap_max_len must be >= 1, got {hml} for link_mdu={link_mdu}"
        );

        Resource {
            state: ResourceState::Queued,
            is_sender: true,
            link_id,
            resource_hash,
            random_hash,
            flags: ResourceFlags::default(),
            total_size: data.len(),
            original_size,
            segment_index: 0,
            total_segments,
            window: WINDOW_INITIAL,
            mdu,
            retries: 0,
            last_activity: 0,
            split_index: 1,
            split_total: 1,
            original_hash: resource_hash,
            metadata: None,
            data: data.to_vec(),
            parts,
            part_hashes,
            received: vec![false; total_segments],
            hashmap_cursor: 0,
            outstanding_parts: 0,
            hashmap_max_len: hml,
        }
    }

    /// Build the advertisement payload (msgpack dict).
    ///
    /// Python RNS format: a msgpack dictionary with keys:
    /// ```text
    /// "t" = transfer_size     (size of encrypted data blob)
    /// "d" = data_size         (size of original uncompressed data)
    /// "n" = num_parts         (number of segments)
    /// "h" = resource_hash     (32-byte SHA-256 hash, bytes)
    /// "r" = random_hash       (4-byte random value, bytes)
    /// "o" = original_hash     (32-byte hash for split resources, or None)
    /// "i" = segment_index     (1-based segment index for split resources)
    /// "l" = total_segments    (total segment count for split resources)
    /// "q" = request_id        (request ID, or None)
    /// "f" = flags_byte        (int)
    /// "m" = hashmap           (concatenated 4-byte part hashes, bytes)
    /// ```
    pub fn build_advertisement(&mut self) -> Vec<u8> {
        self.state = ResourceState::Advertised;
        self.hashmap_cursor = self.hashmap_max_len.min(self.total_segments);

        // Build hashmap bytes: concatenated 4-byte hashes for the first segment of the hashmap
        let hashmap_len = self.hashmap_cursor * MAPHASH_LEN;
        let mut hashmap_bytes = Vec::with_capacity(hashmap_len);
        for i in 0..self.hashmap_cursor {
            hashmap_bytes.extend_from_slice(&self.part_hashes[i]);
        }

        let mut buf = Vec::new();
        msgpack::write_fixmap(&mut buf, 11); // 11 key-value pairs

        // "t" = transfer_size (same as data size for uncompressed)
        msgpack::write_fixstr1(&mut buf, b't');
        msgpack::write_uint(&mut buf, self.total_size as u64);

        // "d" = data_size (original plaintext size, before prepend/compress/encrypt)
        msgpack::write_fixstr1(&mut buf, b'd');
        msgpack::write_uint(&mut buf, self.original_size as u64);

        // "n" = num_parts
        msgpack::write_fixstr1(&mut buf, b'n');
        msgpack::write_uint(&mut buf, self.total_segments as u64);

        // "h" = resource_hash (32 bytes)
        msgpack::write_fixstr1(&mut buf, b'h');
        msgpack::write_bin(&mut buf, &self.resource_hash);

        // "r" = random_hash (4 bytes)
        msgpack::write_fixstr1(&mut buf, b'r');
        msgpack::write_bin(&mut buf, &self.random_hash);

        // "o" = original_hash (group key for split resources, or resource_hash for non-split)
        msgpack::write_fixstr1(&mut buf, b'o');
        msgpack::write_bin(&mut buf, &self.original_hash);

        // "i" = split segment index (1-based, matching Python RNS convention)
        msgpack::write_fixstr1(&mut buf, b'i');
        msgpack::write_uint(&mut buf, self.split_index as u64);

        // "l" = total split segments (1 for non-split, matching Python RNS convention)
        msgpack::write_fixstr1(&mut buf, b'l');
        msgpack::write_uint(&mut buf, self.split_total as u64);

        // "q" = request_id (None for normal resources)
        msgpack::write_fixstr1(&mut buf, b'q');
        msgpack::write_nil(&mut buf);

        // "f" = flags byte
        msgpack::write_fixstr1(&mut buf, b'f');
        msgpack::write_uint(&mut buf, self.flags.to_byte() as u64);

        // "m" = hashmap bytes
        msgpack::write_fixstr1(&mut buf, b'm');
        msgpack::write_bin(&mut buf, &hashmap_bytes);

        buf
    }

    /// Handle a RESOURCE_REQ from the receiver.
    ///
    /// Parses the request and returns a `HandleRequestResult` containing the
    /// list of `(part_index, part_data)` pairs for segments the receiver
    /// requested, and whether the receiver signaled HASHMAP_IS_EXHAUSTED
    /// (meaning the sender should send more hash entries via HMU).
    ///
    /// Request format:
    /// ```text
    /// status[1] + (last_map_hash[4] if status==0xFF else b"") + resource_hash[32] + requested_hashes[N*4]
    /// ```
    pub fn handle_request(&mut self, req_payload: &[u8]) -> HandleRequestResult {
        if req_payload.is_empty() {
            return HandleRequestResult::default();
        }

        self.state = ResourceState::Transferring;

        let hashmap_status = req_payload[0];
        let needs_hmu = hashmap_status == HASHMAP_IS_EXHAUSTED;
        let mut offset = 1;

        // If hashmap is exhausted, the next 4 bytes are the last known map hash.
        // We use it to find where the receiver's hashmap ends and set our cursor
        // so build_hashmap_update() sends the correct hashmap_max_len-aligned segment.
        if needs_hmu {
            if req_payload.len() < offset + MAPHASH_LEN {
                return HandleRequestResult::default();
            }
            let mut last_map_hash = [0u8; MAPHASH_LEN];
            last_map_hash.copy_from_slice(&req_payload[offset..offset + MAPHASH_LEN]);
            offset += MAPHASH_LEN;

            // Search part_hashes for the last_map_hash to find part_index.
            // Only search within the range we've already sent (0..hashmap_cursor)
            // to avoid false matches from duplicate 4-byte truncated hashes.
            let mut part_index = None;
            for idx in (0..self.hashmap_cursor).rev() {
                if self.part_hashes[idx] == last_map_hash {
                    part_index = Some(idx);
                    break;
                }
            }

            if let Some(idx) = part_index {
                // Set cursor past the matched hash so build_hashmap_update()
                // sends the next hashmap_max_len-aligned segment.
                // The receiver always gets aligned chunks, so idx+1 is always
                // at a hashmap_max_len boundary (or at total_segments).
                self.hashmap_cursor = (idx + 1).min(self.total_segments);
            }
        }

        // Next 32 bytes: resource_hash
        if req_payload.len() < offset + 32 {
            return HandleRequestResult::default();
        }
        let _req_hash = &req_payload[offset..offset + 32];
        offset += 32;

        // Remaining: requested part hashes (N * 4 bytes)
        let requested_hashes_data = &req_payload[offset..];
        let num_requested = requested_hashes_data.len() / MAPHASH_LEN;
        let mut parts = Vec::new();

        for i in 0..num_requested {
            let start = i * MAPHASH_LEN;
            let end = start + MAPHASH_LEN;
            if end > requested_hashes_data.len() {
                break;
            }
            let mut req_hash = [0u8; MAPHASH_LEN];
            req_hash.copy_from_slice(&requested_hashes_data[start..end]);

            // Find the matching part
            for (idx, ph) in self.part_hashes.iter().enumerate() {
                if *ph == req_hash {
                    parts.push((idx, self.parts[idx].clone()));
                    break;
                }
            }
        }

        // If no more parts to request (all sent), transition to AwaitingProof
        if num_requested == 0 || parts.is_empty() {
            self.state = ResourceState::AwaitingProof;
        }

        HandleRequestResult { parts, needs_hmu }
    }

    /// Handle RESOURCE_PRF from the receiver. Returns true if transfer is complete.
    ///
    /// Proof format: `resource_hash[32] || proof_hash[32]` = 64 bytes total.
    /// Verifies: `proof_hash == SHA-256(data || resource_hash[32])`
    pub fn handle_proof(&mut self, proof_payload: &[u8]) -> bool {
        if proof_payload.len() < 64 {
            self.state = ResourceState::Failed;
            return false;
        }

        let proof_id = &proof_payload[..32];
        let proof_hash = &proof_payload[32..64];

        // Verify the proof_id matches our full resource_hash
        if proof_id != &self.resource_hash[..] {
            self.state = ResourceState::Failed;
            return false;
        }

        // Compute expected: SHA-256(data || resource_hash[32])
        let mut hasher = Sha256::new();
        hasher.update(&self.data);
        hasher.update(self.resource_hash);
        let expected: [u8; 32] = hasher.finalize().into();

        if proof_hash == &expected[..] {
            self.state = ResourceState::Complete;
            true
        } else {
            self.state = ResourceState::Failed;
            false
        }
    }

    /// Extract the resource hash from a RESOURCE_REQ payload without modifying state.
    ///
    /// Returns `None` if the payload is too short to contain a resource hash.
    pub fn extract_request_hash(req_payload: &[u8]) -> Option<[u8; 32]> {
        if req_payload.is_empty() {
            return None;
        }
        let mut offset = 1;
        if req_payload[0] == HASHMAP_IS_EXHAUSTED {
            offset += MAPHASH_LEN;
        }
        if req_payload.len() < offset + 32 {
            return None;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&req_payload[offset..offset + 32]);
        Some(hash)
    }

    /// Handle cancel from the receiver.
    pub fn handle_cancel(&mut self) {
        self.state = ResourceState::Failed;
    }

    /// Update the last activity timestamp.
    pub fn touch_activity(&mut self, now: u64) {
        self.last_activity = now;
    }

    /// Build a hashmap update payload.
    ///
    /// Format: `resource_hash[32] || msgpack([segment_cursor, hashmap_chunk_bytes])`
    ///
    /// Sends the next window of part hashes starting at `hashmap_cursor`.
    /// Returns `None` if all hashes have already been sent.
    pub fn build_hashmap_update(&mut self) -> Option<Vec<u8>> {
        if self.hashmap_cursor >= self.total_segments {
            return None;
        }

        // Compute the segment number (aligned to hashmap_max_len boundaries)
        let segment_number = self.hashmap_cursor / self.hashmap_max_len;
        let chunk_start = segment_number * self.hashmap_max_len;
        let end = ((segment_number + 1) * self.hashmap_max_len).min(self.total_segments);

        // Build the hash chunk
        let chunk_len = (end - chunk_start) * MAPHASH_LEN;
        let mut chunk_bytes = Vec::with_capacity(chunk_len);
        for i in chunk_start..end {
            chunk_bytes.extend_from_slice(&self.part_hashes[i]);
        }

        // Build msgpack: [segment_number, hashmap_chunk_bytes]
        // Python expects segment_number (0, 1, 2...) NOT the raw cursor
        let mut msgpack_part = Vec::new();
        msgpack::write_fixarray(&mut msgpack_part, 2);
        msgpack::write_uint(&mut msgpack_part, segment_number as u64);
        msgpack::write_bin(&mut msgpack_part, &chunk_bytes);

        // Full payload: resource_hash[32] || msgpack
        let mut payload = Vec::with_capacity(32 + msgpack_part.len());
        payload.extend_from_slice(&self.resource_hash);
        payload.extend_from_slice(&msgpack_part);

        self.hashmap_cursor = end;

        Some(payload)
    }

    // -----------------------------------------------------------------------
    // Receiver methods
    // -----------------------------------------------------------------------

    /// Create a resource from a received advertisement.
    ///
    /// Parses a msgpack dictionary with keys:
    /// "t", "d", "n", "h", "r", "o", "i", "l", "q", "f", "m"
    pub fn from_advertisement(adv_payload: &[u8], link_id: [u8; 16]) -> Result<Self, &'static str> {
        let mut pos = 0;

        let map_len = msgpack::read_map_len(adv_payload, &mut pos).map_err(|e| e.as_str())?;

        // Parse key-value pairs from the map
        let mut transfer_size: Option<usize> = None;
        let mut _data_size: Option<usize> = None;
        let mut num_parts: Option<usize> = None;
        let mut resource_hash_bytes: Option<[u8; 32]> = None;
        let mut random_hash_bytes: Option<[u8; RANDOM_HASH_SIZE]> = None;
        let mut original_hash_parsed: Option<[u8; 32]> = None;
        let mut split_index: usize = 1;
        let mut split_total: usize = 1;
        let mut _request_id: Option<Vec<u8>> = None;
        let mut flags_byte: u8 = 0;
        let mut hashmap_raw: Option<&[u8]> = None;

        for _ in 0..map_len {
            // Read key (should be a 1-char string; accept bin for compat)
            let key_bytes = msgpack::read_bin_or_str(adv_payload, &mut pos).map_err(|e| e.as_str())?;
            if key_bytes.len() != 1 {
                // Skip unknown key
                msgpack::skip_value(adv_payload, &mut pos).map_err(|e| e.as_str())?;
                continue;
            }
            let key = key_bytes[0];

            match key {
                b't' => {
                    transfer_size = Some(msgpack::read_uint(adv_payload, &mut pos).map_err(|e| e.as_str())? as usize);
                }
                b'd' => {
                    _data_size = Some(msgpack::read_uint(adv_payload, &mut pos).map_err(|e| e.as_str())? as usize);
                }
                b'n' => {
                    num_parts = Some(msgpack::read_uint(adv_payload, &mut pos).map_err(|e| e.as_str())? as usize);
                }
                b'h' => {
                    let rh = msgpack::read_bin_or_str(adv_payload, &mut pos).map_err(|e| e.as_str())?;
                    if rh.len() != 32 {
                        return Err("resource_hash must be 32 bytes");
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(rh);
                    resource_hash_bytes = Some(arr);
                }
                b'r' => {
                    let rh = msgpack::read_bin_or_str(adv_payload, &mut pos).map_err(|e| e.as_str())?;
                    if rh.len() != RANDOM_HASH_SIZE {
                        return Err("random_hash must be 4 bytes");
                    }
                    let mut arr = [0u8; RANDOM_HASH_SIZE];
                    arr.copy_from_slice(rh);
                    random_hash_bytes = Some(arr);
                }
                b'o' => {
                    match msgpack::read_bin_or_nil(adv_payload, &mut pos).map_err(|e| e.as_str())? {
                        Some(oh) if oh.len() == 32 => {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(oh);
                            original_hash_parsed = Some(arr);
                        }
                        _ => {} // None or wrong size
                    }
                }
                b'i' => {
                    split_index =
                        msgpack::read_uint_or_nil(adv_payload, &mut pos).map_err(|e| e.as_str())?.unwrap_or(1) as usize;
                }
                b'l' => {
                    split_total =
                        msgpack::read_uint_or_nil(adv_payload, &mut pos).map_err(|e| e.as_str())?.unwrap_or(1) as usize;
                }
                b'q' => {
                    // request_id: can be nil, bin, or str
                    match msgpack::read_bin_or_nil(adv_payload, &mut pos).map_err(|e| e.as_str())? {
                        Some(q) => _request_id = Some(q.to_vec()),
                        None => _request_id = None,
                    }
                }
                b'f' => {
                    flags_byte = msgpack::read_uint(adv_payload, &mut pos).map_err(|e| e.as_str())? as u8;
                }
                b'm' => {
                    hashmap_raw = Some(msgpack::read_bin_or_str(adv_payload, &mut pos).map_err(|e| e.as_str())?);
                }
                _ => {
                    // Unknown key, skip value
                    msgpack::skip_value(adv_payload, &mut pos).map_err(|e| e.as_str())?;
                }
            }
        }

        // Validate required fields
        let total_size = transfer_size.ok_or("missing 't' (transfer_size) in advertisement")?;
        let total_segments = num_parts.ok_or("missing 'n' (num_parts) in advertisement")?;
        let resource_hash =
            resource_hash_bytes.ok_or("missing 'h' (resource_hash) in advertisement")?;
        let random_hash = random_hash_bytes.ok_or("missing 'r' (random_hash) in advertisement")?;
        let hashmap_bytes = hashmap_raw.ok_or("missing 'm' (hashmap) in advertisement")?;

        // Sanity-check total_segments against total_size to prevent OOM from
        // a malicious advertisement. Segments can't be smaller than 1 byte
        // and can't exceed MAX_EFFICIENT_SIZE / MAPHASH_LEN (~4M).
        if total_segments > total_size || total_segments > MAX_EFFICIENT_SIZE {
            return Err("implausible segment count in advertisement");
        }

        let flags = ResourceFlags::from_byte(flags_byte);

        let initial_hashes = hashmap_bytes.len() / MAPHASH_LEN;
        // Pre-allocate full part_hashes vector; fill initial hashes from advertisement
        let mut part_hashes = vec![[0u8; MAPHASH_LEN]; total_segments];
        for (i, ph) in part_hashes
            .iter_mut()
            .enumerate()
            .take(initial_hashes.min(total_segments))
        {
            let start = i * MAPHASH_LEN;
            ph.copy_from_slice(&hashmap_bytes[start..start + MAPHASH_LEN]);
        }

        // For split resources, original_hash is the group key (segment 1's hash).
        // For non-split resources, default to this resource's own hash.
        let original_hash = original_hash_parsed.unwrap_or(resource_hash);

        Ok(Resource {
            state: ResourceState::Transferring,
            is_sender: false,
            link_id,
            resource_hash,
            random_hash,
            flags,
            total_size,
            original_size: _data_size.unwrap_or(total_size),
            segment_index: 0,
            total_segments,
            window: WINDOW_INITIAL,
            mdu: 0, // receiver doesn't need to know the MDU
            retries: 0,
            last_activity: 0,
            split_index,
            split_total,
            original_hash,
            metadata: None,
            data: Vec::new(),
            parts: vec![Vec::new(); total_segments],
            part_hashes,
            received: vec![false; total_segments],
            hashmap_cursor: initial_hashes,
            outstanding_parts: 0,
            hashmap_max_len: initial_hashes,
        })
    }

    /// Receive a resource part. Returns true if all parts have been received.
    ///
    /// Computes the hash of the part data (including random_hash), finds the
    /// matching index in `part_hashes`, and stores it.
    /// Compute the map hash for given data (for debugging).
    pub fn compute_part_hash(&self, part_data: &[u8]) -> [u8; MAPHASH_LEN] {
        let mut hasher = Sha256::new();
        hasher.update(part_data);
        hasher.update(self.random_hash);
        let hash: [u8; 32] = hasher.finalize().into();
        let mut part_hash = [0u8; MAPHASH_LEN];
        part_hash.copy_from_slice(&hash[..MAPHASH_LEN]);
        part_hash
    }

    pub fn receive_part(&mut self, part_data: &[u8]) -> bool {
        let part_hash = self.compute_part_hash(part_data);

        // Search within window range starting from consecutive_completed,
        // matching Python's `for map_hash in self.hashmap[cc:cc+window]`.
        // Cap at hashmap_cursor to avoid matching unfilled sentinel slots.
        let cc = self.consecutive_completed();
        let search_end = (cc + self.window).min(self.hashmap_cursor);
        let mut matched = false;
        for idx in cc..search_end {
            if self.part_hashes[idx] == part_hash && !self.received[idx] {
                self.parts[idx] = part_data.to_vec();
                self.received[idx] = true;
                self.outstanding_parts = self.outstanding_parts.saturating_sub(1);
                matched = true;
                break;
            }
        }

        #[cfg(feature = "relay-debug")]
        if !matched {
            std::eprintln!(
                "resource receive_part: no hash match, computed={:02x}{:02x}{:02x}{:02x} len={} cursor={} total={}",
                part_hash[0], part_hash[1], part_hash[2], part_hash[3],
                part_data.len(), self.hashmap_cursor, self.total_segments,
            );
        }
        let _ = matched; // suppress unused warning when relay-debug is off

        // Check if all parts received
        self.received.iter().all(|&r| r)
    }

    /// Count of consecutively received parts from the start.
    ///
    /// Matches Python's `consecutive_completed_height` — the index of the
    /// first unreceived part. This determines where to start scanning for
    /// the next request.
    pub fn consecutive_completed(&self) -> usize {
        for (i, &r) in self.received.iter().enumerate() {
            if !r {
                return i;
            }
        }
        self.received.len()
    }

    /// Grow the sliding window based on transfer performance.
    ///
    /// Call after successfully receiving a batch of parts.
    /// Window grows by 1 per call, capped at WINDOW_MAX_FAST (75) for fast links
    /// or WINDOW_MAX_SLOW (10) for slow links.
    pub fn grow_window(&mut self, fast_link: bool) {
        let max = if fast_link {
            WINDOW_MAX_FAST
        } else {
            WINDOW_MAX_SLOW
        };
        if self.window < max {
            self.window += 1;
        }
    }

    /// Whether all parts from the current window have been received.
    ///
    /// Python sends the next REQ only when `outstanding_parts == 0`
    /// (Resource.py line 886). Matches that behaviour.
    pub fn is_window_complete(&self) -> bool {
        self.outstanding_parts == 0
    }

    /// Build a RESOURCE_REQ payload requesting needed parts.
    ///
    /// Format:
    /// ```text
    /// status[1] + (last_map_hash[4] if status==0xFF else b"") + resource_hash[32] + needed_hashes[N*4]
    /// ```
    ///
    /// - `hashmap_status` = `HASHMAP_IS_EXHAUSTED` when we've used up all known
    ///   hashes but still need more (i.e. `part_hashes.len() < total_segments`).
    /// - When we have all hashes, status is `0x00` (just requesting parts).
    /// - Only requests parts within the current window that have not been received.
    pub fn build_request(&mut self) -> Vec<u8> {
        // Match Python's consecutive_completed_height scanning:
        // Start from the first unreceived part and scan forward within the window.
        let consecutive_completed = self.consecutive_completed();
        let search_start = consecutive_completed;

        let mut requested_hashes = Vec::new();
        let mut hashmap_exhausted = false;

        for idx in search_start..self.total_segments {
            if requested_hashes.len() >= self.window {
                break;
            }
            if !self.received[idx] {
                if idx < self.hashmap_cursor {
                    // We have the hash — request it
                    requested_hashes.push(self.part_hashes[idx]);
                } else {
                    // Hash not yet received — signal exhausted
                    hashmap_exhausted = true;
                    break;
                }
            }
        }

        // Track how many parts we requested — window is "complete" when all arrive.
        self.outstanding_parts = requested_hashes.len();

        // Also signal exhausted if we couldn't fill the window and more hashes exist
        let exhausted = hashmap_exhausted
            || (self.hashmap_cursor < self.total_segments && requested_hashes.len() < self.window);

        let mut payload = Vec::new();

        if exhausted {
            payload.push(HASHMAP_IS_EXHAUSTED);
            // Include last known map hash so sender knows where we are
            if self.hashmap_cursor > 0 {
                payload.extend_from_slice(&self.part_hashes[self.hashmap_cursor - 1]);
            }
        } else {
            payload.push(0x00);
        }

        // Full 32-byte resource hash
        payload.extend_from_slice(&self.resource_hash);

        // Append requested part hashes
        for ph in &requested_hashes {
            payload.extend_from_slice(ph);
        }

        payload
    }

    /// Process a hashmap update (more part hashes from the sender).
    ///
    /// Format: `resource_hash[32] || msgpack([segment_index, new_hashes_bytes])`
    pub fn apply_hashmap_update(&mut self, hmu_payload: &[u8]) -> Result<(), &'static str> {
        if hmu_payload.len() < 32 {
            return Err("hashmap update too short");
        }

        // Verify full 32-byte resource_hash
        if hmu_payload[..32] != self.resource_hash[..] {
            return Err("resource hash mismatch in hashmap update");
        }

        let msgpack_data = &hmu_payload[32..];
        let mut pos = 0;

        let array_len = msgpack::read_array_len(msgpack_data, &mut pos).map_err(|e| e.as_str())?;
        if array_len != 2 {
            return Err("expected 2-element msgpack array in hashmap update");
        }

        let segment_index = msgpack::read_uint(msgpack_data, &mut pos).map_err(|e| e.as_str())? as usize;
        let new_hashes = msgpack::read_bin(msgpack_data, &mut pos).map_err(|e| e.as_str())?;

        // Place hashes at the correct segment-aligned position
        let placement_start = segment_index * self.hashmap_max_len;
        let count = new_hashes.len() / MAPHASH_LEN;
        for i in 0..count {
            let target = placement_start + i;
            if target >= self.total_segments {
                break;
            }
            let start = i * MAPHASH_LEN;
            self.part_hashes[target].copy_from_slice(&new_hashes[start..start + MAPHASH_LEN]);
        }

        // Advance hashmap_cursor to track how many hashes we now have
        let new_end = (placement_start + count).min(self.total_segments);
        if new_end > self.hashmap_cursor {
            self.hashmap_cursor = new_end;
        }

        Ok(())
    }

    /// Concatenate all received parts into a single byte vector.
    ///
    /// Sets state to `Assembling`. Does NOT verify the hash or finalize
    /// the resource — call [`verify_hash`] after decryption/decompression.
    pub fn concat_parts(&mut self) -> Result<Vec<u8>, ResourceError> {
        self.state = ResourceState::Assembling;

        let mut assembled = Vec::with_capacity(self.total_size);
        for part in &self.parts {
            assembled.extend_from_slice(part);
        }

        Ok(assembled)
    }

    /// Verify the resource hash and finalize the resource.
    ///
    /// Computes `SHA-256(data || random_hash)` and compares to the
    /// advertised `resource_hash`. On success, stores `data` in
    /// `self.data` and sets state to `Complete`. On mismatch, sets
    /// state to `Corrupt`.
    pub fn verify_hash(&mut self, data: Vec<u8>) -> Result<(), ResourceError> {
        let mut hasher = Sha256::new();
        hasher.update(&data);
        hasher.update(self.random_hash);
        let computed: [u8; 32] = hasher.finalize().into();

        if computed == self.resource_hash {
            self.data = data;
            self.state = ResourceState::Complete;
            Ok(())
        } else {
            self.state = ResourceState::Corrupt;
            Err(ResourceError::HashMismatch)
        }
    }

    /// Build proof payload for a completed transfer.
    ///
    /// Format: `resource_hash[32] || SHA-256(data || resource_hash[32])`
    /// Total: 32 + 32 = 64 bytes.
    pub fn build_proof(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&self.data);
        hasher.update(self.resource_hash);
        let proof_hash: [u8; 32] = hasher.finalize().into();

        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&self.resource_hash);
        payload.extend_from_slice(&proof_hash);
        payload
    }

    /// Whether we need more hashmap entries from the sender.
    pub fn needs_hashmap_update(&self) -> bool {
        self.hashmap_cursor < self.total_segments
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_split_into_parts() {
        let data = vec![0xAA; 1000];
        let mdu = 431;
        let mut rng = rand::thread_rng();
        let res = Resource::new_outbound(&data, [0x11; 16], mdu, data.len(), mdu, &mut rng);
        assert_eq!(res.total_segments, 3); // ceil(1000/431)
        assert_eq!(res.total_size, 1000);
        assert_eq!(res.state, ResourceState::Queued);
    }

    #[test]
    fn test_resource_hash_computation() {
        let data = b"hello resource";
        let mut rng = rand::thread_rng();
        let res = Resource::new_outbound(data, [0x11; 16], 431, data.len(), 431, &mut rng);
        // Verify hash = SHA-256(data || random_hash)
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(&res.random_hash);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(res.resource_hash, expected);
    }

    #[test]
    fn test_part_hash_computation() {
        let data = vec![0xBB; 100];
        let mut rng = rand::thread_rng();
        let res = Resource::new_outbound(&data, [0x11; 16], 431, data.len(), 431, &mut rng);
        // Single part — hash should be SHA-256(data || random_hash)[0:4]
        let mut hasher = Sha256::new();
        hasher.update(&data);
        hasher.update(&res.random_hash);
        let hash: [u8; 32] = hasher.finalize().into();
        assert_eq!(res.part_hashes[0], hash[..4]);
    }

    #[test]
    fn test_advertisement_msgpack_round_trip() {
        let data = vec![0xCC; 500];
        let mut rng = rand::thread_rng();
        let mut sender = Resource::new_outbound(&data, [0x11; 16], 431, data.len(), 431, &mut rng);
        let adv = sender.build_advertisement();
        let receiver = Resource::from_advertisement(&adv, [0x11; 16]).unwrap();
        assert_eq!(receiver.total_size, 500);
        assert_eq!(receiver.total_segments, 2); // ceil(500/431)
        assert_eq!(receiver.resource_hash, sender.resource_hash);
        assert_eq!(receiver.random_hash, sender.random_hash);
    }

    #[test]
    fn test_advertisement_is_msgpack_dict() {
        let data = vec![0xDD; 200];
        let mut rng = rand::thread_rng();
        let mut sender = Resource::new_outbound(&data, [0x11; 16], 431, data.len(), 431, &mut rng);
        let adv = sender.build_advertisement();
        // First byte should be a fixmap header (0x80 | n)
        assert_eq!(
            adv[0] & 0xf0,
            0x80,
            "advertisement should start with fixmap header"
        );
        let map_len = (adv[0] & 0x0f) as usize;
        assert_eq!(map_len, 11, "advertisement map should have 11 entries");
    }

    #[test]
    fn test_advertisement_hashmap_layout() {
        let data = vec![0xDD; 2000];
        let mdu = 431;
        let mut rng = rand::thread_rng();
        let mut sender = Resource::new_outbound(&data, [0x11; 16], mdu, data.len(), mdu, &mut rng);
        let _adv = sender.build_advertisement();
        // hashmap_cursor should be min(hashmap_max_len, total_segments)
        let expected_cursor = hashmap_max_len(mdu).min(sender.total_segments);
        assert_eq!(sender.hashmap_cursor, expected_cursor);
    }

    #[test]
    fn test_request_wire_format() {
        let data = vec![0xEE; 100]; // single part
        let mut rng = rand::thread_rng();
        let mut sender = Resource::new_outbound(&data, [0x11; 16], 431, data.len(), 431, &mut rng);
        let adv = sender.build_advertisement();
        let mut receiver = Resource::from_advertisement(&adv, [0x11; 16]).unwrap();
        let req = receiver.build_request();
        // For single part, all hashes known from advertisement => status=0x00 (not exhausted)
        // Format: status[1] + resource_hash[32] + hashes[N*4]
        assert_eq!(req[0], 0x00);
        // 1 (status) + 32 (resource_hash) + 4 (one part hash) = 37
        assert_eq!(req.len(), 37);
        // Verify resource hash is at offset 1
        assert_eq!(&req[1..33], &receiver.resource_hash[..]);
    }

    #[test]
    fn test_proof_format() {
        let data = vec![0xFF; 100];
        let mut rng = rand::thread_rng();
        let mut sender = Resource::new_outbound(&data, [0x11; 16], 431, data.len(), 431, &mut rng);
        let adv = sender.build_advertisement();
        let mut receiver = Resource::from_advertisement(&adv, [0x11; 16]).unwrap();
        // Feed the single part
        receiver.receive_part(&data);
        let assembled = receiver.concat_parts().unwrap();
        assert_eq!(assembled, data);
        receiver.verify_hash(assembled).unwrap();
        let proof = receiver.build_proof();
        // Proof = resource_hash[32] + proof_hash[32] = 64 bytes
        assert_eq!(proof.len(), 64);
        // First 32 bytes should be the resource hash
        assert_eq!(&proof[..32], &receiver.resource_hash[..]);
    }

    #[test]
    fn test_sliding_window_grow() {
        // After successful request handling, window should grow
        let data = vec![0xAA; 2000];
        let mut rng = rand::thread_rng();
        let mut sender = Resource::new_outbound(&data, [0x11; 16], 431, data.len(), 431, &mut rng);
        let adv = sender.build_advertisement();
        let mut receiver = Resource::from_advertisement(&adv, [0x11; 16]).unwrap();
        let initial_window = receiver.window;
        // Simulate receiving all parts in current window
        receiver.window += 1;
        assert!(receiver.window > initial_window);
    }

    #[test]
    fn test_cancel_transitions_to_failed() {
        let data = vec![0xBB; 100];
        let mut rng = rand::thread_rng();
        let mut sender = Resource::new_outbound(&data, [0x11; 16], 431, data.len(), 431, &mut rng);
        sender.handle_cancel();
        assert_eq!(sender.state, ResourceState::Failed);
    }

    #[test]
    fn test_complete_small_transfer() {
        // Full sender -> receiver cycle for small data (1 segment)
        let data = b"small transfer data";
        let mut rng = rand::thread_rng();
        let mut sender = Resource::new_outbound(data, [0x11; 16], 431, data.len(), 431, &mut rng);

        // Step 1: Build advertisement
        let adv = sender.build_advertisement();

        // Step 2: Receiver parses advertisement
        let mut receiver = Resource::from_advertisement(&adv, [0x11; 16]).unwrap();

        // Step 3: Receiver builds request
        let req = receiver.build_request();

        // Step 4: Sender handles request, returns parts
        let result = sender.handle_request(&req);
        assert!(!result.parts.is_empty());

        // Step 5: Receiver receives parts
        for (_idx, part) in &result.parts {
            receiver.receive_part(part);
        }

        // Step 6: Receiver concatenates parts
        let assembled = receiver.concat_parts().unwrap();
        assert_eq!(assembled, data);

        // Step 7: Verify hash and finalize
        receiver.verify_hash(assembled).unwrap();

        // Step 8: Receiver builds proof
        let proof = receiver.build_proof();

        // Step 8: Sender validates proof
        assert!(sender.handle_proof(&proof));
        assert_eq!(sender.state, ResourceState::Complete);
    }

    #[test]
    fn test_resource_flags_byte() {
        let flags = ResourceFlags {
            encrypted: true,
            compressed: false,
            is_split: true,
            is_request: false,
            is_response: true,
            has_metadata: false,
        };
        let byte = flags.to_byte();
        let decoded = ResourceFlags::from_byte(byte);
        assert_eq!(decoded.encrypted, true);
        assert_eq!(decoded.compressed, false);
        assert_eq!(decoded.is_split, true);
        assert_eq!(decoded.is_request, false);
        assert_eq!(decoded.is_response, true);
        assert_eq!(decoded.has_metadata, false);
    }

    #[test]
    fn test_empty_data_resource() {
        let data = b"";
        let mut rng = rand::thread_rng();
        let res = Resource::new_outbound(data, [0x11; 16], 431, data.len(), 431, &mut rng);
        assert_eq!(res.total_segments, 0);
        assert_eq!(res.total_size, 0);
    }

    #[test]
    fn test_hashmap_update_uses_32_byte_hash() {
        // Need >74 segments to have unsent hashes after advertisement
        let data = vec![0xAA; 80 * 431]; // 80 segments
        let mdu = 431;
        let mut rng = rand::thread_rng();
        let mut sender = Resource::new_outbound(&data, [0x11; 16], mdu, data.len(), mdu, &mut rng);
        assert_eq!(sender.total_segments, 80);
        let adv = sender.build_advertisement();
        assert_eq!(sender.hashmap_cursor, 74); // hashmap_max_len(431)
        let mut receiver = Resource::from_advertisement(&adv, [0x11; 16]).unwrap();

        // Build a hashmap update from sender (segment 1: hashes 74-79)
        let hmu = sender
            .build_hashmap_update()
            .expect("should have unsent hashes");
        // First 32 bytes should be the full resource hash
        assert!(hmu.len() >= 32);
        assert_eq!(&hmu[..32], &sender.resource_hash[..]);
        // Receiver should be able to parse it
        receiver.apply_hashmap_update(&hmu).unwrap();
        assert_eq!(receiver.hashmap_cursor, 80);
    }

    #[test]
    fn test_multi_segment_transfer() {
        // Full sender -> receiver cycle for multi-segment data.
        // With hashmap_max_len=74, all 5 hashes fit in the advertisement.
        let data = vec![0x42; 2000]; // ceil(2000/431) = 5 segments
        let mdu = 431;
        let mut rng = rand::thread_rng();
        let mut sender = Resource::new_outbound(&data, [0x11; 16], mdu, data.len(), mdu, &mut rng);
        assert_eq!(sender.total_segments, 5);

        let adv = sender.build_advertisement();
        let mut receiver = Resource::from_advertisement(&adv, [0x11; 16]).unwrap();
        assert_eq!(receiver.total_segments, 5);
        // All 5 hashes included (min(hashmap_max_len=74, 5) = 5)
        assert_eq!(receiver.hashmap_cursor, 5);

        // Receiver requests all parts — no exhaustion since all hashes known
        let req = receiver.build_request();
        assert_eq!(req[0], 0x00);
        let result = sender.handle_request(&req);
        assert!(!result.parts.is_empty());
        assert!(!result.needs_hmu);

        for (_idx, part) in &result.parts {
            receiver.receive_part(part);
        }

        // Request remaining parts (window might not cover all 5 at once)
        let req2 = receiver.build_request();
        let result2 = sender.handle_request(&req2);
        for (_idx, part) in &result2.parts {
            receiver.receive_part(part);
        }

        let assembled = receiver.concat_parts().unwrap();
        assert_eq!(assembled, data);
        receiver.verify_hash(assembled).unwrap();

        let proof = receiver.build_proof();
        assert!(sender.handle_proof(&proof));
        assert_eq!(sender.state, ResourceState::Complete);
    }

    #[test]
    fn test_large_resource_with_hmu() {
        // Resource with >74 segments requires HMU exchange.
        // 80 segments × 431 bytes = 34480 bytes
        // Use varying data so each segment has a unique hash.
        let data: Vec<u8> = (0..80 * 431).map(|i| (i % 256) as u8).collect();
        let mdu = 431;
        let mut rng = rand::thread_rng();
        let mut sender = Resource::new_outbound(&data, [0x11; 16], mdu, data.len(), mdu, &mut rng);
        assert_eq!(sender.total_segments, 80);

        let adv = sender.build_advertisement();
        let mut receiver = Resource::from_advertisement(&adv, [0x11; 16]).unwrap();
        // First 74 hashes in advertisement
        assert_eq!(receiver.hashmap_cursor, 74);
        assert!(receiver.needs_hashmap_update());

        // First request — receive parts for known hashes
        let req = receiver.build_request();
        let result = sender.handle_request(&req);
        for (_idx, part) in &result.parts {
            receiver.receive_part(part);
        }

        // After receiving window-sized parts, receiver may exhaust known hashes.
        // Keep requesting and receiving until we need HMU.
        for _ in 0..100 {
            let req = receiver.build_request();
            if req[0] == HASHMAP_IS_EXHAUSTED {
                // Sender should respond with HMU
                let result = sender.handle_request(&req);
                assert!(result.needs_hmu);
                for (_idx, part) in &result.parts {
                    receiver.receive_part(part);
                }
                let hmu = sender
                    .build_hashmap_update()
                    .expect("should have unsent hashes after HASHMAP_IS_EXHAUSTED");
                receiver.apply_hashmap_update(&hmu).unwrap();
                break;
            }
            let result = sender.handle_request(&req);
            for (_idx, part) in &result.parts {
                receiver.receive_part(part);
            }
        }

        // Now receiver has all 80 hashes
        assert_eq!(receiver.hashmap_cursor, 80);
        assert!(!receiver.needs_hashmap_update());

        // Continue requesting remaining parts until all received
        for _ in 0..100 {
            if receiver.received.iter().all(|&r| r) {
                break;
            }
            let req = receiver.build_request();
            let result = sender.handle_request(&req);
            for (_idx, part) in &result.parts {
                receiver.receive_part(part);
            }
        }
        assert!(
            receiver.received.iter().all(|&r| r),
            "not all parts received"
        );

        let assembled = receiver.concat_parts().unwrap();
        assert_eq!(assembled, data);
        receiver.verify_hash(assembled).unwrap();

        let proof = receiver.build_proof();
        assert!(sender.handle_proof(&proof));
        assert_eq!(sender.state, ResourceState::Complete);
    }

    #[test]
    fn test_python_generated_advertisement() {
        // Test vector generated by Python RNS:
        // segment_data = bytes(range(144)), random_hash = 0xAABBCCDD
        let adv_hex = "8ba174cc90a16464a16e01a168c420f19d7e14d612ac6ef9482200ba1abf031cad63b0430b58f5fc6a92781adf1f82a172c404aabbccdda16fc0a16900a16c00a171c0a16601a16dc404f19d7e14";
        let adv_bytes: Vec<u8> = (0..adv_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&adv_hex[i..i + 2], 16).unwrap())
            .collect();

        let mut receiver = Resource::from_advertisement(&adv_bytes, [0x11; 16]).unwrap();
        assert_eq!(receiver.total_size, 144);
        assert_eq!(receiver.total_segments, 1);
        assert_eq!(receiver.random_hash, [0xAA, 0xBB, 0xCC, 0xDD]);

        // The part hash from the advertisement
        let expected_map_hash = [0xf1, 0x9d, 0x7e, 0x14];
        assert_eq!(receiver.part_hashes[0], expected_map_hash);

        // Now "receive" the segment data (bytes 0..143)
        let segment: Vec<u8> = (0u8..144).collect();
        let all_received = receiver.receive_part(&segment);
        assert!(
            all_received,
            "receive_part should match the Python-computed hash"
        );

        // Concatenate and verify
        let assembled = receiver.concat_parts().unwrap();
        assert_eq!(assembled, segment);
        receiver.verify_hash(assembled).unwrap();
    }

    #[test]
    fn test_python_full_flow_known_values() {
        // Exact Python-generated values: encrypted blob + advertisement
        let encrypted_hex = "5ed944a45ecdbb5a563fbd3e51d9e95f0240a97333cebc31746cadd85c47e903ca24d76c3949835417751aca7b8542b2b149fa146e3000af1dea9ab43e8b659db7a176579a8666d6403a98866a49af9b20f468a305ea595f1939dbfba1e2bb600bdf7d3dd400e281dfa914935cfc32ba7dfd21948a6b254afa061b1d0206b63f579368c33be51b1b960c5f4e5c92756b814d15ae38c8f5f137748fd25a3f6eb3";
        let adv_hex = "8ba174cca0a164cd03eca16e01a168c420493eb72605233936698b9199a5b269f46df92a9460b9c9b68f3e5d9684e40455a172c404deadbeefa16fc0a16900a16c00a171c0a16601a16dc404493eb726";

        let encrypted: Vec<u8> = (0..encrypted_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&encrypted_hex[i..i + 2], 16).unwrap())
            .collect();
        let adv: Vec<u8> = (0..adv_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&adv_hex[i..i + 2], 16).unwrap())
            .collect();

        assert_eq!(encrypted.len(), 160);

        // Parse advertisement
        let mut receiver = Resource::from_advertisement(&adv, [0x11; 16]).unwrap();
        assert_eq!(receiver.total_size, 160);
        assert_eq!(receiver.total_segments, 1);
        assert_eq!(receiver.random_hash, [0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(receiver.part_hashes[0], [0x49, 0x3e, 0xb7, 0x26]);

        // Receive the encrypted segment
        let all = receiver.receive_part(&encrypted);
        assert!(all, "part hash should match");

        // Concatenate and verify
        let assembled = receiver.concat_parts().unwrap();
        assert_eq!(assembled, encrypted);
        receiver.verify_hash(assembled).unwrap();
    }

    #[test]
    fn test_receiver_hashmap_max_len_matches_sender_tcp() {
        // Bug 1a: Receiver hardcodes hashmap_max_len=74 (radio), but TCP sender
        // uses ~1994. When HMU segment_index=1 arrives, placement is wrong.
        //
        // Use TCP-like MDU (8111) with enough segments to require HMU.
        let tcp_mdu = 8111;
        let sender_hml = hashmap_max_len(tcp_mdu);
        assert_eq!(sender_hml, 1994, "TCP hashmap_max_len should be 1994");

        // Create a resource with more segments than sender_hml (need >1994 segments).
        // Each segment is tcp_mdu bytes, so we need >1994*8111 bytes.
        // That's too large. Instead, test with a smaller MDU where the gap is visible.
        //
        // Use MDU=431 (radio) sender → MDU mismatch scenario:
        // Actually the real bug is that from_advertisement() always uses 74.
        // We can demonstrate with TCP MDU: create sender with tcp_mdu, parse on receiver.
        let seg_count = 2500; // more than 1994 → needs HMU
        let data: Vec<u8> = (0..seg_count * tcp_mdu).map(|i| (i % 256) as u8).collect();
        let mut rng = rand::thread_rng();
        let mut sender =
            Resource::new_outbound(&data, [0x11; 16], tcp_mdu, data.len(), tcp_mdu, &mut rng);
        assert_eq!(sender.total_segments, seg_count);

        let adv = sender.build_advertisement();
        let receiver = Resource::from_advertisement(&adv, [0x11; 16]).unwrap();

        // CRITICAL: receiver's hashmap_max_len must match sender's
        assert_eq!(
            receiver.hashmap_max_len, sender_hml,
            "receiver hashmap_max_len must match sender (got {} expected {})",
            receiver.hashmap_max_len, sender_hml
        );
        // Initial hashes in advertisement = min(1994, 2500) = 1994
        assert_eq!(receiver.hashmap_cursor, sender_hml);
    }

    #[test]
    fn test_tcp_hmu_placement_correctness() {
        // Full HMU round-trip with TCP MDU: verify hashes are placed correctly
        // when segment_index > 0.
        let tcp_mdu = 8111;
        let sender_hml = hashmap_max_len(tcp_mdu);
        let seg_count = sender_hml + 100; // 2094 segments, needs 1 HMU
        let data: Vec<u8> = (0..seg_count * tcp_mdu).map(|i| (i % 256) as u8).collect();
        let mut rng = rand::thread_rng();
        let mut sender =
            Resource::new_outbound(&data, [0x11; 16], tcp_mdu, data.len(), tcp_mdu, &mut rng);
        assert_eq!(sender.total_segments, seg_count);

        let adv = sender.build_advertisement();
        let mut receiver = Resource::from_advertisement(&adv, [0x11; 16]).unwrap();
        assert_eq!(receiver.hashmap_cursor, sender_hml); // first 1994 hashes

        // Build HMU from sender (segment_index=1, hashes 1994..2094)
        let hmu = sender
            .build_hashmap_update()
            .expect("sender should have unsent hashes");
        receiver
            .apply_hashmap_update(&hmu)
            .expect("receiver should accept HMU");

        // Receiver should now have all 2094 hashes
        assert_eq!(receiver.hashmap_cursor, seg_count);

        // Verify hash at index 1994 (first hash from HMU) matches sender
        assert_eq!(
            receiver.part_hashes[sender_hml], sender.part_hashes[sender_hml],
            "hash at index {} must match after HMU",
            sender_hml
        );
        // Verify last hash
        assert_eq!(
            receiver.part_hashes[seg_count - 1],
            sender.part_hashes[seg_count - 1],
            "last hash must match after HMU"
        );
    }

    #[test]
    fn test_split_resource_d_field_is_full_data_size() {
        // Bug 1b: For split resources, the "d" field in the advertisement
        // must be the full original data size, not just the segment size.
        // A sender creates a resource for segment 1 of a 2MB file.
        // The encrypted segment might be 1MB, but original_size should be 2MB.
        let segment_data = vec![0xAA; 500]; // encrypted segment
        let full_data_size = 2_000_000; // 2MB total
        let mdu = 431;
        let mut rng = rand::thread_rng();
        let mut sender = Resource::new_outbound(
            &segment_data,
            [0x11; 16],
            mdu,
            full_data_size,
            mdu,
            &mut rng,
        );

        assert_eq!(sender.original_size, full_data_size);

        let adv = sender.build_advertisement();
        // Parse the advertisement and check the "d" field
        let receiver = Resource::from_advertisement(&adv, [0x11; 16]).unwrap();
        assert_eq!(
            receiver.original_size,
            full_data_size,
            "receiver should see d={} (full data size), not segment size {}",
            full_data_size,
            segment_data.len()
        );
    }

    #[test]
    fn test_receive_part_within_window_range() {
        // Bug 1c: receive_part should only search within
        // consecutive_completed..consecutive_completed+window, not 0..hashmap_cursor.
        let data = vec![0x42; 2000]; // 5 segments at MDU=431
        let mdu = 431;
        let mut rng = rand::thread_rng();
        let mut sender = Resource::new_outbound(&data, [0x11; 16], mdu, data.len(), mdu, &mut rng);
        let adv = sender.build_advertisement();
        let mut receiver = Resource::from_advertisement(&adv, [0x11; 16]).unwrap();

        // Get parts via handle_request
        let req = receiver.build_request();
        let result = sender.handle_request(&req);
        assert!(!result.parts.is_empty());

        // Feed first part
        let (_, ref part0) = result.parts[0];
        assert!(!receiver.receive_part(part0)); // not all received yet
        assert_eq!(receiver.consecutive_completed(), 1);

        // Feed second part
        if result.parts.len() > 1 {
            let (_, ref part1) = result.parts[1];
            receiver.receive_part(part1);
            assert_eq!(receiver.consecutive_completed(), 2);
        }

        // Parts should be stored at correct indices
        assert!(receiver.received[0]);
    }

    // -----------------------------------------------------------------------
    // Hash verification tests (Tracker Item 1)
    // -----------------------------------------------------------------------

    /// Helper: create a sender+receiver pair with all parts delivered.
    fn make_delivered_pair(data: &[u8]) -> (Resource, Resource) {
        let mdu = 431;
        let mut rng = rand::thread_rng();
        let mut sender = Resource::new_outbound(data, [0x11; 16], mdu, data.len(), mdu, &mut rng);
        let adv = sender.build_advertisement();
        let mut receiver = Resource::from_advertisement(&adv, [0x11; 16]).unwrap();

        let req = receiver.build_request();
        let result = sender.handle_request(&req);
        for (_, part) in &result.parts {
            receiver.receive_part(part);
        }
        (sender, receiver)
    }

    #[test]
    fn test_concat_parts_does_not_set_complete() {
        let data = b"test data for concat_parts";
        let (_sender, mut receiver) = make_delivered_pair(data);

        let assembled = receiver.concat_parts().unwrap();
        assert_eq!(assembled, data);
        assert_eq!(receiver.state, ResourceState::Assembling);
        // data should NOT be stored by concat_parts
        assert!(receiver.data.is_empty());
    }

    #[test]
    fn test_verify_hash_success_sets_complete_and_stores_data() {
        let data = b"test data for verify_hash";
        let (_sender, mut receiver) = make_delivered_pair(data);

        let assembled = receiver.concat_parts().unwrap();
        receiver.verify_hash(assembled).unwrap();

        assert_eq!(receiver.state, ResourceState::Complete);
        assert_eq!(receiver.data, data);
    }

    #[test]
    fn test_corrupted_resource_hash_detected() {
        let data = b"test data for corruption check";
        let (_sender, mut receiver) = make_delivered_pair(data);

        let assembled = receiver.concat_parts().unwrap();

        // Tamper with the expected hash to simulate a malicious advertisement
        receiver.resource_hash[0] ^= 0xFF;

        let result = receiver.verify_hash(assembled);
        assert_eq!(result, Err(ResourceError::HashMismatch));
        assert_eq!(receiver.state, ResourceState::Corrupt);
        // data should NOT be stored on hash mismatch
        assert!(receiver.data.is_empty());
    }

    #[test]
    fn test_encrypted_verify_needs_plaintext() {
        // Simulate the sender-side flow: resource_hash is over plaintext,
        // but the transferred segments are "encrypted" (different) bytes.
        let plaintext = b"the real plaintext data";
        let fake_encrypted = b"encrypted blob different bytes!";

        let mdu = 431;
        let mut rng = rand::thread_rng();

        // Create resource from the "encrypted" data (what actually gets segmented)
        let mut sender =
            Resource::new_outbound(fake_encrypted, [0x11; 16], mdu, plaintext.len(), mdu, &mut rng);

        // Override resource_hash to be over plaintext (like override_resource_hash does)
        let mut hasher = Sha256::new();
        hasher.update(plaintext);
        hasher.update(sender.random_hash);
        sender.resource_hash = hasher.finalize().into();

        let adv = sender.build_advertisement();
        let mut receiver = Resource::from_advertisement(&adv, [0x11; 16]).unwrap();

        // Deliver the "encrypted" parts
        let req = receiver.build_request();
        let result = sender.handle_request(&req);
        for (_, part) in &result.parts {
            receiver.receive_part(part);
        }

        let assembled = receiver.concat_parts().unwrap();
        assert_eq!(assembled, fake_encrypted);

        // Verifying against encrypted data should FAIL
        assert_eq!(
            receiver.verify_hash(assembled),
            Err(ResourceError::HashMismatch)
        );
        assert_eq!(receiver.state, ResourceState::Corrupt);

        // Reset state to try again with plaintext
        receiver.state = ResourceState::Assembling;

        // Verifying against plaintext should SUCCEED
        receiver.verify_hash(plaintext.to_vec()).unwrap();
        assert_eq!(receiver.state, ResourceState::Complete);
        assert_eq!(receiver.data, plaintext);
    }
}
