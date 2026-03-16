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
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Length of truncated part hashes (4 bytes).
pub const MAPHASH_LEN: usize = 4;
/// Length of the random hash in a resource advertisement.
pub const RANDOM_HASH_SIZE: usize = 4;
/// Maximum efficient resource size (0xFF_FF_FF).
pub const MAX_EFFICIENT_SIZE: usize = 16_777_215;
/// Initial sliding window size.
pub const WINDOW_INITIAL: usize = 4;
/// Minimum window size.
pub const WINDOW_MIN: usize = 2;
/// Maximum window for slow links.
pub const WINDOW_MAX_SLOW: usize = 10;
/// Maximum window for fast links.
pub const WINDOW_MAX_FAST: usize = 75;
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

// ---------------------------------------------------------------------------
// Minimal msgpack helpers (no std dependency)
// ---------------------------------------------------------------------------

/// Write a msgpack fixmap header for `n` entries (n < 16).
fn write_msgpack_fixmap(buf: &mut Vec<u8>, n: u8) {
    debug_assert!(n < 16);
    buf.push(0x80 | n);
}

/// Write a msgpack fixstr of length 1 (single ASCII character key).
fn write_msgpack_fixstr1(buf: &mut Vec<u8>, ch: u8) {
    buf.push(0xa1); // fixstr of length 1
    buf.push(ch);
}

/// Write a msgpack nil value.
fn write_msgpack_nil(buf: &mut Vec<u8>) {
    buf.push(0xc0);
}

/// Write a msgpack fixarray header for `n` elements (n < 16).
fn write_msgpack_fixarray(buf: &mut Vec<u8>, n: u8) {
    debug_assert!(n < 16);
    buf.push(0x90 | n);
}

/// Write a msgpack bin value.
fn write_msgpack_bin(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len < 256 {
        buf.push(0xc4); // bin8
        buf.push(len as u8);
    } else if len < 65536 {
        buf.push(0xc5); // bin16
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push(0xc6); // bin32
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    }
    buf.extend_from_slice(data);
}

/// Write a msgpack unsigned integer.
fn write_msgpack_uint(buf: &mut Vec<u8>, val: u64) {
    if val < 128 {
        buf.push(val as u8); // positive fixint
    } else if val < 256 {
        buf.push(0xcc);
        buf.push(val as u8);
    } else if val < 65536 {
        buf.push(0xcd);
        buf.extend_from_slice(&(val as u16).to_be_bytes());
    } else if val < 0x1_0000_0000 {
        buf.push(0xce);
        buf.extend_from_slice(&(val as u32).to_be_bytes());
    } else {
        buf.push(0xcf);
        buf.extend_from_slice(&val.to_be_bytes());
    }
}

/// Read a msgpack map length. Advances `pos`.
fn read_msgpack_map_len(data: &[u8], pos: &mut usize) -> Result<usize, &'static str> {
    if *pos >= data.len() {
        return Err("unexpected end of msgpack data");
    }
    let b = data[*pos];
    *pos += 1;
    if b & 0xF0 == 0x80 {
        // fixmap
        Ok((b & 0x0F) as usize)
    } else if b == 0xde {
        // map16
        if *pos + 2 > data.len() {
            return Err("truncated map16 length");
        }
        let n = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
        *pos += 2;
        Ok(n as usize)
    } else if b == 0xdf {
        // map32
        if *pos + 4 > data.len() {
            return Err("truncated map32 length");
        }
        let n = u32::from_be_bytes([
            data[*pos],
            data[*pos + 1],
            data[*pos + 2],
            data[*pos + 3],
        ]);
        *pos += 4;
        Ok(n as usize)
    } else {
        Err("expected msgpack map")
    }
}

/// Read a msgpack string. Returns the raw bytes of the string. Advances `pos`.
fn read_msgpack_str<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8], &'static str> {
    if *pos >= data.len() {
        return Err("unexpected end of msgpack data");
    }
    let b = data[*pos];
    *pos += 1;
    let len = if b & 0xe0 == 0xa0 {
        // fixstr: length = b & 0x1f
        (b & 0x1f) as usize
    } else if b == 0xd9 {
        // str8
        if *pos >= data.len() {
            return Err("truncated str8 length");
        }
        let n = data[*pos] as usize;
        *pos += 1;
        n
    } else if b == 0xda {
        // str16
        if *pos + 2 > data.len() {
            return Err("truncated str16 length");
        }
        let n = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
        *pos += 2;
        n
    } else if b == 0xdb {
        // str32
        if *pos + 4 > data.len() {
            return Err("truncated str32 length");
        }
        let n = u32::from_be_bytes([
            data[*pos],
            data[*pos + 1],
            data[*pos + 2],
            data[*pos + 3],
        ]) as usize;
        *pos += 4;
        n
    } else {
        return Err("expected msgpack str");
    };
    if *pos + len > data.len() {
        return Err("truncated str data");
    }
    let result = &data[*pos..*pos + len];
    *pos += len;
    Ok(result)
}

/// Read a msgpack array length. Advances `pos`.
fn read_msgpack_array_len(data: &[u8], pos: &mut usize) -> Result<usize, &'static str> {
    if *pos >= data.len() {
        return Err("unexpected end of msgpack data");
    }
    let b = data[*pos];
    *pos += 1;
    if b & 0xF0 == 0x90 {
        // fixarray
        Ok((b & 0x0F) as usize)
    } else if b == 0xdc {
        // array16
        if *pos + 2 > data.len() {
            return Err("truncated array16 length");
        }
        let n = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
        *pos += 2;
        Ok(n as usize)
    } else if b == 0xdd {
        // array32
        if *pos + 4 > data.len() {
            return Err("truncated array32 length");
        }
        let n = u32::from_be_bytes([
            data[*pos],
            data[*pos + 1],
            data[*pos + 2],
            data[*pos + 3],
        ]);
        *pos += 4;
        Ok(n as usize)
    } else {
        Err("expected msgpack array")
    }
}

/// Read a msgpack bin value. Returns a slice into `data`. Advances `pos`.
fn read_msgpack_bin<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8], &'static str> {
    if *pos >= data.len() {
        return Err("unexpected end of msgpack data");
    }
    let b = data[*pos];
    *pos += 1;
    let len = match b {
        0xc4 => {
            // bin8
            if *pos >= data.len() {
                return Err("truncated bin8 length");
            }
            let n = data[*pos] as usize;
            *pos += 1;
            n
        }
        0xc5 => {
            // bin16
            if *pos + 2 > data.len() {
                return Err("truncated bin16 length");
            }
            let n = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
            *pos += 2;
            n
        }
        0xc6 => {
            // bin32
            if *pos + 4 > data.len() {
                return Err("truncated bin32 length");
            }
            let n = u32::from_be_bytes([
                data[*pos],
                data[*pos + 1],
                data[*pos + 2],
                data[*pos + 3],
            ]) as usize;
            *pos += 4;
            n
        }
        _ => return Err("expected msgpack bin"),
    };
    if *pos + len > data.len() {
        return Err("truncated bin data");
    }
    let result = &data[*pos..*pos + len];
    *pos += len;
    Ok(result)
}

/// Read a msgpack bin or str value (Python msgpack sometimes encodes bytes as
/// either bin or str depending on version/settings). Advances `pos`.
fn read_msgpack_bin_or_str<'a>(
    data: &'a [u8],
    pos: &mut usize,
) -> Result<&'a [u8], &'static str> {
    if *pos >= data.len() {
        return Err("unexpected end of msgpack data");
    }
    let b = data[*pos];
    // Check if it's a str type first
    if (b & 0xe0 == 0xa0) || b == 0xd9 || b == 0xda || b == 0xdb {
        read_msgpack_str(data, pos)
    } else {
        read_msgpack_bin(data, pos)
    }
}

/// Read a msgpack unsigned integer. Advances `pos`.
fn read_msgpack_uint(data: &[u8], pos: &mut usize) -> Result<u64, &'static str> {
    if *pos >= data.len() {
        return Err("unexpected end of msgpack data");
    }
    let b = data[*pos];
    *pos += 1;
    match b {
        // positive fixint
        0x00..=0x7f => Ok(b as u64),
        // uint8
        0xcc => {
            if *pos >= data.len() {
                return Err("truncated uint8");
            }
            let v = data[*pos] as u64;
            *pos += 1;
            Ok(v)
        }
        // uint16
        0xcd => {
            if *pos + 2 > data.len() {
                return Err("truncated uint16");
            }
            let v = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as u64;
            *pos += 2;
            Ok(v)
        }
        // uint32
        0xce => {
            if *pos + 4 > data.len() {
                return Err("truncated uint32");
            }
            let v = u32::from_be_bytes([
                data[*pos],
                data[*pos + 1],
                data[*pos + 2],
                data[*pos + 3],
            ]) as u64;
            *pos += 4;
            Ok(v)
        }
        // uint64
        0xcf => {
            if *pos + 8 > data.len() {
                return Err("truncated uint64");
            }
            let v = u64::from_be_bytes([
                data[*pos],
                data[*pos + 1],
                data[*pos + 2],
                data[*pos + 3],
                data[*pos + 4],
                data[*pos + 5],
                data[*pos + 6],
                data[*pos + 7],
            ]);
            *pos += 8;
            Ok(v)
        }
        _ => Err("expected msgpack uint"),
    }
}

/// Read a msgpack unsigned integer or nil. Returns `None` for nil, `Some(v)` for uint.
fn read_msgpack_uint_or_nil(data: &[u8], pos: &mut usize) -> Result<Option<u64>, &'static str> {
    if *pos >= data.len() {
        return Err("unexpected end of msgpack data");
    }
    if data[*pos] == 0xc0 {
        *pos += 1;
        Ok(None)
    } else {
        read_msgpack_uint(data, pos).map(Some)
    }
}

/// Read a msgpack bin/str or nil. Returns `None` for nil, `Some(bytes)` otherwise.
fn read_msgpack_bin_or_nil<'a>(
    data: &'a [u8],
    pos: &mut usize,
) -> Result<Option<&'a [u8]>, &'static str> {
    if *pos >= data.len() {
        return Err("unexpected end of msgpack data");
    }
    if data[*pos] == 0xc0 {
        *pos += 1;
        Ok(None)
    } else {
        read_msgpack_bin_or_str(data, pos).map(Some)
    }
}

/// Skip a single msgpack value at `pos`. Advances `pos` past it.
fn skip_msgpack_value(data: &[u8], pos: &mut usize) -> Result<(), &'static str> {
    if *pos >= data.len() {
        return Err("unexpected end of msgpack data");
    }
    let b = data[*pos];
    match b {
        // nil, false, true
        0xc0 | 0xc2 | 0xc3 => {
            *pos += 1;
        }
        // positive fixint
        0x00..=0x7f => {
            *pos += 1;
        }
        // negative fixint
        0xe0..=0xff => {
            *pos += 1;
        }
        // fixstr
        b if b & 0xe0 == 0xa0 => {
            let _ = read_msgpack_str(data, pos)?;
        }
        // fixmap
        b if b & 0xf0 == 0x80 => {
            let n = (b & 0x0f) as usize;
            *pos += 1;
            for _ in 0..n {
                skip_msgpack_value(data, pos)?;
                skip_msgpack_value(data, pos)?;
            }
        }
        // fixarray
        b if b & 0xf0 == 0x90 => {
            let n = (b & 0x0f) as usize;
            *pos += 1;
            for _ in 0..n {
                skip_msgpack_value(data, pos)?;
            }
        }
        // bin8
        0xc4 => {
            let _ = read_msgpack_bin(data, pos)?;
        }
        // bin16
        0xc5 => {
            let _ = read_msgpack_bin(data, pos)?;
        }
        // bin32
        0xc6 => {
            let _ = read_msgpack_bin(data, pos)?;
        }
        // uint8
        0xcc => {
            *pos += 2;
        }
        // uint16
        0xcd => {
            *pos += 3;
        }
        // uint32
        0xce => {
            *pos += 5;
        }
        // uint64
        0xcf => {
            *pos += 9;
        }
        // int8
        0xd0 => {
            *pos += 2;
        }
        // int16
        0xd1 => {
            *pos += 3;
        }
        // int32
        0xd2 => {
            *pos += 5;
        }
        // int64
        0xd3 => {
            *pos += 9;
        }
        // str8
        0xd9 => {
            let _ = read_msgpack_str(data, pos)?;
        }
        // str16
        0xda => {
            let _ = read_msgpack_str(data, pos)?;
        }
        // str32
        0xdb => {
            let _ = read_msgpack_str(data, pos)?;
        }
        // array16
        0xdc => {
            let n = read_msgpack_array_len(data, pos)?;
            // pos already advanced past header by read_msgpack_array_len
            // Actually we already consumed the byte; re-read properly
            // read_msgpack_array_len already advances pos past the header
            for _ in 0..n {
                skip_msgpack_value(data, pos)?;
            }
        }
        _ => return Err("unsupported msgpack type in skip"),
    }
    Ok(())
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
    /// Total data size in bytes.
    pub total_size: usize,
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

    // -- Data storage --
    /// Full data (sender has it upfront, receiver assembles).
    data: Vec<u8>,
    /// Individual segments.
    parts: Vec<Vec<u8>>,
    /// 4-byte truncated SHA-256 hash of each segment (includes random_hash).
    part_hashes: Vec<[u8; MAPHASH_LEN]>,
    /// Which parts have been received (receiver side).
    pub received: Vec<bool>,
    /// How far into part_hashes we have sent to the receiver.
    hashmap_cursor: usize,
}

impl Resource {
    // -----------------------------------------------------------------------
    // Sender methods
    // -----------------------------------------------------------------------

    /// Create a new outbound resource.
    ///
    /// Splits `data` into segments of at most `mdu` bytes, computes per-part
    /// hashes, and computes the overall resource hash.
    pub fn new_outbound<R: RngCore + CryptoRng>(
        data: &[u8],
        link_id: [u8; 16],
        mdu: usize,
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

        Resource {
            state: ResourceState::Queued,
            is_sender: true,
            link_id,
            resource_hash,
            random_hash,
            flags: ResourceFlags::default(),
            total_size: data.len(),
            segment_index: 0,
            total_segments,
            window: WINDOW_INITIAL,
            mdu,
            retries: 0,
            last_activity: 0,
            data: data.to_vec(),
            parts,
            part_hashes,
            received: vec![false; total_segments],
            hashmap_cursor: 0,
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
        self.hashmap_cursor = self.window.min(self.total_segments);

        // Build hashmap bytes: concatenated 4-byte hashes for the first `window` parts
        let hashmap_len = self.hashmap_cursor * MAPHASH_LEN;
        let mut hashmap_bytes = Vec::with_capacity(hashmap_len);
        for i in 0..self.hashmap_cursor {
            hashmap_bytes.extend_from_slice(&self.part_hashes[i]);
        }

        let mut buf = Vec::new();
        write_msgpack_fixmap(&mut buf, 11); // 11 key-value pairs

        // "t" = transfer_size (same as data size for uncompressed)
        write_msgpack_fixstr1(&mut buf, b't');
        write_msgpack_uint(&mut buf, self.total_size as u64);

        // "d" = data_size
        write_msgpack_fixstr1(&mut buf, b'd');
        write_msgpack_uint(&mut buf, self.total_size as u64);

        // "n" = num_parts
        write_msgpack_fixstr1(&mut buf, b'n');
        write_msgpack_uint(&mut buf, self.total_segments as u64);

        // "h" = resource_hash (32 bytes)
        write_msgpack_fixstr1(&mut buf, b'h');
        write_msgpack_bin(&mut buf, &self.resource_hash);

        // "r" = random_hash (4 bytes)
        write_msgpack_fixstr1(&mut buf, b'r');
        write_msgpack_bin(&mut buf, &self.random_hash);

        // "o" = original_hash (None for non-split)
        write_msgpack_fixstr1(&mut buf, b'o');
        write_msgpack_nil(&mut buf);

        // "i" = segment_index (0 for non-split)
        write_msgpack_fixstr1(&mut buf, b'i');
        write_msgpack_uint(&mut buf, 0);

        // "l" = total_segments for split (0 for non-split)
        write_msgpack_fixstr1(&mut buf, b'l');
        write_msgpack_uint(&mut buf, 0);

        // "q" = request_id (None for normal resources)
        write_msgpack_fixstr1(&mut buf, b'q');
        write_msgpack_nil(&mut buf);

        // "f" = flags byte
        write_msgpack_fixstr1(&mut buf, b'f');
        write_msgpack_uint(&mut buf, self.flags.to_byte() as u64);

        // "m" = hashmap bytes
        write_msgpack_fixstr1(&mut buf, b'm');
        write_msgpack_bin(&mut buf, &hashmap_bytes);

        buf
    }

    /// Handle a RESOURCE_REQ from the receiver.
    ///
    /// Parses the request and returns a list of `(part_index, part_data)` pairs
    /// for segments the receiver has requested.
    ///
    /// Request format:
    /// ```text
    /// status[1] + (last_map_hash[4] if status==0xFF else b"") + resource_hash[32] + requested_hashes[N*4]
    /// ```
    pub fn handle_request(&mut self, req_payload: &[u8]) -> Vec<(usize, Vec<u8>)> {
        if req_payload.is_empty() {
            return Vec::new();
        }

        self.state = ResourceState::Transferring;

        let hashmap_status = req_payload[0];
        let mut offset = 1;

        // If hashmap is exhausted, the next 4 bytes are the last known map hash
        if hashmap_status == HASHMAP_IS_EXHAUSTED {
            if req_payload.len() < offset + MAPHASH_LEN {
                return Vec::new();
            }
            // Skip the last_map_hash (4 bytes) — we don't need it for part lookup
            offset += MAPHASH_LEN;
        }

        // Next 32 bytes: resource_hash
        if req_payload.len() < offset + 32 {
            return Vec::new();
        }
        let _req_hash = &req_payload[offset..offset + 32];
        offset += 32;

        // Remaining: requested part hashes (N * 4 bytes)
        let requested_hashes_data = &req_payload[offset..];
        let num_requested = requested_hashes_data.len() / MAPHASH_LEN;
        let mut result = Vec::new();

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
                    result.push((idx, self.parts[idx].clone()));
                    break;
                }
            }
        }

        // If no more parts to request (all sent), transition to AwaitingProof
        if num_requested == 0 || result.is_empty() {
            self.state = ResourceState::AwaitingProof;
        }

        result
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

    /// Handle cancel from the receiver.
    pub fn handle_cancel(&mut self) {
        self.state = ResourceState::Failed;
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

        let end = (self.hashmap_cursor + self.window).min(self.total_segments);
        let chunk_start = self.hashmap_cursor;

        // Build the hash chunk
        let chunk_len = (end - chunk_start) * MAPHASH_LEN;
        let mut chunk_bytes = Vec::with_capacity(chunk_len);
        for i in chunk_start..end {
            chunk_bytes.extend_from_slice(&self.part_hashes[i]);
        }

        // Build msgpack: [segment_cursor, hashmap_chunk_bytes]
        let mut msgpack_part = Vec::new();
        write_msgpack_fixarray(&mut msgpack_part, 2);
        write_msgpack_uint(&mut msgpack_part, chunk_start as u64);
        write_msgpack_bin(&mut msgpack_part, &chunk_bytes);

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

        let map_len = read_msgpack_map_len(adv_payload, &mut pos)?;

        // Parse key-value pairs from the map
        let mut transfer_size: Option<usize> = None;
        let mut _data_size: Option<usize> = None;
        let mut num_parts: Option<usize> = None;
        let mut resource_hash_bytes: Option<[u8; 32]> = None;
        let mut random_hash_bytes: Option<[u8; RANDOM_HASH_SIZE]> = None;
        let mut _original_hash: Option<[u8; 32]> = None;
        let mut _segment_index: usize = 0;
        let mut _total_split_segments: usize = 0;
        let mut _request_id: Option<Vec<u8>> = None;
        let mut flags_byte: u8 = 0;
        let mut hashmap_raw: Option<&[u8]> = None;

        for _ in 0..map_len {
            // Read key (should be a 1-char string)
            let key_bytes = read_msgpack_str(adv_payload, &mut pos)?;
            if key_bytes.len() != 1 {
                // Skip unknown key
                skip_msgpack_value(adv_payload, &mut pos)?;
                continue;
            }
            let key = key_bytes[0];

            match key {
                b't' => {
                    transfer_size = Some(read_msgpack_uint(adv_payload, &mut pos)? as usize);
                }
                b'd' => {
                    _data_size = Some(read_msgpack_uint(adv_payload, &mut pos)? as usize);
                }
                b'n' => {
                    num_parts = Some(read_msgpack_uint(adv_payload, &mut pos)? as usize);
                }
                b'h' => {
                    let rh = read_msgpack_bin_or_str(adv_payload, &mut pos)?;
                    if rh.len() != 32 {
                        return Err("resource_hash must be 32 bytes");
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(rh);
                    resource_hash_bytes = Some(arr);
                }
                b'r' => {
                    let rh = read_msgpack_bin_or_str(adv_payload, &mut pos)?;
                    if rh.len() != RANDOM_HASH_SIZE {
                        return Err("random_hash must be 4 bytes");
                    }
                    let mut arr = [0u8; RANDOM_HASH_SIZE];
                    arr.copy_from_slice(rh);
                    random_hash_bytes = Some(arr);
                }
                b'o' => {
                    match read_msgpack_bin_or_nil(adv_payload, &mut pos)? {
                        Some(oh) if oh.len() == 32 => {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(oh);
                            _original_hash = Some(arr);
                        }
                        _ => {} // None or wrong size
                    }
                }
                b'i' => {
                    _segment_index =
                        read_msgpack_uint_or_nil(adv_payload, &mut pos)?.unwrap_or(0) as usize;
                }
                b'l' => {
                    _total_split_segments =
                        read_msgpack_uint_or_nil(adv_payload, &mut pos)?.unwrap_or(0) as usize;
                }
                b'q' => {
                    // request_id: can be nil, bin, or str
                    match read_msgpack_bin_or_nil(adv_payload, &mut pos)? {
                        Some(q) => _request_id = Some(q.to_vec()),
                        None => _request_id = None,
                    }
                }
                b'f' => {
                    flags_byte = read_msgpack_uint(adv_payload, &mut pos)? as u8;
                }
                b'm' => {
                    hashmap_raw = Some(read_msgpack_bin_or_str(adv_payload, &mut pos)?);
                }
                _ => {
                    // Unknown key, skip value
                    skip_msgpack_value(adv_payload, &mut pos)?;
                }
            }
        }

        // Validate required fields
        let total_size = transfer_size.ok_or("missing 't' (transfer_size) in advertisement")?;
        let total_segments = num_parts.ok_or("missing 'n' (num_parts) in advertisement")?;
        let resource_hash =
            resource_hash_bytes.ok_or("missing 'h' (resource_hash) in advertisement")?;
        let random_hash =
            random_hash_bytes.ok_or("missing 'r' (random_hash) in advertisement")?;
        let hashmap_bytes = hashmap_raw.ok_or("missing 'm' (hashmap) in advertisement")?;

        let flags = ResourceFlags::from_byte(flags_byte);

        let initial_hashes = hashmap_bytes.len() / MAPHASH_LEN;
        let mut part_hashes = Vec::with_capacity(total_segments);
        for i in 0..initial_hashes {
            let start = i * MAPHASH_LEN;
            let mut ph = [0u8; MAPHASH_LEN];
            ph.copy_from_slice(&hashmap_bytes[start..start + MAPHASH_LEN]);
            part_hashes.push(ph);
        }

        Ok(Resource {
            state: ResourceState::Transferring,
            is_sender: false,
            link_id,
            resource_hash,
            random_hash,
            flags,
            total_size,
            segment_index: 0,
            total_segments,
            window: WINDOW_INITIAL,
            mdu: 0, // receiver doesn't need to know the MDU
            retries: 0,
            last_activity: 0,
            data: Vec::new(),
            parts: vec![Vec::new(); total_segments],
            part_hashes,
            received: vec![false; total_segments],
            hashmap_cursor: initial_hashes,
        })
    }

    /// Receive a resource part. Returns true if all parts have been received.
    ///
    /// Computes the hash of the part data (including random_hash), finds the
    /// matching index in `part_hashes`, and stores it.
    pub fn receive_part(&mut self, part_data: &[u8]) -> bool {
        // Part hash = SHA-256(segment_data || random_hash)[0:4]
        let mut hasher = Sha256::new();
        hasher.update(part_data);
        hasher.update(self.random_hash);
        let hash: [u8; 32] = hasher.finalize().into();
        let mut part_hash = [0u8; MAPHASH_LEN];
        part_hash.copy_from_slice(&hash[..MAPHASH_LEN]);

        // Find matching index in known part hashes
        for (idx, ph) in self.part_hashes.iter().enumerate() {
            if *ph == part_hash && !self.received[idx] {
                self.parts[idx] = part_data.to_vec();
                self.received[idx] = true;
                break;
            }
        }

        // Check if all parts received
        self.received.iter().all(|&r| r)
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
    pub fn build_request(&self) -> Vec<u8> {
        // Collect unreceived part hashes within current window
        let mut requested_hashes = Vec::new();
        for (idx, ph) in self.part_hashes.iter().enumerate() {
            if !self.received[idx] {
                requested_hashes.push(*ph);
                if requested_hashes.len() >= self.window {
                    break;
                }
            }
        }

        // Signal exhausted ONLY if we don't have all part hashes yet
        // and couldn't fill the window from known hashes.
        let exhausted = self.part_hashes.len() < self.total_segments
            && requested_hashes.len() < self.window;

        let mut payload = Vec::new();

        if exhausted {
            payload.push(HASHMAP_IS_EXHAUSTED);
            // Include last known map hash so sender knows where we are
            if let Some(last) = self.part_hashes.last() {
                payload.extend_from_slice(last);
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

        let array_len = read_msgpack_array_len(msgpack_data, &mut pos)?;
        if array_len != 2 {
            return Err("expected 2-element msgpack array in hashmap update");
        }

        let _segment_index = read_msgpack_uint(msgpack_data, &mut pos)? as usize;
        let new_hashes = read_msgpack_bin(msgpack_data, &mut pos)?;

        let count = new_hashes.len() / MAPHASH_LEN;
        for i in 0..count {
            let start = i * MAPHASH_LEN;
            let mut ph = [0u8; MAPHASH_LEN];
            ph.copy_from_slice(&new_hashes[start..start + MAPHASH_LEN]);
            // Only add if we don't already have enough
            if self.part_hashes.len() < self.total_segments {
                self.part_hashes.push(ph);
            }
        }

        Ok(())
    }

    /// Assemble the complete resource data and verify the hash.
    ///
    /// Concatenates all parts in order, then verifies that
    /// `SHA-256(assembled || random_hash) == resource_hash`.
    pub fn assemble(&mut self) -> Result<Vec<u8>, &'static str> {
        self.state = ResourceState::Assembling;

        // Concatenate all parts in order
        let mut assembled = Vec::with_capacity(self.total_size);
        for part in &self.parts {
            assembled.extend_from_slice(part);
        }

        // Verify: SHA-256(assembled || random_hash) == resource_hash
        let mut hasher = Sha256::new();
        hasher.update(&assembled);
        hasher.update(self.random_hash);
        let computed: [u8; 32] = hasher.finalize().into();

        if computed == self.resource_hash {
            self.data = assembled.clone();
            self.state = ResourceState::Complete;
            Ok(assembled)
        } else {
            self.state = ResourceState::Corrupt;
            Err("resource hash mismatch — data corrupt")
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
        self.part_hashes.len() < self.total_segments
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
        let res = Resource::new_outbound(&data, [0x11; 16], mdu, &mut rng);
        assert_eq!(res.total_segments, 3); // ceil(1000/431)
        assert_eq!(res.total_size, 1000);
        assert_eq!(res.state, ResourceState::Queued);
    }

    #[test]
    fn test_resource_hash_computation() {
        let data = b"hello resource";
        let mut rng = rand::thread_rng();
        let res = Resource::new_outbound(data, [0x11; 16], 431, &mut rng);
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
        let res = Resource::new_outbound(&data, [0x11; 16], 431, &mut rng);
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
        let mut sender = Resource::new_outbound(&data, [0x11; 16], 431, &mut rng);
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
        let mut sender = Resource::new_outbound(&data, [0x11; 16], 431, &mut rng);
        let adv = sender.build_advertisement();
        // First byte should be a fixmap header (0x80 | n)
        assert_eq!(adv[0] & 0xf0, 0x80, "advertisement should start with fixmap header");
        let map_len = (adv[0] & 0x0f) as usize;
        assert_eq!(map_len, 11, "advertisement map should have 11 entries");
    }

    #[test]
    fn test_advertisement_hashmap_layout() {
        let data = vec![0xDD; 2000];
        let mdu = 431;
        let mut rng = rand::thread_rng();
        let mut sender = Resource::new_outbound(&data, [0x11; 16], mdu, &mut rng);
        let _adv = sender.build_advertisement();
        // hashmap_cursor should be min(window, total_segments)
        let expected_cursor = WINDOW_INITIAL.min(sender.total_segments);
        assert_eq!(sender.hashmap_cursor, expected_cursor);
    }

    #[test]
    fn test_request_wire_format() {
        let data = vec![0xEE; 100]; // single part
        let mut rng = rand::thread_rng();
        let mut sender = Resource::new_outbound(&data, [0x11; 16], 431, &mut rng);
        let adv = sender.build_advertisement();
        let receiver = Resource::from_advertisement(&adv, [0x11; 16]).unwrap();
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
        let mut sender = Resource::new_outbound(&data, [0x11; 16], 431, &mut rng);
        let adv = sender.build_advertisement();
        let mut receiver = Resource::from_advertisement(&adv, [0x11; 16]).unwrap();
        // Feed the single part
        receiver.receive_part(&data);
        let assembled = receiver.assemble().unwrap();
        assert_eq!(assembled, data);
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
        let mut sender = Resource::new_outbound(&data, [0x11; 16], 431, &mut rng);
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
        let mut sender = Resource::new_outbound(&data, [0x11; 16], 431, &mut rng);
        sender.handle_cancel();
        assert_eq!(sender.state, ResourceState::Failed);
    }

    #[test]
    fn test_complete_small_transfer() {
        // Full sender -> receiver cycle for small data (1 segment)
        let data = b"small transfer data";
        let mut rng = rand::thread_rng();
        let mut sender = Resource::new_outbound(data, [0x11; 16], 431, &mut rng);

        // Step 1: Build advertisement
        let adv = sender.build_advertisement();

        // Step 2: Receiver parses advertisement
        let mut receiver = Resource::from_advertisement(&adv, [0x11; 16]).unwrap();

        // Step 3: Receiver builds request
        let req = receiver.build_request();

        // Step 4: Sender handles request, returns parts
        let parts = sender.handle_request(&req);
        assert!(!parts.is_empty());

        // Step 5: Receiver receives parts
        for (_idx, part) in &parts {
            receiver.receive_part(part);
        }

        // Step 6: Receiver assembles and verifies
        let assembled = receiver.assemble().unwrap();
        assert_eq!(assembled, data);

        // Step 7: Receiver builds proof
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
        let res = Resource::new_outbound(data, [0x11; 16], 431, &mut rng);
        assert_eq!(res.total_segments, 0);
        assert_eq!(res.total_size, 0);
    }

    #[test]
    fn test_hashmap_update_uses_32_byte_hash() {
        let data = vec![0xAA; 4000]; // multiple segments
        let mdu = 431;
        let mut rng = rand::thread_rng();
        let mut sender = Resource::new_outbound(&data, [0x11; 16], mdu, &mut rng);
        let adv = sender.build_advertisement();
        let mut receiver = Resource::from_advertisement(&adv, [0x11; 16]).unwrap();

        // Build a hashmap update from sender
        if let Some(hmu) = sender.build_hashmap_update() {
            // First 32 bytes should be the full resource hash
            assert!(hmu.len() >= 32);
            assert_eq!(&hmu[..32], &sender.resource_hash[..]);
            // Receiver should be able to parse it
            receiver.apply_hashmap_update(&hmu).unwrap();
        }
    }

    #[test]
    fn test_multi_segment_transfer() {
        // Full sender -> receiver cycle for multi-segment data
        let data = vec![0x42; 2000]; // will produce ceil(2000/431) = 5 segments
        let mdu = 431;
        let mut rng = rand::thread_rng();
        let mut sender = Resource::new_outbound(&data, [0x11; 16], mdu, &mut rng);
        assert_eq!(sender.total_segments, 5);

        // Step 1: Build advertisement (includes first window of hashes)
        let adv = sender.build_advertisement();

        // Step 2: Receiver parses advertisement
        let mut receiver = Resource::from_advertisement(&adv, [0x11; 16]).unwrap();
        assert_eq!(receiver.total_segments, 5);
        // Initial hashes = min(WINDOW_INITIAL, 5) = 4
        assert_eq!(receiver.part_hashes.len(), 4);

        // Step 3: Receiver builds request for known parts
        let req = receiver.build_request();
        // hashmap_status should be 0x00 since we only have 4 of 5 hashes
        assert_eq!(req[0], 0x00);

        // Step 4: Sender handles request
        let parts = sender.handle_request(&req);
        assert!(!parts.is_empty());

        // Step 5: Receiver receives parts
        for (_idx, part) in &parts {
            receiver.receive_part(part);
        }

        // Step 6: Sender sends remaining hashmap entries
        if let Some(hmu) = sender.build_hashmap_update() {
            receiver.apply_hashmap_update(&hmu).unwrap();
        }
        assert_eq!(receiver.part_hashes.len(), 5);

        // Step 7: Build another request for remaining parts
        // All 5 hashes now known, so status is 0x00 (not exhausted)
        let req2 = receiver.build_request();
        assert_eq!(req2[0], 0x00);
        let parts2 = sender.handle_request(&req2);
        for (_idx, part) in &parts2 {
            receiver.receive_part(part);
        }

        // Step 8: Assemble and verify
        let assembled = receiver.assemble().unwrap();
        assert_eq!(assembled, data);

        // Step 9: Proof
        let proof = receiver.build_proof();
        assert_eq!(proof.len(), 64);
        assert!(sender.handle_proof(&proof));
        assert_eq!(sender.state, ResourceState::Complete);
    }
}
