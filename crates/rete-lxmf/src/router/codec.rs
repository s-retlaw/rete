//! Shared msgpack helpers, bz2 compression, announce parsing.

use rete_core::msgpack;

/// Encode a u32 as a msgpack unsigned integer.
pub(super) fn encode_msgpack_uint(val: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    msgpack::write_uint(&mut buf, val as u64);
    buf
}

/// Compress data with bz2 (matching Python LXMF Resource convention).
pub(super) fn bz2_compress(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    encoder.write_all(data).unwrap_or_default();
    encoder.finish().unwrap_or_else(|_| data.to_vec())
}

/// Parsed LXMF announce app_data.
pub(super) struct LxmfAnnounceData {
    pub(super) display_name: Vec<u8>,
    /// True if this is a propagation node announce (second element is `true`).
    pub(super) is_propagation: bool,
    /// Stamp cost from delivery announce (integer tag), if present and non-zero.
    pub(super) stamp_cost: Option<u8>,
}

/// Try to parse LXMF announce app_data: msgpack `[display_name_bytes, tag]`
/// where tag is a stamp_cost int (delivery) or `true` boolean (propagation).
pub(super) fn try_parse_lxmf_announce_data(data: &[u8]) -> Option<Vec<u8>> {
    let parsed = parse_lxmf_announce_data(data)?;
    Some(parsed.display_name)
}

/// Parse full LXMF announce app_data including propagation flag and stamp cost.
pub(super) fn parse_lxmf_announce_data(data: &[u8]) -> Option<LxmfAnnounceData> {
    let mut pos = 0;
    let arr_len = msgpack::read_array_len(data, &mut pos).ok()?;
    if arr_len < 2 {
        return None;
    }
    let display_name = msgpack::read_bin_or_str(data, &mut pos).ok()?.to_vec();
    // Second element: 0xc3 = true (propagation), 0xc0 = nil, integer = stamp_cost
    let tag_byte = *data.get(pos)?;
    let is_propagation = tag_byte == 0xc3;
    let stamp_cost = if !is_propagation && tag_byte != 0xc0 && tag_byte != 0xc2 {
        // Try to read as unsigned integer
        msgpack::read_uint(data, &mut pos).ok().and_then(|v| {
            if v > 0 && v <= 255 {
                Some(v as u8)
            } else {
                None // 0 means no cost required
            }
        })
    } else {
        None
    };
    Some(LxmfAnnounceData {
        display_name,
        is_propagation,
        stamp_cost,
    })
}

/// Encode a list of message hashes as a msgpack array of bin32 elements.
pub(super) fn encode_offer_hashes(hashes: &[[u8; 32]]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(5 + hashes.len() * 35);
    msgpack::write_array_header(&mut buf, hashes.len());
    for h in hashes {
        msgpack::write_bin(&mut buf, h);
    }
    buf
}

/// Decode a msgpack array of bin elements into message hashes.
pub(super) fn decode_offer_hashes(data: &[u8]) -> Option<Vec<[u8; 32]>> {
    let mut pos = 0;
    let arr_len = msgpack::read_array_len(data, &mut pos).ok()?;
    let mut hashes = Vec::with_capacity(arr_len);
    for _ in 0..arr_len {
        let bin = msgpack::read_bin_or_str(data, &mut pos).ok()?;
        if bin.len() != 32 {
            return None;
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(bin);
        hashes.push(h);
    }
    Some(hashes)
}

/// Parse an offer response: `false` (want none) -> empty,
/// `true` (want all) -> return offered, array -> subset.
pub(super) fn parse_offer_response(data: &[u8], offered: &[[u8; 32]]) -> Vec<[u8; 32]> {
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
pub(super) fn pack_sync_messages(now: u64, messages: &[Vec<u8>]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0x92); // fixarray(2)

    // timestamp as float64
    msgpack::write_float64(&mut buf, now as f64);

    msgpack::write_array_header(&mut buf, messages.len());
    for msg in messages {
        msgpack::write_bin(&mut buf, msg);
    }
    buf
}

/// Unpack sync messages from msgpack `[timestamp, [msg1, msg2, ...]]`.
pub(super) fn unpack_sync_messages(data: &[u8]) -> Vec<Vec<u8>> {
    let mut pos = 0;
    // Outer array [timestamp, messages]
    let arr_len = match msgpack::read_array_len(data, &mut pos) {
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
        return Vec::new();
    }
    // Messages array
    let msg_count = match msgpack::read_array_len(data, &mut pos) {
        Ok(n) => n,
        Err(_) => return Vec::new(),
    };
    let mut messages = Vec::with_capacity(msg_count);
    for _ in 0..msg_count {
        match msgpack::read_bin_or_str(data, &mut pos) {
            Ok(bin) => messages.push(bin.to_vec()),
            Err(_) => break,
        }
    }
    messages
}
