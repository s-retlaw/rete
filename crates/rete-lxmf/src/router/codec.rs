//! Shared msgpack helpers, bz2 compression, announce parsing.

/// Encode a u32 as a msgpack unsigned integer.
pub(super) fn encode_msgpack_uint(val: u32) -> Vec<u8> {
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
}

/// Try to parse LXMF announce app_data: msgpack `[display_name_bytes, tag]`
/// where tag is a stamp_cost int (delivery) or `true` boolean (propagation).
pub(super) fn try_parse_lxmf_announce_data(data: &[u8]) -> Option<Vec<u8>> {
    let parsed = parse_lxmf_announce_data(data)?;
    Some(parsed.display_name)
}

/// Parse full LXMF announce app_data including propagation flag.
pub(super) fn parse_lxmf_announce_data(data: &[u8]) -> Option<LxmfAnnounceData> {
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

/// Encode a list of message hashes as a msgpack array of bin32 elements.
pub(super) fn encode_offer_hashes(hashes: &[[u8; 32]]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(5 + hashes.len() * 35);
    write_array_header(&mut buf, hashes.len());
    for h in hashes {
        crate::message::write_bin(&mut buf, h);
    }
    buf
}

/// Decode a msgpack array of bin elements into message hashes.
pub(super) fn decode_offer_hashes(data: &[u8]) -> Option<Vec<[u8; 32]>> {
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
    buf.push(0xcb);
    buf.extend_from_slice(&(now as f64).to_be_bytes());

    write_array_header(&mut buf, messages.len());
    for msg in messages {
        crate::message::write_bin(&mut buf, msg);
    }
    buf
}

/// Unpack sync messages from msgpack `[timestamp, [msg1, msg2, ...]]`.
pub(super) fn unpack_sync_messages(data: &[u8]) -> Vec<Vec<u8>> {
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
