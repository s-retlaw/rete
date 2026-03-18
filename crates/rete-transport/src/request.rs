//! Link request/response primitive — RPC-style communication over established links.
//!
//! Implements `link.request(path, data)` and `link.response()` from Python RNS.
//!
//! # Request wire format (msgpack)
//! ```text
//! fixarray(3) = 0x93
//! float64     = 0xcb + 8 bytes BE (timestamp)
//! bin8/bin16  = path_hash (10 bytes, SHA-256(path.encode("utf-8"))[0:10])
//! bin8/bin16/bin32 = data (arbitrary bytes)
//! ```
//!
//! # Response wire format (msgpack)
//! ```text
//! fixarray(2) = 0x92
//! bin8        = request_id (10 bytes, SHA-256(packed_request)[0:10])
//! bin8/bin16/bin32 = response data
//! ```

extern crate alloc;

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

/// Length of a path hash (truncated SHA-256).
pub const PATH_HASH_LEN: usize = 10;

/// Length of a request ID (truncated SHA-256 of packed request).
pub const REQUEST_ID_LEN: usize = 10;

/// Errors from request/response parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    /// Data too short or truncated.
    TooShort,
    /// Expected msgpack array header not found.
    BadArrayHeader,
    /// Expected msgpack float64 not found.
    BadTimestamp,
    /// Expected msgpack bin (path_hash or data) not found.
    BadBin,
    /// Path hash has wrong length (expected 10 bytes).
    BadPathHashLen,
    /// Request ID has wrong length (expected 10 bytes).
    BadRequestIdLen,
}

/// Compute path hash: `SHA-256(path.as_bytes())[..10]`.
pub fn path_hash(path: &str) -> [u8; PATH_HASH_LEN] {
    let digest = Sha256::digest(path.as_bytes());
    let mut out = [0u8; PATH_HASH_LEN];
    out.copy_from_slice(&digest[..PATH_HASH_LEN]);
    out
}

/// Compute request_id from packed request bytes: `SHA-256(packed)[..10]`.
pub fn request_id(packed_request: &[u8]) -> [u8; REQUEST_ID_LEN] {
    let digest = Sha256::digest(packed_request);
    let mut out = [0u8; REQUEST_ID_LEN];
    out.copy_from_slice(&digest[..REQUEST_ID_LEN]);
    out
}

/// Build a packed request: `msgpack([timestamp_f64, path_hash_bytes, data_bytes])`.
pub fn build_request(path: &str, data: &[u8], now_secs_f64: f64) -> Vec<u8> {
    let ph = path_hash(path);

    // Estimate capacity: 1 (array) + 9 (float64) + 12 (bin8 + 10) + 3+ (bin header + data)
    let mut buf = Vec::with_capacity(1 + 9 + 12 + 3 + data.len());

    // fixarray(3)
    buf.push(0x93);

    // float64
    buf.push(0xcb);
    buf.extend_from_slice(&now_secs_f64.to_be_bytes());

    // path_hash as bin8 (always 10 bytes)
    write_bin(&mut buf, &ph);

    // data as bin
    write_bin(&mut buf, data);

    buf
}

/// Parse a packed request, returning `(timestamp_f64, path_hash, data)`.
pub fn parse_request(packed: &[u8]) -> Result<(f64, [u8; PATH_HASH_LEN], Vec<u8>), RequestError> {
    let mut pos = 0;

    // Read fixarray(3) header
    let arr_len = read_array_len(packed, &mut pos)?;
    if arr_len != 3 {
        return Err(RequestError::BadArrayHeader);
    }

    // Read float64 timestamp
    let timestamp = read_float64(packed, &mut pos)?;

    // Read path_hash (bin, expect 10 bytes)
    let ph_bytes = read_bin(packed, &mut pos)?;
    if ph_bytes.len() != PATH_HASH_LEN {
        return Err(RequestError::BadPathHashLen);
    }
    let mut ph = [0u8; PATH_HASH_LEN];
    ph.copy_from_slice(&ph_bytes);

    // Read data (bin)
    let data = read_bin(packed, &mut pos)?;

    Ok((timestamp, ph, data))
}

/// Build a packed response: `msgpack([request_id_bytes, response_data_bytes])`.
pub fn build_response(req_id: &[u8; REQUEST_ID_LEN], data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 12 + 3 + data.len());

    // fixarray(2)
    buf.push(0x92);

    // request_id as bin8 (always 10 bytes)
    write_bin(&mut buf, req_id);

    // response data as bin
    write_bin(&mut buf, data);

    buf
}

/// Parse a packed response, returning `(request_id, data)`.
pub fn parse_response(packed: &[u8]) -> Result<([u8; REQUEST_ID_LEN], Vec<u8>), RequestError> {
    let mut pos = 0;

    // Read fixarray(2) header
    let arr_len = read_array_len(packed, &mut pos)?;
    if arr_len != 2 {
        return Err(RequestError::BadArrayHeader);
    }

    // Read request_id (bin, expect 10 bytes)
    let rid_bytes = read_bin(packed, &mut pos)?;
    if rid_bytes.len() != REQUEST_ID_LEN {
        return Err(RequestError::BadRequestIdLen);
    }
    let mut rid = [0u8; REQUEST_ID_LEN];
    rid.copy_from_slice(&rid_bytes);

    // Read data (bin)
    let data = read_bin(packed, &mut pos)?;

    Ok((rid, data))
}

// ---------------------------------------------------------------------------
// Low-level msgpack helpers (minimal, no_std compatible)
// ---------------------------------------------------------------------------

fn write_bin(buf: &mut Vec<u8>, data: &[u8]) {
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

fn read_array_len(data: &[u8], pos: &mut usize) -> Result<usize, RequestError> {
    if *pos >= data.len() {
        return Err(RequestError::TooShort);
    }
    let b = data[*pos];
    *pos += 1;
    if b & 0xf0 == 0x90 {
        Ok((b & 0x0f) as usize)
    } else if b == 0xdc {
        // array16
        if *pos + 2 > data.len() {
            return Err(RequestError::TooShort);
        }
        let n = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
        *pos += 2;
        Ok(n as usize)
    } else {
        Err(RequestError::BadArrayHeader)
    }
}

fn read_float64(data: &[u8], pos: &mut usize) -> Result<f64, RequestError> {
    if *pos >= data.len() {
        return Err(RequestError::TooShort);
    }
    let b = data[*pos];
    *pos += 1;
    if b == 0xcb {
        // float64
        if *pos + 8 > data.len() {
            return Err(RequestError::TooShort);
        }
        let bytes = [
            data[*pos],
            data[*pos + 1],
            data[*pos + 2],
            data[*pos + 3],
            data[*pos + 4],
            data[*pos + 5],
            data[*pos + 6],
            data[*pos + 7],
        ];
        *pos += 8;
        Ok(f64::from_be_bytes(bytes))
    } else if b == 0xca {
        // float32
        if *pos + 4 > data.len() {
            return Err(RequestError::TooShort);
        }
        let bytes = [data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]];
        *pos += 4;
        Ok(f32::from_be_bytes(bytes) as f64)
    } else {
        Err(RequestError::BadTimestamp)
    }
}

fn read_bin(data: &[u8], pos: &mut usize) -> Result<Vec<u8>, RequestError> {
    if *pos >= data.len() {
        return Err(RequestError::TooShort);
    }
    let b = data[*pos];
    *pos += 1;
    let len = if b == 0xc4 {
        // bin8
        if *pos >= data.len() {
            return Err(RequestError::TooShort);
        }
        let n = data[*pos] as usize;
        *pos += 1;
        n
    } else if b == 0xc5 {
        // bin16
        if *pos + 2 > data.len() {
            return Err(RequestError::TooShort);
        }
        let n = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
        *pos += 2;
        n
    } else if b == 0xc6 {
        // bin32
        if *pos + 4 > data.len() {
            return Err(RequestError::TooShort);
        }
        let n = u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]])
            as usize;
        *pos += 4;
        n
    } else if b & 0xa0 == 0xa0 && b < 0xc0 {
        // fixstr — treat as bin
        (b & 0x1f) as usize
    } else if b == 0xd9 {
        // str8
        if *pos >= data.len() {
            return Err(RequestError::TooShort);
        }
        let n = data[*pos] as usize;
        *pos += 1;
        n
    } else if b == 0xda {
        // str16
        if *pos + 2 > data.len() {
            return Err(RequestError::TooShort);
        }
        let n = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
        *pos += 2;
        n
    } else {
        return Err(RequestError::BadBin);
    };
    if *pos + len > data.len() {
        return Err(RequestError::TooShort);
    }
    let val = data[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(val)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec;

    use super::*;

    #[test]
    fn test_path_hash_computation() {
        let ph = path_hash("lxmf.delivery");
        // SHA-256("lxmf.delivery") truncated to 10 bytes — verify deterministic
        let ph2 = path_hash("lxmf.delivery");
        assert_eq!(ph, ph2);
        assert_eq!(ph.len(), PATH_HASH_LEN);

        // Verify it's actually SHA-256 truncated
        let digest = Sha256::digest("lxmf.delivery".as_bytes());
        assert_eq!(&ph[..], &digest[..PATH_HASH_LEN]);
    }

    #[test]
    fn test_build_parse_request_roundtrip() {
        let path = "test.echo";
        let data = b"hello, world!";
        let ts = 1700000000.5_f64;

        let packed = build_request(path, data, ts);
        let (parsed_ts, parsed_ph, parsed_data) = parse_request(&packed).unwrap();

        assert!((parsed_ts - ts).abs() < 1e-10);
        assert_eq!(parsed_ph, path_hash(path));
        assert_eq!(parsed_data, data);
    }

    #[test]
    fn test_request_id_deterministic() {
        let packed = build_request("test.echo", b"data1", 1700000000.0);
        let id1 = request_id(&packed);
        let id2 = request_id(&packed);
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), REQUEST_ID_LEN);

        // Different input produces different id
        let packed2 = build_request("test.echo", b"data2", 1700000000.0);
        let id3 = request_id(&packed2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_build_parse_response_roundtrip() {
        let req_id = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A];
        let resp_data = b"response payload";

        let packed = build_response(&req_id, resp_data);
        let (parsed_rid, parsed_data) = parse_response(&packed).unwrap();

        assert_eq!(parsed_rid, req_id);
        assert_eq!(parsed_data, resp_data);
    }

    #[test]
    fn test_parse_request_empty_data() {
        let packed = build_request("test.path", &[], 1700000001.0);
        let (ts, ph, data) = parse_request(&packed).unwrap();

        assert!((ts - 1700000001.0).abs() < 1e-10);
        assert_eq!(ph, path_hash("test.path"));
        assert!(data.is_empty());
    }

    #[test]
    fn test_parse_request_garbage_fails() {
        // Complete garbage
        assert!(parse_request(&[0xFF, 0x00, 0x01]).is_err());
        // Empty input
        assert!(parse_request(&[]).is_err());
        // Wrong array length
        assert!(parse_request(&[0x92]).is_err()); // fixarray(2) instead of 3
    }

    #[test]
    fn test_parse_response_garbage_fails() {
        // Complete garbage
        assert!(parse_response(&[0xFF, 0x00, 0x01]).is_err());
        // Empty input
        assert!(parse_response(&[]).is_err());
        // Wrong array length
        assert!(parse_response(&[0x93]).is_err()); // fixarray(3) instead of 2
    }

    #[test]
    fn test_request_with_large_data() {
        let data = vec![0xAA; 400];
        let packed = build_request("test.large", &data, 1700000002.0);
        let (ts, ph, parsed_data) = parse_request(&packed).unwrap();

        assert!((ts - 1700000002.0).abs() < 1e-10);
        assert_eq!(ph, path_hash("test.large"));
        assert_eq!(parsed_data, data);
    }

    #[test]
    fn test_response_with_empty_data() {
        let req_id = [0xAA; REQUEST_ID_LEN];
        let packed = build_response(&req_id, &[]);
        let (parsed_rid, parsed_data) = parse_response(&packed).unwrap();

        assert_eq!(parsed_rid, req_id);
        assert!(parsed_data.is_empty());
    }

    #[test]
    fn test_path_hash_different_paths() {
        let ph1 = path_hash("lxmf.delivery");
        let ph2 = path_hash("lxmf.propagation");
        assert_ne!(ph1, ph2);
    }
}
