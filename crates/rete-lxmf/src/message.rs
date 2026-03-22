//! LXMF message — pack, unpack, sign, verify.

use rete_core::Identity;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// Field type constants
/// Embedded LXMF messages field.
pub const FIELD_EMBEDDED_LXMS: u8 = 0x01;
/// Telemetry data field.
pub const FIELD_TELEMETRY: u8 = 0x02;
/// Commands field.
pub const FIELD_COMMANDS: u8 = 0x04;
/// File attachments field.
pub const FIELD_FILE_ATTACHMENTS: u8 = 0x05;
/// Image field.
pub const FIELD_IMAGE: u8 = 0x06;
/// Audio field.
pub const FIELD_AUDIO: u8 = 0x07;
/// Thread identifier field.
pub const FIELD_THREAD: u8 = 0x08;

/// LXMF delivery method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryMethod {
    /// Direct delivery via Link (large messages as Resource).
    Direct,
    /// Opportunistic delivery via encrypted DATA packet (small messages).
    Opportunistic,
    /// Propagation via LXMF propagation node.
    Propagation,
    /// Paper message: encoded as `lxm://` URI for QR codes / offline transport.
    Paper,
}

/// URI schema for paper messages.
pub const URI_SCHEMA: &str = "lxm";

/// Maximum bytes in a QR code (Version 40, Error Correction Level L).
pub const QR_MAX_STORAGE: usize = 2953;

/// Maximum data unit for paper messages after base64 encoding overhead.
/// `((QR_MAX_STORAGE - len("lxm://")) * 6) / 8 = 2210 bytes`
pub const PAPER_MDU: usize = ((QR_MAX_STORAGE - 6) * 6) / 8;

/// LXMF message state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LXMessageState {
    /// Newly created, not yet sent.
    New,
    /// Being generated (packing/signing in progress).
    Generating,
    /// Sent to the network.
    Sent,
    /// Confirmed delivered to the recipient.
    Delivered,
    /// Delivery failed.
    Failed,
}

/// Default Link MDU for standard radio links (MTU=500).
/// For TCP links (MTU=8192), the negotiated MDU is ~8111.
/// Use `fits_in_single_packet_with_mdu()` for non-default links.
pub const LINK_MDU_DEFAULT: usize = 431;

/// An LXMF message.
#[derive(Debug)]
pub struct LXMessage {
    /// Destination hash (16 bytes).
    pub destination_hash: [u8; 16],
    /// Source hash (16 bytes).
    pub source_hash: [u8; 16],
    /// Message timestamp as a UNIX epoch float.
    pub timestamp: f64,
    /// Message title (bytes).
    pub title: Vec<u8>,
    /// Message content (bytes).
    pub content: Vec<u8>,
    /// Optional typed fields (field_id -> data).
    pub fields: BTreeMap<u8, Vec<u8>>,
    /// Ed25519 signature over dest_hash || source_hash || msgpack_payload.
    pub signature: [u8; 64],
    /// Current message state.
    pub state: LXMessageState,
    /// Delivery method.
    pub method: DeliveryMethod,
}

impl LXMessage {
    /// Create a new LXMF message and sign it.
    ///
    /// `source_identity` is used to sign the message. The `source_hash`
    /// is the source identity's destination hash (truncated identity hash).
    ///
    /// Signing matches Python LXMF: `sign(hashed_part + SHA256(hashed_part))`
    /// where `hashed_part = dest_hash || source_hash || msgpack_payload`.
    pub fn new(
        destination_hash: [u8; 16],
        source_hash: [u8; 16],
        source_identity: &Identity,
        title: &[u8],
        content: &[u8],
        fields: BTreeMap<u8, Vec<u8>>,
        timestamp: f64,
    ) -> Result<Self, &'static str> {
        // Build msgpack payload
        let msgpack_payload = encode_msgpack_payload(timestamp, title, content, &fields);

        let sign_data = build_sign_data(&destination_hash, &source_hash, &msgpack_payload);

        let signature = source_identity
            .sign(&sign_data)
            .map_err(|_| "signing failed")?;

        Ok(LXMessage {
            destination_hash,
            source_hash,
            timestamp,
            title: title.to_vec(),
            content: content.to_vec(),
            fields,
            signature,
            state: LXMessageState::New,
            method: DeliveryMethod::Opportunistic,
        })
    }

    /// Pack into wire format: dest_hash[16] || source_hash[16] || signature[64] || msgpack_payload
    pub fn pack(&self) -> Vec<u8> {
        let msgpack_payload =
            encode_msgpack_payload(self.timestamp, &self.title, &self.content, &self.fields);
        let mut out = Vec::with_capacity(96 + msgpack_payload.len());
        out.extend_from_slice(&self.destination_hash);
        out.extend_from_slice(&self.source_hash);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&msgpack_payload);
        out
    }

    /// Unpack from wire format and verify signature.
    ///
    /// If `verify_identity` is provided, the signature is verified against it.
    /// Otherwise, the signature is stored but not verified.
    pub fn unpack(data: &[u8], verify_identity: Option<&Identity>) -> Result<Self, &'static str> {
        if data.len() < 96 {
            return Err("message too short (need at least 96 bytes)");
        }

        let mut destination_hash = [0u8; 16];
        let mut source_hash = [0u8; 16];
        let mut signature = [0u8; 64];

        destination_hash.copy_from_slice(&data[..16]);
        source_hash.copy_from_slice(&data[16..32]);
        signature.copy_from_slice(&data[32..96]);
        let msgpack_payload = &data[96..];

        // Verify signature if identity provided
        if let Some(identity) = verify_identity {
            let sign_data = build_sign_data(&destination_hash, &source_hash, msgpack_payload);
            identity
                .verify(&sign_data, &signature)
                .map_err(|_| "signature verification failed")?;
        }

        // Parse msgpack payload
        let (timestamp, title, content, fields) = decode_msgpack_payload(msgpack_payload)?;

        Ok(LXMessage {
            destination_hash,
            source_hash,
            timestamp,
            title,
            content,
            fields,
            signature,
            state: LXMessageState::New,
            method: DeliveryMethod::Opportunistic,
        })
    }

    /// Check if this message fits in a single link packet (default radio MDU=431).
    pub fn fits_in_single_packet(&self) -> bool {
        self.pack().len() <= LINK_MDU_DEFAULT
    }

    /// Check if this message fits in a single link packet with a specific MDU.
    ///
    /// Use this for TCP links where the negotiated MDU may be much larger.
    pub fn fits_in_single_packet_with_mdu(&self, link_mdu: usize) -> bool {
        self.pack().len() <= link_mdu
    }

    /// Compute the message hash (SHA-256 of packed representation).
    pub fn hash(&self) -> [u8; 32] {
        let packed = self.pack();
        Sha256::digest(&packed).into()
    }

    /// Encode this message as an `lxm://` URI for paper/QR transport.
    ///
    /// The packed message is encrypted using the recipient's identity and
    /// encoded as URL-safe base64 (no padding).
    ///
    /// Returns `None` if the encrypted message exceeds `PAPER_MDU`.
    pub fn as_uri<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        recipient: &Identity,
        rng: &mut R,
    ) -> Option<String> {
        let packed = self.pack();
        // Paper format: dest_hash[16] || encrypted(rest)
        let plaintext = &packed[16..]; // skip dest_hash, already in header
        let mut ct_buf = [0u8; 2048]; // MTU-ish buffer
        let ct_len = recipient.encrypt(plaintext, rng, &mut ct_buf).ok()?;

        let mut paper_packed = Vec::with_capacity(16 + ct_len);
        paper_packed.extend_from_slice(&self.destination_hash);
        paper_packed.extend_from_slice(&ct_buf[..ct_len]);

        if paper_packed.len() > PAPER_MDU {
            return None;
        }

        let encoded = base64url_encode(&paper_packed);
        Some(format!("{}://{}", URI_SCHEMA, encoded))
    }

    /// Decode an `lxm://` URI back into message components.
    ///
    /// Returns `(destination_hash, encrypted_payload)` — the caller must
    /// decrypt the payload using their identity's private key and then
    /// call `LXMessage::unpack` on the decrypted data.
    pub fn from_uri(uri: &str) -> Option<([u8; 16], Vec<u8>)> {
        let prefix = format!("{}://", URI_SCHEMA);
        let encoded = uri.strip_prefix(&prefix)?;
        let data = base64url_decode(encoded)?;

        if data.len() < 16 {
            return None;
        }

        let mut dest_hash = [0u8; 16];
        dest_hash.copy_from_slice(&data[..16]);
        let encrypted = data[16..].to_vec();

        Some((dest_hash, encrypted))
    }
}

// ---------------------------------------------------------------------------
// Signing helper
// ---------------------------------------------------------------------------

/// Build the data blob that gets signed/verified for an LXMF message.
///
/// Matches Python LXMF: `sign(hashed_part + SHA256(hashed_part))`
/// where `hashed_part = dest_hash || source_hash || msgpack_payload`.
fn build_sign_data(
    dest_hash: &[u8; 16],
    source_hash: &[u8; 16],
    msgpack_payload: &[u8],
) -> Vec<u8> {
    let mut hashed_part = Vec::with_capacity(32 + msgpack_payload.len() + 32);
    hashed_part.extend_from_slice(dest_hash);
    hashed_part.extend_from_slice(source_hash);
    hashed_part.extend_from_slice(msgpack_payload);

    let message_hash = Sha256::digest(&hashed_part);
    hashed_part.extend_from_slice(&message_hash);
    hashed_part
}

// ---------------------------------------------------------------------------
// Msgpack encoding/decoding helpers
// ---------------------------------------------------------------------------

/// Encode the msgpack payload: array of [timestamp, title, content, fields]
fn encode_msgpack_payload(
    timestamp: f64,
    title: &[u8],
    content: &[u8],
    fields: &BTreeMap<u8, Vec<u8>>,
) -> Vec<u8> {
    let mut buf = Vec::new();

    // fixarray of 4
    buf.push(0x94);

    // float64
    buf.push(0xcb);
    buf.extend_from_slice(&timestamp.to_be_bytes());

    // title as bin
    write_bin(&mut buf, title);

    // content as bin
    write_bin(&mut buf, content);

    // fields as map
    write_map(&mut buf, fields);

    buf
}

/// Decoded msgpack payload: (timestamp, title, content, fields).
type DecodedPayload = (f64, Vec<u8>, Vec<u8>, BTreeMap<u8, Vec<u8>>);

/// Decode the msgpack payload.
fn decode_msgpack_payload(data: &[u8]) -> Result<DecodedPayload, &'static str> {
    let mut pos = 0;

    // Read array header: 4 elements [ts, title, content, fields] or
    // 5 elements [ts, title, content, fields, stamp] (Python LXMF >= 0.9.x)
    let arr_len = read_array_len(data, &mut pos)?;
    if !(4..=5).contains(&arr_len) {
        return Err("expected array of 4 or 5 elements");
    }

    // Read timestamp (float64)
    let timestamp = read_float64(data, &mut pos)?;

    // Read title (bin)
    let title = read_bin(data, &mut pos)?;

    // Read content (bin)
    let content = read_bin(data, &mut pos)?;

    // Read fields (map)
    let fields = read_map(data, &mut pos)?;

    Ok((timestamp, title, content, fields))
}

// ---------------------------------------------------------------------------
// Low-level msgpack helpers
// ---------------------------------------------------------------------------

pub(crate) fn write_bin(buf: &mut Vec<u8>, data: &[u8]) {
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

fn write_map(buf: &mut Vec<u8>, map: &BTreeMap<u8, Vec<u8>>) {
    let len = map.len();
    if len < 16 {
        buf.push(0x80 | len as u8); // fixmap
    } else if len < 65536 {
        buf.push(0xde); // map16
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push(0xdf); // map32
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    }
    for (&key, val) in map {
        // Key: positive fixint (u8 < 128) or uint8
        if key < 128 {
            buf.push(key);
        } else {
            buf.push(0xcc);
            buf.push(key);
        }
        write_bin(buf, val);
    }
}

pub(crate) fn read_array_len(data: &[u8], pos: &mut usize) -> Result<usize, &'static str> {
    if *pos >= data.len() {
        return Err("unexpected end");
    }
    let b = data[*pos];
    *pos += 1;
    if b & 0xf0 == 0x90 {
        Ok((b & 0x0f) as usize)
    } else if b == 0xdc {
        if *pos + 2 > data.len() {
            return Err("unexpected end");
        }
        let n = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
        *pos += 2;
        Ok(n as usize)
    } else {
        Err("expected array")
    }
}

fn read_float64(data: &[u8], pos: &mut usize) -> Result<f64, &'static str> {
    if *pos >= data.len() {
        return Err("unexpected end");
    }
    let b = data[*pos];
    *pos += 1;
    if b == 0xcb {
        if *pos + 8 > data.len() {
            return Err("unexpected end");
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
            return Err("unexpected end");
        }
        let bytes = [data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]];
        *pos += 4;
        Ok(f32::from_be_bytes(bytes) as f64)
    } else {
        // Could be an integer type representing the timestamp
        *pos -= 1;
        let v = read_uint(data, pos)?;
        Ok(v as f64)
    }
}

fn read_uint(data: &[u8], pos: &mut usize) -> Result<u64, &'static str> {
    if *pos >= data.len() {
        return Err("unexpected end");
    }
    let b = data[*pos];
    *pos += 1;
    if b < 0x80 {
        Ok(b as u64)
    } else if b == 0xcc {
        if *pos >= data.len() {
            return Err("unexpected end");
        }
        let v = data[*pos];
        *pos += 1;
        Ok(v as u64)
    } else if b == 0xcd {
        if *pos + 2 > data.len() {
            return Err("unexpected end");
        }
        let v = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
        *pos += 2;
        Ok(v as u64)
    } else if b == 0xce {
        if *pos + 4 > data.len() {
            return Err("unexpected end");
        }
        let v = u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
        *pos += 4;
        Ok(v as u64)
    } else if b == 0xcf {
        if *pos + 8 > data.len() {
            return Err("unexpected end");
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
    } else {
        Err("expected uint")
    }
}

pub(crate) fn read_bin(data: &[u8], pos: &mut usize) -> Result<Vec<u8>, &'static str> {
    if *pos >= data.len() {
        return Err("unexpected end");
    }
    let b = data[*pos];
    *pos += 1;
    let len = if b == 0xc4 {
        // bin8
        if *pos >= data.len() {
            return Err("unexpected end");
        }
        let n = data[*pos] as usize;
        *pos += 1;
        n
    } else if b == 0xc5 {
        // bin16
        if *pos + 2 > data.len() {
            return Err("unexpected end");
        }
        let n = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
        *pos += 2;
        n
    } else if b == 0xc6 {
        // bin32
        if *pos + 4 > data.len() {
            return Err("unexpected end");
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
            return Err("unexpected end");
        }
        let n = data[*pos] as usize;
        *pos += 1;
        n
    } else if b == 0xda {
        // str16
        if *pos + 2 > data.len() {
            return Err("unexpected end");
        }
        let n = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
        *pos += 2;
        n
    } else {
        return Err("expected bin or str");
    };
    if *pos + len > data.len() {
        return Err("unexpected end");
    }
    let val = data[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(val)
}

fn read_map(data: &[u8], pos: &mut usize) -> Result<BTreeMap<u8, Vec<u8>>, &'static str> {
    if *pos >= data.len() {
        return Err("unexpected end");
    }
    let b = data[*pos];
    *pos += 1;
    let len = if b & 0xf0 == 0x80 {
        (b & 0x0f) as usize
    } else if b == 0xde {
        if *pos + 2 > data.len() {
            return Err("unexpected end");
        }
        let n = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
        *pos += 2;
        n
    } else {
        return Err("expected map");
    };
    let mut map = BTreeMap::new();
    for _ in 0..len {
        let key = read_uint(data, pos)? as u8;
        let val = read_bin(data, pos)?;
        map.insert(key, val);
    }
    Ok(map)
}

// ---------------------------------------------------------------------------
// Base64url encode/decode (URL-safe, no padding)
// ---------------------------------------------------------------------------

const B64URL_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 4 + 2) / 3);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(B64URL_CHARS[((triple >> 18) & 0x3F) as usize] as char);
        out.push(B64URL_CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64URL_CHARS[((triple >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64URL_CHARS[(triple & 0x3F) as usize] as char);
        }
    }
    out
}

fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let a = b64url_val(bytes[i])?;
        let b = if i + 1 < bytes.len() { b64url_val(bytes[i + 1])? } else { 0 };
        let c = if i + 2 < bytes.len() { b64url_val(bytes[i + 2])? } else { 0 };
        let d = if i + 3 < bytes.len() { b64url_val(bytes[i + 3])? } else { 0 };

        let triple = ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6) | (d as u32);

        out.push((triple >> 16) as u8);
        if i + 2 < bytes.len() {
            out.push((triple >> 8) as u8);
        }
        if i + 3 < bytes.len() {
            out.push(triple as u8);
        }

        i += 4;
    }
    Some(out)
}

fn b64url_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rete_core::Identity;

    fn make_test_message() -> (LXMessage, Identity) {
        let source = Identity::from_seed(b"lxmf-source-test").unwrap();
        let source_hash = source.hash();
        let dest_hash = [0xAA; 16];
        let timestamp = 1700000000.0_f64;

        let msg = LXMessage::new(
            dest_hash,
            source_hash,
            &source,
            b"Hello",
            b"World",
            BTreeMap::new(),
            timestamp,
        )
        .unwrap();

        (msg, source)
    }

    #[test]
    fn test_lxmf_pack_unpack_round_trip() {
        let (msg, source) = make_test_message();
        let packed = msg.pack();

        let unpacked = LXMessage::unpack(&packed, Some(&source)).unwrap();
        assert_eq!(unpacked.destination_hash, msg.destination_hash);
        assert_eq!(unpacked.source_hash, msg.source_hash);
        assert_eq!(unpacked.title, b"Hello");
        assert_eq!(unpacked.content, b"World");
        assert!((unpacked.timestamp - 1700000000.0).abs() < 0.001);
        assert_eq!(unpacked.signature, msg.signature);
    }

    #[test]
    fn test_lxmf_signature_valid() {
        let (msg, source) = make_test_message();
        let packed = msg.pack();

        // Unpack with verification should succeed
        assert!(LXMessage::unpack(&packed, Some(&source)).is_ok());
    }

    #[test]
    fn test_lxmf_bad_signature_rejected() {
        let (msg, _source) = make_test_message();
        let mut packed = msg.pack();

        // Tamper with content
        if packed.len() > 100 {
            packed[100] ^= 0xFF;
        }

        let wrong_source = Identity::from_seed(b"lxmf-source-test").unwrap();
        assert!(LXMessage::unpack(&packed, Some(&wrong_source)).is_err());
    }

    #[test]
    fn test_lxmf_with_fields() {
        let source = Identity::from_seed(b"lxmf-fields-test").unwrap();
        let source_hash = source.hash();

        let mut fields = BTreeMap::new();
        fields.insert(FIELD_FILE_ATTACHMENTS, b"attachment data".to_vec());
        fields.insert(FIELD_IMAGE, b"image data".to_vec());

        let msg = LXMessage::new(
            [0xBB; 16],
            source_hash,
            &source,
            b"With Fields",
            b"Message body",
            fields,
            1700000001.0,
        )
        .unwrap();

        let packed = msg.pack();
        let unpacked = LXMessage::unpack(&packed, Some(&source)).unwrap();

        assert_eq!(unpacked.fields.len(), 2);
        assert_eq!(
            unpacked.fields.get(&FIELD_FILE_ATTACHMENTS).unwrap(),
            b"attachment data"
        );
        assert_eq!(unpacked.fields.get(&FIELD_IMAGE).unwrap(), b"image data");
    }

    #[test]
    fn test_lxmf_fits_in_packet() {
        let source = Identity::from_seed(b"lxmf-size-test").unwrap();
        let source_hash = source.hash();

        // Small message should fit
        let small = LXMessage::new(
            [0xCC; 16],
            source_hash,
            &source,
            b"Hi",
            b"OK",
            BTreeMap::new(),
            1700000002.0,
        )
        .unwrap();
        assert!(small.fits_in_single_packet());

        // Large message should not fit
        let big_content = vec![0xAA; 500];
        let big = LXMessage::new(
            [0xCC; 16],
            source_hash,
            &source,
            b"Big",
            &big_content,
            BTreeMap::new(),
            1700000003.0,
        )
        .unwrap();
        assert!(!big.fits_in_single_packet());
    }

    #[test]
    fn test_lxmf_empty_content() {
        let source = Identity::from_seed(b"lxmf-empty-test").unwrap();
        let source_hash = source.hash();

        let msg = LXMessage::new(
            [0xDD; 16],
            source_hash,
            &source,
            b"Title Only",
            b"",
            BTreeMap::new(),
            1700000004.0,
        )
        .unwrap();

        let packed = msg.pack();
        let unpacked = LXMessage::unpack(&packed, Some(&source)).unwrap();
        assert_eq!(unpacked.title, b"Title Only");
        assert!(unpacked.content.is_empty());
    }

    #[test]
    fn test_lxmf_unpack_without_verification() {
        let (msg, _source) = make_test_message();
        let packed = msg.pack();

        // Unpack without verification should succeed even without identity
        let unpacked = LXMessage::unpack(&packed, None).unwrap();
        assert_eq!(unpacked.title, b"Hello");
    }

    #[test]
    fn test_lxmf_message_hash() {
        let (msg, _) = make_test_message();
        let hash1 = msg.hash();
        let hash2 = msg.hash();
        assert_eq!(hash1, hash2); // deterministic
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_paper_uri_roundtrip() {
        let identity = Identity::from_seed(b"paper-test-sender").unwrap();
        let recipient = Identity::from_seed(b"paper-test-recipient").unwrap();
        let dest_hash = rete_core::destination_hash("testapp.aspect1", Some(&recipient.hash()));

        let msg = LXMessage::new(
            dest_hash,
            identity.hash(),
            &identity,
            b"Hello",
            b"Paper world!",
            BTreeMap::new(),
            1700000000.0,
        )
        .unwrap();

        let mut rng = rand::thread_rng();
        let uri = msg.as_uri(&recipient, &mut rng).unwrap();
        assert!(uri.starts_with("lxm://"));

        let (parsed_dest, encrypted) = LXMessage::from_uri(&uri).unwrap();
        assert_eq!(parsed_dest, dest_hash);
        assert!(!encrypted.is_empty());
    }

    #[test]
    fn test_lxmf_too_short_rejected() {
        let data = [0u8; 50]; // less than 96 bytes minimum
        assert!(LXMessage::unpack(&data, None).is_err());
    }
}
