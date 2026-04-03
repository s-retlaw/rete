//! LXMF message — pack, unpack, sign, verify.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use rete_core::msgpack::{self, MsgpackError};
use rete_core::Identity;
use sha2::{Digest, Sha256};

/// Errors from LXMF message packing, unpacking, and verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LxmfMessageError {
    /// Message data too short (need at least 96 bytes).
    TooShort,
    /// Signature verification failed.
    InvalidSignature,
    /// Signing failed.
    SigningFailed,
    /// Msgpack decoding failed.
    Msgpack(MsgpackError),
    /// Expected array of 4 or 5 elements.
    InvalidArrayLen,
}

impl From<MsgpackError> for LxmfMessageError {
    fn from(e: MsgpackError) -> Self {
        LxmfMessageError::Msgpack(e)
    }
}

impl core::fmt::Display for LxmfMessageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort => write!(f, "message too short (need at least 96 bytes)"),
            Self::InvalidSignature => write!(f, "signature verification failed"),
            Self::SigningFailed => write!(f, "signing failed"),
            Self::Msgpack(e) => write!(f, "msgpack error: {e}"),
            Self::InvalidArrayLen => write!(f, "expected array of 4 or 5 elements"),
        }
    }
}

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
/// Ticket field — reply stamp ticket included in message.
pub const FIELD_TICKET: u8 = 0x0C;

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

/// URI prefix for paper messages.
const URI_PREFIX: &str = "lxm://";

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
    /// Proof-of-work stamp (2 bytes), if present.
    pub stamp: Option<[u8; crate::stamp::STAMP_SIZE]>,
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
    ) -> Result<Self, LxmfMessageError> {
        // Build msgpack payload
        let msgpack_payload = encode_msgpack_payload(timestamp, title, content, &fields);

        let sign_data = build_sign_data(&destination_hash, &source_hash, &msgpack_payload);

        let signature = source_identity
            .sign(&sign_data)
            .map_err(|_| LxmfMessageError::SigningFailed)?;

        Ok(LXMessage {
            destination_hash,
            source_hash,
            timestamp,
            title: title.to_vec(),
            content: content.to_vec(),
            fields,
            signature,
            stamp: None,
            state: LXMessageState::New,
            method: DeliveryMethod::Opportunistic,
        })
    }

    /// Pack into wire format: dest_hash[16] || source_hash[16] || signature[64] || msgpack_payload
    ///
    /// The msgpack payload is a 4-element array `[ts, title, content, fields]` when
    /// no stamp is set, or a 5-element array `[ts, title, content, fields, stamp]`
    /// when a stamp is present.
    pub fn pack(&self) -> Vec<u8> {
        let msgpack_payload = encode_msgpack_payload_opt_stamp(
            self.timestamp,
            &self.title,
            &self.content,
            &self.fields,
            self.stamp.as_ref(),
        );
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
    ///
    /// Handles both 4-element (no stamp) and 5-element (with stamp) payloads.
    /// Signature is always verified over the 4-element payload, matching Python LXMF.
    pub fn unpack(data: &[u8], verify_identity: Option<&Identity>) -> Result<Self, LxmfMessageError> {
        if data.len() < 96 {
            return Err(LxmfMessageError::TooShort);
        }

        let mut destination_hash = [0u8; 16];
        let mut source_hash = [0u8; 16];
        let mut signature = [0u8; 64];

        destination_hash.copy_from_slice(&data[..16]);
        source_hash.copy_from_slice(&data[16..32]);
        signature.copy_from_slice(&data[32..96]);
        let msgpack_payload = &data[96..];

        // Parse msgpack payload (extracts stamp if present)
        let (timestamp, title, content, fields, stamp) =
            decode_msgpack_payload(msgpack_payload)?;

        // Verify signature over the 4-element payload (without stamp).
        // Python LXMF strips the stamp and re-encodes before verifying.
        if let Some(identity) = verify_identity {
            let payload_for_signing =
                encode_msgpack_payload(timestamp, &title, &content, &fields);
            let sign_data =
                build_sign_data(&destination_hash, &source_hash, &payload_for_signing);
            identity
                .verify(&sign_data, &signature)
                .map_err(|_| LxmfMessageError::InvalidSignature)?;
        }

        Ok(LXMessage {
            destination_hash,
            source_hash,
            timestamp,
            title,
            content,
            fields,
            signature,
            stamp,
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

    /// Compute the message ID used for stamp material.
    ///
    /// This is `SHA-256(dest_hash || source_hash || msgpack(4-element-payload))`
    /// — always computed WITHOUT the stamp, matching Python LXMF.
    pub fn message_id(&self) -> [u8; 32] {
        let payload = encode_msgpack_payload(self.timestamp, &self.title, &self.content, &self.fields);
        let mut hasher = Sha256::new();
        hasher.update(&self.destination_hash);
        hasher.update(&self.source_hash);
        hasher.update(&payload);
        hasher.finalize().into()
    }

    /// Generate a proof-of-work stamp for this message.
    ///
    /// Sets `self.stamp` to the generated stamp. Uses the message_id as
    /// material for workblock generation.
    pub fn generate_stamp(&mut self, cost: u8) {
        if cost == 0 {
            return;
        }
        let mid = self.message_id();
        if let Some((stamp, _value)) = crate::stamp::generate_stamp(&mid, cost) {
            self.stamp = Some(stamp);
        }
    }

    /// Validate the stamp on this message against a target cost.
    ///
    /// Checks ticket-based stamps first (if any tickets provided), then
    /// falls back to proof-of-work validation.
    ///
    /// Returns `true` if stamp is valid or if `target_cost` is 0.
    pub fn validate_stamp(&self, target_cost: u8, tickets: &[[u8; 2]]) -> bool {
        if target_cost == 0 {
            return true;
        }
        let stamp = match &self.stamp {
            Some(s) => s,
            None => return false,
        };
        let mid = self.message_id();
        // Try ticket validation first (avoid Vec<Vec<u8>> allocation)
        for ticket in tickets {
            let expected = crate::stamp::ticket_stamp(ticket, &mid);
            if *stamp == expected {
                return true;
            }
        }
        // Fall back to proof-of-work
        let workblock = crate::stamp::stamp_workblock(&mid, crate::stamp::WORKBLOCK_EXPAND_ROUNDS);
        crate::stamp::stamp_valid(stamp, target_cost, &workblock)
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
        let mut uri = String::with_capacity(URI_PREFIX.len() + encoded.len());
        uri.push_str(URI_PREFIX);
        uri.push_str(&encoded);
        Some(uri)
    }

    /// Decode an `lxm://` URI back into message components.
    ///
    /// Returns `(destination_hash, encrypted_payload)` — the caller must
    /// decrypt the payload using their identity's private key and then
    /// call `LXMessage::unpack` on the decrypted data.
    pub fn from_uri(uri: &str) -> Option<([u8; 16], Vec<u8>)> {
        let encoded = uri.strip_prefix(URI_PREFIX)?;
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

/// Encode the msgpack payload: 4-element array `[timestamp, title, content, fields]`.
///
/// Used for signing and message_id computation (always without stamp).
fn encode_msgpack_payload(
    timestamp: f64,
    title: &[u8],
    content: &[u8],
    fields: &BTreeMap<u8, Vec<u8>>,
) -> Vec<u8> {
    encode_msgpack_payload_opt_stamp(timestamp, title, content, fields, None)
}

/// Encode the msgpack payload with optional stamp for wire format.
///
/// If stamp is `Some`, produces a 5-element array; otherwise 4-element.
fn encode_msgpack_payload_opt_stamp(
    timestamp: f64,
    title: &[u8],
    content: &[u8],
    fields: &BTreeMap<u8, Vec<u8>>,
    stamp: Option<&[u8; crate::stamp::STAMP_SIZE]>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    if stamp.is_some() {
        buf.push(0x95); // fixarray of 5
    } else {
        buf.push(0x94); // fixarray of 4
    }
    msgpack::write_float64(&mut buf, timestamp);
    msgpack::write_bin(&mut buf, title);
    msgpack::write_bin(&mut buf, content);
    write_map(&mut buf, fields);
    if let Some(s) = stamp {
        msgpack::write_bin(&mut buf, s);
    }
    buf
}

/// Decoded msgpack payload: (timestamp, title, content, fields, stamp).
type DecodedPayload = (f64, Vec<u8>, Vec<u8>, BTreeMap<u8, Vec<u8>>, Option<[u8; crate::stamp::STAMP_SIZE]>);

/// Decode the msgpack payload.
fn decode_msgpack_payload(data: &[u8]) -> Result<DecodedPayload, LxmfMessageError> {
    let mut pos = 0;

    // Read array header: 4 elements [ts, title, content, fields] or
    // 5 elements [ts, title, content, fields, stamp] (Python LXMF >= 0.9.x)
    let arr_len = msgpack::read_array_len(data, &mut pos)?;
    if !(4..=5).contains(&arr_len) {
        return Err(LxmfMessageError::InvalidArrayLen);
    }

    let timestamp = msgpack::read_float64(data, &mut pos)?;
    let title = msgpack::read_bin_or_str(data, &mut pos)?.to_vec();
    let content = msgpack::read_bin_or_str(data, &mut pos)?.to_vec();
    let fields = read_map(data, &mut pos)?;

    let stamp = if arr_len == 5 {
        let stamp_bytes = msgpack::read_bin_or_str(data, &mut pos)?;
        if stamp_bytes.len() >= crate::stamp::STAMP_SIZE {
            let mut s = [0u8; crate::stamp::STAMP_SIZE];
            s.copy_from_slice(&stamp_bytes[..crate::stamp::STAMP_SIZE]);
            Some(s)
        } else {
            None
        }
    } else {
        None
    };

    Ok((timestamp, title, content, fields, stamp))
}

// ---------------------------------------------------------------------------
// Domain-specific msgpack helpers (use rete_core::msgpack primitives)
// ---------------------------------------------------------------------------

fn write_map(buf: &mut Vec<u8>, map: &BTreeMap<u8, Vec<u8>>) {
    msgpack::write_map_header(buf, map.len());
    for (&key, val) in map {
        msgpack::write_uint(buf, key as u64);
        msgpack::write_bin(buf, val);
    }
}

fn read_map(data: &[u8], pos: &mut usize) -> Result<BTreeMap<u8, Vec<u8>>, LxmfMessageError> {
    let len = msgpack::read_map_len(data, pos)?;
    let mut map = BTreeMap::new();
    for _ in 0..len {
        let key = msgpack::read_uint(data, pos)? as u8;
        let val = msgpack::read_bin_or_str(data, pos)?.to_vec();
        map.insert(key, val);
    }
    Ok(map)
}

// ---------------------------------------------------------------------------
// Base64url encode/decode (URL-safe, no padding)
// ---------------------------------------------------------------------------

const B64URL_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 4).div_ceil(3));
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
        let b = if i + 1 < bytes.len() {
            b64url_val(bytes[i + 1])?
        } else {
            0
        };
        let c = if i + 2 < bytes.len() {
            b64url_val(bytes[i + 2])?
        } else {
            0
        };
        let d = if i + 3 < bytes.len() {
            b64url_val(bytes[i + 3])?
        } else {
            0
        };

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
    use alloc::collections::BTreeMap;
    use alloc::vec;
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

    // --- Stamp tests (Step 1 TDD) ---

    #[test]
    fn test_pack_without_stamp_produces_4_element_array() {
        let (msg, _) = make_test_message();
        assert!(msg.stamp.is_none());
        let packed = msg.pack();
        // msgpack payload starts at offset 96
        assert_eq!(packed[96], 0x94); // fixarray of 4
    }

    #[test]
    fn test_pack_with_stamp_produces_5_element_array() {
        let (mut msg, _) = make_test_message();
        msg.stamp = Some([0xAB, 0xCD]);
        let packed = msg.pack();
        assert_eq!(packed[96], 0x95); // fixarray of 5
    }

    #[test]
    fn test_unpack_4_element_has_none_stamp() {
        let (msg, source) = make_test_message();
        let packed = msg.pack();
        let unpacked = LXMessage::unpack(&packed, Some(&source)).unwrap();
        assert!(unpacked.stamp.is_none());
    }

    #[test]
    fn test_unpack_5_element_extracts_stamp() {
        let (mut msg, source) = make_test_message();
        msg.stamp = Some([0xAB, 0xCD]);
        let packed = msg.pack();
        // Signature was computed over 4-element payload in new(), and
        // unpack() re-encodes 4-element for verification — should work.
        let unpacked = LXMessage::unpack(&packed, Some(&source)).unwrap();
        assert_eq!(unpacked.stamp, Some([0xAB, 0xCD]));
    }

    #[test]
    fn test_message_id_deterministic() {
        let (msg, _) = make_test_message();
        let id1 = msg.message_id();
        let id2 = msg.message_id();
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 32);
    }

    #[test]
    fn test_message_id_independent_of_stamp() {
        let (mut msg, _) = make_test_message();
        let id_before = msg.message_id();
        msg.stamp = Some([0x12, 0x34]);
        let id_after = msg.message_id();
        assert_eq!(id_before, id_after);
    }

    #[test]
    fn test_generate_stamp_populates_field() {
        let (mut msg, _) = make_test_message();
        assert!(msg.stamp.is_none());
        // Cost 1 should always succeed quickly
        msg.generate_stamp(1);
        assert!(msg.stamp.is_some());
    }

    #[test]
    fn test_generate_stamp_zero_cost_is_noop() {
        let (mut msg, _) = make_test_message();
        msg.generate_stamp(0);
        assert!(msg.stamp.is_none());
    }

    #[test]
    fn test_validate_stamp_valid_pow() {
        let (mut msg, _) = make_test_message();
        msg.generate_stamp(1);
        assert!(msg.validate_stamp(1, &[]));
    }

    #[test]
    fn test_validate_stamp_invalid_pow() {
        let (mut msg, _) = make_test_message();
        msg.stamp = Some([0xFF, 0xFF]); // unlikely to have any leading zeros
        // Cost 16 means 16 leading zero bits — [0xFF, 0xFF] won't satisfy
        assert!(!msg.validate_stamp(16, &[]));
    }

    #[test]
    fn test_validate_stamp_zero_cost_always_valid() {
        let (msg, _) = make_test_message();
        // No stamp, zero cost — should pass
        assert!(msg.validate_stamp(0, &[]));
    }

    #[test]
    fn test_validate_stamp_no_stamp_fails() {
        let (msg, _) = make_test_message();
        assert!(msg.stamp.is_none());
        assert!(!msg.validate_stamp(1, &[]));
    }

    #[test]
    fn test_validate_stamp_with_ticket() {
        let (mut msg, _) = make_test_message();
        let ticket = [0x42, 0x37];
        let mid = msg.message_id();
        // Generate the correct ticket-based stamp
        let stamp = crate::stamp::ticket_stamp(&ticket, &mid);
        msg.stamp = Some(stamp);
        assert!(msg.validate_stamp(8, &[ticket])); // ticket bypasses PoW
    }

    #[test]
    fn test_field_ticket_constant() {
        assert_eq!(FIELD_TICKET, 0x0C);
    }

    #[test]
    fn test_roundtrip_with_stamp_and_signature_verification() {
        // Full round-trip: create message, add stamp, pack, unpack with verification
        let (mut msg, source) = make_test_message();
        msg.generate_stamp(1);
        assert!(msg.stamp.is_some());

        let packed = msg.pack();
        let unpacked = LXMessage::unpack(&packed, Some(&source)).unwrap();
        assert_eq!(unpacked.stamp, msg.stamp);
        assert_eq!(unpacked.title, b"Hello");
        assert_eq!(unpacked.content, b"World");
    }

    #[test]
    fn test_unpack_too_short() {
        let data = [0u8; 50];
        assert_eq!(
            LXMessage::unpack(&data, None).unwrap_err(),
            LxmfMessageError::TooShort
        );
    }

    #[test]
    fn test_unpack_bad_signature() {
        let (msg, _source) = make_test_message();
        let packed = msg.pack();

        let wrong_identity = Identity::from_seed(b"wrong-identity-seed").unwrap();
        assert_eq!(
            LXMessage::unpack(&packed, Some(&wrong_identity)).unwrap_err(),
            LxmfMessageError::InvalidSignature
        );
    }

    #[test]
    fn test_unpack_bad_msgpack() {
        // 96 bytes of header (dest+source+sig) + garbage msgpack
        let mut data = vec![0u8; 96];
        data.extend_from_slice(&[0xFF, 0xFF]); // invalid msgpack

        assert!(matches!(
            LXMessage::unpack(&data, None).unwrap_err(),
            LxmfMessageError::Msgpack(_)
        ));
    }

    #[test]
    fn test_unpack_wrong_array_len() {
        // 96 bytes of header + a 3-element msgpack array (need 4 or 5)
        let mut data = vec![0u8; 96];
        data.push(0x93); // fixarray of 3
        data.push(0xcb); // float64
        data.extend_from_slice(&1700000000.0f64.to_be_bytes());
        // Two more bin elements
        data.extend_from_slice(&[0xc4, 0x01, 0x41]); // bin8 "A"
        data.extend_from_slice(&[0xc4, 0x01, 0x42]); // bin8 "B"

        assert_eq!(
            LXMessage::unpack(&data, None).unwrap_err(),
            LxmfMessageError::InvalidArrayLen
        );
    }
}
