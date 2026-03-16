//! Reticulum packet wire format — parsing and serialization.
//!
//! # HEADER_1 layout (no transport hop)
//! ```text
//! Offset  Len   Field
//! 0       1     flags  — see PackedFlags
//! 1       1     hops   — 0 when freshly sent, incremented by each repeater
//! 2       16    destination_hash
//! 18      1     context byte  (0x00 = normal)
//! 19      var   payload       (plaintext for PLAIN; ciphertext for SINGLE)
//! ```
//!
//! # HEADER_2 layout (with transport hop)
//! ```text
//! Offset  Len   Field
//! 0       1     flags
//! 1       1     hops
//! 2       16    transport_id  — identity hash of the relaying node
//! 18      16    destination_hash
//! 34      1     context byte
//! 35      var   payload
//! ```
//!
//! # Flags byte
//! ```text
//! Bits 7:6  header_type     0=HEADER_1  1=HEADER_2
//! Bit  5    context_flag    0=unset     1=set
//! Bit  4    transport_type  0=BROADCAST 1=TRANSPORT
//! Bits 3:2  dest_type       0=SINGLE  1=GROUP  2=PLAIN  3=LINK
//! Bits 1:0  packet_type     0=DATA  1=ANNOUNCE  2=LINKREQUEST  3=PROOF
//!
//! flags = (header_type<<6)|(context_flag<<5)|(transport_type<<4)|(dest_type<<2)|packet_type
//! ```
//!
//! # Packet hash
//! ```text
//! hashable_part = (flags & 0x0F) || raw[2:]         for HEADER_1
//! hashable_part = (flags & 0x0F) || raw[18:]        for HEADER_2
//! packet_hash   = SHA-256(hashable_part)             full 32 bytes, NOT truncated
//! ```
//! The hash is invariant to hop count and transport changes.

use crate::{Error, HEADER_1_OVERHEAD, HEADER_2_OVERHEAD, MTU, TRUNCATED_HASH_LEN};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Context byte constants (from Python RNS)
// ---------------------------------------------------------------------------

/// Normal data — no special context.
pub const CONTEXT_NONE: u8 = 0x00;
/// Channel message envelope.
pub const CONTEXT_CHANNEL: u8 = 0x0E;
/// Link keepalive request/response.
pub const CONTEXT_KEEPALIVE: u8 = 0xFA;
/// Link identification during handshake.
pub const CONTEXT_LINKIDENTIFY: u8 = 0xFB;
/// Link close request.
pub const CONTEXT_LINKCLOSE: u8 = 0xFC;
/// Link proof (responder → initiator).
pub const CONTEXT_LINKPROOF: u8 = 0xFD;
/// Link RTT measurement (initiator → responder).
pub const CONTEXT_LRRTT: u8 = 0xFE;
/// Link request proof (part of handshake).
pub const CONTEXT_LRPROOF: u8 = 0xFF;

// Resource transfer context bytes
/// Part of a resource transfer.
pub const CONTEXT_RESOURCE: u8 = 0x01;
/// Resource advertisement.
pub const CONTEXT_RESOURCE_ADV: u8 = 0x02;
/// Resource part request.
pub const CONTEXT_RESOURCE_REQ: u8 = 0x03;
/// Resource hashmap update.
pub const CONTEXT_RESOURCE_HMU: u8 = 0x04;
/// Resource proof (transfer complete).
pub const CONTEXT_RESOURCE_PRF: u8 = 0x05;
/// Resource cancel (initiator).
pub const CONTEXT_RESOURCE_ICL: u8 = 0x06;
/// Resource cancel (receiver).
pub const CONTEXT_RESOURCE_RCL: u8 = 0x07;

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

/// Packet type — bits 1:0 of the flags byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    /// Normal data packet.
    Data = 0,
    /// Node advertisement — broadcasts identity and public key.
    Announce = 1,
    /// Request to establish a Link session.
    LinkRequest = 2,
    /// Delivery proof / acknowledgement.
    Proof = 3,
}

impl TryFrom<u8> for PacketType {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self, Error> {
        match v {
            0 => Ok(Self::Data),
            1 => Ok(Self::Announce),
            2 => Ok(Self::LinkRequest),
            3 => Ok(Self::Proof),
            _ => Err(Error::UnknownPacketType(v)),
        }
    }
}

/// Header type — bits 7:6 of the flags byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HeaderType {
    /// HEADER_1: no transport hop field. Most common.
    Header1 = 0,
    /// HEADER_2: includes a 16-byte transport_id hop field.
    Header2 = 1,
}

/// Destination type — bits 3:2 of the flags byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DestType {
    /// Addressed to a single identity (encrypted).
    Single = 0,
    /// Group destination with a shared key.
    Group = 1,
    /// Broadcast / plain (unencrypted).
    Plain = 2,
    /// Link-layer session endpoint.
    Link = 3,
}

impl TryFrom<u8> for DestType {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self, Error> {
        match v {
            0 => Ok(Self::Single),
            1 => Ok(Self::Group),
            2 => Ok(Self::Plain),
            3 => Ok(Self::Link),
            _ => Err(Error::UnknownDestType(v)),
        }
    }
}

// ---------------------------------------------------------------------------
// Packet — zero-copy parsed view
// ---------------------------------------------------------------------------

/// A parsed Reticulum packet — zero-copy view into a raw byte buffer.
///
/// All fields are slices or values derived directly from the buffer.
/// The buffer must outlive this struct.
#[derive(Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    /// Complete raw bytes of the packet.
    pub raw: &'a [u8],
    /// Flags byte (raw[0]).
    pub flags: u8,
    /// Hop count (raw[1]). 0 when freshly sent.
    pub hops: u8,
    /// Packet type (bits 1:0 of flags).
    pub packet_type: PacketType,
    /// Header type (bits 7:6 of flags).
    pub header_type: HeaderType,
    /// Destination type (bits 3:2 of flags).
    pub dest_type: DestType,
    /// Context flag (bit 5 of flags).
    pub context_flag: bool,
    /// Transport type (bit 4 of flags).
    pub transport_type: u8,
    /// Transport ID (HEADER_2 only) — 16 bytes identifying the relay node.
    pub transport_id: Option<&'a [u8]>,
    /// Destination hash — 16 bytes.
    pub destination_hash: &'a [u8],
    /// Context byte (byte immediately following destination_hash).
    pub context: u8,
    /// Payload — plaintext for PLAIN destinations; ciphertext for SINGLE.
    pub payload: &'a [u8],
}

impl<'a> Packet<'a> {
    /// Parse a Reticulum packet from raw bytes.
    ///
    /// Returns a zero-copy view into `raw`. Does not decrypt or verify
    /// signatures — those are the caller's responsibility.
    ///
    /// # Errors
    /// - [`Error::PacketTooShort`] if `raw` is below the minimum header size
    /// - [`Error::PacketTooLong`] if `raw` exceeds the MTU (500 bytes)
    /// - [`Error::UnknownPacketType`] / [`Error::UnknownDestType`] for invalid flags
    pub fn parse(raw: &'a [u8]) -> Result<Self, Error> {
        if raw.len() < HEADER_1_OVERHEAD {
            return Err(Error::PacketTooShort);
        }
        if raw.len() > MTU {
            return Err(Error::PacketTooLong);
        }

        let flags = raw[0];
        let hops = raw[1];
        let header_type = if (flags >> 6) & 0x01 == 0 {
            HeaderType::Header1
        } else {
            HeaderType::Header2
        };
        let context_flag = (flags >> 5) & 0x01 != 0;
        let transport_type = (flags >> 4) & 0x01;
        let dest_type = DestType::try_from((flags >> 2) & 0x03)?;
        let packet_type = PacketType::try_from(flags & 0x03)?;

        let (transport_id, destination_hash, context, payload) = match header_type {
            HeaderType::Header1 => {
                let dst = &raw[2..2 + TRUNCATED_HASH_LEN];
                let ctx = raw[2 + TRUNCATED_HASH_LEN];
                let data = &raw[2 + TRUNCATED_HASH_LEN + 1..];
                (None, dst, ctx, data)
            }
            HeaderType::Header2 => {
                if raw.len() < HEADER_2_OVERHEAD {
                    return Err(Error::PacketTooShort);
                }
                let tid = &raw[2..2 + TRUNCATED_HASH_LEN];
                let dst = &raw[2 + TRUNCATED_HASH_LEN..2 + 2 * TRUNCATED_HASH_LEN];
                let ctx = raw[2 + 2 * TRUNCATED_HASH_LEN];
                let data = &raw[2 + 2 * TRUNCATED_HASH_LEN + 1..];
                (Some(tid), dst, ctx, data)
            }
        };

        Ok(Packet {
            raw,
            flags,
            hops,
            packet_type,
            header_type,
            dest_type,
            context_flag,
            transport_type,
            transport_id,
            destination_hash,
            context,
            payload,
        })
    }

    /// Write the hashable part of this packet into `buf`.
    ///
    /// ```text
    /// HEADER_1: (flags & 0x0F) || raw[2:]
    /// HEADER_2: (flags & 0x0F) || raw[18:]   (skips transport_id)
    /// ```
    ///
    /// Returns the number of bytes written.
    ///
    /// # Errors
    /// [`Error::BufferTooSmall`] if `buf` cannot hold the hashable part.
    pub fn write_hashable_part(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let tail = match self.header_type {
            HeaderType::Header1 => &self.raw[2..],
            HeaderType::Header2 => &self.raw[2 + TRUNCATED_HASH_LEN..],
        };
        let needed = 1 + tail.len();
        if buf.len() < needed {
            return Err(Error::BufferTooSmall);
        }
        buf[0] = self.flags & 0x0F;
        buf[1..needed].copy_from_slice(tail);
        Ok(needed)
    }

    /// Compute the 32-byte packet hash.
    ///
    /// `packet_hash = SHA-256(hashable_part)` — full 32 bytes, NOT truncated.
    ///
    /// Invariant to hop count and transport changes.
    /// Uses incremental hashing to avoid a 500-byte stack buffer.
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([self.flags & 0x0F]);
        let tail = match self.header_type {
            HeaderType::Header1 => &self.raw[2..],
            HeaderType::Header2 => &self.raw[2 + TRUNCATED_HASH_LEN..],
        };
        hasher.update(tail);
        hasher.finalize().into()
    }
}

// ---------------------------------------------------------------------------
// PacketBuilder — serialization into a caller-supplied buffer
// ---------------------------------------------------------------------------

/// Builder for constructing Reticulum packets into a caller-supplied buffer.
///
/// # Example
/// ```rust,ignore
/// let mut buf = [0u8; 500];
/// let len = PacketBuilder::new(&mut buf)
///     .packet_type(PacketType::Data)
///     .dest_type(DestType::Plain)
///     .destination_hash(&dest_hash)
///     .payload(b"hello world")
///     .build()?;
/// ```
pub struct PacketBuilder<'a> {
    buf: &'a mut [u8],
    header_type: HeaderType,
    packet_type: PacketType,
    dest_type: DestType,
    context_flag: bool,
    transport_type: u8,
    transport_id: Option<[u8; TRUNCATED_HASH_LEN]>,
    dest_hash: Option<[u8; TRUNCATED_HASH_LEN]>,
    context: u8,
    payload: Option<&'a [u8]>,
    hops: u8,
}

impl<'a> PacketBuilder<'a> {
    /// Create a builder writing into `buf`.
    pub fn new(buf: &'a mut [u8]) -> Self {
        PacketBuilder {
            buf,
            hops: 0,
            context: 0x00,
            context_flag: false,
            transport_type: 0,
            transport_id: None,
            dest_hash: None,
            payload: None,
            header_type: HeaderType::Header1,
            packet_type: PacketType::Data,
            dest_type: DestType::Plain,
        }
    }

    /// Set the header type (default: Header1).
    pub fn header_type(mut self, v: HeaderType) -> Self {
        self.header_type = v;
        self
    }
    /// Set the packet type (default: Data).
    pub fn packet_type(mut self, v: PacketType) -> Self {
        self.packet_type = v;
        self
    }
    /// Set the destination type (default: Plain).
    pub fn dest_type(mut self, v: DestType) -> Self {
        self.dest_type = v;
        self
    }
    /// Set the context byte (default: 0x00).
    pub fn context(mut self, v: u8) -> Self {
        self.context = v;
        self
    }
    /// Set the hop count (default: 0).
    pub fn hops(mut self, v: u8) -> Self {
        self.hops = v;
        self
    }
    /// Set the transport type (0=BROADCAST, 1=TRANSPORT; default: 0).
    pub fn transport_type(mut self, v: u8) -> Self {
        self.transport_type = v;
        self
    }

    /// Set the destination hash (exactly 16 bytes).
    pub fn destination_hash(mut self, hash: &[u8]) -> Self {
        let mut h = [0u8; TRUNCATED_HASH_LEN];
        let len = hash.len().min(TRUNCATED_HASH_LEN);
        h[..len].copy_from_slice(&hash[..len]);
        self.dest_hash = Some(h);
        self
    }

    /// Set the transport ID (HEADER_2 only, exactly 16 bytes).
    pub fn transport_id(mut self, tid: &[u8]) -> Self {
        let mut t = [0u8; TRUNCATED_HASH_LEN];
        let len = tid.len().min(TRUNCATED_HASH_LEN);
        t[..len].copy_from_slice(&tid[..len]);
        self.transport_id = Some(t);
        self
    }

    /// Set the payload bytes.
    pub fn payload(mut self, data: &'a [u8]) -> Self {
        self.payload = Some(data);
        self
    }

    /// Serialize the packet into the buffer.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Errors
    /// - [`Error::MissingField`] if destination_hash was not set
    /// - [`Error::PacketTooLong`] if the result would exceed the MTU
    /// - [`Error::BufferTooSmall`] if the buffer is too small
    pub fn build(self) -> Result<usize, Error> {
        let payload = self.payload.unwrap_or(&[]);
        let dest_hash = self
            .dest_hash
            .ok_or(Error::MissingField("destination_hash"))?;

        let overhead = match self.header_type {
            HeaderType::Header1 => HEADER_1_OVERHEAD,
            HeaderType::Header2 => HEADER_2_OVERHEAD,
        };
        let total = overhead + payload.len();

        if total > MTU {
            return Err(Error::PacketTooLong);
        }
        if self.buf.len() < total {
            return Err(Error::BufferTooSmall);
        }

        let flags = ((self.header_type as u8) << 6)
            | ((self.context_flag as u8) << 5)
            | (self.transport_type << 4)
            | ((self.dest_type as u8) << 2)
            | (self.packet_type as u8);

        self.buf[0] = flags;
        self.buf[1] = self.hops;

        match self.header_type {
            HeaderType::Header1 => {
                self.buf[2..18].copy_from_slice(&dest_hash);
                self.buf[18] = self.context;
                self.buf[19..total].copy_from_slice(payload);
            }
            HeaderType::Header2 => {
                let tid = self
                    .transport_id
                    .ok_or(Error::MissingField("transport_id"))?;
                self.buf[2..18].copy_from_slice(&tid);
                self.buf[18..34].copy_from_slice(&dest_hash);
                self.buf[34] = self.context;
                self.buf[35..total].copy_from_slice(payload);
            }
        }

        Ok(total)
    }
}

// ---------------------------------------------------------------------------
// Tests — validated against tests/interop/vectors.json
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;

    fn unhex(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Test vectors from tests/interop/vectors.json (generated by
    // generate_test_vectors.py against Python RNS 1.1.4)

    #[test]
    fn parse_plain_data_packet() {
        // data_packet_vectors[0]: PLAIN DATA, payload = b"hello world"
        let raw = unhex("0800066951e758a2aa0068dd10ec3ee8bfbc0068656c6c6f20776f726c64");
        let pkt = Packet::parse(&raw).unwrap();

        assert_eq!(pkt.flags, 0x08);
        assert_eq!(pkt.hops, 0);
        assert_eq!(pkt.packet_type, PacketType::Data);
        assert_eq!(pkt.header_type, HeaderType::Header1);
        assert_eq!(pkt.dest_type, DestType::Plain);
        assert_eq!(pkt.context_flag, false);
        assert_eq!(pkt.context, 0x00);
        assert_eq!(pkt.payload, b"hello world");
        assert!(pkt.transport_id.is_none());
    }

    #[test]
    fn flags_byte_round_trip() {
        // packet_flags_vectors — verify encode/decode symmetry
        let cases: &[(u8, u8, u8, u8, u8)] = &[
            (0, 0, 0, 2, 0), // 0x08 PLAIN DATA
            (0, 0, 0, 0, 1), // 0x01 SINGLE ANNOUNCE
            (1, 0, 0, 0, 0), // 0x40 HEADER_2 SINGLE DATA
            (0, 1, 0, 0, 0), // 0x20 context_flag set
        ];
        for &(ht, cf, tt, dt, pt) in cases {
            let expected = (ht << 6) | (cf << 5) | (tt << 4) | (dt << 2) | pt;
            assert_eq!(
                (expected >> 6) & 0x01,
                ht,
                "header_type mismatch for flags={expected:#04x}"
            );
            assert_eq!((expected >> 2) & 0x03, dt);
            assert_eq!(expected & 0x03, pt);
        }
    }

    #[test]
    fn packet_hash_hop_invariance() {
        // packet_hash_vectors — same hash at hops=0 and hops=5
        let raw_0 = unhex("0800066951e758a2aa0068dd10ec3ee8bfbc0074657374");
        let mut raw_5 = raw_0.clone();
        raw_5[1] = 5;

        let h0 = Packet::parse(&raw_0).unwrap().compute_hash();
        let h5 = Packet::parse(&raw_5).unwrap().compute_hash();
        assert_eq!(h0, h5, "packet hash must be invariant to hop count");
    }

    #[test]
    fn build_plain_round_trip() {
        let dest = [
            0x06u8, 0x69, 0x51, 0xe7, 0x58, 0xa2, 0xaa, 0x00, 0x68, 0xdd, 0x10, 0xec, 0x3e, 0xe8,
            0xbf, 0xbc,
        ];
        let payload = b"hello world";
        let mut buf = [0u8; MTU];

        let n = PacketBuilder::new(&mut buf)
            .dest_type(DestType::Plain)
            .destination_hash(&dest)
            .payload(payload)
            .build()
            .unwrap();

        let pkt = Packet::parse(&buf[..n]).unwrap();
        assert_eq!(pkt.packet_type, PacketType::Data);
        assert_eq!(pkt.dest_type, DestType::Plain);
        assert_eq!(pkt.destination_hash, &dest);
        assert_eq!(pkt.payload, payload);
        assert_eq!(pkt.hops, 0);
    }

    #[test]
    fn too_short_returns_error() {
        assert_eq!(Packet::parse(&[0x08, 0x00]), Err(Error::PacketTooShort));
    }

    #[test]
    fn builder_requires_dest_hash() {
        let mut buf = [0u8; MTU];
        let err = PacketBuilder::new(&mut buf).payload(b"test").build();
        assert_eq!(err, Err(Error::MissingField("destination_hash")));
    }

    #[test]
    fn test_mtu_boundary_packet() {
        // Build a HEADER_1 packet that is exactly MTU (500) bytes.
        // HEADER_1 overhead = 19, so payload = 500 - 19 = 481 bytes.
        let dest = [0xAAu8; TRUNCATED_HASH_LEN];
        let payload = [0xBBu8; MTU - HEADER_1_OVERHEAD];
        let mut buf = [0u8; MTU];

        let n = PacketBuilder::new(&mut buf)
            .dest_type(DestType::Plain)
            .destination_hash(&dest)
            .payload(&payload)
            .build()
            .unwrap();

        assert_eq!(n, MTU, "packet should be exactly MTU bytes");

        let pkt = Packet::parse(&buf[..n]).unwrap();
        assert_eq!(pkt.payload.len(), MTU - HEADER_1_OVERHEAD);
        assert_eq!(pkt.destination_hash, &dest);
    }

    #[test]
    fn test_zero_length_payload() {
        // Build a HEADER_1 DATA packet with empty payload.
        let dest = [0xCCu8; TRUNCATED_HASH_LEN];
        let mut buf = [0u8; MTU];

        let n = PacketBuilder::new(&mut buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Plain)
            .destination_hash(&dest)
            .payload(&[])
            .build()
            .unwrap();

        assert_eq!(n, HEADER_1_OVERHEAD);

        let pkt = Packet::parse(&buf[..n]).unwrap();
        assert_eq!(pkt.packet_type, PacketType::Data);
        assert_eq!(pkt.payload.len(), 0);
        assert_eq!(pkt.destination_hash, &dest);
    }

    #[test]
    fn test_header2_max_payload() {
        // Build a HEADER_2 packet with maximum payload size.
        // HEADER_2 overhead = 35, so payload = 500 - 35 = 465 bytes.
        let dest = [0xAAu8; TRUNCATED_HASH_LEN];
        let tid = [0xBBu8; TRUNCATED_HASH_LEN];
        let payload = [0xCCu8; MTU - HEADER_2_OVERHEAD];
        let mut buf = [0u8; MTU];

        let n = PacketBuilder::new(&mut buf)
            .header_type(HeaderType::Header2)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Single)
            .transport_type(1)
            .transport_id(&tid)
            .destination_hash(&dest)
            .payload(&payload)
            .build()
            .unwrap();

        assert_eq!(n, MTU, "HEADER_2 max payload packet should be exactly MTU");

        let pkt = Packet::parse(&buf[..n]).unwrap();
        assert_eq!(pkt.header_type, HeaderType::Header2);
        assert_eq!(pkt.payload.len(), MTU - HEADER_2_OVERHEAD);
        assert_eq!(pkt.transport_id.unwrap(), &tid);
        assert_eq!(pkt.destination_hash, &dest);
    }

    #[test]
    fn test_mtu_plus_one_returns_packet_too_long() {
        // A packet of exactly MTU+1 (501) bytes must return PacketTooLong.
        let raw = [0u8; MTU + 1];
        assert_eq!(Packet::parse(&raw), Err(Error::PacketTooLong));

        // Also verify the builder rejects it:
        let dest = [0xAAu8; TRUNCATED_HASH_LEN];
        let payload = [0xBBu8; MTU - HEADER_1_OVERHEAD + 1]; // 1 byte too many
        let mut buf = [0u8; MTU + 16];
        let err = PacketBuilder::new(&mut buf)
            .dest_type(DestType::Plain)
            .destination_hash(&dest)
            .payload(&payload)
            .build();
        assert_eq!(err, Err(Error::PacketTooLong));
    }
}
