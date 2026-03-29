//! Interface Access Codes (IFAC) — per-interface packet authentication.
//!
//! IFAC provides a mechanism for interfaces to authenticate packets using
//! Ed25519 signatures and HKDF-XOR masking. Packets from interfaces with an
//! access code get a truncated Ed25519 signature tag inserted and the entire
//! packet XOR-masked. Packets without valid tags are dropped.
//!
//! # Protocol
//!
//! ## Key derivation
//! ```text
//! ifac_origin      = SHA-256(netname.utf8) || SHA-256(netkey.utf8)
//!                    (either or both can be provided)
//! ifac_origin_hash = SHA-256(ifac_origin)
//! ifac_key         = HKDF-SHA256(ikm=ifac_origin_hash, salt=IFAC_SALT, info=b"", length=64)
//! ifac_identity    = Identity::from_private_key(ifac_key)
//! ```
//!
//! ## Transmit (masking)
//! ```text
//! 1. ifac_tag = ifac_identity.sign(raw)[-ifac_size:]
//! 2. mask = HKDF-SHA256(ikm=ifac_tag, salt=ifac_key, info=b"", length=len(raw)+ifac_size)
//! 3. new_header = [raw[0] | 0x80, raw[1]]
//! 4. new_raw = new_header || ifac_tag || raw[2:]
//! 5. XOR-mask new_raw (flags masked but IFAC flag kept; tag unmasked; rest masked)
//! ```
//!
//! ## Receive (unmasking)
//! ```text
//! 1. Check IFAC flag (0x80) is set
//! 2. Extract ifac_tag, generate mask, unmask
//! 3. Strip IFAC tag, unset IFAC flag
//! 4. Verify: expected_tag == ifac_tag
//! ```

use crate::{Error, Identity};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// HKDF salt used for IFAC key derivation (from Python `Reticulum.IFAC_SALT`).
pub const IFAC_SALT: [u8; 32] = [
    0xad, 0xf5, 0x4d, 0x88, 0x2c, 0x9a, 0x9b, 0x80, 0x77, 0x1e, 0xb4, 0x99, 0x5d, 0x70, 0x2d, 0x4a,
    0x3e, 0x73, 0x33, 0x91, 0xb2, 0xa0, 0xf5, 0x3f, 0x41, 0x6d, 0x9f, 0x90, 0x7e, 0x55, 0xcf, 0xf8,
];

/// Default IFAC tag size in bytes (16 bytes = 128 bits).
pub const DEFAULT_IFAC_SIZE: usize = 16;

/// Bit flag set on byte 0 of a packet to indicate IFAC is applied.
pub const IFAC_FLAG: u8 = 0x80;

/// Maximum size of an IFAC-protected packet: MTU + largest possible tag.
const MAX_PROTECTED_LEN: usize = crate::MTU + 64;

/// IFAC key material for protecting and unprotecting packets.
///
/// Derived from a network name and/or network key (passphrase).
/// All interfaces sharing the same `IfacKey` can communicate;
/// packets from interfaces with a different (or no) IFAC key are dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IfacKey {
    identity: Identity,
    key: [u8; 64],
    ifac_size: usize,
}

impl IfacKey {
    /// Derive an IFAC key from a network name and/or network key.
    ///
    /// At least one of `netname` or `netkey` must be `Some`. The derivation
    /// matches the Python reference:
    /// ```text
    /// ifac_origin      = SHA-256(netname.utf8) [|| SHA-256(netkey.utf8)]
    /// ifac_origin_hash = SHA-256(ifac_origin)
    /// ifac_key         = HKDF-SHA256(ikm=ifac_origin_hash, salt=IFAC_SALT, info=b"", len=64)
    /// ifac_identity    = Identity::from_private_key(ifac_key)
    /// ```
    ///
    /// # Errors
    /// - [`Error::InvalidKey`] if both `netname` and `netkey` are `None`.
    /// - [`Error::CryptoError`] if HKDF expansion fails.
    pub fn derive(netname: Option<&str>, netkey: Option<&str>) -> Result<Self, Error> {
        Self::derive_with_size(netname, netkey, DEFAULT_IFAC_SIZE)
    }

    /// Derive an IFAC key with a custom tag size.
    ///
    /// `ifac_size` is the number of bytes of the Ed25519 signature used as the
    /// IFAC tag (default 16). Must be >= 1 and <= 64.
    ///
    /// # Errors
    /// Same as [`IfacKey::derive`], plus [`Error::InvalidKey`] for invalid sizes.
    pub fn derive_with_size(
        netname: Option<&str>,
        netkey: Option<&str>,
        ifac_size: usize,
    ) -> Result<Self, Error> {
        if netname.is_none() && netkey.is_none() {
            return Err(Error::InvalidKey);
        }
        if ifac_size == 0 || ifac_size > 64 {
            return Err(Error::InvalidKey);
        }

        // Build ifac_origin: concatenation of SHA-256 hashes of provided inputs
        let mut ifac_origin = [0u8; 64]; // max: 32 + 32
        let mut origin_len = 0;

        if let Some(name) = netname {
            let hash = Sha256::digest(name.as_bytes());
            ifac_origin[origin_len..origin_len + 32].copy_from_slice(&hash);
            origin_len += 32;
        }
        if let Some(key) = netkey {
            let hash = Sha256::digest(key.as_bytes());
            ifac_origin[origin_len..origin_len + 32].copy_from_slice(&hash);
            origin_len += 32;
        }

        // ifac_origin_hash = SHA-256(ifac_origin)
        let ifac_origin_hash = Sha256::digest(&ifac_origin[..origin_len]);

        // ifac_key = HKDF-SHA256(ikm=ifac_origin_hash, salt=IFAC_SALT, info=b"", length=64)
        let hk = Hkdf::<Sha256>::new(Some(&IFAC_SALT), &ifac_origin_hash);
        let mut ifac_key = [0u8; 64];
        hk.expand(b"", &mut ifac_key)
            .map_err(|_| Error::CryptoError)?;

        // ifac_identity = Identity::from_private_key(ifac_key)
        let identity = Identity::from_private_key(&ifac_key)?;

        Ok(IfacKey {
            identity,
            key: ifac_key,
            ifac_size,
        })
    }

    /// Returns the IFAC tag size in bytes.
    pub fn ifac_size(&self) -> usize {
        self.ifac_size
    }

    /// Check whether a raw packet has the IFAC flag (bit 7) set on byte 0.
    pub fn has_ifac_flag(raw: &[u8]) -> bool {
        !raw.is_empty() && (raw[0] & IFAC_FLAG) == IFAC_FLAG
    }

    /// Apply IFAC protection: sign, insert tag, and mask.
    ///
    /// Writes the protected packet into `out`. Returns the number of bytes
    /// written, which is `raw.len() + ifac_size`.
    ///
    /// # Layout of output
    /// ```text
    /// byte[0]:                (flags ^ mask[0]) | 0x80   (masked, IFAC flag kept)
    /// byte[1]:                hops ^ mask[1]              (masked)
    /// byte[2..2+ifac_size]:   ifac_tag                    (unmasked)
    /// byte[2+ifac_size..]:    raw[2..] ^ mask[..]         (masked)
    /// ```
    ///
    /// # Errors
    /// - [`Error::PacketTooShort`] if `raw` has fewer than 2 bytes.
    /// - [`Error::BufferTooSmall`] if `out` cannot hold `raw.len() + ifac_size` bytes.
    /// - [`Error::CryptoError`] if signing or HKDF fails.
    pub fn protect(&self, raw: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if raw.len() < 2 {
            return Err(Error::PacketTooShort);
        }

        let out_len = raw.len() + self.ifac_size;
        if out.len() < out_len {
            return Err(Error::BufferTooSmall);
        }

        // 1. Sign the raw packet and take the last ifac_size bytes as the tag
        let signature = self.identity.sign(raw)?;
        let ifac_tag = &signature[64 - self.ifac_size..];

        // 2. Generate mask: HKDF-SHA256(ikm=ifac_tag, salt=ifac_key, info=b"", length=out_len)
        let hk = Hkdf::<Sha256>::new(Some(&self.key), ifac_tag);
        // We need out_len bytes of mask. Use a stack buffer large enough for MTU + tag.
        // Max packet = 500 + 64 = 564.
        let mut mask = [0u8; MAX_PROTECTED_LEN];
        hk.expand(b"", &mut mask[..out_len])
            .map_err(|_| Error::CryptoError)?;

        // 3. Assemble: new_header || ifac_tag || raw[2:]
        //    new_header = [raw[0] | 0x80, raw[1]]
        out[0] = raw[0] | IFAC_FLAG;
        out[1] = raw[1];
        out[2..2 + self.ifac_size].copy_from_slice(ifac_tag);
        out[2 + self.ifac_size..out_len].copy_from_slice(&raw[2..]);

        // 4. Apply mask
        //    i=0: (byte ^ mask[0]) | 0x80  — mask flags, keep IFAC flag
        //    i=1: byte ^ mask[1]            — mask hops
        //    i=2..2+ifac_size: no mask      — IFAC tag stays clear
        //    i=2+ifac_size..: byte ^ mask[i] — mask the rest
        out[0] = (out[0] ^ mask[0]) | IFAC_FLAG;
        out[1] ^= mask[1];
        for i in (2 + self.ifac_size)..out_len {
            out[i] ^= mask[i];
        }

        Ok(out_len)
    }

    /// Verify and strip IFAC protection: unmask, verify tag, reconstruct.
    ///
    /// Writes the unprotected packet into `out`. Returns the number of bytes
    /// written, which is `raw.len() - ifac_size`.
    ///
    /// # Errors
    /// - [`Error::PacketTooShort`] if `raw` is too short to contain header + tag.
    /// - [`Error::BufferTooSmall`] if `out` cannot hold the result.
    /// - [`Error::InvalidSignature`] if the IFAC tag does not verify.
    /// - [`Error::CryptoError`] if HKDF fails.
    ///
    /// Also returns `InvalidSignature` if the IFAC flag is not set.
    pub fn unprotect(&self, raw: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if raw.len() < 2 + self.ifac_size {
            return Err(Error::PacketTooShort);
        }

        // Check IFAC flag
        if raw[0] & IFAC_FLAG != IFAC_FLAG {
            return Err(Error::InvalidSignature);
        }

        let out_len = raw.len() - self.ifac_size;
        if out.len() < out_len {
            return Err(Error::BufferTooSmall);
        }

        // 1. Extract ifac_tag (unmasked in the protected packet)
        let ifac_tag = &raw[2..2 + self.ifac_size];

        // 2. Generate mask: HKDF-SHA256(ikm=ifac_tag, salt=ifac_key, info=b"", length=len(raw))
        let hk = Hkdf::<Sha256>::new(Some(&self.key), ifac_tag);
        let mut mask = [0u8; MAX_PROTECTED_LEN];
        hk.expand(b"", &mut mask[..raw.len()])
            .map_err(|_| Error::CryptoError)?;

        // 3. Unmask into a temporary buffer (we need the full unmasked raw to extract fields)
        //    We unmask in-place conceptually but since raw is immutable, build unmasked in out
        //    area temporarily. We need raw.len() bytes of scratch space.
        //    Actually, let's use a stack buffer since out might be smaller than raw.
        let mut unmasked = [0u8; MAX_PROTECTED_LEN];
        let raw_len = raw.len();
        unmasked[..raw_len].copy_from_slice(raw);

        // Unmask: bytes 0,1 and bytes > ifac_size+1 get XOR'd with mask
        // bytes 2..2+ifac_size are NOT unmasked (tag is stored clear)
        unmasked[0] ^= mask[0];
        unmasked[1] ^= mask[1];
        for i in (2 + self.ifac_size)..raw_len {
            unmasked[i] ^= mask[i];
        }

        // 4. Unset IFAC flag
        unmasked[0] &= !IFAC_FLAG;

        // 5. Reconstruct original packet: new_header || raw[2+ifac_size:]
        out[0] = unmasked[0];
        out[1] = unmasked[1];
        let payload_start = 2 + self.ifac_size;
        out[2..out_len].copy_from_slice(&unmasked[payload_start..raw_len]);

        // 6. Verify: sign the reconstructed packet and check tag matches
        let expected_sig = self.identity.sign(&out[..out_len])?;
        let expected_tag = &expected_sig[64 - self.ifac_size..];

        if ifac_tag != expected_tag {
            return Err(Error::InvalidSignature);
        }

        Ok(out_len)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a minimal valid packet for testing.
    fn make_test_packet() -> [u8; 30] {
        // HEADER_1 PLAIN DATA packet: flags=0x08, hops=0, dest_hash=16 bytes, context=0, payload="hello"
        let mut pkt = [0u8; 30];
        pkt[0] = 0x08; // PLAIN DATA
        pkt[1] = 0x00; // hops
                       // dest_hash: 16 bytes of 0xAA
        for i in 2..18 {
            pkt[i] = 0xAA;
        }
        pkt[18] = 0x00; // context
                        // payload: "hello world"
        let payload = b"hello world";
        pkt[19..19 + payload.len()].copy_from_slice(payload);
        pkt
    }

    #[test]
    fn test_ifac_round_trip() {
        let ifac = IfacKey::derive(Some("testnetwork"), None).unwrap();
        let raw = make_test_packet();

        // Protect
        let mut protected = [0u8; MAX_PROTECTED_LEN];
        let prot_len = ifac.protect(&raw, &mut protected).unwrap();
        assert_eq!(prot_len, raw.len() + DEFAULT_IFAC_SIZE);

        // IFAC flag should be set on the protected packet
        assert!(IfacKey::has_ifac_flag(&protected[..prot_len]));

        // Unprotect
        let mut recovered = [0u8; MAX_PROTECTED_LEN];
        let rec_len = ifac
            .unprotect(&protected[..prot_len], &mut recovered)
            .unwrap();
        assert_eq!(rec_len, raw.len());
        assert_eq!(&recovered[..rec_len], &raw[..]);
    }

    #[test]
    fn test_ifac_tamper_rejected() {
        let ifac = IfacKey::derive(Some("testnetwork"), None).unwrap();
        let raw = make_test_packet();

        let mut protected = [0u8; MAX_PROTECTED_LEN];
        let prot_len = ifac.protect(&raw, &mut protected).unwrap();

        // Tamper with a byte in the masked payload area
        let tamper_idx = 2 + DEFAULT_IFAC_SIZE + 5;
        protected[tamper_idx] ^= 0xFF;

        let mut recovered = [0u8; MAX_PROTECTED_LEN];
        let result = ifac.unprotect(&protected[..prot_len], &mut recovered);
        assert_eq!(result, Err(Error::InvalidSignature));
    }

    #[test]
    fn test_ifac_wrong_key_rejected() {
        let ifac_a = IfacKey::derive(Some("network-a"), None).unwrap();
        let ifac_b = IfacKey::derive(Some("network-b"), None).unwrap();
        let raw = make_test_packet();

        let mut protected = [0u8; MAX_PROTECTED_LEN];
        let prot_len = ifac_a.protect(&raw, &mut protected).unwrap();

        let mut recovered = [0u8; MAX_PROTECTED_LEN];
        let result = ifac_b.unprotect(&protected[..prot_len], &mut recovered);
        assert_eq!(result, Err(Error::InvalidSignature));
    }

    #[test]
    fn test_ifac_flag_detection() {
        let raw = make_test_packet();
        assert!(!IfacKey::has_ifac_flag(&raw));

        let ifac = IfacKey::derive(Some("test"), None).unwrap();
        let mut protected = [0u8; MAX_PROTECTED_LEN];
        let prot_len = ifac.protect(&raw, &mut protected).unwrap();
        assert!(IfacKey::has_ifac_flag(&protected[..prot_len]));

        // Empty slice
        assert!(!IfacKey::has_ifac_flag(&[]));
    }

    #[test]
    fn test_ifac_empty_packet() {
        let ifac = IfacKey::derive(Some("test"), None).unwrap();

        // Too short (< 2 bytes)
        let mut out = [0u8; MAX_PROTECTED_LEN];
        assert_eq!(ifac.protect(&[0x08], &mut out), Err(Error::PacketTooShort));
        assert_eq!(ifac.protect(&[], &mut out), Err(Error::PacketTooShort));
    }

    #[test]
    fn test_ifac_derive_netname_only() {
        let ifac = IfacKey::derive(Some("mynetwork"), None);
        assert!(ifac.is_ok());
    }

    #[test]
    fn test_ifac_derive_netkey_only() {
        let ifac = IfacKey::derive(None, Some("secretpassphrase"));
        assert!(ifac.is_ok());
    }

    #[test]
    fn test_ifac_derive_both() {
        let ifac = IfacKey::derive(Some("mynetwork"), Some("secretpassphrase"));
        assert!(ifac.is_ok());
    }

    #[test]
    fn test_ifac_derive_neither_fails() {
        let result = IfacKey::derive(None, None);
        assert_eq!(result.err(), Some(Error::InvalidKey));
    }

    #[test]
    fn test_ifac_derive_deterministic() {
        // Same inputs must produce the same key
        let a = IfacKey::derive(Some("net"), Some("key")).unwrap();
        let b = IfacKey::derive(Some("net"), Some("key")).unwrap();
        assert_eq!(a.key, b.key);
        assert_eq!(a.identity.public_key(), b.identity.public_key());
    }

    #[test]
    fn test_ifac_buffer_too_small_protect() {
        let ifac = IfacKey::derive(Some("test"), None).unwrap();
        let raw = make_test_packet();

        // Output buffer too small
        let mut out = [0u8; 10];
        assert_eq!(ifac.protect(&raw, &mut out), Err(Error::BufferTooSmall));
    }

    #[test]
    fn test_ifac_buffer_too_small_unprotect() {
        let ifac = IfacKey::derive(Some("test"), None).unwrap();
        let raw = make_test_packet();

        let mut protected = [0u8; MAX_PROTECTED_LEN];
        let prot_len = ifac.protect(&raw, &mut protected).unwrap();

        // Output buffer too small
        let mut out = [0u8; 5];
        assert_eq!(
            ifac.unprotect(&protected[..prot_len], &mut out),
            Err(Error::BufferTooSmall)
        );
    }

    #[test]
    fn test_ifac_no_flag_rejected() {
        // A packet without the IFAC flag should be rejected by unprotect
        let ifac = IfacKey::derive(Some("test"), None).unwrap();
        let raw = make_test_packet();
        assert_eq!(raw[0] & IFAC_FLAG, 0); // no IFAC flag

        let mut out = [0u8; MAX_PROTECTED_LEN];
        // Need to make it long enough to pass the length check
        let mut padded = [0u8; 100];
        padded[..raw.len()].copy_from_slice(&raw);
        assert_eq!(
            ifac.unprotect(&padded[..raw.len()], &mut out),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn test_ifac_minimal_packet() {
        // Minimal valid packet: just flags + hops (2 bytes)
        let ifac = IfacKey::derive(Some("test"), None).unwrap();
        let raw = [0x08u8, 0x00];

        let mut protected = [0u8; MAX_PROTECTED_LEN];
        let prot_len = ifac.protect(&raw, &mut protected).unwrap();
        assert_eq!(prot_len, 2 + DEFAULT_IFAC_SIZE);

        let mut recovered = [0u8; MAX_PROTECTED_LEN];
        let rec_len = ifac
            .unprotect(&protected[..prot_len], &mut recovered)
            .unwrap();
        assert_eq!(rec_len, 2);
        assert_eq!(&recovered[..2], &raw[..]);
    }

    #[test]
    fn test_ifac_large_packet() {
        // Test with a near-MTU packet
        let ifac = IfacKey::derive(Some("bigpacket"), Some("key123")).unwrap();

        let mut raw = [0u8; 480];
        raw[0] = 0x08; // PLAIN DATA
        for i in 2..480 {
            raw[i] = (i & 0xFF) as u8;
        }

        let mut protected = [0u8; MAX_PROTECTED_LEN];
        let prot_len = ifac.protect(&raw, &mut protected).unwrap();
        assert_eq!(prot_len, 480 + DEFAULT_IFAC_SIZE);

        let mut recovered = [0u8; MAX_PROTECTED_LEN];
        let rec_len = ifac
            .unprotect(&protected[..prot_len], &mut recovered)
            .unwrap();
        assert_eq!(rec_len, 480);
        assert_eq!(&recovered[..480], &raw[..]);
    }

    #[test]
    fn test_ifac_different_netname_different_key() {
        let a = IfacKey::derive(Some("alpha"), None).unwrap();
        let b = IfacKey::derive(Some("beta"), None).unwrap();
        assert_ne!(a.key, b.key);
    }

    #[test]
    fn test_ifac_custom_size() {
        // Test with a custom IFAC size
        let ifac = IfacKey::derive_with_size(Some("test"), None, 8).unwrap();
        assert_eq!(ifac.ifac_size(), 8);

        let raw = make_test_packet();
        let mut protected = [0u8; MAX_PROTECTED_LEN];
        let prot_len = ifac.protect(&raw, &mut protected).unwrap();
        assert_eq!(prot_len, raw.len() + 8);

        let mut recovered = [0u8; MAX_PROTECTED_LEN];
        let rec_len = ifac
            .unprotect(&protected[..prot_len], &mut recovered)
            .unwrap();
        assert_eq!(rec_len, raw.len());
        assert_eq!(&recovered[..rec_len], &raw[..]);
    }

    #[test]
    fn test_ifac_invalid_size() {
        assert_eq!(
            IfacKey::derive_with_size(Some("test"), None, 0).err(),
            Some(Error::InvalidKey)
        );
        assert_eq!(
            IfacKey::derive_with_size(Some("test"), None, 65).err(),
            Some(Error::InvalidKey)
        );
    }

    #[test]
    fn test_ifac_protect_announce_packet() {
        // ANNOUNCE packet: flags byte = 0x01 (packet_type=ANNOUNCE)
        let ifac = IfacKey::derive(Some("announce-net"), None).unwrap();
        let mut pkt = [0u8; 30];
        pkt[0] = 0x01; // ANNOUNCE
        pkt[1] = 0x00; // hops
        for i in 2..18 {
            pkt[i] = 0xBB;
        }
        pkt[18] = 0x00; // context
        let payload = b"hello world";
        pkt[19..19 + payload.len()].copy_from_slice(payload);

        let mut protected = [0u8; MAX_PROTECTED_LEN];
        let prot_len = ifac.protect(&pkt, &mut protected).unwrap();
        assert_eq!(prot_len, pkt.len() + DEFAULT_IFAC_SIZE);
        assert!(IfacKey::has_ifac_flag(&protected[..prot_len]));

        let mut recovered = [0u8; MAX_PROTECTED_LEN];
        let rec_len = ifac
            .unprotect(&protected[..prot_len], &mut recovered)
            .unwrap();
        assert_eq!(rec_len, pkt.len());
        assert_eq!(&recovered[..rec_len], &pkt[..]);
    }

    #[test]
    fn test_ifac_protect_linkrequest_packet() {
        // LINKREQUEST packet: flags byte = 0x03 (dest_type=SINGLE=0, packet_type=LINKREQUEST=3 → 0x03)
        // Actually: packet_type LINKREQUEST=2 → 0x02, but with dest_type=LINK=3<<2=0x0C → 0x0E
        // The user specified flags byte = 0x03, so use 0x03.
        let ifac = IfacKey::derive(Some("linkreq-net"), None).unwrap();
        let mut pkt = [0u8; 30];
        pkt[0] = 0x03; // LINKREQUEST flags
        pkt[1] = 0x00;
        for i in 2..18 {
            pkt[i] = 0xCC;
        }
        pkt[18] = 0x00;
        let payload = b"hello world";
        pkt[19..19 + payload.len()].copy_from_slice(payload);

        let mut protected = [0u8; MAX_PROTECTED_LEN];
        let prot_len = ifac.protect(&pkt, &mut protected).unwrap();
        assert_eq!(prot_len, pkt.len() + DEFAULT_IFAC_SIZE);
        assert!(IfacKey::has_ifac_flag(&protected[..prot_len]));

        let mut recovered = [0u8; MAX_PROTECTED_LEN];
        let rec_len = ifac
            .unprotect(&protected[..prot_len], &mut recovered)
            .unwrap();
        assert_eq!(rec_len, pkt.len());
        assert_eq!(&recovered[..rec_len], &pkt[..]);
    }

    #[test]
    fn test_ifac_header2_packet() {
        // HEADER_2 transport packet: flags byte = 0x18 (header_type=HEADER_2=0x40? No.)
        // Per CLAUDE.md: header_type bit 7:6 = 1 → 0x40, transport_type bit 4 = 1 → 0x10
        // flags = (1<<6)|(0<<5)|(1<<4)|(0<<2)|0 = 0x50
        // But user says flags byte = 0x18 for HEADER_2 + transport
        // 0x18 = 0b00011000 → bits 4:3 set. Per the flags layout:
        // bits 7:6=0 (HEADER_1), bit5=0, bit4=1 (TRANSPORT), bits 3:2=10 (PLAIN), bits 1:0=00 (DATA)
        // 0x18 = transport + PLAIN DATA. That's not HEADER_2.
        // Let's just use what the user said: flags byte = 0x18.
        // It's a valid byte for IFAC protection regardless.
        let ifac = IfacKey::derive(Some("header2-net"), None).unwrap();

        // HEADER_2 packets have transport_id (16 bytes) between hops and dest_hash
        // Total: flags(1) + hops(1) + transport_id(16) + dest_hash(16) + context(1) + payload
        let mut pkt = [0u8; 46];
        pkt[0] = 0x18; // HEADER_2 + transport flags
        pkt[1] = 0x00; // hops
                       // transport_id: bytes 2..18
        for i in 2..18 {
            pkt[i] = 0xDD;
        }
        // dest_hash: bytes 18..34
        for i in 18..34 {
            pkt[i] = 0xEE;
        }
        pkt[34] = 0x00; // context
        let payload = b"hello world";
        pkt[35..35 + payload.len()].copy_from_slice(payload);

        let mut protected = [0u8; MAX_PROTECTED_LEN];
        let prot_len = ifac.protect(&pkt, &mut protected).unwrap();
        assert_eq!(prot_len, pkt.len() + DEFAULT_IFAC_SIZE);
        assert!(IfacKey::has_ifac_flag(&protected[..prot_len]));

        let mut recovered = [0u8; MAX_PROTECTED_LEN];
        let rec_len = ifac
            .unprotect(&protected[..prot_len], &mut recovered)
            .unwrap();
        assert_eq!(rec_len, pkt.len());
        assert_eq!(&recovered[..rec_len], &pkt[..]);
    }

    #[test]
    fn test_ifac_max_tag_size_64() {
        // Round-trip with ifac_size=64 (maximum allowed)
        let ifac = IfacKey::derive_with_size(Some("max-tag-net"), None, 64).unwrap();
        assert_eq!(ifac.ifac_size(), 64);

        let raw = make_test_packet();
        let mut protected = [0u8; MAX_PROTECTED_LEN];
        let prot_len = ifac.protect(&raw, &mut protected).unwrap();
        assert_eq!(prot_len, raw.len() + 64);
        assert!(IfacKey::has_ifac_flag(&protected[..prot_len]));

        let mut recovered = [0u8; MAX_PROTECTED_LEN];
        let rec_len = ifac
            .unprotect(&protected[..prot_len], &mut recovered)
            .unwrap();
        assert_eq!(rec_len, raw.len());
        assert_eq!(&recovered[..rec_len], &raw[..]);
    }

    #[test]
    fn test_ifac_netkey_vs_netname_different_keys() {
        // derive(netname="x", None) vs derive(None, netkey="x"):
        // When only one input is provided, ifac_origin = SHA-256(input) in both
        // cases, so the same string produces the same key. However, providing
        // BOTH inputs (netname + netkey) concatenates two hashes, producing a
        // different origin than either alone. Verify that the combined derivation
        // differs from either single-input derivation.
        let from_netname = IfacKey::derive(Some("x"), None).unwrap();
        let from_netkey = IfacKey::derive(None, Some("x")).unwrap();
        let from_both = IfacKey::derive(Some("x"), Some("x")).unwrap();

        // Same single input → same origin → same key
        assert_eq!(
            from_netname.key, from_netkey.key,
            "single-input derivation with same string should match"
        );
        // Combined inputs → different origin → different key
        assert_ne!(
            from_netname.key, from_both.key,
            "netname-only vs netname+netkey should differ"
        );
        assert_ne!(
            from_netkey.key, from_both.key,
            "netkey-only vs netname+netkey should differ"
        );
    }
}
