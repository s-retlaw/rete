//! LXMF Stamp system — Proof-of-Work for rate limiting.
//!
//! Stamps are 2-byte values that prove computational effort was expended.
//! The stamper generates a workblock from message material using HKDF-SHA256,
//! then brute-forces a 2-byte stamp whose hash against the workblock has
//! enough leading zero bits.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// Stamp size in bytes (Python: HASHLENGTH // 8 = 2).
pub const STAMP_SIZE: usize = 2;

/// Workblock expand rounds for regular messages.
pub const WORKBLOCK_EXPAND_ROUNDS: usize = 3000;

/// Workblock expand rounds for propagation node stamps.
pub const WORKBLOCK_EXPAND_ROUNDS_PN: usize = 1000;

/// Workblock expand rounds for peering key generation.
pub const WORKBLOCK_EXPAND_ROUNDS_PEERING: usize = 25;

/// Ticket length in bytes.
pub const TICKET_LENGTH: usize = 2;

/// Ticket expiry time in seconds (21 days).
pub const TICKET_EXPIRY: u64 = 21 * 24 * 60 * 60;

/// Ticket grace period in seconds (5 days).
pub const TICKET_GRACE: u64 = 5 * 24 * 60 * 60;

/// Ticket renewal threshold in seconds (14 days).
pub const TICKET_RENEW: u64 = 14 * 24 * 60 * 60;

/// Special stamp value indicating ticket-based delivery (256).
pub const COST_TICKET: u16 = 0x100;

/// Generate a workblock from material using HKDF-SHA256.
///
/// The workblock is `expand_rounds * 256` bytes. For regular messages
/// with 3000 rounds, this is ~768KB.
pub fn stamp_workblock(material: &[u8], expand_rounds: usize) -> Vec<u8> {
    let mut workblock = Vec::with_capacity(expand_rounds * 256);

    for n in 0..expand_rounds {
        // Salt = SHA-256(material || msgpack(n))
        // msgpack encoding of small integers: 0x00..0x7f for 0..127, 0xcc+u8 for 128..255, etc.
        let mut salt_hasher = Sha256::new();
        salt_hasher.update(material);
        // Simple msgpack encoding of usize as integer
        let n_packed = msgpack_uint(n);
        salt_hasher.update(&n_packed);
        let salt: [u8; 32] = salt_hasher.finalize().into();

        // HKDF-SHA256(ikm=material, salt=salt, length=256)
        let hk = Hkdf::<Sha256>::new(Some(&salt), material);
        let mut block = [0u8; 256];
        // hkdf expand can produce up to 255*32 = 8160 bytes, 256 is fine
        hk.expand(b"", &mut block).unwrap();
        workblock.extend_from_slice(&block);
    }

    workblock
}

/// Validate a stamp against a workblock and target cost.
///
/// Returns `true` if SHA-256(workblock || stamp) has at least `target_cost`
/// leading zero bits.
pub fn stamp_valid(stamp: &[u8], target_cost: u8, workblock: &[u8]) -> bool {
    if target_cost == 0 {
        return true;
    }
    stamp_value(workblock, stamp) >= target_cost as u16
}

/// Compute the stamp value (leading zero bits in SHA-256(workblock || stamp)).
pub fn stamp_value(workblock: &[u8], stamp: &[u8]) -> u16 {
    let mut hasher = Sha256::new();
    hasher.update(workblock);
    hasher.update(stamp);
    let hash: [u8; 32] = hasher.finalize().into();
    leading_zero_bits(&hash)
}

/// Generate a stamp that satisfies the target cost.
///
/// Brute-forces through all 2-byte values until one with enough leading
/// zero bits is found. Returns the stamp bytes and its value.
///
/// **Warning:** This can be CPU-intensive for high target costs.
pub fn generate_stamp(material: &[u8], target_cost: u8) -> Option<([u8; STAMP_SIZE], u16)> {
    let workblock = stamp_workblock(material, WORKBLOCK_EXPAND_ROUNDS);
    generate_stamp_with_workblock(&workblock, target_cost)
}

/// Generate a stamp from a pre-computed workblock.
pub fn generate_stamp_with_workblock(
    workblock: &[u8],
    target_cost: u8,
) -> Option<([u8; STAMP_SIZE], u16)> {
    // Try all 65536 possible 2-byte stamps
    for v in 0u16..=u16::MAX {
        let stamp = v.to_be_bytes();
        let val = stamp_value(workblock, &stamp);
        if val >= target_cost as u16 {
            return Some((stamp, val));
        }
    }
    None
}

/// Validate a stamp using a ticket (ticket-based bypass).
///
/// Stamp is valid if it equals `truncated_hash(ticket || message_id)`.
pub fn validate_ticket_stamp(stamp: &[u8], message_id: &[u8], tickets: &[Vec<u8>]) -> bool {
    for ticket in tickets {
        let expected = ticket_stamp(ticket, message_id);
        if stamp.len() >= STAMP_SIZE && stamp[..STAMP_SIZE] == expected {
            return true;
        }
    }
    false
}

/// Generate a ticket-based stamp.
///
/// Returns `truncated_hash(ticket || message_id)[..TICKET_LENGTH]`.
pub fn ticket_stamp(ticket: &[u8], message_id: &[u8]) -> [u8; STAMP_SIZE] {
    let mut data = Vec::with_capacity(ticket.len() + message_id.len());
    data.extend_from_slice(ticket);
    data.extend_from_slice(message_id);
    let hash = Sha256::digest(&data);
    let mut stamp = [0u8; STAMP_SIZE];
    stamp.copy_from_slice(&hash[..STAMP_SIZE]);
    stamp
}

/// Count leading zero bits in a byte slice.
fn leading_zero_bits(data: &[u8]) -> u16 {
    let mut count = 0u16;
    for &byte in data {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros() as u16;
            break;
        }
    }
    count
}

/// Simple msgpack encoding for unsigned integers.
fn msgpack_uint(n: usize) -> Vec<u8> {
    if n <= 127 {
        vec![n as u8]
    } else if n <= 255 {
        vec![0xcc, n as u8]
    } else if n <= 65535 {
        let b = (n as u16).to_be_bytes();
        vec![0xcd, b[0], b[1]]
    } else if n <= 0xFFFF_FFFF {
        let b = (n as u32).to_be_bytes();
        vec![0xce, b[0], b[1], b[2], b[3]]
    } else {
        let b = (n as u64).to_be_bytes();
        vec![0xcf, b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leading_zero_bits() {
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x80]), 16);
        assert_eq!(leading_zero_bits(&[0x00, 0x01]), 15);
        assert_eq!(leading_zero_bits(&[0x80]), 0);
        assert_eq!(leading_zero_bits(&[0x40]), 1);
        assert_eq!(leading_zero_bits(&[0x00]), 8);
    }

    #[test]
    fn test_msgpack_uint() {
        assert_eq!(msgpack_uint(0), vec![0x00]);
        assert_eq!(msgpack_uint(127), vec![0x7f]);
        assert_eq!(msgpack_uint(128), vec![0xcc, 0x80]);
        assert_eq!(msgpack_uint(256), vec![0xcd, 0x01, 0x00]);
    }

    #[test]
    fn test_stamp_workblock_deterministic() {
        let wb1 = stamp_workblock(b"test-material", 2);
        let wb2 = stamp_workblock(b"test-material", 2);
        assert_eq!(wb1, wb2);
        assert_eq!(wb1.len(), 2 * 256);
    }

    #[test]
    fn test_stamp_validation() {
        // Generate a stamp with low cost (should be fast)
        let material = b"test-message-id-12345678901234";
        let wb = stamp_workblock(material, WORKBLOCK_EXPAND_ROUNDS_PEERING);
        if let Some((stamp, val)) = generate_stamp_with_workblock(&wb, 1) {
            assert!(val >= 1);
            assert!(stamp_valid(&stamp, 1, &wb));
        }
    }

    #[test]
    fn test_ticket_stamp_roundtrip() {
        let ticket = b"test-ticket-bytes!";
        let message_id = b"test-message-id-32bytes-long!!!";
        let stamp = ticket_stamp(ticket, message_id);
        assert_eq!(stamp.len(), STAMP_SIZE);

        let tickets = vec![ticket.to_vec()];
        assert!(validate_ticket_stamp(&stamp, message_id, &tickets));
        assert!(!validate_ticket_stamp(
            &stamp,
            b"wrong-message-id",
            &tickets
        ));
    }
}
