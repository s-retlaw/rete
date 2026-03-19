//! Path table entries — learned routes to destinations.

extern crate alloc;

use alloc::vec::Vec;
use rete_core::TRUNCATED_HASH_LEN;

/// A learned path to a destination.
#[derive(Debug, Clone)]
pub struct Path {
    /// Identity hash of the next-hop repeater, or `None` for direct.
    pub via: Option<[u8; TRUNCATED_HASH_LEN]>,
    /// Monotonic timestamp (ticks or seconds) when this path was learned.
    pub learned_at: u64,
    /// Last observed SNR × 4 (as in the Python reference).
    pub last_snr: i8,
    /// Hop count to destination.
    pub hops: u8,
    /// Cached raw announce packet (for path request responses).
    pub announce_raw: Option<Vec<u8>>,
}

impl Path {
    /// Create a direct path (no intermediate repeater).
    pub fn direct(learned_at: u64) -> Self {
        Path {
            via: None,
            learned_at,
            last_snr: 0,
            hops: 1,
            announce_raw: None,
        }
    }

    /// Create a path via an intermediate repeater.
    pub fn via_repeater(repeater: [u8; TRUNCATED_HASH_LEN], hops: u8, learned_at: u64) -> Self {
        Path {
            via: Some(repeater),
            learned_at,
            last_snr: 0,
            hops,
            announce_raw: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_direct_creation() {
        let path = Path::direct(100);
        assert!(path.via.is_none());
        assert_eq!(path.hops, 1);
        assert_eq!(path.learned_at, 100);
        assert!(path.announce_raw.is_none());
    }

    #[test]
    fn test_path_via_repeater_creation() {
        let repeater = [0xAAu8; TRUNCATED_HASH_LEN];
        let path = Path::via_repeater(repeater, 3, 200);
        assert_eq!(path.via, Some(repeater));
        assert_eq!(path.hops, 3);
        assert_eq!(path.learned_at, 200);
        assert!(path.announce_raw.is_none());
    }

    #[test]
    fn test_path_announce_raw_storage() {
        let mut path = Path::direct(50);
        assert!(path.announce_raw.is_none());

        let raw_data = alloc::vec![0x01, 0x02, 0x03];
        path.announce_raw = Some(raw_data.clone());
        assert_eq!(path.announce_raw.as_ref().unwrap(), &raw_data);
    }
}
