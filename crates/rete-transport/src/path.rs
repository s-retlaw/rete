//! Path table entries — learned routes to destinations.

use rete_core::TRUNCATED_HASH_LEN;

/// A learned path to a destination.
#[derive(Debug, Clone)]
pub struct Path {
    /// Identity hash of the next-hop repeater, or `None` for direct.
    pub via:        Option<[u8; TRUNCATED_HASH_LEN]>,
    /// Monotonic timestamp (ticks or seconds) when this path was learned.
    pub learned_at: u64,
    /// Last observed SNR × 4 (as in the Python reference).
    pub last_snr:   i8,
    /// Hop count to destination.
    pub hops:       u8,
}

impl Path {
    /// Create a direct path (no intermediate repeater).
    pub fn direct(learned_at: u64) -> Self {
        Path { via: None, learned_at, last_snr: 0, hops: 1 }
    }

    /// Create a path via an intermediate repeater.
    pub fn via_repeater(
        repeater: [u8; TRUNCATED_HASH_LEN],
        hops:     u8,
        learned_at: u64,
    ) -> Self {
        Path { via: Some(repeater), learned_at, last_snr: 0, hops }
    }
}
