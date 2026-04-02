//! Duplicate packet detection — ring buffer of recent hashes.
//!
//! Generic over [`StorageDeque`] so it works with both fixed-size
//! (`heapless::Deque`) and growable (`VecDeque`) backends.

use crate::storage::StorageDeque;

/// Rolling window for duplicate-packet detection.
///
/// Uses a ring buffer. O(N) lookup, but N is small on embedded.
/// When full the oldest entry is silently evicted.
pub struct DedupWindow<D: StorageDeque<[u8; 32]>> {
    buf: D,
}

impl<D: StorageDeque<[u8; 32]>> Default for DedupWindow<D> {
    fn default() -> Self {
        DedupWindow { buf: D::default() }
    }
}

impl<D: StorageDeque<[u8; 32]>> DedupWindow<D> {
    /// Check `hash` and insert it if not seen before.
    ///
    /// Returns `true` if the hash was already present (duplicate — drop it).
    /// Returns `false` if it was new (process it).
    pub fn check_and_insert(&mut self, hash: &[u8; 32]) -> bool {
        if self.buf.iter().any(|h| h == hash) {
            return true; // duplicate
        }
        if self.buf.is_full() {
            self.buf.pop_front();
        }
        let _ = self.buf.push_back(*hash);
        false
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.buf.clear();
    }

    /// Number of hashes currently tracked.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// True if the window is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestDedup = DedupWindow<heapless::Deque<[u8; 32], 16>>;
    type SmallDedup = DedupWindow<heapless::Deque<[u8; 32], 4>>;
    type ExactDedup = DedupWindow<heapless::Deque<[u8; 32], 8>>;

    #[test]
    fn new_hash_not_duplicate() {
        let mut w = TestDedup::default();
        assert!(!w.check_and_insert(&[1u8; 32]));
    }

    #[test]
    fn repeated_hash_is_duplicate() {
        let mut w = TestDedup::default();
        let h = [2u8; 32];
        w.check_and_insert(&h);
        assert!(w.check_and_insert(&h));
    }

    #[test]
    fn evicts_oldest_when_full() {
        let mut w = SmallDedup::default();
        for i in 0u8..4 {
            let mut h = [0u8; 32];
            h[0] = i;
            w.check_and_insert(&h);
        }
        // Insert a 5th — evicts first
        let mut h5 = [0u8; 32];
        h5[0] = 5;
        w.check_and_insert(&h5);
        // Original h0 should be gone now
        assert!(
            !w.check_and_insert(&[0u8; 32]),
            "evicted entry must not be a duplicate"
        );
    }

    #[test]
    fn different_hashes_not_duplicates() {
        let mut w = TestDedup::default();
        for i in 0u8..8 {
            let mut h = [0u8; 32];
            h[0] = i;
            assert!(!w.check_and_insert(&h));
        }
        assert_eq!(w.len(), 8);
    }

    #[test]
    fn test_window_at_exact_capacity() {
        let mut w = ExactDedup::default();

        // Insert exactly 8 unique hashes
        for i in 0u8..8 {
            let mut h = [0u8; 32];
            h[0] = i;
            assert!(!w.check_and_insert(&h), "hash {} should be new", i);
        }
        assert_eq!(w.len(), 8, "window should contain exactly 8 entries");

        // Verify all 8 are tracked as duplicates
        for i in 0u8..8 {
            let mut h = [0u8; 32];
            h[0] = i;
            assert!(w.check_and_insert(&h), "hash {} should be a duplicate", i);
        }
        assert_eq!(w.len(), 8);
    }
}
