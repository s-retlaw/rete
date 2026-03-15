//! Duplicate packet detection — fixed-size ring buffer of recent hashes.

/// Rolling window for duplicate-packet detection.
///
/// Uses a fixed-size ring buffer. O(N) lookup, but N is small on embedded.
/// When full the oldest entry is silently evicted.
pub struct DedupWindow<const N: usize> {
    buf: heapless::Deque<[u8; 32], N>,
}

impl<const N: usize> DedupWindow<N> {
    /// Create an empty window.
    pub const fn new() -> Self {
        DedupWindow { buf: heapless::Deque::new() }
    }

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
        while self.buf.pop_front().is_some() {}
    }

    /// Number of hashes currently tracked.
    pub fn len(&self) -> usize { self.buf.len() }

    /// True if the window is empty.
    pub fn is_empty(&self) -> bool { self.buf.is_empty() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_hash_not_duplicate() {
        let mut w: DedupWindow<16> = DedupWindow::new();
        assert!(!w.check_and_insert(&[1u8; 32]));
    }

    #[test]
    fn repeated_hash_is_duplicate() {
        let mut w: DedupWindow<16> = DedupWindow::new();
        let h = [2u8; 32];
        w.check_and_insert(&h);
        assert!(w.check_and_insert(&h));
    }

    #[test]
    fn evicts_oldest_when_full() {
        let mut w: DedupWindow<4> = DedupWindow::new();
        for i in 0u8..4 { let mut h=[0u8;32]; h[0]=i; w.check_and_insert(&h); }
        // Insert a 5th — evicts first
        let mut h5 = [0u8; 32]; h5[0] = 5;
        w.check_and_insert(&h5);
        // Original h0 should be gone now
        assert!(!w.check_and_insert(&[0u8; 32]), "evicted entry must not be a duplicate");
    }

    #[test]
    fn different_hashes_not_duplicates() {
        let mut w: DedupWindow<16> = DedupWindow::new();
        for i in 0u8..8 {
            let mut h = [0u8; 32]; h[0] = i;
            assert!(!w.check_and_insert(&h));
        }
        assert_eq!(w.len(), 8);
    }
}
