//! Packet receipt tracking — validates delivery proofs for sent packets.
//!
//! When the node sends a DATA packet, it registers a [`PacketReceipt`] keyed
//! by the truncated packet hash. When a PROOF arrives, the receipt table
//! validates the signature and fires a callback.
//!
//! Generic over [`StorageMap`] so it works with both fixed-size
//! (`FnvIndexMap`) and growable (`HashMap`) backends.

extern crate alloc;

use alloc::vec::Vec;
use crate::storage::StorageMap;
use rete_core::{Identity, TRUNCATED_HASH_LEN};

/// Status of a packet receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptStatus {
    /// Waiting for proof.
    Sent,
    /// Proof received and validated.
    Delivered,
    /// Timed out without proof.
    Failed,
}

/// A receipt for a sent packet, awaiting delivery proof.
#[derive(Debug, Clone)]
pub struct PacketReceipt {
    /// Full 32-byte packet hash. Truncated hash = `packet_hash[..16]`.
    pub packet_hash: [u8; 32],
    /// Destination's public key (64 bytes) — used to verify the proof signature.
    pub dest_pub_key: [u8; 64],
    /// Current receipt status.
    pub status: ReceiptStatus,
    /// Monotonic timestamp when the packet was sent.
    pub sent_at: u64,
    /// Timeout in seconds (0 = no timeout).
    pub timeout: u64,
}

/// Table of outstanding packet receipts.
///
/// Generic over `M` — the map backend (fixed-size or growable).
pub struct ReceiptTable<M: StorageMap<[u8; TRUNCATED_HASH_LEN], PacketReceipt>> {
    entries: M,
}

impl<M: StorageMap<[u8; TRUNCATED_HASH_LEN], PacketReceipt>> Default for ReceiptTable<M> {
    fn default() -> Self {
        ReceiptTable {
            entries: M::default(),
        }
    }
}

impl<M: StorageMap<[u8; TRUNCATED_HASH_LEN], PacketReceipt>> ReceiptTable<M> {
    /// Register a receipt for a sent packet.
    ///
    /// Returns `false` if the table is full.
    pub fn register(
        &mut self,
        packet_hash: [u8; 32],
        dest_pub_key: [u8; 64],
        now: u64,
        timeout: u64,
    ) -> bool {
        let mut truncated = [0u8; TRUNCATED_HASH_LEN];
        truncated.copy_from_slice(&packet_hash[..TRUNCATED_HASH_LEN]);
        let receipt = PacketReceipt {
            packet_hash,
            dest_pub_key,
            status: ReceiptStatus::Sent,
            sent_at: now,
            timeout,
        };
        self.entries.insert(truncated, receipt).is_ok()
    }

    /// Look up a receipt by truncated hash.
    pub fn get(&self, truncated_hash: &[u8; TRUNCATED_HASH_LEN]) -> Option<&PacketReceipt> {
        self.entries.get(truncated_hash)
    }

    /// Validate a proof against a registered receipt.
    ///
    /// # Proof formats
    /// - **Explicit proof** (96 bytes): `packet_hash[32] || signature[64]`
    /// - **Implicit proof** (64 bytes): `signature[64]` (packet_hash recalled from receipt)
    ///
    /// Returns the full packet hash on success, or `None` if validation fails.
    pub fn validate_proof(
        &mut self,
        truncated_hash: &[u8; TRUNCATED_HASH_LEN],
        proof_payload: &[u8],
    ) -> Option<[u8; 32]> {
        let receipt = self.entries.get(truncated_hash)?;
        if receipt.status != ReceiptStatus::Sent {
            return None;
        }

        let (packet_hash, signature) = if proof_payload.len() >= 96 {
            // Explicit proof: packet_hash[32] || signature[64]
            let mut ph = [0u8; 32];
            ph.copy_from_slice(&proof_payload[..32]);
            // Verify the packet hash matches
            if ph != receipt.packet_hash {
                return None;
            }
            (ph, &proof_payload[32..96])
        } else if proof_payload.len() >= 64 {
            // Implicit proof: signature[64] only
            (receipt.packet_hash, &proof_payload[..64])
        } else {
            return None;
        };

        // Verify signature using the destination's public key
        let identity = Identity::from_public_key(&receipt.dest_pub_key).ok()?;
        identity.verify(&packet_hash, signature).ok()?;

        // Mark as delivered
        if let Some(r) = self.entries.get_mut(truncated_hash) {
            r.status = ReceiptStatus::Delivered;
        }

        Some(packet_hash)
    }

    /// Expire receipts that have timed out.
    pub fn tick(&mut self, now: u64) {
        let mut to_expire: Vec<[u8; TRUNCATED_HASH_LEN]> = Vec::new();

        for (key, receipt) in self.entries.iter() {
            if receipt.status == ReceiptStatus::Sent
                && receipt.timeout > 0
                && now.saturating_sub(receipt.sent_at) > receipt.timeout
            {
                to_expire.push(*key);
            }
        }

        for key in &to_expire {
            if let Some(r) = self.entries.get_mut(key) {
                r.status = ReceiptStatus::Failed;
            }
        }
    }

    /// Number of tracked receipts.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove a receipt (after delivery or failure).
    pub fn remove(&mut self, truncated_hash: &[u8; TRUNCATED_HASH_LEN]) {
        self.entries.remove(truncated_hash);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use heapless::FnvIndexMap;

    type TestTable = ReceiptTable<FnvIndexMap<[u8; TRUNCATED_HASH_LEN], PacketReceipt, 16>>;
    type SmallTable = ReceiptTable<FnvIndexMap<[u8; TRUNCATED_HASH_LEN], PacketReceipt, 4>>;

    fn make_test_identity() -> Identity {
        Identity::from_seed(b"receipt-test-identity").unwrap()
    }

    #[test]
    fn receipt_register_and_lookup() {
        let mut table = TestTable::default();
        let identity = make_test_identity();
        let packet_hash = [0xABu8; 32];

        assert!(table.register(packet_hash, identity.public_key(), 100, 30));
        assert_eq!(table.len(), 1);

        let trunc: [u8; TRUNCATED_HASH_LEN] = packet_hash[..TRUNCATED_HASH_LEN].try_into().unwrap();
        let receipt = table.get(&trunc).unwrap();
        assert_eq!(receipt.packet_hash, packet_hash);
        assert_eq!(receipt.status, ReceiptStatus::Sent);
    }

    #[test]
    fn receipt_validate_explicit_proof() {
        let mut table = TestTable::default();
        let identity = make_test_identity();
        let packet_hash = [0x42u8; 32];

        table.register(packet_hash, identity.public_key(), 100, 30);
        let trunc: [u8; TRUNCATED_HASH_LEN] = packet_hash[..TRUNCATED_HASH_LEN].try_into().unwrap();

        // Build explicit proof: packet_hash[32] || signature[64]
        let sig = identity.sign(&packet_hash).unwrap();
        let mut proof = [0u8; 96];
        proof[..32].copy_from_slice(&packet_hash);
        proof[32..].copy_from_slice(&sig);

        let result = table.validate_proof(&trunc, &proof);
        assert_eq!(result, Some(packet_hash));
        assert_eq!(table.get(&trunc).unwrap().status, ReceiptStatus::Delivered);
    }

    #[test]
    fn receipt_validate_implicit_proof() {
        let mut table = TestTable::default();
        let identity = make_test_identity();
        let packet_hash = [0x42u8; 32];

        table.register(packet_hash, identity.public_key(), 100, 30);
        let trunc: [u8; TRUNCATED_HASH_LEN] = packet_hash[..TRUNCATED_HASH_LEN].try_into().unwrap();

        // Build implicit proof: signature[64] only
        let sig = identity.sign(&packet_hash).unwrap();

        let result = table.validate_proof(&trunc, &sig);
        assert_eq!(result, Some(packet_hash));
    }

    #[test]
    fn receipt_bad_signature_rejected() {
        let mut table = TestTable::default();
        let identity = make_test_identity();
        let packet_hash = [0x42u8; 32];

        table.register(packet_hash, identity.public_key(), 100, 30);
        let trunc: [u8; TRUNCATED_HASH_LEN] = packet_hash[..TRUNCATED_HASH_LEN].try_into().unwrap();

        // Corrupt signature
        let mut sig = identity.sign(&packet_hash).unwrap();
        sig[0] ^= 0xFF;

        let result = table.validate_proof(&trunc, &sig);
        assert_eq!(result, None);
        // Status should still be Sent
        assert_eq!(table.get(&trunc).unwrap().status, ReceiptStatus::Sent);
    }

    #[test]
    fn receipt_timeout_expiry() {
        let mut table = TestTable::default();
        let identity = make_test_identity();
        let packet_hash = [0x42u8; 32];

        table.register(packet_hash, identity.public_key(), 100, 30);
        let trunc: [u8; TRUNCATED_HASH_LEN] = packet_hash[..TRUNCATED_HASH_LEN].try_into().unwrap();

        // Before timeout
        table.tick(129);
        assert_eq!(table.get(&trunc).unwrap().status, ReceiptStatus::Sent);

        // After timeout
        table.tick(131);
        assert_eq!(table.get(&trunc).unwrap().status, ReceiptStatus::Failed);
    }

    #[test]
    fn test_receipt_table_full() {
        let mut table = SmallTable::default();
        let identity = make_test_identity();

        for i in 0u8..4 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            assert!(
                table.register(hash, identity.public_key(), 100, 30),
                "slot {} should succeed",
                i
            );
        }
        assert_eq!(table.len(), 4);

        // 5th registration should fail (returns false, no panic)
        let mut overflow_hash = [0u8; 32];
        overflow_hash[0] = 0xFF;
        assert!(
            !table.register(overflow_hash, identity.public_key(), 100, 30),
            "table full — register should return false"
        );
        assert_eq!(table.len(), 4);
    }

    #[test]
    fn test_validate_proof_already_delivered() {
        let mut table = TestTable::default();
        let identity = make_test_identity();
        let packet_hash = [0x42u8; 32];

        table.register(packet_hash, identity.public_key(), 100, 30);
        let trunc: [u8; TRUNCATED_HASH_LEN] = packet_hash[..TRUNCATED_HASH_LEN].try_into().unwrap();

        // First proof — should succeed
        let sig = identity.sign(&packet_hash).unwrap();
        let result = table.validate_proof(&trunc, &sig);
        assert_eq!(result, Some(packet_hash));
        assert_eq!(table.get(&trunc).unwrap().status, ReceiptStatus::Delivered);

        // Second proof on the same receipt — should return None
        let result2 = table.validate_proof(&trunc, &sig);
        assert_eq!(
            result2, None,
            "already-delivered receipt should reject proof"
        );
    }
}
