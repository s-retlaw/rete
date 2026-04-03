//! Delivery proofs and receipts.

use rete_core::{DestType, Identity, LinkId, PacketBuilder, PacketType, TRUNCATED_HASH_LEN};

use super::Transport;

impl<S: crate::storage::TransportStorage> Transport<S> {
    /// Register a receipt for a sent packet.
    pub fn register_receipt(
        &mut self,
        packet_hash: [u8; 32],
        dest_pub_key: [u8; 64],
        now: u64,
        timeout: u64,
    ) -> bool {
        self.receipts
            .register(packet_hash, dest_pub_key, now, timeout)
    }

    /// Number of tracked receipts.
    pub fn receipt_count(&self) -> usize {
        self.receipts.len()
    }

    // -----------------------------------------------------------------------
    // Proof packet construction
    // -----------------------------------------------------------------------

    /// Build a PROOF packet with the given dest_type and destination_hash.
    ///
    /// Payload: `packet_hash[32] || Ed25519_signature[64]`.
    fn build_proof_inner(
        identity: &Identity,
        packet_hash: &[u8; 32],
        dest_type: DestType,
        destination_hash: &[u8; TRUNCATED_HASH_LEN],  // truncated packet hash, NOT DestHash
    ) -> Option<alloc::vec::Vec<u8>> {
        let signature = identity.sign(packet_hash).ok()?;
        let mut payload = [0u8; 96];
        payload[..32].copy_from_slice(packet_hash);
        payload[32..96].copy_from_slice(&signature);

        let mut buf = [0u8; rete_core::MTU];
        let n = PacketBuilder::new(&mut buf)
            .packet_type(PacketType::Proof)
            .dest_type(dest_type)
            .destination_hash(destination_hash)
            .context(0x00)
            .payload(&payload)
            .build()
            .ok()?;
        Some(buf[..n].to_vec())
    }

    /// Build a PROOF packet for a received data packet (non-link proofs).
    ///
    /// Uses `dest_type=Single` and `destination_hash=packet_hash[0:16]`.
    /// For link-related proofs (channel, link data), use [`build_link_proof_packet`] instead.
    pub fn build_proof_packet(
        identity: &Identity,
        packet_hash: &[u8; 32],
    ) -> Option<alloc::vec::Vec<u8>> {
        let trunc: [u8; TRUNCATED_HASH_LEN] = packet_hash[..TRUNCATED_HASH_LEN].try_into().ok()?;
        Self::build_proof_inner(identity, packet_hash, DestType::Single, &trunc)
    }

    /// Build a PROOF packet for a link-related packet (channel messages, link data).
    ///
    /// Uses `dest_type=Link` and `destination_hash=link_id` so that transport
    /// relays (rnsd) can route the proof back through their link table.
    pub fn build_link_proof_packet(
        identity: &Identity,
        packet_hash: &[u8; 32],
        link_id: &LinkId,
    ) -> Option<alloc::vec::Vec<u8>> {
        let link_id_bytes: [u8; TRUNCATED_HASH_LEN] = (*link_id).into();
        Self::build_proof_inner(identity, packet_hash, DestType::Link, &link_id_bytes)
    }
}
