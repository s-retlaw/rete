//! Destination registration, lookup, and proof strategy management.

use rete_core::{Identity, TRUNCATED_HASH_LEN};

use crate::destination::{Destination, DestinationType, Direction};
use crate::node_core::compute_dest_hashes;

use super::NodeCore;

impl<const P: usize, const A: usize, const D: usize, const L: usize> NodeCore<P, A, D, L> {
    /// Register an additional destination on this node.
    ///
    /// Computes the destination hash from the node's identity + given app_name/aspects,
    /// registers it with transport as a local destination, and stores the Destination
    /// metadata for decryption and proof generation.
    ///
    /// Returns the 16-byte destination hash.
    pub fn register_destination(
        &mut self,
        app_name: &str,
        aspects: &[&str],
    ) -> [u8; TRUNCATED_HASH_LEN] {
        let (dest_hash, name_hash) = compute_dest_hashes(&self.identity, app_name, aspects);

        let dest = Destination::from_hashes(
            DestinationType::Single,
            Direction::In,
            app_name,
            aspects,
            dest_hash,
            name_hash,
        );

        self.transport.add_local_destination(dest_hash);
        self.additional_dests.push(dest);

        dest_hash
    }

    /// Register an additional destination with specified type and direction.
    ///
    /// Supports GROUP, PLAIN, and OUT destinations in addition to the default
    /// Single/In. For PLAIN destinations, identity is not used in hashing.
    /// For OUT destinations, transport does NOT register them as local
    /// (they are for sending, not receiving).
    pub fn register_destination_typed(
        &mut self,
        app_name: &str,
        aspects: &[&str],
        dest_type: DestinationType,
        direction: Direction,
    ) -> [u8; TRUNCATED_HASH_LEN] {
        let id_hash = if dest_type == DestinationType::Plain {
            None
        } else {
            Some(self.identity.hash())
        };

        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name(app_name, aspects, &mut name_buf)
            .expect("app_name + aspects too long");
        let dest_hash = rete_core::destination_hash(expanded, id_hash.as_ref());

        let name_hash_full = <sha2::Sha256 as sha2::Digest>::digest(expanded.as_bytes());
        let mut name_hash = [0u8; rete_core::NAME_HASH_LEN];
        name_hash.copy_from_slice(&name_hash_full[..rete_core::NAME_HASH_LEN]);

        let dest = Destination::from_hashes(
            dest_type, direction, app_name, aspects, dest_hash, name_hash,
        );

        // Only register as local if direction is In (we receive packets for it)
        if direction == Direction::In {
            self.transport.add_local_destination(dest_hash);
        }
        self.additional_dests.push(dest);

        dest_hash
    }

    /// Look up a destination by hash (checks primary first, then additional).
    pub fn get_destination(&self, dest_hash: &[u8; TRUNCATED_HASH_LEN]) -> Option<&Destination> {
        if *self.primary_dest.hash() == *dest_hash {
            return Some(&self.primary_dest);
        }
        self.additional_dests
            .iter()
            .find(|d| d.dest_hash == *dest_hash)
    }

    /// Look up a destination mutably by hash.
    pub fn get_destination_mut(
        &mut self,
        dest_hash: &[u8; TRUNCATED_HASH_LEN],
    ) -> Option<&mut Destination> {
        if *self.primary_dest.hash() == *dest_hash {
            return Some(&mut self.primary_dest);
        }
        self.additional_dests
            .iter_mut()
            .find(|d| d.dest_hash == *dest_hash)
    }

    /// Pre-register a peer's identity for sending DATA without waiting for an announce.
    pub fn register_peer(&mut self, peer: &Identity, app_name: &str, aspects: &[&str], now: u64) {
        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name(app_name, aspects, &mut name_buf)
            .expect("app_name + aspects must fit in 128 bytes");
        let peer_id_hash = peer.hash();
        let peer_dest_hash = rete_core::destination_hash(expanded, Some(&peer_id_hash));
        self.transport
            .register_identity(peer_dest_hash, peer.public_key(), now);
    }

    /// Look up a request handler scoped to a specific destination.
    pub(super) fn find_request_handler(
        &self,
        dest_hash: &[u8; TRUNCATED_HASH_LEN],
        path_hash: &[u8; TRUNCATED_HASH_LEN],
    ) -> Option<&super::RequestHandler> {
        let dest = self.get_destination(dest_hash)?;
        dest.lookup_request_handler(path_hash)
    }
}
