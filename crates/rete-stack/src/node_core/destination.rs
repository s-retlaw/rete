//! Destination registration, lookup, and proof strategy management.

use rete_core::{Identity, TRUNCATED_HASH_LEN};

use crate::destination::{Destination, DestinationType, Direction};

use super::NodeCore;

impl<S: rete_transport::TransportStorage> NodeCore<S> {
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
    ) -> Result<[u8; TRUNCATED_HASH_LEN], rete_core::Error> {
        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name(app_name, aspects, &mut name_buf)?;
        let id_hash = self.identity.hash();
        let (dest_hash, name_hash) = rete_core::destination_hashes(expanded, Some(&id_hash));

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

        Ok(dest_hash)
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
    ) -> Result<[u8; TRUNCATED_HASH_LEN], rete_core::Error> {
        let id_hash = if dest_type == DestinationType::Plain {
            None
        } else {
            Some(self.identity.hash())
        };

        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name(app_name, aspects, &mut name_buf)?;
        let (dest_hash, name_hash) = rete_core::destination_hashes(expanded, id_hash.as_ref());

        let dest = Destination::from_hashes(
            dest_type, direction, app_name, aspects, dest_hash, name_hash,
        );

        // Only register as local if direction is In (we receive packets for it)
        if direction == Direction::In {
            self.transport.add_local_destination(dest_hash);
        }
        self.additional_dests.push(dest);

        Ok(dest_hash)
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
    pub fn register_peer(
        &mut self,
        peer: &Identity,
        app_name: &str,
        aspects: &[&str],
        now: u64,
    ) -> Result<(), rete_core::Error> {
        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name(app_name, aspects, &mut name_buf)?;
        let peer_id_hash = peer.hash();
        let peer_dest_hash = rete_core::destination_hash(expanded, Some(&peer_id_hash));
        self.transport
            .register_identity(peer_dest_hash, peer.public_key(), now);
        Ok(())
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
