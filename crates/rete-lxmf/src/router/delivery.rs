//! Opportunistic & direct message send/receive.

use rete_core::TRUNCATED_HASH_LEN;
use rete_stack::{NodeCore, OutboundPacket};

use crate::propagation::MessageStore;
use crate::LXMessage;

use super::LxmfRouter;

impl<S: MessageStore> LxmfRouter<S> {
    // -----------------------------------------------------------------------
    // Opportunistic send/receive
    // -----------------------------------------------------------------------

    /// Pack a message for opportunistic delivery.
    ///
    /// Strips the first 16 bytes (dest_hash) from the packed LXMF message,
    /// matching the Python LXMF protocol: the dest_hash is implicit in the
    /// Reticulum packet header.
    pub fn pack_opportunistic(msg: &LXMessage) -> Vec<u8> {
        let mut packed = msg.pack();
        if packed.len() > 16 {
            packed.drain(..16);
        }
        packed
    }

    /// Send an LXMF message opportunistically via encrypted DATA packet.
    ///
    /// Returns the outbound packet, or None if the recipient's identity
    /// is not cached (announce not yet received).
    pub fn send_opportunistic<R, const P: usize, const A: usize, const D: usize, const L: usize>(
        &self,
        core: &mut NodeCore<P, A, D, L>,
        msg: &LXMessage,
        rng: &mut R,
        now: u64,
    ) -> Option<OutboundPacket>
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        let payload = Self::pack_opportunistic(msg);
        let pkt_data = core
            .build_data_packet(&msg.destination_hash, &payload, rng, now)
            .ok()?;
        Some(OutboundPacket::broadcast(pkt_data))
    }

    /// Try to parse an LXMF message from a received DataReceived event.
    ///
    /// Checks that the dest_hash matches our delivery destination, prepends
    /// the dest_hash back to the payload, then unpacks.
    pub fn try_parse_lxmf(
        &self,
        dest_hash: &[u8; TRUNCATED_HASH_LEN],
        payload: &[u8],
    ) -> Option<LXMessage> {
        if *dest_hash != self.delivery_dest_hash {
            return None;
        }
        // Reconstruct full packed message: dest_hash[16] || payload
        let mut full = Vec::with_capacity(16 + payload.len());
        full.extend_from_slice(dest_hash);
        full.extend_from_slice(payload);
        LXMessage::unpack(&full, None).ok()
    }

    // -----------------------------------------------------------------------
    // Direct send/receive (over Link/Resource)
    // -----------------------------------------------------------------------

    /// Pack a message for direct delivery (full packed message).
    pub fn pack_direct(msg: &LXMessage) -> Vec<u8> {
        msg.pack()
    }

    /// Send an LXMF message directly via Resource over a Link.
    ///
    /// Returns the outbound resource advertisement packet.
    pub fn send_direct<R, const P: usize, const A: usize, const D: usize, const L: usize>(
        &self,
        core: &mut NodeCore<P, A, D, L>,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        msg: &LXMessage,
        rng: &mut R,
    ) -> Option<OutboundPacket>
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        let data = Self::pack_direct(msg);
        core.start_resource(link_id, &data, rng).ok()
    }

    /// Try to parse an LXMF message from Resource data.
    ///
    /// For direct delivery, the resource data is the full packed message.
    pub fn try_parse_lxmf_resource(data: &[u8]) -> Option<LXMessage> {
        LXMessage::unpack(data, None).ok()
    }
}
