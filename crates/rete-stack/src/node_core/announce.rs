//! Announce building, queuing, and flushing.

use alloc::vec::Vec;

use rand_core::{CryptoRng, RngCore};
use rete_core::{MTU, TRUNCATED_HASH_LEN};
use rete_transport::{PendingAnnounce, Transport};

use super::{NodeCore, OutboundPacket};

impl<const P: usize, const A: usize, const D: usize, const L: usize> NodeCore<P, A, D, L> {
    /// Build and return a raw announce packet for this node.
    pub fn build_announce<R: RngCore + CryptoRng>(
        &self,
        app_data: Option<&[u8]>,
        rng: &mut R,
        now: u64,
    ) -> Result<Vec<u8>, rete_core::Error> {
        let aspects_refs: Vec<&str> = self
            .primary_dest
            .aspects
            .iter()
            .map(|s| s.as_str())
            .collect();
        let mut buf = [0u8; MTU];
        let n = Transport::<P, A, D, L>::create_announce(
            &self.identity,
            &self.primary_dest.app_name,
            &aspects_refs,
            app_data,
            rng,
            now,
            &mut buf,
        )?;
        Ok(buf[..n].to_vec())
    }

    /// Queue a local announce into the transport's announce queue.
    ///
    /// The announce will be sent immediately on the next `flush_announces()` or
    /// `handle_tick()` call, then retransmitted once after ~10s (matching
    /// Python RNS's `PATHFINDER_R=1` behavior).
    pub fn queue_announce<R: RngCore + CryptoRng>(
        &mut self,
        app_data: Option<&[u8]>,
        rng: &mut R,
        now: u64,
    ) -> bool {
        let dest_hash = *self.primary_dest.hash();
        self.queue_announce_for(&dest_hash, app_data, rng, now)
    }

    /// Queue an announce for a specific registered destination.
    ///
    /// Looks up the destination by hash, builds an announce using the node's
    /// identity with that destination's app_name/aspects, and queues it.
    pub fn queue_announce_for<R: RngCore + CryptoRng>(
        &mut self,
        dest_hash: &[u8; TRUNCATED_HASH_LEN],
        app_data: Option<&[u8]>,
        rng: &mut R,
        now: u64,
    ) -> bool {
        // Find the destination by hash (borrow app_name/aspects without cloning)
        let dest = if *self.primary_dest.hash() == *dest_hash {
            Some(&self.primary_dest)
        } else {
            self.additional_dests
                .iter()
                .find(|d| d.dest_hash == *dest_hash)
        };
        let dest = match dest {
            Some(d) => d,
            None => return false,
        };

        let aspects_refs: Vec<&str> = dest.aspects.iter().map(|s| s.as_str()).collect();
        let mut buf = [0u8; MTU];
        let n = match Transport::<P, A, D, L>::create_announce(
            &self.identity,
            &dest.app_name,
            &aspects_refs,
            app_data,
            rng,
            now,
            &mut buf,
        ) {
            Ok(n) => n,
            Err(_) => return false,
        };
        self.transport.queue_announce(PendingAnnounce {
            dest_hash: *dest_hash,
            raw: buf[..n].to_vec(),
            tx_count: 0,
            retransmit_timeout: 0,
            local: true,
            local_rebroadcasts: 0,
            block_rebroadcasts: false,
            received_hops: 0,
        })
    }

    /// Drain pending announces from the transport queue, returning them as outbound packets.
    ///
    /// Call after `queue_announce()` to flush the announce immediately, or rely
    /// on `handle_tick()` which calls this internally.
    pub fn flush_announces<R: RngCore>(&mut self, now: u64, rng: &mut R) -> Vec<OutboundPacket> {
        self.transport
            .pending_outbound(now, rng)
            .into_iter()
            .map(OutboundPacket::broadcast)
            .collect()
    }

    /// Return cached announce packets from the path table as outbound broadcasts.
    ///
    /// Used to flush known announces to a newly connected interface so it
    /// immediately learns about destinations the node has already seen.
    pub fn cached_announces(&self) -> Vec<OutboundPacket> {
        self.transport
            .cached_announces()
            .into_iter()
            .map(OutboundPacket::broadcast)
            .collect()
    }

    /// Queue the initial local announce and return all packets to dispatch on startup.
    ///
    /// Returns `(announce_packets, cached_announce_packets)` where:
    /// - `announce_packets` — the freshly built announce (sent immediately + retransmit queued)
    /// - `cached_announce_packets` — announces for paths already in the path table, useful for
    ///   flushing to a newly-connected interface so it immediately learns known destinations
    ///
    /// Replaces the repeated queue_announce + flush_announces + cached_announces pattern
    /// at the start of every runtime's event loop.
    pub fn initial_announce<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        now: u64,
    ) -> (Vec<OutboundPacket>, Vec<OutboundPacket>) {
        self.queue_announce(None, rng, now);
        let announces = self.flush_announces(now, rng);
        let cached = self.cached_announces();
        (announces, cached)
    }
}
