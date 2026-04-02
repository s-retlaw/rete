//! Link lifecycle, handshake, keepalives, close.

use crate::link::{compute_link_id, Link};
use crate::storage::StorageMap;
use rand_core::{CryptoRng, RngCore};
use rete_core::{
    DestType, Identity, PacketBuilder, PacketType, CONTEXT_CHANNEL, CONTEXT_KEEPALIVE,
    CONTEXT_LINKCLOSE, CONTEXT_LRPROOF, CONTEXT_LRRTT, CONTEXT_REQUEST, CONTEXT_RESOURCE,
    CONTEXT_RESOURCE_ADV, CONTEXT_RESOURCE_HMU, CONTEXT_RESOURCE_ICL, CONTEXT_RESOURCE_PRF,
    CONTEXT_RESOURCE_RCL, CONTEXT_RESOURCE_REQ, CONTEXT_RESPONSE, Packet, TRUNCATED_HASH_LEN,
};

use super::{ChannelReceipt, IngestResult, SendError, Transport};

impl<S: crate::storage::TransportStorage> Transport<S> {
    /// Look up an active link by link_id.
    pub fn get_link(&self, link_id: &[u8; TRUNCATED_HASH_LEN]) -> Option<&Link> {
        self.links.get(link_id)
    }

    /// Look up an active link mutably by link_id.
    pub fn get_link_mut(&mut self, link_id: &[u8; TRUNCATED_HASH_LEN]) -> Option<&mut Link> {
        self.links.get_mut(link_id)
    }

    /// Number of active links.
    pub fn link_count(&self) -> usize {
        self.links.len()
    }

    /// Number of tracked channel receipts (pending channel ACKs).
    pub fn channel_receipt_count(&self) -> usize {
        self.channel_receipts.len()
    }

    // -----------------------------------------------------------------------
    // Link management
    // -----------------------------------------------------------------------

    /// Initiate a link to a destination.
    ///
    /// Returns the raw LINKREQUEST packet and the link_id.
    pub fn initiate_link<R: RngCore + CryptoRng>(
        &mut self,
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        identity: &Identity,
        rng: &mut R,
        now: u64,
    ) -> Result<(alloc::vec::Vec<u8>, [u8; TRUNCATED_HASH_LEN]), SendError> {
        let (mut link, request_payload) =
            Link::new_initiator(dest_hash, identity.ed25519_pub(), rng, now);

        // Build LINKREQUEST packet.
        // dest_type must be Single (matching the target destination type), not Link.
        // Python RNS uses `self.destination.type` for LINKREQUEST flags (Packet.py:172),
        // and the receiving node checks `destination.type == packet.destination_type`.
        //
        // If we have a transport path (via relay), build HEADER_2 so the relay
        // creates a link_table entry and can route the LRPROOF back.
        let via = self.paths.get(&dest_hash).and_then(|p| p.via);
        self.touch_path(&dest_hash, now);
        let mut pkt_buf = [0u8; rete_core::MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::LinkRequest)
            .dest_type(DestType::Single)
            .destination_hash(&dest_hash)
            .context(0x00)
            .payload(&request_payload)
            .via(via.as_ref())
            .build()
            .map_err(SendError::PacketBuild)?;

        // Compute link_id from the HEADER_1 form of the packet (strip transport
        // header if present). Python computes link_id from the hashable part which
        // masks header_type/transport bits, but uses get_hashable_part() which for
        // HEADER_2 starts at raw[18:] (skipping transport_id). Our compute_link_id
        // handles both HEADER_1 and HEADER_2.
        let link_id = compute_link_id(&pkt_buf[..pkt_len]).map_err(SendError::PacketBuild)?;
        link.set_link_id(link_id);

        let _ = self.links.insert(link_id, link);
        Ok((pkt_buf[..pkt_len].to_vec(), link_id))
    }

    /// Build an encrypted DATA packet for a link.
    pub fn build_link_data_packet<R: RngCore + CryptoRng>(
        &self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        plaintext: &[u8],
        context: u8,
        rng: &mut R,
    ) -> Result<alloc::vec::Vec<u8>, SendError> {
        let link = self.links.get(link_id).ok_or(SendError::LinkNotFound)?;
        if !link.is_active() {
            return Err(SendError::LinkNotActive);
        }
        Self::build_link_packet(link, link_id, plaintext, context, rng)
    }

    /// Build an LRRTT measurement packet for a link (initiator sends after proof).
    pub fn build_lrrtt_packet<R: RngCore + CryptoRng>(
        &self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        rtt_bytes: &[u8],
        rng: &mut R,
    ) -> Result<alloc::vec::Vec<u8>, SendError> {
        let link = self.links.get(link_id).ok_or(SendError::LinkNotFound)?;
        Self::build_link_packet(link, link_id, rtt_bytes, CONTEXT_LRRTT, rng)
    }

    /// Build a keepalive request/response packet for a link.
    ///
    /// Allows sending on both Active and Stale links — a keepalive response
    /// to a Stale link can revive it when the peer receives it and responds.
    pub fn build_keepalive_packet<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        request: bool,
        rng: &mut R,
    ) -> Result<alloc::vec::Vec<u8>, SendError> {
        let link = self.links.get(link_id).ok_or(SendError::LinkNotFound)?;
        if !link.is_active() && link.state != crate::link::LinkState::Stale {
            return Err(SendError::LinkNotActive);
        }
        let payload: &[u8] = if request { &[0xFF] } else { &[0xFE] };
        Self::build_link_packet(link, link_id, payload, CONTEXT_KEEPALIVE, rng)
    }

    /// Encrypt plaintext and build a link DATA packet. Shared by all link packet builders.
    pub(super) fn build_link_packet<R: RngCore + CryptoRng>(
        link: &Link,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        plaintext: &[u8],
        context: u8,
        rng: &mut R,
    ) -> Result<alloc::vec::Vec<u8>, SendError> {
        let mut ct_buf = [0u8; rete_core::MTU];
        let ct_len = link
            .encrypt(plaintext, rng, &mut ct_buf)
            .map_err(SendError::Crypto)?;
        let mut pkt_buf = [0u8; rete_core::MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Link)
            .destination_hash(link_id)
            .context(context)
            .payload(&ct_buf[..ct_len])
            .build()
            .map_err(SendError::PacketBuild)?;
        Ok(pkt_buf[..pkt_len].to_vec())
    }

    /// Build a LINKCLOSE packet and remove the link.
    pub fn build_linkclose_packet<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        rng: &mut R,
    ) -> Result<alloc::vec::Vec<u8>, SendError> {
        let link = self.links.get(link_id).ok_or(SendError::LinkNotFound)?;
        let mut close_buf = [0u8; rete_core::MTU];
        let close_len = link
            .build_close(rng, &mut close_buf)
            .map_err(SendError::Crypto)?;

        let mut pkt_buf = [0u8; rete_core::MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Link)
            .destination_hash(link_id)
            .context(CONTEXT_LINKCLOSE)
            .payload(&close_buf[..close_len])
            .build()
            .map_err(SendError::PacketBuild)?;

        self.links.remove(link_id);
        Ok(pkt_buf[..pkt_len].to_vec())
    }

    pub(super) fn handle_link_request<'a, R: RngCore + CryptoRng>(
        &mut self,
        raw: &'a [u8],
        dest_hash: &[u8; TRUNCATED_HASH_LEN],
        payload: &[u8],
        now: u64,
        rng: &mut R,
        identity: &Identity,
    ) -> IngestResult<'a> {
        let link_id = match compute_link_id(raw) {
            Ok(id) => id,
            Err(_) => return IngestResult::Invalid,
        };

        // Check for duplicate link request
        if self.links.contains_key(&link_id) {
            return IngestResult::Duplicate;
        }

        let mut link = match Link::from_request(link_id, payload, rng, now) {
            Ok(l) => l,
            Err(_) => {
                self.stats.links_failed += 1;
                self.stats.crypto_failures += 1;
                return IngestResult::Invalid;
            }
        };
        link.destination_hash = *dest_hash;

        // Build LRPROOF
        let proof_payload = match link.build_proof(identity) {
            Ok(p) => p,
            Err(_) => {
                self.stats.links_failed += 1;
                self.stats.crypto_failures += 1;
                return IngestResult::Invalid;
            }
        };

        // Build LRPROOF packet: Proof type, Link dest_type, dest=link_id, context=LRPROOF
        let mut proof_buf = [0u8; rete_core::MTU];
        let proof_len = match PacketBuilder::new(&mut proof_buf)
            .packet_type(PacketType::Proof)
            .dest_type(DestType::Link)
            .destination_hash(&link_id)
            .context(CONTEXT_LRPROOF)
            .payload(&proof_payload)
            .build()
        {
            Ok(n) => n,
            Err(_) => return IngestResult::Invalid,
        };

        let _ = self.links.insert(link_id, link);

        self.stats.link_requests_received += 1;
        IngestResult::LinkRequestReceived {
            link_id,
            proof_raw: proof_buf[..proof_len].to_vec(),
        }
    }

    /// Validate an LRPROOF payload at a relay node.
    ///
    /// Matches Python `Transport.py` relay behavior: validates the responder's
    /// signature before forwarding. Returns true if valid or if validation is
    /// not possible (identity unknown).
    pub(super) fn validate_lrproof_relay(
        &self,
        proof_payload: &[u8],
        link_id: &[u8; TRUNCATED_HASH_LEN],
        dest_identity: &Identity,
    ) -> bool {
        use crate::link::LINK_MTU_SIZE;

        if proof_payload.len() < 96 {
            return false;
        }

        let signature = &proof_payload[..64];
        let responder_x25519_pub = &proof_payload[64..96];
        let signalling = &proof_payload[96..];

        // Reject unexpected trailing data
        if signalling.len() > LINK_MTU_SIZE {
            return false;
        }

        // Reconstruct signed_data: link_id || responder_x25519_pub || ed25519_pub [|| signalling]
        let signed_len = 80 + signalling.len();
        let mut signed_data = [0u8; 83]; // max: 16+32+32+3
        signed_data[..16].copy_from_slice(link_id);
        signed_data[16..48].copy_from_slice(responder_x25519_pub);
        signed_data[48..80].copy_from_slice(dest_identity.ed25519_pub());
        signed_data[80..signed_len].copy_from_slice(signalling);

        dest_identity
            .verify(&signed_data[..signed_len], signature)
            .is_ok()
    }

    pub(super) fn handle_lrproof<'a>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        proof_payload: &[u8],
        now: u64,
    ) -> IngestResult<'a> {
        // Look up the initiator link
        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return IngestResult::Invalid,
        };

        // Need the destination identity to verify the proof
        let dest_hash = link.destination_hash;
        let pub_key = match self.known_identities.get(&dest_hash) {
            Some(pk) => *pk,
            None => return IngestResult::Invalid,
        };

        let dest_identity = match Identity::from_public_key(&pub_key) {
            Ok(id) => id,
            Err(_) => {
                self.stats.links_failed += 1;
                self.stats.crypto_failures += 1;
                return IngestResult::Invalid;
            }
        };

        if link.validate_proof(proof_payload, &dest_identity).is_err() {
            self.stats.links_failed += 1;
            self.stats.crypto_failures += 1;
            return IngestResult::Invalid;
        }

        // Compute RTT: time since LINKREQUEST was sent (last_outbound was set at creation).
        // With u64-second timestamps, loopback RTT rounds to 0. Use a floor of 0.001s
        // so update_keepalive still fires (producing keepalive=5s for sub-second RTT).
        let raw_rtt = now.saturating_sub(link.last_outbound) as f32;
        let rtt = if raw_rtt <= 0.0 { 0.001 } else { raw_rtt };
        link.update_keepalive(rtt);

        // Initiator activates after proof validation (will send LRRTT next)
        link.activate(now);

        self.stats.links_established += 1;
        IngestResult::LinkEstablished { link_id: *link_id }
    }

    pub(super) fn handle_link_data<'a, R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        context: u8,
        ciphertext: &[u8],
        now: u64,
        pkt_hash: [u8; 32],
        rng: &mut R,
    ) -> IngestResult<'a> {
        // For resource contexts, decrypt first in a sub-scope to release the link
        // borrow, then handle resources using self.resources separately.
        if matches!(
            context,
            CONTEXT_RESOURCE
                | CONTEXT_RESOURCE_ADV
                | CONTEXT_RESOURCE_REQ
                | CONTEXT_RESOURCE_HMU
                | CONTEXT_RESOURCE_PRF
                | CONTEXT_RESOURCE_ICL
                | CONTEXT_RESOURCE_RCL
        ) {
            // CONTEXT_RESOURCE data parts are NOT link-encrypted — they travel as raw payload.
            // All other resource contexts (ADV, REQ, HMU, PRF, ICL, RCL) ARE link-encrypted.
            if context == CONTEXT_RESOURCE {
                // Pass raw ciphertext payload directly (no link decryption).
                // Still need to verify link is active and touch inbound.
                {
                    let link = match self.links.get_mut(link_id) {
                        Some(l) => l,
                        None => return IngestResult::Invalid,
                    };
                    if !link.is_active() {
                        return IngestResult::Invalid;
                    }
                    link.touch_inbound(now);
                }
                return self.handle_resource_data(link_id, context, ciphertext, now, rng);
            }

            // Use heap buffer for resource contexts — TCP links can carry
            // payloads much larger than the 500-byte radio MTU.
            let mut dec_buf = alloc::vec![0u8; ciphertext.len()];
            let dec_len = {
                let link = match self.links.get_mut(link_id) {
                    Some(l) => l,
                    None => return IngestResult::Invalid,
                };
                if !link.is_active() {
                    return IngestResult::Invalid;
                }
                link.touch_inbound(now);
                match link.decrypt(ciphertext, &mut dec_buf) {
                    Ok(n) => n,
                    Err(_) => {
                        self.stats.crypto_failures += 1;
                        return IngestResult::Invalid;
                    }
                }
            };
            // self.links borrow is released. Now we can use self.resources.
            return self.handle_resource_data(link_id, context, &dec_buf[..dec_len], now, rng);
        }

        let link = match self.links.get_mut(link_id) {
            Some(l) => l,
            None => return IngestResult::Invalid,
        };

        // Decrypt payload — use heap if ciphertext exceeds radio MTU
        let mut dec_buf = alloc::vec![0u8; core::cmp::max(ciphertext.len(), rete_core::MTU)];
        let dec_len = match link.decrypt(ciphertext, &mut dec_buf) {
            Ok(n) => n,
            Err(_) => {
                self.stats.crypto_failures += 1;
                return IngestResult::Invalid;
            }
        };

        match context {
            CONTEXT_LRRTT => {
                // RTT measurement — activates responder link.
                // Compute RTT: time since link was created (proof sent shortly after).
                // Floor at 0.001s so sub-second RTT (from u64 truncation) still triggers
                // dynamic keepalive tuning.
                let raw_rtt = now.saturating_sub(link.last_outbound) as f32;
                let rtt = if raw_rtt <= 0.0 { 0.001 } else { raw_rtt };
                link.update_keepalive(rtt);
                link.activate(now);
                self.stats.links_established += 1;
                IngestResult::LinkEstablished { link_id: *link_id }
            }
            CONTEXT_KEEPALIVE => {
                if let Some(response_byte) = link.handle_keepalive(&dec_buf[..dec_len], now) {
                    IngestResult::LinkData {
                        link_id: *link_id,
                        data: alloc::vec![response_byte],
                        context: CONTEXT_KEEPALIVE,
                    }
                } else {
                    IngestResult::Duplicate
                }
            }
            CONTEXT_LINKCLOSE => {
                let lid = *link_id;
                if link.handle_close(&dec_buf[..dec_len]) {
                    self.links.remove(&lid);
                    self.stats.links_closed += 1;
                    IngestResult::LinkClosed { link_id: lid }
                } else {
                    IngestResult::Invalid
                }
            }
            CONTEXT_CHANNEL => {
                if !link.is_active() {
                    return IngestResult::Invalid;
                }
                link.touch_inbound(now);
                // Lazy-init channel
                let channel = link
                    .channel
                    .get_or_insert_with(crate::channel::Channel::new);
                channel.receive(&dec_buf[..dec_len]);
                let mut messages = alloc::vec::Vec::new();
                while let Some(env) = channel.next_received() {
                    messages.push(env);
                }
                if messages.is_empty() {
                    IngestResult::Buffered {
                        packet_hash: pkt_hash,
                        link_id: *link_id,
                    }
                } else {
                    IngestResult::ChannelMessages {
                        link_id: *link_id,
                        messages,
                        packet_hash: pkt_hash,
                    }
                }
            }
            CONTEXT_REQUEST => {
                if !link.is_active() {
                    return IngestResult::Invalid;
                }
                link.touch_inbound(now);
                match crate::request::parse_request(&dec_buf[..dec_len]) {
                    Ok((ts, rq_path_hash, data)) => {
                        // Python RNS uses the packet's truncated hash as request_id
                        // for single-packet requests (Link.py: RequestReceipt uses
                        // packet_receipt.truncated_hash). This is SHA-256(hashable)[..16].
                        let mut req_id = [0u8; TRUNCATED_HASH_LEN];
                        req_id.copy_from_slice(&pkt_hash[..TRUNCATED_HASH_LEN]);
                        IngestResult::RequestReceived {
                            link_id: *link_id,
                            request_id: req_id,
                            path_hash: rq_path_hash,
                            data,
                            requested_at: ts,
                        }
                    }
                    Err(_) => IngestResult::Invalid,
                }
            }
            CONTEXT_RESPONSE => {
                if !link.is_active() {
                    return IngestResult::Invalid;
                }
                link.touch_inbound(now);
                match crate::request::parse_response(&dec_buf[..dec_len]) {
                    Ok((req_id, data)) => IngestResult::ResponseReceived {
                        link_id: *link_id,
                        request_id: req_id,
                        data,
                    },
                    Err(_) => IngestResult::Invalid,
                }
            }
            _ => {
                // Regular link data — only this branch allocates
                if !link.is_active() {
                    return IngestResult::Invalid;
                }
                link.touch_inbound(now);
                IngestResult::LinkData {
                    link_id: *link_id,
                    data: dec_buf[..dec_len].to_vec(),
                    context,
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Channel message send
    // -----------------------------------------------------------------------

    /// Send a channel message on a link.
    ///
    /// Lazy-inits the channel, enqueues the message, encrypts it, and returns
    /// the raw packet bytes. Returns `Err` if the link is not active or the
    /// channel window is full.
    pub fn send_channel_message<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        message_type: u16,
        payload: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<alloc::vec::Vec<u8>, SendError> {
        let link = self.links.get_mut(link_id).ok_or(SendError::LinkNotFound)?;
        if !link.is_active() {
            return Err(SendError::LinkNotActive);
        }
        let channel = link
            .channel
            .get_or_insert_with(crate::channel::Channel::new);
        let sequence = channel.next_tx_sequence();
        let envelope_bytes = channel
            .send(message_type, payload)
            .ok_or(SendError::WindowFull)?;
        channel.mark_sent(now);
        link.last_outbound = now;
        let raw = Self::build_link_packet(link, link_id, &envelope_bytes, CONTEXT_CHANNEL, rng)?;

        // Register channel receipt: parse the built packet to get its hash
        if let Ok(parsed) = Packet::parse(&raw) {
            let pkt_hash = parsed.compute_hash();
            let mut trunc = [0u8; TRUNCATED_HASH_LEN];
            trunc.copy_from_slice(&pkt_hash[..TRUNCATED_HASH_LEN]);
            let _ = self.channel_receipts.insert(
                trunc,
                ChannelReceipt {
                    link_id: *link_id,
                    sequence,
                    sent_at: now,
                },
            );
        }

        Ok(raw)
    }

    // -----------------------------------------------------------------------
    // Channel retransmission
    // -----------------------------------------------------------------------

    /// Build retransmit packets for all channels that have timed-out messages.
    ///
    /// Also checks for channel teardown (max retries exceeded) and closes
    /// the associated link.
    pub fn pending_channel_retransmits<R: RngCore + CryptoRng>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        let mut packets = alloc::vec::Vec::new();
        let mut teardown_links = alloc::vec::Vec::<[u8; TRUNCATED_HASH_LEN]>::new();

        let mut link_ids = alloc::vec::Vec::<[u8; TRUNCATED_HASH_LEN]>::new();
        for (lid, l) in self.links.iter() {
            if l.channel.is_some() && l.is_active() {
                link_ids.push(*lid);
            }
        }

        for lid in link_ids {
            let link = match self.links.get_mut(&lid) {
                Some(l) => l,
                None => continue,
            };
            let channel = match link.channel.as_mut() {
                Some(c) => c,
                None => continue,
            };
            let retransmits = channel.pending_retransmit(now);
            if channel.teardown {
                teardown_links.push(lid);
                continue;
            }
            for envelope_bytes in retransmits {
                if let Ok(pkt) =
                    Self::build_link_packet(link, &lid, &envelope_bytes, CONTEXT_CHANNEL, rng)
                {
                    packets.push(pkt);
                }
            }
        }

        // Close links that hit max retries
        for lid in teardown_links {
            self.links.remove(&lid);
        }

        packets
    }

    // -----------------------------------------------------------------------
    // Keepalive generation
    // -----------------------------------------------------------------------

    /// Build keepalive request packets for links that need them.
    ///
    /// Iterates active links and generates a keepalive request for each
    /// that has been idle for more than half the keepalive interval.
    /// Updates `last_outbound` on each link that gets a keepalive.
    pub fn build_pending_keepalives<R: RngCore + CryptoRng>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        let mut need_ka = alloc::vec::Vec::<[u8; TRUNCATED_HASH_LEN]>::new();
        for (lid, link) in self.links.iter() {
            if link.needs_keepalive(now) {
                need_ka.push(*lid);
            }
        }

        let mut packets = alloc::vec::Vec::new();
        for lid in need_ka {
            if let Ok(pkt) = self.build_keepalive_packet(&lid, true, rng) {
                if let Some(link) = self.links.get_mut(&lid) {
                    link.last_outbound = now;
                }
                packets.push(pkt);
            }
        }
        packets
    }
}
