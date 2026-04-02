//! Resource send/recv, split transfers, encryption.

use crate::link::decode_mtu;
use crate::resource::Resource;
use rand_core::{CryptoRng, RngCore};
use rete_core::{
    DestType, PacketBuilder, PacketType, CONTEXT_RESOURCE, CONTEXT_RESOURCE_ADV,
    CONTEXT_RESOURCE_HMU, CONTEXT_RESOURCE_ICL, CONTEXT_RESOURCE_PRF, CONTEXT_RESOURCE_RCL,
    CONTEXT_RESOURCE_REQ, TRUNCATED_HASH_LEN,
};

use super::{IngestResult, SplitMeta, SplitSendEntry, Transport, RESOURCE_OUTBOUND_MAX, RESOURCE_RETRY_THRESHOLD_SECS};

impl<const P: usize, const A: usize, const D: usize, const L: usize> Transport<P, A, D, L> {
    // -----------------------------------------------------------------------
    // Resource management
    // -----------------------------------------------------------------------

    /// Start a new outbound resource transfer on a link.
    ///
    /// Matches Python RNS protocol flow:
    /// 1. Prepend 4 random bytes to data
    /// 2. Optionally compress (caller decides)
    /// 3. Encrypt prepended data via link Token
    /// 4. Create Resource from the encrypted blob
    /// 5. Build advertisement and send it
    ///
    /// `data` is the bytes to transmit (possibly compressed).
    /// `original_data` is the original uncompressed plaintext (for proof
    /// validation and `original_size`).  When not compressed, pass the
    /// same slice for both.
    ///
    /// Returns the advertisement payload as raw packet bytes.
    pub fn start_resource<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        data: &[u8],
        original_data: &[u8],
        compressed: bool,
        rng: &mut R,
    ) -> Option<alloc::vec::Vec<u8>> {
        use crate::resource::MAX_EFFICIENT_SIZE;

        // Check if this needs to be split into multiple segments.
        // Python splits based on original plaintext size (including metadata,
        // but we don't use metadata). The split operates on pre-compression data.
        if original_data.len() > MAX_EFFICIENT_SIZE {
            return self.start_split_resource(link_id, original_data, rng);
        }

        self.start_single_resource(link_id, data, original_data, compressed, rng)
    }

    /// Start a single (non-split) resource transfer.
    fn start_single_resource<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        data: &[u8],
        original_data: &[u8],
        compressed: bool,
        rng: &mut R,
    ) -> Option<alloc::vec::Vec<u8>> {
        let (pkt, _) = self.prepare_and_advertise_segment(
            link_id,
            data,
            original_data,
            compressed,
            None,
            rng,
        )?;
        Some(pkt)
    }

    /// Start a split resource transfer (data > MAX_EFFICIENT_SIZE).
    ///
    /// Splits the input data into segments of MAX_EFFICIENT_SIZE bytes each,
    /// processes segment 1 (prepend, encrypt, create Resource, advertise),
    /// and queues remaining segments for later (advertised on proof receipt).
    fn start_split_resource<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        original_data: &[u8],
        rng: &mut R,
    ) -> Option<alloc::vec::Vec<u8>> {
        use crate::resource::MAX_EFFICIENT_SIZE;

        let total_size = original_data.len();
        let split_total = ((total_size - 1) / MAX_EFFICIENT_SIZE) + 1;

        let seg1_end = MAX_EFFICIENT_SIZE.min(total_size);
        let seg1_data = &original_data[..seg1_end];

        let (pkt, seg1_hash) = self.prepare_and_advertise_segment(
            link_id,
            seg1_data,
            seg1_data,
            false,
            Some(SplitMeta {
                split_index: 1,
                split_total,
                original_hash: [0u8; 32],
                full_original_size: total_size,
            }),
            rng,
        )?;

        // Queue remaining data for later segments (only the tail after segment 1)
        if self.split_send_queue.len() >= L {
            return None;
        }
        self.split_send_queue.push(SplitSendEntry {
            link_id: *link_id,
            original_hash: seg1_hash,
            next_segment: 2,
            split_total,
            full_original_size: total_size,
            data: original_data[seg1_end..].to_vec(),
        });

        Some(pkt)
    }

    /// Prepend 4 random bytes and encrypt data via link Token.
    fn prepend_and_encrypt<R: RngCore + CryptoRng>(
        &self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        data: &[u8],
        rng: &mut R,
    ) -> Option<(alloc::vec::Vec<u8>, usize)> {
        let link = self.links.get(link_id)?;
        if !link.is_active() {
            return None;
        }
        let mtu = decode_mtu(&link.signalling) as usize;

        let mut prepended = alloc::vec::Vec::with_capacity(4 + data.len());
        let mut prepend_bytes = [0u8; 4];
        rng.fill_bytes(&mut prepend_bytes);
        prepended.extend_from_slice(&prepend_bytes);
        prepended.extend_from_slice(data);

        let max_ct_len = 16 + ((prepended.len() / 16) + 1) * 16 + 32;
        let mut ct_buf = alloc::vec![0u8; max_ct_len];
        let ct_len = link.encrypt(&prepended, rng, &mut ct_buf).ok()?;
        ct_buf.truncate(ct_len);
        Some((ct_buf, mtu))
    }

    /// Compute SDU and link_mdu from peer MTU.
    fn compute_sdu_and_link_mdu(peer_mtu: usize) -> (usize, usize) {
        let sdu = if peer_mtu > 36 { peer_mtu - 36 } else { 464 };
        let link_mdu = if peer_mtu > 68 {
            ((peer_mtu - 68) / 16) * 16 - 1
        } else {
            crate::link::LINK_MDU
        };
        (sdu, link_mdu)
    }

    /// Override resource_hash to match Python convention: SHA-256(plaintext || random_hash).
    /// Only sets `resource_hash`; caller is responsible for `original_hash`.
    fn override_resource_hash(resource: &mut Resource, original_data: &[u8]) {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(original_data);
        hasher.update(resource.random_hash);
        resource.resource_hash = hasher.finalize().into();
    }

    /// Create an outbound Resource from data, encrypt it, build the
    /// advertisement packet, and push the Resource to self.resources.
    ///
    /// `send_data` is what gets encrypted (may be compressed).
    /// `original_data` is the uncompressed plaintext (used for resource_hash
    /// and proof validation). For uncompressed resources, pass the same slice.
    /// `split` optionally sets split metadata: (split_index, split_total, original_hash).
    ///
    /// Returns (advertisement_packet, resource_hash).
    pub(super) fn push_resource_outbound(&mut self, pkt: alloc::vec::Vec<u8>) {
        if self.resource_outbound.len() < RESOURCE_OUTBOUND_MAX {
            self.resource_outbound.push(pkt);
        }
    }

    fn prepare_and_advertise_segment<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        send_data: &[u8],
        original_data: &[u8],
        compressed: bool,
        split: Option<SplitMeta>,
        rng: &mut R,
    ) -> Option<(alloc::vec::Vec<u8>, [u8; 32])> {
        if self.resources.len() >= L {
            return None;
        }
        let (encrypted, peer_mtu) = self.prepend_and_encrypt(link_id, send_data, rng)?;
        let (sdu, link_mdu) = Self::compute_sdu_and_link_mdu(peer_mtu);
        let original_size = split
            .as_ref()
            .map(|s| s.full_original_size)
            .unwrap_or(original_data.len());
        let mut resource =
            Resource::new_outbound(&encrypted, *link_id, sdu, original_size, link_mdu, rng);
        resource.flags.encrypted = true;
        resource.flags.compressed = compressed;

        Self::override_resource_hash(&mut resource, original_data);
        resource.data = original_data.to_vec();

        if let Some(meta) = split {
            resource.split_index = meta.split_index;
            resource.split_total = meta.split_total;
            resource.flags.is_split = true;
            // For segment 1, original_hash == [0;32] means "use this segment's hash"
            resource.original_hash = if meta.original_hash == [0u8; 32] {
                resource.resource_hash
            } else {
                meta.original_hash
            };
        }

        let resource_hash = resource.resource_hash;
        let adv = resource.build_advertisement();
        let pkt = self.encrypt_and_build_adv(link_id, &adv, rng)?;

        self.resources.push(resource);
        Some((pkt, resource_hash))
    }

    /// Encrypt an advertisement payload and build the RESOURCE_ADV packet.
    fn encrypt_and_build_adv<R: RngCore + CryptoRng>(
        &self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        adv: &[u8],
        rng: &mut R,
    ) -> Option<alloc::vec::Vec<u8>> {
        let link = self.links.get(link_id)?;
        let peer_mtu = decode_mtu(&link.signalling) as usize;
        // Use peer MTU for buffer size: TCP links (MTU=8192) produce larger
        // advertisements with more part hashes in the hashmap.
        let buf_size = peer_mtu.max(rete_core::MTU);
        let mut adv_ct_buf = alloc::vec![0u8; buf_size];
        let adv_ct_len = link.encrypt(adv, rng, &mut adv_ct_buf).ok()?;

        let mut pkt_buf = alloc::vec![0u8; buf_size];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Link)
            .destination_hash(link_id)
            .context(CONTEXT_RESOURCE_ADV)
            .payload(&adv_ct_buf[..adv_ct_len])
            .build()
            .ok()?;

        Some(pkt_buf[..pkt_len].to_vec())
    }

    /// Advertise the next split segment after proof receipt.
    /// Returns the advertisement packet to send, or None if no more segments.
    pub(super) fn advertise_next_split_segment<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        original_hash: &[u8; 32],
        rng: &mut R,
    ) -> Option<alloc::vec::Vec<u8>> {
        use crate::resource::MAX_EFFICIENT_SIZE;

        let entry_idx = self
            .split_send_queue
            .iter()
            .position(|e| e.link_id == *link_id && e.original_hash == *original_hash)?;

        let seg_idx = self.split_send_queue[entry_idx].next_segment;
        let split_total = self.split_send_queue[entry_idx].split_total;

        if seg_idx > split_total {
            self.split_send_queue.swap_remove(entry_idx);
            return None;
        }

        // Queue data starts at segment 2, so offset from segment 2
        let data_len = self.split_send_queue[entry_idx].data.len();
        let seg_start = (seg_idx - 2) * MAX_EFFICIENT_SIZE;
        let seg_end = (seg_start + MAX_EFFICIENT_SIZE).min(data_len);
        let seg_data = self.split_send_queue[entry_idx].data[seg_start..seg_end].to_vec();
        let full_original_size = self.split_send_queue[entry_idx].full_original_size;
        let oh = *original_hash;

        let (pkt, _) = self.prepare_and_advertise_segment(
            link_id,
            &seg_data,
            &seg_data,
            false,
            Some(SplitMeta {
                split_index: seg_idx,
                split_total,
                original_hash: oh,
                full_original_size,
            }),
            rng,
        )?;

        // Advance or remove queue entry
        let entry = &mut self.split_send_queue[entry_idx];
        entry.next_segment += 1;
        if entry.next_segment > entry.split_total {
            self.split_send_queue.swap_remove(entry_idx);
        }

        Some(pkt)
    }

    /// Accept a resource offer and build the first request.
    ///
    /// Returns the encrypted RESOURCE_REQ packet.
    pub fn accept_resource<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        resource_hash: &[u8; TRUNCATED_HASH_LEN],
        rng: &mut R,
    ) -> Option<alloc::vec::Vec<u8>> {
        let req = {
            let res = self.resources.iter_mut().find(|r| {
                !r.is_sender
                    && r.link_id == *link_id
                    && r.resource_hash[..TRUNCATED_HASH_LEN] == *resource_hash
            })?;
            res.build_request()
        };
        self.build_resource_req_packet(link_id, &req, rng)
    }

    /// Reject a resource offer and send RESOURCE_RCL to the sender.
    ///
    /// Marks the resource as `Rejected` and returns an encrypted RESOURCE_RCL packet
    /// containing the full 32-byte resource hash (Python expects this).
    pub fn reject_resource<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        resource_hash: &[u8; TRUNCATED_HASH_LEN],
        rng: &mut R,
    ) -> Option<alloc::vec::Vec<u8>> {
        let full_hash = {
            let res = self.resources.iter_mut().find(|r| {
                !r.is_sender
                    && r.link_id == *link_id
                    && r.resource_hash[..TRUNCATED_HASH_LEN] == *resource_hash
            })?;
            res.state = crate::resource::ResourceState::Rejected;
            res.resource_hash
        };
        self.build_resource_rcl_packet(link_id, &full_hash, rng)
    }

    /// Build an encrypted RESOURCE_RCL packet containing the full 32-byte resource hash.
    fn build_resource_rcl_packet<R: RngCore + CryptoRng>(
        &self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        resource_hash: &[u8; 32],
        rng: &mut R,
    ) -> Option<alloc::vec::Vec<u8>> {
        let link = self.links.get(link_id)?;
        Self::build_link_packet(link, link_id, resource_hash, CONTEXT_RESOURCE_RCL, rng).ok()
    }

    /// Build a follow-up RESOURCE_REQ for a receiver resource that still has
    /// unreceived parts.
    ///
    /// Used by NodeCore after receiving a window of parts (ResourceProgress
    /// with current < total) to request the next batch.
    pub fn build_followup_request<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        resource_hash: &[u8; TRUNCATED_HASH_LEN],
        rng: &mut R,
    ) -> Option<alloc::vec::Vec<u8>> {
        let req = {
            let res = self.resources.iter_mut().find(|r| {
                !r.is_sender
                    && r.link_id == *link_id
                    && r.resource_hash[..TRUNCATED_HASH_LEN] == *resource_hash
            })?;
            // All parts already received — no follow-up needed
            if res.received.iter().all(|&r| r) {
                return None;
            }
            res.build_request()
        };
        self.build_resource_req_packet(link_id, &req, rng)
    }

    /// Encrypt a RESOURCE_REQ payload via a link and build the packet.
    fn build_resource_req_packet<R: RngCore + CryptoRng>(
        &self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        req_payload: &[u8],
        rng: &mut R,
    ) -> Option<alloc::vec::Vec<u8>> {
        let link = self.links.get(link_id)?;
        let mut ct_buf = [0u8; rete_core::MTU];
        let ct_len = link.encrypt(req_payload, rng, &mut ct_buf).ok()?;

        let mut pkt_buf = [0u8; rete_core::MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Link)
            .destination_hash(link_id)
            .context(CONTEXT_RESOURCE_REQ)
            .payload(&ct_buf[..ct_len])
            .build()
            .ok()?;

        Some(pkt_buf[..pkt_len].to_vec())
    }

    pub(super) fn handle_resource_data<'a, R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        context: u8,
        decrypted: &[u8],
        now: u64,
        rng: &mut R,
    ) -> IngestResult<'a> {
        match context {
            CONTEXT_RESOURCE => {
                // A resource data part (NOT link-encrypted — raw segment data)
                if let Some(res) = self
                    .resources
                    .iter_mut()
                    .find(|r| !r.is_sender && r.link_id == *link_id)
                {
                    res.touch_activity(now);
                    let all_received = res.receive_part(decrypted);
                    let mut rh = [0u8; TRUNCATED_HASH_LEN];
                    rh.copy_from_slice(&res.resource_hash[..TRUNCATED_HASH_LEN]);
                    if all_received {
                        IngestResult::ResourceProgress {
                            link_id: *link_id,
                            resource_hash: rh,
                            current: res.total_segments,
                            total: res.total_segments,
                        }
                    } else {
                        let received_count = res.received.iter().filter(|&&r| r).count();
                        IngestResult::ResourceProgress {
                            link_id: *link_id,
                            resource_hash: rh,
                            current: received_count,
                            total: res.total_segments,
                        }
                    }
                } else {
                    IngestResult::Invalid
                }
            }
            CONTEXT_RESOURCE_ADV => {
                // Resource advertisement from sender
                match Resource::from_advertisement(decrypted, *link_id) {
                    Ok(res) => {
                        if self.resources.len() >= L {
                            return IngestResult::Invalid;
                        }
                        let mut rh = [0u8; TRUNCATED_HASH_LEN];
                        rh.copy_from_slice(&res.resource_hash[..TRUNCATED_HASH_LEN]);
                        // Deduplicate: if a resource with same link+hash already exists,
                        // ignore the duplicate advertisement.
                        let already_exists = self.resources.iter().any(|r| {
                            !r.is_sender
                                && r.link_id == *link_id
                                && r.resource_hash[..TRUNCATED_HASH_LEN] == rh
                        });
                        if already_exists {
                            return IngestResult::Duplicate;
                        }
                        let total_size = res.total_size;
                        let is_request_or_response =
                            res.flags.is_request || res.flags.is_response;
                        self.resources.push(res);
                        IngestResult::ResourceOffered {
                            link_id: *link_id,
                            resource_hash: rh,
                            total_size,
                            is_request_or_response,
                        }
                    }
                    Err(_) => IngestResult::Invalid,
                }
            }
            CONTEXT_RESOURCE_REQ => {
                // Resource request from receiver (we are sender).
                let req_hash = Resource::extract_request_hash(decrypted);
                let (parts_to_send, hmu_payload) = {
                    if let Some(res) = self.resources.iter_mut().find(|r| {
                        r.is_sender
                            && r.link_id == *link_id
                            && req_hash.is_none_or(|h| h == r.resource_hash)
                    }) {
                        res.touch_activity(now);
                        let result = res.handle_request(decrypted);
                        // If receiver signaled HASHMAP_IS_EXHAUSTED, build HMU
                        // in the same borrow scope (avoids double lookup).
                        let hmu = if result.needs_hmu {
                            res.build_hashmap_update()
                        } else {
                            None
                        };
                        (result.parts, hmu)
                    } else {
                        return IngestResult::Invalid;
                    }
                };
                // Send data parts (NOT link-encrypted in Python RNS).
                for (_idx, part_data) in parts_to_send {
                    // Use heap buffer for large TCP segments (SDU up to 8156)
                    let buf_size = part_data.len() + 20; // header + payload
                    let mut pkt_buf = alloc::vec![0u8; buf_size];
                    if let Ok(pkt_len) = PacketBuilder::new(&mut pkt_buf)
                        .packet_type(PacketType::Data)
                        .dest_type(DestType::Link)
                        .destination_hash(link_id)
                        .context(CONTEXT_RESOURCE)
                        .payload(&part_data)
                        .build()
                    {
                        self.push_resource_outbound(pkt_buf[..pkt_len].to_vec());
                    }
                }
                // Send link-encrypted HMU so receiver gets hashes for next window.
                if let Some(payload) = hmu_payload {
                    if let Some(link) = self.links.get(link_id) {
                        if let Ok(pkt) = Self::build_link_packet(
                            link,
                            link_id,
                            &payload,
                            CONTEXT_RESOURCE_HMU,
                            rng,
                        ) {
                            self.push_resource_outbound(pkt);
                        }
                    }
                }
                IngestResult::Duplicate // Parts queued in resource_outbound
            }
            CONTEXT_RESOURCE_HMU => {
                // Hashmap update from sender
                if let Some(res) = self
                    .resources
                    .iter_mut()
                    .find(|r| !r.is_sender && r.link_id == *link_id)
                {
                    let _ = res.apply_hashmap_update(decrypted);
                }
                IngestResult::Duplicate
            }
            CONTEXT_RESOURCE_PRF => {
                // Resource proof from receiver (we are sender).
                // Match by resource_hash from proof payload (first 32 bytes).
                let proof_rh: Option<[u8; 32]> = if decrypted.len() >= 32 {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&decrypted[..32]);
                    Some(h)
                } else {
                    None
                };
                if let Some(res) = self.resources.iter_mut().find(|r| {
                    r.is_sender
                        && r.link_id == *link_id
                        && proof_rh.is_none_or(|h| h == r.resource_hash)
                }) {
                    let mut rh = [0u8; TRUNCATED_HASH_LEN];
                    rh.copy_from_slice(&res.resource_hash[..TRUNCATED_HASH_LEN]);
                    let is_split = res.split_total > 1;
                    let is_final_segment = res.split_index >= res.split_total;
                    let original_hash = res.original_hash;
                    if res.handle_proof(decrypted) {
                        // For split resources: if non-final, advertise next segment
                        if is_split && !is_final_segment {
                            if let Some(adv_pkt) =
                                self.advertise_next_split_segment(link_id, &original_hash, rng)
                            {
                                self.push_resource_outbound(adv_pkt);
                            }
                            // Return Duplicate so NodeCore doesn't emit ResourceComplete yet
                            IngestResult::Duplicate
                        } else {
                            IngestResult::ResourceComplete {
                                link_id: *link_id,
                                resource_hash: rh,
                                data: alloc::vec::Vec::new(), // sender doesn't return data
                            }
                        }
                    } else {
                        // Proof failed — clean up split queue
                        if is_split {
                            self.split_send_queue.retain(|e| {
                                !(e.link_id == *link_id && e.original_hash == original_hash)
                            });
                        }
                        IngestResult::ResourceFailed {
                            link_id: *link_id,
                            resource_hash: rh,
                        }
                    }
                } else {
                    IngestResult::Invalid
                }
            }
            CONTEXT_RESOURCE_ICL => {
                // Cancel from initiator (sender-side cancel).
                // Payload contains resource hash — match on it to handle
                // concurrent resources on the same link correctly.
                let hash_prefix = if decrypted.len() >= TRUNCATED_HASH_LEN {
                    &decrypted[..TRUNCATED_HASH_LEN]
                } else {
                    &[]
                };
                if let Some(res) = self.resources.iter_mut().find(|r| {
                    r.link_id == *link_id
                        && (hash_prefix.is_empty()
                            || r.resource_hash[..TRUNCATED_HASH_LEN] == *hash_prefix)
                }) {
                    res.handle_cancel();
                    let mut rh = [0u8; TRUNCATED_HASH_LEN];
                    rh.copy_from_slice(&res.resource_hash[..TRUNCATED_HASH_LEN]);
                    IngestResult::ResourceFailed {
                        link_id: *link_id,
                        resource_hash: rh,
                    }
                } else {
                    IngestResult::Duplicate
                }
            }
            CONTEXT_RESOURCE_RCL => {
                // Rejection from receiver — distinct from cancel.
                // Payload contains resource hash for matching.
                let hash_prefix = if decrypted.len() >= TRUNCATED_HASH_LEN {
                    &decrypted[..TRUNCATED_HASH_LEN]
                } else {
                    &[]
                };
                if let Some(res) = self.resources.iter_mut().find(|r| {
                    r.link_id == *link_id
                        && (hash_prefix.is_empty()
                            || r.resource_hash[..TRUNCATED_HASH_LEN] == *hash_prefix)
                }) {
                    res.state = crate::resource::ResourceState::Rejected;
                    let mut rh = [0u8; TRUNCATED_HASH_LEN];
                    rh.copy_from_slice(&res.resource_hash[..TRUNCATED_HASH_LEN]);
                    IngestResult::ResourceRejected {
                        link_id: *link_id,
                        resource_hash: rh,
                    }
                } else {
                    IngestResult::Duplicate
                }
            }
            _ => IngestResult::Invalid,
        }
    }

    /// Periodic resource maintenance.
    ///
    /// Python doesn't proactively send HMU — it only sends in response to
    /// RESOURCE_REQ with HASHMAP_IS_EXHAUSTED. The receiver retries via its
    /// watchdog/timeout. Matching that behavior: no proactive HMU sending.
    pub fn tick_resources<R: RngCore + CryptoRng>(&mut self, now: u64, rng: &mut R) {
        // Retry follow-up requests for stalled receiver resources.
        // Only retry when outstanding_parts == 0 (not waiting for in-flight parts)
        // AND enough time has passed since last activity (time-gated to avoid
        // spamming REQs before the sender has time to respond).
        let mut req_packets = alloc::vec::Vec::new();
        for res in &mut self.resources {
            if !res.is_sender
                && !res.received.iter().all(|&r| r)
                && res.outstanding_parts == 0
                && now.saturating_sub(res.last_activity) >= RESOURCE_RETRY_THRESHOLD_SECS
            {
                let req_payload = res.build_request();
                req_packets.push((res.link_id, req_payload));
                res.touch_activity(now);
            }
        }
        // Encrypt REQ packets via the link (separate loop to avoid borrow conflict)
        for (link_id, req_payload) in &req_packets {
            if let Some(pkt) = self.build_resource_req_packet(link_id, req_payload, rng) {
                self.push_resource_outbound(pkt);
            }
        }
        // Also send link-encrypted HMU for sender resources with unsent hashes.
        // Collect payloads first to avoid borrow conflict between resources and links.
        let mut hmu_items: alloc::vec::Vec<([u8; TRUNCATED_HASH_LEN], alloc::vec::Vec<u8>)> =
            alloc::vec::Vec::new();
        for res in &mut self.resources {
            if res.is_sender && res.needs_hashmap_update() {
                if let Some(hmu) = res.build_hashmap_update() {
                    hmu_items.push((res.link_id, hmu));
                }
            }
        }
        for (lid, hmu_payload) in &hmu_items {
            if let Some(link) = self.links.get(lid) {
                if let Ok(pkt) =
                    Self::build_link_packet(link, lid, hmu_payload, CONTEXT_RESOURCE_HMU, rng)
                {
                    self.push_resource_outbound(pkt);
                }
            }
        }
    }

    /// Drain pending resource outbound packets.
    pub fn drain_resource_outbound(&mut self) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        core::mem::take(&mut self.resource_outbound)
    }

    /// Get a resource by its truncated hash and link.
    pub fn get_resource(
        &self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        resource_hash: &[u8; TRUNCATED_HASH_LEN],
    ) -> Option<&Resource> {
        self.resources.iter().find(|r| {
            r.link_id == *link_id && r.resource_hash[..TRUNCATED_HASH_LEN] == *resource_hash
        })
    }

    /// Get a mutable resource by its truncated hash and link.
    pub fn get_resource_mut(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        resource_hash: &[u8; TRUNCATED_HASH_LEN],
    ) -> Option<&mut Resource> {
        self.resources.iter_mut().find(|r| {
            r.link_id == *link_id && r.resource_hash[..TRUNCATED_HASH_LEN] == *resource_hash
        })
    }

    /// Remove completed, failed, corrupt, or rejected resources.
    pub fn cleanup_resources(&mut self) {
        self.resources.retain(|r| {
            !matches!(
                r.state,
                crate::resource::ResourceState::Complete
                    | crate::resource::ResourceState::Failed
                    | crate::resource::ResourceState::Corrupt
                    | crate::resource::ResourceState::Rejected
            )
        });
    }
}
