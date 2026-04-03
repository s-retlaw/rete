//! Inbound packet dispatch, request handling, and resource buffering.

use alloc::vec;
use alloc::vec::Vec;

use rand_core::{CryptoRng, RngCore};
use rete_core::{
    DestType, Identity, PacketBuilder, PacketType, MTU, TRUNCATED_HASH_LEN,
};
use rete_transport::{IngestResult, PATH_REQUEST_DEST};

use crate::destination::DestinationType;
use crate::{NodeEvent, ProofStrategy, RequestFailReason, ResourceStrategy};

use super::{IngestOutcome, NodeCore, OutboundPacket, PacketRouting, SplitRecvEntry};

impl<S: rete_transport::TransportStorage> NodeCore<S> {
    /// Process an inbound raw packet and return the outcome.
    ///
    /// The runtime loop dispatches packets based on `IngestOutcome.packets`
    /// routing and emits `IngestOutcome.events` to the application callback.
    pub fn handle_ingest<R: RngCore + CryptoRng>(
        &mut self,
        raw: &[u8],
        now: u64,
        iface: u8,
        rng: &mut R,
    ) -> IngestOutcome {
        let len = raw.len();

        // TCP links can carry packets up to ~8192 bytes (link MTU negotiated
        // during handshake). Allow up to TCP_MAX_PKT for TCP-capable nodes.
        const TCP_MAX_PKT: usize = 8292;
        if len > TCP_MAX_PKT {
            return IngestOutcome::empty();
        }

        // Packet log: inbound
        if let Some(hooks) = &self.hooks {
            hooks.log_packet(raw, "IN", iface);
        }

        // Use stack buffer for small packets (common case), heap for large TCP packets.
        if len <= MTU {
            let mut pkt_buf = [0u8; MTU];
            pkt_buf[..len].copy_from_slice(raw);
            self.dispatch_ingest(&mut pkt_buf[..len], now, iface, rng)
        } else {
            let mut pkt_buf = vec![0u8; len];
            pkt_buf[..len].copy_from_slice(raw);
            self.dispatch_ingest(&mut pkt_buf[..len], now, iface, rng)
        }
    }

    /// Dispatch a parsed packet buffer to the transport layer.
    fn dispatch_ingest<R: RngCore + CryptoRng>(
        &mut self,
        pkt_buf: &mut [u8],
        now: u64,
        iface: u8,
        rng: &mut R,
    ) -> IngestOutcome {
        match self
            .transport
            .ingest_on(pkt_buf, now, iface, rng, &self.identity)
        {
            IngestResult::AnnounceReceived {
                dest_hash,
                identity_hash,
                hops,
                app_data,
                ratchet,
            } => {
                // Store ratchet public key from announcing peer
                if let (Some(store), Some(ratchet_pub)) =
                    (&mut self.ratchet_store, ratchet)
                {
                    store.store_peer_ratchet(&identity_hash, ratchet_pub);
                }

                let mut packets = Vec::new();

                // Auto-reply to announcing peer
                if let Some(msg) = self.auto_reply.take() {
                    let result = self.build_data_packet(&dest_hash, &msg, rng, now);
                    self.auto_reply = Some(msg);
                    if let Ok(pkt) = result {
                        packets.push(OutboundPacket {
                            data: pkt,
                            routing: PacketRouting::SourceInterface,
                        });
                    }
                }

                // Flush pending announces so received announces are forwarded
                // immediately (retransmit_timeout=now fires on first flush).
                let flushed = self.flush_announces(now, rng);
                packets.extend(flushed);

                IngestOutcome {
                    events: vec![NodeEvent::AnnounceReceived {
                        dest_hash,
                        identity_hash,
                        hops,
                        app_data: app_data.map(|d| d.to_vec()),
                    }],
                    packets,
                }
            }
            IngestResult::LocalData {
                dest_hash,
                payload,
                packet_hash,
            } => {
                let dest = match self.get_destination(&dest_hash) {
                    Some(d) => d,
                    None => return IngestOutcome::empty(),
                };
                let proof_strategy = dest.proof_strategy;

                let mut dec_buf = [0u8; MTU];

                // Gather ratchet private keys for Single destinations
                let mut privkeys = Vec::new();
                if dest.dest_type == DestinationType::Single {
                    if let Some(store) = &self.ratchet_store {
                        if let Some(k) = store.local_ratchet_private() {
                            privkeys.push(k);
                        }
                        privkeys.extend_from_slice(store.previous_ratchet_privates());
                    }
                }

                let decrypted = match dest.decrypt_with_identity(
                    payload,
                    Some(&self.identity),
                    &privkeys,
                    &mut dec_buf,
                ) {
                    Ok(n) => dec_buf[..n].to_vec(),
                    Err(_) => return IngestOutcome::empty(),
                };

                let mut packets = Vec::new();

                let should_prove = match proof_strategy {
                    ProofStrategy::ProveAll => true,
                    ProofStrategy::ProveApp => {
                        if let Some(hooks) = &self.hooks {
                            hooks.prove_app(&dest_hash, &packet_hash, &decrypted)
                        } else {
                            false
                        }
                    }
                    ProofStrategy::ProveNone => false,
                };
                if should_prove {
                    packets.extend(self.proof_outbound(&packet_hash));
                }

                IngestOutcome {
                    events: vec![NodeEvent::DataReceived {
                        dest_hash,
                        payload: decrypted,
                    }],
                    packets,
                }
            }
            IngestResult::Forward { raw, .. } => IngestOutcome {
                events: vec![],
                packets: vec![OutboundPacket {
                    data: raw.to_vec(),
                    routing: PacketRouting::AllExceptSource,
                }],
            },
            IngestResult::LinkRequestReceived { link_id, proof_raw } => IngestOutcome {
                events: vec![NodeEvent::LinkEstablished { link_id }],
                packets: vec![OutboundPacket {
                    data: proof_raw,
                    routing: PacketRouting::SourceInterface,
                }],
            },
            IngestResult::LinkEstablished { link_id } => {
                let mut packets = Vec::new();
                // Auto-send LRRTT if we are the initiator (activates responder).
                // Uses the low 32 bits of epoch seconds as a timing marker for RTT calculation.
                if self
                    .transport
                    .get_link(&link_id)
                    .map(|l| l.role == rete_transport::LinkRole::Initiator)
                    .unwrap_or(false)
                {
                    let rtt_bytes = &now.to_be_bytes()[4..8];
                    if let Ok(pkt) = self.transport.build_lrrtt_packet(&link_id, rtt_bytes, rng) {
                        packets.push(OutboundPacket::broadcast(pkt));
                    }
                }
                IngestOutcome {
                    events: vec![NodeEvent::LinkEstablished { link_id }],
                    packets,
                }
            }
            IngestResult::LinkData {
                link_id,
                data,
                context,
            } => {
                let mut packets = Vec::new();
                // If this is a keepalive request, send the response back
                if context == rete_core::CONTEXT_KEEPALIVE {
                    if let Ok(pkt) = self.transport.build_keepalive_packet(&link_id, false, rng) {
                        packets.push(OutboundPacket::broadcast(pkt));
                    }
                }
                // Handle LINKIDENTIFY: validate and emit LinkIdentified event
                if context == rete_core::CONTEXT_LINKIDENTIFY && data.len() >= 128 {
                    let mut pub_key = [0u8; 64];
                    pub_key.copy_from_slice(&data[..64]);
                    let sig = &data[64..128];
                    if let Ok(peer_id) = Identity::from_public_key(&pub_key) {
                        if peer_id.verify(&pub_key, sig).is_ok() {
                            let id_hash = peer_id.hash();
                            if let Some(link) = self.transport.get_link_mut(&link_id) {
                                link.set_identified(pub_key);
                            }
                            return IngestOutcome {
                                events: vec![NodeEvent::LinkIdentified {
                                    link_id,
                                    identity_hash: id_hash,
                                    public_key: pub_key,
                                }],
                                packets,
                            };
                        }
                    }
                }
                IngestOutcome {
                    events: vec![NodeEvent::LinkData {
                        link_id,
                        data,
                        context,
                    }],
                    packets,
                }
            }
            IngestResult::ChannelMessages {
                link_id,
                messages,
                packet_hash,
            } => IngestOutcome {
                events: vec![NodeEvent::ChannelMessages {
                    link_id,
                    messages: messages
                        .into_iter()
                        .map(|e| (e.message_type, e.payload))
                        .collect(),
                }],
                // Auto-prove received channel packets (link-destination proof for relay routing)
                packets: self
                    .link_proof_outbound(&packet_hash, &link_id)
                    .into_iter()
                    .collect(),
            },
            IngestResult::RequestReceived {
                link_id,
                request_id,
                path_hash,
                data,
                requested_at,
            } => {
                let response_packets = self.dispatch_request_handler(
                    &link_id, &request_id, &path_hash, &data, requested_at, rng,
                );
                IngestOutcome {
                    events: vec![NodeEvent::RequestReceived {
                        link_id,
                        request_id,
                        path_hash,
                        data,
                    }],
                    packets: response_packets,
                }
            }
            IngestResult::ResponseReceived {
                link_id,
                request_id,
                data,
            } => {
                // Clear matching pending request
                self.pending_requests
                    .retain(|r| r.request_id != request_id);
                IngestOutcome {
                    events: vec![NodeEvent::ResponseReceived {
                        link_id,
                        request_id,
                        data,
                    }],
                    packets: Vec::new(),
                }
            }
            IngestResult::LinkClosed { link_id } => {
                // Fail any pending requests on this link (single pass)
                let mut events: Vec<NodeEvent> = Vec::new();
                self.pending_requests.retain(|r| {
                    if r.link_id == link_id {
                        events.push(NodeEvent::RequestFailed {
                            link_id,
                            request_id: r.request_id,
                            reason: RequestFailReason::LinkClosed,
                        });
                        false
                    } else {
                        true
                    }
                });
                events.push(NodeEvent::LinkClosed { link_id });
                IngestOutcome {
                    events,
                    packets: Vec::new(),
                }
            }
            IngestResult::ProofReceived { packet_hash } => IngestOutcome {
                events: vec![NodeEvent::ProofReceived { packet_hash }],
                packets: Vec::new(),
            },
            IngestResult::Buffered {
                packet_hash,
                link_id,
            } => IngestOutcome {
                events: vec![],
                // Auto-prove buffered channel packets too (link-destination proof for relay routing)
                packets: self
                    .link_proof_outbound(&packet_hash, &link_id)
                    .into_iter()
                    .collect(),
            },
            IngestResult::ResourceOffered {
                link_id,
                resource_hash,
                total_size,
                is_request_or_response,
                is_response,
            } => {
                let mut packets = Vec::new();

                // Associate response-resource with pending request
                if is_response {
                    if let Some(req) = self
                        .pending_requests
                        .iter_mut()
                        .find(|r| r.link_id == link_id && r.response_resource_hash.is_none()
                            && matches!(r.status, super::request_receipt::RequestStatus::Sent))
                    {
                        req.response_resource_hash = Some(resource_hash);
                    }
                }

                // Request/Response resources bypass strategy (Python behavior)
                let effective = if is_request_or_response {
                    ResourceStrategy::AcceptAll
                } else {
                    self.resource_strategy
                };

                match effective {
                    ResourceStrategy::AcceptAll => {
                        if let Some(pkt) =
                            self.transport.accept_resource(&link_id, &resource_hash, rng)
                        {
                            packets.push(OutboundPacket::broadcast(pkt));
                        }
                        for pkt in self.transport.drain_resource_outbound() {
                            packets.push(OutboundPacket::broadcast(pkt));
                        }
                    }
                    ResourceStrategy::AcceptNone => {
                        if let Some(pkt) =
                            self.transport.reject_resource(&link_id, &resource_hash, rng)
                        {
                            packets.push(OutboundPacket::broadcast(pkt));
                        }
                        self.transport.cleanup_resources();
                    }
                    ResourceStrategy::AcceptApp => {
                        // No auto-action — application calls accept/reject
                    }
                }

                IngestOutcome {
                    events: vec![NodeEvent::ResourceOffered {
                        link_id,
                        resource_hash,
                        total_size,
                    }],
                    packets,
                }
            }
            IngestResult::ResourceProgress {
                link_id,
                resource_hash,
                current,
                total,
            } => {
                let mut packets = Vec::new();
                // If all parts received, concat → decrypt → decompress → verify → proof
                if current == total && total > 0 {
                    // Step 1: Concatenate encrypted parts, get flags and split metadata
                    let (concat_result, is_compressed, is_response, is_request, split_index, split_total, original_hash) = {
                        if let Some(res) = self.transport.get_resource_mut(&link_id, &resource_hash)
                        {
                            let compressed = res.flags.compressed;
                            let resp = res.flags.is_response;
                            let req = res.flags.is_request;
                            let si = res.split_index;
                            let st = res.split_total;
                            let oh = res.original_hash;
                            match res.concat_parts() {
                                Ok(data) => (Some(data), compressed, resp, req, si, st, oh),
                                Err(_) => (None, compressed, resp, req, si, st, oh),
                            }
                        } else {
                            (None, false, false, false, 1, 1, [0u8; 32])
                        }
                    };

                    // Failure helper: drain outbound, cleanup, clean split buf
                    macro_rules! resource_failed {
                        ($packets:expr) => {{
                            for pkt in self.transport.drain_resource_outbound() {
                                $packets.push(OutboundPacket::broadcast(pkt));
                            }
                            self.transport.cleanup_resources();
                            if split_total > 1 {
                                if let Some(idx) = self.split_recv_buf.iter().position(|e| {
                                    e.link_id == link_id && e.original_hash == original_hash
                                }) {
                                    self.split_recv_buf.swap_remove(idx);
                                }
                            }
                            return IngestOutcome {
                                events: vec![NodeEvent::ResourceFailed {
                                    link_id,
                                    resource_hash,
                                }],
                                packets: core::mem::take(&mut $packets),
                            };
                        }};
                    }

                    let encrypted_data = match concat_result {
                        Some(data) => data,
                        None => resource_failed!(packets),
                    };

                    // Step 2: Decrypt via link Token, strip 4-byte random prepend — hard fail
                    let decrypted = if let Some(link) = self.transport.get_link(&link_id) {
                        let mut dec_buf = vec![0u8; encrypted_data.len()];
                        match link.decrypt(&encrypted_data, &mut dec_buf) {
                            Ok(dec_len) => {
                                dec_buf.truncate(dec_len);
                                if dec_buf.len() >= 4 {
                                    dec_buf.drain(..4);
                                }
                                dec_buf
                            }
                            Err(_) => resource_failed!(packets),
                        }
                    } else {
                        resource_failed!(packets)
                    };

                    // Step 3: Decompress if compressed flag is set — hard fail
                    let plaintext = if is_compressed {
                        match self.hooks.as_ref().and_then(|h| h.decompress(&decrypted)) {
                            Some(d) => d,
                            None => resource_failed!(packets),
                        }
                    } else {
                        decrypted
                    };

                    // Step 4: Verify hash — stores plaintext in resource on success
                    if let Some(res) =
                        self.transport.get_resource_mut(&link_id, &resource_hash)
                    {
                        if res.verify_hash(plaintext).is_err() {
                            resource_failed!(packets);
                        }
                    } else {
                        resource_failed!(packets);
                    }

                    // Step 5: Build proof from verified data
                    let (proof, plaintext) = if let Some(res) =
                        self.transport.get_resource_mut(&link_id, &resource_hash)
                    {
                        let proof = res.build_proof();
                        (proof, core::mem::take(&mut res.data))
                    } else {
                        resource_failed!(packets);
                    };

                    // Step 6: Send proof packet
                    if !proof.is_empty() {
                        let mut pkt_buf = [0u8; MTU];
                        if let Ok(pkt_len) = PacketBuilder::new(&mut pkt_buf)
                            .packet_type(PacketType::Proof)
                            .dest_type(DestType::Link)
                            .destination_hash(&link_id)
                            .context(rete_core::CONTEXT_RESOURCE_PRF)
                            .payload(&proof)
                            .build()
                        {
                            packets
                                .push(OutboundPacket::broadcast(pkt_buf[..pkt_len].to_vec()));
                        }
                    }

                    // Drain any resource outbound packets
                    for pkt in self.transport.drain_resource_outbound() {
                        packets.push(OutboundPacket::broadcast(pkt));
                    }
                    // Clean up completed receiver resource
                    self.transport.cleanup_resources();

                    // Step 7: Handle split resources
                    let mut oh_trunc = [0u8; TRUNCATED_HASH_LEN];
                    oh_trunc.copy_from_slice(&original_hash[..TRUNCATED_HASH_LEN]);

                    if split_total > 1 && split_index < split_total {
                        // Non-final split segment: buffer data, wait for next
                        if let Some(entry) = self
                            .split_recv_buf
                            .iter_mut()
                            .find(|e| e.link_id == link_id && e.original_hash == original_hash)
                        {
                            entry.data.extend_from_slice(&plaintext);
                        } else {
                            self.split_recv_buf.push(SplitRecvEntry {
                                link_id,
                                original_hash,
                                data: plaintext,
                            });
                        }
                        return IngestOutcome {
                            events: vec![NodeEvent::ResourceProgress {
                                link_id,
                                resource_hash: oh_trunc,
                                current: split_index,
                                total: split_total,
                            }],
                            packets,
                        };
                    } else if split_total > 1 && split_index == split_total {
                        // Final split segment: concatenate all buffered data
                        let mut full_data = Vec::new();
                        if let Some(idx) = self.split_recv_buf.iter().position(|e| {
                            e.link_id == link_id && e.original_hash == original_hash
                        }) {
                            let entry = self.split_recv_buf.swap_remove(idx);
                            full_data = entry.data;
                        }
                        full_data.extend_from_slice(&plaintext);
                        return IngestOutcome {
                            events: vec![NodeEvent::ResourceComplete {
                                link_id,
                                resource_hash: oh_trunc,
                                data: full_data,
                            }],
                            packets,
                        };
                    }

                    // Non-split resource: deliver directly
                    // If this is a response-as-resource, parse and emit ResponseReceived
                    if is_response {
                        if let Ok((req_id, resp_data)) = rete_transport::parse_response(&plaintext) {
                            self.pending_requests.retain(|r| r.request_id != req_id);
                            return IngestOutcome {
                                events: vec![NodeEvent::ResponseReceived {
                                    link_id,
                                    request_id: req_id,
                                    data: resp_data,
                                }],
                                packets,
                            };
                        }
                    }
                    // If this is a request-as-resource, parse and dispatch
                    if is_request {
                        if let Ok((requested_at, path_hash, req_data)) =
                            rete_transport::parse_request(&plaintext)
                        {
                            let request_id = rete_transport::request_id(&plaintext);
                            let mut handler_packets =
                                self.dispatch_request_handler(&link_id, &request_id, &path_hash, &req_data, requested_at, rng);
                            packets.append(&mut handler_packets);
                            return IngestOutcome {
                                events: vec![NodeEvent::RequestReceived {
                                    link_id,
                                    request_id,
                                    path_hash,
                                    data: req_data,
                                }],
                                packets,
                            };
                        }
                    }
                    return IngestOutcome {
                        events: vec![NodeEvent::ResourceComplete {
                            link_id,
                            resource_hash,
                            data: plaintext,
                        }],
                        packets,
                    };
                }
                // Not all parts received yet — drain resource outbound
                for pkt in self.transport.drain_resource_outbound() {
                    packets.push(OutboundPacket::broadcast(pkt));
                }
                // Only send follow-up REQ when the entire window batch has
                // arrived (outstanding_parts == 0). Python does the same:
                // Resource.py line 886 checks `outstanding_parts == 0`.
                if current < total {
                    let window_complete = self
                        .transport
                        .get_resource(&link_id, &resource_hash)
                        .is_some_and(|r| r.is_window_complete());
                    if window_complete {
                        if let Some(res) = self.transport.get_resource_mut(&link_id, &resource_hash)
                        {
                            res.grow_window(true); // assume fast link (localhost/TCP)
                        }
                        if let Some(req_pkt) =
                            self.transport
                                .build_followup_request(&link_id, &resource_hash, rng)
                        {
                            packets.push(OutboundPacket::broadcast(req_pkt));
                        }
                    }
                }
                let mut events = vec![NodeEvent::ResourceProgress {
                    link_id,
                    resource_hash,
                    current,
                    total,
                }];
                // Map response-resource progress to RequestProgress
                if let Some(req) = self.pending_requests.iter_mut().find(|r| {
                    r.link_id == link_id && r.response_resource_hash == Some(resource_hash)
                }) {
                    req.status = super::request_receipt::RequestStatus::Receiving;
                    events.push(NodeEvent::RequestProgress {
                        link_id,
                        request_id: req.request_id,
                        current,
                        total,
                    });
                }
                IngestOutcome { events, packets }
            }
            IngestResult::ResourceComplete {
                link_id,
                resource_hash,
                data,
            } => {
                // Sender received proof — transfer complete on our end
                self.transport.cleanup_resources();
                let mut packets = Vec::new();
                for pkt in self.transport.drain_resource_outbound() {
                    packets.push(OutboundPacket::broadcast(pkt));
                }
                IngestOutcome {
                    events: vec![NodeEvent::ResourceComplete {
                        link_id,
                        resource_hash,
                        data,
                    }],
                    packets,
                }
            }
            IngestResult::ResourceFailed {
                link_id,
                resource_hash,
            } => {
                self.transport.cleanup_resources();
                let mut packets = Vec::new();
                for pkt in self.transport.drain_resource_outbound() {
                    packets.push(OutboundPacket::broadcast(pkt));
                }
                let mut events = vec![NodeEvent::ResourceFailed {
                    link_id,
                    resource_hash,
                }];
                // Map resource failure to RequestFailed (single pass for both response and request resources)
                self.pending_requests.retain(|r| {
                    if r.link_id == link_id
                        && (r.response_resource_hash == Some(resource_hash)
                            || r.request_resource_hash == Some(resource_hash))
                    {
                        events.push(NodeEvent::RequestFailed {
                            link_id,
                            request_id: r.request_id,
                            reason: RequestFailReason::ResourceFailed,
                        });
                        false
                    } else {
                        true
                    }
                });
                IngestOutcome { events, packets }
            }
            IngestResult::ResourceRejected {
                link_id,
                resource_hash,
            } => {
                self.transport.cleanup_resources();
                IngestOutcome {
                    events: vec![NodeEvent::ResourceRejected {
                        link_id,
                        resource_hash,
                    }],
                    packets: Vec::new(),
                }
            }
            IngestResult::PathRequestForward { payload } => {
                // Forward path request to all interfaces as a broadcast
                // Build a path request packet from the payload
                let mut buf = [0u8; MTU];
                let result = PacketBuilder::new(&mut buf)
                    .packet_type(PacketType::Data)
                    .dest_type(DestType::Plain)
                    .destination_hash(&PATH_REQUEST_DEST)
                    .context(rete_core::CONTEXT_NONE)
                    .payload(&payload)
                    .build();
                match result {
                    Ok(n) => IngestOutcome {
                        events: vec![],
                        packets: vec![OutboundPacket::broadcast(buf[..n].to_vec())],
                    },
                    Err(_) => IngestOutcome::empty(),
                }
            }
            IngestResult::Duplicate | IngestResult::Invalid => {
                // Drain any resource outbound packets that may have been queued
                let resource_pkts = self.transport.drain_resource_outbound();
                if resource_pkts.is_empty() {
                    IngestOutcome::empty()
                } else {
                    IngestOutcome {
                        events: vec![],
                        packets: resource_pkts
                            .into_iter()
                            .map(OutboundPacket::broadcast)
                            .collect(),
                    }
                }
            }
        }
    }

    /// Dispatch a request through the handler system.
    ///
    /// Reused for both single-packet requests and request-as-resource.
    /// Returns outbound response packets (empty if no handler or no response).
    fn dispatch_request_handler<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        request_id: &[u8; TRUNCATED_HASH_LEN],
        path_hash: &[u8; TRUNCATED_HASH_LEN],
        data: &[u8],
        requested_at: f64,
        rng: &mut R,
    ) -> Vec<OutboundPacket> {
        let mut response_packets = Vec::new();
        let link_meta = self.transport.get_link(link_id).map(|link| {
            let mtu = rete_transport::link::decode_mtu(&link.signalling) as usize;
            let link_mdu = if mtu == 0 {
                rete_transport::link::LINK_MDU
            } else {
                rete_transport::link::compute_link_mdu(mtu)
            };
            (
                link.destination_hash,
                link.identified_identity_hash().copied(),
                link_mdu,
            )
        });
        if let Some((dest_hash, remote_identity, link_mdu)) = link_meta {
            if let Some(handler) = self.find_request_handler(&dest_hash, path_hash) {
                if handler.policy.allows(remote_identity.as_ref()) {
                    let ctx = super::RequestContext {
                        destination_hash: dest_hash,
                        path: &handler.path,
                        path_hash: *path_hash,
                        link_id: *link_id,
                        request_id: *request_id,
                        requested_at,
                        remote_identity,
                    };
                    if let Some(response_data) = handler.handler.handle(&ctx, data) {
                        let final_data = if handler
                            .compression_policy
                            .should_compress(response_data.len())
                        {
                            self.hooks
                                .as_ref()
                                .and_then(|h| h.compress(&response_data))
                                .filter(|c| c.len() < response_data.len())
                                .unwrap_or(response_data)
                        } else {
                            response_data
                        };
                        // Response framing: fixarray(2) + bin8 header(2) + request_id(16) + bin header(up to 3)
                        const RESPONSE_FRAMING_OVERHEAD: usize = 1 + 2 + TRUNCATED_HASH_LEN + 3;
                        if final_data.len() + RESPONSE_FRAMING_OVERHEAD <= link_mdu {
                            if let Ok(pkt) =
                                self.send_response(link_id, request_id, &final_data, rng)
                            {
                                response_packets.push(pkt);
                            }
                        } else {
                            if let Ok(pkt) =
                                self.start_response_resource(link_id, request_id, &final_data, rng)
                            {
                                response_packets.push(pkt);
                            }
                            for rpkt in self.transport.drain_resource_outbound() {
                                response_packets.push(OutboundPacket::broadcast(rpkt));
                            }
                        }
                    }
                }
            }
        }
        response_packets
    }

    /// Periodic maintenance: expire paths, collect pending announces, send keepalives.
    pub fn handle_tick<R: RngCore + CryptoRng>(&mut self, now: u64, rng: &mut R) -> IngestOutcome {
        let mut packets = self.flush_announces(now, rng);

        // Resource maintenance: send HMU for sender resources with unsent hashes
        self.transport.tick_resources(now, rng);

        // Drain any resource outbound packets queued during ingest or tick_resources
        for pkt in self.transport.drain_resource_outbound() {
            packets.push(OutboundPacket::broadcast(pkt));
        }

        // Send keepalives BEFORE tick — tick may mark links Stale, which would
        // prevent build_keepalive_packet from working (it requires Active state).
        // With dynamic keepalive on fast links, keepalive_interval can be as low
        // as 5s, which equals TICK_INTERVAL. Sending keepalives first ensures
        // they go out before the stale check.
        for ka in self.transport.build_pending_keepalives(now, rng) {
            packets.push(OutboundPacket::broadcast(ka));
        }

        // Channel retransmissions
        for retx in self.transport.pending_channel_retransmits(now, rng) {
            packets.push(OutboundPacket::broadcast(retx));
        }

        // Now run tick: expire paths, check stale links, etc.
        let result = self.transport.tick(now);

        // Check request timeouts
        let mut events = self.check_request_timeouts(now);

        events.push(NodeEvent::Tick {
            expired_paths: result.expired_paths,
            closed_links: result.closed_links,
        });

        IngestOutcome { events, packets }
    }

    /// Check pending requests for timeout and return timeout events.
    fn check_request_timeouts(&mut self, now: u64) -> Vec<NodeEvent> {
        use super::request_receipt::RequestStatus;

        let mut events = Vec::new();
        self.pending_requests.retain(|req| {
            if matches!(req.status, RequestStatus::Sent | RequestStatus::Receiving)
                && now.saturating_sub(req.sent_at) > req.timeout_secs
            {
                events.push(NodeEvent::RequestFailed {
                    link_id: req.link_id,
                    request_id: req.request_id,
                    reason: RequestFailReason::Timeout,
                });
                false // remove timed-out request
            } else {
                true
            }
        });
        events
    }
}
