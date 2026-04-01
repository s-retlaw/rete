//! Inbound packet dispatch, request handling, and resource buffering.

use alloc::vec;
use alloc::vec::Vec;

use rand_core::{CryptoRng, RngCore};
use rete_core::{
    DestType, Identity, PacketBuilder, PacketType, MTU, TRUNCATED_HASH_LEN,
};
use rete_transport::{IngestResult, PATH_REQUEST_DEST};

use crate::destination::DestinationType;
use crate::{NodeEvent, ProofStrategy};

use super::{IngestOutcome, NodeCore, OutboundPacket, PacketRouting, SplitRecvEntry};

impl<const P: usize, const A: usize, const D: usize, const L: usize> NodeCore<P, A, D, L> {
    /// Process an inbound raw packet and return the outcome.
    ///
    /// The runtime loop dispatches packets based on `IngestOutcome.packets`
    /// routing and emits `IngestOutcome.event` to the application callback.
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
        if let Some(log_fn) = self.packet_log_fn {
            log_fn(raw, "IN", iface);
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
                    event: Some(NodeEvent::AnnounceReceived {
                        dest_hash,
                        identity_hash,
                        hops,
                        app_data: app_data.map(|d| d.to_vec()),
                    }),
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
                let decrypted = match dest.dest_type {
                    DestinationType::Plain => payload.to_vec(),
                    DestinationType::Single => {
                        let mut privkeys = Vec::new();
                        if let Some(store) = &self.ratchet_store {
                            if let Some(k) = store.local_ratchet_private() {
                                privkeys.push(k);
                            }
                            privkeys.extend_from_slice(store.previous_ratchet_privates());
                        }
                        if !privkeys.is_empty() {
                            match self.identity.decrypt_with_ratchets(
                                payload,
                                &privkeys,
                                false,
                                &mut dec_buf,
                            ) {
                                Ok((n, _)) => dec_buf[..n].to_vec(),
                                Err(_) => return IngestOutcome::empty(),
                            }
                        } else {
                            match self.identity.decrypt(payload, &mut dec_buf) {
                                Ok(n) => dec_buf[..n].to_vec(),
                                Err(_) => return IngestOutcome::empty(),
                            }
                        }
                    }
                    DestinationType::Group => {
                        match dest.decrypt(payload, &mut dec_buf) {
                            Ok(n) => dec_buf[..n].to_vec(),
                            Err(_) => return IngestOutcome::empty(),
                        }
                    }
                    DestinationType::Link => return IngestOutcome::empty(),
                };

                let mut packets = Vec::new();

                let should_prove = match proof_strategy {
                    ProofStrategy::ProveAll => true,
                    ProofStrategy::ProveApp => {
                        if let Some(f) = self.prove_app_fn {
                            f(&dest_hash, &packet_hash, &decrypted)
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
                    event: Some(NodeEvent::DataReceived {
                        dest_hash,
                        payload: decrypted,
                    }),
                    packets,
                }
            }
            IngestResult::Forward { raw, .. } => IngestOutcome {
                event: None,
                packets: vec![OutboundPacket {
                    data: raw.to_vec(),
                    routing: PacketRouting::AllExceptSource,
                }],
            },
            IngestResult::LinkRequestReceived { link_id, proof_raw } => IngestOutcome {
                event: Some(NodeEvent::LinkEstablished { link_id }),
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
                    event: Some(NodeEvent::LinkEstablished { link_id }),
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
                                event: Some(NodeEvent::LinkIdentified {
                                    link_id,
                                    identity_hash: id_hash,
                                    public_key: pub_key,
                                }),
                                packets,
                            };
                        }
                    }
                }
                IngestOutcome {
                    event: Some(NodeEvent::LinkData {
                        link_id,
                        data,
                        context,
                    }),
                    packets,
                }
            }
            IngestResult::ChannelMessages {
                link_id,
                messages,
                packet_hash,
            } => IngestOutcome {
                event: Some(NodeEvent::ChannelMessages {
                    link_id,
                    messages: messages
                        .into_iter()
                        .map(|e| (e.message_type, e.payload))
                        .collect(),
                }),
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
                // Extract link metadata (dest_hash + identified identity) before
                // borrowing self for handler lookup.
                let mut response_packets = Vec::new();
                let link_meta = self.transport.get_link(&link_id).map(|link| {
                    (
                        link.destination_hash,
                        link.identified_identity_hash().copied(),
                    )
                });
                if let Some((dest_hash, remote_identity)) = link_meta {
                    if let Some(handler) =
                        self.find_request_handler(&dest_hash, &path_hash)
                    {
                        if handler.policy.allows(remote_identity.as_ref()) {
                            let ctx = super::RequestContext {
                                destination_hash: dest_hash,
                                path: &handler.path,
                                path_hash,
                                link_id,
                                request_id,
                                requested_at,
                                remote_identity,
                            };
                            if let Some(response_data) = (handler.handler)(&ctx, &data) {
                                let final_data = if handler
                                    .compression_policy
                                    .should_compress(response_data.len())
                                {
                                    self.compress_fn
                                        .and_then(|f| f(&response_data))
                                        .filter(|c| c.len() < response_data.len())
                                        .unwrap_or(response_data)
                                } else {
                                    response_data
                                };
                                if let Ok(pkt) = self.send_response(
                                    &link_id,
                                    &request_id,
                                    &final_data,
                                    rng,
                                ) {
                                    response_packets.push(pkt);
                                }
                            }
                        }
                    }
                }
                IngestOutcome {
                    event: Some(NodeEvent::RequestReceived {
                        link_id,
                        request_id,
                        path_hash,
                        data,
                    }),
                    packets: response_packets,
                }
            }
            IngestResult::ResponseReceived {
                link_id,
                request_id,
                data,
            } => IngestOutcome {
                event: Some(NodeEvent::ResponseReceived {
                    link_id,
                    request_id,
                    data,
                }),
                packets: Vec::new(),
            },
            IngestResult::LinkClosed { link_id } => IngestOutcome {
                event: Some(NodeEvent::LinkClosed { link_id }),
                packets: Vec::new(),
            },
            IngestResult::ProofReceived { packet_hash } => IngestOutcome {
                event: Some(NodeEvent::ProofReceived { packet_hash }),
                packets: Vec::new(),
            },
            IngestResult::Buffered {
                packet_hash,
                link_id,
            } => IngestOutcome {
                event: None,
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
            } => {
                // Auto-accept: send first request
                let mut packets = Vec::new();
                if let Some(pkt) = self
                    .transport
                    .accept_resource(&link_id, &resource_hash, rng)
                {
                    packets.push(OutboundPacket::broadcast(pkt));
                }
                // Drain any resource outbound packets queued during ingest
                for pkt in self.transport.drain_resource_outbound() {
                    packets.push(OutboundPacket::broadcast(pkt));
                }
                IngestOutcome {
                    event: Some(NodeEvent::ResourceOffered {
                        link_id,
                        resource_hash,
                        total_size,
                    }),
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
                // If all parts received, assemble and send proof
                if current == total && total > 0 {
                    // Step 1: Assemble encrypted parts, get flags and split metadata
                    let (assembly_result, is_compressed, split_index, split_total, original_hash) = {
                        if let Some(res) = self.transport.get_resource_mut(&link_id, &resource_hash)
                        {
                            let compressed = res.flags.compressed;
                            let si = res.split_index;
                            let st = res.split_total;
                            let oh = res.original_hash;
                            match res.assemble() {
                                Ok(data) => (Some(Ok(data)), compressed, si, st, oh),
                                Err(_) => (Some(Err(())), compressed, si, st, oh),
                            }
                        } else {
                            (None, false, 1, 1, [0u8; 32])
                        }
                    };

                    if let Some(Ok(encrypted_data)) = assembly_result {
                        // Step 2: Decrypt via link Token, strip 4-byte random prepend
                        let decrypted = if let Some(link) = self.transport.get_link(&link_id) {
                            let mut dec_buf = vec![0u8; encrypted_data.len()];
                            if let Ok(dec_len) = link.decrypt(&encrypted_data, &mut dec_buf) {
                                dec_buf.truncate(dec_len);
                                if dec_buf.len() >= 4 {
                                    dec_buf.drain(..4);
                                }
                                dec_buf
                            } else {
                                encrypted_data
                            }
                        } else {
                            encrypted_data
                        };

                        // Step 3: Decompress if compressed flag is set
                        let plaintext = if is_compressed {
                            if let Some(decompress) = self.decompress_fn {
                                decompress(&decrypted).unwrap_or(decrypted)
                            } else {
                                decrypted
                            }
                        } else {
                            decrypted
                        };

                        // Step 4: Move plaintext into resource, build proof, take it back
                        // Proof = SHA-256(plaintext || resource_hash) — must match Python
                        let (proof, plaintext) = if let Some(res) =
                            self.transport.get_resource_mut(&link_id, &resource_hash)
                        {
                            res.data = plaintext;
                            let proof = res.build_proof();
                            (proof, core::mem::take(&mut res.data))
                        } else {
                            (Vec::new(), plaintext)
                        };

                        // Step 5: Build and send proof packet
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

                        // Step 6: Handle split resources
                        // Truncate original_hash to 16 bytes for NodeEvent resource_hash field
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
                                event: Some(NodeEvent::ResourceProgress {
                                    link_id,
                                    resource_hash: oh_trunc,
                                    current: split_index,
                                    total: split_total,
                                }),
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
                                event: Some(NodeEvent::ResourceComplete {
                                    link_id,
                                    resource_hash: oh_trunc,
                                    data: full_data,
                                }),
                                packets,
                            };
                        }

                        // Non-split resource: deliver directly
                        return IngestOutcome {
                            event: Some(NodeEvent::ResourceComplete {
                                link_id,
                                resource_hash,
                                data: plaintext,
                            }),
                            packets,
                        };
                    } else if let Some(Err(())) = assembly_result {
                        for pkt in self.transport.drain_resource_outbound() {
                            packets.push(OutboundPacket::broadcast(pkt));
                        }
                        self.transport.cleanup_resources();

                        // Clean up split buffer on failure
                        if split_total > 1 {
                            if let Some(idx) = self.split_recv_buf.iter().position(|e| {
                                e.link_id == link_id && e.original_hash == original_hash
                            }) {
                                self.split_recv_buf.swap_remove(idx);
                            }
                        }

                        return IngestOutcome {
                            event: Some(NodeEvent::ResourceFailed {
                                link_id,
                                resource_hash,
                            }),
                            packets,
                        };
                    }
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
                IngestOutcome {
                    event: Some(NodeEvent::ResourceProgress {
                        link_id,
                        resource_hash,
                        current,
                        total,
                    }),
                    packets,
                }
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
                    event: Some(NodeEvent::ResourceComplete {
                        link_id,
                        resource_hash,
                        data,
                    }),
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
                IngestOutcome {
                    event: Some(NodeEvent::ResourceFailed {
                        link_id,
                        resource_hash,
                    }),
                    packets,
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
                        event: None,
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
                        event: None,
                        packets: resource_pkts
                            .into_iter()
                            .map(OutboundPacket::broadcast)
                            .collect(),
                    }
                }
            }
        }
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

        IngestOutcome {
            event: Some(NodeEvent::Tick {
                expired_paths: result.expired_paths,
                closed_links: result.closed_links,
            }),
            packets,
        }
    }
}
