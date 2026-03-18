//! NodeCore — shared node logic extracted from TokioNode and EmbassyNode.
//!
//! This struct owns the identity, transport state, and destination configuration.
//! Runtime wrappers (TokioNode, EmbassyNode) become thin shells that provide
//! async event loops and timer management, delegating all packet processing
//! to NodeCore.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use rand_core::{CryptoRng, RngCore};
use rete_core::{
    DestType, HeaderType, Identity, Packet, PacketBuilder, PacketType, MTU, TRUNCATED_HASH_LEN,
};
use rete_transport::{IngestResult, PendingAnnounce, Transport, RECEIPT_TIMEOUT};

use crate::destination::{Destination, DestinationType, Direction};
use crate::{NodeEvent, ProofStrategy};

// ---------------------------------------------------------------------------
// OutboundPacket + PacketRouting
// ---------------------------------------------------------------------------

/// How to route an outbound packet across interfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketRouting {
    /// Send only on the interface the inbound packet arrived on.
    SourceInterface,
    /// Send on all interfaces except the source.
    AllExceptSource,
    /// Send on all interfaces.
    All,
}

/// A packet to be sent, with routing instructions.
#[derive(Debug, Clone)]
pub struct OutboundPacket {
    /// Raw packet bytes.
    pub data: Vec<u8>,
    /// How to route this packet.
    pub routing: PacketRouting,
}

impl OutboundPacket {
    /// Create a packet to be sent on all interfaces.
    pub fn broadcast(data: Vec<u8>) -> Self {
        OutboundPacket {
            data,
            routing: PacketRouting::All,
        }
    }
}

// ---------------------------------------------------------------------------
// IngestOutcome
// ---------------------------------------------------------------------------

/// Result of processing an inbound packet or tick through NodeCore.
#[derive(Debug)]
pub struct IngestOutcome {
    /// Event to emit to the application (if any).
    pub event: Option<NodeEvent>,
    /// Packets to send out.
    pub packets: Vec<OutboundPacket>,
}

impl IngestOutcome {
    /// Empty outcome — nothing to do.
    fn empty() -> Self {
        IngestOutcome {
            event: None,
            packets: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// NodeCore
// ---------------------------------------------------------------------------

/// Shared node logic, parameterized by Transport const generics.
///
/// `P` = max paths, `A` = max announces, `D` = dedup window size, `L` = max links.
pub struct NodeCore<const P: usize, const A: usize, const D: usize, const L: usize> {
    /// The local identity for this node.
    pub identity: Identity,
    /// Transport state (path table, announce queue, dedup).
    pub transport: Transport<P, A, D, L>,
    /// Primary destination (addressing metadata, proof strategy, app data).
    primary_dest: Destination,
    /// Additional registered destinations (e.g. LXMF delivery).
    additional_dests: Vec<Destination>,
    /// Optional auto-reply message sent after receiving an announce.
    auto_reply: Option<Vec<u8>>,
    /// When true, echo received DATA back to sender with "echo:" prefix.
    echo_data: bool,
    /// Dest hash of the most recently announced peer (echo target).
    last_peer: Option<[u8; TRUNCATED_HASH_LEN]>,
}

/// Compute (dest_hash, name_hash) for a given identity + app_name + aspects.
fn compute_dest_hashes(
    identity: &Identity,
    app_name: &str,
    aspects: &[&str],
) -> ([u8; TRUNCATED_HASH_LEN], [u8; rete_core::NAME_HASH_LEN]) {
    use sha2::{Digest, Sha256};

    let mut name_buf = [0u8; 128];
    let expanded = rete_core::expand_name(app_name, aspects, &mut name_buf)
        .expect("app_name + aspects must fit in 128 bytes");
    let id_hash = identity.hash();
    let dest_hash = rete_core::destination_hash(expanded, Some(&id_hash));

    let name_hash_full = Sha256::digest(expanded.as_bytes());
    let mut name_hash = [0u8; rete_core::NAME_HASH_LEN];
    name_hash.copy_from_slice(&name_hash_full[..rete_core::NAME_HASH_LEN]);

    (dest_hash, name_hash)
}

impl<const P: usize, const A: usize, const D: usize, const L: usize> NodeCore<P, A, D, L> {
    /// Create a new NodeCore with the given identity and destination.
    pub fn new(identity: Identity, app_name: &str, aspects: &[&str]) -> Self {
        let (dest_hash, name_hash) = compute_dest_hashes(&identity, app_name, aspects);

        let primary_dest = Destination::from_hashes(
            DestinationType::Single,
            Direction::In,
            app_name,
            aspects,
            dest_hash,
            name_hash,
        );

        let mut transport = Transport::new();
        transport.add_local_destination(dest_hash);

        NodeCore {
            identity,
            transport,
            primary_dest,
            additional_dests: Vec::new(),
            auto_reply: None,
            echo_data: false,
            last_peer: None,
        }
    }

    /// Enable transport mode: forward HEADER_2 packets for other nodes.
    pub fn enable_transport(&mut self) {
        self.transport.set_local_identity(self.identity.hash());
    }

    /// Returns our destination hash.
    pub fn dest_hash(&self) -> &[u8; TRUNCATED_HASH_LEN] {
        self.primary_dest.hash()
    }

    /// Returns a reference to the node's identity (for signing, etc.).
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Set an auto-reply message sent to any peer that announces.
    pub fn set_auto_reply(&mut self, msg: Option<Vec<u8>>) {
        self.auto_reply = msg;
    }

    /// Enable echo mode: received DATA is sent back to the sender with "echo:" prefix.
    pub fn set_echo_data(&mut self, echo: bool) {
        self.echo_data = echo;
    }

    /// Returns a reference to the primary destination.
    pub fn primary_dest(&self) -> &Destination {
        &self.primary_dest
    }

    /// Returns a mutable reference to the primary destination.
    pub fn primary_dest_mut(&mut self) -> &mut Destination {
        &mut self.primary_dest
    }

    /// Set the proof generation strategy for incoming data packets.
    pub fn set_proof_strategy(&mut self, strategy: ProofStrategy) {
        self.primary_dest.set_proof_strategy(strategy);
    }

    /// Set default application data included in announces.
    pub fn set_default_app_data(&mut self, data: Option<Vec<u8>>) {
        self.primary_dest.set_default_app_data(data);
    }

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
        self.last_peer = Some(peer_dest_hash);
    }

    /// Build an encrypted DATA packet addressed to a known destination.
    ///
    /// Also registers a receipt for proof tracking. The `now` timestamp is
    /// used for receipt timeout calculation.
    pub fn build_data_packet<R: RngCore + CryptoRng>(
        &mut self,
        dest_hash: &[u8; TRUNCATED_HASH_LEN],
        plaintext: &[u8],
        rng: &mut R,
        now: u64,
    ) -> Option<Vec<u8>> {
        let pub_key = *self.transport.recall_identity(dest_hash)?;
        let recipient = Identity::from_public_key(&pub_key).ok()?;
        let mut ct_buf = [0u8; MTU];
        let ct_len = recipient.encrypt(plaintext, rng, &mut ct_buf).ok()?;
        let via = self.transport.get_path(dest_hash).and_then(|p| p.via);
        let mut pkt_buf = [0u8; MTU];
        let builder = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Single)
            .destination_hash(dest_hash)
            .context(0x00)
            .payload(&ct_buf[..ct_len]);
        let builder = if let Some(transport_id) = via {
            builder
                .header_type(HeaderType::Header2)
                .transport_type(1)
                .transport_id(&transport_id)
        } else {
            builder
        };
        let pkt_len = builder.build().ok()?;

        // Register receipt for proof tracking
        if let Ok(parsed) = Packet::parse(&pkt_buf[..pkt_len]) {
            let pkt_hash = parsed.compute_hash();
            self.transport
                .register_receipt(pkt_hash, pub_key, now, RECEIPT_TIMEOUT);
        }

        Some(pkt_buf[..pkt_len].to_vec())
    }

    /// Build and return a raw announce packet for this node.
    pub fn build_announce<R: RngCore + CryptoRng>(
        &self,
        app_data: Option<&[u8]>,
        rng: &mut R,
        now: u64,
    ) -> Vec<u8> {
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
        )
        .expect("announce creation should not fail");
        buf[..n].to_vec()
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
        // Find the destination's app_name and aspects
        let (app_name, aspects) = if *self.primary_dest.hash() == *dest_hash {
            (
                self.primary_dest.app_name.clone(),
                self.primary_dest.aspects.clone(),
            )
        } else if let Some(dest) = self
            .additional_dests
            .iter()
            .find(|d| d.dest_hash == *dest_hash)
        {
            (dest.app_name.clone(), dest.aspects.clone())
        } else {
            return false;
        };

        let aspects_refs: Vec<&str> = aspects.iter().map(|s| s.as_str()).collect();
        let mut buf = [0u8; MTU];
        let n = match Transport::<P, A, D, L>::create_announce(
            &self.identity,
            &app_name,
            &aspects_refs,
            app_data,
            rng,
            now,
            &mut buf,
        ) {
            Ok(n) => n,
            Err(_) => return false,
        };
        let mut raw = heapless::Vec::new();
        if raw.extend_from_slice(&buf[..n]).is_err() {
            return false;
        }
        self.transport.queue_announce(PendingAnnounce {
            dest_hash: *dest_hash,
            raw,
            tx_count: 0,
            last_tx_at: 0,
            local: true,
        })
    }

    /// Drain pending announces from the transport queue, returning them as outbound packets.
    ///
    /// Call after `queue_announce()` to flush the announce immediately, or rely
    /// on `handle_tick()` which calls this internally.
    pub fn flush_announces(&mut self, now: u64) -> Vec<OutboundPacket> {
        self.transport
            .pending_outbound(now)
            .into_iter()
            .map(|raw| OutboundPacket::broadcast(raw.to_vec()))
            .collect()
    }

    /// Initiate a link to a destination.
    ///
    /// Returns the outbound LINKREQUEST packet and the link_id on success.
    pub fn initiate_link<R: RngCore + CryptoRng>(
        &mut self,
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        now: u64,
        rng: &mut R,
    ) -> Option<(OutboundPacket, [u8; TRUNCATED_HASH_LEN])> {
        let (raw, link_id) = self
            .transport
            .initiate_link(dest_hash, &self.identity, rng, now)?;
        Some((OutboundPacket::broadcast(raw), link_id))
    }

    /// Send a channel message on a link.
    ///
    /// Returns the outbound packet if the message was queued, or `None` if
    /// the link is not active or the channel window is full.
    pub fn send_channel_message<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        message_type: u16,
        payload: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Option<OutboundPacket> {
        let raw = self
            .transport
            .send_channel_message(link_id, message_type, payload, now, rng)?;
        Some(OutboundPacket::broadcast(raw))
    }

    /// Send stream data on a link via channel.
    ///
    /// Packs a `StreamDataMessage` and sends it as a channel message with
    /// `MSG_TYPE_STREAM`. Uses stack buffer to avoid intermediate heap allocations.
    pub fn send_stream_data<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        stream_id: u16,
        data: &[u8],
        eof: bool,
        now: u64,
        rng: &mut R,
    ) -> Option<OutboundPacket> {
        let mut buf = [0u8; MTU];
        let n = rete_transport::StreamDataMessage::pack_into(stream_id, eof, false, data, &mut buf);
        self.send_channel_message(
            link_id,
            rete_transport::MSG_TYPE_STREAM,
            &buf[..n],
            now,
            rng,
        )
    }

    /// Send plain data over an established link.
    pub fn send_link_data<R: RngCore + CryptoRng>(
        &self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        data: &[u8],
        rng: &mut R,
    ) -> Option<OutboundPacket> {
        let pkt = self
            .transport
            .build_link_data_packet(link_id, data, rete_core::CONTEXT_NONE, rng)?;
        Some(OutboundPacket::broadcast(pkt))
    }

    /// Start a resource transfer on a link.
    ///
    /// Returns the outbound advertisement packet.
    pub fn start_resource<R: RngCore + CryptoRng>(
        &mut self,
        link_id: &[u8; TRUNCATED_HASH_LEN],
        data: &[u8],
        rng: &mut R,
    ) -> Option<OutboundPacket> {
        let pkt = self.transport.start_resource(link_id, data, rng)?;
        Some(OutboundPacket::broadcast(pkt))
    }

    /// Build a path request packet for a destination.
    pub fn request_path(&self, dest_hash: &[u8; TRUNCATED_HASH_LEN]) -> OutboundPacket {
        let raw = Transport::<P, A, D, L>::build_path_request(dest_hash);
        OutboundPacket::broadcast(raw)
    }

    /// Build a proof OutboundPacket for a received packet hash, if possible.
    fn proof_outbound(&self, packet_hash: &[u8; 32]) -> Option<OutboundPacket> {
        Transport::<P, A, D, L>::build_proof_packet(&self.identity, packet_hash).map(|data| {
            OutboundPacket {
                data,
                routing: PacketRouting::SourceInterface,
            }
        })
    }

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
        if len > MTU {
            return IngestOutcome::empty();
        }
        let mut pkt_buf = [0u8; MTU];
        pkt_buf[..len].copy_from_slice(raw);

        match self
            .transport
            .ingest_on(&mut pkt_buf[..len], now, iface, rng, &self.identity)
        {
            IngestResult::AnnounceReceived {
                dest_hash,
                identity_hash,
                hops,
                app_data,
            } => {
                self.last_peer = Some(dest_hash);
                let mut packets = Vec::new();

                // Auto-reply to announcing peer
                if let Some(msg) = self.auto_reply.take() {
                    let result = self.build_data_packet(&dest_hash, &msg, rng, now);
                    self.auto_reply = Some(msg);
                    if let Some(pkt) = result {
                        packets.push(OutboundPacket {
                            data: pkt,
                            routing: PacketRouting::SourceInterface,
                        });
                    }
                }

                // Flush pending announces (retransmissions) to all interfaces
                packets.extend(self.flush_announces(now));

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
                // Transport already verified this is one of our local destinations.
                // Single lookup to get the proof strategy.
                let proof_strategy = self
                    .get_destination(&dest_hash)
                    .map(|d| d.proof_strategy)
                    .unwrap_or(ProofStrategy::ProveNone);

                let mut dec_buf = [0u8; MTU];
                let decrypted = match self.identity.decrypt(payload, &mut dec_buf) {
                    Ok(n) => dec_buf[..n].to_vec(),
                    Err(_) => payload.to_vec(),
                };

                let mut packets = Vec::new();

                if proof_strategy == ProofStrategy::ProveAll {
                    packets.extend(self.proof_outbound(&packet_hash));
                }

                // Echo data back to sender if echo mode is on
                if self.echo_data {
                    if let Some(peer) = self.last_peer {
                        let mut echo_msg = Vec::with_capacity(5 + decrypted.len());
                        echo_msg.extend_from_slice(b"echo:");
                        echo_msg.extend_from_slice(&decrypted);
                        if let Some(pkt) = self.build_data_packet(&peer, &echo_msg, rng, now) {
                            packets.push(OutboundPacket {
                                data: pkt,
                                routing: PacketRouting::SourceInterface,
                            });
                        }
                    }
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
                    if let Some(pkt) = self.transport.build_lrrtt_packet(&link_id, rtt_bytes, rng) {
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
                    if let Some(pkt) = self.transport.build_keepalive_packet(&link_id, false, rng) {
                        packets.push(OutboundPacket::broadcast(pkt));
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
                // Auto-prove received channel packets (transport-layer delivery proof)
                packets: self.proof_outbound(&packet_hash).into_iter().collect(),
            },
            IngestResult::LinkClosed { link_id } => IngestOutcome {
                event: Some(NodeEvent::LinkClosed { link_id }),
                packets: Vec::new(),
            },
            IngestResult::ProofReceived { packet_hash } => IngestOutcome {
                event: Some(NodeEvent::ProofReceived { packet_hash }),
                packets: Vec::new(),
            },
            IngestResult::Buffered { packet_hash } => IngestOutcome {
                event: None,
                // Auto-prove buffered channel packets too (transport ACK ≠ application delivery)
                packets: self.proof_outbound(&packet_hash).into_iter().collect(),
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
                    // Step 1: assemble data and build proof (borrows transport mutably)
                    let assembly_result = {
                        if let Some(res) = self.transport.get_resource_mut(&link_id, &resource_hash)
                        {
                            match res.assemble() {
                                Ok(data) => {
                                    let proof = res.build_proof();
                                    Some(Ok((data, proof)))
                                }
                                Err(_) => Some(Err(())),
                            }
                        } else {
                            None
                        }
                    };
                    // Step 2: Decrypt assembled data via link Token, strip 4-byte prepend.
                    // Python flow: link.decrypt() -> bz2.decompress() -> strip 4 prepend bytes
                    // We skip decompression for now (app layer can handle it).
                    if let Some(Ok((encrypted_data, proof))) = assembly_result {
                        // Decrypt via link Token
                        let data = if let Some(link) = self.transport.get_link(&link_id) {
                            let mut dec_buf = vec![0u8; encrypted_data.len()];
                            if let Ok(dec_len) = link.decrypt(&encrypted_data, &mut dec_buf) {
                                // Strip 4-byte random prepend
                                if dec_len >= 4 {
                                    dec_buf[4..dec_len].to_vec()
                                } else {
                                    dec_buf[..dec_len].to_vec()
                                }
                            } else {
                                // Decryption failed — return encrypted data as-is
                                // (might be from our own Rust sender without encryption)
                                encrypted_data
                            }
                        } else {
                            encrypted_data
                        };

                        // Step 3: Build and send proof packet.
                        // Resource proof is Proof packet type, NOT link-encrypted.
                        // Matches Python: packet_type=PROOF, context=RESOURCE_PRF,
                        // and "Resource proofs are not encrypted" in Packet.pack().
                        {
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
                        // Clean up completed receiver resource so it doesn't
                        // interfere with subsequent resource operations on this link
                        self.transport.cleanup_resources();
                        return IngestOutcome {
                            event: Some(NodeEvent::ResourceComplete {
                                link_id,
                                resource_hash,
                                data,
                            }),
                            packets,
                        };
                    } else if let Some(Err(())) = assembly_result {
                        for pkt in self.transport.drain_resource_outbound() {
                            packets.push(OutboundPacket::broadcast(pkt));
                        }
                        self.transport.cleanup_resources();
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
        let result = self.transport.tick(now);
        let mut packets = self.flush_announces(now);

        // Drain any resource outbound packets queued during ingest
        for pkt in self.transport.drain_resource_outbound() {
            packets.push(OutboundPacket::broadcast(pkt));
        }

        // Send keepalives for idle links
        for ka in self.transport.build_pending_keepalives(now, rng) {
            packets.push(OutboundPacket::broadcast(ka));
        }

        // Channel retransmissions
        for retx in self.transport.pending_channel_retransmits(now, rng) {
            packets.push(OutboundPacket::broadcast(retx));
        }

        IngestOutcome {
            event: Some(NodeEvent::Tick {
                expired_paths: result.expired_paths,
                closed_links: result.closed_links,
            }),
            packets,
        }
    }
}

/// Hosted node core (generous memory for desktop/gateway).
pub type HostedNodeCore = NodeCore<
    { rete_transport::HOSTED_MAX_PATHS },
    { rete_transport::HOSTED_MAX_ANNOUNCES },
    { rete_transport::HOSTED_DEDUP_WINDOW },
    { rete_transport::HOSTED_MAX_LINKS },
>;

/// Embedded node core (conservative memory for MCUs).
pub type EmbeddedNodeCore = NodeCore<
    { rete_transport::EMBEDDED_MAX_PATHS },
    { rete_transport::EMBEDDED_MAX_ANNOUNCES },
    { rete_transport::EMBEDDED_DEDUP_WINDOW },
    { rete_transport::EMBEDDED_MAX_LINKS },
>;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rete_core::{Packet, PacketType};

    type TestNodeCore = NodeCore<64, 16, 128, 4>;

    fn make_core(seed: &[u8]) -> TestNodeCore {
        let identity = Identity::from_seed(seed).unwrap();
        TestNodeCore::new(identity, "testapp", &["aspect1"])
    }

    #[test]
    fn node_core_new_computes_dest_hash() {
        let core = make_core(b"dest-hash-test");
        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name("testapp", &["aspect1"], &mut name_buf).unwrap();
        let expected = rete_core::destination_hash(expanded, Some(&core.identity.hash()));
        assert_eq!(*core.dest_hash(), expected);
    }

    #[test]
    fn node_core_build_announce_valid() {
        let core = make_core(b"announce-test");
        let mut rng = rand::thread_rng();
        let raw = core.build_announce(None, &mut rng, 1000);
        let pkt = Packet::parse(&raw).unwrap();
        assert_eq!(pkt.packet_type, PacketType::Announce);
        assert_eq!(pkt.destination_hash, core.dest_hash());
    }

    #[test]
    fn node_core_build_data_packet_encrypted() {
        let mut sender = make_core(b"sender-node");
        let receiver = make_core(b"receiver-node");
        let mut rng = rand::thread_rng();

        // Register receiver's identity with sender
        let receiver_id = Identity::from_seed(b"receiver-node").unwrap();
        sender.register_peer(&receiver_id, "testapp", &["aspect1"], 100);

        let pkt = sender
            .build_data_packet(receiver.dest_hash(), b"hello", &mut rng, 100)
            .expect("should build data packet");

        let parsed = Packet::parse(&pkt).unwrap();
        assert_eq!(parsed.packet_type, PacketType::Data);

        // Recipient should be able to decrypt
        let mut dec_buf = [0u8; MTU];
        let n = receiver
            .identity
            .decrypt(parsed.payload, &mut dec_buf)
            .unwrap();
        assert_eq!(&dec_buf[..n], b"hello");
    }

    #[test]
    fn node_core_handle_ingest_announce() {
        let mut core = make_core(b"ingest-announce-node");
        let mut rng = rand::thread_rng();

        // Build an announce from a peer
        let _peer = Identity::from_seed(b"peer-announce").unwrap();
        let peer_core = make_core(b"peer-announce");
        let announce = peer_core.build_announce(None, &mut rng, 1000);

        let outcome = core.handle_ingest(&announce, 1000, 0, &mut rng);
        assert!(matches!(
            outcome.event,
            Some(NodeEvent::AnnounceReceived { .. })
        ));
    }

    #[test]
    fn node_core_handle_ingest_data() {
        let mut core = make_core(b"ingest-data-node");
        let mut rng = rand::thread_rng();

        // Build encrypted DATA addressed to this node
        let node_id = Identity::from_seed(b"ingest-data-node").unwrap();
        let recipient = Identity::from_public_key(&node_id.public_key()).unwrap();
        let plaintext = b"hello node";
        let mut ct_buf = [0u8; MTU];
        let ct_len = recipient.encrypt(plaintext, &mut rng, &mut ct_buf).unwrap();

        let mut pkt_buf = [0u8; MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Single)
            .destination_hash(core.dest_hash())
            .context(0x00)
            .payload(&ct_buf[..ct_len])
            .build()
            .unwrap();

        let outcome = core.handle_ingest(&pkt_buf[..pkt_len], 1000, 0, &mut rng);
        match outcome.event {
            Some(NodeEvent::DataReceived { payload, .. }) => {
                assert_eq!(payload, plaintext);
            }
            other => panic!("expected DataReceived, got {:?}", other),
        }
    }

    #[test]
    fn node_core_handle_ingest_data_with_proof() {
        let mut core = make_core(b"proof-node");
        core.set_proof_strategy(ProofStrategy::ProveAll);
        let mut rng = rand::thread_rng();

        // Build encrypted DATA
        let node_id = Identity::from_seed(b"proof-node").unwrap();
        let recipient = Identity::from_public_key(&node_id.public_key()).unwrap();
        let mut ct_buf = [0u8; MTU];
        let ct_len = recipient
            .encrypt(b"proof me", &mut rng, &mut ct_buf)
            .unwrap();

        let mut pkt_buf = [0u8; MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Single)
            .destination_hash(core.dest_hash())
            .context(0x00)
            .payload(&ct_buf[..ct_len])
            .build()
            .unwrap();

        let outcome = core.handle_ingest(&pkt_buf[..pkt_len], 1000, 0, &mut rng);
        // Should have a proof packet in outcome
        let proof_packets: Vec<_> = outcome
            .packets
            .iter()
            .filter(|p| {
                Packet::parse(&p.data)
                    .map(|pkt| pkt.packet_type == PacketType::Proof)
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(proof_packets.len(), 1, "should generate one proof packet");
        assert_eq!(proof_packets[0].routing, PacketRouting::SourceInterface);
    }

    #[test]
    fn node_core_handle_ingest_data_with_echo() {
        let mut core = make_core(b"echo-node");
        core.set_echo_data(true);
        let mut rng = rand::thread_rng();

        // Register a peer so we have a last_peer to echo back to
        let peer = Identity::from_seed(b"echo-peer").unwrap();
        core.register_peer(&peer, "testapp", &["aspect1"], 100);

        // Build encrypted DATA
        let node_id = Identity::from_seed(b"echo-node").unwrap();
        let recipient = Identity::from_public_key(&node_id.public_key()).unwrap();
        let mut ct_buf = [0u8; MTU];
        let ct_len = recipient.encrypt(b"ping", &mut rng, &mut ct_buf).unwrap();

        let mut pkt_buf = [0u8; MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Single)
            .destination_hash(core.dest_hash())
            .context(0x00)
            .payload(&ct_buf[..ct_len])
            .build()
            .unwrap();

        let outcome = core.handle_ingest(&pkt_buf[..pkt_len], 1000, 0, &mut rng);
        // Should have an echo DATA packet
        let data_packets: Vec<_> = outcome
            .packets
            .iter()
            .filter(|p| {
                Packet::parse(&p.data)
                    .map(|pkt| pkt.packet_type == PacketType::Data)
                    .unwrap_or(false)
            })
            .collect();
        assert!(
            !data_packets.is_empty(),
            "echo mode should produce a DATA packet"
        );
    }

    #[test]
    fn node_core_handle_ingest_forward() {
        let mut core = make_core(b"forward-node");
        core.enable_transport();
        let mut rng = rand::thread_rng();

        let local_hash = core.identity.hash();
        let dest = [0xCC; TRUNCATED_HASH_LEN];
        let next_hop = [0xDD; TRUNCATED_HASH_LEN];
        let path = rete_transport::Path::via_repeater(next_hop, 3, 100);
        core.transport.insert_path(dest, path);

        // Build HEADER_2 DATA addressed through us
        let mut buf = [0u8; MTU];
        let n = PacketBuilder::new(&mut buf)
            .header_type(HeaderType::Header2)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Single)
            .transport_type(1)
            .transport_id(&local_hash)
            .destination_hash(&dest)
            .context(0x00)
            .payload(b"forward me")
            .build()
            .unwrap();

        let outcome = core.handle_ingest(&buf[..n], 100, 0, &mut rng);
        assert!(
            outcome.event.is_none(),
            "forward should not produce an event"
        );
        assert_eq!(outcome.packets.len(), 1);
        assert_eq!(outcome.packets[0].routing, PacketRouting::AllExceptSource);
    }

    #[test]
    fn node_core_handle_tick() {
        let mut core = make_core(b"tick-node");
        let mut rng = rand::thread_rng();

        let outcome = core.handle_tick(1000, &mut rng);
        match outcome.event {
            Some(NodeEvent::Tick { expired_paths, .. }) => {
                assert_eq!(expired_paths, 0);
            }
            other => panic!("expected Tick, got {:?}", other),
        }
    }

    #[test]
    fn node_core_register_peer() {
        let mut core = make_core(b"register-node");
        let mut rng = rand::thread_rng();

        let peer = Identity::from_seed(b"known-peer").unwrap();
        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name("testapp", &["aspect1"], &mut name_buf).unwrap();
        let peer_dest = rete_core::destination_hash(expanded, Some(&peer.hash()));

        core.register_peer(&peer, "testapp", &["aspect1"], 100);

        // Should be able to build data packet to registered peer
        let pkt = core.build_data_packet(&peer_dest, b"hello peer", &mut rng, 100);
        assert!(pkt.is_some(), "should build data packet to registered peer");
    }

    // -----------------------------------------------------------------------
    // Helper: full handshake between two NodeCores
    // -----------------------------------------------------------------------

    /// Set up two NodeCores and perform a full handshake.
    /// Returns (initiator, responder, link_id).
    fn two_core_handshake() -> (TestNodeCore, TestNodeCore, [u8; TRUNCATED_HASH_LEN]) {
        let mut rng = rand::thread_rng();

        // Responder
        let mut resp = make_core(b"resp-core");

        // Initiator — register responder's identity so proof can be verified
        let mut init = make_core(b"init-core");
        let resp_id = Identity::from_seed(b"resp-core").unwrap();
        init.register_peer(&resp_id, "testapp", &["aspect1"], 100);

        // Initiator sends LINKREQUEST
        let (outbound, link_id) = init
            .initiate_link(*resp.dest_hash(), 100, &mut rng)
            .expect("should produce LINKREQUEST");

        // Responder ingests LINKREQUEST → emits LinkEstablished + proof
        let resp_outcome = resp.handle_ingest(&outbound.data, 100, 0, &mut rng);
        assert!(
            matches!(resp_outcome.event, Some(NodeEvent::LinkEstablished { .. })),
            "responder should emit LinkEstablished"
        );
        assert!(
            !resp_outcome.packets.is_empty(),
            "responder should send LRPROOF"
        );
        let proof_pkt = &resp_outcome.packets[0];

        // Initiator ingests LRPROOF → emits LinkEstablished + auto-sends LRRTT
        let init_outcome = init.handle_ingest(&proof_pkt.data, 101, 0, &mut rng);
        assert!(
            matches!(init_outcome.event, Some(NodeEvent::LinkEstablished { .. })),
            "initiator should emit LinkEstablished"
        );

        // Find the LRRTT packet in initiator's outcome
        let lrrtt_pkt = init_outcome
            .packets
            .iter()
            .find(|p| {
                rete_core::Packet::parse(&p.data)
                    .map(|pkt| pkt.context == rete_core::CONTEXT_LRRTT)
                    .unwrap_or(false)
            })
            .expect("initiator should auto-send LRRTT");

        // Responder ingests LRRTT → activates
        let resp_outcome2 = resp.handle_ingest(&lrrtt_pkt.data, 102, 0, &mut rng);
        assert!(
            matches!(resp_outcome2.event, Some(NodeEvent::LinkEstablished { .. })),
            "responder should emit LinkEstablished on LRRTT"
        );

        (init, resp, link_id)
    }

    // -----------------------------------------------------------------------
    // Phase 1: LRRTT auto-send tests
    // -----------------------------------------------------------------------

    #[test]
    fn node_core_link_established_initiator_sends_lrrtt() {
        let mut rng = rand::thread_rng();

        let mut resp = make_core(b"lrrtt-resp");
        let mut init = make_core(b"lrrtt-init");
        let resp_id = Identity::from_seed(b"lrrtt-resp").unwrap();
        init.register_peer(&resp_id, "testapp", &["aspect1"], 100);

        let (outbound, _link_id) = init
            .initiate_link(*resp.dest_hash(), 100, &mut rng)
            .unwrap();

        // Responder ingests LINKREQUEST
        let resp_outcome = resp.handle_ingest(&outbound.data, 100, 0, &mut rng);
        let proof_pkt = &resp_outcome.packets[0];

        // Initiator ingests LRPROOF
        let init_outcome = init.handle_ingest(&proof_pkt.data, 101, 0, &mut rng);

        // Should have LRRTT in packets
        let has_lrrtt = init_outcome.packets.iter().any(|p| {
            rete_core::Packet::parse(&p.data)
                .map(|pkt| pkt.context == rete_core::CONTEXT_LRRTT)
                .unwrap_or(false)
        });
        assert!(has_lrrtt, "initiator should auto-send LRRTT after LRPROOF");
    }

    // -----------------------------------------------------------------------
    // Phase 2: Link initiation tests
    // -----------------------------------------------------------------------

    #[test]
    fn node_core_initiate_link_produces_request() {
        let mut core = make_core(b"init-link-test");
        let mut rng = rand::thread_rng();
        let dest_hash = [0xAA; TRUNCATED_HASH_LEN];

        let (outbound, link_id) = core
            .initiate_link(dest_hash, 100, &mut rng)
            .expect("should produce a link request");

        let parsed = Packet::parse(&outbound.data).unwrap();
        assert_eq!(parsed.packet_type, PacketType::LinkRequest);
        assert_eq!(outbound.routing, PacketRouting::All);
        assert!(core.transport.get_link(&link_id).is_some());
    }

    #[test]
    fn node_core_full_link_lifecycle_two_cores() {
        let (init, resp, link_id) = two_core_handshake();

        // Both links should be active
        let init_link = init.transport.get_link(&link_id).unwrap();
        assert_eq!(init_link.state, rete_transport::LinkState::Active);

        let resp_link = resp.transport.get_link(&link_id).unwrap();
        assert_eq!(resp_link.state, rete_transport::LinkState::Active);
    }

    // -----------------------------------------------------------------------
    // Phase 3: Keepalive tests
    // -----------------------------------------------------------------------

    #[test]
    fn node_core_tick_sends_keepalives() {
        let (mut init, _resp, link_id) = two_core_handshake();
        let mut rng = rand::thread_rng();

        let ka_interval = init
            .transport
            .get_link(&link_id)
            .unwrap()
            .keepalive_interval;

        // Tick with time well past half keepalive interval
        let outcome = init.handle_tick(101 + ka_interval / 2 + 1, &mut rng);
        let has_keepalive = outcome.packets.iter().any(|p| {
            rete_core::Packet::parse(&p.data)
                .map(|pkt| pkt.context == rete_core::CONTEXT_KEEPALIVE)
                .unwrap_or(false)
        });
        assert!(has_keepalive, "tick should produce keepalive packet");
    }

    // -----------------------------------------------------------------------
    // Phase 4: Channel through NodeCore tests
    // -----------------------------------------------------------------------

    #[test]
    fn node_core_channel_send_receive() {
        let (mut init, mut resp, link_id) = two_core_handshake();
        let mut rng = rand::thread_rng();

        // Send channel message from initiator
        let outbound = init
            .send_channel_message(&link_id, 0x42, b"core channel msg", 200, &mut rng)
            .expect("should send channel message");

        // Responder ingests
        let outcome = resp.handle_ingest(&outbound.data, 200, 0, &mut rng);
        match outcome.event {
            Some(NodeEvent::ChannelMessages {
                link_id: lid,
                messages,
            }) => {
                assert_eq!(lid, link_id);
                assert_eq!(messages.len(), 1);
                assert_eq!(messages[0].0, 0x42); // message_type
                assert_eq!(messages[0].1, b"core channel msg"); // payload
            }
            other => panic!("expected ChannelMessages, got {:?}", other),
        }
    }

    #[test]
    fn node_core_channel_in_tick_retransmit() {
        let (mut init, _resp, link_id) = two_core_handshake();
        let mut rng = rand::thread_rng();

        // Send a channel message (sent_at=200)
        let _outbound = init
            .send_channel_message(&link_id, 0x01, b"tick retx", 200, &mut rng)
            .unwrap();

        // Tick before timeout — no retransmit
        let outcome = init.handle_tick(210, &mut rng);
        let channel_pkts: Vec<_> = outcome
            .packets
            .iter()
            .filter(|p| {
                rete_core::Packet::parse(&p.data)
                    .map(|pkt| pkt.context == rete_core::CONTEXT_CHANNEL)
                    .unwrap_or(false)
            })
            .collect();
        assert!(channel_pkts.is_empty(), "no retransmit before timeout");

        // Tick after timeout (15s)
        let outcome = init.handle_tick(216, &mut rng);
        let channel_pkts: Vec<_> = outcome
            .packets
            .iter()
            .filter(|p| {
                rete_core::Packet::parse(&p.data)
                    .map(|pkt| pkt.context == rete_core::CONTEXT_CHANNEL)
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(channel_pkts.len(), 1, "should retransmit one channel msg");
    }

    // -----------------------------------------------------------------------
    // Phase 5: Stream convenience tests
    // -----------------------------------------------------------------------

    #[test]
    fn node_core_stream_data_round_trip() {
        let (mut init, mut resp, link_id) = two_core_handshake();
        let mut rng = rand::thread_rng();

        // Send stream data
        let outbound = init
            .send_stream_data(&link_id, 1, b"stream payload", false, 200, &mut rng)
            .expect("should send stream data");

        // Responder receives it
        let outcome = resp.handle_ingest(&outbound.data, 200, 0, &mut rng);
        match outcome.event {
            Some(NodeEvent::ChannelMessages { messages, .. }) => {
                assert_eq!(messages.len(), 1);
                assert_eq!(messages[0].0, rete_transport::MSG_TYPE_STREAM);
                // Unpack the stream message
                let sdm = rete_transport::StreamDataMessage::unpack(&messages[0].1).unwrap();
                assert_eq!(sdm.stream_id, 1);
                assert_eq!(sdm.data, b"stream payload");
                assert!(!sdm.eof);
            }
            other => panic!("expected ChannelMessages, got {:?}", other),
        }

        // Send EOF segment
        let outbound2 = init
            .send_stream_data(&link_id, 1, b"final", true, 201, &mut rng)
            .expect("should send stream EOF");

        let outcome2 = resp.handle_ingest(&outbound2.data, 201, 0, &mut rng);
        match outcome2.event {
            Some(NodeEvent::ChannelMessages { messages, .. }) => {
                let sdm = rete_transport::StreamDataMessage::unpack(&messages[0].1).unwrap();
                assert_eq!(sdm.stream_id, 1);
                assert!(sdm.eof);
                assert_eq!(sdm.data, b"final");
            }
            other => panic!("expected ChannelMessages, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Phase: Receipt wiring tests
    // -----------------------------------------------------------------------

    #[test]
    fn receipt_auto_registered_on_data_send() {
        let mut sender = make_core(b"receipt-sender");
        let receiver = make_core(b"receipt-receiver");
        let mut rng = rand::thread_rng();

        let receiver_id = Identity::from_seed(b"receipt-receiver").unwrap();
        sender.register_peer(&receiver_id, "testapp", &["aspect1"], 100);

        assert_eq!(sender.transport.receipt_count(), 0);
        let _pkt = sender
            .build_data_packet(receiver.dest_hash(), b"hello", &mut rng, 100)
            .expect("should build data packet");
        assert_eq!(sender.transport.receipt_count(), 1);
    }

    #[test]
    fn proof_for_sent_data_fires_event() {
        let mut sender = make_core(b"proof-fire-sender");
        let mut receiver = make_core(b"proof-fire-receiver");
        receiver.set_proof_strategy(ProofStrategy::ProveAll);
        let mut rng = rand::thread_rng();

        // Register each other
        let receiver_id = Identity::from_seed(b"proof-fire-receiver").unwrap();
        sender.register_peer(&receiver_id, "testapp", &["aspect1"], 100);

        // Sender builds data → receipt auto-registered
        let pkt = sender
            .build_data_packet(receiver.dest_hash(), b"prove me", &mut rng, 100)
            .expect("should build data packet");
        assert_eq!(sender.transport.receipt_count(), 1);

        // Receiver ingests → generates proof
        let outcome = receiver.handle_ingest(&pkt, 100, 0, &mut rng);
        let proof_pkt = outcome
            .packets
            .iter()
            .find(|p| {
                Packet::parse(&p.data)
                    .map(|pkt| pkt.packet_type == PacketType::Proof)
                    .unwrap_or(false)
            })
            .expect("receiver should generate proof");

        // Sender ingests proof → should fire ProofReceived
        let outcome = sender.handle_ingest(&proof_pkt.data, 101, 0, &mut rng);
        assert!(
            matches!(outcome.event, Some(NodeEvent::ProofReceived { .. })),
            "expected ProofReceived, got {:?}",
            outcome.event
        );
    }

    #[test]
    fn receipt_expires_on_tick() {
        let mut sender = make_core(b"receipt-expire");
        let receiver = make_core(b"receipt-expire-recv");
        let mut rng = rand::thread_rng();

        let receiver_id = Identity::from_seed(b"receipt-expire-recv").unwrap();
        sender.register_peer(&receiver_id, "testapp", &["aspect1"], 100);

        let _pkt = sender
            .build_data_packet(receiver.dest_hash(), b"hello", &mut rng, 100)
            .expect("should build data packet");
        assert_eq!(sender.transport.receipt_count(), 1);

        // Tick before timeout — receipt should still be there
        sender.handle_tick(120, &mut rng);
        assert_eq!(sender.transport.receipt_count(), 1);

        // Tick after timeout (30s) — receipt should be failed
        sender.handle_tick(131, &mut rng);
        // Receipt is still in the table but marked Failed
        assert_eq!(sender.transport.receipt_count(), 1);
    }

    // -----------------------------------------------------------------------
    // Phase: Path request origination tests
    // -----------------------------------------------------------------------

    #[test]
    fn path_request_produces_valid_packet() {
        let core = make_core(b"path-req-test");
        let dest = [0xBB; rete_core::TRUNCATED_HASH_LEN];
        let outbound = core.request_path(&dest);
        let parsed = Packet::parse(&outbound.data).unwrap();
        assert_eq!(parsed.packet_type, PacketType::Data);
        assert_eq!(parsed.dest_type, rete_core::DestType::Plain);
        assert_eq!(parsed.destination_hash, &rete_transport::PATH_REQUEST_DEST);
        assert_eq!(parsed.payload, &dest);
    }

    // -----------------------------------------------------------------------
    // Announce queue tests
    // -----------------------------------------------------------------------

    #[test]
    fn queue_announce_adds_to_transport() {
        let mut core = make_core(b"queue-announce");
        let mut rng = rand::thread_rng();

        assert_eq!(core.transport.announce_count(), 0);
        assert!(core.queue_announce(None, &mut rng, 1000));
        assert_eq!(core.transport.announce_count(), 1);
    }

    #[test]
    fn queue_announce_local_flushes_immediately() {
        let mut core = make_core(b"queue-flush");
        let mut rng = rand::thread_rng();

        core.queue_announce(None, &mut rng, 1000);
        let pending = core.transport.pending_outbound(1000);

        // local=true means it's sent immediately
        assert_eq!(pending.len(), 1);
        // The announce should be valid
        let pkt = Packet::parse(&pending[0]).unwrap();
        assert_eq!(pkt.packet_type, PacketType::Announce);
    }

    #[test]
    fn queue_announce_retransmits_once() {
        let mut core = make_core(b"queue-retx");
        let mut rng = rand::thread_rng();

        core.queue_announce(None, &mut rng, 1000);

        // First flush: immediate (local=true)
        let p1 = core.transport.pending_outbound(1000);
        assert_eq!(p1.len(), 1);

        // Still in queue (tx_count=1, PATHFINDER_R=1)
        assert_eq!(core.transport.announce_count(), 1);

        // Too early for retransmit (delay = 5 * 2^1 = 10s)
        let p2 = core.transport.pending_outbound(1005);
        assert_eq!(p2.len(), 0);

        // After delay: retransmit
        let p3 = core.transport.pending_outbound(1011);
        assert_eq!(p3.len(), 1);

        // Now tx_count=2 > PATHFINDER_R=1, so dropped from queue
        assert_eq!(core.transport.announce_count(), 0);
    }

    // -----------------------------------------------------------------------
    // Channel proof (ACK) tests
    // -----------------------------------------------------------------------

    #[test]
    fn channel_receive_generates_proof() {
        let (mut init, mut resp, link_id) = two_core_handshake();
        let mut rng = rand::thread_rng();

        // Initiator sends channel message
        let outbound = init
            .send_channel_message(&link_id, 0x42, b"prove this", 200, &mut rng)
            .expect("should send");

        // Responder ingests — should generate a proof in the packets
        let outcome = resp.handle_ingest(&outbound.data, 200, 0, &mut rng);
        assert!(
            matches!(outcome.event, Some(NodeEvent::ChannelMessages { .. })),
            "expected ChannelMessages, got {:?}",
            outcome.event
        );
        let proof_pkt = outcome
            .packets
            .iter()
            .find(|p| {
                Packet::parse(&p.data)
                    .map(|pkt| pkt.packet_type == PacketType::Proof)
                    .unwrap_or(false)
            })
            .expect("responder should auto-prove channel packet");
        assert_eq!(
            proof_pkt.routing,
            PacketRouting::SourceInterface,
            "proof should route back to source"
        );
    }

    #[test]
    fn channel_proof_marks_delivered() {
        let (mut init, mut resp, link_id) = two_core_handshake();
        let mut rng = rand::thread_rng();

        // Initiator sends channel message
        let outbound = init
            .send_channel_message(&link_id, 0x42, b"ack me", 200, &mut rng)
            .expect("should send");

        // Confirm channel has 1 pending
        let init_link = init.transport.get_link(&link_id).unwrap();
        assert_eq!(init_link.channel().unwrap().pending_count(), 1);

        // Responder ingests → gets proof packet
        let outcome = resp.handle_ingest(&outbound.data, 200, 0, &mut rng);
        let proof_pkt = outcome
            .packets
            .iter()
            .find(|p| {
                Packet::parse(&p.data)
                    .map(|pkt| pkt.packet_type == PacketType::Proof)
                    .unwrap_or(false)
            })
            .expect("should have proof");

        // Verify channel receipt was registered
        assert_eq!(
            init.transport.channel_receipt_count(),
            1,
            "should have 1 channel receipt after send"
        );

        // Initiator ingests the proof → should fire ProofReceived + mark_delivered
        let init_outcome = init.handle_ingest(&proof_pkt.data, 201, 0, &mut rng);
        assert!(
            matches!(init_outcome.event, Some(NodeEvent::ProofReceived { .. })),
            "expected ProofReceived, got {:?}",
            init_outcome.event
        );

        // Channel should now have 0 pending
        let init_link = init.transport.get_link(&link_id).unwrap();
        assert_eq!(
            init_link.channel().unwrap().pending_count(),
            0,
            "proof should clear pending channel message"
        );
    }

    #[test]
    fn buffered_channel_packet_also_proved() {
        let (mut init, mut resp, link_id) = two_core_handshake();
        let mut rng = rand::thread_rng();

        // Send two messages — deliver seq 1 first (out of order)
        let _pkt0 = init
            .send_channel_message(&link_id, 0x01, b"msg0", 200, &mut rng)
            .unwrap();
        let pkt1 = init
            .send_channel_message(&link_id, 0x01, b"msg1", 201, &mut rng)
            .unwrap();

        // Deliver seq 1 first — should be buffered
        let outcome = resp.handle_ingest(&pkt1.data, 202, 0, &mut rng);
        assert!(outcome.event.is_none(), "buffered should not emit event");

        // But should still have a proof packet
        let has_proof = outcome.packets.iter().any(|p| {
            Packet::parse(&p.data)
                .map(|pkt| pkt.packet_type == PacketType::Proof)
                .unwrap_or(false)
        });
        assert!(has_proof, "buffered channel packet should still be proved");
    }

    // -----------------------------------------------------------------------
    // Edge-case tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ingest_oversized_packet() {
        // Pass a 501-byte buffer to handle_ingest — should not panic,
        // should return empty outcome (no event).
        let mut core = make_core(b"oversized-test");
        let mut rng = rand::thread_rng();

        let oversized = [0u8; 501];
        let outcome = core.handle_ingest(&oversized, 1000, 0, &mut rng);
        assert!(
            outcome.event.is_none(),
            "oversized packet should produce no event"
        );
        assert!(
            outcome.packets.is_empty(),
            "oversized packet should produce no outbound packets"
        );
    }

    #[test]
    fn test_ingest_undersized_packet() {
        // Pass a 1-byte buffer (< minimum 2 bytes for flags+hops).
        // Should not crash and should return empty outcome.
        let mut core = make_core(b"undersized-test");
        let mut rng = rand::thread_rng();

        let tiny = [0x08u8]; // just flags byte, no hops
        let outcome = core.handle_ingest(&tiny, 1000, 0, &mut rng);
        assert!(
            outcome.event.is_none(),
            "undersized packet should produce no event"
        );

        // Also try empty
        let empty: [u8; 0] = [];
        let outcome2 = core.handle_ingest(&empty, 1000, 0, &mut rng);
        assert!(
            outcome2.event.is_none(),
            "empty packet should produce no event"
        );
    }

    #[test]
    fn test_build_data_packet_no_cached_key() {
        // build_data_packet when no public key is cached for the destination.
        // Should return None.
        let mut core = make_core(b"no-key-test");
        let mut rng = rand::thread_rng();

        let unknown_dest = [0xFFu8; TRUNCATED_HASH_LEN];
        let result = core.build_data_packet(&unknown_dest, b"hello", &mut rng, 100);
        assert!(result.is_none(), "should return None when no cached key");
    }

    // -----------------------------------------------------------------------
    // Multi-destination tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_register_destination_adds_to_transport() {
        let mut core = make_core(b"register-dest-test");
        let hash = core.register_destination("lxmf", &["delivery"]);
        // Should be a valid 16-byte hash, different from primary
        assert_ne!(hash, *core.dest_hash());
        // Transport should have it as local
        assert!(core.get_destination(&hash).is_some());
    }

    #[test]
    fn test_register_destination_returns_correct_dest_hash() {
        let core_seed = b"dest-hash-verify";
        let mut core = make_core(core_seed);
        let hash = core.register_destination("lxmf", &["delivery"]);

        // Compute expected hash independently
        let identity = Identity::from_seed(core_seed).unwrap();
        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name("lxmf", &["delivery"], &mut name_buf).unwrap();
        let expected = rete_core::destination_hash(expanded, Some(&identity.hash()));
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_register_destination_multiple() {
        let mut core = make_core(b"multi-dest-test");
        let h1 = core.register_destination("lxmf", &["delivery"]);
        let h2 = core.register_destination("myapp", &["service"]);
        assert_ne!(h1, h2);
        assert!(core.get_destination(&h1).is_some());
        assert!(core.get_destination(&h2).is_some());
    }

    #[test]
    fn test_primary_dest_still_accessible_after_register() {
        let mut core = make_core(b"primary-access-test");
        let primary = *core.dest_hash();
        core.register_destination("lxmf", &["delivery"]);
        assert!(core.get_destination(&primary).is_some());
        assert_eq!(core.get_destination(&primary).unwrap().app_name, "testapp");
    }

    #[test]
    fn test_get_destination_mut() {
        let mut core = make_core(b"dest-mut-test");
        let hash = core.register_destination("lxmf", &["delivery"]);
        let dest = core.get_destination_mut(&hash).unwrap();
        dest.set_proof_strategy(ProofStrategy::ProveAll);
        assert_eq!(
            core.get_destination(&hash).unwrap().proof_strategy,
            ProofStrategy::ProveAll
        );
    }

    #[test]
    fn test_ingest_data_for_secondary_dest_decrypts() {
        let mut core = make_core(b"secondary-decrypt-test");
        let lxmf_hash = core.register_destination("lxmf", &["delivery"]);
        let mut rng = rand::thread_rng();

        // Build encrypted DATA addressed to the LXMF destination
        let node_id = Identity::from_seed(b"secondary-decrypt-test").unwrap();
        let recipient = Identity::from_public_key(&node_id.public_key()).unwrap();
        let plaintext = b"lxmf message";
        let mut ct_buf = [0u8; MTU];
        let ct_len = recipient.encrypt(plaintext, &mut rng, &mut ct_buf).unwrap();

        let mut pkt_buf = [0u8; MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Single)
            .destination_hash(&lxmf_hash)
            .context(0x00)
            .payload(&ct_buf[..ct_len])
            .build()
            .unwrap();

        let outcome = core.handle_ingest(&pkt_buf[..pkt_len], 1000, 0, &mut rng);
        match outcome.event {
            Some(NodeEvent::DataReceived { dest_hash, payload }) => {
                assert_eq!(dest_hash, lxmf_hash);
                assert_eq!(payload, plaintext);
            }
            other => panic!("expected DataReceived, got {:?}", other),
        }
    }

    #[test]
    fn test_ingest_data_for_secondary_dest_proves() {
        let mut core = make_core(b"secondary-prove-test");
        let lxmf_hash = core.register_destination("lxmf", &["delivery"]);
        // Set ProveAll on the secondary dest
        core.get_destination_mut(&lxmf_hash)
            .unwrap()
            .set_proof_strategy(ProofStrategy::ProveAll);
        let mut rng = rand::thread_rng();

        // Build encrypted DATA addressed to the LXMF destination
        let node_id = Identity::from_seed(b"secondary-prove-test").unwrap();
        let recipient = Identity::from_public_key(&node_id.public_key()).unwrap();
        let mut ct_buf = [0u8; MTU];
        let ct_len = recipient
            .encrypt(b"prove me", &mut rng, &mut ct_buf)
            .unwrap();

        let mut pkt_buf = [0u8; MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Single)
            .destination_hash(&lxmf_hash)
            .context(0x00)
            .payload(&ct_buf[..ct_len])
            .build()
            .unwrap();

        let outcome = core.handle_ingest(&pkt_buf[..pkt_len], 1000, 0, &mut rng);
        let proof_packets: Vec<_> = outcome
            .packets
            .iter()
            .filter(|p| {
                Packet::parse(&p.data)
                    .map(|pkt| pkt.packet_type == PacketType::Proof)
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(
            proof_packets.len(),
            1,
            "secondary dest should generate proof"
        );
    }

    #[test]
    fn test_queue_announce_for_secondary_dest() {
        let mut core = make_core(b"announce-secondary-test");
        let lxmf_hash = core.register_destination("lxmf", &["delivery"]);
        let mut rng = rand::thread_rng();

        assert!(core.queue_announce_for(&lxmf_hash, None, &mut rng, 1000));
        let pending = core.transport.pending_outbound(1000);
        assert_eq!(pending.len(), 1);

        let pkt = Packet::parse(&pending[0]).unwrap();
        assert_eq!(pkt.packet_type, PacketType::Announce);
        assert_eq!(pkt.destination_hash, &lxmf_hash);
    }

    #[test]
    fn test_queue_announce_for_with_app_data() {
        let mut core = make_core(b"announce-appdata-test");
        let lxmf_hash = core.register_destination("lxmf", &["delivery"]);
        let mut rng = rand::thread_rng();

        let app_data = b"some app data";
        assert!(core.queue_announce_for(&lxmf_hash, Some(app_data), &mut rng, 1000));
        let pending = core.transport.pending_outbound(1000);
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn test_queue_announce_for_unknown_dest_fails() {
        let mut core = make_core(b"announce-unknown-test");
        let mut rng = rand::thread_rng();
        let unknown = [0xFF; TRUNCATED_HASH_LEN];
        assert!(!core.queue_announce_for(&unknown, None, &mut rng, 1000));
    }

    #[test]
    fn test_queue_announce_when_full() {
        // Queue announces until the transport queue is full, then verify
        // the next queue attempt handles gracefully.
        type SmallNodeCore = NodeCore<64, 4, 128, 4>; // only 4 announce slots
        let identity = Identity::from_seed(b"queue-full-test").unwrap();
        let mut core = SmallNodeCore::new(identity, "testapp", &["aspect1"]);
        let mut rng = rand::thread_rng();

        // Queue 4 announces (filling the queue)
        for _ in 0..4 {
            assert!(core.queue_announce(None, &mut rng, 1000));
        }

        // 5th queue attempt should return false (not crash)
        let result = core.queue_announce(None, &mut rng, 1000);
        assert!(!result, "queue should be full, returning false");
    }
}
