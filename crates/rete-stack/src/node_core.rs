//! NodeCore — shared node logic extracted from TokioNode and EmbassyNode.
//!
//! This struct owns the identity, transport state, and destination configuration.
//! Runtime wrappers (TokioNode, EmbassyNode) become thin shells that provide
//! async event loops and timer management, delegating all packet processing
//! to NodeCore.

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use rand_core::{CryptoRng, RngCore};
use rete_core::{
    DestType, HeaderType, Identity, PacketBuilder, PacketType, MTU, TRUNCATED_HASH_LEN,
};
use rete_transport::{IngestResult, Transport};

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
    /// Application name for our destination.
    app_name: String,
    /// Destination aspects.
    aspects: Vec<String>,
    /// Our destination hash.
    dest_hash: [u8; TRUNCATED_HASH_LEN],
    /// Optional auto-reply message sent after receiving an announce.
    auto_reply: Option<Vec<u8>>,
    /// When true, echo received DATA back to sender with "echo:" prefix.
    echo_data: bool,
    /// Dest hash of the most recently announced peer (echo target).
    last_peer: Option<[u8; TRUNCATED_HASH_LEN]>,
    /// Proof generation strategy for incoming data packets.
    proof_strategy: ProofStrategy,
}

impl<const P: usize, const A: usize, const D: usize, const L: usize> NodeCore<P, A, D, L> {
    /// Create a new NodeCore with the given identity and destination.
    pub fn new(identity: Identity, app_name: &str, aspects: &[&str]) -> Self {
        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name(app_name, aspects, &mut name_buf)
            .expect("app_name + aspects must fit in 128 bytes");
        let id_hash = identity.hash();
        let dest_hash = rete_core::destination_hash(expanded, Some(&id_hash));

        let mut transport = Transport::new();
        transport.add_local_destination(dest_hash);

        NodeCore {
            identity,
            transport,
            app_name: String::from(app_name),
            aspects: aspects.iter().map(|s| String::from(*s)).collect(),
            dest_hash,
            auto_reply: None,
            echo_data: false,
            last_peer: None,
            proof_strategy: ProofStrategy::ProveNone,
        }
    }

    /// Enable transport mode: forward HEADER_2 packets for other nodes.
    pub fn enable_transport(&mut self) {
        self.transport.set_local_identity(self.identity.hash());
    }

    /// Returns our destination hash.
    pub fn dest_hash(&self) -> &[u8; TRUNCATED_HASH_LEN] {
        &self.dest_hash
    }

    /// Set an auto-reply message sent to any peer that announces.
    pub fn set_auto_reply(&mut self, msg: Option<Vec<u8>>) {
        self.auto_reply = msg;
    }

    /// Enable echo mode: received DATA is sent back to the sender with "echo:" prefix.
    pub fn set_echo_data(&mut self, echo: bool) {
        self.echo_data = echo;
    }

    /// Set the proof generation strategy for incoming data packets.
    pub fn set_proof_strategy(&mut self, strategy: ProofStrategy) {
        self.proof_strategy = strategy;
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
    pub fn build_data_packet<R: RngCore + CryptoRng>(
        &self,
        dest_hash: &[u8; TRUNCATED_HASH_LEN],
        plaintext: &[u8],
        rng: &mut R,
    ) -> Option<Vec<u8>> {
        let pub_key = self.transport.recall_identity(dest_hash)?;
        let recipient = Identity::from_public_key(pub_key).ok()?;
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
        Some(pkt_buf[..pkt_len].to_vec())
    }

    /// Build and return a raw announce packet for this node.
    pub fn build_announce<R: RngCore + CryptoRng>(
        &self,
        app_data: Option<&[u8]>,
        rng: &mut R,
        now: u64,
    ) -> Vec<u8> {
        let aspects_refs: Vec<&str> = self.aspects.iter().map(|s| s.as_str()).collect();
        let mut buf = [0u8; MTU];
        let n = Transport::<P, A, D, L>::create_announce(
            &self.identity,
            &self.app_name,
            &aspects_refs,
            app_data,
            rng,
            now,
            &mut buf,
        )
        .expect("announce creation should not fail");
        buf[..n].to_vec()
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
                if let Some(ref msg) = self.auto_reply {
                    if let Some(pkt) = self.build_data_packet(&dest_hash, msg, rng) {
                        packets.push(OutboundPacket {
                            data: pkt,
                            routing: PacketRouting::SourceInterface,
                        });
                    }
                }

                // Flush pending announces (retransmissions) to all interfaces
                let pending = self.transport.pending_outbound(now);
                for ann_raw in pending {
                    packets.push(OutboundPacket {
                        data: ann_raw.to_vec(),
                        routing: PacketRouting::All,
                    });
                }

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
                let decrypted = if dest_hash == self.dest_hash {
                    let mut dec_buf = [0u8; MTU];
                    match self.identity.decrypt(payload, &mut dec_buf) {
                        Ok(n) => dec_buf[..n].to_vec(),
                        Err(_) => payload.to_vec(),
                    }
                } else {
                    payload.to_vec()
                };

                let mut packets = Vec::new();

                // Generate proof if strategy requires it
                if self.proof_strategy == ProofStrategy::ProveAll {
                    if let Some(proof) =
                        Transport::<P, A, D, L>::build_proof_packet(&self.identity, &packet_hash)
                    {
                        packets.push(OutboundPacket {
                            data: proof,
                            routing: PacketRouting::SourceInterface,
                        });
                    }
                }

                // Echo data back to sender if echo mode is on
                if self.echo_data {
                    if let Some(peer) = self.last_peer {
                        let mut echo_msg = Vec::with_capacity(5 + decrypted.len());
                        echo_msg.extend_from_slice(b"echo:");
                        echo_msg.extend_from_slice(&decrypted);
                        if let Some(pkt) = self.build_data_packet(&peer, &echo_msg, rng) {
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
            IngestResult::LinkEstablished { link_id } => IngestOutcome {
                event: Some(NodeEvent::LinkEstablished { link_id }),
                packets: Vec::new(),
            },
            IngestResult::LinkData {
                link_id,
                data,
                context,
            } => IngestOutcome {
                event: Some(NodeEvent::LinkData {
                    link_id,
                    data,
                    context,
                }),
                packets: Vec::new(),
            },
            IngestResult::LinkClosed { link_id } => IngestOutcome {
                event: Some(NodeEvent::LinkClosed { link_id }),
                packets: Vec::new(),
            },
            IngestResult::Duplicate | IngestResult::Invalid => IngestOutcome::empty(),
        }
    }

    /// Periodic maintenance: expire paths, collect pending announces.
    pub fn handle_tick(&mut self, now: u64) -> IngestOutcome {
        let result = self.transport.tick(now);
        let pending = self.transport.pending_outbound(now);
        let packets: Vec<OutboundPacket> = pending
            .into_iter()
            .map(|raw| OutboundPacket {
                data: raw.to_vec(),
                routing: PacketRouting::All,
            })
            .collect();

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
pub type HostedNodeCore = NodeCore<1024, 256, 4096, 32>;

/// Embedded node core (conservative memory for MCUs).
pub type EmbeddedNodeCore = NodeCore<64, 16, 128, 4>;

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
            .build_data_packet(receiver.dest_hash(), b"hello", &mut rng)
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

        let outcome = core.handle_tick(1000);
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
        let pkt = core.build_data_packet(&peer_dest, b"hello peer", &mut rng);
        assert!(pkt.is_some(), "should build data packet to registered peer");
    }
}
