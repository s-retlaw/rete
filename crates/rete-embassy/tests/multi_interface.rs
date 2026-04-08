//! Multi-interface tests for EmbassyNode.
//!
//! Mirrors the four tests in `rete-tokio/tests/multi_interface.rs`:
//! - forward_excludes_source_interface
//! - announce_sent_on_all_interfaces
//! - local_data_not_forwarded
//! - proof_routed_to_correct_interface
//!
//! These tests exercise `dispatch_dual` routing and `handle_ingest` with
//! dual-interface semantics. The Embassy run loop is thin glue over these
//! primitives, so testing them directly gives high confidence without
//! requiring the full Embassy executor.

// Force-link embassy-executor to provide timer queue symbols required
// by embassy-time's mock-driver at link time.
use embassy_executor as _;

use rete_core::{
    DestType, HeaderType, Identity, Packet, PacketBuilder, PacketType, MTU,
    TRANSPORT_TYPE_TRANSPORT, TRUNCATED_HASH_LEN,
};
use rete_embassy::EmbassyNode;
use rete_stack::{dispatch_dual, OutboundPacket, PacketRouting, ReteInterface};

use alloc::collections::VecDeque;
use alloc::vec::Vec;
extern crate alloc;

// ---------------------------------------------------------------------------
// MockInterface
// ---------------------------------------------------------------------------

/// A simple mock interface that delivers pre-loaded packets on recv()
/// and captures packets sent via send().
struct MockInterface {
    inbound: VecDeque<Vec<u8>>,
    outbound: Vec<Vec<u8>>,
}

impl MockInterface {
    fn new() -> Self {
        MockInterface {
            inbound: VecDeque::new(),
            outbound: Vec::new(),
        }
    }

}

#[derive(Debug)]
struct MockError;

impl ReteInterface for MockInterface {
    type Error = MockError;

    async fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
        self.outbound.push(frame.to_vec());
        Ok(())
    }

    async fn recv<'a>(&mut self, buf: &'a mut [u8]) -> Result<&'a [u8], Self::Error> {
        if let Some(pkt) = self.inbound.pop_front() {
            let len = pkt.len().min(buf.len());
            buf[..len].copy_from_slice(&pkt[..len]);
            Ok(&buf[..len])
        } else {
            // Block forever — no more packets
            core::future::pending::<()>().await;
            unreachable!()
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_node(seed: &[u8]) -> EmbassyNode {
    let identity = Identity::from_seed(seed).unwrap();
    EmbassyNode::new(identity, "testapp", &["aspect1"]).unwrap()
}

fn build_header1_data(dest_hash: &[u8; TRUNCATED_HASH_LEN], payload: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; MTU];
    let n = PacketBuilder::new(&mut buf)
        .packet_type(PacketType::Data)
        .dest_type(DestType::Single)
        .destination_hash(dest_hash.as_ref())
        .context(0x00)
        .payload(payload)
        .build()
        .unwrap();
    buf[..n].to_vec()
}

fn build_header2_data(
    transport_id: &[u8; TRUNCATED_HASH_LEN],
    dest_hash: &[u8; TRUNCATED_HASH_LEN],
    payload: &[u8],
) -> Vec<u8> {
    let mut buf = [0u8; MTU];
    let n = PacketBuilder::new(&mut buf)
        .header_type(HeaderType::Header2)
        .packet_type(PacketType::Data)
        .dest_type(DestType::Single)
        .transport_type(TRANSPORT_TYPE_TRANSPORT)
        .transport_id(transport_id.as_ref())
        .destination_hash(dest_hash.as_ref())
        .context(0x00)
        .payload(payload)
        .build()
        .unwrap();
    buf[..n].to_vec()
}

// ---------------------------------------------------------------------------
// dispatch_dual unit tests
// ---------------------------------------------------------------------------

/// Helper to run async code in a blocking context for tests.
fn block_on<F: core::future::Future>(f: F) -> F::Output {
    // Use a simple tokio current_thread runtime for test convenience.
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

#[test]
fn dispatch_dual_source_interface_routes_to_source_only() {
    block_on(async {
        let mut iface0 = MockInterface::new();
        let mut iface1 = MockInterface::new();

        let packets = vec![OutboundPacket {
            data: b"test-packet".to_vec(),
            routing: PacketRouting::SourceInterface,
        }];

        // source_iface = 0 → should only go to iface0
        dispatch_dual(&mut iface0, &mut iface1, &packets, 0).await;
        assert_eq!(iface0.outbound.len(), 1);
        assert_eq!(iface1.outbound.len(), 0);

        // Reset
        iface0.outbound.clear();

        // source_iface = 1 → should only go to iface1
        dispatch_dual(&mut iface0, &mut iface1, &packets, 1).await;
        assert_eq!(iface0.outbound.len(), 0);
        assert_eq!(iface1.outbound.len(), 1);
    });
}

#[test]
fn dispatch_dual_all_except_source_excludes_source() {
    block_on(async {
        let mut iface0 = MockInterface::new();
        let mut iface1 = MockInterface::new();

        let packets = vec![OutboundPacket {
            data: b"test-packet".to_vec(),
            routing: PacketRouting::AllExceptSource,
        }];

        // source = 0 → send to iface1 only
        dispatch_dual(&mut iface0, &mut iface1, &packets, 0).await;
        assert_eq!(iface0.outbound.len(), 0, "source iface should be excluded");
        assert_eq!(iface1.outbound.len(), 1, "non-source iface should receive");
    });
}

#[test]
fn dispatch_dual_all_sends_to_both() {
    block_on(async {
        let mut iface0 = MockInterface::new();
        let mut iface1 = MockInterface::new();

        let packets = vec![OutboundPacket {
            data: b"test-packet".to_vec(),
            routing: PacketRouting::All,
        }];

        dispatch_dual(&mut iface0, &mut iface1, &packets, 0).await;
        assert_eq!(iface0.outbound.len(), 1);
        assert_eq!(iface1.outbound.len(), 1);
    });
}

// ---------------------------------------------------------------------------
// Integration tests mirroring rete-tokio multi_interface tests
// ---------------------------------------------------------------------------

#[test]
fn forward_excludes_source_interface() {
    let mut node = make_node(b"multi-embassy-1");
    let mut rng = rand::thread_rng();
    node.core.enable_transport();

    let local_hash = node.core.identity.hash();
    let dest = rete_core::DestHash::from([0xCC; TRUNCATED_HASH_LEN]);
    let next_hop = rete_core::IdentityHash::from([0xDD; TRUNCATED_HASH_LEN]);

    let path = rete_transport::Path::via_repeater(next_hop, 3, 100);
    node.core.transport.insert_path(dest, path);

    // Bootstrap
    let _ = node.core.initial_announce(&mut rng, 1000);

    // Header2 DATA arriving on iface 0, addressed through this node as transport
    let data = build_header2_data(local_hash.as_bytes(), dest.as_bytes(), b"forward test");
    let outcome = node.core.handle_ingest(&data, 1001, 0, &mut rng);

    // Dispatch the resulting packets across two mock interfaces
    block_on(async {
        let mut iface0 = MockInterface::new();
        let mut iface1 = MockInterface::new();

        dispatch_dual(&mut iface0, &mut iface1, &outcome.packets, 0).await;

        // Forwarded data should NOT go back to source (iface 0)
        let iface0_data: Vec<_> = iface0
            .outbound
            .iter()
            .filter(|pkt| {
                Packet::parse(pkt)
                    .map(|p| p.packet_type == PacketType::Data)
                    .unwrap_or(false)
            })
            .collect();
        assert!(
            iface0_data.is_empty(),
            "forwarded packet should NOT go back to source interface 0"
        );

        // Should appear on iface 1
        let iface1_data: Vec<_> = iface1
            .outbound
            .iter()
            .filter(|pkt| {
                Packet::parse(pkt)
                    .map(|p| p.packet_type == PacketType::Data)
                    .unwrap_or(false)
            })
            .collect();
        assert!(
            !iface1_data.is_empty(),
            "forwarded packet should go to interface 1"
        );
    });
}

#[test]
fn announce_sent_on_all_interfaces() {
    let mut node = make_node(b"multi-embassy-2");
    let mut rng = rand::thread_rng();

    let (announces, _cached) = node.core.initial_announce(&mut rng, 1000);

    block_on(async {
        let mut iface0 = MockInterface::new();
        let mut iface1 = MockInterface::new();

        // dispatch_dual with All routing (announces use All routing)
        dispatch_dual(&mut iface0, &mut iface1, &announces, 0).await;

        let iface0_announces: Vec<_> = iface0
            .outbound
            .iter()
            .filter(|pkt| {
                Packet::parse(pkt)
                    .map(|p| p.packet_type == PacketType::Announce)
                    .unwrap_or(false)
            })
            .collect();
        assert!(
            !iface0_announces.is_empty(),
            "interface 0 should receive the initial announce"
        );

        let iface1_announces: Vec<_> = iface1
            .outbound
            .iter()
            .filter(|pkt| {
                Packet::parse(pkt)
                    .map(|p| p.packet_type == PacketType::Announce)
                    .unwrap_or(false)
            })
            .collect();
        assert!(
            !iface1_announces.is_empty(),
            "interface 1 should receive the initial announce"
        );
    });
}

#[test]
fn local_data_not_forwarded() {
    let mut node = make_node(b"multi-embassy-3");
    let mut rng = rand::thread_rng();
    let node_dest = *node.core.dest_hash();

    // Bootstrap
    let _ = node.core.initial_announce(&mut rng, 1000);

    // Header1 DATA addressed to this node (local delivery, no forwarding)
    let data = build_header1_data(node_dest.as_bytes(), b"local data");
    let outcome = node.core.handle_ingest(&data, 1001, 0, &mut rng);

    block_on(async {
        let mut iface0 = MockInterface::new();
        let mut iface1 = MockInterface::new();

        dispatch_dual(&mut iface0, &mut iface1, &outcome.packets, 0).await;

        for (i, iface) in [&iface0, &iface1].iter().enumerate() {
            let data_pkts: Vec<_> = iface
                .outbound
                .iter()
                .filter(|pkt| {
                    Packet::parse(pkt)
                        .map(|p| p.packet_type == PacketType::Data)
                        .unwrap_or(false)
                })
                .collect();
            assert!(
                data_pkts.is_empty(),
                "interface {i} should not receive local data"
            );
        }
    });
}

#[test]
fn proof_routed_to_correct_interface() {
    let mut node = make_node(b"multi-embassy-4");
    let mut rng = rand::thread_rng();
    node.core.enable_transport();

    let local_hash = node.core.identity.hash();
    let dest = rete_core::DestHash::from([0xCC; TRUNCATED_HASH_LEN]);
    let next_hop = rete_core::IdentityHash::from([0xDD; TRUNCATED_HASH_LEN]);

    let path = rete_transport::Path::via_repeater(next_hop, 3, 100);
    node.core.transport.insert_path(dest, path);

    // Bootstrap
    let _ = node.core.initial_announce(&mut rng, 1000);

    // Forward a DATA on iface 1 to create reverse path entry
    let data = build_header2_data(local_hash.as_bytes(), dest.as_bytes(), b"proof routing test");
    let pkt_hash = Packet::parse(&data).unwrap().compute_hash();

    let _outcome = node.core.handle_ingest(&data, 1001, 1, &mut rng);

    // Now send a PROOF with dest_hash = truncated packet hash, arriving on iface 2
    // (We only have two interfaces 0/1, so PROOF arrives on iface 0)
    let trunc: [u8; TRUNCATED_HASH_LEN] = pkt_hash[..TRUNCATED_HASH_LEN].try_into().unwrap();
    let mut proof_buf = [0u8; MTU];
    let proof_len = PacketBuilder::new(&mut proof_buf)
        .packet_type(PacketType::Proof)
        .dest_type(DestType::Single)
        .destination_hash(trunc.as_ref())
        .context(0x00)
        .payload(b"proof")
        .build()
        .unwrap();
    let proof = proof_buf[..proof_len].to_vec();

    let outcome = node.core.handle_ingest(&proof, 1002, 0, &mut rng);

    block_on(async {
        let mut iface0 = MockInterface::new();
        let mut iface1 = MockInterface::new();

        dispatch_dual(&mut iface0, &mut iface1, &outcome.packets, 0).await;

        // Proof should be routed to iface 1 (where original DATA came from)
        let iface1_proofs: Vec<_> = iface1
            .outbound
            .iter()
            .filter(|pkt| {
                Packet::parse(pkt)
                    .map(|p| p.packet_type == PacketType::Proof)
                    .unwrap_or(false)
            })
            .collect();
        assert!(
            !iface1_proofs.is_empty(),
            "proof should be routed to interface 1 (where DATA came from)"
        );

        // Proof should NOT go back to source (iface 0)
        let iface0_proofs: Vec<_> = iface0
            .outbound
            .iter()
            .filter(|pkt| {
                Packet::parse(pkt)
                    .map(|p| p.packet_type == PacketType::Proof)
                    .unwrap_or(false)
            })
            .collect();
        assert!(
            iface0_proofs.is_empty(),
            "proof should NOT go back to source interface 0"
        );
    });
}
