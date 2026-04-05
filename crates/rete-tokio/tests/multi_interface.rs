//! Sprint 5: Multi-interface TokioNode tests.
//!
//! Validates that `run_multi` correctly routes packets between interfaces:
//! - Forward excludes source interface
//! - Announce sent on all interfaces
//! - Local data not forwarded
//! - Proof routed to correct interface
//!
//! Note: In debug builds `Box::new(T::new())` may materialise the struct on
//! the stack before moving to heap, so tests run on a thread with enlarged stack.

use rete_core::{
    DestType, HeaderType, Identity, Packet, PacketBuilder, PacketType, MTU,
    TRANSPORT_TYPE_TRANSPORT, TRUNCATED_HASH_LEN,
};
use rete_tokio::{InboundMsg, InterfaceSlot, TokioNode};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

/// Box-allocate a TokioNode to avoid debug-build stack overflow.
fn make_node(seed: &[u8]) -> Box<TokioNode> {
    let identity = Identity::from_seed(seed).unwrap();
    Box::new(TokioNode::new(identity, "rete", &["example", "v1"]).unwrap())
}

/// Run `run_multi` with prepared inbound messages and collect outbound per interface.
async fn run_multi_with_inbound(
    node: &mut TokioNode,
    num_interfaces: usize,
    inbound: Vec<InboundMsg>,
) -> Vec<Vec<Vec<u8>>> {
    let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel::<InboundMsg>(256);

    let mut slots = Vec::new();
    let mut receivers = Vec::new();
    for _ in 0..num_interfaces {
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
        slots.push(InterfaceSlot::Direct(tx));
        receivers.push(rx);
    }

    for msg in inbound {
        inbound_tx.send(msg).await.unwrap();
    }
    drop(inbound_tx);

    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        node.run_multi(slots, inbound_rx, |_| {}),
    )
    .await;

    let mut result = Vec::new();
    for mut rx in receivers {
        let mut packets = Vec::new();
        while let Ok(pkt) = rx.try_recv() {
            packets.push(pkt);
        }
        result.push(packets);
    }
    result
}

/// Run an async test on a thread with 16MB stack.
///
/// In debug builds `Box::new(T::new())` may materialise the struct on the
/// stack before moving it to the heap, so we need a generous stack.
fn big_stack_test(f: fn()) {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn forward_excludes_source_interface() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let mut node = make_node(b"multi-iface-1");
                node.core.enable_transport();

                let local_hash = node.core.identity.hash();
                let dest = rete_core::DestHash::from([0xCC; TRUNCATED_HASH_LEN]);
                let next_hop = rete_core::IdentityHash::from([0xDD; TRUNCATED_HASH_LEN]);

                let path = rete_transport::Path::via_repeater(next_hop, 3, 100);
                node.core.transport.insert_path(dest, path);

                let data = build_header2_data(local_hash.as_bytes(), dest.as_bytes(), b"forward test");
                let inbound = vec![InboundMsg { iface_idx: 0, data, client_id: None }];

                let outbound = run_multi_with_inbound(&mut node, 2, inbound).await;

                let iface0_data: Vec<_> = outbound[0]
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

                let iface1_data: Vec<_> = outbound[1]
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
    });
}

#[test]
fn announce_sent_on_all_interfaces() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let mut node = make_node(b"multi-iface-2");

                let outbound = run_multi_with_inbound(&mut node, 3, vec![]).await;

                for (i, iface_pkts) in outbound.iter().enumerate() {
                    let announces: Vec<_> = iface_pkts
                        .iter()
                        .filter(|pkt| {
                            Packet::parse(pkt)
                                .map(|p| p.packet_type == PacketType::Announce)
                                .unwrap_or(false)
                        })
                        .collect();
                    assert!(
                        !announces.is_empty(),
                        "interface {i} should receive the initial announce"
                    );
                }
            });
    });
}

#[test]
fn local_data_not_forwarded() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let mut node = make_node(b"multi-iface-3");
                let node_dest = *node.core.dest_hash();

                let data = build_header1_data(node_dest.as_bytes(), b"local data");
                let inbound = vec![InboundMsg { iface_idx: 0, data, client_id: None }];

                let outbound = run_multi_with_inbound(&mut node, 2, inbound).await;

                for (i, iface_pkts) in outbound.iter().enumerate() {
                    let data_pkts: Vec<_> = iface_pkts
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
    });
}

#[test]
fn proof_routed_to_correct_interface() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let mut node = make_node(b"multi-iface-4");
                node.core.enable_transport();

                let local_hash = node.core.identity.hash();
                let dest = rete_core::DestHash::from([0xCC; TRUNCATED_HASH_LEN]);
                let next_hop = rete_core::IdentityHash::from([0xDD; TRUNCATED_HASH_LEN]);

                let path = rete_transport::Path::via_repeater(next_hop, 3, 100);
                node.core.transport.insert_path(dest, path);

                // Forward a DATA on iface 1 to create reverse entry
                let data = build_header2_data(local_hash.as_bytes(), dest.as_bytes(), b"proof routing test");
                let pkt_hash = Packet::parse(&data).unwrap().compute_hash();

                let inbound_data = vec![InboundMsg { iface_idx: 1, data, client_id: None }];
                let _ = run_multi_with_inbound(&mut node, 3, inbound_data).await;

                // Now send a PROOF with dest_hash = truncated packet hash on iface 2
                let trunc: [u8; TRUNCATED_HASH_LEN] =
                    pkt_hash[..TRUNCATED_HASH_LEN].try_into().unwrap();
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

                let inbound_proof = vec![InboundMsg {
                    iface_idx: 2,
                    data: proof,
                    client_id: None,
                }];

                let outbound = run_multi_with_inbound(&mut node, 3, inbound_proof).await;

                // Proof should be routed to iface 1 (where original DATA came from)
                let iface1_proofs: Vec<_> = outbound[1]
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

                // Interface 2 should NOT get the proof (it's the source)
                let iface2_proofs: Vec<_> = outbound[2]
                    .iter()
                    .filter(|pkt| {
                        Packet::parse(pkt)
                            .map(|p| p.packet_type == PacketType::Proof)
                            .unwrap_or(false)
                    })
                    .collect();
                assert!(
                    iface2_proofs.is_empty(),
                    "proof should NOT go back to source interface 2"
                );
            });
    });
}
