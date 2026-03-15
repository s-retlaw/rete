//! Sprint 5: Multi-interface TokioNode tests.
//!
//! Validates that `run_multi` correctly routes packets between interfaces:
//! - Forward excludes source interface
//! - Announce sent on all interfaces
//! - Local data not forwarded
//! - Proof routed to correct interface
//!
//! Note: TokioNode uses HostedTransport (~600KB). Tests run on a thread with
//! 4MB stack to avoid overflow.

use rete_core::{
    DestType, HeaderType, Identity, Packet, PacketBuilder, PacketType, MTU, TRUNCATED_HASH_LEN,
};
use rete_tokio::{InboundMsg, TokioNode};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_header1_data(dest_hash: &[u8; TRUNCATED_HASH_LEN], payload: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; MTU];
    let n = PacketBuilder::new(&mut buf)
        .packet_type(PacketType::Data)
        .dest_type(DestType::Single)
        .destination_hash(dest_hash)
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
        .transport_type(1)
        .transport_id(transport_id)
        .destination_hash(dest_hash)
        .context(0x00)
        .payload(payload)
        .build()
        .unwrap();
    buf[..n].to_vec()
}

/// Box-allocate a TokioNode to avoid stack overflow (HostedTransport is ~600KB).
fn make_node(seed: &[u8]) -> Box<TokioNode> {
    let identity = Identity::from_seed(seed).unwrap();
    Box::new(TokioNode::new(identity, "rete", &["example", "v1"]))
}

/// Run `run_multi` with prepared inbound messages and collect outbound per interface.
async fn run_multi_with_inbound(
    node: &mut TokioNode,
    num_interfaces: usize,
    inbound: Vec<InboundMsg>,
) -> Vec<Vec<Vec<u8>>> {
    let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel::<InboundMsg>(256);

    let mut senders = Vec::new();
    let mut receivers = Vec::new();
    for _ in 0..num_interfaces {
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
        senders.push(tx);
        receivers.push(rx);
    }

    for msg in inbound {
        inbound_tx.send(msg).await.unwrap();
    }
    drop(inbound_tx);

    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        node.run_multi(senders, inbound_rx, |_| {}),
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

/// Run an async test on a thread with 4MB stack (HostedTransport needs it).
fn big_stack_test(f: fn()) {
    std::thread::Builder::new()
        .stack_size(4 * 1024 * 1024)
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
                node.enable_transport();

                let local_hash = node.core.identity.hash();
                let dest = [0xCC; TRUNCATED_HASH_LEN];
                let next_hop = [0xDD; TRUNCATED_HASH_LEN];

                let path = rete_transport::Path::via_repeater(next_hop, 3, 100);
                node.core.transport.insert_path(dest, path);

                let data = build_header2_data(&local_hash, &dest, b"forward test");
                let inbound = vec![InboundMsg {
                    iface_idx: 0,
                    data,
                }];

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
                let node_dest = *node.dest_hash();

                let data = build_header1_data(&node_dest, b"local data");
                let inbound = vec![InboundMsg {
                    iface_idx: 0,
                    data,
                }];

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
                node.enable_transport();

                let local_hash = node.core.identity.hash();
                let dest = [0xCC; TRUNCATED_HASH_LEN];
                let next_hop = [0xDD; TRUNCATED_HASH_LEN];

                let path = rete_transport::Path::via_repeater(next_hop, 3, 100);
                node.core.transport.insert_path(dest, path);

                // Forward a DATA on iface 1 to create reverse entry
                let data = build_header2_data(&local_hash, &dest, b"proof routing test");
                let pkt_hash = Packet::parse(&data).unwrap().compute_hash();

                let inbound_data = vec![InboundMsg {
                    iface_idx: 1,
                    data,
                }];
                let _ = run_multi_with_inbound(&mut node, 3, inbound_data).await;

                // Now send a PROOF with dest_hash = truncated packet hash on iface 2
                let trunc: [u8; TRUNCATED_HASH_LEN] =
                    pkt_hash[..TRUNCATED_HASH_LEN].try_into().unwrap();
                let mut proof_buf = [0u8; MTU];
                let proof_len = PacketBuilder::new(&mut proof_buf)
                    .packet_type(PacketType::Proof)
                    .dest_type(DestType::Single)
                    .destination_hash(&trunc)
                    .context(0x00)
                    .payload(b"proof")
                    .build()
                    .unwrap();
                let proof = proof_buf[..proof_len].to_vec();

                let inbound_proof = vec![InboundMsg {
                    iface_idx: 2,
                    data: proof,
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
