//! EmbassyNode integration tests.
//!
//! These tests verify the node logic through `EmbeddedNodeCore` directly,
//! bypassing the Embassy run loop (which requires an Embassy executor for
//! its timers). The run loop is trivial select4 glue — the interesting
//! logic is all in NodeCore.
//!
//! Tests verify:
//! - Sends an announce on startup
//! - Processes inbound announces (learns paths)
//! - Processes inbound encrypted DATA (decrypts)
//! - Sends auto-reply after receiving an announce

// Force-link embassy-executor to provide timer queue symbols required
// by embassy-time's mock-driver at link time.
use embassy_executor as _;

use rete_core::{Identity, Packet, PacketType, MTU};
use rete_embassy::EmbassyNode;
use rete_stack::NodeEvent;
use rete_transport::Transport;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_node(seed: &[u8]) -> EmbassyNode {
    let identity = Identity::from_seed(seed).unwrap();
    EmbassyNode::new(identity, "testapp", &["aspect1"])
}

/// Create a valid announce packet from the given identity.
fn build_announce(identity: &Identity) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut buf = [0u8; MTU];
    let n = Transport::<64, 16, 128, 4>::create_announce(
        identity,
        "testapp",
        &["aspect1"],
        None,
        &mut rng,
        1000,
        &mut buf,
    )
    .unwrap();
    buf[..n].to_vec()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn embassy_node_sends_announce_on_start() {
    let mut node = make_node(b"test-node-1");
    let mut rng = rand::thread_rng();

    let (announces, _cached) = node.core.initial_announce(&mut rng, 1000);

    assert!(
        !announces.is_empty(),
        "node should produce at least one packet on startup"
    );
    let first = &announces[0];
    let pkt = Packet::parse(first.data.as_slice()).unwrap();
    assert_eq!(
        pkt.packet_type,
        PacketType::Announce,
        "first packet should be an announce"
    );
}

#[test]
fn embassy_node_receives_announce() {
    let mut node = make_node(b"test-node-2");
    let mut rng = rand::thread_rng();

    // Bootstrap the node
    let _ = node.core.initial_announce(&mut rng, 1000);

    // Create a peer and ingest their announce
    let peer = Identity::from_seed(b"peer-node-2").unwrap();
    let announce = build_announce(&peer);
    let outcome = node.core.handle_ingest(&announce, 1001, 0, &mut rng);

    // Should have received an AnnounceReceived event
    assert!(
        matches!(outcome.event, Some(NodeEvent::AnnounceReceived { .. })),
        "should receive an announce event"
    );

    // Path should be learned
    let peer_hash = peer.hash();
    let mut name_buf = [0u8; 128];
    let expanded = rete_core::expand_name("testapp", &["aspect1"], &mut name_buf).unwrap();
    let peer_dest = rete_core::destination_hash(expanded, Some(&peer_hash));
    assert!(
        node.core.transport.get_path(&peer_dest).is_some(),
        "path to peer should be learned"
    );
}

#[test]
fn embassy_node_receives_encrypted_data() {
    let mut node = make_node(b"test-node-3");
    let node_dest = *node.core.dest_hash();
    let mut rng = rand::thread_rng();

    // Bootstrap the node
    let _ = node.core.initial_announce(&mut rng, 1000);

    // Build encrypted DATA addressed to this node
    let node_identity = Identity::from_seed(b"test-node-3").unwrap();
    let recipient = Identity::from_public_key(&node_identity.public_key()).unwrap();

    let plaintext = b"hello embassy node";
    let mut ct_buf = [0u8; MTU];
    let ct_len = recipient.encrypt(plaintext, &mut rng, &mut ct_buf).unwrap();

    let mut pkt_buf = [0u8; MTU];
    let pkt_len = rete_core::PacketBuilder::new(&mut pkt_buf)
        .packet_type(PacketType::Data)
        .dest_type(rete_core::DestType::Single)
        .destination_hash(&node_dest)
        .context(0x00)
        .payload(&ct_buf[..ct_len])
        .build()
        .unwrap();

    let outcome = node
        .core
        .handle_ingest(&pkt_buf[..pkt_len], 1002, 0, &mut rng);

    // Should have a DataReceived event with decrypted payload
    match outcome.event {
        Some(NodeEvent::DataReceived { payload, .. }) => {
            assert_eq!(payload, plaintext, "payload should be decrypted correctly");
        }
        other => panic!("expected DataReceived, got {other:?}"),
    }
}

#[test]
fn embassy_node_auto_reply() {
    let mut node = make_node(b"test-node-5");
    node.core
        .set_auto_reply(Some(b"auto-reply message".to_vec()));
    let mut rng = rand::thread_rng();

    // Bootstrap the node
    let _ = node.core.initial_announce(&mut rng, 1000);

    // Inject a peer announce — this should trigger auto-reply
    let peer = Identity::from_seed(b"peer-node-5").unwrap();
    let announce = build_announce(&peer);
    let outcome = node.core.handle_ingest(&announce, 1001, 0, &mut rng);

    // The announce ingest should produce outbound packets (the forwarded
    // announce and/or the auto-reply). The auto-reply is queued via
    // flush_announces, so trigger a tick to flush it.
    let tick_outcome = node.core.handle_tick(1002, &mut rng);

    // Collect all outbound packets
    let all_packets: Vec<_> = outcome
        .packets
        .iter()
        .chain(tick_outcome.packets.iter())
        .collect();

    let data_packets: Vec<_> = all_packets
        .iter()
        .filter(|pkt| {
            Packet::parse(pkt.data.as_slice())
                .map(|p| p.packet_type == PacketType::Data)
                .unwrap_or(false)
        })
        .collect();
    assert!(
        !data_packets.is_empty(),
        "auto_reply should produce at least one DATA packet after receiving announce"
    );
}
