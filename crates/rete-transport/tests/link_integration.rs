//! Link integration tests — validates link lifecycle through Transport.
//!
//! Tests the full link handshake, data exchange, keepalive, close, and
//! edge cases (stale, invalid proof, duplicate request, etc.).

use rete_core::{
    DestType, Identity, Packet, PacketBuilder, PacketType, CONTEXT_KEEPALIVE, CONTEXT_LRPROOF, MTU,
    TRUNCATED_HASH_LEN,
};
use rete_transport::{compute_link_id, IngestResult, Link, LinkState, Transport};

type TestTransport = Transport<64, 16, 128, 4>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Set up a responder transport with a local destination and identity.
fn make_responder(seed: &[u8]) -> (TestTransport, Identity, [u8; TRUNCATED_HASH_LEN]) {
    let identity = Identity::from_seed(seed).unwrap();
    let mut name_buf = [0u8; 128];
    let expanded = rete_core::expand_name("testapp", &["link"], &mut name_buf).unwrap();
    let id_hash = identity.hash();
    let dest_hash = rete_core::destination_hash(expanded, Some(&id_hash));

    let mut t = TestTransport::new();
    t.add_local_destination(dest_hash);
    (t, identity, dest_hash)
}

/// Build a LINKREQUEST packet for a destination.
fn build_link_request(
    dest_hash: &[u8; TRUNCATED_HASH_LEN],
    identity: &Identity,
    rng: &mut impl rand_core::CryptoRngCore,
) -> (Vec<u8>, [u8; 64]) {
    let (_, request_payload) = Link::new_initiator(*dest_hash, identity.ed25519_pub(), rng, 100);

    let mut buf = [0u8; MTU];
    let n = PacketBuilder::new(&mut buf)
        .packet_type(PacketType::LinkRequest)
        .dest_type(DestType::Link)
        .destination_hash(dest_hash)
        .context(0x00)
        .payload(&request_payload)
        .build()
        .unwrap();
    (buf[..n].to_vec(), request_payload)
}

/// Full handshake between two transports. Returns (initiator, responder, link_id).
fn full_handshake() -> (
    TestTransport,
    Identity,
    TestTransport,
    Identity,
    [u8; TRUNCATED_HASH_LEN],
) {
    let mut rng = rand::thread_rng();
    let (mut resp_t, resp_id, resp_dest) = make_responder(b"responder-hs");
    let init_id = Identity::from_seed(b"initiator-hs").unwrap();
    let mut init_t = TestTransport::new();

    // Register responder identity so initiator can verify proof
    init_t.register_identity(resp_dest, resp_id.public_key(), 100);

    // Initiator builds and sends LINKREQUEST
    let (request_pkt, _) = build_link_request(&resp_dest, &init_id, &mut rng);
    let link_id = compute_link_id(&request_pkt).unwrap();

    // Responder ingests LINKREQUEST
    let mut req_buf = request_pkt.clone();
    let resp_result = resp_t.ingest(&mut req_buf, 100, &mut rng, &resp_id);
    let _proof_raw = match resp_result {
        IngestResult::LinkRequestReceived { proof_raw, .. } => proof_raw,
        other => panic!("expected LinkRequestReceived, got {:?}", other),
    };

    // Initiator sets up its link (manually, since it needs the raw packet)
    let (mut init_link, _) = Link::new_initiator(resp_dest, init_id.ed25519_pub(), &mut rng, 100);
    // Recompute from the same raw packet
    init_link.set_link_id(link_id);

    // We need to use initiate_link for the initiator transport to have the link
    let (init_req, init_link_id) = init_t
        .initiate_link(resp_dest, &init_id, &mut rng, 100)
        .unwrap();

    // The link_id from initiate_link may differ from our manually built one
    // because the ephemeral key is different. Use the transport's link.
    // Send LINKREQUEST to responder again with the transport's packet
    let mut req_buf2 = init_req.clone();
    // Clear responder's dedup so we can ingest again
    let (mut resp_t2, resp_id2, resp_dest2) = make_responder(b"responder-hs");
    resp_t2.register_identity(resp_dest2, resp_id2.public_key(), 100);
    let resp_result2 = resp_t2.ingest(&mut req_buf2, 100, &mut rng, &resp_id2);
    let proof_raw2 = match resp_result2 {
        IngestResult::LinkRequestReceived {
            link_id, proof_raw, ..
        } => {
            assert_eq!(link_id, init_link_id);
            proof_raw
        }
        other => panic!("expected LinkRequestReceived, got {:?}", other),
    };

    // Initiator ingests LRPROOF
    let mut proof_buf = proof_raw2.clone();
    let init_result = init_t.ingest(&mut proof_buf, 101, &mut rng, &init_id);
    match init_result {
        IngestResult::LinkEstablished { link_id } => {
            assert_eq!(link_id, init_link_id);
        }
        other => panic!("expected LinkEstablished, got {:?}", other),
    }

    (init_t, init_id, resp_t2, resp_id2, init_link_id)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn link_request_local_creates_link() {
    let mut rng = rand::thread_rng();
    let (mut t, identity, dest_hash) = make_responder(b"responder-1");

    let initiator = Identity::from_seed(b"initiator-1").unwrap();
    let (request_pkt, _) = build_link_request(&dest_hash, &initiator, &mut rng);

    let mut raw = request_pkt;
    match t.ingest(&mut raw, 100, &mut rng, &identity) {
        IngestResult::LinkRequestReceived { link_id, proof_raw } => {
            assert_eq!(link_id.len(), 16);
            assert!(!proof_raw.is_empty());
            // Proof should be a parseable packet
            let pkt = Packet::parse(&proof_raw).unwrap();
            assert_eq!(pkt.packet_type, PacketType::Proof);
            assert_eq!(pkt.dest_type, DestType::Link);
            assert_eq!(pkt.context, CONTEXT_LRPROOF);
        }
        other => panic!("expected LinkRequestReceived, got {:?}", other),
    }
    assert_eq!(t.link_count(), 1);
}

#[test]
fn link_request_non_local_forwards() {
    let mut rng = rand::thread_rng();
    let mut t = TestTransport::new();
    let identity = Identity::from_seed(b"non-local-node").unwrap();

    let remote_dest = [0xAA; TRUNCATED_HASH_LEN];
    let initiator = Identity::from_seed(b"initiator-2").unwrap();
    let (request_pkt, _) = build_link_request(&remote_dest, &initiator, &mut rng);

    let mut raw = request_pkt;
    match t.ingest(&mut raw, 100, &mut rng, &identity) {
        IngestResult::Forward { .. } => {}
        other => panic!("expected Forward, got {:?}", other),
    }
    assert_eq!(t.link_count(), 0);
}

#[test]
fn full_handshake_two_transports() {
    let (init_t, _, resp_t, _, link_id) = full_handshake();

    // Initiator should have an active link
    let init_link = init_t.get_link(&link_id).unwrap();
    assert_eq!(init_link.state, LinkState::Active);

    // Responder should have a handshake link (waiting for LRRTT)
    let resp_link = resp_t.get_link(&link_id).unwrap();
    assert_eq!(resp_link.state, LinkState::Handshake);
}

#[test]
fn lrrtt_activates_responder_link() {
    let (init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Initiator sends LRRTT
    let lrrtt = init_t
        .build_lrrtt_packet(&link_id, b"rtt-data", &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    match resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id) {
        IngestResult::LinkEstablished { link_id: lid } => {
            assert_eq!(lid, link_id);
        }
        other => panic!("expected LinkEstablished, got {:?}", other),
    }

    // Responder link should now be Active
    let resp_link = resp_t.get_link(&link_id).unwrap();
    assert_eq!(resp_link.state, LinkState::Active);
}

#[test]
fn link_data_encrypt_decrypt() {
    let (init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Activate responder via LRRTT
    let lrrtt = init_t
        .build_lrrtt_packet(&link_id, b"rtt", &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    // Initiator sends encrypted data
    let data_pkt = init_t
        .build_link_data_packet(&link_id, b"hello link", 0x00, &mut rng)
        .unwrap();
    let mut data_buf = data_pkt;
    match resp_t.ingest(&mut data_buf, 103, &mut rng, &resp_id) {
        IngestResult::LinkData {
            link_id: lid,
            data,
            context,
        } => {
            assert_eq!(lid, link_id);
            assert_eq!(data, b"hello link");
            assert_eq!(context, 0x00);
        }
        other => panic!("expected LinkData, got {:?}", other),
    }
}

#[test]
fn bidirectional_link_data() {
    let (mut init_t, init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Activate responder via LRRTT
    let lrrtt = init_t
        .build_lrrtt_packet(&link_id, b"rtt", &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    // Initiator → Responder
    let pkt1 = init_t
        .build_link_data_packet(&link_id, b"from initiator", 0x00, &mut rng)
        .unwrap();
    let mut buf1 = pkt1;
    match resp_t.ingest(&mut buf1, 103, &mut rng, &resp_id) {
        IngestResult::LinkData { data, .. } => assert_eq!(data, b"from initiator"),
        other => panic!("expected LinkData, got {:?}", other),
    }

    // Responder → Initiator
    let pkt2 = resp_t
        .build_link_data_packet(&link_id, b"from responder", 0x00, &mut rng)
        .unwrap();
    let mut buf2 = pkt2;
    match init_t.ingest(&mut buf2, 104, &mut rng, &init_id) {
        IngestResult::LinkData { data, .. } => assert_eq!(data, b"from responder"),
        other => panic!("expected LinkData, got {:?}", other),
    }
}

#[test]
fn keepalive_request_response() {
    let (init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Activate responder
    let lrrtt = init_t
        .build_lrrtt_packet(&link_id, b"rtt", &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    // Initiator sends keepalive request
    let ka = init_t
        .build_keepalive_packet(&link_id, true, &mut rng)
        .unwrap();
    let mut ka_buf = ka;
    match resp_t.ingest(&mut ka_buf, 200, &mut rng, &resp_id) {
        IngestResult::LinkData { data, context, .. } => {
            assert_eq!(context, CONTEXT_KEEPALIVE);
            assert_eq!(data, &[0xFE]); // response byte
        }
        other => panic!("expected LinkData with keepalive response, got {:?}", other),
    }
}

#[test]
fn linkclose_tears_down() {
    let (mut init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Activate responder
    let lrrtt = init_t
        .build_lrrtt_packet(&link_id, b"rtt", &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    // Initiator closes link
    let close = init_t.build_linkclose_packet(&link_id, &mut rng).unwrap();
    // Initiator's link should be removed
    assert_eq!(init_t.link_count(), 0);

    // Responder receives close
    let mut close_buf = close;
    match resp_t.ingest(&mut close_buf, 200, &mut rng, &resp_id) {
        IngestResult::LinkClosed { link_id: lid } => {
            assert_eq!(lid, link_id);
        }
        other => panic!("expected LinkClosed, got {:?}", other),
    }
    assert_eq!(resp_t.link_count(), 0);
}

#[test]
fn link_stale_in_tick() {
    let (init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Activate responder via LRRTT first
    let lrrtt = init_t
        .build_lrrtt_packet(&link_id, b"rtt", &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    // Now responder link is Active
    let link = resp_t.get_link(&link_id).unwrap();
    assert_eq!(link.state, LinkState::Active);
    let stale_time = link.stale_time;

    // Tick well past stale time
    let result = resp_t.tick(102 + stale_time + 1);
    assert_eq!(result.closed_links, 1);
    assert_eq!(resp_t.link_count(), 0);
}

#[test]
fn invalid_lrproof_rejected() {
    let mut rng = rand::thread_rng();
    let init_id = Identity::from_seed(b"initiator-bad-proof").unwrap();
    let resp_id = Identity::from_seed(b"responder-bad-proof").unwrap();

    let mut name_buf = [0u8; 128];
    let expanded = rete_core::expand_name("testapp", &["link"], &mut name_buf).unwrap();
    let resp_dest = rete_core::destination_hash(expanded, Some(&resp_id.hash()));

    let mut init_t = TestTransport::new();
    // Register a WRONG identity for the responder dest
    let wrong_id = Identity::from_seed(b"wrong-identity").unwrap();
    init_t.register_identity(resp_dest, wrong_id.public_key(), 100);

    let (init_req, _init_link_id) = init_t
        .initiate_link(resp_dest, &init_id, &mut rng, 100)
        .unwrap();

    // Build a valid proof from the real responder
    let (mut resp_t, _, _) = make_responder(b"responder-bad-proof");
    let mut req_buf = init_req;
    let proof_raw = match resp_t.ingest(&mut req_buf, 100, &mut rng, &resp_id) {
        IngestResult::LinkRequestReceived { proof_raw, .. } => proof_raw,
        other => panic!("expected LinkRequestReceived, got {:?}", other),
    };

    // Initiator tries to validate — should fail because wrong identity registered
    let mut proof_buf = proof_raw;
    match init_t.ingest(&mut proof_buf, 101, &mut rng, &init_id) {
        IngestResult::Invalid => {} // expected — signature mismatch
        other => panic!("expected Invalid, got {:?}", other),
    }
}

#[test]
fn link_data_before_active_rejected() {
    let (_, _, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Responder link is in Handshake state (not yet Active, no LRRTT received)
    let link = resp_t.get_link(&link_id).unwrap();
    assert_eq!(link.state, LinkState::Handshake);

    // Try to send data on the link — should be able to decrypt but reject
    // because link is not active for regular data
    // Build a data packet directly
    let mut ct_buf = [0u8; MTU];
    let ct_len = link.encrypt(b"too early", &mut rng, &mut ct_buf).unwrap();

    let mut pkt_buf = [0u8; MTU];
    let pkt_len = PacketBuilder::new(&mut pkt_buf)
        .packet_type(PacketType::Data)
        .dest_type(DestType::Link)
        .destination_hash(&link_id)
        .context(0x00)
        .payload(&ct_buf[..ct_len])
        .build()
        .unwrap();

    let mut raw = pkt_buf[..pkt_len].to_vec();
    match resp_t.ingest(&mut raw, 103, &mut rng, &resp_id) {
        IngestResult::Invalid => {} // expected
        other => panic!("expected Invalid, got {:?}", other),
    }
}

#[test]
fn duplicate_link_request() {
    let mut rng = rand::thread_rng();
    let (mut t, identity, dest_hash) = make_responder(b"responder-dup");

    let initiator = Identity::from_seed(b"initiator-dup").unwrap();
    let (request_pkt, _) = build_link_request(&dest_hash, &initiator, &mut rng);

    // First request
    let mut raw1 = request_pkt.clone();
    match t.ingest(&mut raw1, 100, &mut rng, &identity) {
        IngestResult::LinkRequestReceived { .. } => {}
        other => panic!("expected LinkRequestReceived, got {:?}", other),
    }
    assert_eq!(t.link_count(), 1);

    // Same request again — should be duplicate (same packet hash dedup)
    let mut raw2 = request_pkt.clone();
    match t.ingest(&mut raw2, 101, &mut rng, &identity) {
        IngestResult::Duplicate => {} // packet hash dedup
        other => panic!("expected Duplicate, got {:?}", other),
    }
    assert_eq!(t.link_count(), 1);
}

#[test]
fn channel_data_over_link() {
    let (init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Activate responder
    let lrrtt = init_t
        .build_lrrtt_packet(&link_id, b"rtt", &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    // Send a properly-formed channel envelope with CONTEXT_CHANNEL
    let envelope = rete_transport::ChannelEnvelope {
        message_type: 0x01,
        sequence: 0,
        payload: b"channel msg".to_vec(),
    };
    let packed = envelope.pack();
    let pkt = init_t
        .build_link_data_packet(&link_id, &packed, rete_core::CONTEXT_CHANNEL, &mut rng)
        .unwrap();
    let mut buf = pkt;
    match resp_t.ingest(&mut buf, 103, &mut rng, &resp_id) {
        IngestResult::ChannelMessages {
            link_id: lid,
            messages,
        } => {
            assert_eq!(lid, link_id);
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0].message_type, 0x01);
            assert_eq!(messages[0].payload, b"channel msg");
        }
        other => panic!("expected ChannelMessages, got {:?}", other),
    }
}

#[test]
fn initiate_link_returns_request() {
    let mut rng = rand::thread_rng();
    let identity = Identity::from_seed(b"initiator-test").unwrap();
    let dest_hash = [0xAA; TRUNCATED_HASH_LEN];

    let mut t = TestTransport::new();
    let (pkt, link_id) = t
        .initiate_link(dest_hash, &identity, &mut rng, 100)
        .unwrap();

    // Should be a parseable LINKREQUEST
    let parsed = Packet::parse(&pkt).unwrap();
    assert_eq!(parsed.packet_type, PacketType::LinkRequest);
    assert_eq!(parsed.dest_type, DestType::Link);

    // Transport should have the link
    assert_eq!(t.link_count(), 1);
    let link = t.get_link(&link_id).unwrap();
    assert_eq!(link.state, LinkState::Handshake);
}

// ---------------------------------------------------------------------------
// Keepalive timer tests
// ---------------------------------------------------------------------------

#[test]
fn transport_keepalive_sent_when_due() {
    let (init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Activate responder via LRRTT
    let lrrtt = init_t
        .build_lrrtt_packet(&link_id, b"rtt", &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    let link = resp_t.get_link(&link_id).unwrap();
    let ka_interval = link.keepalive_interval;

    // Not due yet
    let keepalives = resp_t.build_pending_keepalives(102, &mut rng);
    assert!(keepalives.is_empty(), "no keepalive should be needed yet");

    // Advance past half keepalive interval
    let keepalives = resp_t.build_pending_keepalives(102 + ka_interval / 2 + 1, &mut rng);
    assert_eq!(keepalives.len(), 1, "should produce one keepalive");

    // Verify it's a parseable packet
    let parsed = Packet::parse(&keepalives[0]).unwrap();
    assert_eq!(parsed.packet_type, PacketType::Data);
    assert_eq!(parsed.dest_type, DestType::Link);
    assert_eq!(parsed.context, CONTEXT_KEEPALIVE);
}

// ---------------------------------------------------------------------------
// Channel through Transport tests
// ---------------------------------------------------------------------------

#[test]
fn channel_send_receive_through_transport() {
    let (mut init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Activate both sides
    let lrrtt = init_t
        .build_lrrtt_packet(&link_id, b"rtt", &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    // Initiator sends channel message
    let pkt = init_t
        .send_channel_message(&link_id, 0x42, b"hello channel", 200, &mut rng)
        .expect("should send channel message");

    // Responder ingests
    let mut buf = pkt;
    match resp_t.ingest(&mut buf, 200, &mut rng, &resp_id) {
        IngestResult::ChannelMessages {
            link_id: lid,
            messages,
        } => {
            assert_eq!(lid, link_id);
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0].message_type, 0x42);
            assert_eq!(messages[0].payload, b"hello channel");
        }
        other => panic!("expected ChannelMessages, got {:?}", other),
    }
}

#[test]
fn channel_reorder_through_transport() {
    let (mut init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Activate responder
    let lrrtt = init_t
        .build_lrrtt_packet(&link_id, b"rtt", &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    // Send two channel messages
    let pkt0 = init_t
        .send_channel_message(&link_id, 0x01, b"msg0", 200, &mut rng)
        .unwrap();
    let pkt1 = init_t
        .send_channel_message(&link_id, 0x01, b"msg1", 201, &mut rng)
        .unwrap();

    // Deliver seq 1 first (out of order)
    let mut buf1 = pkt1;
    match resp_t.ingest(&mut buf1, 202, &mut rng, &resp_id) {
        IngestResult::Buffered => {} // out-of-order, held for reordering
        other => panic!("expected Buffered (out-of-order), got {:?}", other),
    }

    // Now deliver seq 0 — should flush both
    let mut buf0 = pkt0;
    match resp_t.ingest(&mut buf0, 203, &mut rng, &resp_id) {
        IngestResult::ChannelMessages { messages, .. } => {
            assert_eq!(messages.len(), 2);
            assert_eq!(messages[0].sequence, 0);
            assert_eq!(messages[1].sequence, 1);
            assert_eq!(messages[0].payload, b"msg0");
            assert_eq!(messages[1].payload, b"msg1");
        }
        other => panic!("expected ChannelMessages with 2 messages, got {:?}", other),
    }
}

#[test]
fn channel_retransmit_on_timeout() {
    let (mut init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Activate responder
    let lrrtt = init_t
        .build_lrrtt_packet(&link_id, b"rtt", &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    // Send channel message from initiator (marks sent_at=200)
    let _pkt = init_t
        .send_channel_message(&link_id, 0x01, b"retry me", 200, &mut rng)
        .unwrap();

    // Before timeout: no retransmits
    let retx = init_t.pending_channel_retransmits(210, &mut rng);
    assert!(retx.is_empty());

    // After timeout (15s default)
    let retx = init_t.pending_channel_retransmits(216, &mut rng);
    assert_eq!(retx.len(), 1, "should retransmit one message");
}

#[test]
fn channel_window_blocks_at_capacity() {
    let (mut init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Activate responder
    let lrrtt = init_t
        .build_lrrtt_packet(&link_id, b"rtt", &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    // Fill the window (DEFAULT_WINDOW = 4)
    for i in 0..rete_transport::DEFAULT_WINDOW {
        assert!(
            init_t
                .send_channel_message(&link_id, 0x01, &[i as u8], 200, &mut rng)
                .is_some(),
            "message {} should succeed",
            i
        );
    }

    // Next should be blocked
    assert!(
        init_t
            .send_channel_message(&link_id, 0x01, b"blocked", 201, &mut rng)
            .is_none(),
        "window should be full"
    );
}

#[test]
fn channel_teardown_on_max_retries() {
    let (mut init_t, _init_id, mut resp_t, resp_id, link_id) = full_handshake();
    let mut rng = rand::thread_rng();

    // Activate responder
    let lrrtt = init_t
        .build_lrrtt_packet(&link_id, b"rtt", &mut rng)
        .unwrap();
    let mut lrrtt_buf = lrrtt;
    let _ = resp_t.ingest(&mut lrrtt_buf, 102, &mut rng, &resp_id);

    // Send one message
    let _pkt = init_t
        .send_channel_message(&link_id, 0x01, b"will fail", 100, &mut rng)
        .unwrap();

    // Exhaust retries (MAX_RETRIES = 5, timeout = 15s)
    let mut now = 100u64;
    for _ in 0..=rete_transport::channel::MAX_RETRIES {
        now += 16; // past retry_timeout
        let _ = init_t.pending_channel_retransmits(now, &mut rng);
    }

    // Link should be removed (teardown)
    assert_eq!(
        init_t.link_count(),
        0,
        "link should be removed after max retries"
    );
}
