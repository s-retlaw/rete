//! Sprint 4: Path request handling tests.

use rete_core::{Identity, MTU, TRUNCATED_HASH_LEN};
use rete_transport::{IngestResult, Transport, PATH_REQUEST_DEST};

/// Small transport suitable for tests.
type TestTransport = Transport<64, 16, 128, 4>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_path_request(requested_dest: &[u8; TRUNCATED_HASH_LEN]) -> Vec<u8> {
    TestTransport::build_path_request(requested_dest)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn path_request_dest_hash_matches_python() {
    // Precomputed: destination_hash("rnstransport.path.request", None)
    let computed = rete_core::destination_hash("rnstransport.path.request", None);
    assert_eq!(
        computed, PATH_REQUEST_DEST,
        "PATH_REQUEST_DEST must match Python destination_hash('rnstransport.path.request', None)"
    );
}

#[test]
fn path_request_known_dest_queues_announce() {
    let mut t = TestTransport::new();
    t.set_local_identity([0x11; TRUNCATED_HASH_LEN]); // enable transport mode

    // Create an announcer and ingest their announce (to populate path + cached announce)
    let announcer = Identity::from_seed(b"path-req-announcer").unwrap();
    let mut rng = rand::thread_rng();
    let mut buf = [0u8; MTU];
    let identity = Identity::from_seed(b"test-identity").unwrap();
    let n = Transport::<64, 16, 128, 4>::create_announce(
        &announcer,
        "testapp",
        &["aspect1"],
        None,
        None,
        &mut rng,
        1000,
        &mut buf,
    )
    .unwrap();

    let mut ann = buf[..n].to_vec();
    match t.ingest(&mut ann, 1000, &mut rng, &identity) {
        IngestResult::AnnounceReceived { dest_hash, .. } => {
            // Drain the retransmit announce from normal announce processing
            // First call sends (tx_count 0→1) at retransmit_timeout (1000+5=1005)
            let _ = t.pending_outbound(1006, &mut rng);
            // Second call sends (tx_count 1→2) and drops (tx_count > PATHFINDER_R)
            let _ = t.pending_outbound(1012, &mut rng);
            let count_before = t.announce_count();
            assert_eq!(count_before, 0, "queue should be drained");

            // Now send a path request for this dest
            let mut req = build_path_request(&dest_hash);
            match t.ingest(&mut req, 1020, &mut rng, &identity) {
                IngestResult::Duplicate => {} // consumed by path request handler
                other => panic!("expected Duplicate (consumed), got {:?}", other),
            }

            assert_eq!(
                t.announce_count(),
                1,
                "path request should queue the cached announce"
            );
        }
        other => panic!("expected AnnounceReceived, got {:?}", other),
    }
}

#[test]
fn path_request_unknown_dest_no_response() {
    let mut t = TestTransport::new();
    t.set_local_identity([0x11; TRUNCATED_HASH_LEN]);

    let identity = Identity::from_seed(b"test-identity").unwrap();
    let mut rng = rand::thread_rng();
    let unknown = [0xFF; TRUNCATED_HASH_LEN];
    let mut req = build_path_request(&unknown);
    let _ = t.ingest(&mut req, 1000, &mut rng, &identity);

    assert_eq!(
        t.announce_count(),
        0,
        "unknown dest should not queue any announce"
    );
}

#[test]
fn path_request_ignored_without_transport() {
    let mut t = TestTransport::new();
    // No transport mode — no set_local_identity()
    let identity = Identity::from_seed(b"test-identity").unwrap();
    let mut rng = rand::thread_rng();

    // Path request on a non-transport node is dropped (PATH_REQUEST_DEST
    // is not a local destination and there's no path to forward to).
    let requested = [0xAA; TRUNCATED_HASH_LEN];
    let mut req = build_path_request(&requested);
    match t.ingest(&mut req, 1000, &mut rng, &identity) {
        IngestResult::Invalid => {} // non-transport nodes drop path requests
        other => panic!("expected Invalid, got {:?}", other),
    }
}

#[test]
fn cached_announce_stored_on_path_learn() {
    let mut t = TestTransport::new();
    let announcer = Identity::from_seed(b"cached-announce-test").unwrap();
    let mut rng = rand::thread_rng();

    let mut buf = [0u8; MTU];
    let identity = Identity::from_seed(b"test-identity").unwrap();
    let n = Transport::<64, 16, 128, 4>::create_announce(
        &announcer,
        "testapp",
        &["aspect1"],
        None,
        None,
        &mut rng,
        1000,
        &mut buf,
    )
    .unwrap();

    let mut ann = buf[..n].to_vec();
    match t.ingest(&mut ann, 1000, &mut rng, &identity) {
        IngestResult::AnnounceReceived { dest_hash, .. } => {
            let path = t.get_path(&dest_hash).expect("path should exist");
            assert!(
                path.announce_raw.is_some(),
                "path should have cached announce"
            );
        }
        other => panic!("expected AnnounceReceived, got {:?}", other),
    }
}
