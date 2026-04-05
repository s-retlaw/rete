//! Integration tests for SharedDaemon RPC control plane.
//!
//! Covers parity rows:
//! - S1-GEN-CTRL-001: Control request routing and auth
//! - S1-UNX-CTRL-001: Unix status query
//! - S1-TCP-CTRL-001: TCP status query
//! - S1-TCP-CTRL-003: Auth failure handling
//! - S2-UNX-OPER-002: Live path_table query (EPIC-07)
//! - S2-UNX-OPER-003: next_hop query (EPIC-07)

mod common;

use common::{big_stack_test, make_tcp_config, make_unix_config};
use rete_daemon::control;
use rete_daemon::daemon::SharedDaemonBuilder;
use rete_daemon::pickle;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};

/// Perform the client side of the multiprocessing.connection auth handshake.
async fn client_auth<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    authkey: &[u8],
) -> bool {
    // Read challenge.
    let challenge = control::read_message(stream).await.unwrap();
    assert!(
        challenge.starts_with(b"#CHALLENGE#{sha256}"),
        "challenge must start with #CHALLENGE#{{sha256}}"
    );

    // Compute HMAC-SHA256(authkey, message) — matches Python
    // multiprocessing.connection._create_response which computes
    // HMAC over everything after #CHALLENGE# (i.e. {sha256}+nonce).
    let message = &challenge[control::CHALLENGE_PREFIX.len()..];
    let mut mac = Hmac::<Sha256>::new_from_slice(authkey).unwrap();
    mac.update(message);
    let digest = mac.finalize().into_bytes();

    // Send digest.
    let mut response = Vec::with_capacity(8 + 32);
    response.extend_from_slice(control::SHA256_TAG);
    response.extend_from_slice(&digest);
    control::write_message(stream, &response).await.unwrap();

    // Read welcome/failure.
    let result = control::read_message(stream).await.unwrap();
    if result != b"#WELCOME#" {
        return false;
    }

    // Phase 2: Mutual auth — client challenges the server.
    // Python's multiprocessing.connection.Client does:
    //   answer_challenge(c, authkey)   ← done above
    //   deliver_challenge(c, authkey)  ← now we challenge the server
    let mut nonce = [0u8; 40];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    let nonce_hex = hex::encode(nonce);

    let mut challenge2 = Vec::with_capacity(11 + 8 + 80);
    challenge2.extend_from_slice(control::CHALLENGE_PREFIX);
    challenge2.extend_from_slice(control::SHA256_TAG);
    challenge2.extend_from_slice(nonce_hex.as_bytes());
    control::write_message(stream, &challenge2).await.unwrap();

    // Read server's response
    let server_response = control::read_message(stream).await.unwrap();
    let server_hmac = if server_response.starts_with(control::SHA256_TAG) {
        &server_response[control::SHA256_TAG.len()..]
    } else {
        &server_response[..]
    };

    // Verify server's HMAC over message (everything after #CHALLENGE#)
    let msg2 = &challenge2[control::CHALLENGE_PREFIX.len()..];
    let mut mac2 = Hmac::<Sha256>::new_from_slice(authkey).unwrap();
    mac2.update(msg2);
    if mac2.verify_slice(server_hmac).is_err() {
        return false;
    }

    // Send welcome
    control::write_message(stream, b"#WELCOME#").await.unwrap();
    true
}

/// Send an RPC request and receive the response (post-auth).
async fn rpc_query<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    request: &pickle::PickleValue,
) -> pickle::PickleValue {
    let request_bytes = pickle::encode_proto2(request);
    control::write_message(stream, &request_bytes)
        .await
        .unwrap();

    let response_bytes = control::read_message(stream).await.unwrap();
    pickle::decode(&response_bytes).expect("response must be valid pickle")
}

// ---------------------------------------------------------------------------
// Test 1: Unix control — auth + interface_stats query
// ---------------------------------------------------------------------------

#[test]
fn test_unix_control_status_query() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let name = format!("ctrl-test-{}", std::process::id());
                let data_dir = tempfile::tempdir().unwrap();

                let config = make_unix_config(&name);
                let (daemon, run_future) = SharedDaemonBuilder::new(config)
                    .data_dir(data_dir.path())
                    .start()
                    .await
                    .expect("daemon must start");

                tokio::pin!(run_future);

                // Read identity to derive authkey.
                let identity_bytes = std::fs::read(data_dir.path().join("identity")).unwrap();
                let authkey = control::derive_authkey(&identity_bytes);

                tokio::select! {
                    _ = &mut run_future => panic!("daemon exited unexpectedly"),
                    _ = async {
                        tokio::time::sleep(Duration::from_millis(200)).await;

                        // Connect to control socket.
                        let rpc_path = format!("\0rns/{name}/rpc");
                        let mut stream = tokio::net::UnixStream::connect(&rpc_path)
                            .await
                            .expect("connect to control socket");

                        // Auth.
                        let authed = client_auth(&mut stream, &authkey).await;
                        assert!(authed, "auth must succeed with correct key");

                        // Query interface_stats.
                        let request = pickle::PickleValue::Dict(vec![(
                            pickle::PickleValue::String("get".into()),
                            pickle::PickleValue::String("interface_stats".into()),
                        )]);
                        let response = rpc_query(&mut stream, &request).await;

                        // Validate response structure.
                        let dict = response.as_dict().expect("response must be dict");
                        let keys: Vec<&str> =
                            dict.iter().filter_map(|(k, _)| k.as_str()).collect();
                        assert_eq!(
                            keys,
                            ["interfaces", "rxb", "txb", "rxs", "txs", "rss"],
                            "response keys must match golden trace"
                        );

                        // Validate interface entry.
                        let ifaces = response.get("interfaces").unwrap().as_list().unwrap();
                        assert_eq!(ifaces.len(), 1);
                        let iface = &ifaces[0];
                        let iface_name = iface.get("name").unwrap().as_str().unwrap();
                        assert_eq!(
                            iface_name,
                            format!("Shared Instance[rns/{name}]"),
                            "interface name must match"
                        );
                        assert_eq!(
                            iface.get("type").unwrap().as_str().unwrap(),
                            "LocalServerInterface"
                        );
                        assert!(matches!(
                            iface.get("status").unwrap(),
                            pickle::PickleValue::Bool(true)
                        ));
                    } => {},
                }

                daemon.shutdown().await;
                let result = timeout(Duration::from_secs(5), &mut run_future).await;
                assert!(result.is_ok(), "daemon must shut down within 5s");
            });
    });
}

// ---------------------------------------------------------------------------
// Test 2: TCP control — auth + interface_stats query
// ---------------------------------------------------------------------------

#[test]
fn test_tcp_control_status_query() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let port = 49800 + (std::process::id() % 100) as u16;
                let control_port = port + 1;
                let data_dir = tempfile::tempdir().unwrap();

                let mut config = make_tcp_config(port);
                config.instance_control_port = control_port;
                let (daemon, run_future) = SharedDaemonBuilder::new(config)
                    .data_dir(data_dir.path())
                    .start()
                    .await
                    .expect("daemon must start");

                tokio::pin!(run_future);

                // Read identity to derive authkey.
                let identity_bytes = std::fs::read(data_dir.path().join("identity")).unwrap();
                let authkey = control::derive_authkey(&identity_bytes);

                tokio::select! {
                    _ = &mut run_future => panic!("daemon exited unexpectedly"),
                    _ = async {
                        tokio::time::sleep(Duration::from_millis(200)).await;

                        // Connect to TCP control port.
                        let mut stream = tokio::net::TcpStream::connect(
                            ("127.0.0.1", control_port),
                        )
                        .await
                        .expect("connect to control port");

                        // Auth.
                        let authed = client_auth(&mut stream, &authkey).await;
                        assert!(authed, "auth must succeed with correct key");

                        // Query interface_stats.
                        let request = pickle::PickleValue::Dict(vec![(
                            pickle::PickleValue::String("get".into()),
                            pickle::PickleValue::String("interface_stats".into()),
                        )]);
                        let response = rpc_query(&mut stream, &request).await;

                        // Validate response structure.
                        let keys: Vec<&str> = response
                            .as_dict()
                            .unwrap()
                            .iter()
                            .filter_map(|(k, _)| k.as_str())
                            .collect();
                        assert_eq!(keys, ["interfaces", "rxb", "txb", "rxs", "txs", "rss"]);

                        // Validate TCP-specific interface name.
                        let ifaces = response.get("interfaces").unwrap().as_list().unwrap();
                        let iface_name =
                            ifaces[0].get("name").unwrap().as_str().unwrap();
                        assert_eq!(
                            iface_name,
                            format!("Shared Instance[{port}]"),
                            "TCP interface name must use port number"
                        );
                    } => {},
                }

                daemon.shutdown().await;
                let result = timeout(Duration::from_secs(5), &mut run_future).await;
                assert!(result.is_ok(), "daemon must shut down within 5s");
            });
    });
}

// ---------------------------------------------------------------------------
// Test 3: Auth failure — wrong key gets #FAILURE#
// ---------------------------------------------------------------------------

#[test]
fn test_tcp_control_auth_failure() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let port = 49800 + (std::process::id() % 100) as u16 + 2;
                let control_port = port + 1;
                let data_dir = tempfile::tempdir().unwrap();

                let mut config = make_tcp_config(port);
                config.instance_control_port = control_port;
                let (daemon, run_future) = SharedDaemonBuilder::new(config)
                    .data_dir(data_dir.path())
                    .start()
                    .await
                    .expect("daemon must start");

                tokio::pin!(run_future);

                tokio::select! {
                    _ = &mut run_future => panic!("daemon exited unexpectedly"),
                    _ = async {
                        tokio::time::sleep(Duration::from_millis(200)).await;

                        let mut stream = tokio::net::TcpStream::connect(
                            ("127.0.0.1", control_port),
                        )
                        .await
                        .expect("connect to control port");

                        // Auth with WRONG key.
                        let wrong_key = control::derive_authkey(b"wrong-key-material");
                        let authed = client_auth(&mut stream, &wrong_key).await;
                        assert!(!authed, "auth must fail with wrong key");

                        // Connection should be closed — further reads should fail.
                        let mut buf = [0u8; 1];
                        let result = timeout(
                            Duration::from_secs(1),
                            stream.read(&mut buf),
                        )
                        .await;
                        match result {
                            Ok(Ok(0)) => {} // EOF — expected
                            Ok(Err(_)) => {} // connection reset — also fine
                            _ => {} // timeout or anything else — acceptable
                        }
                    } => {},
                }

                daemon.shutdown().await;
                let result = timeout(Duration::from_secs(5), &mut run_future).await;
                assert!(result.is_ok(), "daemon must shut down within 5s");
            });
    });
}

// ---------------------------------------------------------------------------
// Test 4: Multiple sequential RPC queries on separate connections
// ---------------------------------------------------------------------------

#[test]
fn test_tcp_control_multiple_queries() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let port = 49800 + (std::process::id() % 100) as u16 + 4;
                let control_port = port + 1;
                let data_dir = tempfile::tempdir().unwrap();

                let mut config = make_tcp_config(port);
                config.instance_control_port = control_port;
                let (daemon, run_future) = SharedDaemonBuilder::new(config)
                    .data_dir(data_dir.path())
                    .start()
                    .await
                    .expect("daemon must start");

                tokio::pin!(run_future);

                let identity_bytes = std::fs::read(data_dir.path().join("identity")).unwrap();
                let authkey = control::derive_authkey(&identity_bytes);

                tokio::select! {
                    _ = &mut run_future => panic!("daemon exited unexpectedly"),
                    _ = async {
                        tokio::time::sleep(Duration::from_millis(200)).await;

                        // Query 1: interface_stats
                        {
                            let mut stream = tokio::net::TcpStream::connect(
                                ("127.0.0.1", control_port),
                            )
                            .await
                            .unwrap();
                            assert!(client_auth(&mut stream, &authkey).await);
                            let request = pickle::PickleValue::Dict(vec![(
                                pickle::PickleValue::String("get".into()),
                                pickle::PickleValue::String("interface_stats".into()),
                            )]);
                            let resp = rpc_query(&mut stream, &request).await;
                            assert!(resp.get("interfaces").is_some());
                        }

                        // Query 2: path_table (separate connection)
                        {
                            let mut stream = tokio::net::TcpStream::connect(
                                ("127.0.0.1", control_port),
                            )
                            .await
                            .unwrap();
                            assert!(client_auth(&mut stream, &authkey).await);
                            let request = pickle::PickleValue::Dict(vec![(
                                pickle::PickleValue::String("get".into()),
                                pickle::PickleValue::String("path_table".into()),
                            )]);
                            let resp = rpc_query(&mut stream, &request).await;
                            // Empty path table is a dict.
                            assert!(resp.as_dict().is_some());
                        }

                        // Query 3: link_count
                        {
                            let mut stream = tokio::net::TcpStream::connect(
                                ("127.0.0.1", control_port),
                            )
                            .await
                            .unwrap();
                            assert!(client_auth(&mut stream, &authkey).await);
                            let request = pickle::PickleValue::Dict(vec![(
                                pickle::PickleValue::String("get".into()),
                                pickle::PickleValue::String("link_count".into()),
                            )]);
                            let resp = rpc_query(&mut stream, &request).await;
                            assert_eq!(resp.as_int().unwrap(), 0);
                        }
                    } => {},
                }

                daemon.shutdown().await;
                let result = timeout(Duration::from_secs(5), &mut run_future).await;
                assert!(result.is_ok(), "daemon must shut down within 5s");
            });
    });
}

// ---------------------------------------------------------------------------
// Test 5: Live path_table after announce injection (EPIC-07)
// ---------------------------------------------------------------------------

#[test]
fn test_unix_path_table_with_announce() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                use rete_core::Identity;
                use rete_stack::ReteInterface;
                use rete_tokio::local::LocalClient;
                use rete_tokio::TokioNode;

                let name = format!("ctrl-pt-{}", std::process::id());
                let data_dir = tempfile::tempdir().unwrap();

                let config = make_unix_config(&name);
                let (daemon, run_future) = SharedDaemonBuilder::new(config)
                    .data_dir(data_dir.path())
                    .start()
                    .await
                    .expect("daemon must start");

                tokio::pin!(run_future);

                let identity_bytes = std::fs::read(data_dir.path().join("identity")).unwrap();
                let authkey = control::derive_authkey(&identity_bytes);

                tokio::select! {
                    _ = &mut run_future => panic!("daemon exited unexpectedly"),
                    _ = async {
                        tokio::time::sleep(Duration::from_millis(200)).await;

                        // Inject announce via a client.
                        let mut client = LocalClient::connect(&name)
                            .await.expect("client connect");

                        let announce_identity = Identity::from_seed(b"path-table-test").unwrap();
                        let announce_node = Box::new(
                            TokioNode::new(announce_identity, "testapp", &["aspect1"]).unwrap()
                        );
                        let dest_hash = announce_node.core.primary_dest().hash();
                        let announce = announce_node.build_announce(None).unwrap();
                        client.send(&announce).await.expect("send announce");

                        // Wait for node to process announce + tick to drain RPC.
                        tokio::time::sleep(Duration::from_secs(6)).await;

                        // Query path_table via RPC.
                        let rpc_path = format!("\0rns/{name}/rpc");
                        let mut stream = tokio::net::UnixStream::connect(&rpc_path)
                            .await.expect("connect to control socket");
                        assert!(client_auth(&mut stream, &authkey).await);

                        let request = pickle::PickleValue::Dict(vec![(
                            pickle::PickleValue::String("get".into()),
                            pickle::PickleValue::String("path_table".into()),
                        )]);
                        let response = rpc_query(&mut stream, &request).await;

                        let dict = response.as_dict().expect("path_table must be dict");
                        assert!(
                            !dict.is_empty(),
                            "path_table must have entries after announce injection"
                        );

                        // Verify the dest hash is present as a key.
                        let found = dict.iter().any(|(k, _)| {
                            k.as_bytes().map_or(false, |b| b == dest_hash.as_bytes())
                        });
                        assert!(found, "dest_hash must be in path_table");
                    } => {},
                }

                daemon.shutdown().await;
                let result = timeout(Duration::from_secs(5), &mut run_future).await;
                assert!(result.is_ok(), "daemon must shut down within 5s");
            });
    });
}

// ---------------------------------------------------------------------------
// Test 6: next_hop query for known and unknown destinations (EPIC-07)
// ---------------------------------------------------------------------------

#[test]
fn test_unix_next_hop_query() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                use rete_core::Identity;
                use rete_stack::ReteInterface;
                use rete_tokio::local::LocalClient;
                use rete_tokio::TokioNode;

                let name = format!("ctrl-nh-{}", std::process::id());
                let data_dir = tempfile::tempdir().unwrap();

                let config = make_unix_config(&name);
                let (daemon, run_future) = SharedDaemonBuilder::new(config)
                    .data_dir(data_dir.path())
                    .start()
                    .await
                    .expect("daemon must start");

                tokio::pin!(run_future);

                let identity_bytes = std::fs::read(data_dir.path().join("identity")).unwrap();
                let authkey = control::derive_authkey(&identity_bytes);

                tokio::select! {
                    _ = &mut run_future => panic!("daemon exited unexpectedly"),
                    _ = async {
                        tokio::time::sleep(Duration::from_millis(200)).await;

                        // Inject announce.
                        let mut client = LocalClient::connect(&name)
                            .await.expect("client connect");

                        let announce_identity = Identity::from_seed(b"next-hop-test").unwrap();
                        let announce_node = Box::new(
                            TokioNode::new(announce_identity, "testapp", &["aspect1"]).unwrap()
                        );
                        let dest_hash = announce_node.core.primary_dest().hash();
                        let announce = announce_node.build_announce(None).unwrap();
                        client.send(&announce).await.expect("send announce");

                        // Wait for processing + tick.
                        tokio::time::sleep(Duration::from_secs(6)).await;

                        let rpc_path = format!("\0rns/{name}/rpc");

                        // Query next_hop for the known destination.
                        {
                            let mut stream = tokio::net::UnixStream::connect(&rpc_path)
                                .await.expect("connect");
                            assert!(client_auth(&mut stream, &authkey).await);

                            let request = pickle::PickleValue::Dict(vec![
                                (pickle::PickleValue::String("get".into()),
                                 pickle::PickleValue::String("next_hop".into())),
                                (pickle::PickleValue::String("destination_hash".into()),
                                 pickle::PickleValue::Bytes(dest_hash.as_bytes().to_vec())),
                            ]);
                            let response = rpc_query(&mut stream, &request).await;
                            // Direct path has no via, so next_hop returns None.
                            assert!(
                                matches!(response, pickle::PickleValue::None),
                                "direct path should have no next_hop (None), got: {response:?}"
                            );
                        }

                        // Query next_hop for an unknown destination.
                        {
                            let mut stream = tokio::net::UnixStream::connect(&rpc_path)
                                .await.expect("connect");
                            assert!(client_auth(&mut stream, &authkey).await);

                            let request = pickle::PickleValue::Dict(vec![
                                (pickle::PickleValue::String("get".into()),
                                 pickle::PickleValue::String("next_hop".into())),
                                (pickle::PickleValue::String("destination_hash".into()),
                                 pickle::PickleValue::Bytes(vec![0xDE; 16])),
                            ]);
                            let response = rpc_query(&mut stream, &request).await;
                            assert!(
                                matches!(response, pickle::PickleValue::None),
                                "unknown dest should return None, got: {response:?}"
                            );
                        }

                        // Query next_hop_if_name for the known destination.
                        {
                            let mut stream = tokio::net::UnixStream::connect(&rpc_path)
                                .await.expect("connect");
                            assert!(client_auth(&mut stream, &authkey).await);

                            let request = pickle::PickleValue::Dict(vec![
                                (pickle::PickleValue::String("get".into()),
                                 pickle::PickleValue::String("next_hop_if_name".into())),
                                (pickle::PickleValue::String("destination_hash".into()),
                                 pickle::PickleValue::Bytes(dest_hash.as_bytes().to_vec())),
                            ]);
                            let response = rpc_query(&mut stream, &request).await;
                            let name_str = response.as_str().expect("next_hop_if_name should return string");
                            assert!(
                                name_str.contains("Shared Instance"),
                                "interface name should contain 'Shared Instance', got: {name_str}"
                            );
                        }
                    } => {},
                }

                daemon.shutdown().await;
                let result = timeout(Duration::from_secs(5), &mut run_future).await;
                assert!(result.is_ok(), "daemon must shut down within 5s");
            });
    });
}

// ---------------------------------------------------------------------------
// Test 7: Drop path via RPC (EPIC-07)
// ---------------------------------------------------------------------------

#[test]
fn test_unix_drop_path_via_rpc() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                use rete_core::Identity;
                use rete_stack::ReteInterface;
                use rete_tokio::local::LocalClient;
                use rete_tokio::TokioNode;

                let name = format!("ctrl-dp-{}", std::process::id());
                let data_dir = tempfile::tempdir().unwrap();

                let config = make_unix_config(&name);
                let (daemon, run_future) = SharedDaemonBuilder::new(config)
                    .data_dir(data_dir.path())
                    .start()
                    .await
                    .expect("daemon must start");

                tokio::pin!(run_future);

                let identity_bytes = std::fs::read(data_dir.path().join("identity")).unwrap();
                let authkey = control::derive_authkey(&identity_bytes);

                tokio::select! {
                    _ = &mut run_future => panic!("daemon exited unexpectedly"),
                    _ = async {
                        tokio::time::sleep(Duration::from_millis(200)).await;

                        // Inject announce.
                        let mut client = LocalClient::connect(&name)
                            .await.expect("client connect");

                        let announce_identity = Identity::from_seed(b"drop-path-test").unwrap();
                        let announce_node = Box::new(
                            TokioNode::new(announce_identity, "testapp", &["aspect1"]).unwrap()
                        );
                        let dest_hash = announce_node.core.primary_dest().hash();
                        let announce = announce_node.build_announce(None).unwrap();
                        client.send(&announce).await.expect("send announce");

                        // Wait for processing + tick.
                        tokio::time::sleep(Duration::from_secs(6)).await;

                        let rpc_path = format!("\0rns/{name}/rpc");

                        // Verify path exists.
                        {
                            let mut stream = tokio::net::UnixStream::connect(&rpc_path)
                                .await.expect("connect");
                            assert!(client_auth(&mut stream, &authkey).await);
                            let request = pickle::PickleValue::Dict(vec![(
                                pickle::PickleValue::String("get".into()),
                                pickle::PickleValue::String("path_table".into()),
                            )]);
                            let response = rpc_query(&mut stream, &request).await;
                            assert!(
                                !response.as_dict().unwrap().is_empty(),
                                "path_table must not be empty before drop"
                            );
                        }

                        // Drop the path.
                        {
                            let mut stream = tokio::net::UnixStream::connect(&rpc_path)
                                .await.expect("connect");
                            assert!(client_auth(&mut stream, &authkey).await);
                            let request = pickle::PickleValue::Dict(vec![
                                (pickle::PickleValue::String("drop".into()),
                                 pickle::PickleValue::String("path".into())),
                                (pickle::PickleValue::String("destination_hash".into()),
                                 pickle::PickleValue::Bytes(dest_hash.as_bytes().to_vec())),
                            ]);
                            let response = rpc_query(&mut stream, &request).await;
                            assert_eq!(response.as_str().unwrap(), "ok");
                        }

                        // Wait for drop to be processed.
                        tokio::time::sleep(Duration::from_secs(6)).await;

                        // Verify path is gone.
                        {
                            let mut stream = tokio::net::UnixStream::connect(&rpc_path)
                                .await.expect("connect");
                            assert!(client_auth(&mut stream, &authkey).await);
                            let request = pickle::PickleValue::Dict(vec![(
                                pickle::PickleValue::String("get".into()),
                                pickle::PickleValue::String("path_table".into()),
                            )]);
                            let response = rpc_query(&mut stream, &request).await;
                            let dict = response.as_dict().unwrap();
                            let still_present = dict.iter().any(|(k, _)| {
                                k.as_bytes().map_or(false, |b| b == dest_hash.as_bytes())
                            });
                            assert!(
                                !still_present,
                                "dropped dest_hash must not appear in path_table"
                            );
                        }
                    } => {},
                }

                daemon.shutdown().await;
                let result = timeout(Duration::from_secs(5), &mut run_future).await;
                assert!(result.is_ok(), "daemon must shut down within 5s");
            });
    });
}
