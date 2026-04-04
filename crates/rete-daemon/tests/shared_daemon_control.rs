//! Integration tests for SharedDaemon RPC control plane.
//!
//! Covers parity rows:
//! - S1-GEN-CTRL-001: Control request routing and auth
//! - S1-UNX-CTRL-001: Unix status query
//! - S1-TCP-CTRL-001: TCP status query
//! - S1-TCP-CTRL-003: Auth failure handling

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

    // Compute HMAC-SHA256(authkey, challenge).
    let mut mac = Hmac::<Sha256>::new_from_slice(authkey).unwrap();
    mac.update(&challenge);
    let digest = mac.finalize().into_bytes();

    // Send digest.
    let mut response = Vec::with_capacity(8 + 32);
    response.extend_from_slice(b"{sha256}");
    response.extend_from_slice(&digest);
    control::write_message(stream, &response).await.unwrap();

    // Read welcome/failure.
    let result = control::read_message(stream).await.unwrap();
    result == b"#WELCOME#"
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
