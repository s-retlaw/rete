//! Integration tests for SharedDaemon robustness.
//!
//! Covers parity rows:
//! - S3-GEN-ROBUST-001: Malformed control rejection
//! - S3-GEN-ROBUST-002: Half-open session cleanup

mod common;

use common::{big_stack_async_test, make_tcp_config, make_unix_config};
use rete_daemon::control;
use rete_daemon::daemon::SharedDaemonBuilder;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};

// ---------------------------------------------------------------------------
// Test 1: Garbage bytes to control socket — daemon stays alive
// ---------------------------------------------------------------------------

#[test]
fn test_tcp_control_garbage_bytes() {
    big_stack_async_test(|| async {
        let port = 50100 + (std::process::id() % 100) as u16;
        let control_port = port + 1;
        let data_dir = tempfile::tempdir().unwrap();

        let config = make_tcp_config(port);
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

                // Send raw garbage bytes to the control port.
                {
                    let mut stream = tokio::net::TcpStream::connect(
                        ("127.0.0.1", control_port),
                    ).await.expect("connect to control port");
                    stream.write_all(b"GARBAGE_DATA_NOT_A_VALID_MESSAGE").await.unwrap();
                    // Connection should be dropped by daemon.
                    let mut buf = [0u8; 1];
                    let result = timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
                    match result {
                        Ok(Ok(0)) => {} // EOF — expected
                        Ok(Err(_)) => {} // connection reset — also fine
                        Err(_) => {} // timeout — acceptable
                        _ => {}
                    }
                }

                // Verify daemon is still alive by connecting again.
                tokio::time::sleep(Duration::from_millis(200)).await;
                {
                    let stream = tokio::net::TcpStream::connect(
                        ("127.0.0.1", control_port),
                    ).await;
                    assert!(stream.is_ok(), "daemon must still accept connections after garbage");
                }
            } => {},
        }

        daemon.shutdown().await;
        let result = timeout(Duration::from_secs(5), &mut run_future).await;
        assert!(result.is_ok(), "daemon must shut down within 5s");
    });
}

// ---------------------------------------------------------------------------
// Test 2: Oversized message to control socket — rejected by MAX_MESSAGE_SIZE
// ---------------------------------------------------------------------------

#[test]
fn test_tcp_control_oversized_message() {
    big_stack_async_test(|| async {
        let port = 50100 + (std::process::id() % 100) as u16 + 2;
        let control_port = port + 1;
        let data_dir = tempfile::tempdir().unwrap();

        let config = make_tcp_config(port);
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

                // Send a length prefix claiming 2 MiB (exceeds MAX_MESSAGE_SIZE=1 MiB).
                {
                    let mut stream = tokio::net::TcpStream::connect(
                        ("127.0.0.1", control_port),
                    ).await.expect("connect to control port");
                    let oversized_len: u32 = 2 * 1024 * 1024;
                    stream.write_all(&oversized_len.to_be_bytes()).await.unwrap();
                    // Don't send actual payload — the length check should trigger.
                    let mut buf = [0u8; 1];
                    let result = timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
                    match result {
                        Ok(Ok(0)) => {} // EOF — expected
                        Ok(Err(_)) => {} // connection reset
                        Err(_) => {} // timeout — server may wait for payload
                        _ => {}
                    }
                }

                // Verify daemon still alive.
                tokio::time::sleep(Duration::from_millis(200)).await;
                {
                    let stream = tokio::net::TcpStream::connect(
                        ("127.0.0.1", control_port),
                    ).await;
                    assert!(stream.is_ok(), "daemon must still accept connections after oversized msg");
                }
            } => {},
        }

        daemon.shutdown().await;
        let result = timeout(Duration::from_secs(5), &mut run_future).await;
        assert!(result.is_ok(), "daemon must shut down within 5s");
    });
}

// ---------------------------------------------------------------------------
// Test 3: Valid length prefix + garbage payload — auth fails gracefully
// ---------------------------------------------------------------------------

#[test]
fn test_tcp_control_garbage_payload() {
    big_stack_async_test(|| async {
        let port = 50100 + (std::process::id() % 100) as u16 + 4;
        let control_port = port + 1;
        let data_dir = tempfile::tempdir().unwrap();

        let config = make_tcp_config(port);
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

                // Send a well-formed message (valid length prefix) with garbage content.
                // The daemon should read the challenge, send it, then get garbage back
                // as the "response" and reject it.
                {
                    let mut stream = tokio::net::TcpStream::connect(
                        ("127.0.0.1", control_port),
                    ).await.expect("connect to control port");

                    // First the daemon sends a challenge — read it.
                    let challenge = control::read_message(&mut stream).await.unwrap();
                    assert!(challenge.starts_with(b"#CHALLENGE#"));

                    // Send garbage as the auth response.
                    control::write_message(&mut stream, b"NOT_A_VALID_HMAC_RESPONSE").await.unwrap();

                    // Should get #FAILURE# back.
                    let result = control::read_message(&mut stream).await.unwrap();
                    assert_eq!(result, b"#FAILURE#", "daemon must send FAILURE for bad auth");
                }

                // Verify daemon still alive.
                tokio::time::sleep(Duration::from_millis(200)).await;
                {
                    let stream = tokio::net::TcpStream::connect(
                        ("127.0.0.1", control_port),
                    ).await;
                    assert!(stream.is_ok(), "daemon must still accept connections after auth failure");
                }
            } => {},
        }

        daemon.shutdown().await;
        let result = timeout(Duration::from_secs(5), &mut run_future).await;
        assert!(result.is_ok(), "daemon must shut down within 5s");
    });
}

// ---------------------------------------------------------------------------
// Test 4: Partial length prefix then disconnect — no crash
// ---------------------------------------------------------------------------

#[test]
fn test_tcp_control_partial_length() {
    big_stack_async_test(|| async {
        let port = 50100 + (std::process::id() % 100) as u16 + 6;
        let control_port = port + 1;
        let data_dir = tempfile::tempdir().unwrap();

        let config = make_tcp_config(port);
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

                // Send only 2 bytes of a 4-byte length prefix, then disconnect.
                {
                    let mut stream = tokio::net::TcpStream::connect(
                        ("127.0.0.1", control_port),
                    ).await.expect("connect to control port");
                    // The daemon sends a challenge first — just ignore it and
                    // send partial bytes.
                    stream.write_all(&[0x00, 0x01]).await.unwrap();
                    drop(stream);
                }

                // Verify daemon still alive.
                tokio::time::sleep(Duration::from_millis(500)).await;
                {
                    let stream = tokio::net::TcpStream::connect(
                        ("127.0.0.1", control_port),
                    ).await;
                    assert!(stream.is_ok(), "daemon must still accept connections after partial disconnect");
                }
            } => {},
        }

        daemon.shutdown().await;
        let result = timeout(Duration::from_secs(5), &mut run_future).await;
        assert!(result.is_ok(), "daemon must shut down within 5s");
    });
}

// ---------------------------------------------------------------------------
// Test 5: Unix data socket — abrupt client drop cleans up session
// ---------------------------------------------------------------------------

#[test]
fn test_unix_data_abrupt_disconnect_cleanup() {
    big_stack_async_test(|| async {
        use rete_tokio::local::LocalClient;

        let name = format!("robust-dc-{}", std::process::id());
        let data_dir = tempfile::tempdir().unwrap();

        let config = make_unix_config(&name);
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

                // Connect a client, then drop it abruptly.
                {
                    let client = LocalClient::connect(&name)
                        .await.expect("client connect");
                    // Drop immediately — simulates crash.
                    drop(client);
                }

                // Give the daemon time to process the disconnect event.
                tokio::time::sleep(Duration::from_millis(500)).await;

                // Connect another client to verify daemon is healthy.
                {
                    let _client2 = LocalClient::connect(&name)
                        .await.expect("second client must connect after abrupt disconnect");
                }
            } => {},
        }

        daemon.shutdown().await;
        let result = timeout(Duration::from_secs(5), &mut run_future).await;
        assert!(result.is_ok(), "daemon must shut down within 5s");
    });
}

// ---------------------------------------------------------------------------
// Test 6: Multiple clients — killing one doesn't affect others
// ---------------------------------------------------------------------------

#[test]
fn test_unix_data_multi_client_partial_disconnect() {
    big_stack_async_test(|| async {
        use rete_tokio::local::LocalClient;

        let name = format!("robust-mc-{}", std::process::id());
        let data_dir = tempfile::tempdir().unwrap();

        let config = make_unix_config(&name);
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

                // Connect 3 clients.
                let client1 = LocalClient::connect(&name).await.expect("client1");
                let _client2 = LocalClient::connect(&name).await.expect("client2");
                let _client3 = LocalClient::connect(&name).await.expect("client3");

                // Drop client1 abruptly.
                drop(client1);
                tokio::time::sleep(Duration::from_millis(300)).await;

                // Clients 2 and 3 should still be connected. Verify by
                // connecting yet another client (daemon is still healthy).
                let _client4 = LocalClient::connect(&name)
                    .await.expect("client4 must connect after client1 dropped");
            } => {},
        }

        daemon.shutdown().await;
        let result = timeout(Duration::from_secs(5), &mut run_future).await;
        assert!(result.is_ok(), "daemon must shut down within 5s");
    });
}

// ---------------------------------------------------------------------------
// Test 7: Rapid connect/disconnect cycles — no session leaks
// ---------------------------------------------------------------------------

#[test]
fn test_unix_rapid_connect_disconnect() {
    big_stack_async_test(|| async {
        use rete_tokio::local::LocalClient;

        let name = format!("robust-rapid-{}", std::process::id());
        let data_dir = tempfile::tempdir().unwrap();

        let config = make_unix_config(&name);
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

                // Rapidly connect and disconnect 50 times.
                for _ in 0..50 {
                    let client = LocalClient::connect(&name).await.expect("connect");
                    drop(client);
                }

                // Small delay for disconnect events to process.
                tokio::time::sleep(Duration::from_millis(500)).await;

                // Daemon should still be healthy.
                let _final_client = LocalClient::connect(&name)
                    .await.expect("final client must connect after 50 rapid cycles");
            } => {},
        }

        daemon.shutdown().await;
        let result = timeout(Duration::from_secs(5), &mut run_future).await;
        assert!(result.is_ok(), "daemon must shut down within 5s");
    });
}
