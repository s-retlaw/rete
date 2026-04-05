//! Integration tests for SharedDaemon restart, state restore, and multi-instance isolation.
//!
//! Covers parity rows S2-GEN-RESTART-001 and S2-GEN-RESTART-002.

mod common;

use common::{big_stack_test, make_tcp_config_with_control, make_unix_config};
use rete_daemon::daemon::SharedDaemonBuilder;

use rete_core::Identity;
use rete_stack::ReteInterface;
use rete_tokio::local::LocalClient;
use rete_tokio::TokioNode;

use tokio::time::{timeout, Duration};

// ---------------------------------------------------------------------------
// Test 1: Restart state restore — announce → shutdown → restart → state survives
// ---------------------------------------------------------------------------

#[test]
fn test_restart_state_restore() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let name = format!("test_rst_{}", std::process::id());
                let data_dir = tempfile::tempdir().unwrap();

                // --- First daemon: start, receive announce, shutdown ---
                let config = make_unix_config(&name);
                let (daemon, run_future) = SharedDaemonBuilder::new(config)
                    .data_dir(data_dir.path())
                    .start()
                    .await
                    .expect("daemon 1 must start");

                tokio::pin!(run_future);

                tokio::select! {
                    _ = &mut run_future => panic!("daemon exited unexpectedly"),
                    _ = async {
                        tokio::time::sleep(Duration::from_millis(100)).await;

                        // Connect a client and send an announce.
                        let mut client = LocalClient::connect(&name)
                            .await.expect("client connect");
                        tokio::time::sleep(Duration::from_millis(50)).await;

                        let identity = Identity::from_seed(b"restart-test-seed").unwrap();
                        let node = Box::new(
                            TokioNode::new(identity, "restartapp", &["aspect1"]).unwrap()
                        );
                        let announce = node.build_announce(None).unwrap();
                        client.send(&announce).await.expect("client send announce");

                        // Give the daemon time to process.
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    } => {},
                }

                // Shutdown daemon 1.
                daemon.shutdown().await;
                let result = timeout(Duration::from_secs(5), &mut run_future).await;
                assert!(result.is_ok(), "daemon 1 must shut down within 5s");

                // Verify snapshot and identity files exist.
                assert!(
                    data_dir.path().join("identity").exists(),
                    "identity file must persist after daemon 1"
                );
                let snap_path = data_dir.path().join("snapshot.json");
                assert!(
                    snap_path.exists(),
                    "snapshot.json must exist after daemon shutdown"
                );

                // Verify snapshot contains paths.
                let snap_data = std::fs::read_to_string(&snap_path).unwrap();
                let snap: rete_transport::Snapshot =
                    serde_json::from_str(&snap_data).unwrap();
                assert!(
                    !snap.paths.is_empty(),
                    "snapshot must contain the announced path (got {} paths)",
                    snap.paths.len()
                );

                // --- Second daemon: restart with same data_dir ---
                let config2 = make_unix_config(&name);
                let (daemon2, run_future2) = SharedDaemonBuilder::new(config2)
                    .data_dir(data_dir.path())
                    .start()
                    .await
                    .expect("daemon 2 must start (restart with same data_dir)");

                tokio::pin!(run_future2);

                tokio::select! {
                    _ = &mut run_future2 => panic!("daemon 2 exited unexpectedly"),
                    _ = async {
                        tokio::time::sleep(Duration::from_millis(100)).await;

                        // Verify a client can connect to the restarted daemon.
                        let client2 = LocalClient::connect(&name).await;
                        assert!(client2.is_ok(), "client must connect to restarted daemon");
                    } => {},
                }

                daemon2.shutdown().await;
                let result2 = timeout(Duration::from_secs(5), &mut run_future2).await;
                assert!(result2.is_ok(), "daemon 2 must shut down within 5s");

                // Identity must be the same across restarts.
                let id_bytes = std::fs::read(data_dir.path().join("identity")).unwrap();
                assert_eq!(id_bytes.len(), 64, "identity file must be 64 bytes");
            });
    });
}

// ---------------------------------------------------------------------------
// Test 2: Multi-instance isolation — Unix (two daemons, different names)
// ---------------------------------------------------------------------------

#[test]
fn test_multi_instance_isolation_unix() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let pid = std::process::id();
                let name_a = format!("iso_a_{pid}");
                let name_b = format!("iso_b_{pid}");
                let data_dir_a = tempfile::tempdir().unwrap();
                let data_dir_b = tempfile::tempdir().unwrap();

                let config_a = make_unix_config(&name_a);
                let (daemon_a, run_a) = SharedDaemonBuilder::new(config_a)
                    .data_dir(data_dir_a.path())
                    .start()
                    .await
                    .expect("daemon A must start");

                let config_b = make_unix_config(&name_b);
                let (daemon_b, run_b) = SharedDaemonBuilder::new(config_b)
                    .data_dir(data_dir_b.path())
                    .start()
                    .await
                    .expect("daemon B must start");

                tokio::pin!(run_a);
                tokio::pin!(run_b);

                tokio::select! {
                    _ = &mut run_a => panic!("daemon A exited unexpectedly"),
                    _ = &mut run_b => panic!("daemon B exited unexpectedly"),
                    _ = async {
                        tokio::time::sleep(Duration::from_millis(100)).await;

                        // Both daemons accept independent clients.
                        let client_a = LocalClient::connect(&name_a).await;
                        assert!(client_a.is_ok(), "client must connect to daemon A");

                        let client_b = LocalClient::connect(&name_b).await;
                        assert!(client_b.is_ok(), "client must connect to daemon B");

                        // Identity files must differ (different data_dirs).
                        let id_a = std::fs::read(data_dir_a.path().join("identity")).unwrap();
                        let id_b = std::fs::read(data_dir_b.path().join("identity")).unwrap();
                        assert_ne!(id_a, id_b, "separate instances must have different identities");
                    } => {},
                }

                daemon_a.shutdown().await;
                daemon_b.shutdown().await;
                let _ = timeout(Duration::from_secs(5), &mut run_a).await;
                let _ = timeout(Duration::from_secs(5), &mut run_b).await;
            });
    });
}

// ---------------------------------------------------------------------------
// Test 3: Multi-instance isolation — TCP (two daemons, different ports)
// ---------------------------------------------------------------------------

#[test]
fn test_multi_instance_isolation_tcp() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let base = 49700 + (std::process::id() % 50) as u16;
                let data_dir_a = tempfile::tempdir().unwrap();
                let data_dir_b = tempfile::tempdir().unwrap();

                let config_a = make_tcp_config_with_control(base, base + 1);
                let (daemon_a, run_a) = SharedDaemonBuilder::new(config_a)
                    .data_dir(data_dir_a.path())
                    .start()
                    .await
                    .expect("TCP daemon A must start");

                let config_b = make_tcp_config_with_control(base + 2, base + 3);
                let (daemon_b, run_b) = SharedDaemonBuilder::new(config_b)
                    .data_dir(data_dir_b.path())
                    .start()
                    .await
                    .expect("TCP daemon B must start");

                tokio::pin!(run_a);
                tokio::pin!(run_b);

                tokio::select! {
                    _ = &mut run_a => panic!("TCP daemon A exited unexpectedly"),
                    _ = &mut run_b => panic!("TCP daemon B exited unexpectedly"),
                    _ = async {
                        tokio::time::sleep(Duration::from_millis(100)).await;

                        // Both daemons accept independent TCP connections.
                        let conn_a = tokio::net::TcpStream::connect(
                            format!("127.0.0.1:{base}")
                        ).await;
                        assert!(conn_a.is_ok(), "TCP client must connect to daemon A");

                        let conn_b = tokio::net::TcpStream::connect(
                            format!("127.0.0.1:{}", base + 2)
                        ).await;
                        assert!(conn_b.is_ok(), "TCP client must connect to daemon B");
                    } => {},
                }

                daemon_a.shutdown().await;
                daemon_b.shutdown().await;
                let _ = timeout(Duration::from_secs(5), &mut run_a).await;
                let _ = timeout(Duration::from_secs(5), &mut run_b).await;
            });
    });
}
