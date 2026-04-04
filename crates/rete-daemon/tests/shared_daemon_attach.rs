//! Integration tests for SharedDaemon attach and packet relay.
//!
//! Covers parity row S1-GEN-ATTACH-001: Unix listener bind, accept, and relay.

mod common;

use common::{big_stack_test, make_unix_config};
use rete_daemon::daemon::SharedDaemonBuilder;

use rete_stack::ReteInterface;
use rete_tokio::local::LocalClient;

use tokio::time::{timeout, Duration};

// ---------------------------------------------------------------------------
// Test 1: Two Rust clients relay packets through the full daemon stack
// ---------------------------------------------------------------------------

#[test]
fn test_daemon_client_to_client_relay() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let name = format!("test_relay_{}", std::process::id());
                let data_dir = tempfile::tempdir().unwrap();

                let config = make_unix_config(&name);
                let (daemon, run_future) = SharedDaemonBuilder::new(config)
                    .data_dir(data_dir.path())
                    .start()
                    .await
                    .expect("daemon must start");

                tokio::pin!(run_future);

                // Drive the daemon future concurrently — the server accept loop
                // is spawned inside it and must be polled for relay to work.
                tokio::select! {
                    _ = &mut run_future => panic!("daemon exited unexpectedly"),
                    _ = async {
                        // Let the server accept loop start.
                        tokio::time::sleep(Duration::from_millis(100)).await;

                        let mut client1 = LocalClient::connect(&name)
                            .await.expect("client1 connect");
                        let mut client2 = LocalClient::connect(&name)
                            .await.expect("client2 connect");

                        // Client1 sends -> Client2 receives via relay
                        let test_data = b"hello from client1";
                        client1.send(test_data).await.expect("client1 send");

                        let mut buf = [0u8; 1024];
                        let received = timeout(Duration::from_secs(2), client2.recv(&mut buf))
                            .await
                            .expect("timeout waiting for relay")
                            .expect("client2 recv");
                        assert_eq!(received, test_data, "client2 must receive relayed packet");

                        // Client2 sends -> Client1 receives (bidirectional)
                        let reply_data = b"reply from client2";
                        client2.send(reply_data).await.expect("client2 send");

                        let received = timeout(Duration::from_secs(2), client1.recv(&mut buf))
                            .await
                            .expect("timeout waiting for reply")
                            .expect("client1 recv");
                        assert_eq!(received, reply_data, "client1 must receive reply");
                    } => {},
                }

                daemon.shutdown().await;
                let result = timeout(Duration::from_secs(5), &mut run_future).await;
                assert!(result.is_ok(), "daemon must shut down within 5s");
            });
    });
}

// ---------------------------------------------------------------------------
// Test 2: Client disconnect does not crash daemon or affect other clients
// ---------------------------------------------------------------------------

#[test]
fn test_daemon_client_disconnect_no_crash() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let name = format!("test_disc_{}", std::process::id());
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
                        tokio::time::sleep(Duration::from_millis(100)).await;

                        let client1 = LocalClient::connect(&name)
                            .await.expect("client1 connect");
                        let mut client2 = LocalClient::connect(&name)
                            .await.expect("client2 connect");

                        // Drop client1 — daemon must handle disconnect cleanly
                        drop(client1);
                        tokio::task::yield_now().await;
                        tokio::time::sleep(Duration::from_millis(50)).await;

                        // New client connects after disconnect
                        let mut client3 = LocalClient::connect(&name)
                            .await.expect("client3 connect");

                        // Client3 sends -> Client2 receives (relay still works)
                        let test_data = b"after disconnect";
                        client3.send(test_data).await.expect("client3 send");

                        let mut buf = [0u8; 1024];
                        let received = timeout(Duration::from_secs(2), client2.recv(&mut buf))
                            .await
                            .expect("timeout")
                            .expect("client2 recv");
                        assert_eq!(received, test_data);
                    } => {},
                }

                daemon.shutdown().await;
                let result = timeout(Duration::from_secs(5), &mut run_future).await;
                assert!(result.is_ok(), "daemon must shut down within 5s");
            });
    });
}

// ---------------------------------------------------------------------------
// Test 3: Daemon ingests a well-formed packet without crash
// ---------------------------------------------------------------------------

#[test]
fn test_daemon_ingests_packet_without_crash() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let name = format!("test_pkt_{}", std::process::id());
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
                        tokio::time::sleep(Duration::from_millis(100)).await;

                        let dest_hash = [0xAA; 16];
                        let mut pkt_buf = [0u8; 500];
                        let pkt_len = rete_core::packet::PacketBuilder::new(&mut pkt_buf)
                            .packet_type(rete_core::packet::PacketType::Data)
                            .dest_type(rete_core::packet::DestType::Plain)
                            .destination_hash(&dest_hash)
                            .payload(b"hello daemon")
                            .build()
                            .expect("build packet");

                        let mut client = LocalClient::connect(&name)
                            .await.expect("client connect");

                        client.send(&pkt_buf[..pkt_len]).await.expect("send packet");

                        // Verify daemon is still healthy by connecting a new client
                        tokio::task::yield_now().await;
                        let client2 = LocalClient::connect(&name).await;
                        assert!(
                            client2.is_ok(),
                            "daemon must still accept connections after packet ingest"
                        );
                    } => {},
                }

                daemon.shutdown().await;
                let result = timeout(Duration::from_secs(5), &mut run_future).await;
                assert!(result.is_ok(), "daemon must shut down within 5s");
            });
    });
}
