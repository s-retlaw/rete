//! Integration tests for SharedDaemon attach and canonical packet routing.
//!
//! Covers parity rows S1-GEN-ATTACH-001 and S1-GEN-STATE-003.

mod common;

use common::{big_stack_async_test, make_unix_config};
use rete_daemon::daemon::SharedDaemonBuilder;

use rete_core::{Identity, Packet, PacketType};
use rete_stack::ReteInterface;
use rete_tokio::local::LocalClient;
use rete_tokio::TokioNode;

use tokio::time::{timeout, Duration};

// ---------------------------------------------------------------------------
// Test 1: Announce propagates canonically between two clients through the node
// ---------------------------------------------------------------------------

#[test]
fn test_daemon_canonical_announce_routing() {
    big_stack_async_test(|| async {
                let name = format!("test_annc_{}", std::process::id());
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

                        let mut client1 = LocalClient::connect(&name)
                            .await.expect("client1 connect");
                        let mut client2 = LocalClient::connect(&name)
                            .await.expect("client2 connect");
                        tokio::time::sleep(Duration::from_millis(50)).await;

                        // Build a valid announce from a separate identity.
                        let identity = Identity::from_seed(b"test-announce-seed").unwrap();
                        let node = Box::new(
                            TokioNode::new(identity, "testapp", &["aspect1"]).unwrap()
                        );
                        let announce = node.build_announce(None).unwrap();

                        // Client1 sends announce — should be processed by node
                        // and dispatched to client2 via AllExceptSource.
                        client1.send(&announce).await.expect("client1 send");

                        // Client2 should receive the announce.
                        let mut buf = [0u8; 4096];
                        let frame = timeout(Duration::from_secs(3), client2.recv(&mut buf))
                            .await
                            .expect("timeout — client2 did not receive announce")
                            .expect("client2 recv");

                        let pkt = Packet::parse(frame).expect("invalid packet");
                        assert_eq!(pkt.packet_type, PacketType::Announce);
                    } => {},
                }

                daemon.shutdown().await;
                let result = timeout(Duration::from_secs(5), &mut run_future).await;
                assert!(result.is_ok(), "daemon must shut down within 5s");
    });
}

// ---------------------------------------------------------------------------
// Test 2: Client disconnect does not crash daemon or affect other clients
// ---------------------------------------------------------------------------

#[test]
fn test_daemon_client_disconnect_no_crash() {
    big_stack_async_test(|| async {
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
                        let _client2 = LocalClient::connect(&name)
                            .await.expect("client2 connect");

                        // Drop client1 — daemon must handle disconnect cleanly
                        drop(client1);
                        tokio::task::yield_now().await;
                        tokio::time::sleep(Duration::from_millis(50)).await;

                        // New client connects after disconnect
                        let _client3 = LocalClient::connect(&name)
                            .await.expect("client3 connect");

                        // Daemon still alive
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    } => {},
                }

                daemon.shutdown().await;
                let result = timeout(Duration::from_secs(5), &mut run_future).await;
                assert!(result.is_ok(), "daemon must shut down within 5s");
    });
}

// ---------------------------------------------------------------------------
// Test 3: Daemon ingests a well-formed packet without crash
// ---------------------------------------------------------------------------

#[test]
fn test_daemon_ingests_packet_without_crash() {
    big_stack_async_test(|| async {
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
}
