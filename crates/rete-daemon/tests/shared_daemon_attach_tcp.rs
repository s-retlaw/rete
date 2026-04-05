//! Integration tests for SharedDaemon TCP attach and canonical packet routing.
//!
//! Covers parity row S1-GEN-ATTACH-002: TCP listener bind, accept, and routing.
//! Mirrors shared_daemon_attach.rs but uses TCP instead of Unix sockets.

mod common;

use common::{big_stack_async_test, make_tcp_config};
use rete_daemon::daemon::SharedDaemonBuilder;

use rete_core::hdlc::{self, HdlcDecoder};
use rete_core::{Identity, Packet, PacketType};
use rete_tokio::TokioNode;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

const TCP_MAX_FRAME: usize = 8292;

/// HDLC-encode and write a raw packet over a TCP stream.
async fn hdlc_write(stream: &mut TcpStream, data: &[u8]) {
    let mut encoded = [0u8; 16384];
    let n = hdlc::encode(data, &mut encoded).unwrap();
    stream.write_all(&encoded[..n]).await.unwrap();
    stream.flush().await.unwrap();
}

/// Read and HDLC-decode one frame from a TCP stream.
async fn hdlc_read(stream: &mut TcpStream) -> Vec<u8> {
    let mut decoder: HdlcDecoder<TCP_MAX_FRAME> = HdlcDecoder::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).await.unwrap();
        assert!(n > 0, "unexpected EOF");
        for &byte in &buf[..n] {
            if decoder.feed(byte) {
                return decoder.frame().unwrap().to_vec();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Test 1: Announce propagates canonically between TCP clients
// ---------------------------------------------------------------------------

#[test]
fn test_daemon_tcp_canonical_announce_routing() {
    big_stack_async_test(|| async {
                let port = 48800 + (std::process::id() % 100) as u16;
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
                        tokio::time::sleep(Duration::from_millis(100)).await;

                        let mut client1 = TcpStream::connect(("127.0.0.1", port))
                            .await.expect("client1 connect");
                        let mut client2 = TcpStream::connect(("127.0.0.1", port))
                            .await.expect("client2 connect");
                        tokio::time::sleep(Duration::from_millis(50)).await;

                        // Build a valid announce from a separate identity.
                        let identity = Identity::from_seed(b"tcp-announce-seed").unwrap();
                        let node = Box::new(
                            TokioNode::new(identity, "testapp", &["tcptest"]).unwrap()
                        );
                        let announce = node.build_announce(None).unwrap();

                        // Client1 sends announce — should be processed by node
                        // and dispatched to client2 via AllExceptSource.
                        hdlc_write(&mut client1, &announce).await;

                        // Client2 should receive the announce.
                        let frame = timeout(Duration::from_secs(3), hdlc_read(&mut client2))
                            .await
                            .expect("timeout — client2 did not receive announce");

                        let pkt = Packet::parse(&frame).expect("invalid packet");
                        assert_eq!(pkt.packet_type, PacketType::Announce);
                    } => {},
                }

                daemon.shutdown().await;
                let result = timeout(Duration::from_secs(5), &mut run_future).await;
                assert!(result.is_ok(), "daemon must shut down within 5s");
    });
}

// ---------------------------------------------------------------------------
// Test 2: TCP client disconnect does not crash daemon
// ---------------------------------------------------------------------------

#[test]
fn test_daemon_tcp_client_disconnect_no_crash() {
    big_stack_async_test(|| async {
                let port = 48800 + (std::process::id() % 100) as u16 + 1;
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
                        tokio::time::sleep(Duration::from_millis(100)).await;

                        let client1 = TcpStream::connect(("127.0.0.1", port))
                            .await.expect("client1 connect");
                        let _client2 = TcpStream::connect(("127.0.0.1", port))
                            .await.expect("client2 connect");

                        // Drop client1 — daemon must handle disconnect cleanly
                        drop(client1);
                        tokio::task::yield_now().await;
                        tokio::time::sleep(Duration::from_millis(100)).await;

                        // New client connects after disconnect
                        let _client3 = TcpStream::connect(("127.0.0.1", port))
                            .await.expect("client3 connect");

                        tokio::time::sleep(Duration::from_millis(50)).await;
                    } => {},
                }

                daemon.shutdown().await;
                let result = timeout(Duration::from_secs(5), &mut run_future).await;
                assert!(result.is_ok(), "daemon must shut down within 5s");
    });
}

// ---------------------------------------------------------------------------
// Test 3: Daemon ingests a well-formed packet via TCP without crash
// ---------------------------------------------------------------------------

#[test]
fn test_daemon_tcp_ingests_packet_without_crash() {
    big_stack_async_test(|| async {
                let port = 48800 + (std::process::id() % 100) as u16 + 2;
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
                        tokio::time::sleep(Duration::from_millis(100)).await;

                        let dest_hash = [0xBB; 16];
                        let mut pkt_buf = [0u8; 500];
                        let pkt_len = rete_core::packet::PacketBuilder::new(&mut pkt_buf)
                            .packet_type(rete_core::packet::PacketType::Data)
                            .dest_type(rete_core::packet::DestType::Plain)
                            .destination_hash(&dest_hash)
                            .payload(b"hello tcp daemon")
                            .build()
                            .expect("build packet");

                        let mut client = TcpStream::connect(("127.0.0.1", port))
                            .await.expect("client connect");

                        hdlc_write(&mut client, &pkt_buf[..pkt_len]).await;

                        // Verify daemon is still healthy by connecting a new client
                        tokio::task::yield_now().await;
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        let client2 = TcpStream::connect(("127.0.0.1", port)).await;
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
