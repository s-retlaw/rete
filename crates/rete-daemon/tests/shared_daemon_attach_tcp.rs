//! Integration tests for SharedDaemon TCP attach and packet relay.
//!
//! Covers parity row S1-GEN-ATTACH-002: TCP listener bind, accept, and relay.
//! Mirrors shared_daemon_attach.rs but uses TCP instead of Unix sockets.

mod common;

use common::{big_stack_test, make_tcp_config};
use rete_daemon::daemon::SharedDaemonBuilder;

use rete_core::hdlc::{self, HdlcDecoder};

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
// Test 1: Two TCP clients relay packets through the full daemon stack
// ---------------------------------------------------------------------------

#[test]
fn test_daemon_tcp_client_to_client_relay() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
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

                        // Client1 sends -> Client2 receives via relay
                        let test_data = b"hello from tcp client1";
                        hdlc_write(&mut client1, test_data).await;

                        let received = timeout(Duration::from_secs(2), hdlc_read(&mut client2))
                            .await
                            .expect("timeout waiting for relay");
                        assert_eq!(received, test_data, "client2 must receive relayed packet");

                        // Client2 sends -> Client1 receives (bidirectional)
                        let reply_data = b"reply from tcp client2";
                        hdlc_write(&mut client2, reply_data).await;

                        let received = timeout(Duration::from_secs(2), hdlc_read(&mut client1))
                            .await
                            .expect("timeout waiting for reply");
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
// Test 2: TCP client disconnect does not crash daemon or affect other clients
// ---------------------------------------------------------------------------

#[test]
fn test_daemon_tcp_client_disconnect_no_crash() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
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
                        let mut client2 = TcpStream::connect(("127.0.0.1", port))
                            .await.expect("client2 connect");

                        // Drop client1 — daemon must handle disconnect cleanly
                        drop(client1);
                        tokio::task::yield_now().await;
                        tokio::time::sleep(Duration::from_millis(100)).await;

                        // New client connects after disconnect
                        let mut client3 = TcpStream::connect(("127.0.0.1", port))
                            .await.expect("client3 connect");

                        // Client3 sends -> Client2 receives (relay still works)
                        let test_data = b"after tcp disconnect";
                        hdlc_write(&mut client3, test_data).await;

                        let received = timeout(Duration::from_secs(2), hdlc_read(&mut client2))
                            .await
                            .expect("timeout");
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
// Test 3: Daemon ingests a well-formed packet via TCP without crash
// ---------------------------------------------------------------------------

#[test]
fn test_daemon_tcp_ingests_packet_without_crash() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
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
    });
}
