//! TCP server interface — accepts incoming Reticulum TCP connections.
//!
//! [`TcpServer`] listens for incoming TCP connections and manages each as a
//! virtual client within a [`ClientHub`]. Packets are HDLC-framed and
//! optionally IFAC-protected, matching the protocol spoken by Python RNS
//! `TCPServerInterface` and `TCPClientInterface`.
//!
//! All connected clients share a single interface index in the transport
//! layer. Packets routed to this interface are broadcast to all clients.

use rete_core::hdlc::{self, HdlcDecoder};
use rete_core::ifac::IfacKey;

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::hub::{ClientEvent, ClientHub, HubBroadcaster};
use crate::InboundMsg;

/// Maximum frame size for TCP shared-instance connections.
///
/// Shared-instance TCP clients negotiate link MTUs up to 262 KB.
/// Resource transfers and LXMF messages can produce single frames at
/// the full link MTU. Set large enough to handle these.
const TCP_MAX_FRAME: usize = 300 * 1024;
/// Maximum HDLC-encoded size for TCP frames (worst case: every byte escaped + 2 flags).
const TCP_MAX_ENCODED: usize = TCP_MAX_FRAME * 2 + 2;

/// Configuration for [`TcpServer`].
pub struct TcpServerConfig {
    /// Per-client outbound channel capacity (default: 64).
    pub channel_capacity: usize,
    /// Maximum concurrent clients. 0 means unlimited.
    pub max_clients: usize,
}

impl Default for TcpServerConfig {
    fn default() -> Self {
        Self {
            channel_capacity: 64,
            max_clients: 0,
        }
    }
}

/// TCP server that accepts incoming Reticulum connections.
///
/// Each connected client gets HDLC-framed read/write tasks. Inbound packets
/// are forwarded to the transport layer via `inbound_tx`. Outbound packets
/// are broadcast to all connected clients via [`HubBroadcaster`].
pub struct TcpServer {
    listener: TcpListener,
    hub: ClientHub,
    inbound_tx: mpsc::Sender<InboundMsg>,
    iface_idx: u8,
    ifac: Option<Arc<IfacKey>>,
    max_clients: usize,
}

impl TcpServer {
    /// Bind a TCP server on the given address.
    pub async fn bind(
        addr: &str,
        inbound_tx: mpsc::Sender<InboundMsg>,
        iface_idx: u8,
        ifac: Option<IfacKey>,
        config: TcpServerConfig,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(TcpServer {
            listener,
            hub: ClientHub::new(config.channel_capacity),
            inbound_tx,
            iface_idx,
            ifac: ifac.map(Arc::new),
            max_clients: config.max_clients,
        })
    }

    /// Get a broadcaster handle for sending to all connected clients.
    pub fn broadcaster(&self) -> HubBroadcaster {
        self.hub.broadcaster()
    }

    /// Return the local address the server is bound to.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Enable [`ClientEvent`] notifications on the internal hub.
    ///
    /// Must be called before [`run()`](Self::run). Returns a receiver for
    /// connect/disconnect events.
    pub fn enable_client_events(
        &mut self,
        event_capacity: usize,
    ) -> mpsc::Receiver<ClientEvent> {
        self.hub.enable_events(event_capacity)
    }

    /// Run the accept loop forever, spawning tasks for each connection.
    ///
    /// This should be spawned as a Tokio task.
    pub async fn run(self) {
        loop {
            match self.listener.accept().await {
                Ok((stream, addr)) => {
                    // Check max clients
                    if self.max_clients > 0 && self.hub.client_count().await >= self.max_clients {
                        eprintln!(
                            "[rete-tcp-server] max clients ({}) reached, rejecting {}",
                            self.max_clients, addr
                        );
                        drop(stream);
                        continue;
                    }

                    let (client_id, client_rx) = self.hub.register().await;
                    eprintln!(
                        "[rete-tcp-server] client {} connected from {}",
                        client_id, addr
                    );

                    let (read_half, write_half) = stream.into_split();

                    // Write task: dequeue packets, optionally IFAC-protect, HDLC-encode, send
                    let ifac_w = self.ifac.clone();
                    let write_handle =
                        tokio::spawn(tcp_client_write_task(write_half, client_rx, ifac_w));

                    // Read task: read bytes, HDLC-decode, optionally IFAC-unprotect, forward
                    let inbound_tx = self.inbound_tx.clone();
                    let iface_idx = self.iface_idx;
                    let broadcaster = self.hub.broadcaster();
                    let ifac_r = self.ifac.clone();

                    tokio::spawn(async move {
                        let read_fut = tcp_client_read_task(
                            read_half,
                            inbound_tx,
                            iface_idx,
                            client_id,
                            ifac_r,
                        );
                        tokio::select! {
                            _ = read_fut => {},
                            _ = write_handle => {
                                log::debug!(
                                    "[rete-tcp-server] write task exited for client {}",
                                    client_id,
                                );
                            },
                        }

                        broadcaster.remove_client(client_id).await;
                        eprintln!("[rete-tcp-server] client {} disconnected", client_id);
                    });
                }
                Err(e) => {
                    eprintln!("[rete-tcp-server] accept error: {}", e);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }
}

/// Write task for a TCP server client.
///
/// Dequeues raw packets from `rx`, optionally IFAC-protects them,
/// HDLC-encodes, and writes to the TCP stream.
async fn tcp_client_write_task(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    mut rx: mpsc::Receiver<Vec<u8>>,
    ifac: Option<Arc<IfacKey>>,
) {
    let tcp_max_encoded = TCP_MAX_ENCODED;
    let mut encoded = vec![0u8; tcp_max_encoded];
    let mut ifac_buf = vec![0u8; TCP_MAX_FRAME];

    while let Some(data) = rx.recv().await {
        let to_encode: &[u8] = if let Some(ref ifac) = ifac {
            match ifac.protect(&data, &mut ifac_buf) {
                Ok(len) => &ifac_buf[..len],
                Err(_) => continue, // Skip frame on protect error
            }
        } else {
            &data
        };

        match hdlc::encode(to_encode, &mut encoded) {
            Ok(n) => {
                if let Err(e) = writer.write_all(&encoded[..n]).await {
                    log::debug!("[rete-tcp-server] client write failed: {e}");
                    break;
                }
                if let Err(e) = writer.flush().await {
                    log::debug!("[rete-tcp-server] client flush failed: {e}");
                    break;
                }
            }
            Err(_) => {
                // Frame too large — skip
            }
        }
    }
}

/// Read task for a TCP server client.
///
/// Reads bytes from the TCP stream, HDLC-decodes them, optionally
/// IFAC-unprotects, and forwards to the node inbound channel.
async fn tcp_client_read_task(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    inbound_tx: mpsc::Sender<InboundMsg>,
    iface_idx: u8,
    client_id: usize,
    ifac: Option<Arc<IfacKey>>,
) {
    let mut decoder: Box<HdlcDecoder<TCP_MAX_FRAME>> = Box::new(HdlcDecoder::new());
    let mut read_buf = [0u8; 4096];
    let mut ifac_buf = vec![0u8; TCP_MAX_FRAME];

    loop {
        let n = match reader.read(&mut read_buf).await {
            Ok(0) => break, // EOF
            Ok(n) => n,
            Err(_) => break, // Error
        };

        for &byte in &read_buf[..n] {
            if decoder.feed(byte) {
                if let Some(frame) = decoder.frame() {
                    // IFAC handling (same logic as TcpInterface::recv)
                    let packet: &[u8] = if let Some(ref ifac) = ifac {
                        if !IfacKey::has_ifac_flag(frame) {
                            // No IFAC flag on IFAC-enabled interface: drop
                            continue;
                        }
                        match ifac.unprotect(frame, &mut ifac_buf) {
                            Ok(len) => &ifac_buf[..len],
                            Err(_) => continue, // Invalid IFAC: drop
                        }
                    } else {
                        if IfacKey::has_ifac_flag(frame) {
                            // IFAC flag on non-IFAC interface: drop
                            continue;
                        }
                        frame
                    };

                    let data = packet.to_vec();

                    // Forward to node's inbound channel (node handles dispatch).
                    let msg = InboundMsg {
                        iface_idx,
                        data,
                        client_id: Some(client_id),
                    };
                    if inbound_tx.send(msg).await.is_err() {
                        return; // Node shut down
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};

    /// Helper: HDLC-encode and write a raw packet over a TCP stream.
    async fn hdlc_write(stream: &mut TcpStream, data: &[u8]) {
        let mut encoded = vec![0u8; TCP_MAX_ENCODED];
        let n = hdlc::encode(data, &mut encoded).unwrap();
        stream.write_all(&encoded[..n]).await.unwrap();
        stream.flush().await.unwrap();
    }

    /// Helper: read and HDLC-decode one frame from a TCP stream.
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

    use crate::test_utils::big_stack_test;

    #[test]
    fn test_tcp_server_accept_and_forward() {
        big_stack_test(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (inbound_tx, mut inbound_rx) = mpsc::channel(256);
                    let server =
                        TcpServer::bind("127.0.0.1:0", inbound_tx, 3, None, Default::default())
                            .await
                            .unwrap();
                    let addr = server.listener.local_addr().unwrap();
                    let broadcaster = server.broadcaster();

                    tokio::spawn(server.run());
                    tokio::time::sleep(Duration::from_millis(50)).await;

                    // Connect two clients
                    let mut client1 = TcpStream::connect(addr).await.unwrap();
                    let _client2 = TcpStream::connect(addr).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(50)).await;

                    assert_eq!(broadcaster.client_count().await, 2);

                    // Client1 sends a packet
                    let test_data = b"hello from client1";
                    hdlc_write(&mut client1, test_data).await;

                    // Node inbound should receive it with correct iface_idx and client_id
                    let msg = timeout(Duration::from_secs(2), inbound_rx.recv())
                        .await
                        .expect("timeout")
                        .expect("channel closed");
                    assert_eq!(msg.iface_idx, 3);
                    assert_eq!(msg.data, test_data);
                    assert!(msg.client_id.is_some(), "client_id should be set for hub clients");
                });
        });
    }

    #[test]
    fn test_tcp_server_broadcast_from_node() {
        big_stack_test(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (inbound_tx, _inbound_rx) = mpsc::channel(256);
                    let server =
                        TcpServer::bind("127.0.0.1:0", inbound_tx, 0, None, Default::default())
                            .await
                            .unwrap();
                    let addr = server.listener.local_addr().unwrap();
                    let broadcaster = server.broadcaster();

                    tokio::spawn(server.run());
                    tokio::time::sleep(Duration::from_millis(50)).await;

                    let mut client = TcpStream::connect(addr).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(50)).await;

                    // Broadcast from node
                    broadcaster.broadcast(b"from node", None).await;

                    let received = timeout(Duration::from_secs(2), hdlc_read(&mut client))
                        .await
                        .expect("timeout");
                    assert_eq!(received, b"from node");
                });
        });
    }

    #[test]
    fn test_tcp_server_disconnect_cleanup() {
        big_stack_test(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (inbound_tx, _inbound_rx) = mpsc::channel(256);
                    let server =
                        TcpServer::bind("127.0.0.1:0", inbound_tx, 0, None, Default::default())
                            .await
                            .unwrap();
                    let addr = server.listener.local_addr().unwrap();
                    let broadcaster = server.broadcaster();

                    tokio::spawn(server.run());
                    tokio::time::sleep(Duration::from_millis(50)).await;

                    let client1 = TcpStream::connect(addr).await.unwrap();
                    let mut client2 = TcpStream::connect(addr).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    assert_eq!(broadcaster.client_count().await, 2);

                    // Drop client1
                    drop(client1);
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    assert_eq!(broadcaster.client_count().await, 1);

                    // Client2 still works
                    broadcaster.broadcast(b"still alive", None).await;
                    let received = timeout(Duration::from_secs(2), hdlc_read(&mut client2))
                        .await
                        .expect("timeout");
                    assert_eq!(received, b"still alive");
                });
        });
    }

    #[test]
    fn test_tcp_server_max_clients() {
        big_stack_test(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (inbound_tx, _inbound_rx) = mpsc::channel(256);
                    let server = TcpServer::bind(
                        "127.0.0.1:0",
                        inbound_tx,
                        0,
                        None,
                        TcpServerConfig {
                            channel_capacity: 64,
                            max_clients: 2,
                        },
                    )
                    .await
                    .unwrap();
                    let addr = server.listener.local_addr().unwrap();
                    let broadcaster = server.broadcaster();

                    tokio::spawn(server.run());
                    tokio::time::sleep(Duration::from_millis(50)).await;

                    // Connect 2 clients — should succeed
                    let _c1 = TcpStream::connect(addr).await.unwrap();
                    let _c2 = TcpStream::connect(addr).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    assert_eq!(broadcaster.client_count().await, 2);

                    // 3rd connection: server accepts at TCP level but drops immediately
                    let c3 = TcpStream::connect(addr).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    // The third client should NOT be registered
                    assert_eq!(broadcaster.client_count().await, 2);
                    drop(c3);
                });
        });
    }
}
