//! Local shared instance IPC — Unix domain socket server and client.
//!
//! Implements the same protocol as Python RNS `LocalInterface`:
//! - Server listens on an abstract-namespace Unix socket `\0rns/{instance_name}`
//! - Clients connect and exchange HDLC-framed packets
//! - Server relays packets between all clients and the transport layer
//!
//! The framing is identical to the TCP interface (HDLC byte-stuffing with
//! FLAG=0x7E, ESC=0x7D).

use rete_core::hdlc::{self, HdlcDecoder, MAX_ENCODED};
use rete_core::MTU;
use rete_stack::ReteInterface;

use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

use crate::hub::{ClientHub, HubBroadcaster};
use crate::InboundMsg;

// ---------------------------------------------------------------------------
// LocalServer — accepts local clients and relays packets
// ---------------------------------------------------------------------------

/// Server for local shared instance IPC.
///
/// Listens on an abstract-namespace Unix socket and relays HDLC-framed
/// packets between connected clients and the node's transport layer.
pub struct LocalServer {
    listener: UnixListener,
    /// Sender for packets from clients -> main node event loop.
    inbound_tx: mpsc::Sender<InboundMsg>,
    /// Interface index assigned to local clients in the multi-interface model.
    /// All local clients share a single "local" interface index.
    iface_idx: u8,
    /// Shared client management hub.
    hub: ClientHub,
}

impl LocalServer {
    /// Bind to an abstract-namespace Unix socket for the given instance name.
    ///
    /// Uses default channel capacity (64). See [`bind_with_config`](Self::bind_with_config)
    /// for configurable capacity.
    pub fn bind(
        instance_name: &str,
        inbound_tx: mpsc::Sender<InboundMsg>,
        iface_idx: u8,
    ) -> io::Result<Self> {
        Self::bind_with_config(
            instance_name,
            inbound_tx,
            iface_idx,
            LocalServerConfig::default(),
        )
    }

    /// Bind with explicit configuration.
    pub fn bind_with_config(
        instance_name: &str,
        inbound_tx: mpsc::Sender<InboundMsg>,
        iface_idx: u8,
        config: LocalServerConfig,
    ) -> io::Result<Self> {
        let path = format!("\0rns/{}", instance_name);
        let listener = UnixListener::bind(path)?;

        Ok(LocalServer {
            listener,
            inbound_tx,
            iface_idx,
            hub: ClientHub::new(config.channel_capacity),
        })
    }

    /// Get a handle for broadcasting packets to all connected local clients.
    pub fn broadcaster(&self) -> HubBroadcaster {
        self.hub.broadcaster()
    }

    /// Run the accept loop forever, spawning a task for each client.
    ///
    /// This should be spawned as a Tokio task.
    pub async fn run(self) {
        loop {
            match self.listener.accept().await {
                Ok((stream, _addr)) => {
                    let (client_id, client_rx) = self.hub.register().await;
                    eprintln!("[rete-local] client {} connected", client_id);

                    // Spawn read/write tasks for this client
                    let (read_half, write_half) = stream.into_split();

                    // Write task: sends HDLC-framed packets to the client
                    let write_handle = tokio::spawn(client_write_task(write_half, client_rx));

                    // Read task: reads HDLC-framed packets from the client,
                    // forwards to the node inbound channel and broadcasts to
                    // other clients.  We race the read against the write
                    // handle so that a write failure immediately cancels the
                    // read (no zombie half-connections).
                    let inbound_tx = self.inbound_tx.clone();
                    let iface_idx = self.iface_idx;
                    let broadcaster = self.hub.broadcaster();
                    tokio::spawn(async move {
                        let read_fut = client_read_task(
                            read_half,
                            inbound_tx,
                            iface_idx,
                            client_id,
                            &broadcaster,
                        );
                        tokio::select! {
                            _ = read_fut => {},
                            _ = write_handle => {
                                log::debug!(
                                    "[rete-local] write task exited, terminating read for client {}",
                                    client_id,
                                );
                            },
                        }

                        // Client disconnected — remove from hub
                        broadcaster.remove_client(client_id).await;
                        eprintln!("[rete-local] client {} disconnected", client_id);
                    });
                }
                Err(e) => {
                    eprintln!("[rete-local] accept error: {}", e);
                    // Brief pause to avoid spinning on persistent errors
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }
}

/// Write task for a single local client — sends HDLC-framed packets.
async fn client_write_task(
    mut writer: tokio::net::unix::OwnedWriteHalf,
    mut rx: mpsc::Receiver<Vec<u8>>,
) {
    // Box-allocate to avoid 16+ KB stack usage per spawned task.
    let mut encoded = vec![0u8; MAX_ENCODED];
    while let Some(data) = rx.recv().await {
        match hdlc::encode(&data, &mut encoded) {
            Ok(n) => {
                if let Err(e) = writer.write_all(&encoded[..n]).await {
                    log::debug!("[rete-local] client write failed: {e}");
                    break;
                }
                if let Err(e) = writer.flush().await {
                    log::debug!("[rete-local] client flush failed: {e}");
                    break;
                }
            }
            Err(_) => {
                // Frame too large — skip
            }
        }
    }
}

/// Read task for a single local client — reads HDLC-framed packets,
/// forwards to node inbound and broadcasts to other clients.
async fn client_read_task(
    mut reader: tokio::net::unix::OwnedReadHalf,
    inbound_tx: mpsc::Sender<InboundMsg>,
    iface_idx: u8,
    client_id: usize,
    broadcaster: &HubBroadcaster,
) {
    // Box-allocate the decoder to avoid ~9 KB stack usage per spawned task.
    let mut decoder: Box<HdlcDecoder<{ MTU }>> = Box::new(HdlcDecoder::new());
    let mut read_buf = [0u8; 1024];

    loop {
        let n = match reader.read(&mut read_buf).await {
            Ok(0) => break, // EOF
            Ok(n) => n,
            Err(_) => break, // Error
        };

        for &byte in &read_buf[..n] {
            if decoder.feed(byte) {
                if let Some(frame) = decoder.frame() {
                    let data = frame.to_vec();

                    // Forward to node's inbound channel
                    let msg = InboundMsg {
                        iface_idx,
                        data: data.clone(),
                    };
                    if inbound_tx.send(msg).await.is_err() {
                        return; // Node shut down
                    }

                    // Broadcast to other local clients (not back to sender).
                    broadcaster.broadcast(&data, Some(client_id)).await;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// LocalClient — connects to a shared instance server
// ---------------------------------------------------------------------------

/// Errors from the local client interface.
#[derive(Debug)]
pub enum LocalError {
    /// Underlying I/O error.
    Io(io::Error),
    /// HDLC encoding error.
    Encode(rete_core::Error),
    /// Connection closed.
    Disconnected,
}

impl From<io::Error> for LocalError {
    fn from(e: io::Error) -> Self {
        LocalError::Io(e)
    }
}

impl core::fmt::Display for LocalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LocalError::Io(e) => write!(f, "local I/O error: {e}"),
            LocalError::Encode(e) => write!(f, "HDLC encode error: {e}"),
            LocalError::Disconnected => write!(f, "local connection closed"),
        }
    }
}

/// Client connection to a local shared instance.
///
/// Implements [`ReteInterface`] using the same HDLC framing as the TCP
/// interface, but over a Unix domain socket.
pub struct LocalClient {
    stream: UnixStream,
    decoder: HdlcDecoder<{ MTU }>,
    read_buf: [u8; 1024],
    read_pos: usize,
    read_len: usize,
}

impl LocalClient {
    /// Connect to a shared instance by name.
    ///
    /// Uses the abstract-namespace Unix socket `\0rns/{instance_name}`.
    pub async fn connect(instance_name: &str) -> io::Result<Self> {
        let path = format!("\0rns/{}", instance_name);
        let stream = UnixStream::connect(path).await?;
        Ok(LocalClient {
            stream,
            decoder: HdlcDecoder::new(),
            read_buf: [0u8; 1024],
            read_pos: 0,
            read_len: 0,
        })
    }
}

impl ReteInterface for LocalClient {
    type Error = LocalError;

    async fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
        let mut encoded = [0u8; MAX_ENCODED];
        let n = hdlc::encode(frame, &mut encoded).map_err(LocalError::Encode)?;
        self.stream.write_all(&encoded[..n]).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn recv<'a>(&mut self, buf: &'a mut [u8]) -> Result<&'a [u8], Self::Error> {
        loop {
            // Drain leftover bytes from previous read
            while self.read_pos < self.read_len {
                let byte = self.read_buf[self.read_pos];
                self.read_pos += 1;
                if self.decoder.feed(byte) {
                    if let Some(frame) = self.decoder.frame() {
                        let len = frame.len();
                        if len <= buf.len() {
                            buf[..len].copy_from_slice(frame);
                            return Ok(&buf[..len]);
                        }
                        // Frame too large — skip
                    }
                }
            }

            // Read more from socket
            let n = self.stream.read(&mut self.read_buf).await?;
            if n == 0 {
                return Err(LocalError::Disconnected);
            }
            self.read_pos = 0;
            self.read_len = n;
        }
    }
}

// ---------------------------------------------------------------------------
// ReconnectingLocalClient — auto-reconnect wrapper
// ---------------------------------------------------------------------------

/// A [`LocalClient`] wrapper that reconnects with exponential backoff.
///
/// If the server restarts or the connection drops, this client will
/// automatically re-establish the connection on the next send/recv.
/// Gives up after `connect_timeout` (default: 2 minutes) and returns
/// an error so the caller can decide what to do.
pub struct ReconnectingLocalClient {
    instance_name: String,
    inner: Option<LocalClient>,
    base_delay: std::time::Duration,
    max_delay: std::time::Duration,
    connect_timeout: std::time::Duration,
}

impl ReconnectingLocalClient {
    /// Create a reconnecting client for the given shared instance name.
    pub fn new(instance_name: String) -> Self {
        Self {
            instance_name,
            inner: None,
            base_delay: std::time::Duration::from_secs(1),
            max_delay: std::time::Duration::from_secs(16),
            connect_timeout: std::time::Duration::from_secs(120),
        }
    }

    /// Attempt to connect (or reconnect) with exponential backoff.
    ///
    /// Returns an error if the connection cannot be established within
    /// `connect_timeout`.
    async fn ensure_connected(&mut self) -> Result<(), LocalError> {
        if self.inner.is_some() {
            return Ok(());
        }

        let deadline = tokio::time::Instant::now() + self.connect_timeout;
        let mut delay = self.base_delay;
        loop {
            match LocalClient::connect(&self.instance_name).await {
                Ok(client) => {
                    log::info!(
                        "[rete-local] connected to shared instance '{}'",
                        self.instance_name,
                    );
                    self.inner = Some(client);
                    return Ok(());
                }
                Err(e) => {
                    if tokio::time::Instant::now() + delay > deadline {
                        log::warn!(
                            "[rete-local] connect to '{}' timed out after {:?}",
                            self.instance_name,
                            self.connect_timeout,
                        );
                        return Err(LocalError::Io(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!(
                                "connect to '{}' timed out after {:?}",
                                self.instance_name, self.connect_timeout,
                            ),
                        )));
                    }
                    log::debug!(
                        "[rete-local] reconnect to '{}' failed: {e}, retrying in {:?}",
                        self.instance_name,
                        delay,
                    );
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(self.max_delay);
                }
            }
        }
    }
}

impl ReteInterface for ReconnectingLocalClient {
    type Error = LocalError;

    async fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
        self.ensure_connected().await?;
        let client = self.inner.as_mut().unwrap();
        match client.send(frame).await {
            Ok(()) => Ok(()),
            Err(e) => {
                log::debug!("[rete-local] send failed, will reconnect: {e}");
                self.inner = None;
                Err(e)
            }
        }
    }

    async fn recv<'a>(&mut self, buf: &'a mut [u8]) -> Result<&'a [u8], Self::Error> {
        loop {
            self.ensure_connected().await?;
            let client = self.inner.as_mut().unwrap();
            match client.recv(buf).await {
                Ok(data) => {
                    let len = data.len();
                    return Ok(&buf[..len]);
                }
                Err(e) => {
                    log::debug!("[rete-local] recv failed, will reconnect: {e}");
                    self.inner = None;
                    // Loop back to reconnect
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// LocalServerConfig — configurable server parameters
// ---------------------------------------------------------------------------

/// Configuration for [`LocalServer`].
pub struct LocalServerConfig {
    /// Per-client outbound channel capacity (default: 64).
    pub channel_capacity: usize,
}

impl Default for LocalServerConfig {
    fn default() -> Self {
        Self {
            channel_capacity: 64,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    /// Helper: encode and write a raw packet over a Unix stream with HDLC framing.
    async fn hdlc_write(stream: &mut UnixStream, data: &[u8]) {
        let mut encoded = [0u8; MAX_ENCODED];
        let n = hdlc::encode(data, &mut encoded).unwrap();
        stream.write_all(&encoded[..n]).await.unwrap();
        stream.flush().await.unwrap();
    }

    /// Helper: read and decode one HDLC frame from a Unix stream.
    async fn hdlc_read(stream: &mut UnixStream) -> Vec<u8> {
        let mut decoder: HdlcDecoder<{ MTU }> = HdlcDecoder::new();
        let mut buf = [0u8; 1024];
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
    fn test_local_client_connect_disconnect() {
        big_stack_test(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (inbound_tx, _inbound_rx) = mpsc::channel(256);
                    // Use a unique name to avoid collisions with other tests
                    let name = format!("test_connect_{}", std::process::id());
                    let server = LocalServer::bind(&name, inbound_tx, 0).unwrap();
                    let broadcaster = server.broadcaster();

                    tokio::spawn(server.run());

                    // Small delay for server to start accepting
                    tokio::time::sleep(Duration::from_millis(50)).await;

                    // Connect a client
                    let client = LocalClient::connect(&name).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    assert_eq!(broadcaster.client_count().await, 1);

                    // Drop client to disconnect
                    drop(client);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    assert_eq!(broadcaster.client_count().await, 0);
                });
        });
    }

    #[test]
    fn test_local_packet_relay_to_node() {
        big_stack_test(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (inbound_tx, mut inbound_rx) = mpsc::channel(256);
                    let name = format!("test_relay_{}", std::process::id());
                    let server = LocalServer::bind(&name, inbound_tx, 5).unwrap();

                    tokio::spawn(server.run());
                    tokio::time::sleep(Duration::from_millis(50)).await;

                    // Connect and send a packet
                    let path = format!("\0rns/{}", name);
                    let mut stream = UnixStream::connect(path).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(50)).await;

                    let test_data = b"hello from client";
                    hdlc_write(&mut stream, test_data).await;

                    // Server should forward to inbound channel
                    let msg = timeout(Duration::from_secs(2), inbound_rx.recv())
                        .await
                        .expect("timeout")
                        .expect("channel closed");

                    assert_eq!(msg.iface_idx, 5);
                    assert_eq!(msg.data, test_data);
                });
        });
    }

    #[test]
    fn test_local_broadcast_to_clients() {
        big_stack_test(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (inbound_tx, _inbound_rx) = mpsc::channel(256);
                    let name = format!("test_bcast_{}", std::process::id());
                    let server = LocalServer::bind(&name, inbound_tx, 0).unwrap();
                    let broadcaster = server.broadcaster();

                    tokio::spawn(server.run());
                    tokio::time::sleep(Duration::from_millis(50)).await;

                    // Connect two clients via raw streams
                    let path = format!("\0rns/{}", name);
                    let mut client1 = UnixStream::connect(&path).await.unwrap();
                    let mut client2 = UnixStream::connect(&path).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(50)).await;

                    assert_eq!(broadcaster.client_count().await, 2);

                    // Broadcast a packet (from node, no exclusion)
                    broadcaster.broadcast(b"broadcast packet", None).await;

                    // Both clients should receive it
                    let frame1 = timeout(Duration::from_secs(2), hdlc_read(&mut client1))
                        .await
                        .expect("timeout on client1");
                    let frame2 = timeout(Duration::from_secs(2), hdlc_read(&mut client2))
                        .await
                        .expect("timeout on client2");

                    assert_eq!(frame1, b"broadcast packet");
                    assert_eq!(frame2, b"broadcast packet");
                });
        });
    }

    #[test]
    fn test_local_client_to_client_relay() {
        big_stack_test(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (inbound_tx, _inbound_rx) = mpsc::channel(256);
                    let name = format!("test_c2c_{}", std::process::id());
                    let server = LocalServer::bind(&name, inbound_tx, 0).unwrap();

                    tokio::spawn(server.run());
                    tokio::time::sleep(Duration::from_millis(50)).await;

                    // Connect two raw clients
                    let path = format!("\0rns/{}", name);
                    let mut client1 = UnixStream::connect(&path).await.unwrap();
                    let mut client2 = UnixStream::connect(&path).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(50)).await;

                    // Client1 sends a packet -> Client2 should receive it
                    let test_data = b"client1 says hello";
                    hdlc_write(&mut client1, test_data).await;

                    let received = timeout(Duration::from_secs(2), hdlc_read(&mut client2))
                        .await
                        .expect("timeout on client2");
                    assert_eq!(received, test_data);
                });
        });
    }

    #[test]
    fn test_local_client_disconnect_cleanup() {
        big_stack_test(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (inbound_tx, _inbound_rx) = mpsc::channel(256);
                    let name = format!("test_cleanup_{}", std::process::id());
                    let server = LocalServer::bind(&name, inbound_tx, 0).unwrap();
                    let broadcaster = server.broadcaster();

                    tokio::spawn(server.run());
                    tokio::time::sleep(Duration::from_millis(50)).await;

                    let path = format!("\0rns/{}", name);

                    // Connect two clients
                    let client1 = UnixStream::connect(&path).await.unwrap();
                    let mut client2 = UnixStream::connect(&path).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    assert_eq!(broadcaster.client_count().await, 2);

                    // Drop client1
                    drop(client1);
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    assert_eq!(broadcaster.client_count().await, 1);

                    // Client2 should still work
                    let test_data = b"still alive";
                    broadcaster.broadcast(test_data, None).await;

                    let received = timeout(Duration::from_secs(2), hdlc_read(&mut client2))
                        .await
                        .expect("timeout on client2");
                    assert_eq!(received, test_data);
                });
        });
    }

    #[test]
    fn test_local_reteinterface_send_recv() {
        big_stack_test(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (inbound_tx, _inbound_rx) = mpsc::channel(256);
                    let name = format!("test_iface_{}", std::process::id());
                    let server = LocalServer::bind(&name, inbound_tx, 0).unwrap();
                    let broadcaster = server.broadcaster();

                    tokio::spawn(server.run());
                    tokio::time::sleep(Duration::from_millis(50)).await;

                    // Connect using the ReteInterface-implementing LocalClient
                    let mut client = LocalClient::connect(&name).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(50)).await;

                    // Test send: client -> node (read via raw broadcast to a
                    // second raw client that acts as observer)
                    let path = format!("\0rns/{}", name);
                    let mut observer = UnixStream::connect(&path).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(50)).await;

                    let send_data = b"via ReteInterface::send";
                    client.send(send_data).await.unwrap();

                    let received = timeout(Duration::from_secs(2), hdlc_read(&mut observer))
                        .await
                        .expect("timeout");
                    assert_eq!(received, send_data);

                    // Test recv: node broadcasts -> client receives
                    let recv_data = b"via ReteInterface::recv";
                    broadcaster.broadcast(recv_data, None).await;

                    let mut buf = [0u8; MTU];
                    let frame = timeout(Duration::from_secs(2), client.recv(&mut buf))
                        .await
                        .expect("timeout")
                        .unwrap();
                    assert_eq!(frame, recv_data);
                });
        });
    }
}
