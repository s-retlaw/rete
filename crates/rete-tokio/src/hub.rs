//! Reusable multi-client connection hub.
//!
//! [`ClientHub`] manages a dynamic set of connected clients, each with an
//! outbound channel. [`HubBroadcaster`] is a clone-friendly handle for
//! sending packets to all (or all-but-one) connected clients.
//!
//! Used by [`LocalServer`](crate::local::LocalServer),
//! [`TcpServer`](crate::tcp_server::TcpServer), and future WebSocket servers.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::sync::RwLock;

/// Lifecycle event for a hub client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientEvent {
    Connected(usize),
    Disconnected(usize),
}

/// A connected client tracked by the hub.
struct ClientEntry {
    id: usize,
    tx: mpsc::Sender<Vec<u8>>,
}

/// Manages a dynamic set of connected clients.
///
/// Each registered client gets a unique ID and an outbound channel.
/// The hub tracks all clients and provides a [`HubBroadcaster`] for
/// sending packets to all of them.
pub struct ClientHub {
    clients: Arc<RwLock<Vec<ClientEntry>>>,
    next_id: Arc<AtomicUsize>,
    channel_capacity: usize,
    event_tx: Option<Arc<mpsc::Sender<ClientEvent>>>,
}

impl ClientHub {
    /// Create a new hub with the given per-client outbound channel capacity.
    pub fn new(channel_capacity: usize) -> Self {
        ClientHub {
            clients: Arc::new(RwLock::new(Vec::new())),
            next_id: Arc::new(AtomicUsize::new(0)),
            channel_capacity,
            event_tx: None,
        }
    }

    /// Create a hub that emits [`ClientEvent`]s on connect/disconnect.
    pub fn new_with_events(
        channel_capacity: usize,
        event_capacity: usize,
    ) -> (Self, mpsc::Receiver<ClientEvent>) {
        let (tx, rx) = mpsc::channel(event_capacity);
        let hub = ClientHub {
            clients: Arc::new(RwLock::new(Vec::new())),
            next_id: Arc::new(AtomicUsize::new(0)),
            channel_capacity,
            event_tx: Some(Arc::new(tx)),
        };
        (hub, rx)
    }

    /// Register a new client, returning its unique ID and outbound receiver.
    ///
    /// The caller should spawn read/write tasks for the client and use the
    /// receiver to dequeue packets for sending.
    pub async fn register(&self) -> (usize, mpsc::Receiver<Vec<u8>>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(self.channel_capacity);
        {
            let mut clients = self.clients.write().await;
            clients.push(ClientEntry { id, tx });
        }
        if let Some(ref event_tx) = self.event_tx {
            let _ = event_tx.send(ClientEvent::Connected(id)).await;
        }
        (id, rx)
    }

    /// Get a broadcaster handle for sending to all clients.
    pub fn broadcaster(&self) -> HubBroadcaster {
        HubBroadcaster {
            clients: Arc::clone(&self.clients),
            event_tx: self.event_tx.clone(),
        }
    }

    /// Current number of connected clients.
    pub async fn client_count(&self) -> usize {
        self.clients.read().await.len()
    }

    /// Replace this hub with one that emits [`ClientEvent`]s.
    ///
    /// Must be called before any clients are registered. Returns a receiver
    /// for connect/disconnect events.
    pub fn enable_events(&mut self, event_capacity: usize) -> mpsc::Receiver<ClientEvent> {
        let (tx, rx) = mpsc::channel(event_capacity);
        self.event_tx = Some(Arc::new(tx));
        rx
    }
}

/// Clone-friendly handle for broadcasting packets to all connected clients.
///
/// Obtained via [`ClientHub::broadcaster`]. Safe to hold alongside other
/// references and pass between tasks.
#[derive(Clone)]
pub struct HubBroadcaster {
    clients: Arc<RwLock<Vec<ClientEntry>>>,
    event_tx: Option<Arc<mpsc::Sender<ClientEvent>>>,
}

impl HubBroadcaster {
    /// Broadcast raw packet bytes to all connected clients.
    ///
    /// If `exclude_client` is `Some(id)`, that client is skipped (used when
    /// relaying a packet that originated from that client to avoid echo).
    pub async fn broadcast(&self, data: &[u8], exclude_client: Option<usize>) {
        // Collect senders under the lock, then release before sending.
        // This avoids holding the RwLock across .await (backpressure risk).
        let senders: Vec<_> = {
            let clients = self.clients.read().await;
            clients
                .iter()
                .filter(|c| exclude_client != Some(c.id))
                .map(|c| c.tx.clone())
                .collect()
        };
        let payload = data.to_vec();
        for tx in senders {
            if tx.send(payload.clone()).await.is_err() {
                tracing::debug!("hub: broadcast send failed (client disconnected or full)");
            }
        }
    }

    /// Send raw packet bytes to a specific client by ID.
    pub async fn send_to_client(&self, client_id: usize, data: &[u8]) {
        let sender = {
            let clients = self.clients.read().await;
            clients
                .iter()
                .find(|c| c.id == client_id)
                .map(|c| c.tx.clone())
        };
        if let Some(tx) = sender {
            if tx.send(data.to_vec()).await.is_err() {
                tracing::debug!("hub: send_to_client failed (client disconnected or full)");
            }
        }
    }

    /// Remove a client by ID (used by spawned tasks on disconnect).
    pub async fn remove_client(&self, client_id: usize) {
        {
            let mut clients = self.clients.write().await;
            clients.retain(|c| c.id != client_id);
        }
        if let Some(ref event_tx) = self.event_tx {
            let _ = event_tx.send(ClientEvent::Disconnected(client_id)).await;
        }
    }

    /// Number of currently connected clients.
    pub async fn client_count(&self) -> usize {
        self.clients.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn test_client_hub_register_remove() {
        let hub = ClientHub::new(16);
        let broadcaster = hub.broadcaster();
        assert_eq!(hub.client_count().await, 0);

        let (id1, _rx1) = hub.register().await;
        let (id2, _rx2) = hub.register().await;
        assert_ne!(id1, id2);
        assert_eq!(hub.client_count().await, 2);

        broadcaster.remove_client(id1).await;
        assert_eq!(hub.client_count().await, 1);

        broadcaster.remove_client(id2).await;
        assert_eq!(hub.client_count().await, 0);
    }

    #[tokio::test]
    async fn test_hub_broadcaster_exclude() {
        let hub = ClientHub::new(16);
        let broadcaster = hub.broadcaster();

        let (_id1, mut rx1) = hub.register().await;
        let (id2, mut rx2) = hub.register().await;

        // Broadcast excluding client 2
        broadcaster.broadcast(b"hello", Some(id2)).await;

        // Client 1 should receive
        let msg = timeout(Duration::from_secs(1), rx1.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(msg, b"hello");

        // Client 2 should NOT receive (excluded)
        let result = timeout(Duration::from_millis(50), rx2.recv()).await;
        assert!(result.is_err(), "client 2 should not have received");
    }

    #[tokio::test]
    async fn test_hub_broadcaster_all() {
        let hub = ClientHub::new(16);
        let broadcaster = hub.broadcaster();

        let (_id1, mut rx1) = hub.register().await;
        let (_id2, mut rx2) = hub.register().await;

        broadcaster.broadcast(b"world", None).await;

        let msg1 = timeout(Duration::from_secs(1), rx1.recv())
            .await
            .expect("timeout")
            .expect("closed");
        let msg2 = timeout(Duration::from_secs(1), rx2.recv())
            .await
            .expect("timeout")
            .expect("closed");
        assert_eq!(msg1, b"world");
        assert_eq!(msg2, b"world");
    }

    #[tokio::test]
    async fn test_hub_send_to_client() {
        let hub = ClientHub::new(16);
        let broadcaster = hub.broadcaster();

        let (id1, mut rx1) = hub.register().await;
        let (_id2, mut rx2) = hub.register().await;

        // Send only to client 1
        broadcaster.send_to_client(id1, b"targeted").await;

        let msg = timeout(Duration::from_secs(1), rx1.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(msg, b"targeted");

        // Client 2 should NOT receive
        let result = timeout(Duration::from_millis(50), rx2.recv()).await;
        assert!(result.is_err(), "client 2 should not have received targeted message");
    }

    #[tokio::test]
    async fn test_hub_client_events() {
        let (hub, mut event_rx) = ClientHub::new_with_events(16, 64);
        let broadcaster = hub.broadcaster();

        let (id1, _rx1) = hub.register().await;
        let (id2, _rx2) = hub.register().await;

        // Should have received Connected events
        let e1 = timeout(Duration::from_secs(1), event_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(e1, ClientEvent::Connected(id1));

        let e2 = timeout(Duration::from_secs(1), event_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(e2, ClientEvent::Connected(id2));

        // Remove client 1
        broadcaster.remove_client(id1).await;

        let e3 = timeout(Duration::from_secs(1), event_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(e3, ClientEvent::Disconnected(id1));
    }
}
