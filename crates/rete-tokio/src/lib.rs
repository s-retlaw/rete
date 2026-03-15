//! rete-tokio — Tokio runtime harness for Reticulum.
//!
//! Provides [`TokioNode`] which drives transport + interfaces in an async
//! event loop using `tokio::select!`.

use rete_core::{Identity, MTU, TRUNCATED_HASH_LEN};
pub use rete_stack::NodeEvent;
pub use rete_stack::ProofStrategy;
use rete_stack::{HostedNodeCore, OutboundPacket, PacketRouting, ReteInterface};
use rete_transport::{ANNOUNCE_INTERVAL_SECS, TICK_INTERVAL_SECS};

use std::time::{SystemTime, UNIX_EPOCH};

/// A Reticulum node running on the Tokio runtime.
///
/// Thin wrapper around [`HostedNodeCore`] that provides the Tokio async
/// event loop and timer management.
pub struct TokioNode {
    /// Shared node logic (identity, transport, packet processing).
    pub core: HostedNodeCore,
    /// Initial data to send right after the first announce (to a pre-registered peer).
    initial_send: Option<(Vec<u8>, [u8; TRUNCATED_HASH_LEN])>,
}

impl TokioNode {
    /// Create a new node with the given identity and destination.
    pub fn new(identity: Identity, app_name: &str, aspects: &[&str]) -> Self {
        TokioNode {
            core: HostedNodeCore::new(identity, app_name, aspects),
            initial_send: None,
        }
    }

    /// Enable transport mode: forward HEADER_2 packets for other nodes.
    pub fn enable_transport(&mut self) {
        self.core.enable_transport();
    }

    /// Returns our destination hash.
    pub fn dest_hash(&self) -> &[u8; TRUNCATED_HASH_LEN] {
        self.core.dest_hash()
    }

    /// Set an auto-reply message sent to any peer that announces.
    pub fn set_auto_reply(&mut self, msg: Option<Vec<u8>>) {
        self.core.set_auto_reply(msg);
    }

    /// Enable echo mode: received DATA is sent back to the sender with "echo:" prefix.
    pub fn set_echo_data(&mut self, echo: bool) {
        self.core.set_echo_data(echo);
    }

    /// Set the proof generation strategy for incoming data packets.
    pub fn set_proof_strategy(&mut self, strategy: ProofStrategy) {
        self.core.set_proof_strategy(strategy);
    }

    /// Queue a data message to send immediately after the initial announce.
    pub fn send_on_start(&mut self, dest_hash: [u8; TRUNCATED_HASH_LEN], data: Vec<u8>) {
        self.initial_send = Some((data, dest_hash));
    }

    /// Pre-register a peer's identity for sending DATA without waiting for an announce.
    pub fn register_peer(&mut self, peer: &Identity, app_name: &str, aspects: &[&str]) {
        let now = current_time_secs();
        self.core.register_peer(peer, app_name, aspects, now);
    }

    /// Build and return a raw announce packet for this node.
    pub fn build_announce(&self, app_data: Option<&[u8]>) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let now = current_time_secs();
        self.core.build_announce(app_data, &mut rng, now)
    }

    /// Run the main event loop with a single interface.
    pub async fn run<I, F>(&mut self, iface: &mut I, mut on_event: F)
    where
        I: ReteInterface,
        F: FnMut(NodeEvent),
    {
        let mut rng = rand::thread_rng();

        // Send initial announce
        let announce = self.core.build_announce(None, &mut rng, current_time_secs());
        if let Err(e) = iface.send(&announce).await {
            eprintln!("[rete] failed to send initial announce: {:?}", e);
        } else {
            eprintln!(
                "[rete] sent announce for dest {}",
                hex(self.core.dest_hash())
            );
        }

        // Send initial data to pre-registered peer (if configured)
        if let Some((data, dest)) = self.initial_send.take() {
            if let Some(pkt) = self.core.build_data_packet(&dest, &data, &mut rng) {
                if let Err(e) = iface.send(&pkt).await {
                    eprintln!("[rete] initial send failed: {:?}", e);
                } else {
                    eprintln!(
                        "[rete] sent initial DATA to {}: {}",
                        hex(&dest),
                        String::from_utf8_lossy(&data)
                    );
                    println!(
                        "DATA_SENT:{}:{}",
                        hex(&dest),
                        String::from_utf8_lossy(&data)
                    );
                }
            } else {
                eprintln!("[rete] initial send failed: peer not registered");
            }
        }

        let mut announce_timer =
            tokio::time::interval(std::time::Duration::from_secs(ANNOUNCE_INTERVAL_SECS));
        let mut tick_timer =
            tokio::time::interval(std::time::Duration::from_secs(TICK_INTERVAL_SECS));
        announce_timer.tick().await;
        tick_timer.tick().await;

        let mut recv_buf = [0u8; MTU];

        loop {
            tokio::select! {
                result = iface.recv(&mut recv_buf) => {
                    match result {
                        Ok(data) => {
                            let now = current_time_secs();
                            let outcome = self.core.handle_ingest(data, now, 0, &mut rng);
                            dispatch_single(iface, &outcome.packets, 0).await;
                            if let Some(event) = outcome.event {
                                on_event(event);
                            }
                        }
                        Err(e) => {
                            eprintln!("[rete] recv error: {:?}", e);
                            break;
                        }
                    }
                }
                _ = announce_timer.tick() => {
                    let announce = self.core.build_announce(None, &mut rng, current_time_secs());
                    if let Err(e) = iface.send(&announce).await {
                        eprintln!("[rete] failed to send periodic announce: {:?}", e);
                    }
                }
                _ = tick_timer.tick() => {
                    let now = current_time_secs();
                    let outcome = self.core.handle_tick(now);
                    dispatch_single(iface, &outcome.packets, 0).await;
                    if let Some(event) = outcome.event {
                        on_event(event);
                    }
                }
            }
        }
    }
}

/// Dispatch outbound packets on a single interface.
async fn dispatch_single<I: ReteInterface>(
    iface: &mut I,
    packets: &[OutboundPacket],
    _source_iface: u8,
) {
    for pkt in packets {
        // With a single interface, all routing modes result in sending on the same iface
        let _ = iface.send(&pkt.data).await;
    }
}

/// Message from an interface recv task to the main loop.
pub struct InboundMsg {
    /// Interface index this packet was received on.
    pub iface_idx: u8,
    /// Raw packet data.
    pub data: Vec<u8>,
}

impl TokioNode {
    /// Run the main event loop with multiple interfaces.
    pub async fn run_multi<F>(
        &mut self,
        iface_senders: Vec<tokio::sync::mpsc::Sender<Vec<u8>>>,
        mut inbound_rx: tokio::sync::mpsc::Receiver<InboundMsg>,
        mut on_event: F,
    ) where
        F: FnMut(NodeEvent),
    {
        let mut rng = rand::thread_rng();

        // Send initial announce to all interfaces
        let announce = self.core.build_announce(None, &mut rng, current_time_secs());
        for tx in &iface_senders {
            let _ = tx.send(announce.clone()).await;
        }
        eprintln!("[rete] sent announce on {} interfaces", iface_senders.len());

        // Send initial data to pre-registered peer (if configured)
        if let Some((data, dest)) = self.initial_send.take() {
            if let Some(pkt) = self.core.build_data_packet(&dest, &data, &mut rng) {
                for tx in &iface_senders {
                    let _ = tx.send(pkt.clone()).await;
                }
            }
        }

        let mut announce_timer =
            tokio::time::interval(std::time::Duration::from_secs(ANNOUNCE_INTERVAL_SECS));
        let mut tick_timer =
            tokio::time::interval(std::time::Duration::from_secs(TICK_INTERVAL_SECS));
        announce_timer.tick().await;
        tick_timer.tick().await;

        loop {
            tokio::select! {
                msg = inbound_rx.recv() => {
                    let Some(msg) = msg else { break };
                    let now = current_time_secs();
                    let outcome = self.core.handle_ingest(&msg.data, now, msg.iface_idx, &mut rng);
                    dispatch_multi(&iface_senders, &outcome.packets, msg.iface_idx).await;
                    if let Some(event) = outcome.event {
                        on_event(event);
                    }
                }
                _ = announce_timer.tick() => {
                    let announce = self.core.build_announce(None, &mut rng, current_time_secs());
                    for tx in &iface_senders {
                        let _ = tx.send(announce.clone()).await;
                    }
                }
                _ = tick_timer.tick() => {
                    let now = current_time_secs();
                    let outcome = self.core.handle_tick(now);
                    dispatch_multi(&iface_senders, &outcome.packets, 0).await;
                    if let Some(event) = outcome.event {
                        on_event(event);
                    }
                }
            }
        }
    }
}

/// Dispatch outbound packets across multiple interfaces.
async fn dispatch_multi(
    senders: &[tokio::sync::mpsc::Sender<Vec<u8>>],
    packets: &[OutboundPacket],
    source_iface: u8,
) {
    for pkt in packets {
        match pkt.routing {
            PacketRouting::SourceInterface => {
                if let Some(tx) = senders.get(source_iface as usize) {
                    let _ = tx.send(pkt.data.clone()).await;
                }
            }
            PacketRouting::AllExceptSource => {
                for (i, tx) in senders.iter().enumerate() {
                    if i as u8 != source_iface {
                        let _ = tx.send(pkt.data.clone()).await;
                    }
                }
            }
            PacketRouting::All => {
                for tx in senders {
                    let _ = tx.send(pkt.data.clone()).await;
                }
            }
        }
    }
}

/// Create channels for an interface and return its driver future.
pub fn interface_task<I>(
    mut iface: I,
    iface_idx: u8,
    inbound_tx: tokio::sync::mpsc::Sender<InboundMsg>,
) -> (
    tokio::sync::mpsc::Sender<Vec<u8>>,
    impl std::future::Future<Output = ()>,
)
where
    I: ReteInterface,
{
    let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    let driver = async move {
        let mut recv_buf = [0u8; MTU];
        loop {
            tokio::select! {
                result = iface.recv(&mut recv_buf) => {
                    match result {
                        Ok(data) => {
                            let msg = InboundMsg {
                                iface_idx,
                                data: data.to_vec(),
                            };
                            if inbound_tx.send(msg).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                pkt = outbound_rx.recv() => {
                    let Some(pkt) = pkt else { break };
                    let _ = iface.send(&pkt).await;
                }
            }
        }
    };

    (outbound_tx, driver)
}

/// Get current time as seconds since UNIX epoch.
pub fn current_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Format bytes as hex string.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
