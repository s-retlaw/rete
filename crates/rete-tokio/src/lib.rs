//! rete-tokio — Tokio runtime harness for Reticulum.
//!
//! Provides [`TokioNode`] which drives transport + interfaces in an async
//! event loop using `tokio::select!`.

pub mod local;

use rete_core::{Identity, MTU, TRUNCATED_HASH_LEN};
pub use rete_stack::NodeEvent;
pub use rete_stack::ProofStrategy;
use rete_stack::{HostedNodeCore, OutboundPacket, PacketRouting, ReteInterface};
use rete_transport::{ANNOUNCE_INTERVAL_SECS, TICK_INTERVAL_SECS};

use std::time::{SystemTime, UNIX_EPOCH};

/// Command injected into a running node's event loop.
#[derive(Debug)]
pub enum NodeCommand {
    /// Send encrypted DATA to a destination.
    SendData {
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        payload: Vec<u8>,
    },
    /// Initiate a link to a destination.
    InitiateLink { dest_hash: [u8; TRUNCATED_HASH_LEN] },
    /// Send a channel message on an active link.
    SendChannelMessage {
        link_id: [u8; TRUNCATED_HASH_LEN],
        message_type: u16,
        payload: Vec<u8>,
    },
    /// Request a path to a destination.
    RequestPath { dest_hash: [u8; TRUNCATED_HASH_LEN] },
    /// Send plain data over an established link.
    SendLinkData {
        link_id: [u8; TRUNCATED_HASH_LEN],
        payload: Vec<u8>,
    },
    /// Send a resource (large data) over a link.
    SendResource {
        link_id: [u8; TRUNCATED_HASH_LEN],
        data: Vec<u8>,
    },
    /// Emit an announce (optionally with app_data).
    Announce { app_data: Option<Vec<u8>> },
    /// Application-layer command, opaque to the runtime.
    ///
    /// Used by example binaries for LXMF or other protocol-specific commands.
    /// `handle_command` logs a warning and returns; callers should intercept
    /// these before passing to TokioNode.
    AppCommand {
        /// Subcommand name (e.g. "lxmf-send", "lxmf-link-send").
        name: String,
        /// Target destination hash (if applicable).
        dest_hash: Option<[u8; TRUNCATED_HASH_LEN]>,
        /// Target link ID (if applicable).
        link_id: Option<[u8; TRUNCATED_HASH_LEN]>,
        /// Payload / message text.
        payload: Vec<u8>,
    },
    /// Shut down the event loop.
    Shutdown,
}

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

    /// Dispatch a single command, returning outbound packets and whether to continue.
    pub fn handle_command<R>(
        &mut self,
        cmd: NodeCommand,
        rng: &mut R,
    ) -> (Vec<OutboundPacket>, bool)
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        let now = current_time_secs();
        match cmd {
            NodeCommand::SendData { dest_hash, payload } => {
                if let Some(pkt) = self.core.build_data_packet(&dest_hash, &payload, rng, now) {
                    eprintln!("[rete] cmd: sent DATA to {}", hex(&dest_hash));
                    (vec![OutboundPacket::broadcast(pkt)], true)
                } else {
                    eprintln!("[rete] cmd: send failed (unknown dest {})", hex(&dest_hash));
                    (vec![], true)
                }
            }
            NodeCommand::InitiateLink { dest_hash } => {
                if let Some((outbound, link_id)) = self.core.initiate_link(dest_hash, now, rng) {
                    eprintln!(
                        "[rete] cmd: initiated link {} to {}",
                        hex(&link_id),
                        hex(&dest_hash)
                    );
                    (vec![outbound], true)
                } else {
                    eprintln!("[rete] cmd: link initiation failed");
                    (vec![], true)
                }
            }
            NodeCommand::SendChannelMessage {
                link_id,
                message_type,
                payload,
            } => {
                if let Some(outbound) =
                    self.core
                        .send_channel_message(&link_id, message_type, &payload, now, rng)
                {
                    (vec![outbound], true)
                } else {
                    eprintln!("[rete] cmd: channel send failed");
                    (vec![], true)
                }
            }
            NodeCommand::RequestPath { dest_hash } => {
                eprintln!("[rete] cmd: requesting path to {}", hex(&dest_hash));
                (vec![self.core.request_path(&dest_hash)], true)
            }
            NodeCommand::SendLinkData { link_id, payload } => {
                if let Some(outbound) = self.core.send_link_data(&link_id, &payload, rng) {
                    eprintln!("[rete] cmd: sent link data on {}", hex(&link_id));
                    (vec![outbound], true)
                } else {
                    eprintln!("[rete] cmd: link data send failed (link {})", hex(&link_id));
                    (vec![], true)
                }
            }
            NodeCommand::SendResource { link_id, data } => {
                if let Some(pkt) = self.core.start_resource(&link_id, &data, rng) {
                    eprintln!(
                        "[rete] cmd: started resource transfer on link {}",
                        hex(&link_id)
                    );
                    (vec![pkt], true)
                } else {
                    eprintln!("[rete] cmd: resource send failed (link {})", hex(&link_id));
                    (vec![], true)
                }
            }
            NodeCommand::Announce { app_data } => {
                self.core.queue_announce(app_data.as_deref(), rng, now);
                eprintln!("[rete] cmd: queued announce");
                (self.core.flush_announces(now), true)
            }
            NodeCommand::AppCommand { name, .. } => {
                eprintln!(
                    "[rete] cmd: app command '{name}' not handled (no app handler installed)"
                );
                (vec![], true)
            }
            NodeCommand::Shutdown => {
                eprintln!("[rete] cmd: shutdown requested");
                (vec![], false)
            }
        }
    }

    /// Run the main event loop with a single interface (no command channel).
    pub async fn run<I, F>(&mut self, iface: &mut I, mut on_event: F)
    where
        I: ReteInterface,
        F: FnMut(NodeEvent),
    {
        let (dummy_tx, cmd_rx) = tokio::sync::mpsc::channel(1);
        drop(dummy_tx);
        self.run_with_app_handler(
            iface,
            cmd_rx,
            |e, _, _: &mut rand::rngs::ThreadRng| {
                on_event(e);
                Vec::new()
            },
            |_, _, _: &mut rand::rngs::ThreadRng| None,
            rand::thread_rng(),
        )
        .await;
    }

    /// Run the main event loop with a single interface and command channel.
    pub async fn run_with_commands<I, F>(
        &mut self,
        iface: &mut I,
        cmd_rx: tokio::sync::mpsc::Receiver<NodeCommand>,
        mut on_event: F,
    ) where
        I: ReteInterface,
        F: FnMut(NodeEvent),
    {
        self.run_with_app_handler(
            iface,
            cmd_rx,
            |e, _, _: &mut rand::rngs::ThreadRng| {
                on_event(e);
                Vec::new()
            },
            |_, _, _: &mut rand::rngs::ThreadRng| None,
            rand::thread_rng(),
        )
        .await;
    }
    /// Run the main event loop with a single interface, command channel, and
    /// application-level command handler.
    ///
    /// The `on_event` callback receives the event, a mutable reference to the
    /// node core, and the RNG. It may return outbound packets to send (e.g.
    /// for propagation auto-forward). Return an empty Vec for no packets.
    ///
    /// The `rng` parameter is used for both the runtime's own operations
    /// and passed to the app command handler for encryption/signing.
    pub async fn run_with_app_handler<I, F, C, R>(
        &mut self,
        iface: &mut I,
        mut cmd_rx: tokio::sync::mpsc::Receiver<NodeCommand>,
        mut on_event: F,
        mut on_app_cmd: C,
        mut rng: R,
    ) where
        I: ReteInterface,
        F: FnMut(NodeEvent, &mut HostedNodeCore, &mut R) -> Vec<OutboundPacket>,
        R: rand_core::RngCore + rand_core::CryptoRng,
        C: FnMut(NodeCommand, &mut HostedNodeCore, &mut R) -> Option<Vec<OutboundPacket>>,
    {
        // Queue initial announce through transport (gets immediate + one retransmit)
        {
            let now = current_time_secs();
            self.core.queue_announce(None, &mut rng, now);
            dispatch_single(iface, &self.core.flush_announces(now)).await;
        }
        eprintln!(
            "[rete] sent announce for dest {}",
            hex(self.core.dest_hash())
        );

        // Send initial data to pre-registered peer (if configured)
        if let Some((data, dest)) = self.initial_send.take() {
            let now = current_time_secs();
            if let Some(pkt) = self.core.build_data_packet(&dest, &data, &mut rng, now) {
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
                            dispatch_single(iface, &outcome.packets).await;
                            if let Some(event) = outcome.event {
                                let extra = on_event(event, &mut self.core, &mut rng);
                                dispatch_single(iface, &extra).await;
                            }
                        }
                        Err(e) => {
                            eprintln!("[rete] recv error: {:?}", e);
                            break;
                        }
                    }
                }
                cmd = cmd_rx.recv() => {
                    if let Some(cmd) = cmd {
                        if matches!(&cmd, NodeCommand::AppCommand { .. }) {
                            if let Some(pkts) = on_app_cmd(cmd, &mut self.core, &mut rng) {
                                dispatch_single(iface, &pkts).await;
                            }
                        } else {
                            let (packets, cont) = self.handle_command(cmd, &mut rng);
                            dispatch_single(iface, &packets).await;
                            if !cont { break; }
                        }
                    }
                }
                _ = announce_timer.tick() => {
                    let now = current_time_secs();
                    self.core.queue_announce(None, &mut rng, now);
                    dispatch_single(iface, &self.core.flush_announces(now)).await;
                }
                _ = tick_timer.tick() => {
                    let now = current_time_secs();
                    let outcome = self.core.handle_tick(now, &mut rng);
                    dispatch_single(iface, &outcome.packets).await;
                    if let Some(event) = outcome.event {
                        let extra = on_event(event, &mut self.core, &mut rng);
                        dispatch_single(iface, &extra).await;
                    }
                }
            }
        }
    }
}

/// Dispatch outbound packets on a single interface.
///
/// `AllExceptSource` is a no-op: the only interface IS the source,
/// so forwarded packets must not be sent back where they came from.
async fn dispatch_single<I: ReteInterface>(iface: &mut I, packets: &[OutboundPacket]) {
    for pkt in packets {
        if pkt.routing == PacketRouting::AllExceptSource {
            continue;
        }
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
    /// Run the main event loop with multiple interfaces (no command channel).
    pub async fn run_multi<F>(
        &mut self,
        iface_senders: Vec<tokio::sync::mpsc::Sender<Vec<u8>>>,
        inbound_rx: tokio::sync::mpsc::Receiver<InboundMsg>,
        mut on_event: F,
    ) where
        F: FnMut(NodeEvent),
    {
        let (dummy_tx, cmd_rx) = tokio::sync::mpsc::channel(1);
        drop(dummy_tx);
        self.run_multi_with_commands(
            iface_senders,
            inbound_rx,
            cmd_rx,
            |e, _, _: &mut rand::rngs::ThreadRng| {
                on_event(e);
                Vec::new()
            },
        )
        .await;
    }

    /// Run the main event loop with multiple interfaces and a command channel.
    ///
    /// The `on_event` callback receives the event, a mutable reference to the
    /// node core, and the RNG. It may return outbound packets to send.
    pub async fn run_multi_with_commands<F>(
        &mut self,
        iface_senders: Vec<tokio::sync::mpsc::Sender<Vec<u8>>>,
        mut inbound_rx: tokio::sync::mpsc::Receiver<InboundMsg>,
        mut cmd_rx: tokio::sync::mpsc::Receiver<NodeCommand>,
        mut on_event: F,
    ) where
        F: FnMut(NodeEvent, &mut HostedNodeCore, &mut rand::rngs::ThreadRng) -> Vec<OutboundPacket>,
    {
        let mut rng = rand::thread_rng();

        // Queue initial announce through transport (gets immediate + one retransmit)
        {
            let now = current_time_secs();
            self.core.queue_announce(None, &mut rng, now);
            dispatch_multi(&iface_senders, &self.core.flush_announces(now), 0).await;
        }
        eprintln!("[rete] sent announce on {} interfaces", iface_senders.len());

        // Send initial data to pre-registered peer (if configured)
        if let Some((data, dest)) = self.initial_send.take() {
            let now = current_time_secs();
            if let Some(pkt) = self.core.build_data_packet(&dest, &data, &mut rng, now) {
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
                        let extra = on_event(event, &mut self.core, &mut rng);
                        dispatch_multi(&iface_senders, &extra, 0).await;
                    }
                }
                cmd = cmd_rx.recv() => {
                    if let Some(cmd) = cmd {
                        let (packets, cont) = self.handle_command(cmd, &mut rng);
                        dispatch_multi(&iface_senders, &packets, 0).await;
                        if !cont { break; }
                    }
                }
                _ = announce_timer.tick() => {
                    let now = current_time_secs();
                    self.core.queue_announce(None, &mut rng, now);
                    dispatch_multi(&iface_senders, &self.core.flush_announces(now), 0).await;
                }
                _ = tick_timer.tick() => {
                    let now = current_time_secs();
                    let outcome = self.core.handle_tick(now, &mut rng);
                    dispatch_multi(&iface_senders, &outcome.packets, 0).await;
                    if let Some(event) = outcome.event {
                        let extra = on_event(event, &mut self.core, &mut rng);
                        dispatch_multi(&iface_senders, &extra, 0).await;
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
