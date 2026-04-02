//! rete-tokio — Tokio runtime harness for Reticulum.
//!
//! Provides [`TokioNode`] which drives transport + interfaces in an async
//! event loop using `tokio::select!`.

pub mod hub;
pub mod local;
pub mod tcp_server;

#[cfg(test)]
pub(crate) mod test_utils {
    /// Run a test on a thread with 4 MB stack to avoid overflow from large
    /// structs (HdlcDecoder, HostedTransport) in debug builds.
    pub fn big_stack_test(f: fn()) {
        std::thread::Builder::new()
            .stack_size(4 * 1024 * 1024)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap();
    }
}

use rete_core::{Identity, TRUNCATED_HASH_LEN};
pub use rete_stack::NodeEvent;
pub use rete_stack::ProofStrategy;
pub use rete_stack::ResourceStrategy;
use rete_stack::{dispatch_single, HostedNodeCore, OutboundPacket, PacketRouting, ReteInterface};
use rete_transport::{ANNOUNCE_INTERVAL_SECS, TICK_INTERVAL_SECS};

pub use hub::{ClientHub, HubBroadcaster};
pub use tcp_server::TcpServer;

use std::time::{SystemTime, UNIX_EPOCH};

/// A dispatch target for outbound packets.
///
/// Static interfaces (TCP client, serial, AutoInterface) use [`Direct`](InterfaceSlot::Direct)
/// with a point-to-point channel. Dynamic interfaces (local IPC server, TCP server,
/// future WebSocket) use [`Hub`](InterfaceSlot::Hub) with broadcast semantics.
pub enum InterfaceSlot {
    /// Point-to-point: single send channel to one interface task.
    Direct(tokio::sync::mpsc::Sender<Vec<u8>>),
    /// Multi-client: broadcast to all connected clients.
    Hub(HubBroadcaster),
}

impl InterfaceSlot {
    async fn send_packet(&self, data: &[u8]) {
        match self {
            InterfaceSlot::Direct(tx) => {
                let _ = tx.send(data.to_vec()).await;
            }
            InterfaceSlot::Hub(broadcaster) => {
                broadcaster.broadcast(data, None).await;
            }
        }
    }
}

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
    /// Accept an offered resource (for AcceptApp strategy).
    AcceptResource {
        link_id: [u8; TRUNCATED_HASH_LEN],
        resource_hash: [u8; TRUNCATED_HASH_LEN],
    },
    /// Reject an offered resource (for AcceptApp strategy).
    RejectResource {
        link_id: [u8; TRUNCATED_HASH_LEN],
        resource_hash: [u8; TRUNCATED_HASH_LEN],
    },
    /// Close an established link.
    CloseLink { link_id: [u8; TRUNCATED_HASH_LEN] },
    /// Send a request on an established link.
    SendRequest {
        link_id: [u8; TRUNCATED_HASH_LEN],
        path: String,
        payload: Vec<u8>,
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
    pub fn new(
        identity: Identity,
        app_name: &str,
        aspects: &[&str],
    ) -> Result<Self, rete_core::Error> {
        Ok(TokioNode {
            core: HostedNodeCore::new(identity, app_name, aspects)?,
            initial_send: None,
        })
    }

    /// Heap-allocate a new node (convenience for `Box::new(TokioNode::new(...))`).
    pub fn new_boxed(
        identity: Identity,
        app_name: &str,
        aspects: &[&str],
    ) -> Result<Box<Self>, rete_core::Error> {
        Ok(Box::new(TokioNode {
            core: HostedNodeCore::new(identity, app_name, aspects)?,
            initial_send: None,
        }))
    }

    /// Queue a data message to send immediately after the initial announce.
    pub fn send_on_start(&mut self, dest_hash: [u8; TRUNCATED_HASH_LEN], data: Vec<u8>) {
        self.initial_send = Some((data, dest_hash));
    }

    /// Pre-register a peer's identity for sending DATA without waiting for an announce.
    pub fn register_peer(
        &mut self,
        peer: &Identity,
        app_name: &str,
        aspects: &[&str],
    ) -> Result<(), rete_core::Error> {
        let now = current_time_secs();
        self.core.register_peer(peer, app_name, aspects, now)
    }

    /// Build and return a raw announce packet for this node.
    pub fn build_announce(
        &self,
        app_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, rete_core::Error> {
        let mut rng = rand::thread_rng();
        let now = current_time_secs();
        self.core.build_announce(app_data, &mut rng, now)
    }

    /// Set the resource acceptance strategy for inbound resource advertisements.
    pub fn set_resource_strategy(&mut self, strategy: ResourceStrategy) {
        self.core.set_resource_strategy(strategy);
    }

    /// Dispatch a single command, returning outbound packets, whether to
    /// continue, and an optional [`NodeEvent`] that the caller should emit
    /// through the `on_event` callback.
    pub fn handle_command<R>(
        &mut self,
        cmd: NodeCommand,
        rng: &mut R,
    ) -> (Vec<OutboundPacket>, bool, Option<NodeEvent>)
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        let now = current_time_secs();
        match cmd {
            NodeCommand::SendData { dest_hash, payload } => {
                match self.core.build_data_packet(&dest_hash, &payload, rng, now) {
                    Ok(pkt) => {
                        eprintln!("[rete] cmd: sent DATA to {}", hex::encode(dest_hash));
                        (vec![OutboundPacket::broadcast(pkt)], true, None)
                    }
                    Err(e) => {
                        eprintln!("[rete] cmd: send failed: {e}");
                        (vec![], true, None)
                    }
                }
            }
            NodeCommand::InitiateLink { dest_hash } => {
                match self.core.initiate_link(dest_hash, now, rng) {
                    Ok((outbound, link_id)) => {
                        eprintln!(
                            "[rete] cmd: initiated link {} to {}",
                            hex::encode(link_id),
                            hex::encode(dest_hash)
                        );
                        (vec![outbound], true, None)
                    }
                    Err(e) => {
                        eprintln!("[rete] cmd: link initiation failed: {e}");
                        (vec![], true, None)
                    }
                }
            }
            NodeCommand::SendChannelMessage {
                link_id,
                message_type,
                payload,
            } => {
                match self
                    .core
                    .send_channel_message(&link_id, message_type, &payload, now, rng)
                {
                    Ok(outbound) => (vec![outbound], true, None),
                    Err(e) => {
                        eprintln!("[rete] cmd: channel send failed: {e}");
                        (vec![], true, None)
                    }
                }
            }
            NodeCommand::RequestPath { dest_hash } => {
                eprintln!("[rete] cmd: requesting path to {}", hex::encode(dest_hash));
                (vec![self.core.request_path(&dest_hash)], true, None)
            }
            NodeCommand::SendLinkData { link_id, payload } => {
                match self.core.send_link_data(&link_id, &payload, rng) {
                    Ok(outbound) => {
                        eprintln!("[rete] cmd: sent link data on {}", hex::encode(link_id));
                        (vec![outbound], true, None)
                    }
                    Err(e) => {
                        eprintln!(
                            "[rete] cmd: link data send failed (link {}): {e}",
                            hex::encode(link_id)
                        );
                        (vec![], true, None)
                    }
                }
            }
            NodeCommand::SendResource { link_id, data } => {
                match self.core.start_resource(&link_id, &data, rng) {
                    Ok(pkt) => {
                        eprintln!(
                            "[rete] cmd: started resource transfer on link {}",
                            hex::encode(link_id)
                        );
                        (vec![pkt], true, None)
                    }
                    Err(e) => {
                        eprintln!(
                            "[rete] cmd: resource send failed (link {}): {e}",
                            hex::encode(link_id)
                        );
                        (vec![], true, None)
                    }
                }
            }
            NodeCommand::AcceptResource {
                link_id,
                resource_hash,
            } => {
                let packets = self.core.accept_resource(&link_id, &resource_hash, rng);
                eprintln!(
                    "[rete] cmd: accepted resource {} on link {}",
                    hex::encode(resource_hash),
                    hex::encode(link_id)
                );
                (packets, true, None)
            }
            NodeCommand::RejectResource {
                link_id,
                resource_hash,
            } => {
                let packets = self.core.reject_resource(&link_id, &resource_hash, rng);
                eprintln!(
                    "[rete] cmd: rejected resource {} on link {}",
                    hex::encode(resource_hash),
                    hex::encode(link_id)
                );
                (packets, true, None)
            }
            NodeCommand::CloseLink { link_id } => {
                let (pkt, event) = self.core.close_link(&link_id, rng);
                let packets = pkt.into_iter().collect();
                if event.is_some() {
                    eprintln!("[rete] cmd: closed link {}", hex::encode(link_id));
                } else {
                    eprintln!("[rete] cmd: close failed (link {})", hex::encode(link_id));
                }
                (packets, true, event)
            }
            NodeCommand::SendRequest {
                link_id,
                path,
                payload,
            } => match self.core.send_request(&link_id, &path, &payload, now, rng) {
                Ok((outbound, request_id)) => {
                    eprintln!(
                        "[rete] cmd: sent request on link {} (req_id={})",
                        hex::encode(link_id),
                        hex::encode(request_id)
                    );
                    (vec![outbound], true, None)
                }
                Err(e) => {
                    eprintln!("[rete] cmd: request send failed: {e}");
                    (vec![], true, None)
                }
            },
            NodeCommand::Announce { app_data } => {
                self.core.queue_announce(app_data.as_deref(), rng, now);
                eprintln!("[rete] cmd: queued announce");
                (self.core.flush_announces(now, rng), true, None)
            }
            NodeCommand::AppCommand { name, .. } => {
                eprintln!(
                    "[rete] cmd: app command '{name}' not handled (no app handler installed)"
                );
                (vec![], true, None)
            }
            NodeCommand::Shutdown => {
                eprintln!("[rete] cmd: shutdown requested");
                (vec![], false, None)
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
        // Queue initial announce and flush cached path-table announces to the new interface.
        {
            let now = current_time_secs();
            let (announces, cached) = self.core.initial_announce(&mut rng, now);
            dispatch_single(iface, &announces).await;
            eprintln!(
                "[rete] sent announce for dest {}",
                hex::encode(self.core.dest_hash())
            );
            if !cached.is_empty() {
                eprintln!(
                    "[rete] flushing {} cached announces to new interface",
                    cached.len()
                );
                dispatch_single(iface, &cached).await;
            }
        }

        // Send initial data to pre-registered peer (if configured)
        if let Some((data, dest)) = self.initial_send.take() {
            let now = current_time_secs();
            if let Ok(pkt) = self.core.build_data_packet(&dest, &data, &mut rng, now) {
                if let Err(e) = iface.send(&pkt).await {
                    eprintln!("[rete] initial send failed: {:?}", e);
                } else {
                    eprintln!(
                        "[rete] sent initial DATA to {}: {}",
                        hex::encode(dest),
                        String::from_utf8_lossy(&data)
                    );
                    println!(
                        "DATA_SENT:{}:{}",
                        hex::encode(dest),
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

        let mut recv_buf = [0u8; 8292];

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
                            let (packets, cont, event) = self.handle_command(cmd, &mut rng);
                            dispatch_single(iface, &packets).await;
                            if let Some(e) = event {
                                let extra = on_event(e, &mut self.core, &mut rng);
                                dispatch_single(iface, &extra).await;
                            }
                            if !cont { break; }
                        }
                    }
                }
                _ = announce_timer.tick() => {
                    let now = current_time_secs();
                    self.core.queue_announce(None, &mut rng, now);
                    dispatch_single(iface, &self.core.flush_announces(now, &mut rng)).await;
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
        slots: Vec<InterfaceSlot>,
        inbound_rx: tokio::sync::mpsc::Receiver<InboundMsg>,
        mut on_event: F,
    ) where
        F: FnMut(NodeEvent),
    {
        let (dummy_tx, cmd_rx) = tokio::sync::mpsc::channel(1);
        drop(dummy_tx);
        self.run_multi_with_commands(
            slots,
            inbound_rx,
            cmd_rx,
            |e, _, _: &mut rand::rngs::ThreadRng| {
                on_event(e);
                Vec::new()
            },
        )
        .await;
    }

    /// Run the main event loop with multiple interface slots and a command channel.
    ///
    /// Each slot is either a [`Direct`](InterfaceSlot::Direct) point-to-point channel
    /// (for TCP client, serial, AutoInterface) or a [`Hub`](InterfaceSlot::Hub) broadcaster
    /// (for local IPC server, TCP server, future WebSocket).
    ///
    /// The `on_event` callback receives the event, a mutable reference to the
    /// node core, and the RNG. It may return outbound packets to send.
    pub async fn run_multi_with_commands<F>(
        &mut self,
        slots: Vec<InterfaceSlot>,
        mut inbound_rx: tokio::sync::mpsc::Receiver<InboundMsg>,
        mut cmd_rx: tokio::sync::mpsc::Receiver<NodeCommand>,
        mut on_event: F,
    ) where
        F: FnMut(NodeEvent, &mut HostedNodeCore, &mut rand::rngs::ThreadRng) -> Vec<OutboundPacket>,
    {
        let mut rng = rand::thread_rng();

        // Queue initial announce and flush cached path-table announces to all interfaces.
        {
            let now = current_time_secs();
            let (announces, cached) = self.core.initial_announce(&mut rng, now);
            dispatch(&slots, &announces, 0).await;
            eprintln!("[rete] sent announce on {} interface slots", slots.len());
            if !cached.is_empty() {
                eprintln!(
                    "[rete] flushing {} cached announces to interfaces",
                    cached.len()
                );
                dispatch(&slots, &cached, 0).await;
            }
        }

        // Send initial data to pre-registered peer (if configured)
        if let Some((data, dest)) = self.initial_send.take() {
            let now = current_time_secs();
            if let Ok(pkt) = self.core.build_data_packet(&dest, &data, &mut rng, now) {
                for slot in &slots {
                    slot.send_packet(&pkt).await;
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
                    dispatch(&slots, &outcome.packets, msg.iface_idx).await;
                    if let Some(event) = outcome.event {
                        let extra = on_event(event, &mut self.core, &mut rng);
                        dispatch(&slots, &extra, 0).await;
                    }
                }
                cmd = cmd_rx.recv() => {
                    if let Some(cmd) = cmd {
                        let (packets, cont, event) = self.handle_command(cmd, &mut rng);
                        dispatch(&slots, &packets, 0).await;
                        if let Some(e) = event {
                            let extra = on_event(e, &mut self.core, &mut rng);
                            dispatch(&slots, &extra, 0).await;
                        }
                        if !cont { break; }
                    }
                }
                _ = announce_timer.tick() => {
                    let now = current_time_secs();
                    self.core.queue_announce(None, &mut rng, now);
                    dispatch(&slots, &self.core.flush_announces(now, &mut rng), 0).await;
                }
                _ = tick_timer.tick() => {
                    let now = current_time_secs();
                    let outcome = self.core.handle_tick(now, &mut rng);
                    dispatch(&slots, &outcome.packets, 0).await;
                    if let Some(event) = outcome.event {
                        let extra = on_event(event, &mut self.core, &mut rng);
                        dispatch(&slots, &extra, 0).await;
                    }
                }
            }
        }
    }
}

/// Dispatch outbound packets across interface slots.
///
/// Handles both point-to-point ([`InterfaceSlot::Direct`]) and multi-client
/// ([`InterfaceSlot::Hub`]) slots uniformly.
pub async fn dispatch(slots: &[InterfaceSlot], packets: &[OutboundPacket], source_iface: u8) {
    for pkt in packets {
        match pkt.routing {
            PacketRouting::SourceInterface => {
                if let Some(slot) = slots.get(source_iface as usize) {
                    slot.send_packet(&pkt.data).await;
                }
            }
            PacketRouting::AllExceptSource => {
                for (i, slot) in slots.iter().enumerate() {
                    if i as u8 != source_iface {
                        slot.send_packet(&pkt.data).await;
                    }
                }
            }
            PacketRouting::All => {
                for slot in slots {
                    slot.send_packet(&pkt.data).await;
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
        let mut recv_buf = [0u8; 8292];
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
