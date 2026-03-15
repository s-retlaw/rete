//! rete-tokio — Tokio runtime harness for Reticulum.
//!
//! Provides [`TokioNode`] which drives transport + interfaces in an async
//! event loop using `tokio::select!`.

use rete_core::{
    DestType, HeaderType, Identity, PacketBuilder, PacketType, MTU, TRUNCATED_HASH_LEN,
};
pub use rete_stack::NodeEvent;
pub use rete_stack::ProofStrategy;
use rete_stack::ReteInterface;
use rete_transport::{
    HostedTransport, IngestResult, Transport, ANNOUNCE_INTERVAL_SECS, TICK_INTERVAL_SECS,
};

use std::time::{SystemTime, UNIX_EPOCH};

/// A Reticulum node running on the Tokio runtime.
///
/// Owns the transport state machine and drives one or more interfaces.
pub struct TokioNode {
    /// The local identity for this node.
    pub identity: Identity,
    /// Transport state (path table, announce queue, dedup).
    pub transport: HostedTransport,
    /// Application name for our destination.
    app_name: String,
    /// Destination aspects.
    aspects: Vec<String>,
    /// Our destination hash.
    dest_hash: [u8; TRUNCATED_HASH_LEN],
    /// Optional auto-reply message sent after receiving an announce.
    auto_reply: Option<Vec<u8>>,
    /// When true, echo received DATA back to sender with "echo:" prefix.
    echo_data: bool,
    /// Dest hash of the most recently announced peer (echo target).
    last_peer: Option<[u8; TRUNCATED_HASH_LEN]>,
    /// Initial data to send right after the first announce (to a pre-registered peer).
    initial_send: Option<(Vec<u8>, [u8; TRUNCATED_HASH_LEN])>,
    /// Proof generation strategy for incoming data packets.
    proof_strategy: ProofStrategy,
}

impl TokioNode {
    /// Create a new node with the given identity and destination.
    pub fn new(identity: Identity, app_name: &str, aspects: &[&str]) -> Self {
        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name(app_name, aspects, &mut name_buf)
            .expect("app_name + aspects must fit in 128 bytes");
        let id_hash = identity.hash();
        let dest_hash = rete_core::destination_hash(expanded, Some(&id_hash));

        let mut transport = Transport::new();
        transport.add_local_destination(dest_hash);

        TokioNode {
            identity,
            transport,
            app_name: app_name.to_string(),
            aspects: aspects.iter().map(|s| s.to_string()).collect(),
            dest_hash,
            auto_reply: None,
            echo_data: false,
            last_peer: None,
            initial_send: None,
            proof_strategy: ProofStrategy::ProveNone,
        }
    }

    /// Enable transport mode: forward HEADER_2 packets for other nodes.
    pub fn enable_transport(&mut self) {
        self.transport.set_local_identity(self.identity.hash());
    }

    /// Returns our destination hash.
    pub fn dest_hash(&self) -> &[u8; TRUNCATED_HASH_LEN] {
        &self.dest_hash
    }

    /// Set an auto-reply message sent to any peer that announces.
    pub fn set_auto_reply(&mut self, msg: Option<Vec<u8>>) {
        self.auto_reply = msg;
    }

    /// Enable echo mode: received DATA is sent back to the sender with "echo:" prefix.
    pub fn set_echo_data(&mut self, echo: bool) {
        self.echo_data = echo;
    }

    /// Set the proof generation strategy for incoming data packets.
    pub fn set_proof_strategy(&mut self, strategy: ProofStrategy) {
        self.proof_strategy = strategy;
    }

    /// Queue a data message to send immediately after the initial announce.
    ///
    /// Requires `register_peer` to have been called first so the peer's
    /// identity is known for encryption.
    pub fn send_on_start(&mut self, dest_hash: [u8; TRUNCATED_HASH_LEN], data: Vec<u8>) {
        self.initial_send = Some((data, dest_hash));
    }

    /// Pre-register a peer's identity for sending DATA without waiting for an announce.
    ///
    /// Computes the peer's dest hash from the given app_name + aspects and registers
    /// their public key in the transport table.
    pub fn register_peer(&mut self, peer: &Identity, app_name: &str, aspects: &[&str]) {
        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name(app_name, aspects, &mut name_buf)
            .expect("app_name + aspects must fit in 128 bytes");
        let peer_id_hash = peer.hash();
        let peer_dest_hash = rete_core::destination_hash(expanded, Some(&peer_id_hash));
        let now = current_time_secs();
        self.transport
            .register_identity(peer_dest_hash, peer.public_key(), now);
        self.last_peer = Some(peer_dest_hash);
    }

    /// Build an encrypted DATA packet addressed to a known destination.
    ///
    /// Uses HEADER_2 (transport) when the path was learned via a relay node.
    fn build_data_packet(
        &self,
        dest_hash: &[u8; TRUNCATED_HASH_LEN],
        plaintext: &[u8],
    ) -> Option<Vec<u8>> {
        let pub_key = self.transport.recall_identity(dest_hash)?;
        let recipient = Identity::from_public_key(pub_key).ok()?;
        let mut rng = rand::thread_rng();
        let mut ct_buf = [0u8; MTU];
        let ct_len = recipient.encrypt(plaintext, &mut rng, &mut ct_buf).ok()?;
        let via = self.transport.get_path(dest_hash).and_then(|p| p.via);
        let mut pkt_buf = [0u8; MTU];
        let builder = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Single)
            .destination_hash(dest_hash)
            .context(0x00)
            .payload(&ct_buf[..ct_len]);
        let builder = if let Some(transport_id) = via {
            builder
                .header_type(HeaderType::Header2)
                .transport_type(1)
                .transport_id(&transport_id)
        } else {
            builder
        };
        let pkt_len = builder.build().ok()?;
        Some(pkt_buf[..pkt_len].to_vec())
    }

    /// Build and return a raw announce packet for this node.
    pub fn build_announce(&self, app_data: Option<&[u8]>) -> Vec<u8> {
        let aspects_refs: Vec<&str> = self.aspects.iter().map(|s| s.as_str()).collect();
        let mut rng = rand::thread_rng();
        let now = current_time_secs();
        let mut buf = [0u8; MTU];
        let n = Transport::<1024, 256, 4096>::create_announce(
            &self.identity,
            &self.app_name,
            &aspects_refs,
            app_data,
            &mut rng,
            now,
            &mut buf,
        )
        .expect("announce creation should not fail");
        buf[..n].to_vec()
    }

    /// Run the main event loop with a single interface.
    ///
    /// Sends an initial announce, then loops:
    /// - Receive packets from the interface → ingest → emit events
    /// - Periodically re-announce
    /// - Periodically tick (expire paths, retransmit announces)
    ///
    /// The `on_event` callback is invoked for each event.
    pub async fn run<I, F>(&mut self, iface: &mut I, mut on_event: F)
    where
        I: ReteInterface,
        F: FnMut(NodeEvent),
    {
        // Send initial announce
        let announce = self.build_announce(None);
        if let Err(e) = iface.send(&announce).await {
            eprintln!("[rete] failed to send initial announce: {:?}", e);
        } else {
            eprintln!("[rete] sent announce for dest {}", hex(&self.dest_hash));
        }

        // Send initial data to pre-registered peer (if configured)
        if let Some((data, dest)) = self.initial_send.take() {
            if let Some(pkt) = self.build_data_packet(&dest, &data) {
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
        // Skip the immediate first tick (we just sent the announce)
        announce_timer.tick().await;
        tick_timer.tick().await;

        let mut recv_buf = [0u8; MTU];

        loop {
            tokio::select! {
                result = iface.recv(&mut recv_buf) => {
                    match result {
                        Ok(data) => {
                            let len = data.len();
                            // Copy into a mutable buffer for ingest (which increments hops)
                            let mut pkt_buf = [0u8; MTU];
                            pkt_buf[..len].copy_from_slice(data);
                            let now = current_time_secs();
                            match self.transport.ingest(&mut pkt_buf[..len], now) {
                                IngestResult::AnnounceReceived { dest_hash, identity_hash, hops, app_data } => {
                                    self.last_peer = Some(dest_hash);
                                    on_event(NodeEvent::AnnounceReceived {
                                        dest_hash,
                                        identity_hash,
                                        hops,
                                        app_data: app_data.map(|d| d.to_vec()),
                                    });
                                    if let Some(ref msg) = self.auto_reply {
                                        if let Some(pkt) = self.build_data_packet(&dest_hash, msg) {
                                            if let Err(e) = iface.send(&pkt).await {
                                                eprintln!("[rete] auto-reply send failed: {:?}", e);
                                            } else {
                                                println!("DATA_SENT:{}:{}", hex(&dest_hash), String::from_utf8_lossy(msg));
                                            }
                                        }
                                    }
                                    // Immediately flush pending announces (retransmissions)
                                    let pending = self.transport.pending_outbound(now);
                                    for ann_raw in pending {
                                        let _ = iface.send(&ann_raw).await;
                                    }
                                }
                                IngestResult::LocalData { dest_hash, payload, packet_hash } => {
                                    let decrypted = if dest_hash == self.dest_hash {
                                        let mut dec_buf = [0u8; MTU];
                                        match self.identity.decrypt(payload, &mut dec_buf) {
                                            Ok(n) => dec_buf[..n].to_vec(),
                                            Err(_) => payload.to_vec(),
                                        }
                                    } else {
                                        payload.to_vec()
                                    };
                                    // Generate proof if strategy requires it
                                    if self.proof_strategy == ProofStrategy::ProveAll {
                                        if let Some(proof) = Transport::<1024, 256, 4096>::build_proof_packet(&self.identity, &packet_hash) {
                                            let _ = iface.send(&proof).await;
                                        }
                                    }
                                    // Echo data back to sender if echo mode is on
                                    if self.echo_data {
                                        if let Some(peer) = self.last_peer {
                                            let mut echo_msg = Vec::with_capacity(5 + decrypted.len());
                                            echo_msg.extend_from_slice(b"echo:");
                                            echo_msg.extend_from_slice(&decrypted);
                                            if let Some(pkt) = self.build_data_packet(&peer, &echo_msg) {
                                                let _ = iface.send(&pkt).await;
                                            }
                                        }
                                    }
                                    on_event(NodeEvent::DataReceived {
                                        dest_hash,
                                        payload: decrypted,
                                    });
                                }
                                IngestResult::Forward { raw, .. } => {
                                    // Forward to all interfaces (we only have one for now)
                                    let _ = iface.send(raw).await;
                                }
                                IngestResult::Duplicate | IngestResult::Invalid | IngestResult::LinkRequestReceived { .. } | IngestResult::LinkEstablished { .. } | IngestResult::LinkData { .. } | IngestResult::LinkClosed { .. } => {
                                    // Silently drop
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("[rete] recv error: {:?}", e);
                            break;
                        }
                    }
                }
                _ = announce_timer.tick() => {
                    let announce = self.build_announce(None);
                    if let Err(e) = iface.send(&announce).await {
                        eprintln!("[rete] failed to send periodic announce: {:?}", e);
                    }
                }
                _ = tick_timer.tick() => {
                    let now = current_time_secs();
                    let result = self.transport.tick(now);
                    on_event(NodeEvent::Tick {
                        expired_paths: result.expired_paths,
                    });

                    // Send pending outbound announces
                    let pending = self.transport.pending_outbound(now);
                    for ann_raw in pending {
                        if let Err(e) = iface.send(&ann_raw).await {
                            eprintln!("[rete] failed to retransmit announce: {:?}", e);
                        }
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
    /// Run the main event loop with multiple interfaces.
    ///
    /// Each interface is wrapped in a spawned recv task feeding into a shared
    /// inbound channel. Outbound is dispatched to all interfaces except the source.
    ///
    /// `senders` and `receivers` are parallel vecs — one per interface.
    /// Each sender is used by the main loop to send outbound packets.
    /// Each receiver is a spawned task feeding into `inbound_tx`.
    pub async fn run_multi<F>(
        &mut self,
        iface_senders: Vec<tokio::sync::mpsc::Sender<Vec<u8>>>,
        mut inbound_rx: tokio::sync::mpsc::Receiver<InboundMsg>,
        mut on_event: F,
    ) where
        F: FnMut(NodeEvent),
    {
        // Send initial announce to all interfaces
        let announce = self.build_announce(None);
        for tx in &iface_senders {
            let _ = tx.send(announce.clone()).await;
        }
        eprintln!("[rete] sent announce on {} interfaces", iface_senders.len());

        // Send initial data to pre-registered peer (if configured)
        if let Some((data, dest)) = self.initial_send.take() {
            if let Some(pkt) = self.build_data_packet(&dest, &data) {
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
                    let len = msg.data.len();
                    let mut pkt_buf = [0u8; MTU];
                    if len > MTU { continue; }
                    pkt_buf[..len].copy_from_slice(&msg.data);
                    let now = current_time_secs();
                    match self.transport.ingest_on(&mut pkt_buf[..len], now, msg.iface_idx) {
                        IngestResult::AnnounceReceived { dest_hash, identity_hash, hops, app_data } => {
                            self.last_peer = Some(dest_hash);
                            on_event(NodeEvent::AnnounceReceived {
                                dest_hash,
                                identity_hash,
                                hops,
                                app_data: app_data.map(|d| d.to_vec()),
                            });
                            if let Some(ref reply_msg) = self.auto_reply {
                                if let Some(pkt) = self.build_data_packet(&dest_hash, reply_msg) {
                                    if let Some(tx) = iface_senders.get(msg.iface_idx as usize) {
                                        let _ = tx.send(pkt).await;
                                    }
                                }
                            }
                            // Immediately flush pending announces to all interfaces
                            let pending = self.transport.pending_outbound(now);
                            for ann_raw in pending {
                                let v: Vec<u8> = ann_raw.iter().copied().collect();
                                for tx in &iface_senders {
                                    let _ = tx.send(v.clone()).await;
                                }
                            }
                        }
                        IngestResult::LocalData { dest_hash, payload, packet_hash } => {
                            let decrypted = if dest_hash == self.dest_hash {
                                let mut dec_buf = [0u8; MTU];
                                match self.identity.decrypt(payload, &mut dec_buf) {
                                    Ok(n) => dec_buf[..n].to_vec(),
                                    Err(_) => payload.to_vec(),
                                }
                            } else {
                                payload.to_vec()
                            };
                            // Generate proof if strategy requires it
                            if self.proof_strategy == ProofStrategy::ProveAll {
                                if let Some(proof) = Transport::<1024, 256, 4096>::build_proof_packet(&self.identity, &packet_hash) {
                                    if let Some(tx) = iface_senders.get(msg.iface_idx as usize) {
                                        let _ = tx.send(proof).await;
                                    }
                                }
                            }
                            if self.echo_data {
                                if let Some(peer) = self.last_peer {
                                    let mut echo = Vec::with_capacity(5 + decrypted.len());
                                    echo.extend_from_slice(b"echo:");
                                    echo.extend_from_slice(&decrypted);
                                    if let Some(pkt) = self.build_data_packet(&peer, &echo) {
                                        if let Some(tx) = iface_senders.get(msg.iface_idx as usize) {
                                            let _ = tx.send(pkt).await;
                                        }
                                    }
                                }
                            }
                            on_event(NodeEvent::DataReceived {
                                dest_hash,
                                payload: decrypted,
                            });
                        }
                        IngestResult::Forward { raw, source_iface } => {
                            let fwd = raw.to_vec();
                            for (i, tx) in iface_senders.iter().enumerate() {
                                if i as u8 != source_iface {
                                    let _ = tx.send(fwd.clone()).await;
                                }
                            }
                        }
                        IngestResult::Duplicate | IngestResult::Invalid | IngestResult::LinkRequestReceived { .. } | IngestResult::LinkEstablished { .. } | IngestResult::LinkData { .. } | IngestResult::LinkClosed { .. } => {}
                    }
                }
                _ = announce_timer.tick() => {
                    let announce = self.build_announce(None);
                    for tx in &iface_senders {
                        let _ = tx.send(announce.clone()).await;
                    }
                }
                _ = tick_timer.tick() => {
                    let now = current_time_secs();
                    let result = self.transport.tick(now);
                    on_event(NodeEvent::Tick {
                        expired_paths: result.expired_paths,
                    });
                    let pending = self.transport.pending_outbound(now);
                    for ann_raw in pending {
                        let v: Vec<u8> = ann_raw.iter().copied().collect();
                        for tx in &iface_senders {
                            let _ = tx.send(v.clone()).await;
                        }
                    }
                }
            }
        }
    }
}

/// Create channels for an interface and return its driver future.
///
/// Returns `(outbound_sender, driver_future)`. The caller must spawn or
/// poll the driver future (e.g. via `tokio::spawn` when the concrete type
/// is known to be `Send`).
///
/// - `inbound_tx`: feed received packets into the shared inbound channel
/// - `iface_idx`: index of this interface (for source tracking)
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
fn current_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Format bytes as hex string.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
