//! Shared-instance daemon abstraction.
//!
//! [`SharedDaemonBuilder`] configures and starts a shared-instance daemon.
//! [`SharedDaemon`] is a handle to the running daemon for shutdown control.

use crate::config::{SharedInstanceConfig, SharedInstanceType};
use crate::control::{self, ControlContext, InterfaceInfo, RpcQuery};
use crate::identity::{load_or_create_identity, JsonFileStore};
use crate::session::SessionRegistry;
use rete_tokio::InboundMsg;

use rete_stack::OutboundPacket;
use rete_tokio::hub::ClientEvent;
use rete_tokio::{InterfaceSlot, NodeCommand, NodeEvent, TokioNode};

use std::io::Write as _;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;

/// Emitted to stdout when all listeners are bound and the daemon is ready.
pub const DAEMON_READY: &str = "DAEMON_READY";

/// Emitted to stdout on clean shutdown.
pub const DAEMON_SHUTDOWN: &str = "DAEMON_SHUTDOWN";

/// Periodic snapshot interval in ticks (~5 min at 5-second tick rate).
const SNAPSHOT_INTERVAL_TICKS: u64 = 60;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from daemon startup.
#[derive(Debug)]
pub enum DaemonError {
    /// Config validation failed.
    Config(String),
    /// Identity load/create failed.
    Identity(String),
    /// Listener bind failed (exclusive bind violation or I/O error).
    Bind(String),
    /// Node creation failed.
    Node(String),
}

impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaemonError::Config(msg) => write!(f, "config error: {msg}"),
            DaemonError::Identity(msg) => write!(f, "identity error: {msg}"),
            DaemonError::Bind(msg) => write!(f, "bind error: {msg}"),
            DaemonError::Node(msg) => write!(f, "node error: {msg}"),
        }
    }
}

impl std::error::Error for DaemonError {}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for configuring and starting a [`SharedDaemon`].
pub struct SharedDaemonBuilder {
    config: SharedInstanceConfig,
    data_dir: PathBuf,
    transport_mode: bool,
}

impl SharedDaemonBuilder {
    /// Create a builder from a shared-instance config.
    pub fn new(config: SharedInstanceConfig) -> Self {
        SharedDaemonBuilder {
            config,
            data_dir: crate::identity::default_data_dir(),
            transport_mode: false,
        }
    }

    /// Override the data directory (default: `$HOME/.rete`).
    pub fn data_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.data_dir = path.into();
        self
    }

    /// Enable transport mode (relay packets for other nodes).
    pub fn transport_mode(mut self, enabled: bool) -> Self {
        self.transport_mode = enabled;
        self
    }

    /// Start the daemon: load identity, bind listeners, prepare event loop.
    ///
    /// Returns a [`SharedDaemon`] handle and a future that drives the event
    /// loop. The future completes when the daemon shuts down.
    ///
    /// Emits [`DAEMON_READY`] to stdout after all listeners are bound.
    /// Emits [`DAEMON_SHUTDOWN`] to stdout before the future resolves.
    pub async fn start(self) -> Result<(SharedDaemon, DaemonFuture), DaemonError> {
        self.config.validate().map_err(DaemonError::Config)?;

        // Ensure data directory exists.
        std::fs::create_dir_all(&self.data_dir).map_err(|e| {
            DaemonError::Config(format!(
                "failed to create data dir {}: {e}",
                self.data_dir.display()
            ))
        })?;

        // Load or create identity.
        let identity_path = self.data_dir.join("identity");
        let identity = load_or_create_identity(&identity_path).map_err(DaemonError::Identity)?;

        // Extract private key for authkey derivation before identity is moved.
        let private_key = identity.private_key();
        let identity_hash = identity.hash();
        eprintln!("[rete-shared] identity: {}", hex::encode(identity_hash.as_bytes()));

        // Create the node.
        let mut node = TokioNode::new_boxed(identity, "rete", &["shared"])
            .map_err(|e| DaemonError::Node(e.to_string()))?;

        // Enable transport mode if requested.
        if self.transport_mode {
            node.core.enable_transport();
            eprintln!("[rete-shared] transport mode enabled");
        }

        // Load snapshot if available.
        let snapshot_store = std::cell::RefCell::new(
            JsonFileStore::new(self.data_dir.join("snapshot.json")),
        );
        {
            use rete_transport::SnapshotStore;
            if let Ok(Some(snap)) = snapshot_store.borrow_mut().load() {
                node.core.load_snapshot(&snap);
            }
        }

        // Create channels.
        let (inbound_tx, mut inbound_rx) = mpsc::channel(256);
        let (cmd_tx, cmd_rx) = mpsc::channel(64);

        // Bind listener based on transport type.
        type ServerFuture = Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
        let (slot, server_future, client_events_rx): (
            InterfaceSlot,
            ServerFuture,
            mpsc::Receiver<ClientEvent>,
        ) = match self.config.shared_instance_type {
            SharedInstanceType::Unix => {
                let mut server =
                    rete_tokio::local::LocalServer::bind(&self.config.instance_name, inbound_tx, 0)
                        .map_err(|e| {
                            DaemonError::Bind(format!(
                                "failed to bind shared instance '{}': {e} \
                             (another daemon may be running with the same instance name)",
                                self.config.instance_name
                            ))
                        })?;
                let events_rx = server.enable_client_events(64);
                let broadcaster = server.broadcaster();
                (
                    InterfaceSlot::Hub(broadcaster),
                    Box::pin(server.run()),
                    events_rx,
                )
            }
            SharedInstanceType::Tcp => {
                let addr = format!("127.0.0.1:{}", self.config.shared_instance_port);
                let mut server = rete_tokio::TcpServer::bind(
                    &addr,
                    inbound_tx,
                    0,
                    None, // No IFAC on shared-attach (local-trust)
                    Default::default(),
                )
                .await
                .map_err(|e| {
                    DaemonError::Bind(format!(
                        "failed to bind shared instance on {addr}: {e} \
                             (another daemon may be running on the same port)",
                    ))
                })?;
                let events_rx = server.enable_client_events(64);
                let broadcaster = server.broadcaster();
                (
                    InterfaceSlot::Hub(broadcaster),
                    Box::pin(server.run()),
                    events_rx,
                )
            }
        };

        // Create session registry for client lifecycle tracking.
        let session_registry = SessionRegistry::new();

        // Compute authkey for RPC control plane.
        let authkey = match self.config.rpc_key {
            Some(ref rpc_key) if !rpc_key.is_empty() => hex::decode(rpc_key)
                .map_err(|e| DaemonError::Config(format!("invalid rpc_key (must be hex): {e}")))?,
            _ => control::derive_authkey(&private_key),
        };

        let iface_info = InterfaceInfo::from_config(&self.config);

        // Create the RPC query channel and shared client count.
        let (rpc_tx, mut rpc_rx) = mpsc::channel::<RpcQuery>(64);
        let client_count = Arc::new(AtomicUsize::new(0));

        let control_ctx = Arc::new(ControlContext::new(
            authkey,
            iface_info.clone(),
            rpc_tx,
            client_count.clone(),
        ));

        // Bind control listener.
        type ControlFuture = Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
        let control_future: ControlFuture = match self.config.shared_instance_type {
            SharedInstanceType::Unix => {
                let name = self.config.instance_name.clone();
                let ctx = control_ctx.clone();
                Box::pin(async move {
                    if let Err(e) = control::run_unix_control_listener(&name, ctx).await {
                        eprintln!("[rete-shared] control listener error: {e}");
                    }
                })
            }
            SharedInstanceType::Tcp => {
                let port = self.config.instance_control_port;
                let ctx = control_ctx.clone();
                Box::pin(async move {
                    if let Err(e) = control::run_tcp_control_listener(port, ctx).await {
                        eprintln!("[rete-shared] control listener error: {e}");
                    }
                })
            }
        };

        // Signal readiness.
        println!("{DAEMON_READY}");
        let _ = std::io::stdout().flush();

        let daemon = SharedDaemon {
            cmd_tx: cmd_tx.clone(),
            config: self.config,
        };

        // Build the run future.
        let run_future = DaemonFuture {
            inner: Box::pin(async move {
                // Spawn server accept loop.
                let server_handle = tokio::spawn(async move {
                    server_future.await;
                });

                // Spawn control listener.
                let control_handle = tokio::spawn(control_future);

                // Spawn session event processor.
                let session_client_count = client_count.clone();
                let session_handle = tokio::spawn(async move {
                    process_client_events(client_events_rx, session_registry, session_client_count).await;
                });

                // Extract the broadcaster for sending cached announces to new clients.
                let announce_broadcaster = match &slot {
                    InterfaceSlot::Hub(b) => Some(b.clone()),
                    _ => None,
                };

                let slots = vec![slot];

                // Intercept inbound messages to replay cached announces to
                // newly-connected clients.  Python rnsd does this implicitly;
                // without it, clients that connect after an announce miss it.
                const MAX_CACHED_ANNOUNCES: usize = 256;
                let (wrapped_tx, wrapped_rx) = tokio::sync::mpsc::channel::<InboundMsg>(256);
                tokio::spawn(async move {
                    let mut known_clients: std::collections::HashSet<usize> = std::collections::HashSet::new();
                    let mut cached_announces: std::collections::VecDeque<Vec<u8>> = std::collections::VecDeque::new();
                    while let Some(msg) = inbound_rx.recv().await {
                        if let Some(cid) = msg.client_id {
                            if known_clients.insert(cid) {
                                for ann in &cached_announces {
                                    if let Some(ref bc) = announce_broadcaster {
                                        bc.send_to_client(cid, ann).await;
                                    }
                                }
                            }
                        }
                        if msg.data.len() > 2 && (msg.data[0] & 0x03) == 1 {
                            cached_announces.push_back(msg.data.clone());
                            while cached_announces.len() > MAX_CACHED_ANNOUNCES {
                                cached_announces.pop_front();
                            }
                        }
                        let _ = wrapped_tx.send(msg).await;
                    }
                });

                // Run the node event loop with periodic snapshot on tick
                // and RPC query drain.
                let rpc_iface_name = iface_info.name.clone();
                let mut tick_count: u64 = 0;
                node.run_multi_with_commands(
                    slots,
                    wrapped_rx,
                    cmd_rx,
                    |event: NodeEvent,
                     core: &mut rete_stack::HostedNodeCore,
                     _rng: &mut rand::rngs::ThreadRng|
                     -> Vec<OutboundPacket> {
                        // Drain pending RPC queries on every event loop iteration.
                        control::drain_rpc_queries(&mut rpc_rx, core, &rpc_iface_name);

                        if let NodeEvent::Tick { .. } = &event {
                            tick_count += 1;
                            if tick_count % SNAPSHOT_INTERVAL_TICKS == 0 && core.path_count() > 0 {
                                use rete_transport::SnapshotStore;
                                let snap = core.save_snapshot(
                                    rete_transport::SnapshotDetail::Standard,
                                );
                                if let Err(e) = snapshot_store.borrow_mut().save(&snap) {
                                    eprintln!("[rete-shared] periodic snapshot failed: {e}");
                                }
                            }
                        }
                        Vec::new()
                    },
                )
                .await;

                // Abort the server, control, and session accept loops.
                server_handle.abort();
                control_handle.abort();
                session_handle.abort();
                let _ = server_handle.await;
                let _ = control_handle.await;
                let _ = session_handle.await;

                // Save snapshot on shutdown.
                {
                    use rete_transport::SnapshotStore;
                    let snap = node
                        .core
                        .save_snapshot(rete_transport::SnapshotDetail::Standard);
                    if let Err(e) = snapshot_store.borrow_mut().save(&snap) {
                        eprintln!("[rete-shared] failed to save snapshot: {e}");
                    }
                }

                println!("{DAEMON_SHUTDOWN}");
                let _ = std::io::stdout().flush();
            }),
        };

        Ok((daemon, run_future))
    }
}

// ---------------------------------------------------------------------------
// Running daemon handle
// ---------------------------------------------------------------------------

/// Handle to a running shared-instance daemon.
///
/// Use [`shutdown`](SharedDaemon::shutdown) to request a clean shutdown.
pub struct SharedDaemon {
    cmd_tx: mpsc::Sender<NodeCommand>,
    config: SharedInstanceConfig,
}

impl SharedDaemon {
    /// Request a clean shutdown of the daemon.
    pub async fn shutdown(&self) {
        let _ = self.cmd_tx.send(NodeCommand::Shutdown).await;
    }

    /// Get a clone of the command sender for injecting commands.
    pub fn command_sender(&self) -> mpsc::Sender<NodeCommand> {
        self.cmd_tx.clone()
    }

    /// Get the shared-instance config used at startup.
    pub fn config(&self) -> &SharedInstanceConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// Daemon future
// ---------------------------------------------------------------------------

/// Future that drives the daemon event loop. Completes on shutdown.
///
/// Not `Send` because the internal `ThreadRng` used by `TokioNode`
/// contains `Rc`. Use with `tokio::task::LocalSet` or a
/// `current_thread` runtime.
pub struct DaemonFuture {
    inner: std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>,
}

impl std::future::Future for DaemonFuture {
    type Output = ();

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        self.inner.as_mut().poll(cx)
    }
}

// ---------------------------------------------------------------------------
// Session event processor
// ---------------------------------------------------------------------------

/// Process client connect/disconnect events and update the session registry.
async fn process_client_events(
    mut rx: mpsc::Receiver<ClientEvent>,
    mut registry: SessionRegistry,
    client_count: Arc<AtomicUsize>,
) {
    while let Some(event) = rx.recv().await {
        match event {
            ClientEvent::Connected(id) => {
                registry.register(id);
                client_count.store(registry.session_count(), Ordering::Relaxed);
                eprintln!("[rete-session] client {id} connected ({} active)", registry.session_count());
            }
            ClientEvent::Disconnected(id) => {
                let removed = registry.unregister(id);
                client_count.store(registry.session_count(), Ordering::Relaxed);
                eprintln!(
                    "[rete-session] client {id} disconnected, {} dest(s) released ({} active)",
                    removed.len(),
                    registry.session_count(),
                );
            }
        }
    }
}
