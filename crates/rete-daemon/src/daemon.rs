//! Shared-instance daemon abstraction.
//!
//! [`SharedDaemonBuilder`] configures and starts a shared-instance daemon.
//! [`SharedDaemon`] is a handle to the running daemon for shutdown control.

use crate::config::{SharedInstanceConfig, SharedInstanceType};
use crate::control::{self, ControlContext, InterfaceInfo};
use crate::identity::{load_or_create_identity, JsonFileStore};

use rete_stack::OutboundPacket;
use rete_tokio::{InterfaceSlot, NodeCommand, NodeEvent, TokioNode};

use std::io::Write as _;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::mpsc;

/// Emitted to stdout when all listeners are bound and the daemon is ready.
pub const DAEMON_READY: &str = "DAEMON_READY";

/// Emitted to stdout on clean shutdown.
pub const DAEMON_SHUTDOWN: &str = "DAEMON_SHUTDOWN";

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
        if !self.config.share_instance {
            return Err(DaemonError::Config(
                "share_instance is false — this config is for a client, not a daemon".into(),
            ));
        }

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

        // Create the node.
        let mut node = TokioNode::new_boxed(identity, "rete", &["shared"])
            .map_err(|e| DaemonError::Node(e.to_string()))?;

        // Enable transport mode if requested.
        if self.transport_mode {
            node.core.enable_transport();
        }

        // Load snapshot if available.
        let mut snapshot_store = JsonFileStore::new(self.data_dir.join("snapshot.json"));
        {
            use rete_transport::SnapshotStore;
            if let Ok(Some(snap)) = snapshot_store.load() {
                node.core.load_snapshot(&snap);
            }
        }

        // Create channels.
        let (inbound_tx, inbound_rx) = mpsc::channel(256);
        let (cmd_tx, cmd_rx) = mpsc::channel(64);

        // Bind listener based on transport type.
        type ServerFuture = Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
        let (slot, server_future): (InterfaceSlot, ServerFuture) = match self
            .config
            .shared_instance_type
        {
            SharedInstanceType::Unix => {
                let server =
                    rete_tokio::local::LocalServer::bind(&self.config.instance_name, inbound_tx, 0)
                        .map_err(|e| {
                            DaemonError::Bind(format!(
                                "failed to bind shared instance '{}': {e} \
                             (another daemon may be running with the same instance name)",
                                self.config.instance_name
                            ))
                        })?;
                let broadcaster = server.broadcaster();
                (InterfaceSlot::Hub(broadcaster), Box::pin(server.run()))
            }
            SharedInstanceType::Tcp => {
                let addr = format!("127.0.0.1:{}", self.config.shared_instance_port);
                let server = rete_tokio::TcpServer::bind(
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
                let broadcaster = server.broadcaster();
                (InterfaceSlot::Hub(broadcaster), Box::pin(server.run()))
            }
        };

        // Compute authkey for RPC control plane.
        let authkey = match self.config.rpc_key {
            Some(ref rpc_key) if !rpc_key.is_empty() => hex::decode(rpc_key)
                .map_err(|e| DaemonError::Config(format!("invalid rpc_key (must be hex): {e}")))?,
            _ => control::derive_authkey(&private_key).to_vec(),
        };

        let iface_info = InterfaceInfo::from_config(&self.config);
        let control_ctx = Arc::new(ControlContext::new(authkey, iface_info));

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

                let slots = vec![slot];

                // Run the node event loop.
                node.run_multi_with_commands(
                    slots,
                    inbound_rx,
                    cmd_rx,
                    |_event: NodeEvent,
                     _core: &mut rete_stack::HostedNodeCore,
                     _rng: &mut rand::rngs::ThreadRng|
                     -> Vec<OutboundPacket> { Vec::new() },
                )
                .await;

                // Abort the server and control accept loops.
                server_handle.abort();
                control_handle.abort();
                let _ = server_handle.await;
                let _ = control_handle.await;

                // Save snapshot on shutdown.
                {
                    use rete_transport::SnapshotStore;
                    let snap = node
                        .core
                        .save_snapshot(rete_transport::SnapshotDetail::Standard);
                    if let Err(e) = snapshot_store.save(&snap) {
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
