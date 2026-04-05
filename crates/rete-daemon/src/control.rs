//! Control plane: wire framing, HMAC auth, and RPC listener.
//!
//! Implements the Python `multiprocessing.connection` wire protocol used by
//! `rnstatus` and other RNS shared-mode utilities.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// ── Wire framing ────────────────────────────────────────────────────────────

/// Maximum message size (1 MiB) to prevent OOM from rogue clients.
const MAX_MESSAGE_SIZE: u32 = 1 << 20;

/// Read a 4-byte big-endian length-prefixed message.
pub async fn read_message<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message too large: {len} bytes"),
        ));
    }
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

/// Write a 4-byte big-endian length-prefixed message.
pub async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> io::Result<()> {
    let len = payload.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

// ── Auth handshake ──────────────────────────────────────────────────────────

/// `multiprocessing.connection` auth protocol constants.
pub const CHALLENGE_PREFIX: &[u8] = b"#CHALLENGE#";
/// SHA-256 digest tag used in auth challenge/response.
pub const SHA256_TAG: &[u8] = b"{sha256}";
const WELCOME: &[u8] = b"#WELCOME#";
const FAILURE: &[u8] = b"#FAILURE#";

/// Derive the default RPC auth key from a transport identity's private key.
///
/// `authkey = SHA-256(private_key_bytes)` — matches Python RNS's
/// `RNS.Identity.full_hash(Transport.identity.get_private_key())`.
pub fn derive_authkey(private_key: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(private_key);
    hasher.finalize().to_vec()
}

/// Run the server side of the `multiprocessing.connection` HMAC auth handshake.
///
/// Returns `Ok(true)` if the client authenticated successfully, `Ok(false)` if
/// the client sent a wrong digest (a `#FAILURE#` response is sent), or `Err`
/// on I/O errors.
pub async fn server_auth<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    authkey: &[u8],
) -> io::Result<bool> {
    // 1. Generate challenge: #CHALLENGE#{sha256} + 20 random bytes (hex-encoded to 40 chars).
    let mut rng_bytes = [0u8; 20];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut rng_bytes);
    let nonce_hex = hex::encode(rng_bytes); // 40 ASCII hex chars

    let mut challenge = Vec::with_capacity(11 + 8 + 40);
    challenge.extend_from_slice(CHALLENGE_PREFIX);
    challenge.extend_from_slice(SHA256_TAG);
    challenge.extend_from_slice(nonce_hex.as_bytes());

    write_message(stream, &challenge).await?;

    // 2. Read client digest: {sha256} + 32-byte HMAC digest.
    let digest_msg = read_message(stream).await?;

    // Extract HMAC from response — Python's _create_response prefixes with {sha256}.
    let client_hmac = if digest_msg.starts_with(SHA256_TAG) {
        &digest_msg[SHA256_TAG.len()..]
    } else {
        &digest_msg[..]
    };

    if client_hmac.len() < 32 {
        write_message(stream, FAILURE).await?;
        return Ok(false);
    }

    // Verify HMAC-SHA256(authkey, message).
    // Python's _create_response computes HMAC over the "message" which is
    // everything AFTER #CHALLENGE# — i.e., "{sha256}" + random_bytes.
    // The MAC protects the digest name prefix and the random nonce.
    let message_start = CHALLENGE_PREFIX.len();
    let mut mac = Hmac::<Sha256>::new_from_slice(authkey).expect("HMAC accepts any key length");
    mac.update(&challenge[message_start..]);
    if mac.verify_slice(client_hmac).is_err() {
        write_message(stream, FAILURE).await?;
        return Ok(false);
    }

    // 3. Send welcome.
    write_message(stream, WELCOME).await?;
    Ok(true)
}

// ── RPC query channel ──────────────────────────────────────────────────────

use crate::config::{SharedInstanceConfig, SharedInstanceType};
use crate::pickle::{self, PickleValue};
use rete_core::{DestHash, IdentityHash};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::oneshot;

/// A snapshot of live daemon stats for the interface_stats response.
#[derive(Debug, Clone)]
pub struct DaemonStats {
    pub packets_received: u64,
    pub packets_sent: u64,
    pub announces_received: u64,
    pub announces_sent: u64,
    pub paths_learned: u64,
    pub links_established: u64,
    pub links_closed: u64,
    pub started_at: u64,
}

/// A path table entry for RPC responses.
#[derive(Debug, Clone)]
pub struct PathTableEntry {
    pub dest_hash: DestHash,
    pub via: Option<IdentityHash>,
    pub hops: u8,
    pub learned_at: u64,
    pub interface_name: String,
}

/// An RPC query sent from the control listener to the node event loop.
pub enum RpcQuery {
    /// Get live daemon stats (for interface_stats).
    Stats {
        reply: oneshot::Sender<DaemonStats>,
    },
    /// Get the path table (for path_table query).
    PathTable {
        max_hops: Option<i64>,
        reply: oneshot::Sender<Vec<PathTableEntry>>,
    },
    /// Look up the next hop for a destination (for next_hop query).
    NextHop {
        dest_hash: DestHash,
        reply: oneshot::Sender<Option<IdentityHash>>,
    },
    /// Look up the next hop interface name (for next_hop_if_name query).
    NextHopIfName {
        dest_hash: DestHash,
        reply: oneshot::Sender<Option<String>>,
    },
    /// Get the first hop timeout for a destination.
    FirstHopTimeout {
        dest_hash: DestHash,
        reply: oneshot::Sender<Option<f64>>,
    },
    /// Check if a path exists for a destination.
    HasPath {
        dest_hash: DestHash,
        reply: oneshot::Sender<bool>,
    },
    /// Get the active link count.
    LinkCount {
        reply: oneshot::Sender<u64>,
    },
    /// Drop a specific path.
    DropPath {
        dest_hash: DestHash,
        reply: oneshot::Sender<bool>,
    },
    /// Drop all paths via a specific next-hop.
    DropAllVia {
        via_hash: IdentityHash,
        reply: oneshot::Sender<bool>,
    },
    /// Clear all pending announce queues.
    DropAnnounceQueues {
        reply: oneshot::Sender<bool>,
    },
}

// ── RPC dispatch ────────────────────────────────────────────────────────────

/// Static interface info known at daemon startup.
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    /// e.g. "Shared Instance[rns/default]" or "Shared Instance[37428]"
    pub name: String,
    /// SHA-256(name) — 32 bytes.
    pub hash: [u8; 32],
}

impl InterfaceInfo {
    /// Build interface info from a shared-instance config.
    pub fn from_config(config: &SharedInstanceConfig) -> Self {
        let name = match config.shared_instance_type {
            SharedInstanceType::Unix => {
                format!("Shared Instance[rns/{}]", config.instance_name)
            }
            SharedInstanceType::Tcp => {
                format!("Shared Instance[{}]", config.shared_instance_port)
            }
        };
        let hash = {
            use sha2::Digest;
            let mut h = Sha256::new();
            h.update(name.as_bytes());
            h.finalize().into()
        };
        InterfaceInfo { name, hash }
    }
}

/// Context shared with the control listener.
pub struct ControlContext {
    authkey: Vec<u8>,
    iface_info: InterfaceInfo,
    rpc_tx: tokio::sync::mpsc::Sender<RpcQuery>,
    client_count: Arc<AtomicUsize>,
}

impl ControlContext {
    /// Create a new control context.
    pub fn new(
        authkey: Vec<u8>,
        iface_info: InterfaceInfo,
        rpc_tx: tokio::sync::mpsc::Sender<RpcQuery>,
        client_count: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            authkey,
            iface_info,
            rpc_tx,
            client_count,
        }
    }
}

/// Default per-hop timeout in seconds (matches Python RNS.Reticulum.DEFAULT_PER_HOP_TIMEOUT).
const DEFAULT_PER_HOP_TIMEOUT: f64 = 6.0;

/// Handle a decoded RPC request dict and return a response dict.
async fn handle_rpc_request(request: &PickleValue, ctx: &ControlContext) -> PickleValue {
    // Check for "get" key.
    if let Some(cmd) = request.get("get") {
        if let Some(cmd_str) = cmd.as_str() {
            return match cmd_str {
                "interface_stats" => handle_interface_stats(ctx).await,
                "path_table" => {
                    let max_hops = request.get("max_hops").and_then(|v| v.as_int());
                    handle_path_table(ctx, max_hops).await
                }
                "rate_table" => PickleValue::Dict(Vec::new()),
                "link_count" => handle_link_count(ctx).await,
                "next_hop" => {
                    let dest = request.get("destination_hash").and_then(|v| v.as_bytes());
                    handle_next_hop(ctx, dest).await
                }
                "next_hop_if_name" => {
                    let dest = request.get("destination_hash").and_then(|v| v.as_bytes());
                    handle_next_hop_if_name(ctx, dest).await
                }
                "first_hop_timeout" => {
                    let dest = request.get("destination_hash").and_then(|v| v.as_bytes());
                    handle_first_hop_timeout(ctx, dest).await
                }
                "has_path" => {
                    let dest = request.get("destination_hash").and_then(|v| v.as_bytes());
                    handle_has_path(ctx, dest).await
                }
                "packet_rssi" | "packet_snr" | "packet_q" => PickleValue::None,
                "blackholed_identities" => PickleValue::List(Vec::new()),
                _ => PickleValue::None,
            };
        }
    }
    // Check for "drop" key.
    if let Some(drop_cmd) = request.get("drop") {
        if let Some(cmd_str) = drop_cmd.as_str() {
            return match cmd_str {
                "path" => {
                    let dest = request.get("destination_hash").and_then(|v| v.as_bytes());
                    handle_drop_path(ctx, dest).await
                }
                "all_via" => {
                    let dest = request.get("destination_hash").and_then(|v| v.as_bytes());
                    handle_drop_all_via(ctx, dest).await
                }
                "announce_queues" => handle_drop_announce_queues(ctx).await,
                _ => PickleValue::String("ok".into()),
            };
        }
    }
    PickleValue::None
}

// ── GET handlers ────────────────────────────────────────────────────────────

async fn handle_interface_stats(ctx: &ControlContext) -> PickleValue {
    let clients = ctx.client_count.load(Ordering::Relaxed);
    let (tx, rx) = oneshot::channel();
    if ctx.rpc_tx.send(RpcQuery::Stats { reply: tx }).await.is_err() {
        return build_static_interface_stats(&ctx.iface_info, clients);
    }
    match rx.await {
        Ok(stats) => build_live_interface_stats(&ctx.iface_info, &stats, clients),
        Err(_) => build_static_interface_stats(&ctx.iface_info, clients),
    }
}

async fn handle_path_table(ctx: &ControlContext, max_hops: Option<i64>) -> PickleValue {
    let (tx, rx) = oneshot::channel();
    if ctx.rpc_tx.send(RpcQuery::PathTable { max_hops, reply: tx }).await.is_err() {
        return PickleValue::Dict(Vec::new());
    }
    match rx.await {
        Ok(entries) => build_path_table_response(entries),
        Err(_) => PickleValue::Dict(Vec::new()),
    }
}

async fn handle_link_count(ctx: &ControlContext) -> PickleValue {
    let (tx, rx) = oneshot::channel();
    if ctx.rpc_tx.send(RpcQuery::LinkCount { reply: tx }).await.is_err() {
        return PickleValue::Int(0);
    }
    match rx.await {
        Ok(count) => PickleValue::Int(count as i64),
        Err(_) => PickleValue::Int(0),
    }
}

async fn handle_next_hop(ctx: &ControlContext, dest: Option<&[u8]>) -> PickleValue {
    let Some(hash) = extract_dest_hash(dest) else {
        return PickleValue::None;
    };
    let (tx, rx) = oneshot::channel();
    if ctx.rpc_tx.send(RpcQuery::NextHop { dest_hash: hash, reply: tx }).await.is_err() {
        return PickleValue::None;
    }
    match rx.await {
        Ok(Some(via)) => PickleValue::Bytes(via.as_bytes().to_vec()),
        _ => PickleValue::None,
    }
}

async fn handle_next_hop_if_name(ctx: &ControlContext, dest: Option<&[u8]>) -> PickleValue {
    let Some(hash) = extract_dest_hash(dest) else {
        return PickleValue::None;
    };
    let (tx, rx) = oneshot::channel();
    if ctx.rpc_tx.send(RpcQuery::NextHopIfName { dest_hash: hash, reply: tx }).await.is_err() {
        return PickleValue::None;
    }
    match rx.await {
        Ok(Some(name)) => PickleValue::String(name),
        _ => PickleValue::None,
    }
}

async fn handle_first_hop_timeout(ctx: &ControlContext, dest: Option<&[u8]>) -> PickleValue {
    let Some(hash) = extract_dest_hash(dest) else {
        return PickleValue::None;
    };
    let (tx, rx) = oneshot::channel();
    if ctx.rpc_tx.send(RpcQuery::FirstHopTimeout { dest_hash: hash, reply: tx }).await.is_err() {
        return PickleValue::None;
    }
    match rx.await {
        Ok(Some(timeout)) => PickleValue::Float(timeout),
        _ => PickleValue::None,
    }
}

async fn handle_has_path(ctx: &ControlContext, dest: Option<&[u8]>) -> PickleValue {
    let Some(hash) = extract_dest_hash(dest) else {
        return PickleValue::Bool(false);
    };
    let (tx, rx) = oneshot::channel();
    if ctx.rpc_tx.send(RpcQuery::HasPath { dest_hash: hash, reply: tx }).await.is_err() {
        return PickleValue::Bool(false);
    }
    match rx.await {
        Ok(has) => PickleValue::Bool(has),
        _ => PickleValue::Bool(false),
    }
}

// ── DROP handlers ───────────────────────────────────────────────────────────

async fn handle_drop_path(ctx: &ControlContext, dest: Option<&[u8]>) -> PickleValue {
    let Some(hash) = extract_dest_hash(dest) else {
        return PickleValue::String("ok".into());
    };
    let (tx, rx) = oneshot::channel();
    let _ = ctx.rpc_tx.send(RpcQuery::DropPath { dest_hash: hash, reply: tx }).await;
    let _ = rx.await;
    PickleValue::String("ok".into())
}

async fn handle_drop_all_via(ctx: &ControlContext, dest: Option<&[u8]>) -> PickleValue {
    let Some(hash) = extract_identity_hash(dest) else {
        return PickleValue::String("ok".into());
    };
    let (tx, rx) = oneshot::channel();
    let _ = ctx.rpc_tx.send(RpcQuery::DropAllVia { via_hash: hash, reply: tx }).await;
    let _ = rx.await;
    PickleValue::String("ok".into())
}

async fn handle_drop_announce_queues(ctx: &ControlContext) -> PickleValue {
    let (tx, rx) = oneshot::channel();
    let _ = ctx.rpc_tx.send(RpcQuery::DropAnnounceQueues { reply: tx }).await;
    let _ = rx.await;
    PickleValue::String("ok".into())
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn extract_dest_hash(bytes: Option<&[u8]>) -> Option<DestHash> {
    bytes.and_then(|b| {
        if b.len() >= 16 {
            Some(DestHash::from_slice(&b[..16]))
        } else {
            None
        }
    })
}

fn extract_identity_hash(bytes: Option<&[u8]>) -> Option<IdentityHash> {
    bytes.and_then(|b| {
        if b.len() >= 16 {
            Some(IdentityHash::from_slice(&b[..16]))
        } else {
            None
        }
    })
}

fn s(v: &str) -> PickleValue {
    PickleValue::String(v.into())
}

// ── Response builders ───────────────────────────────────────────────────────

fn build_live_interface_stats(
    iface: &InterfaceInfo,
    stats: &DaemonStats,
    client_count: usize,
) -> PickleValue {
    let iface_dict = PickleValue::Dict(vec![
        (s("clients"), PickleValue::Int(client_count as i64)),
        (s("bitrate"), PickleValue::Int(1_000_000_000)),
        (s("rxs"), PickleValue::Float(0.0)),
        (s("txs"), PickleValue::Float(0.0)),
        (s("ifac_signature"), PickleValue::None),
        (s("ifac_size"), PickleValue::None),
        (s("ifac_netname"), PickleValue::None),
        (s("autoconnect_source"), PickleValue::None),
        (s("name"), PickleValue::String(iface.name.clone())),
        (s("short_name"), s("Reticulum")),
        (s("hash"), PickleValue::Bytes(iface.hash.to_vec())),
        (s("type"), s("LocalServerInterface")),
        (s("rxb"), PickleValue::Int(0)),
        (s("txb"), PickleValue::Int(0)),
        (s("incoming_announce_frequency"), PickleValue::Int(stats.announces_received as i64)),
        (s("outgoing_announce_frequency"), PickleValue::Int(stats.announces_sent as i64)),
        (s("held_announces"), PickleValue::Int(0)),
        (s("status"), PickleValue::Bool(true)),
        (s("mode"), PickleValue::Int(1)),
    ]);

    PickleValue::Dict(vec![
        (s("interfaces"), PickleValue::List(vec![iface_dict])),
        (s("rxb"), PickleValue::Int(0)),
        (s("txb"), PickleValue::Int(0)),
        (s("rxs"), PickleValue::Float(0.0)),
        (s("txs"), PickleValue::Float(0.0)),
        (s("rss"), PickleValue::None),
    ])
}

fn build_static_interface_stats(iface: &InterfaceInfo, client_count: usize) -> PickleValue {
    build_live_interface_stats(
        iface,
        &DaemonStats {
            packets_received: 0,
            packets_sent: 0,
            announces_received: 0,
            announces_sent: 0,
            paths_learned: 0,
            links_established: 0,
            links_closed: 0,
            started_at: 0,
        },
        client_count,
    )
}

fn build_path_table_response(entries: Vec<PathTableEntry>) -> PickleValue {
    // Python rnstatus expects: dict keyed by bytes(dest_hash) → list of path info.
    // Each value is a list: [via_hash_or_none, hops, expires, interface_name]
    let pairs: Vec<(PickleValue, PickleValue)> = entries
        .into_iter()
        .map(|e| {
            let key = PickleValue::Bytes(e.dest_hash.as_bytes().to_vec());
            let via = match e.via {
                Some(h) => PickleValue::Bytes(h.as_bytes().to_vec()),
                None => PickleValue::None,
            };
            let value = PickleValue::List(vec![
                via,
                PickleValue::Int(e.hops as i64),
                PickleValue::Int(e.learned_at as i64),
                PickleValue::String(e.interface_name),
            ]);
            (key, value)
        })
        .collect();
    PickleValue::Dict(pairs)
}

// ── Control listener ────────────────────────────────────────────────────────

/// Handle a single authenticated RPC connection.
async fn handle_rpc_connection<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    ctx: &ControlContext,
) -> io::Result<()> {
    // Read request pickle.
    let request_bytes = read_message(stream).await?;
    let request = pickle::decode(&request_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("pickle decode: {e}")))?;

    // Dispatch.
    let response = handle_rpc_request(&request, ctx).await;

    // Encode and send response.
    let response_bytes = pickle::encode(&response);
    write_message(stream, &response_bytes).await?;
    Ok(())
}

/// Run the Unix control listener accept loop.
#[cfg(unix)]
pub async fn run_unix_control_listener(
    instance_name: &str,
    ctx: Arc<ControlContext>,
) -> io::Result<()> {
    use tokio::net::UnixListener;

    let socket_path = format!("\0rns/{}/rpc", instance_name);
    let listener = UnixListener::bind(&socket_path)?;
    tracing::info!(socket = %format_args!("rns/{}/rpc", instance_name), "control listener bound (unix)");

    loop {
        let (stream, _addr) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let mut stream = stream;
            if let Err(e) = handle_control_connection(&mut stream, &ctx).await {
                tracing::debug!(error = %e, "control connection error");
            }
        });
    }
}

/// Run the TCP control listener accept loop.
pub async fn run_tcp_control_listener(port: u16, ctx: Arc<ControlContext>) -> io::Result<()> {
    use tokio::net::TcpListener;

    let addr = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!(addr = %addr, "control listener bound (tcp)");

    loop {
        let (mut stream, _addr) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_control_connection(&mut stream, &ctx).await {
                tracing::debug!(error = %e, "control connection error");
            }
        });
    }
}

/// Handle a single control connection: auth → RPC request → response → close.
/// Answer a challenge from the client (mutual auth, second phase).
///
/// Python's `multiprocessing.connection.Client` calls `deliver_challenge`
/// after `answer_challenge`, expecting the server to answer back.
pub async fn answer_client_challenge<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    authkey: &[u8],
) -> io::Result<bool> {
    // Read client's challenge: #CHALLENGE#{sha256} + nonce
    let challenge = read_message(stream).await?;
    if !challenge.starts_with(CHALLENGE_PREFIX) {
        return Ok(false);
    }

    // Compute HMAC over "message" (everything after #CHALLENGE#)
    let message_start = CHALLENGE_PREFIX.len();
    let message = &challenge[message_start..];

    // Determine digest name and compute response
    let (prefix, digest) = if message.starts_with(SHA256_TAG) {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(authkey).expect("HMAC accepts any key length");
        mac.update(message);
        (SHA256_TAG, mac.finalize().into_bytes().to_vec())
    } else {
        // Legacy MD5 — not supported, just fail gracefully
        return Ok(false);
    };

    // Send response: {sha256} + digest
    let mut response = Vec::with_capacity(prefix.len() + digest.len());
    response.extend_from_slice(prefix);
    response.extend_from_slice(&digest);
    write_message(stream, &response).await?;

    // Read welcome/failure
    let result = read_message(stream).await?;
    Ok(result == WELCOME)
}

async fn handle_control_connection<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    ctx: &ControlContext,
) -> io::Result<()> {
    // Phase 1: Server challenges client (deliver_challenge).
    let authed = server_auth(stream, &ctx.authkey).await?;
    if !authed {
        tracing::warn!("control auth failed (phase 1)");
        return Ok(());
    }

    // Phase 2: Answer client's challenge (mutual auth).
    // Python's multiprocessing.connection.Client does:
    //   answer_challenge(c, authkey)   ← phase 1 (we just did this as server)
    //   deliver_challenge(c, authkey)  ← phase 2 (client challenges us)
    let mutual = answer_client_challenge(stream, &ctx.authkey).await?;
    if !mutual {
        tracing::warn!("control auth failed (phase 2 mutual)");
        return Ok(());
    }

    // Handle RPC request.
    handle_rpc_connection(stream, ctx).await
}

// ── Node-side query handler ────────────────────────────────────────────────

/// Drain pending RPC queries from the channel and respond using live node state.
///
/// Called from the daemon's `on_event` closure, which has `&mut HostedNodeCore`.
pub fn drain_rpc_queries(
    rpc_rx: &mut tokio::sync::mpsc::Receiver<RpcQuery>,
    core: &mut rete_stack::HostedNodeCore,
    iface_name: &str,
) {
    while let Ok(query) = rpc_rx.try_recv() {
        match query {
            RpcQuery::Stats { reply } => {
                let ts = core.transport.stats();
                let _ = reply.send(DaemonStats {
                    packets_received: ts.packets_received,
                    packets_sent: ts.packets_sent,
                    announces_received: ts.announces_received,
                    announces_sent: ts.announces_sent,
                    paths_learned: ts.paths_learned,
                    links_established: ts.links_established,
                    links_closed: ts.links_closed,
                    started_at: ts.started_at,
                });
            }
            RpcQuery::PathTable { max_hops, reply } => {
                let entries: Vec<PathTableEntry> = core
                    .transport
                    .iter_paths()
                    .filter(|(_, p)| {
                        max_hops.map_or(true, |mh| (p.hops as i64) <= mh)
                    })
                    .map(|(dest, p)| PathTableEntry {
                        dest_hash: *dest,
                        via: p.via,
                        hops: p.hops,
                        learned_at: p.learned_at,
                        interface_name: iface_name.to_string(),
                    })
                    .collect();
                let _ = reply.send(entries);
            }
            RpcQuery::NextHop { dest_hash, reply } => {
                let via = core.transport.get_path(&dest_hash).and_then(|p| p.via);
                let _ = reply.send(via);
            }
            RpcQuery::NextHopIfName { dest_hash, reply } => {
                let name = core
                    .transport
                    .get_path(&dest_hash)
                    .map(|_| iface_name.to_string());
                let _ = reply.send(name);
            }
            RpcQuery::FirstHopTimeout { dest_hash, reply } => {
                let timeout = core
                    .transport
                    .get_path(&dest_hash)
                    .map(|p| DEFAULT_PER_HOP_TIMEOUT * (p.hops.max(1) as f64));
                let _ = reply.send(timeout);
            }
            RpcQuery::LinkCount { reply } => {
                let _ = reply.send(core.transport.link_count() as u64);
            }
            RpcQuery::DropPath { dest_hash, reply } => {
                core.transport.remove_path(&dest_hash);
                let _ = reply.send(true);
            }
            RpcQuery::DropAllVia { via_hash, reply } => {
                core.transport.remove_paths_via(&via_hash);
                let _ = reply.send(true);
            }
            RpcQuery::HasPath { dest_hash, reply } => {
                let has = core.transport.get_path(&dest_hash).is_some();
                let _ = reply.send(has);
            }
            RpcQuery::DropAnnounceQueues { reply } => {
                core.transport.clear_announces();
                let _ = reply.send(true);
            }
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a golden auth fixture into its length-prefixed messages.
    fn parse_auth_fixture(data: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
        let mut messages = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            if pos + 4 > data.len() {
                return Err("truncated length prefix");
            }
            let len = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                as usize;
            pos += 4;
            if pos + len > data.len() {
                return Err("truncated message payload");
            }
            messages.push(data[pos..pos + len].to_vec());
            pos += len;
        }
        Ok(messages)
    }

    const FIXTURE_DIR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/shared-instance/unix/control-status-query"
    );

    // ── Framing tests ───────────────────────────────────────────────────

    #[tokio::test]
    async fn framing_roundtrip() {
        let payload = b"hello world";
        let mut buf = Vec::new();
        write_message(&mut buf, payload).await.unwrap();

        // Check wire format: 4-byte BE length + payload.
        assert_eq!(buf.len(), 4 + payload.len());
        assert_eq!(&buf[..4], &(payload.len() as u32).to_be_bytes());

        let mut cursor = io::Cursor::new(buf);
        let decoded = read_message(&mut cursor).await.unwrap();
        assert_eq!(decoded, payload);
    }

    #[tokio::test]
    async fn framing_golden_auth_first_message() {
        // First 4 bytes of rpc_auth.bin should be 0x0000003b (59).
        let data = std::fs::read(format!("{FIXTURE_DIR}/rpc_auth.bin")).unwrap();
        assert_eq!(
            u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            59,
            "first auth message length should be 59"
        );
    }

    // ── Auth fixture parsing ────────────────────────────────────────────

    #[test]
    fn parse_golden_auth_messages() {
        let data = std::fs::read(format!("{FIXTURE_DIR}/rpc_auth.bin")).unwrap();
        assert_eq!(data.len(), 120);

        let messages = parse_auth_fixture(&data).unwrap();
        assert_eq!(messages.len(), 3, "auth fixture should have 3 messages");

        // Message 1: CHALLENGE — 59 bytes, starts with #CHALLENGE#{sha256}
        assert_eq!(messages[0].len(), 59);
        assert!(messages[0].starts_with(b"#CHALLENGE#{sha256}"));

        // Message 2: DIGEST — 40 bytes, starts with {sha256}
        assert_eq!(messages[1].len(), 40);
        assert!(messages[1].starts_with(b"{sha256}"));

        // Message 3: WELCOME — 9 bytes
        assert_eq!(messages[2].len(), 9);
        assert_eq!(&messages[2], b"#WELCOME#");
    }

    #[test]
    fn hmac_sha256_computation() {
        // Verify that we can compute the same HMAC as in the golden fixture.
        let data = std::fs::read(format!("{FIXTURE_DIR}/rpc_auth.bin")).unwrap();
        let messages = parse_auth_fixture(&data).unwrap();

        // We need the authkey to verify. Since we don't have the identity file
        // from the golden trace, we just verify the structure and that our
        // HMAC code produces consistent results with a known key.
        let test_key = b"test-auth-key-for-unit-test-only";
        let challenge = &messages[0];

        let mut mac = Hmac::<Sha256>::new_from_slice(test_key).unwrap();
        mac.update(challenge);
        let digest = mac.finalize().into_bytes();
        assert_eq!(digest.len(), 32);

        // Verify consistency: same key + same challenge = same digest.
        let mut mac2 = Hmac::<Sha256>::new_from_slice(test_key).unwrap();
        mac2.update(challenge);
        let digest2 = mac2.finalize().into_bytes();
        assert_eq!(digest, digest2);
    }

    // ── Live auth handshake test ────────────────────────────────────────

    #[tokio::test]
    async fn auth_success() {
        let authkey = derive_authkey(b"test-private-key-bytes");
        let authkey_clone = authkey.clone();
        let (client, server) = tokio::io::duplex(1024);
        let (mut client_r, mut client_w) = tokio::io::split(client);
        let mut server = server;

        let server_task =
            tokio::spawn(async move { server_auth(&mut server, &authkey_clone).await.unwrap() });

        // Client side: read challenge, compute HMAC over message (after #CHALLENGE#)
        // matching Python multiprocessing.connection._create_response.
        let challenge = read_message(&mut client_r).await.unwrap();
        assert!(challenge.starts_with(b"#CHALLENGE#{sha256}"));

        let message = &challenge[b"#CHALLENGE#".len()..];
        let mut mac = Hmac::<Sha256>::new_from_slice(&authkey).unwrap();
        mac.update(message);
        let digest = mac.finalize().into_bytes();

        let mut response = Vec::with_capacity(8 + 32);
        response.extend_from_slice(b"{sha256}");
        response.extend_from_slice(&digest);
        write_message(&mut client_w, &response).await.unwrap();

        // Read welcome.
        let welcome = read_message(&mut client_r).await.unwrap();
        assert_eq!(welcome, b"#WELCOME#");

        assert!(server_task.await.unwrap());
    }

    #[tokio::test]
    async fn auth_failure_wrong_key() {
        let authkey = derive_authkey(b"correct-key");
        let authkey_clone = authkey.clone();
        let (client, server) = tokio::io::duplex(1024);
        let (mut client_r, mut client_w) = tokio::io::split(client);
        let mut server = server;

        let server_task =
            tokio::spawn(async move { server_auth(&mut server, &authkey_clone).await.unwrap() });

        // Client side: read challenge, compute HMAC with WRONG key.
        let challenge = read_message(&mut client_r).await.unwrap();

        let message = &challenge[b"#CHALLENGE#".len()..];
        let wrong_key = derive_authkey(b"wrong-key");
        let mut mac = Hmac::<Sha256>::new_from_slice(&wrong_key).unwrap();
        mac.update(message);
        let digest = mac.finalize().into_bytes();

        let mut response = Vec::with_capacity(8 + 32);
        response.extend_from_slice(b"{sha256}");
        response.extend_from_slice(&digest);
        write_message(&mut client_w, &response).await.unwrap();

        // Read failure.
        let failure = read_message(&mut client_r).await.unwrap();
        assert_eq!(failure, b"#FAILURE#");

        assert!(!server_task.await.unwrap());
    }
}
