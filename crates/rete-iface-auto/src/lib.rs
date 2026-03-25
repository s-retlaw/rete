//! rete-iface-auto — AutoInterface for Reticulum LAN peer discovery.
//!
//! Implements automatic peer discovery using IPv6 link-local UDP multicast,
//! matching the behaviour of Python RNS `AutoInterface`.
//!
//! # Protocol
//!
//! 1. **Discovery** — Each node periodically multicasts a 32-byte discovery
//!    token (`SHA-256(group_id || link_local_addr)`) on a well-known IPv6
//!    multicast group derived from the group ID.
//!
//! 2. **Peering** — When a valid discovery token is received from a new
//!    address, the peer is added to the peer table and data exchange begins.
//!
//! 3. **Data** — Raw Reticulum packets are sent via UDP unicast to each
//!    known peer's data port. No HDLC framing — unlike TCP/Local interfaces.
//!
//! 4. **Reverse peering** — Discovery tokens are also sent via unicast to
//!    each known peer periodically, keeping peering alive if multicast fails.
//!
//! 5. **Deduplication** — A ring buffer of recent packet hashes prevents
//!    processing the same packet twice (important in multi-interface setups).

use rete_stack::ReteInterface;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// Protocol constants — match Python RNS AutoInterface
// ---------------------------------------------------------------------------

/// Hardware MTU for AutoInterface (matches Python `HW_MTU = 1196`).
pub const HW_MTU: usize = 1196;

/// Default multicast discovery port.
pub const DEFAULT_DISCOVERY_PORT: u16 = 29716;

/// Default data port for unicast packet exchange.
pub const DEFAULT_DATA_PORT: u16 = 42671;

/// Default group identifier.
pub const DEFAULT_GROUP_ID: &[u8] = b"reticulum";

/// Peering timeout in seconds — peers not heard from within this window
/// are considered offline and removed.
pub const PEERING_TIMEOUT_SECS: f64 = 22.0;

/// Multicast discovery announce interval in seconds.
pub const ANNOUNCE_INTERVAL_SECS: f64 = 1.6;

/// Peer maintenance job interval in seconds.
pub const PEER_JOB_INTERVAL_SECS: f64 = 4.0;

/// Reverse peering interval: `ANNOUNCE_INTERVAL * 3.25`.
pub const REVERSE_PEERING_INTERVAL_SECS: f64 = ANNOUNCE_INTERVAL_SECS * 3.25;

/// Deduplication ring buffer length.
const DEDUP_LEN: usize = 48;

/// Deduplication TTL in seconds.
const DEDUP_TTL_SECS: f64 = 0.75;

/// IPv6 multicast address type: "1" = temporary.
/// Used in the multicast prefix construction: `ff12::`.
const _MULTICAST_ADDRESS_TYPE: &str = "1";

/// IPv6 multicast scope: "2" = link-local.
/// Used in the multicast prefix construction: `ff12::`.
const _DISCOVERY_SCOPE: &str = "2";

// ---------------------------------------------------------------------------
// Multicast address derivation
// ---------------------------------------------------------------------------

/// Derive the IPv6 multicast group address from the group hash.
///
/// Matches the Python reference:
/// ```python
/// g = self.group_hash
/// gt  = "0"
/// gt += ":"+"{:02x}".format(g[3]+(g[2]<<8))
/// gt += ":"+"{:02x}".format(g[5]+(g[4]<<8))
/// gt += ":"+"{:02x}".format(g[7]+(g[6]<<8))
/// gt += ":"+"{:02x}".format(g[9]+(g[8]<<8))
/// gt += ":"+"{:02x}".format(g[11]+(g[10]<<8))
/// gt += ":"+"{:02x}".format(g[13]+(g[12]<<8))
/// mcast = "ff" + address_type + scope + ":" + gt
/// ```
pub fn multicast_address_from_group_hash(group_hash: &[u8; 32]) -> Ipv6Addr {
    let g = group_hash;

    // First segment: "ff12:0" → prefix byte 0xff, type|scope nibble, then 0x0000
    // The "0" in Python is the second 16-bit segment (always zero).
    let seg0: u16 = 0xff12; // ff + type "1" + scope "2"
    let seg1: u16 = 0x0000;
    let seg2: u16 = g[3] as u16 + ((g[2] as u16) << 8);
    let seg3: u16 = g[5] as u16 + ((g[4] as u16) << 8);
    let seg4: u16 = g[7] as u16 + ((g[6] as u16) << 8);
    let seg5: u16 = g[9] as u16 + ((g[8] as u16) << 8);
    let seg6: u16 = g[11] as u16 + ((g[10] as u16) << 8);
    let seg7: u16 = g[13] as u16 + ((g[12] as u16) << 8);

    Ipv6Addr::new(seg0, seg1, seg2, seg3, seg4, seg5, seg6, seg7)
}

/// Compute the group hash: `SHA-256(group_id)`.
pub fn compute_group_hash(group_id: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(group_id);
    hash.into()
}

/// Compute a discovery token for a given group_id and link-local address string.
///
/// `discovery_token = SHA-256(group_id || link_local_address_utf8)`
pub fn compute_discovery_token(group_id: &[u8], link_local_addr: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(group_id);
    hasher.update(link_local_addr.as_bytes());
    hasher.finalize().into()
}

/// Compute full SHA-256 hash of data (for deduplication).
fn full_hash(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

// ---------------------------------------------------------------------------
// Peer tracking
// ---------------------------------------------------------------------------

/// A discovered peer on the LAN.
#[derive(Debug, Clone)]
struct Peer {
    /// The interface name this peer was discovered on.
    ifname: String,
    /// Last time we heard from this peer (discovery or data).
    last_heard: Instant,
    /// Last time we sent a reverse peering announcement to this peer.
    last_outbound: Instant,
}

// ---------------------------------------------------------------------------
// Deduplication ring buffer
// ---------------------------------------------------------------------------

struct DedupEntry {
    hash: [u8; 32],
    time: Instant,
}

struct DedupRing {
    entries: Vec<DedupEntry>,
    max_len: usize,
}

impl DedupRing {
    fn new(max_len: usize) -> Self {
        Self {
            entries: Vec::with_capacity(max_len),
            max_len,
        }
    }

    /// Returns `true` if the data is a duplicate (already seen within TTL).
    fn is_duplicate(&mut self, data: &[u8]) -> bool {
        let hash = full_hash(data);
        let now = Instant::now();

        // Check if hash exists and is within TTL
        let found = self.entries.iter().any(|entry| {
            entry.hash == hash && now.duration_since(entry.time).as_secs_f64() < DEDUP_TTL_SECS
        });

        if found {
            return true;
        }

        // Evict expired entries before adding a new one
        self.entries
            .retain(|e| now.duration_since(e.time).as_secs_f64() < DEDUP_TTL_SECS);

        // Not a duplicate — add it
        if self.entries.len() >= self.max_len {
            self.entries.remove(0);
        }
        self.entries.push(DedupEntry { hash, time: now });
        false
    }
}

// ---------------------------------------------------------------------------
// Interface enumeration
// ---------------------------------------------------------------------------

/// Ignored interface name prefixes (matching Python ALL_IGNORE_IFS + common virtual).
const IGNORED_PREFIXES: &[&str] = &[
    "lo", "docker", "br-", "veth", "virbr", "lxc", "tun", "tap", "vnet", "wg",
];

/// Represents a discovered network interface with an IPv6 link-local address.
#[derive(Debug, Clone)]
pub struct IfaceInfo {
    /// Interface name (e.g. "eth0", "wlan0").
    pub name: String,
    /// Interface index (for scope_id in IPv6 sockets).
    pub index: u32,
    /// IPv6 link-local address on this interface.
    pub link_local: Ipv6Addr,
}

/// List network interfaces with IPv6 link-local addresses, filtering out
/// loopback, virtual, and Docker interfaces.
pub fn list_suitable_interfaces(
    allowed: Option<&[String]>,
    ignored: Option<&[String]>,
) -> Vec<IfaceInfo> {
    let mut result = Vec::new();

    // Use nix to enumerate interfaces
    let addrs = match nix::ifaddrs::getifaddrs() {
        Ok(a) => a,
        Err(e) => {
            log::warn!("Failed to enumerate interfaces: {e}");
            return result;
        }
    };

    for ifaddr in addrs {
        let name = ifaddr.interface_name.clone();

        // Check allowed list (if set, only these are allowed)
        if let Some(allowed) = allowed {
            if !allowed.iter().any(|a| a == &name) {
                continue;
            }
        }

        // Check ignored list
        if let Some(ignored) = ignored {
            if ignored.iter().any(|i| i == &name) {
                continue;
            }
        }

        // Check default ignored prefixes (only if no explicit allowed list)
        if allowed.is_none() && IGNORED_PREFIXES.iter().any(|p| name.starts_with(p)) {
            continue;
        }

        // Get the address — must be IPv6 link-local
        let Some(addr) = ifaddr.address else {
            continue;
        };
        let Some(sockaddr) = addr.as_sockaddr_in6() else {
            continue;
        };
        let ip = sockaddr.ip();

        // Must be link-local (fe80::/10)
        if !is_link_local(&ip) {
            continue;
        }

        // Get interface index
        let index = match nix::net::if_::if_nametoindex(name.as_str()) {
            Ok(idx) => idx,
            Err(_) => continue,
        };

        // Avoid duplicates (same interface can appear multiple times)
        if result.iter().any(|r: &IfaceInfo| r.name == name) {
            continue;
        }

        result.push(IfaceInfo {
            name,
            index,
            link_local: ip,
        });
    }

    result
}

fn is_link_local(addr: &Ipv6Addr) -> bool {
    let segs = addr.segments();
    (segs[0] & 0xffc0) == 0xfe80
}

/// Normalize a link-local address string the way Python RNS does:
/// strip the scope_id suffix and collapse `fe80:xxxx::` to `fe80::`.
fn normalize_link_local(addr: &Ipv6Addr) -> String {
    // Python: link_local_addr.split("%")[0]
    // Python: re.sub(r"fe80:[0-9a-f]*::", "fe80::", addr)
    let s = addr.to_string();
    // Strip %scope if present (Rust doesn't include it, but be safe)
    let s = s.split('%').next().unwrap_or(&s);
    // Collapse fe80:xxxx:: to fe80::
    if let Some(rest) = s.strip_prefix("fe80:") {
        if let Some(after_double_colon) = rest.find("::") {
            let suffix = &rest[after_double_colon..];
            return format!("fe80{suffix}");
        }
    }
    s.to_string()
}

// ---------------------------------------------------------------------------
// Shared state for the discovery background task
// ---------------------------------------------------------------------------

struct SharedState {
    peers: HashMap<Ipv6Addr, Peer>,
    dedup: DedupRing,
}

// ---------------------------------------------------------------------------
// AutoInterface
// ---------------------------------------------------------------------------

/// Configuration for the AutoInterface.
#[derive(Debug, Clone)]
pub struct AutoInterfaceConfig {
    /// Group identifier (default: `b"reticulum"`).
    pub group_id: Vec<u8>,
    /// Multicast discovery port (default: 29716).
    pub discovery_port: u16,
    /// Unicast data port (default: 42671).
    pub data_port: u16,
    /// Peering timeout in seconds (default: 22.0).
    pub peering_timeout: f64,
    /// Announce interval in seconds (default: 1.6).
    pub announce_interval: f64,
    /// Explicitly allowed interface names (None = all non-ignored).
    pub allowed_interfaces: Option<Vec<String>>,
    /// Explicitly ignored interface names.
    pub ignored_interfaces: Option<Vec<String>>,
}

impl Default for AutoInterfaceConfig {
    fn default() -> Self {
        Self {
            group_id: DEFAULT_GROUP_ID.to_vec(),
            discovery_port: DEFAULT_DISCOVERY_PORT,
            data_port: DEFAULT_DATA_PORT,
            peering_timeout: PEERING_TIMEOUT_SECS,
            announce_interval: ANNOUNCE_INTERVAL_SECS,
            allowed_interfaces: None,
            ignored_interfaces: None,
        }
    }
}

/// AutoInterface — LAN peer discovery via IPv6 link-local multicast.
///
/// Implements the `ReteInterface` trait: `send()` transmits to all discovered
/// peers via UDP unicast, `recv()` receives data packets from any peer.
///
/// Discovery runs in a background Tokio task, spawned on creation.
/// Dropping the interface signals the background tasks to shut down.
pub struct AutoInterface {
    /// Per-interface UDP data sockets, each bound to a specific link-local address.
    /// Matches Python RNS which creates per-interface UDPServer instances.
    /// Key is interface scope_id for routing sends to the correct socket.
    data_sockets: Vec<(u32, Arc<UdpSocket>)>,
    /// Merged data receiver — background tasks forward packets from all data sockets.
    data_rx: tokio::sync::mpsc::Receiver<(Vec<u8>, std::net::SocketAddr)>,
    /// Shared peer table and dedup state (accessed by background discovery task).
    shared: Arc<Mutex<SharedState>>,
    /// Configuration snapshot.
    config: AutoInterfaceConfig,
    /// Interfaces we are operating on.
    interfaces: Vec<IfaceInfo>,
    /// Handle to the background discovery task (dropped on teardown).
    _discovery_handle: tokio::task::JoinHandle<()>,
    /// Handle to the background peer-jobs task.
    _peer_jobs_handle: tokio::task::JoinHandle<()>,
    /// Handles to the per-interface data recv tasks.
    _data_recv_handles: Vec<tokio::task::JoinHandle<()>>,
    /// Shutdown signal — send `true` to stop background tasks.
    shutdown_tx: tokio::sync::watch::Sender<bool>,
}

impl AutoInterface {
    /// Create a new AutoInterface with the given configuration.
    ///
    /// Discovers suitable network interfaces, joins the multicast group on
    /// each, binds the data socket, and spawns background tasks for discovery
    /// and peer maintenance.
    pub async fn new(config: AutoInterfaceConfig) -> std::io::Result<Self> {
        let group_hash = compute_group_hash(&config.group_id);
        let mcast_addr = multicast_address_from_group_hash(&group_hash);

        // Enumerate suitable interfaces
        let interfaces = list_suitable_interfaces(
            config.allowed_interfaces.as_deref(),
            config.ignored_interfaces.as_deref(),
        );

        if interfaces.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no suitable network interfaces found for AutoInterface",
            ));
        }

        for iface in &interfaces {
            log::info!(
                "AutoInterface: using {} (index {}, addr {})",
                iface.name,
                iface.index,
                iface.link_local
            );
        }

        // Bind per-interface data sockets on each link-local address.
        // Matches Python RNS per-interface UDPServer instances. SO_REUSEPORT
        // is set for coexistence when Python and Rust share the same host.
        let mut data_sockets = Vec::new();
        for iface in &interfaces {
            let addr = SocketAddrV6::new(iface.link_local, config.data_port, 0, iface.index);
            let sock = Arc::new(UdpSocket::from_std(bind_udp6(addr, true)?)?);
            data_sockets.push((iface.index, sock));
        }

        // Merge all data sockets into a single channel for recv()
        let (data_tx, data_rx) = tokio::sync::mpsc::channel(256);

        let shared = Arc::new(Mutex::new(SharedState {
            peers: HashMap::new(),
            dedup: DedupRing::new(DEDUP_LEN),
        }));

        // Create discovery sockets matching Python RNS's per-interface binding strategy.
        // Python binds the multicast socket to the multicast group address (not [::]),
        // and the unicast socket to the specific link-local address.
        // Use the first interface for binding (matches common single-interface case).
        let primary_iface = &interfaces[0];

        // Multicast discovery: bind to the multicast group address on the primary interface.
        let discovery_socket = {
            let addr = SocketAddrV6::new(mcast_addr, config.discovery_port, 0, primary_iface.index);
            let std_sock = bind_udp6(addr, true)?;
            for iface in &interfaces {
                join_multicast(&std_sock, &mcast_addr, iface.index)?;
            }
            Arc::new(UdpSocket::from_std(std_sock)?)
        };

        // Unicast discovery: bind to the specific link-local address (no reuse needed).
        let unicast_disc_socket = {
            let addr = SocketAddrV6::new(
                primary_iface.link_local,
                config.discovery_port + 1,
                0,
                primary_iface.index,
            );
            Arc::new(UdpSocket::from_std(bind_udp6(addr, false)?)?)
        };

        // Collect our own link-local addresses (to ignore our own announcements)
        let our_addrs: Vec<Ipv6Addr> = interfaces.iter().map(|i| i.link_local).collect();

        // Build per-interface discovery tokens and link-local address strings
        let iface_tokens: Vec<(IfaceInfo, [u8; 32], String)> = interfaces
            .iter()
            .map(|i| {
                let addr_str = normalize_link_local(&i.link_local);
                let token = compute_discovery_token(&config.group_id, &addr_str);
                (i.clone(), token, addr_str)
            })
            .collect();

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        // Spawn discovery task: announces + listens for multicast & unicast discovery
        let discovery_handle = {
            let shared = shared.clone();
            let group_id = config.group_id.clone();
            let announce_interval = config.announce_interval;
            let discovery_port = config.discovery_port;
            let our_addrs = our_addrs.clone();
            let iface_tokens = iface_tokens.clone();
            let shutdown_rx = shutdown_rx.clone();

            tokio::spawn(discovery_loop(
                shared,
                discovery_socket,
                unicast_disc_socket,
                mcast_addr,
                group_id,
                our_addrs,
                iface_tokens,
                discovery_port,
                announce_interval,
                shutdown_rx,
            ))
        };

        // Spawn peer jobs task: expire stale peers, send reverse peering
        let peer_jobs_handle = {
            let shared = shared.clone();
            let group_id = config.group_id.clone();
            let peering_timeout = config.peering_timeout;
            let reverse_interval = config.announce_interval * 3.25;
            let discovery_port = config.discovery_port;
            let iface_tokens = iface_tokens.clone();

            tokio::spawn(peer_jobs_loop(
                shared,
                group_id,
                iface_tokens,
                peering_timeout,
                reverse_interval,
                discovery_port,
                shutdown_rx,
            ))
        };

        // Spawn per-socket recv tasks that forward data to the merged channel
        let mut data_recv_handles = Vec::new();
        let shutdown_rx_data = shutdown_tx.subscribe();
        for (scope_id, sock) in &data_sockets {
            let sock = sock.clone();
            let tx = data_tx.clone();
            let mut shutdown = shutdown_rx_data.clone();
            let scope = *scope_id;
            data_recv_handles.push(tokio::spawn(async move {
                let mut buf = vec![0u8; HW_MTU + 64];
                loop {
                    tokio::select! {
                        result = sock.recv_from(&mut buf) => {
                            match result {
                                Ok((n, src)) => {
                                    if tx.send((buf[..n].to_vec(), src)).await.is_err() {
                                        break; // channel closed
                                    }
                                }
                                Err(e) => {
                                    log::debug!("AutoInterface data recv error on scope {scope}: {e}");
                                }
                            }
                        }
                        _ = shutdown.changed() => break,
                    }
                }
            }));
        }
        // Drop the sender clone so the channel closes when all tasks exit
        drop(data_tx);

        Ok(Self {
            data_sockets,
            data_rx,
            shared,
            config,
            interfaces,
            _discovery_handle: discovery_handle,
            _peer_jobs_handle: peer_jobs_handle,
            _data_recv_handles: data_recv_handles,
            shutdown_tx,
        })
    }

    /// Create a new AutoInterface with default configuration.
    pub async fn new_default() -> std::io::Result<Self> {
        Self::new(AutoInterfaceConfig::default()).await
    }

    /// Return a snapshot of currently known peers.
    pub async fn peer_count(&self) -> usize {
        self.shared.lock().await.peers.len()
    }

    /// Return the list of interfaces this AutoInterface is operating on.
    pub fn interfaces(&self) -> &[IfaceInfo] {
        &self.interfaces
    }

    /// Return the configuration.
    pub fn config(&self) -> &AutoInterfaceConfig {
        &self.config
    }
}

impl Drop for AutoInterface {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
    }
}

impl ReteInterface for AutoInterface {
    type Error = std::io::Error;

    async fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
        if frame.len() > HW_MTU {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("frame too large ({} > {})", frame.len(), HW_MTU),
            ));
        }

        let peers: Vec<(Ipv6Addr, Peer)> = {
            let state = self.shared.lock().await;
            state
                .peers
                .iter()
                .map(|(addr, peer)| (*addr, peer.clone()))
                .collect()
        };

        for (addr, peer) in &peers {
            // Resolve scope_id from the interface name — skip peer if interface
            // vanished (scope_id 0 is invalid for link-local IPv6).
            let scope_id = match self
                .interfaces
                .iter()
                .find(|i| i.name == peer.ifname)
                .map(|i| i.index)
            {
                Some(id) => id,
                None => {
                    log::warn!(
                        "AutoInterface: no interface '{}' for peer {}, skipping",
                        peer.ifname,
                        addr,
                    );
                    continue;
                }
            };

            // Route through the socket bound to this peer's interface
            let sock = match self.data_sockets.iter().find(|(sid, _)| *sid == scope_id) {
                Some((_, s)) => s,
                None => continue,
            };

            let dest = SocketAddrV6::new(*addr, self.config.data_port, 0, scope_id);
            if let Err(e) = sock.send_to(frame, dest).await {
                log::debug!("AutoInterface: send to {} failed: {e}", addr);
            }
        }

        Ok(())
    }

    async fn recv<'a>(&mut self, buf: &'a mut [u8]) -> Result<&'a [u8], Self::Error> {
        loop {
            let (data, src) = self.data_rx.recv().await.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "data channel closed")
            })?;

            // Extract IPv6 address from source
            let src_addr = match src {
                std::net::SocketAddr::V6(v6) => *v6.ip(),
                _ => continue,
            };

            // Ignore packets from ourselves
            if self.interfaces.iter().any(|i| i.link_local == src_addr) {
                continue;
            }

            if data.len() > buf.len() {
                log::warn!(
                    "AutoInterface: packet ({} bytes) exceeds buffer ({} bytes), dropping",
                    data.len(),
                    buf.len()
                );
                continue;
            }
            let n = data.len();
            buf[..n].copy_from_slice(&data);

            // Deduplication
            {
                let mut state = self.shared.lock().await;
                if state.dedup.is_duplicate(&buf[..n]) {
                    continue;
                }
                // Refresh peer last_heard on data reception
                if let Some(peer) = state.peers.get_mut(&src_addr) {
                    peer.last_heard = Instant::now();
                }
            }

            return Ok(&buf[..n]);
        }
    }
}

// ---------------------------------------------------------------------------
// Background discovery loop
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn discovery_loop(
    shared: Arc<Mutex<SharedState>>,
    mcast_socket: Arc<UdpSocket>,
    unicast_socket: Arc<UdpSocket>,
    mcast_addr: Ipv6Addr,
    group_id: Vec<u8>,
    our_addrs: Vec<Ipv6Addr>,
    iface_tokens: Vec<(IfaceInfo, [u8; 32], String)>,
    discovery_port: u16,
    announce_interval: f64,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let mut announce_tick =
        tokio::time::interval(std::time::Duration::from_secs_f64(announce_interval));
    announce_tick.tick().await; // consume immediate tick

    let mut mcast_buf = [0u8; 64];
    let mut ucast_buf = [0u8; 64];

    loop {
        tokio::select! {
            // Periodic multicast announcement
            _ = announce_tick.tick() => {
                for (iface, token, _) in &iface_tokens {
                    // Create a per-announcement socket to set the outgoing interface
                    if let Ok(sock) = make_announce_socket(iface.index).await {
                        let dest = SocketAddrV6::new(mcast_addr, discovery_port, 0, iface.index);
                        if let Err(e) = sock.send_to(token, dest).await {
                            log::debug!("AutoInterface: announce on {} failed: {e}", iface.name);
                        }
                    }
                }
            }

            // Multicast discovery reception
            result = mcast_socket.recv_from(&mut mcast_buf) => {
                if let Ok((n, src)) = result {
                    if n == 32 {
                        if let std::net::SocketAddr::V6(src_v6) = src {
                            let src_ip = *src_v6.ip();
                            if !our_addrs.contains(&src_ip) {
                                handle_discovery_packet(
                                    &mcast_buf[..32],
                                    src_ip,
                                    src_v6.scope_id(),
                                    &group_id,
                                    &iface_tokens,
                                    &shared,
                                ).await;
                            }
                        }
                    }
                }
            }

            // Unicast discovery reception (reverse peering)
            result = unicast_socket.recv_from(&mut ucast_buf) => {
                if let Ok((n, src)) = result {
                    if n == 32 {
                        if let std::net::SocketAddr::V6(src_v6) = src {
                            let src_ip = *src_v6.ip();
                            if !our_addrs.contains(&src_ip) {
                                handle_discovery_packet(
                                    &ucast_buf[..32],
                                    src_ip,
                                    src_v6.scope_id(),
                                    &group_id,
                                    &iface_tokens,
                                    &shared,
                                ).await;
                            }
                        }
                    }
                }
            }

            // Shutdown signal
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    log::info!("AutoInterface: discovery loop shutting down");
                    return;
                }
            }
        }
    }
}

/// Validate an incoming discovery packet and add/refresh the peer.
async fn handle_discovery_packet(
    data: &[u8],
    src_ip: Ipv6Addr,
    scope_id: u32,
    group_id: &[u8],
    iface_tokens: &[(IfaceInfo, [u8; 32], String)],
    shared: &Arc<Mutex<SharedState>>,
) {
    let src_str = normalize_link_local(&src_ip);
    let expected = compute_discovery_token(group_id, &src_str);

    if data.len() < 32 || data[..32] != expected {
        log::debug!("AutoInterface: invalid discovery token from {}", src_ip);
        return;
    }

    // Determine which interface this came from using the socket's scope_id.
    // Falls back to first interface only when scope_id is 0 (kernel didn't set it).
    let ifname = if scope_id != 0 {
        iface_tokens
            .iter()
            .find(|(i, _, _)| i.index == scope_id)
            .map(|(i, _, _)| i.name.clone())
    } else {
        None
    }
    .or_else(|| iface_tokens.first().map(|(i, _, _)| i.name.clone()))
    .unwrap_or_default();

    let mut state = shared.lock().await;
    let now = Instant::now();

    if let Some(peer) = state.peers.get_mut(&src_ip) {
        // Refresh existing peer
        peer.last_heard = now;
    } else {
        // New peer discovered
        log::info!("AutoInterface: new peer discovered: {}", src_ip);
        state.peers.insert(
            src_ip,
            Peer {
                ifname,
                last_heard: now,
                last_outbound: now,
            },
        );
    }
}

// ---------------------------------------------------------------------------
// Peer maintenance loop
// ---------------------------------------------------------------------------

async fn peer_jobs_loop(
    shared: Arc<Mutex<SharedState>>,
    _group_id: Vec<u8>,
    iface_tokens: Vec<(IfaceInfo, [u8; 32], String)>,
    peering_timeout: f64,
    reverse_interval: f64,
    discovery_port: u16,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let mut tick =
        tokio::time::interval(std::time::Duration::from_secs_f64(PEER_JOB_INTERVAL_SECS));
    tick.tick().await;

    loop {
        tokio::select! {
            _ = tick.tick() => {},
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    log::info!("AutoInterface: peer jobs loop shutting down");
                    return;
                }
            }
        }

        let now = Instant::now();
        let mut timed_out = Vec::new();
        let mut reverse_targets = Vec::new();

        {
            let mut state = shared.lock().await;

            // Find timed-out peers
            for (addr, peer) in state.peers.iter() {
                if now.duration_since(peer.last_heard).as_secs_f64() > peering_timeout {
                    timed_out.push(*addr);
                }
            }

            // Remove timed-out peers
            for addr in &timed_out {
                log::info!("AutoInterface: peer timed out: {}", addr);
                state.peers.remove(addr);
            }

            // Collect peers that need reverse peering
            for (addr, peer) in state.peers.iter_mut() {
                if now.duration_since(peer.last_outbound).as_secs_f64() > reverse_interval {
                    reverse_targets.push((*addr, peer.ifname.clone()));
                    peer.last_outbound = now;
                }
            }
        }

        // Send reverse peering announcements (outside the lock)
        for (peer_addr, ifname) in &reverse_targets {
            // Find the interface info + token for this ifname
            if let Some((iface, token, _)) = iface_tokens.iter().find(|(i, _, _)| i.name == *ifname)
            {
                if let Ok(sock) = make_announce_socket(iface.index).await {
                    let dest = SocketAddrV6::new(*peer_addr, discovery_port + 1, 0, iface.index);
                    if let Err(e) = sock.send_to(token, dest).await {
                        log::debug!(
                            "AutoInterface: reverse announce to {} failed: {e}",
                            peer_addr
                        );
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Socket helpers
// ---------------------------------------------------------------------------

/// Create and bind a UDP IPv6 socket.
///
/// When `reuse` is true, sets SO_REUSEADDR + SO_REUSEPORT (for sockets that
/// may coexist with Python RNS on the same host). When false, binds exclusively.
fn bind_udp6(addr: SocketAddrV6, reuse: bool) -> std::io::Result<std::net::UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    if reuse {
        socket.set_reuse_address(true)?;
        #[cfg(not(windows))]
        socket.set_reuse_port(true)?;
    }
    socket.set_only_v6(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&socket2::SockAddr::from(addr))?;
    Ok(socket.into())
}

/// Join an IPv6 multicast group on the given interface.
fn join_multicast(
    socket: &std::net::UdpSocket,
    group: &Ipv6Addr,
    if_index: u32,
) -> std::io::Result<()> {
    // Re-wrap as socket2 to access join_multicast_v6
    let sock2 = socket2::SockRef::from(socket);
    sock2.join_multicast_v6(group, if_index)
}

/// Create a UDP socket for sending multicast announcements on a specific interface.
async fn make_announce_socket(if_index: u32) -> std::io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    socket.set_only_v6(true)?;
    socket.set_nonblocking(true)?;

    // Set multicast interface
    let if_bytes = if_index.to_ne_bytes();
    socket.set_multicast_if_v6(u32::from_ne_bytes(if_bytes))?;

    // Set multicast hops (TTL) to 1 for link-local
    socket.set_multicast_hops_v6(1)?;

    // Bind to any available port
    let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0);
    socket.bind(&socket2::SockAddr::from(addr))?;

    UdpSocket::from_std(socket.into())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_hash_reticulum() {
        let hash = compute_group_hash(b"reticulum");
        // SHA-256("reticulum") = eac4d70bfb1c16e45e39485e31e1f5cc...
        assert_eq!(hash[0], 0xea);
        assert_eq!(hash[1], 0xc4);
        assert_eq!(hash[2], 0xd7);
        assert_eq!(hash[3], 0x0b);
    }

    #[test]
    fn test_multicast_address_derivation() {
        let hash = compute_group_hash(b"reticulum");
        let addr = multicast_address_from_group_hash(&hash);

        // Expected: ff12:0:d70b:fb1c:16e4:5e39:485e:31e1
        let segs = addr.segments();
        assert_eq!(segs[0], 0xff12);
        assert_eq!(segs[1], 0x0000);
        assert_eq!(segs[2], 0xd70b);
        assert_eq!(segs[3], 0xfb1c);
        assert_eq!(segs[4], 0x16e4);
        assert_eq!(segs[5], 0x5e39);
        assert_eq!(segs[6], 0x485e);
        assert_eq!(segs[7], 0x31e1);

        // Single zero segment is rendered as ":0:", not "::"
        assert_eq!(addr.to_string(), "ff12:0:d70b:fb1c:16e4:5e39:485e:31e1");
    }

    #[test]
    fn test_discovery_token_computation() {
        // Token = SHA-256(group_id || address_string)
        let group_id = b"reticulum";
        let addr_str = "fe80::1";
        let token = compute_discovery_token(group_id, addr_str);

        // Manually compute expected value
        let mut hasher = Sha256::new();
        hasher.update(b"reticulum");
        hasher.update(b"fe80::1");
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(token, expected);
    }

    #[test]
    fn test_dedup_ring() {
        let mut ring = DedupRing::new(4);

        // First time: not a duplicate
        assert!(!ring.is_duplicate(b"packet_1"));
        // Second time (within TTL): duplicate
        assert!(ring.is_duplicate(b"packet_1"));

        // Different packet: not a duplicate
        assert!(!ring.is_duplicate(b"packet_2"));
        assert!(!ring.is_duplicate(b"packet_3"));
        assert!(!ring.is_duplicate(b"packet_4"));

        // Overflow: ring should evict oldest entry
        assert!(!ring.is_duplicate(b"packet_5"));
        // packet_1 was evicted, so it should not be found as duplicate
        // (it was the oldest entry when we added packet_5)
        assert!(!ring.is_duplicate(b"packet_1"));
    }

    #[test]
    fn test_normalize_link_local() {
        // Standard link-local address
        let addr: Ipv6Addr = "fe80::1".parse().unwrap();
        assert_eq!(normalize_link_local(&addr), "fe80::1");

        // Address with non-zero second segment (fe80:xxxx::)
        let addr: Ipv6Addr = "fe80::abcd:1234:5678:9abc".parse().unwrap();
        let normalized = normalize_link_local(&addr);
        // Should keep it as-is since there's no second segment to strip
        assert!(normalized.starts_with("fe80::"));
    }

    #[test]
    fn test_is_link_local() {
        assert!(is_link_local(&"fe80::1".parse().unwrap()));
        assert!(is_link_local(&"fe80::abcd:1234:5678:9abc".parse().unwrap()));
        assert!(!is_link_local(&"2001:db8::1".parse().unwrap()));
        assert!(!is_link_local(&"::1".parse().unwrap()));
        assert!(!is_link_local(&"ff02::1".parse().unwrap()));
    }

    #[test]
    fn test_discovery_token_different_groups() {
        // Different group_ids must produce different tokens for the same address
        let addr = "fe80::1";
        let token_a = compute_discovery_token(b"group_alpha", addr);
        let token_b = compute_discovery_token(b"group_beta", addr);
        assert_ne!(
            token_a, token_b,
            "different group_ids should produce different discovery tokens"
        );
    }

    #[test]
    fn test_multicast_address_different_groups() {
        // Different group_ids must produce different multicast addresses
        let hash_a = compute_group_hash(b"group_alpha");
        let hash_b = compute_group_hash(b"group_beta");
        let addr_a = multicast_address_from_group_hash(&hash_a);
        let addr_b = multicast_address_from_group_hash(&hash_b);
        assert_ne!(
            addr_a, addr_b,
            "different group_ids should produce different multicast addresses"
        );
    }

    #[test]
    fn test_dedup_ring_full_cycle() {
        // DedupRing with capacity 4: fill it, then cycle through more entries
        let mut ring = DedupRing::new(4);

        // Fill all 4 slots
        assert!(!ring.is_duplicate(b"a"));
        assert!(!ring.is_duplicate(b"b"));
        assert!(!ring.is_duplicate(b"c"));
        assert!(!ring.is_duplicate(b"d"));
        assert_eq!(ring.entries.len(), 4);

        // All 4 should be detected as duplicates
        assert!(ring.is_duplicate(b"a"));
        assert!(ring.is_duplicate(b"b"));
        assert!(ring.is_duplicate(b"c"));
        assert!(ring.is_duplicate(b"d"));

        // Adding a 5th entry evicts the oldest ("a")
        assert!(!ring.is_duplicate(b"e"));
        assert_eq!(ring.entries.len(), 4);
        // "a" was evicted, so it's no longer a duplicate
        assert!(!ring.is_duplicate(b"a"));
        // "b" was evicted by the re-insertion of "a" above
        assert!(!ring.is_duplicate(b"b"));

        // After cycling, ring still has exactly 4 entries
        assert_eq!(ring.entries.len(), 4);
    }
}
