//! Linux/hosted example — Reticulum node on desktop or Raspberry Pi.
//!
//! Connects to Python rnsd over TCP for interop testing, or directly to
//! an ESP32 over serial. Also supports local shared instance IPC and
//! AutoInterface for LAN peer discovery.
//!
//! Usage:
//!   cargo run -p rete-example-linux -- --connect 127.0.0.1:4242
//!   cargo run -p rete-example-linux -- --serial /dev/ttyACM0
//!   cargo run -p rete-example-linux -- --connect 127.0.0.1:4242 --local-server default
//!   cargo run -p rete-example-linux -- --local-client default
//!   cargo run -p rete-example-linux -- --auto
//!   cargo run -p rete-example-linux -- --auto --auto-group mynetwork
//!   cargo run -p rete-example-linux -- --connect 127.0.0.1:4242 --propagation
//!   cargo run -p rete-example-linux -- --listen 0.0.0.0:4242 --transport
//!   cargo run -p rete-example-linux -- --connect 127.0.0.1:4242 --monitoring 127.0.0.1:9100

use rete_core::Identity;
use rete_iface_auto::{AutoInterface, AutoInterfaceConfig};
use rete_iface_serial::SerialInterface;
use rete_iface_tcp::TcpInterface;
use rete_lxmf::{LXMessage, LxmfEvent, LxmfRouter};
use rete_stack::{OutboundPacket, RequestHandler, RequestPolicy};
use rete_tokio::local::{LocalServer, ReconnectingLocalClient};
use rete_tokio::tcp_server::TcpServer;
use rete_tokio::{interface_task, InboundMsg, InterfaceSlot, NodeCommand, NodeEvent, TokioNode};
use rete_transport::SnapshotStore;

use std::cell::RefCell;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_ADDR: &str = "127.0.0.1:4242";
const DEFAULT_BAUD: u32 = 115200;
const APP_NAME: &str = "rete";
const ASPECTS: &[&str] = &["example", "v1"];
/// Default propagation message TTL: 30 days in seconds.
const PROPAGATION_TTL_SECS: u64 = 2_592_000;

// ---------------------------------------------------------------------------
// TOML configuration file
// ---------------------------------------------------------------------------

/// Top-level config file structure. All fields are `Option` so CLI flags
/// can override individual values while the rest come from the file.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
struct Config {
    node: NodeConfig,
    interfaces: InterfacesConfig,
    ifac: IfacConfig,
    logging: LoggingConfig,
}

#[derive(Debug, Default, serde::Deserialize)]
struct NodeConfig {
    transport: Option<bool>,
    identity_file: Option<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
struct InterfacesConfig {
    tcp_server: Option<TcpServerConfig>,
    tcp_client: Option<TcpClientConfig>,
    serial: Option<SerialConfig>,
    auto: Option<AutoConfig>,
}

#[derive(Debug, Default, serde::Deserialize)]
struct TcpServerConfig {
    listen: Option<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
struct TcpClientConfig {
    connect: Option<Vec<String>>,
}

#[derive(Debug, Default, serde::Deserialize)]
struct SerialConfig {
    port: Option<String>,
    baud: Option<u32>,
}

#[derive(Debug, Default, serde::Deserialize)]
struct AutoConfig {
    enabled: Option<bool>,
    group: Option<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
struct IfacConfig {
    netname: Option<String>,
    netkey: Option<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
struct LoggingConfig {
    packet_log: Option<bool>,
}

fn load_config(path: &std::path::Path) -> Option<Config> {
    match std::fs::read_to_string(path) {
        Ok(text) => match toml::from_str(&text) {
            Ok(cfg) => {
                eprintln!("[rete] loaded config from {}", path.display());
                Some(cfg)
            }
            Err(e) => {
                eprintln!("[rete] failed to parse config {}: {e}", path.display());
                std::process::exit(1);
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            eprintln!("[rete] failed to read config {}: {e}", path.display());
            std::process::exit(1);
        }
    }
}

fn generate_default_config() -> &'static str {
    r#"# rete node configuration
# CLI flags override values in this file.

[node]
# Enable transport mode (relay packets for other nodes)
# transport = true

# Path to identity file (default: ~/.rete/identity)
# identity_file = "~/.rete/identity"

[interfaces.tcp_server]
# Listen for incoming TCP connections
# listen = "0.0.0.0:4242"

[interfaces.tcp_client]
# Connect to these TCP servers
# connect = ["127.0.0.1:4242"]

[interfaces.serial]
# Serial port path
# port = "/dev/ttyACM0"
# baud = 115200

[interfaces.auto]
# Enable AutoInterface (IPv6 link-local multicast peer discovery)
# enabled = true
# group = "reticulum"

[ifac]
# Interface Access Control
# netname = "mynetwork"
# netkey = "secret"

[logging]
# Log every inbound/outbound packet header to stderr
# packet_log = false
"#
}

// ---------------------------------------------------------------------------
// Packet logging
// ---------------------------------------------------------------------------

/// Log a raw packet's parsed header to stderr (used as packet_log_fn callback).
fn log_packet(raw: &[u8], direction: &str, iface_idx: u8) {
    use rete_core::{HeaderType, Packet};

    let pkt = match Packet::parse(raw) {
        Ok(p) => p,
        Err(_) => {
            eprintln!(
                "[pkt] {} iface={} PARSE_ERROR len={}",
                direction,
                iface_idx,
                raw.len()
            );
            return;
        }
    };

    let hdr = match pkt.header_type {
        HeaderType::Header1 => "H1",
        HeaderType::Header2 => "H2",
    };
    let ctx_name = match pkt.context {
        rete_core::CONTEXT_NONE => "NONE",
        rete_core::CONTEXT_RESOURCE => "RESOURCE",
        rete_core::CONTEXT_RESOURCE_ADV => "RES_ADV",
        rete_core::CONTEXT_RESOURCE_REQ => "RES_REQ",
        rete_core::CONTEXT_RESOURCE_HMU => "RES_HMU",
        rete_core::CONTEXT_RESOURCE_PRF => "RES_PRF",
        rete_core::CONTEXT_RESOURCE_ICL => "RES_ICL",
        rete_core::CONTEXT_RESOURCE_RCL => "RES_RCL",
        rete_core::CONTEXT_REQUEST => "REQUEST",
        rete_core::CONTEXT_RESPONSE => "RESPONSE",
        rete_core::CONTEXT_CHANNEL => "CHANNEL",
        rete_core::CONTEXT_KEEPALIVE => "KEEPALIVE",
        rete_core::CONTEXT_LINKIDENTIFY => "LINKIDENT",
        rete_core::CONTEXT_LINKCLOSE => "LINKCLOSE",
        rete_core::CONTEXT_LINKPROOF => "LINKPROOF",
        rete_core::CONTEXT_LRRTT => "LRRTT",
        rete_core::CONTEXT_LRPROOF => "LRPROOF",
        _ => "?",
    };

    eprintln!(
        "[pkt] {} iface={} {}/{:?}/{:?} hops={} dest={} ctx={:#04x}({}) plen={} raw={}",
        direction,
        iface_idx,
        hdr,
        pkt.packet_type,
        pkt.dest_type,
        pkt.hops,
        hex::encode(pkt.destination_hash),
        pkt.context,
        ctx_name,
        pkt.payload.len(),
        hex::encode(&raw[..raw.len().min(64)])
    );
}

// ---------------------------------------------------------------------------
// bz2 compression / decompression for resource data
// ---------------------------------------------------------------------------

fn bz2_compress(data: &[u8]) -> Option<Vec<u8>> {
    use core::ffi::{c_char, c_int, c_uint};
    use libbz2_rs_sys::BZ2_bzBuffToBuffCompress;

    // bz2 worst-case: input + 1% + 600 bytes
    let out_size = data.len() + data.len() / 100 + 600;
    let mut out = vec![0u8; out_size];
    let mut dest_len = out_size as c_uint;

    let ret = unsafe {
        BZ2_bzBuffToBuffCompress(
            out.as_mut_ptr() as *mut c_char,
            &mut dest_len,
            data.as_ptr() as *mut c_char,
            data.len() as c_uint,
            9 as c_int, // blockSize100k=9 (max compression)
            0,          // verbosity=0
            30,         // workFactor=30 (Python default)
        )
    };

    if ret == 0 {
        out.truncate(dest_len as usize);
        Some(out)
    } else {
        None
    }
}

fn bz2_decompress(data: &[u8]) -> Option<Vec<u8>> {
    use core::ffi::{c_char, c_uint};
    use libbz2_rs_sys::BZ2_bzBuffToBuffDecompress;

    const BZ_OUTBUFF_FULL: i32 = -8;

    // Try 10x first, retry with 100x if buffer was too small
    for multiplier in [10, 100] {
        let out_size = (data.len() * multiplier).max(4096);
        let mut out = vec![0u8; out_size];
        let mut dest_len = out_size as c_uint;

        let ret = unsafe {
            BZ2_bzBuffToBuffDecompress(
                out.as_mut_ptr() as *mut c_char,
                &mut dest_len,
                data.as_ptr() as *mut c_char,
                data.len() as c_uint,
                0, // small=0 (fast mode)
                0, // verbosity=0
            )
        };

        if ret == 0 {
            out.truncate(dest_len as usize);
            return Some(out);
        }
        if ret != BZ_OUTBUFF_FULL {
            return None;
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Identity persistence
// ---------------------------------------------------------------------------

fn default_rete_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".rete")
}

fn default_identity_path() -> PathBuf {
    default_rete_dir().join("identity")
}

fn default_snapshot_path() -> PathBuf {
    default_rete_dir().join("snapshot.json")
}

// ---------------------------------------------------------------------------
// Path table snapshot persistence
// ---------------------------------------------------------------------------

/// JSON file-based snapshot store for hosted/desktop nodes.
struct JsonFileStore {
    path: PathBuf,
}

impl JsonFileStore {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl rete_transport::SnapshotStore for JsonFileStore {
    type Error = std::io::Error;

    fn save(&mut self, snapshot: &rete_transport::Snapshot) -> Result<(), Self::Error> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::File::create(&self.path)?;
        serde_json::to_writer(file, snapshot)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    fn load(&mut self) -> Result<Option<rete_transport::Snapshot>, Self::Error> {
        match std::fs::read_to_string(&self.path) {
            Ok(json) => {
                let snap: rete_transport::Snapshot = serde_json::from_str(&json)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                eprintln!("[rete] loaded snapshot from {}", self.path.display());
                Ok(Some(snap))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

fn load_or_create_identity(path: &std::path::Path) -> Identity {
    match std::fs::read(path) {
        Ok(data) => {
            if data.len() != 64 {
                eprintln!(
                    "[rete] invalid identity file (expected 64 bytes, got {})",
                    data.len()
                );
                std::process::exit(1);
            }
            eprintln!("[rete] loaded identity from {}", path.display());
            Identity::from_private_key(&data).expect("invalid identity file")
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut rng = rand::thread_rng();
            let mut prv = [0u8; 64];
            rand::RngCore::fill_bytes(&mut rng, &mut prv);
            let identity = Identity::from_private_key(&prv).expect("invalid random key");

            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("failed to create identity directory");
            }
            std::fs::write(path, identity.private_key()).expect("failed to write identity file");

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                    .expect("failed to set identity file permissions");
            }

            eprintln!("[rete] created new identity at {}", path.display());
            identity
        }
        Err(e) => {
            eprintln!("[rete] failed to read identity file: {e}");
            std::process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Stdin command parser
// ---------------------------------------------------------------------------

fn parse_hex_16(hex_str: &str) -> Option<[u8; 16]> {
    let bytes = hex::decode(hex_str).ok()?;
    bytes.as_slice().try_into().ok()
}

/// Parse `<cmd> <link_id_hex> <text>` into (link_id, payload).
fn parse_link_and_text(line: &str, cmd: &str) -> Option<([u8; 16], Vec<u8>)> {
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() < 3 {
        eprintln!("[rete] usage: {cmd} <link_id_hex> <text>");
        return None;
    }
    let link_id = parse_hex_16(parts[1])?;
    Some((link_id, parts[2].as_bytes().to_vec()))
}

fn parse_command(line: &str) -> Option<NodeCommand> {
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    match parts.first().copied()? {
        "send" if parts.len() >= 3 => Some(NodeCommand::SendData {
            dest_hash: parse_hex_16(parts[1])?,
            payload: parts[2].as_bytes().to_vec(),
        }),
        "link" if parts.len() >= 2 => Some(NodeCommand::InitiateLink {
            dest_hash: parse_hex_16(parts[1])?,
        }),
        "channel" => {
            let parts: Vec<&str> = line.splitn(4, ' ').collect();
            if parts.len() < 4 {
                eprintln!("[rete] usage: channel <link_id_hex> <msg_type_hex> <text>");
                return None;
            }
            let link_id = parse_hex_16(parts[1])?;
            let msg_type = u16::from_str_radix(parts[2].trim_start_matches("0x"), 16).ok()?;
            Some(NodeCommand::SendChannelMessage {
                link_id,
                message_type: msg_type,
                payload: parts[3].as_bytes().to_vec(),
            })
        }
        "path" if parts.len() >= 2 => Some(NodeCommand::RequestPath {
            dest_hash: parse_hex_16(parts[1])?,
        }),
        "announce" => {
            let app_data = if parts.len() >= 2 {
                Some(parts[1..].join(" ").into_bytes())
            } else {
                None
            };
            Some(NodeCommand::Announce { app_data })
        }
        "linkdata" => {
            let (link_id, payload) = parse_link_and_text(line, "linkdata")?;
            Some(NodeCommand::SendLinkData { link_id, payload })
        }
        "resource" => {
            let (link_id, data) = parse_link_and_text(line, "resource")?;
            Some(NodeCommand::SendResource { link_id, data })
        }
        "close" if parts.len() >= 2 => Some(NodeCommand::CloseLink {
            link_id: parse_hex_16(parts[1])?,
        }),
        "request" => {
            let parts: Vec<&str> = line.splitn(4, ' ').collect();
            if parts.len() < 4 {
                eprintln!("[rete] usage: request <link_id_hex> <path> <data>");
                return None;
            }
            let link_id = parse_hex_16(parts[1])?;
            Some(NodeCommand::SendRequest {
                link_id,
                path: parts[2].to_string(),
                payload: parts[3].as_bytes().to_vec(),
            })
        }
        "lxmf" => {
            let parts: Vec<&str> = line.splitn(3, ' ').collect();
            if parts.len() < 3 {
                eprintln!("[rete] usage: lxmf <dest_hash_hex> <message>");
                return None;
            }
            Some(NodeCommand::AppCommand {
                name: "lxmf-send".to_string(),
                dest_hash: Some(parse_hex_16(parts[1])?),
                link_id: None,
                payload: parts[2].as_bytes().to_vec(),
            })
        }
        "lxmf-link" => {
            let parts: Vec<&str> = line.splitn(4, ' ').collect();
            if parts.len() < 4 {
                eprintln!("[rete] usage: lxmf-link <link_id_hex> <dest_hash_hex> <message>");
                return None;
            }
            Some(NodeCommand::AppCommand {
                name: "lxmf-link-send".to_string(),
                dest_hash: Some(parse_hex_16(parts[2])?),
                link_id: Some(parse_hex_16(parts[1])?),
                payload: parts[3].as_bytes().to_vec(),
            })
        }
        "lxmf-announce" => Some(NodeCommand::AppCommand {
            name: "lxmf-announce".to_string(),
            dest_hash: None,
            link_id: None,
            payload: vec![],
        }),
        "lxmf-prop-announce" => Some(NodeCommand::AppCommand {
            name: "lxmf-prop-announce".to_string(),
            dest_hash: None,
            link_id: None,
            payload: vec![],
        }),
        "stats" => Some(NodeCommand::AppCommand {
            name: "stats".to_string(),
            dest_hash: None,
            link_id: None,
            payload: vec![],
        }),
        "quit" => Some(NodeCommand::Shutdown),
        _ => {
            eprintln!("[rete] unknown command: {line}");
            eprintln!("[rete] commands: send <dest_hex> <text> | link <dest_hex> | close <link_id> | linkdata <link_id> <text> | channel <link_id> <msg_type> <text> | resource <link_id> <text> | request <link_id> <path> <data> | path <dest_hex> | announce [data] | lxmf <dest_hex> <msg> | lxmf-link <link_id> <dest_hex> <msg> | lxmf-prop-announce | stats | quit");
            None
        }
    }
}

fn spawn_signal_handler(cmd_tx: tokio::sync::mpsc::Sender<NodeCommand>) {
    tokio::spawn(async move {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = sigterm.recv() => {},
        }
        let _ = cmd_tx.send(NodeCommand::Shutdown).await;
    });
}

fn spawn_stdin_reader(cmd_tx: tokio::sync::mpsc::Sender<NodeCommand>) {
    tokio::task::spawn_blocking(move || {
        use std::io::BufRead;
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { break };
            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }
            if let Some(cmd) = parse_command(&line) {
                if cmd_tx.blocking_send(cmd).is_err() {
                    break;
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    // --generate-config: print default config to stdout and exit
    if args.iter().any(|a| a == "--generate-config") {
        print!("{}", generate_default_config());
        return;
    }

    // Load config file: --config <path> or fallback to ~/.rete/config.toml
    let config_path = args
        .windows(2)
        .find(|w| w[0] == "--config")
        .map(|w| PathBuf::from(&w[1]));
    let cfg = if let Some(ref path) = config_path {
        // Explicit --config: error if not found
        load_config(path).unwrap_or_else(|| {
            eprintln!("[rete] config file not found: {}", path.display());
            std::process::exit(1);
        })
    } else {
        // Implicit fallback: silently skip if not found
        let default_path = default_rete_dir().join("config.toml");
        load_config(&default_path).unwrap_or_default()
    };

    // Parse CLI flags — CLI values override config file values.

    // --connect <addr> (can be repeated for multi-interface)
    let cli_addrs: Vec<String> = args
        .windows(2)
        .filter(|w| w[0] == "--connect")
        .map(|w| w[1].clone())
        .collect();
    let addrs: Vec<String> = if !cli_addrs.is_empty() {
        cli_addrs
    } else {
        cfg.interfaces
            .tcp_client
            .as_ref()
            .and_then(|c| c.connect.clone())
            .unwrap_or_default()
    };

    // --serial <path>
    let serial_path: Option<String> = args
        .windows(2)
        .find(|w| w[0] == "--serial")
        .map(|w| w[1].clone())
        .or_else(|| cfg.interfaces.serial.as_ref().and_then(|s| s.port.clone()));

    // --baud <rate> (default 115200)
    let baud: u32 = args
        .windows(2)
        .find(|w| w[0] == "--baud")
        .and_then(|w| w[1].parse().ok())
        .or_else(|| cfg.interfaces.serial.as_ref().and_then(|s| s.baud))
        .unwrap_or(DEFAULT_BAUD);

    // --identity-file <path>
    let identity_file: Option<PathBuf> = args
        .windows(2)
        .find(|w| w[0] == "--identity-file")
        .map(|w| PathBuf::from(&w[1]))
        .or_else(|| cfg.node.identity_file.as_ref().map(PathBuf::from));

    // --auto-reply <message> (send DATA after receiving an announce)
    let auto_reply = args
        .windows(2)
        .find(|w| w[0] == "--auto-reply")
        .map(|w| w[1].clone());

    // --auto-reply-ping: send "ping:<unix_timestamp>" on announce receipt
    let auto_reply_ping = args.iter().any(|a| a == "--auto-reply-ping");

    // --transport: enable transport mode (relay HEADER_2 packets)
    let transport_mode =
        args.iter().any(|a| a == "--transport") || cfg.node.transport.unwrap_or(false);

    // --local-server <instance_name>
    let local_server_name = args
        .windows(2)
        .find(|w| w[0] == "--local-server")
        .map(|w| w[1].clone());

    // --local-client <instance_name>
    let local_client_name = args
        .windows(2)
        .find(|w| w[0] == "--local-client")
        .map(|w| w[1].clone());

    // --listen <addr>
    let listen_addr: Option<String> = args
        .windows(2)
        .find(|w| w[0] == "--listen")
        .map(|w| w[1].clone())
        .or_else(|| {
            cfg.interfaces
                .tcp_server
                .as_ref()
                .and_then(|s| s.listen.clone())
        });

    // --ifac-netname <name>
    let ifac_netname: Option<String> = args
        .windows(2)
        .find(|w| w[0] == "--ifac-netname")
        .map(|w| w[1].clone())
        .or_else(|| cfg.ifac.netname.clone());

    // --ifac-netkey <key>
    let ifac_netkey: Option<String> = args
        .windows(2)
        .find(|w| w[0] == "--ifac-netkey")
        .map(|w| w[1].clone())
        .or_else(|| cfg.ifac.netkey.clone());

    // --packet-log
    let packet_log =
        args.iter().any(|a| a == "--packet-log") || cfg.logging.packet_log.unwrap_or(false);
    if packet_log {
        eprintln!("[rete] packet logging enabled");
    }

    // --auto: enable AutoInterface
    let auto_enabled = args.iter().any(|a| a == "--auto")
        || cfg
            .interfaces
            .auto
            .as_ref()
            .and_then(|a| a.enabled)
            .unwrap_or(false);

    // --auto-group <group_id>
    let auto_group: Option<String> = args
        .windows(2)
        .find(|w| w[0] == "--auto-group")
        .map(|w| w[1].clone())
        .or_else(|| cfg.interfaces.auto.as_ref().and_then(|a| a.group.clone()));

    // Parse --monitoring <addr:port> (HTTP monitoring endpoint for health/metrics)
    let monitoring_addr: Option<String> = args
        .windows(2)
        .find(|w| w[0] == "--monitoring")
        .map(|w| w[1].clone());

    // Check IFAC is configured (derive will happen per-interface)
    let ifac_enabled = ifac_netname.is_some() || ifac_netkey.is_some();
    if ifac_enabled {
        // Validate that derivation works before proceeding
        rete_core::IfacKey::derive(ifac_netname.as_deref(), ifac_netkey.as_deref())
            .expect("failed to derive IFAC key");
        eprintln!(
            "[rete] IFAC enabled (netname={}, netkey={})",
            ifac_netname.as_deref().unwrap_or("<none>"),
            if ifac_netkey.is_some() {
                "<set>"
            } else {
                "<none>"
            },
        );
    }

    // Create or load identity
    let id_path = identity_file.unwrap_or_else(default_identity_path);
    let identity = load_or_create_identity(&id_path);

    let id_hash = identity.hash();
    eprintln!("[rete] identity hash: {}", hex::encode(id_hash));

    // Create node
    let mut node = TokioNode::new(identity, APP_NAME, ASPECTS);
    node.core.set_decompress_fn(Some(bz2_decompress));
    node.core.set_compress_fn(Some(bz2_compress));
    if packet_log {
        node.core.set_packet_log_fn(Some(log_packet));
    }

    // Load snapshot from previous run (if any)
    let mut snapshot_store = JsonFileStore::new(default_snapshot_path());
    match snapshot_store.load() {
        Ok(Some(snap)) => {
            let n_paths = snap.paths.len();
            let n_ids = snap.identities.len();
            node.core.load_snapshot(&snap);
            eprintln!("[rete] restored {n_paths} paths, {n_ids} identities from snapshot");
        }
        Ok(None) => {}
        Err(e) => {
            eprintln!("[rete] failed to load snapshot: {e:?}");
        }
    }

    if transport_mode {
        node.core.enable_transport();
        eprintln!("[rete] transport mode enabled");
    }

    // Auto-reply-ping: send ping on announce receipt
    if auto_reply_ping {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let msg = format!("ping:{ts}");
        eprintln!("[rete] auto-reply-ping: {msg}");
        node.core.set_auto_reply(Some(msg.into_bytes()));
    }

    if let Some(msg) = auto_reply {
        node.core.set_auto_reply(Some(msg.into_bytes()));
    }
    eprintln!(
        "[rete] destination hash: {}",
        hex::encode(node.core.dest_hash())
    );
    // Print to stdout for interop test discovery (many tests wait for this line).
    println!("IDENTITY:{}", hex::encode(node.core.dest_hash()));

    // Register /test/echo request handler for interop testing
    {
        let dh = *node.core.dest_hash();
        node.core.register_request_handler(
            &dh,
            RequestHandler {
                path: "/test/echo".into(),
                handler: |_path, data, _request_id, _link_id| Some(data.to_vec()),
                policy: RequestPolicy::AllowAll,
            },
        );
        eprintln!("[rete] registered /test/echo request handler");
    }

    // Register LXMF delivery destination
    let mut lxmf_router = LxmfRouter::register(&mut node.core);

    // Parse --lxmf-name <display_name>
    let lxmf_name = args
        .windows(2)
        .find(|w| w[0] == "--lxmf-name")
        .map(|w| w[1].clone());
    if let Some(name) = lxmf_name {
        lxmf_router.set_display_name(name.into_bytes());
    }

    eprintln!(
        "[rete] LXMF delivery hash: {}",
        hex::encode(lxmf_router.delivery_dest_hash())
    );

    // --propagation: enable LXMF propagation node (store-and-forward)
    let propagation_enabled = args.iter().any(|a| a == "--propagation");
    if propagation_enabled {
        lxmf_router.register_propagation(&mut node.core);
        eprintln!(
            "[rete] LXMF propagation hash: {}",
            hex::encode(lxmf_router.propagation_dest_hash().unwrap())
        );

        // Always queue propagation announce when propagation is enabled —
        // this is how other nodes discover our propagation capability.
        let mut rng = rand::thread_rng();
        let now = rete_tokio::current_time_secs();
        lxmf_router.queue_propagation_announce(&mut node.core, &mut rng, now);
        eprintln!("[rete] LXMF propagation announce queued");
    }

    // --lxmf-announce: queue LXMF delivery announce at startup.
    // Note: when propagation is enabled, the propagation announce is already
    // queued above. Due to rnsd dedup (only one announce per identity relayed
    // per cycle), we skip the delivery announce when propagation is active —
    // it will be sent on the next 300s announce timer tick.
    let lxmf_announce = args.iter().any(|a| a == "--lxmf-announce");
    if lxmf_announce && !propagation_enabled {
        let mut rng = rand::thread_rng();
        let now = rete_tokio::current_time_secs();
        lxmf_router.queue_delivery_announce(&mut node.core, &mut rng, now);
        eprintln!("[rete] LXMF delivery announce queued");
    }

    // --autopeer: enable auto-peering with propagation nodes
    let autopeer_enabled = args.iter().any(|a| a == "--autopeer");
    if autopeer_enabled {
        lxmf_router.set_autopeer(true, 4);
        eprintln!("[rete] auto-peering enabled (maxdepth=4)");
    }

    // Wrap lxmf_router and snapshot_store in RefCell for interior mutability
    // (needed for propagation deposit in event handler + command handler access).
    let lxmf_router = RefCell::new(lxmf_router);
    let snapshot_store = RefCell::new(snapshot_store);

    // Create command channel + stdin reader
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel::<NodeCommand>(64);
    spawn_signal_handler(cmd_tx.clone());
    spawn_stdin_reader(cmd_tx);

    // Create watch channel for stats (used by monitoring endpoint)
    let (stats_tx, stats_rx) = tokio::sync::watch::channel::<Option<rete_stack::NodeStats>>(None);

    // Start HTTP monitoring server if requested
    if let Some(ref addr) = monitoring_addr {
        let addr = addr
            .parse::<std::net::SocketAddr>()
            .expect("invalid monitoring address");
        let rx = stats_rx.clone();
        tokio::spawn(async move {
            run_monitoring_server(addr, rx).await;
        });
        eprintln!("[rete] monitoring endpoint on http://{}", addr);
    }

    // Dispatch based on interface type
    if auto_enabled
        && addrs.is_empty()
        && serial_path.is_none()
        && local_client_name.is_none()
        && local_server_name.is_none()
    {
        // AutoInterface-only mode (single interface)
        let mut config = AutoInterfaceConfig::default();
        if let Some(ref gid) = auto_group {
            config.group_id = gid.as_bytes().to_vec();
        }
        eprintln!(
            "[rete] starting AutoInterface (group={}) ...",
            String::from_utf8_lossy(&config.group_id)
        );
        let mut iface = match AutoInterface::new(config).await {
            Ok(i) => i,
            Err(e) => {
                eprintln!("[rete] failed to start AutoInterface: {e}");
                std::process::exit(1);
            }
        };
        for info in iface.interfaces() {
            eprintln!(
                "[rete]   interface: {} (index {}, addr {})",
                info.name, info.index, info.link_local
            );
        }
        eprintln!("[rete] AutoInterface ready, discovering peers ...");
        node.run_with_app_handler(
            &mut iface,
            cmd_rx,
            |e, core, rng| on_event(e, &lxmf_router, &snapshot_store, &stats_tx, core, rng),
            |cmd, core, rng| handle_lxmf_command(cmd, core, &lxmf_router, rng),
            rand::thread_rng(),
        )
        .await;
    } else if let Some(ref client_name) = local_client_name {
        // Local client mode: connect to a shared instance server via Unix socket.
        // Uses ReconnectingLocalClient for automatic reconnection with backoff.
        eprintln!("[rete] connecting to local instance '{}' ...", client_name);
        let mut iface = ReconnectingLocalClient::new(client_name.clone());
        eprintln!("[rete] local client ready for instance '{}'", client_name);
        node.run_with_app_handler(
            &mut iface,
            cmd_rx,
            |e, core, rng| on_event(e, &lxmf_router, &snapshot_store, &stats_tx, core, rng),
            |cmd, core, rng| handle_lxmf_command(cmd, core, &lxmf_router, rng),
            rand::thread_rng(),
        )
        .await;
    } else if let Some(path) = serial_path
        .as_deref()
        .filter(|_| addrs.is_empty() && local_server_name.is_none())
    {
        eprintln!("[rete] opening serial port {} at {} baud ...", path, baud);
        let mut iface = match SerialInterface::open(path, baud) {
            Ok(i) => i,
            Err(e) => {
                eprintln!("[rete] failed to open serial port: {e}");
                std::process::exit(1);
            }
        };
        eprintln!("[rete] serial port open");
        node.run_with_app_handler(
            &mut iface,
            cmd_rx,
            |e, core, rng| on_event(e, &lxmf_router, &snapshot_store, &stats_tx, core, rng),
            |cmd, core, rng| handle_lxmf_command(cmd, core, &lxmf_router, rng),
            rand::thread_rng(),
        )
        .await;
    } else if local_server_name.is_some()
        || listen_addr.is_some()
        || addrs.len() > 1
        || (auto_enabled && !addrs.is_empty())
        || (serial_path.is_some() && !addrs.is_empty())
    {
        // Multi-interface mode: TCP endpoints + optional servers + optional AutoInterface.
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel::<InboundMsg>(256);
        let mut slots: Vec<InterfaceSlot> = Vec::new();
        let mut next_iface_idx: u8 = 0;

        // Connect TCP interfaces
        for addr in &addrs {
            let idx = next_iface_idx;
            next_iface_idx += 1;
            eprintln!("[rete] connecting to {} (iface {}) ...", addr, idx);
            let mut iface = match TcpInterface::connect(addr).await {
                Ok(i) => i,
                Err(e) => {
                    eprintln!("[rete] failed to connect to {}: {e}", addr);
                    std::process::exit(1);
                }
            };
            if ifac_enabled {
                let key =
                    rete_core::IfacKey::derive(ifac_netname.as_deref(), ifac_netkey.as_deref())
                        .unwrap();
                iface.set_ifac(key);
            }
            eprintln!("[rete] connected to {} (iface {})", addr, idx);
            let (tx, driver) = interface_task(iface, idx, inbound_tx.clone());
            slots.push(InterfaceSlot::Direct(tx));
            tokio::spawn(driver);
        }

        // Start AutoInterface (if configured in multi-interface mode)
        if auto_enabled {
            let auto_idx = next_iface_idx;
            next_iface_idx += 1;
            let mut config = AutoInterfaceConfig::default();
            if let Some(ref gid) = auto_group {
                config.group_id = gid.as_bytes().to_vec();
            }
            eprintln!(
                "[rete] starting AutoInterface (iface {}, group={}) ...",
                auto_idx,
                String::from_utf8_lossy(&config.group_id)
            );
            match AutoInterface::new(config).await {
                Ok(iface) => {
                    for info in iface.interfaces() {
                        eprintln!(
                            "[rete]   auto interface: {} (index {}, addr {})",
                            info.name, info.index, info.link_local
                        );
                    }
                    let (tx, driver) = interface_task(iface, auto_idx, inbound_tx.clone());
                    slots.push(InterfaceSlot::Direct(tx));
                    tokio::spawn(driver);
                    eprintln!("[rete] AutoInterface ready (iface {})", auto_idx);
                }
                Err(e) => {
                    eprintln!("[rete] failed to start AutoInterface: {e}");
                    std::process::exit(1);
                }
            }
        }

        // Add serial interface (if configured in multi-interface mode)
        if let Some(ref path) = serial_path {
            let serial_idx = next_iface_idx;
            next_iface_idx += 1;
            eprintln!(
                "[rete] opening serial port {} (iface {}) ...",
                path, serial_idx
            );
            let iface = match SerialInterface::open(path, baud) {
                Ok(i) => i,
                Err(e) => {
                    eprintln!("[rete] failed to open serial port: {e}");
                    std::process::exit(1);
                }
            };
            let (tx, driver) = interface_task(iface, serial_idx, inbound_tx.clone());
            slots.push(InterfaceSlot::Direct(tx));
            tokio::spawn(driver);
            eprintln!("[rete] serial port open (iface {})", serial_idx);
        }

        // Start local server (if configured)
        if let Some(ref server_name) = local_server_name {
            let local_iface_idx = next_iface_idx;
            next_iface_idx += 1;
            eprintln!(
                "[rete] starting local server '{}' (iface {}) ...",
                server_name, local_iface_idx
            );
            match LocalServer::bind(server_name, inbound_tx.clone(), local_iface_idx) {
                Ok(server) => {
                    let broadcaster = server.broadcaster();
                    tokio::spawn(server.run());
                    slots.push(InterfaceSlot::Hub(broadcaster));
                    eprintln!(
                        "[rete] local server '{}' listening on \\0rns/{}",
                        server_name, server_name
                    );
                }
                Err(e) => {
                    eprintln!("[rete] failed to start local server: {e}");
                    std::process::exit(1);
                }
            }
        }

        // Start TCP server (if configured)
        if let Some(ref addr) = listen_addr {
            let tcp_server_idx = next_iface_idx;
            next_iface_idx += 1;

            let ifac = if ifac_enabled {
                Some(
                    rete_core::IfacKey::derive(ifac_netname.as_deref(), ifac_netkey.as_deref())
                        .unwrap(),
                )
            } else {
                None
            };

            match TcpServer::bind(
                addr,
                inbound_tx.clone(),
                tcp_server_idx,
                ifac,
                Default::default(),
            )
            .await
            {
                Ok(server) => {
                    let broadcaster = server.broadcaster();
                    tokio::spawn(server.run());
                    slots.push(InterfaceSlot::Hub(broadcaster));
                    eprintln!(
                        "[rete] TCP server listening on {} (iface {})",
                        addr, tcp_server_idx
                    );
                }
                Err(e) => {
                    eprintln!("[rete] failed to bind TCP server on {}: {e}", addr);
                    std::process::exit(1);
                }
            }
        }

        // Suppress unused variable warning
        let _ = next_iface_idx;

        // Drop the original inbound_tx so the channel closes when all tasks exit
        drop(inbound_tx);

        node.run_multi_with_commands(slots, inbound_rx, cmd_rx, |e, core, rng| {
            on_event(e, &lxmf_router, &snapshot_store, &stats_tx, core, rng)
        })
        .await;
    } else {
        let addr = addrs.first().map(|s| s.as_str()).unwrap_or(DEFAULT_ADDR);
        eprintln!("[rete] connecting to {} ...", addr);
        let mut iface = match TcpInterface::connect(addr).await {
            Ok(i) => i,
            Err(e) => {
                eprintln!("[rete] failed to connect: {e}");
                std::process::exit(1);
            }
        };
        if ifac_enabled {
            let key = rete_core::IfacKey::derive(ifac_netname.as_deref(), ifac_netkey.as_deref())
                .unwrap();
            iface.set_ifac(key);
        }
        eprintln!("[rete] connected");
        node.run_with_app_handler(
            &mut iface,
            cmd_rx,
            |e, core, rng| on_event(e, &lxmf_router, &snapshot_store, &stats_tx, core, rng),
            |cmd, core, rng| handle_lxmf_command(cmd, core, &lxmf_router, rng),
            rand::thread_rng(),
        )
        .await;
    }

    // Final snapshot save on shutdown
    {
        let snap = node
            .core
            .save_snapshot(rete_transport::SnapshotDetail::Standard);
        if let Err(e) = snapshot_store.borrow_mut().save(&snap) {
            eprintln!("[rete] failed to save final snapshot: {e:?}");
        } else {
            eprintln!(
                "[rete] final snapshot saved ({} paths, {} identities)",
                snap.paths.len(),
                snap.identities.len()
            );
        }
    }
    println!("SHUTDOWN_COMPLETE");
    // Flush stdout before exiting so piped readers see the marker.
    use std::io::Write;
    std::io::stdout().flush().ok();
    // Force exit to avoid blocking on the stdin reader thread, which
    // cannot be interrupted on Unix (blocking read on stdin).
    std::process::exit(0);
}

// ---------------------------------------------------------------------------
// HTTP monitoring server
// ---------------------------------------------------------------------------

async fn run_monitoring_server(
    addr: std::net::SocketAddr,
    stats_rx: tokio::sync::watch::Receiver<Option<rete_stack::NodeStats>>,
) {
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[rete] monitoring: failed to bind {addr}: {e}");
            return;
        }
    };
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => continue,
        };
        let rx = stats_rx.clone();
        tokio::spawn(async move {
            handle_monitoring_connection(stream, rx).await;
        });
    }
}

async fn handle_monitoring_connection(
    stream: tokio::net::TcpStream,
    stats_rx: tokio::sync::watch::Receiver<Option<rete_stack::NodeStats>>,
) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut request_line = String::new();

    // Read the first line of the HTTP request
    if buf_reader.read_line(&mut request_line).await.is_err() {
        return;
    }

    // Parse path from "GET /path HTTP/1.x"
    let path = request_line.split_whitespace().nth(1).unwrap_or("/");

    // Drain remaining headers (read until empty line)
    let mut hdr_buf = String::with_capacity(256);
    loop {
        hdr_buf.clear();
        match buf_reader.read_line(&mut hdr_buf).await {
            Ok(0) => break,
            Ok(_) if hdr_buf.trim().is_empty() => break,
            Err(_) => break,
            _ => continue,
        }
    }

    let (status, content_type, body) = match path {
        "/health" => (
            "200 OK",
            "application/json",
            r#"{"status":"ok"}"#.to_string(),
        ),
        "/stats" => {
            let stats = stats_rx.borrow().clone();
            match stats {
                Some(s) => match serde_json::to_string(&s) {
                    Ok(json) => ("200 OK", "application/json", json),
                    Err(_) => (
                        "500 Internal Server Error",
                        "text/plain",
                        "serialization error".to_string(),
                    ),
                },
                None => (
                    "503 Service Unavailable",
                    "application/json",
                    r#"{"error":"stats not yet available"}"#.to_string(),
                ),
            }
        }
        "/metrics" => {
            let stats = stats_rx.borrow().clone();
            match stats {
                Some(s) => (
                    "200 OK",
                    "text/plain; version=0.0.4; charset=utf-8",
                    format_prometheus(&s),
                ),
                None => (
                    "503 Service Unavailable",
                    "text/plain",
                    "# stats not yet available\n".to_string(),
                ),
            }
        }
        _ => ("404 Not Found", "text/plain", "not found\n".to_string()),
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = writer.write_all(response.as_bytes()).await;
    let _ = writer.shutdown().await;
}

fn format_prometheus(stats: &rete_stack::NodeStats) -> String {
    use std::fmt::Write;
    let t = &stats.transport;
    let mut s = String::with_capacity(2048);

    s.push_str("# HELP rete_node_info Node identification\n# TYPE rete_node_info gauge\n");
    let _ = writeln!(
        s,
        "rete_node_info{{identity_hash=\"{}\"}} 1",
        stats.identity_hash
    );

    s.push_str("# HELP rete_uptime_seconds Seconds since the node started\n# TYPE rete_uptime_seconds gauge\n");
    let _ = writeln!(s, "rete_uptime_seconds {}", stats.uptime_secs);

    macro_rules! prom_counter {
        ($field:ident, $help:expr) => {
            let _ = write!(
                s,
                "# HELP rete_{}_total {}\n# TYPE rete_{}_total counter\nrete_{}_total {}\n",
                stringify!($field),
                $help,
                stringify!($field),
                stringify!($field),
                t.$field
            );
        };
    }

    prom_counter!(packets_received, "Total packets received");
    prom_counter!(packets_sent, "Total packets sent");
    prom_counter!(packets_forwarded, "Packets forwarded for other nodes");
    prom_counter!(packets_dropped_dedup, "Packets dropped as duplicates");
    prom_counter!(packets_dropped_invalid, "Packets dropped as invalid");
    prom_counter!(announces_received, "Valid announces received");
    prom_counter!(announces_sent, "Announces sent");
    prom_counter!(announces_retransmitted, "Announce retransmissions");
    prom_counter!(
        announces_rate_limited,
        "Announces suppressed by rate limiter"
    );
    prom_counter!(links_established, "Links established");
    prom_counter!(links_closed, "Links closed");
    prom_counter!(links_failed, "Link handshake failures");
    prom_counter!(link_requests_received, "Link requests received");
    prom_counter!(paths_learned, "Paths learned or updated");
    prom_counter!(paths_expired, "Paths expired and removed");
    prom_counter!(crypto_failures, "Cryptographic failures");

    s.push_str("# HELP rete_started_at_seconds Unix timestamp of first activity\n# TYPE rete_started_at_seconds gauge\n");
    let _ = writeln!(s, "rete_started_at_seconds {}", t.started_at);

    s
}

fn on_event(
    event: NodeEvent,
    lxmf_router: &RefCell<LxmfRouter>,
    snapshot_store: &RefCell<JsonFileStore>,
    stats_tx: &tokio::sync::watch::Sender<Option<rete_stack::NodeStats>>,
    core: &mut rete_stack::HostedNodeCore,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> Vec<OutboundPacket> {
    // Handle propagation pruning + periodic snapshot on tick events
    if let NodeEvent::Tick { .. } = &event {
        let now = rete_tokio::current_time_secs();
        let pruned = lxmf_router
            .borrow_mut()
            .prune_propagation(now, PROPAGATION_TTL_SECS);
        if pruned > 0 {
            eprintln!("[rete] propagation: pruned {pruned} expired messages");
        }

        // Save snapshot every ~5 minutes (60 ticks × 5s interval)
        use std::sync::atomic::{AtomicU64, Ordering};
        static TICK_COUNT: AtomicU64 = AtomicU64::new(0);
        let ticks = TICK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        if ticks.is_multiple_of(60) && core.path_count() > 0 {
            let snap = core.save_snapshot(rete_transport::SnapshotDetail::Standard);
            if let Err(e) = snapshot_store.borrow_mut().save(&snap) {
                eprintln!("[rete] failed to save snapshot: {e:?}");
            } else {
                eprintln!(
                    "[rete] snapshot saved: {} paths, {} identities",
                    snap.paths.len(),
                    snap.identities.len()
                );
            }
        }

        // Publish stats for monitoring endpoint (only if someone is listening)
        if stats_tx.receiver_count() > 0 {
            let stats = core.stats(now);
            let _ = stats_tx.send(Some(stats));
        }

        // Check peer syncs
        let sync_pkts = lxmf_router
            .borrow_mut()
            .check_peer_syncs(core, rng, now);
        if !sync_pkts.is_empty() {
            eprintln!("[rete] peer sync: initiated {} link(s)", sync_pkts.len());
            return sync_pkts;
        }
    }

    // Use mutable handler — handles propagation deposit when enabled,
    // falls through to immutable handler otherwise.
    let now = rete_tokio::current_time_secs();
    let lxmf_event = lxmf_router.borrow_mut().handle_event_mut(event, now);
    match lxmf_event {
        LxmfEvent::MessageReceived { message, method } => {
            let source = hex::encode(message.source_hash);
            let title = String::from_utf8_lossy(&message.title);
            let content = String::from_utf8_lossy(&message.content);
            eprintln!(
                "[rete] LXMF_RECEIVED from={} method={:?} title=\"{}\" content=\"{}\"",
                source, method, title, content,
            );
            println!("LXMF_RECEIVED:{}:{}:{}", source, title, content);
        }
        LxmfEvent::PeerAnnounced {
            dest_hash,
            display_name,
        } => {
            let name = display_name
                .as_deref()
                .map(|n| String::from_utf8_lossy(n).to_string())
                .unwrap_or_default();
            eprintln!(
                "[rete] LXMF_PEER dest={} name=\"{}\"",
                hex::encode(dest_hash),
                name,
            );
            println!("LXMF_PEER:{}:{}", hex::encode(dest_hash), name);
        }
        LxmfEvent::PropagationDeposit {
            dest_hash,
            message_hash,
        } => {
            eprintln!(
                "[rete] PROP_DEPOSIT dest={} msg={}",
                hex::encode(dest_hash),
                hex::encode(message_hash),
            );
            println!(
                "PROP_DEPOSIT:{}:{}",
                hex::encode(dest_hash),
                hex::encode(message_hash),
            );
        }
        LxmfEvent::PropagationRetrievalRequest {
            link_id,
            request_id,
            dest_hash,
            result,
        } => {
            let count = result.messages.len();
            eprintln!(
                "[rete] PROP_RETRIEVAL_REQUEST link={} dest={} count={}",
                hex::encode(link_id),
                hex::encode(dest_hash),
                count,
            );
            println!(
                "PROP_RETRIEVAL_REQUEST:{}:{}:{}",
                hex::encode(link_id),
                hex::encode(dest_hash),
                count,
            );

            let mut packets = Vec::new();

            // Send the response (count of messages)
            if let Ok(resp_pkt) =
                core.send_response(&link_id, &request_id, &result.response_data, rng)
            {
                packets.push(resp_pkt);
            }

            // Start sending messages as Resources via retrieval job
            if !result.messages.is_empty() {
                let msgs = result.messages;
                let retrieval_pkts = lxmf_router
                    .borrow_mut()
                    .start_retrieval_send(&link_id, msgs, core, rng);
                packets.extend(retrieval_pkts);
            }

            return packets;
        }
        LxmfEvent::PropagationForward { dest_hash, count } => {
            eprintln!(
                "[rete] PROP_FORWARD dest={} count={}",
                hex::encode(dest_hash),
                count,
            );
            println!("PROP_FORWARD:{}:{}", hex::encode(dest_hash), count);

            // Auto-forward: initiate a link to the destination
            let mut router = lxmf_router.borrow_mut();
            if !router.has_forward_job_for(&dest_hash) {
                let now = rete_tokio::current_time_secs();
                if let Some((pkt, link_id)) =
                    router.start_propagation_forward(&dest_hash, core, rng, now)
                {
                    eprintln!(
                        "[rete] PROP_FORWARD_LINK dest={} link={}",
                        hex::encode(dest_hash),
                        hex::encode(link_id),
                    );
                    println!(
                        "PROP_FORWARD_LINK:{}:{}",
                        hex::encode(dest_hash),
                        hex::encode(link_id),
                    );
                    return vec![pkt];
                } else {
                    eprintln!(
                        "[rete] PROP_FORWARD_FAIL dest={} (no path or no messages)",
                        hex::encode(dest_hash),
                    );
                }
            }
        }
        LxmfEvent::PeerDiscovered {
            dest_hash,
            identity_hash,
        } => {
            eprintln!(
                "[rete] PEER_DISCOVERED dest={} identity={}",
                hex::encode(dest_hash),
                hex::encode(identity_hash),
            );
            println!(
                "PEER_DISCOVERED:{}:{}",
                hex::encode(dest_hash),
                hex::encode(identity_hash),
            );
        }
        LxmfEvent::PeerSyncComplete {
            dest_hash,
            messages_sent,
        } => {
            eprintln!(
                "[rete] PEER_SYNC_COMPLETE dest={} sent={}",
                hex::encode(dest_hash),
                messages_sent,
            );
            println!(
                "PEER_SYNC_COMPLETE:{}:{}",
                hex::encode(dest_hash),
                messages_sent,
            );
        }
        LxmfEvent::PeerOfferReceived {
            link_id,
            request_id,
            response_data,
        } => {
            eprintln!(
                "[rete] PEER_OFFER_RECEIVED link={} response_len={}",
                hex::encode(link_id),
                response_data.len(),
            );
            println!("PEER_OFFER_RECEIVED:{}", hex::encode(link_id));

            // Send the response back
            if let Ok(pkt) = core.send_response(&link_id, &request_id, &response_data, rng) {
                return vec![pkt];
            }
        }
        LxmfEvent::Other(event) => {
            // Check if this is a link event that advances a forward or sync job
            match &event {
                NodeEvent::LinkEstablished { link_id } => {
                    // Try forward jobs
                    let pkts = lxmf_router
                        .borrow_mut()
                        .advance_forward_on_link_established(link_id, core, rng);
                    if !pkts.is_empty() {
                        eprintln!(
                            "[rete] PROP_FORWARD_SENDING link={} pkts={}",
                            hex::encode(link_id),
                            pkts.len(),
                        );
                        println!("PROP_FORWARD_SENDING:{}", hex::encode(link_id));
                        on_node_event(event);
                        return pkts;
                    }

                    // Try sync jobs
                    let pkts = lxmf_router
                        .borrow_mut()
                        .advance_sync_on_link_established(link_id, core, rng, rete_tokio::current_time_secs());
                    if !pkts.is_empty() {
                        eprintln!(
                            "[rete] PEER_SYNC_IDENTIFYING link={}",
                            hex::encode(link_id),
                        );
                        on_node_event(event);
                        return pkts;
                    }
                }
                NodeEvent::ResponseReceived {
                    link_id, ref data, ..
                } => {
                    // Advance sync job on offer response
                    let now = rete_tokio::current_time_secs();
                    let pkts = lxmf_router
                        .borrow_mut()
                        .advance_sync_on_response(link_id, data, core, rng, now);
                    if !pkts.is_empty() {
                        eprintln!(
                            "[rete] PEER_SYNC_TRANSFERRING link={}",
                            hex::encode(link_id),
                        );
                        on_node_event(event);
                        return pkts;
                    }
                }
                NodeEvent::ResourceComplete {
                    link_id,
                    resource_hash,
                    ref data,
                } => {
                    // Try advancing forward jobs first
                    let pkts = lxmf_router
                        .borrow_mut()
                        .advance_forward_on_resource_complete(link_id, resource_hash, core, rng);
                    if !pkts.is_empty() {
                        on_node_event(event);
                        return pkts;
                    }

                    // Try advancing retrieval jobs
                    let pkts = lxmf_router
                        .borrow_mut()
                        .advance_retrieval_on_resource_complete(link_id, resource_hash, core, rng);
                    if !pkts.is_empty() {
                        eprintln!(
                            "[rete] PROP_RETRIEVAL_SENDING link={} pkts={}",
                            hex::encode(link_id),
                            pkts.len(),
                        );
                        println!("PROP_RETRIEVAL_SENDING:{}", hex::encode(link_id));
                        on_node_event(event);
                        return pkts;
                    }

                    // Try advancing sync jobs (outbound)
                    let now = rete_tokio::current_time_secs();
                    let (pkts, sync_event) = lxmf_router
                        .borrow_mut()
                        .advance_sync_on_resource_complete(link_id, core, rng, now);
                    if let Some(evt) = sync_event {
                        match &evt {
                            LxmfEvent::PeerSyncComplete {
                                dest_hash,
                                messages_sent,
                            } => {
                                eprintln!(
                                    "[rete] PEER_SYNC_COMPLETE dest={} sent={}",
                                    hex::encode(dest_hash),
                                    messages_sent,
                                );
                                println!(
                                    "PEER_SYNC_COMPLETE:{}:{}",
                                    hex::encode(dest_hash),
                                    messages_sent,
                                );
                            }
                            _ => {}
                        }
                        on_node_event(event);
                        return pkts;
                    }

                    // Try depositing as inbound sync resource
                    if lxmf_router.borrow().has_sync_job_for_link(link_id) {
                        let deposited = lxmf_router
                            .borrow_mut()
                            .deposit_sync_resource(data, now);
                        if !deposited.is_empty() {
                            for (dest, hash) in &deposited {
                                eprintln!(
                                    "[rete] PEER_SYNC_DEPOSIT dest={} msg={}",
                                    hex::encode(dest),
                                    hex::encode(hash),
                                );
                                println!(
                                    "PEER_SYNC_DEPOSIT:{}:{}",
                                    hex::encode(dest),
                                    hex::encode(hash),
                                );
                            }
                            on_node_event(event);
                            return Vec::new();
                        }
                    }
                }
                NodeEvent::LinkClosed { link_id } => {
                    lxmf_router
                        .borrow_mut()
                        .cleanup_forward_jobs_for_link(link_id);
                    lxmf_router
                        .borrow_mut()
                        .cleanup_sync_jobs_for_link(link_id);
                }
                _ => {}
            }
            // Fall through to normal event handling
            on_node_event(event);
        }
    }
    // Flush stdout so piped readers see LXMF output immediately.
    use std::io::Write;
    std::io::stdout().flush().ok();
    Vec::new()
}

fn on_node_event(event: NodeEvent) {
    match event {
        NodeEvent::AnnounceReceived {
            dest_hash,
            identity_hash,
            hops,
            app_data,
        } => {
            eprintln!(
                "[rete] ANNOUNCE dest={} identity={} hops={}{}",
                hex::encode(dest_hash),
                hex::encode(identity_hash),
                hops,
                app_data
                    .as_ref()
                    .map(|d| {
                        match std::str::from_utf8(d) {
                            Ok(s) => format!(" app_data=\"{s}\""),
                            Err(_) => format!(" app_data={}", hex::encode(d)),
                        }
                    })
                    .unwrap_or_default(),
            );
            if let Some(ref ad) = app_data {
                println!(
                    "ANNOUNCE:{}:{}:{}:{}",
                    hex::encode(dest_hash),
                    hex::encode(identity_hash),
                    hops,
                    hex::encode(ad),
                );
            } else {
                println!(
                    "ANNOUNCE:{}:{}:{}",
                    hex::encode(dest_hash),
                    hex::encode(identity_hash),
                    hops,
                );
            }
        }
        NodeEvent::DataReceived { dest_hash, payload } => {
            eprintln!(
                "[rete] DATA dest={} len={}",
                hex::encode(dest_hash),
                payload.len(),
            );
            match std::str::from_utf8(&payload) {
                Ok(text) => {
                    eprintln!("[rete]   text: {text}");
                    println!("DATA:{}:{}", hex::encode(dest_hash), text);
                }
                Err(_) => {
                    eprintln!("[rete]   hex: {}", hex::encode(&payload));
                    println!("DATA:{}:{}", hex::encode(dest_hash), hex::encode(&payload));
                }
            }
        }
        NodeEvent::ProofReceived { packet_hash } => {
            eprintln!(
                "[rete] PROOF received for packet {}",
                hex::encode(packet_hash),
            );
            println!("PROOF_RECEIVED:{}", hex::encode(packet_hash));
        }
        NodeEvent::LinkEstablished { link_id } => {
            eprintln!("[rete] LINK established: {}", hex::encode(link_id));
            println!("LINK_ESTABLISHED:{}", hex::encode(link_id));
        }
        NodeEvent::LinkData {
            link_id,
            data,
            context,
        } => {
            eprintln!(
                "[rete] LINK_DATA link={} ctx={:#04x} len={}",
                hex::encode(link_id),
                context,
                data.len(),
            );
            match std::str::from_utf8(&data) {
                Ok(text) => println!("LINK_DATA:{}:{}", hex::encode(link_id), text),
                Err(_) => println!("LINK_DATA:{}:{}", hex::encode(link_id), hex::encode(&data)),
            }
        }
        NodeEvent::ChannelMessages { link_id, messages } => {
            eprintln!(
                "[rete] CHANNEL messages on {}: {} msgs",
                hex::encode(link_id),
                messages.len()
            );
            for (msg_type, payload) in &messages {
                eprintln!("  type=0x{:04x} len={}", msg_type, payload.len());
                match std::str::from_utf8(payload) {
                    Ok(text) => println!(
                        "CHANNEL_MSG:{}:{:#06x}:{}",
                        hex::encode(link_id),
                        msg_type,
                        text
                    ),
                    Err(_) => println!(
                        "CHANNEL_MSG:{}:{:#06x}:{}",
                        hex::encode(link_id),
                        msg_type,
                        hex::encode(payload)
                    ),
                }
            }
        }
        NodeEvent::RequestReceived {
            link_id,
            request_id,
            path_hash,
            data,
        } => {
            eprintln!(
                "[rete] REQUEST on link={} req_id={} path_hash={} data_len={}",
                hex::encode(link_id),
                hex::encode(request_id),
                hex::encode(path_hash),
                data.len()
            );
            println!(
                "REQUEST_RECEIVED:{}:{}:{}:{}",
                hex::encode(link_id),
                hex::encode(request_id),
                hex::encode(path_hash),
                data.len()
            );
        }
        NodeEvent::ResponseReceived {
            link_id,
            request_id,
            data,
        } => {
            eprintln!(
                "[rete] RESPONSE on link={} req_id={} data_len={}",
                hex::encode(link_id),
                hex::encode(request_id),
                data.len()
            );
            println!(
                "RESPONSE_RECEIVED:{}:{}:{}",
                hex::encode(link_id),
                hex::encode(request_id),
                data.len()
            );
        }
        NodeEvent::LinkClosed { link_id } => {
            eprintln!("[rete] LINK closed: {}", hex::encode(link_id));
            println!("LINK_CLOSED:{}", hex::encode(link_id));
        }
        NodeEvent::ResourceOffered {
            link_id,
            resource_hash,
            total_size,
        } => {
            eprintln!(
                "[rete] RESOURCE offered on link={} hash={} size={}",
                hex::encode(link_id),
                hex::encode(resource_hash),
                total_size
            );
            println!(
                "RESOURCE_OFFERED:{}:{}:{}",
                hex::encode(link_id),
                hex::encode(resource_hash),
                total_size
            );
            // Debug: log how many outbound packets the ingest generated
            eprintln!("[rete] RESOURCE_OFFERED event processed");
        }
        NodeEvent::ResourceProgress {
            link_id,
            resource_hash,
            current,
            total,
        } => {
            eprintln!(
                "[rete] RESOURCE progress on link={} hash={} {}/{}",
                hex::encode(link_id),
                hex::encode(resource_hash),
                current,
                total
            );
        }
        NodeEvent::ResourceComplete {
            link_id,
            resource_hash,
            ref data,
        } => {
            let display = match std::str::from_utf8(data) {
                Ok(text) => text.to_string(),
                Err(_) => hex::encode(data),
            };
            eprintln!(
                "[rete] RESOURCE complete on link={} hash={} len={}",
                hex::encode(link_id),
                hex::encode(resource_hash),
                data.len()
            );
            println!(
                "RESOURCE_COMPLETE:{}:{}:{}",
                hex::encode(link_id),
                hex::encode(resource_hash),
                display
            );
        }
        NodeEvent::ResourceFailed {
            link_id,
            resource_hash,
        } => {
            eprintln!(
                "[rete] RESOURCE failed on link={} hash={}",
                hex::encode(link_id),
                hex::encode(resource_hash)
            );
            println!(
                "RESOURCE_FAILED:{}:{}",
                hex::encode(link_id),
                hex::encode(resource_hash)
            );
        }
        NodeEvent::Tick { expired_paths, .. } => {
            if expired_paths > 0 {
                eprintln!("[rete] tick: expired {expired_paths} paths");
            }
        }
        NodeEvent::LinkIdentified {
            link_id,
            identity_hash,
            ..
        } => {
            eprintln!(
                "[rete] link {} identified: peer {}",
                hex::encode(&link_id[..4]),
                hex::encode(&identity_hash[..4])
            );
        }
    }
    // Flush stdout so piped readers (test harnesses) see output immediately.
    use std::io::Write;
    std::io::stdout().flush().ok();
}

fn handle_lxmf_command(
    cmd: NodeCommand,
    core: &mut rete_stack::HostedNodeCore,
    lxmf_router: &RefCell<LxmfRouter>,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> Option<Vec<OutboundPacket>> {
    let NodeCommand::AppCommand {
        name,
        dest_hash,
        link_id: _,
        payload,
    } = cmd
    else {
        return None;
    };

    match name.as_str() {
        "stats" => {
            let now = rete_tokio::current_time_secs();
            let stats = core.stats(now);
            match serde_json::to_string(&stats) {
                Ok(json) => {
                    println!("STATS:{json}");
                    use std::io::Write as _;
                    std::io::stdout().flush().ok();
                }
                Err(e) => eprintln!("[rete] stats: serialize error: {e}"),
            }
            None
        }
        "lxmf-send" => {
            let Some(dest_hash) = dest_hash else {
                eprintln!("[rete] lxmf-send: missing dest_hash");
                return None;
            };
            let now_secs = rete_tokio::current_time_secs();
            let router = lxmf_router.borrow();
            let source_hash = *router.delivery_dest_hash();
            let msg = match LXMessage::new(
                dest_hash,
                source_hash,
                core.identity(),
                b"",
                &payload,
                std::collections::BTreeMap::new(),
                now_secs as f64,
            ) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("[rete] lxmf-send: failed to create message: {e}");
                    return None;
                }
            };

            match router.send_opportunistic(core, &msg, rng, now_secs) {
                Some(pkt) => {
                    eprintln!("[rete] LXMF sent to {}", hex::encode(dest_hash));
                    println!("LXMF_SENT:{}", hex::encode(dest_hash));
                    Some(vec![pkt])
                }
                None => {
                    eprintln!(
                        "[rete] lxmf-send: failed to send (unknown dest {})",
                        hex::encode(dest_hash)
                    );
                    None
                }
            }
        }
        "lxmf-announce" => {
            let now = rete_tokio::current_time_secs();
            let router = lxmf_router.borrow();
            router.queue_delivery_announce(core, rng, now);
            router.queue_propagation_announce(core, rng, now);
            let announces = core.flush_announces(now, rng);
            eprintln!("[rete] LXMF delivery announce sent");
            Some(announces)
        }
        "lxmf-prop-announce" => {
            let now = rete_tokio::current_time_secs();
            let router = lxmf_router.borrow();
            if router.queue_propagation_announce(core, rng, now) {
                let announces = core.flush_announces(now, rng);
                eprintln!("[rete] LXMF propagation announce sent");
                Some(announces)
            } else {
                eprintln!("[rete] propagation not enabled");
                None
            }
        }
        _ => {
            eprintln!("[rete] unknown app command: {name}");
            None
        }
    }
}
