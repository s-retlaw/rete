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

use rete_core::Identity;
use rete_iface_auto::{AutoInterface, AutoInterfaceConfig};
use rete_iface_serial::SerialInterface;
use rete_iface_tcp::TcpInterface;
use rete_lxmf::{LXMessage, LxmfEvent, LxmfRouter};
use rete_stack::{OutboundPacket, RequestHandler, RequestPolicy};
use rete_tokio::local::{LocalServer, ReconnectingLocalClient};
use rete_tokio::{interface_task, InboundMsg, NodeCommand, NodeEvent, TokioNode};

use std::cell::RefCell;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_ADDR: &str = "127.0.0.1:4242";
const DEFAULT_BAUD: u32 = 115200;
const APP_NAME: &str = "rete";
const ASPECTS: &[&str] = &["example", "v1"];
/// Default propagation message TTL: 30 days in seconds.
const PROPAGATION_TTL_SECS: u64 = 2_592_000;

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

fn load_snapshot(path: &std::path::Path) -> Option<rete_transport::Snapshot> {
    match std::fs::read_to_string(path) {
        Ok(json) => match serde_json::from_str(&json) {
            Ok(snap) => {
                eprintln!("[rete] loaded snapshot from {}", path.display());
                Some(snap)
            }
            Err(e) => {
                eprintln!("[rete] failed to parse snapshot: {e}");
                None
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            eprintln!("[rete] failed to read snapshot: {e}");
            None
        }
    }
}

fn save_snapshot(path: &std::path::Path, snap: &rete_transport::Snapshot) {
    match serde_json::to_string(snap) {
        Ok(json) => {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Err(e) = std::fs::write(path, json) {
                eprintln!("[rete] failed to write snapshot: {e}");
            }
        }
        Err(e) => {
            eprintln!("[rete] failed to serialize snapshot: {e}");
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
        "quit" => Some(NodeCommand::Shutdown),
        _ => {
            eprintln!("[rete] unknown command: {line}");
            eprintln!("[rete] commands: send <dest_hex> <text> | link <dest_hex> | close <link_id> | linkdata <link_id> <text> | channel <link_id> <msg_type> <text> | resource <link_id> <text> | request <link_id> <path> <data> | path <dest_hex> | announce [data] | lxmf <dest_hex> <msg> | lxmf-link <link_id> <dest_hex> <msg> | lxmf-prop-announce | quit");
            None
        }
    }
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

    // Parse --connect <addr> (can be repeated for multi-interface)
    let addrs: Vec<&str> = args
        .windows(2)
        .filter(|w| w[0] == "--connect")
        .map(|w| w[1].as_str())
        .collect();

    // Parse --serial <path>
    let serial_path = args
        .windows(2)
        .find(|w| w[0] == "--serial")
        .map(|w| w[1].as_str());

    // Parse --baud <rate> (default 115200, ignored for USB-CDC)
    let baud: u32 = args
        .windows(2)
        .find(|w| w[0] == "--baud")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(DEFAULT_BAUD);

    // Parse --identity-file <path> (default: ~/.rete/identity)
    let identity_file = args
        .windows(2)
        .find(|w| w[0] == "--identity-file")
        .map(|w| PathBuf::from(&w[1]));

    // Parse --auto-reply <message> (send DATA after receiving an announce)
    let auto_reply = args
        .windows(2)
        .find(|w| w[0] == "--auto-reply")
        .map(|w| w[1].clone());

    // --auto-reply-ping: send "ping:<unix_timestamp>" on announce receipt
    let auto_reply_ping = args.iter().any(|a| a == "--auto-reply-ping");

    // --transport: enable transport mode (relay HEADER_2 packets)
    let transport_mode = args.iter().any(|a| a == "--transport");

    // Parse --local-server <instance_name> (run as shared instance server)
    let local_server_name = args
        .windows(2)
        .find(|w| w[0] == "--local-server")
        .map(|w| w[1].clone());

    // Parse --local-client <instance_name> (connect to shared instance as client)
    let local_client_name = args
        .windows(2)
        .find(|w| w[0] == "--local-client")
        .map(|w| w[1].clone());

    // Parse --ifac-netname <name> (IFAC network name for interface access control)
    let ifac_netname = args
        .windows(2)
        .find(|w| w[0] == "--ifac-netname")
        .map(|w| w[1].clone());

    // Parse --ifac-netkey <key> (IFAC network key/passphrase for interface access control)
    let ifac_netkey = args
        .windows(2)
        .find(|w| w[0] == "--ifac-netkey")
        .map(|w| w[1].clone());

    // --packet-log: log every inbound/outbound packet header to stderr
    let packet_log = args.iter().any(|a| a == "--packet-log");
    if packet_log {
        eprintln!("[rete] packet logging enabled");
    }

    // --auto: enable AutoInterface (IPv6 link-local multicast peer discovery)
    let auto_enabled = args.iter().any(|a| a == "--auto");

    // --auto-group <group_id>: override the AutoInterface group ID (default: "reticulum")
    let auto_group = args
        .windows(2)
        .find(|w| w[0] == "--auto-group")
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
    let snapshot_path = default_snapshot_path();
    if let Some(snap) = load_snapshot(&snapshot_path) {
        let n_paths = snap.paths.len();
        let n_ids = snap.identities.len();
        node.core.load_snapshot(&snap);
        eprintln!("[rete] restored {n_paths} paths, {n_ids} identities from snapshot");
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

    // --lxmf-announce: queue LXMF delivery announce at startup
    let lxmf_announce = args.iter().any(|a| a == "--lxmf-announce");
    if lxmf_announce {
        let mut rng = rand::thread_rng();
        let now = rete_tokio::current_time_secs();
        lxmf_router.queue_delivery_announce(&mut node.core, &mut rng, now);
        eprintln!("[rete] LXMF delivery announce queued");
    }

    // --propagation: enable LXMF propagation node (store-and-forward)
    let propagation_enabled = args.iter().any(|a| a == "--propagation");
    if propagation_enabled {
        lxmf_router.register_propagation(&mut node.core);
        eprintln!(
            "[rete] LXMF propagation hash: {}",
            hex::encode(lxmf_router.propagation_dest_hash().unwrap())
        );

        // Queue propagation announce at startup
        let mut rng = rand::thread_rng();
        let now = rete_tokio::current_time_secs();
        lxmf_router.queue_propagation_announce(&mut node.core, &mut rng, now);
        eprintln!("[rete] LXMF propagation announce queued");
    }

    // Wrap lxmf_router in RefCell for interior mutability (needed for
    // propagation deposit in event handler + command handler access).
    let lxmf_router = RefCell::new(lxmf_router);

    // Create command channel + stdin reader
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel::<NodeCommand>(64);
    spawn_stdin_reader(cmd_tx);

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
            |e, core, rng| on_event(e, &lxmf_router, core, rng),
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
            |e, core, rng| on_event(e, &lxmf_router, core, rng),
            |cmd, core, rng| handle_lxmf_command(cmd, core, &lxmf_router, rng),
            rand::thread_rng(),
        )
        .await;
    } else if let Some(path) =
        serial_path.filter(|_| addrs.is_empty() && local_server_name.is_none())
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
            |e, core, rng| on_event(e, &lxmf_router, core, rng),
            |cmd, core, rng| handle_lxmf_command(cmd, core, &lxmf_router, rng),
            rand::thread_rng(),
        )
        .await;
    } else if local_server_name.is_some()
        || addrs.len() > 1
        || (auto_enabled && !addrs.is_empty())
        || (serial_path.is_some() && !addrs.is_empty())
    {
        // Multi-interface mode: TCP endpoints + optional local server + optional AutoInterface.
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel::<InboundMsg>(256);
        let mut senders = Vec::new();
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
            senders.push(tx);
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
                    senders.push(tx);
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
        if let Some(path) = serial_path {
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
            senders.push(tx);
            tokio::spawn(driver);
            eprintln!("[rete] serial port open (iface {})", serial_idx);
        }

        // Start local server (if configured)
        let local_broadcaster = if let Some(ref server_name) = local_server_name {
            let local_iface_idx = next_iface_idx;
            eprintln!(
                "[rete] starting local server '{}' (iface {}) ...",
                server_name, local_iface_idx
            );
            match LocalServer::bind(server_name, inbound_tx.clone(), local_iface_idx) {
                Ok(server) => {
                    let broadcaster = server.broadcaster();
                    tokio::spawn(server.run());
                    eprintln!(
                        "[rete] local server '{}' listening on \\0rns/{}",
                        server_name, server_name
                    );
                    Some(broadcaster)
                }
                Err(e) => {
                    eprintln!("[rete] failed to start local server: {e}");
                    std::process::exit(1);
                }
            }
        } else {
            None
        };

        // Drop the original inbound_tx so the channel closes when all tasks exit
        drop(inbound_tx);

        // If we have a local server, we need to also broadcast outbound packets
        // to local clients. We wrap the multi-interface loop with a broadcaster.
        if let Some(broadcaster) = local_broadcaster {
            run_multi_with_local_server(
                &mut node,
                senders,
                inbound_rx,
                cmd_rx,
                broadcaster,
                |e, core, rng| on_event(e, &lxmf_router, core, rng),
            )
            .await;
        } else {
            node.run_multi_with_commands(senders, inbound_rx, cmd_rx, |e, core, rng| {
                on_event(e, &lxmf_router, core, rng)
            })
            .await;
        }
    } else {
        let addr = addrs.first().copied().unwrap_or(DEFAULT_ADDR);
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
            |e, core, rng| on_event(e, &lxmf_router, core, rng),
            |cmd, core, rng| handle_lxmf_command(cmd, core, &lxmf_router, rng),
            rand::thread_rng(),
        )
        .await;
    }
}

// ---------------------------------------------------------------------------
// Multi-interface loop with local server broadcasting
// ---------------------------------------------------------------------------

/// Run the multi-interface event loop, additionally broadcasting outbound
/// packets to local IPC clients via the [`LocalBroadcaster`].
///
/// This is used when `--local-server` is combined with TCP `--connect`
/// interfaces. Packets from local clients arrive via `inbound_rx` (like any
/// other interface). Outbound packets from the node are sent to TCP interfaces
/// via their senders AND broadcast to all local clients.
async fn run_multi_with_local_server<F>(
    node: &mut TokioNode,
    iface_senders: Vec<tokio::sync::mpsc::Sender<Vec<u8>>>,
    mut inbound_rx: tokio::sync::mpsc::Receiver<InboundMsg>,
    mut cmd_rx: tokio::sync::mpsc::Receiver<NodeCommand>,
    broadcaster: rete_tokio::local::LocalBroadcaster,
    mut on_event: F,
) where
    F: FnMut(
        NodeEvent,
        &mut rete_stack::HostedNodeCore,
        &mut rand::rngs::ThreadRng,
    ) -> Vec<OutboundPacket>,
{
    use rete_transport::{ANNOUNCE_INTERVAL_SECS, TICK_INTERVAL_SECS};

    let mut rng = rand::thread_rng();

    // Queue initial announce
    {
        let now = rete_tokio::current_time_secs();
        node.core.queue_announce(None, &mut rng, now);
        let announces = node.core.flush_announces(now, &mut rng);
        dispatch_with_local(&iface_senders, &announces, 0, &broadcaster, None).await;
    }
    eprintln!(
        "[rete] sent announce on {} TCP interfaces + local server",
        iface_senders.len()
    );

    // Flush cached announces to all interfaces + local clients
    {
        let cached = node.core.cached_announces();
        if !cached.is_empty() {
            eprintln!("[rete] flushing {} cached announces", cached.len());
            dispatch_with_local(&iface_senders, &cached, 0, &broadcaster, None).await;
        }
    }

    let mut announce_timer =
        tokio::time::interval(std::time::Duration::from_secs(ANNOUNCE_INTERVAL_SECS));
    let mut tick_timer = tokio::time::interval(std::time::Duration::from_secs(TICK_INTERVAL_SECS));
    announce_timer.tick().await;
    tick_timer.tick().await;

    loop {
        tokio::select! {
            msg = inbound_rx.recv() => {
                let Some(msg) = msg else { break };
                let now = rete_tokio::current_time_secs();
                let outcome = node.core.handle_ingest(&msg.data, now, msg.iface_idx, &mut rng);
                dispatch_with_local(
                    &iface_senders,
                    &outcome.packets,
                    msg.iface_idx,
                    &broadcaster,
                    None,
                ).await;
                if let Some(event) = outcome.event {
                    let extra = on_event(event, &mut node.core, &mut rng);
                    dispatch_with_local(&iface_senders, &extra, 0, &broadcaster, None).await;
                }
            }
            cmd = cmd_rx.recv() => {
                if let Some(cmd) = cmd {
                    let (packets, cont, event) = node.handle_command(cmd, &mut rng);
                    dispatch_with_local(&iface_senders, &packets, 0, &broadcaster, None).await;
                    if let Some(e) = event {
                        let extra = on_event(e, &mut node.core, &mut rng);
                        dispatch_with_local(&iface_senders, &extra, 0, &broadcaster, None).await;
                    }
                    if !cont { break; }
                }
            }
            _ = announce_timer.tick() => {
                let now = rete_tokio::current_time_secs();
                node.core.queue_announce(None, &mut rng, now);
                let announces = node.core.flush_announces(now, &mut rng);
                dispatch_with_local(&iface_senders, &announces, 0, &broadcaster, None).await;
            }
            _ = tick_timer.tick() => {
                let now = rete_tokio::current_time_secs();
                let outcome = node.core.handle_tick(now, &mut rng);
                dispatch_with_local(&iface_senders, &outcome.packets, 0, &broadcaster, None).await;
                if let Some(event) = outcome.event {
                    let extra = on_event(event, &mut node.core, &mut rng);
                    dispatch_with_local(&iface_senders, &extra, 0, &broadcaster, None).await;
                }
            }
        }
    }
}

/// Dispatch outbound packets to TCP interfaces AND local IPC clients.
async fn dispatch_with_local(
    senders: &[tokio::sync::mpsc::Sender<Vec<u8>>],
    packets: &[rete_stack::OutboundPacket],
    source_iface: u8,
    broadcaster: &rete_tokio::local::LocalBroadcaster,
    exclude_client: Option<usize>,
) {
    use rete_stack::PacketRouting;

    for pkt in packets {
        match pkt.routing {
            PacketRouting::SourceInterface => {
                if let Some(tx) = senders.get(source_iface as usize) {
                    let _ = tx.send(pkt.data.clone()).await;
                }
                // Also send to local clients if source is the local iface
                // (source_iface >= senders.len() means local)
                if source_iface as usize >= senders.len() {
                    broadcaster.broadcast(&pkt.data, exclude_client).await;
                }
            }
            PacketRouting::AllExceptSource => {
                for (i, tx) in senders.iter().enumerate() {
                    if i as u8 != source_iface {
                        let _ = tx.send(pkt.data.clone()).await;
                    }
                }
                // Broadcast to local clients (unless source was local)
                if (source_iface as usize) < senders.len() {
                    // Source was a TCP iface — broadcast to all local clients
                    broadcaster.broadcast(&pkt.data, None).await;
                }
                // If source was local, the server's read task already relayed
                // to other local clients. We still need to send to TCP ifaces
                // (handled above).
            }
            PacketRouting::All => {
                for tx in senders {
                    let _ = tx.send(pkt.data.clone()).await;
                }
                broadcaster.broadcast(&pkt.data, exclude_client).await;
            }
        }
    }
}

fn on_event(
    event: NodeEvent,
    lxmf_router: &RefCell<LxmfRouter>,
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
            save_snapshot(&default_snapshot_path(), &snap);
            eprintln!(
                "[rete] snapshot saved: {} paths, {} identities",
                snap.paths.len(),
                snap.identities.len()
            );
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
        LxmfEvent::Other(event) => {
            // Check if this is a link event that advances a forward job
            match &event {
                NodeEvent::LinkEstablished { link_id } => {
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
                        // Also log the base event
                        on_node_event(event);
                        return pkts;
                    }
                }
                NodeEvent::ResourceComplete {
                    link_id,
                    resource_hash,
                    ..
                } => {
                    // Try advancing forward jobs first
                    let pkts = lxmf_router
                        .borrow_mut()
                        .advance_forward_on_resource_complete(link_id, resource_hash, core, rng);
                    if !pkts.is_empty() {
                        on_node_event(event);
                        return pkts;
                    }

                    // Then try advancing retrieval jobs
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
                }
                NodeEvent::LinkClosed { link_id } => {
                    lxmf_router
                        .borrow_mut()
                        .cleanup_forward_jobs_for_link(link_id);
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
