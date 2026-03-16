//! Linux/hosted example — Reticulum node on desktop or Raspberry Pi.
//!
//! Connects to Python rnsd over TCP for interop testing, or directly to
//! an ESP32 over serial.
//!
//! Usage:
//!   cargo run -p rete-example-linux -- --connect 127.0.0.1:4242
//!   cargo run -p rete-example-linux -- --serial /dev/ttyACM0

use rete_core::Identity;
use rete_iface_serial::SerialInterface;
use rete_iface_tcp::TcpInterface;
use rete_tokio::{interface_task, InboundMsg, NodeCommand, NodeEvent, TokioNode};

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_ADDR: &str = "127.0.0.1:4242";
const DEFAULT_BAUD: u32 = 115200;
const APP_NAME: &str = "rete";
const ASPECTS: &[&str] = &["example", "v1"];

// ---------------------------------------------------------------------------
// Identity persistence
// ---------------------------------------------------------------------------

fn default_identity_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".rete").join("identity")
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

fn parse_dest_hash(hex_str: &str) -> Option<[u8; 16]> {
    let bytes = hex::decode(hex_str).ok()?;
    bytes.as_slice().try_into().ok()
}

fn parse_command(line: &str) -> Option<NodeCommand> {
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    match parts.first().copied()? {
        "send" if parts.len() >= 3 => Some(NodeCommand::SendData {
            dest_hash: parse_dest_hash(parts[1])?,
            payload: parts[2].as_bytes().to_vec(),
        }),
        "link" if parts.len() >= 2 => Some(NodeCommand::InitiateLink {
            dest_hash: parse_dest_hash(parts[1])?,
        }),
        "path" if parts.len() >= 2 => Some(NodeCommand::RequestPath {
            dest_hash: parse_dest_hash(parts[1])?,
        }),
        "announce" => {
            let app_data = if parts.len() >= 2 {
                Some(parts[1..].join(" ").into_bytes())
            } else {
                None
            };
            Some(NodeCommand::Announce { app_data })
        }
        "quit" => Some(NodeCommand::Shutdown),
        _ => {
            eprintln!("[rete] unknown command: {line}");
            eprintln!("[rete] commands: send <dest_hex> <text> | link <dest_hex> | path <dest_hex> | announce [data] | quit");
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

    // Parse --identity-seed <seed> (deterministic key for testing, takes priority)
    let seed = args
        .windows(2)
        .find(|w| w[0] == "--identity-seed")
        .map(|w| w[1].clone());

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

    // Parse --peer-seed <seed> (pre-register peer identity from deterministic seed)
    let peer_seed = args
        .windows(2)
        .find(|w| w[0] == "--peer-seed")
        .map(|w| w[1].clone());

    // --transport: enable transport mode (relay HEADER_2 packets)
    let transport_mode = args.iter().any(|a| a == "--transport");

    // Create or derive identity
    let identity = if let Some(seed_str) = seed {
        Identity::from_seed(seed_str.as_bytes()).expect("invalid derived key")
    } else {
        let id_path = identity_file.unwrap_or_else(default_identity_path);
        load_or_create_identity(&id_path)
    };

    let id_hash = identity.hash();
    eprintln!("[rete] identity hash: {}", hex::encode(id_hash));

    // Create node
    let mut node = TokioNode::new(identity, APP_NAME, ASPECTS);
    if transport_mode {
        node.core.enable_transport();
        eprintln!("[rete] transport mode enabled");
    }

    // Pre-register peer identity (so we can send DATA without waiting for announce)
    if let Some(ref ps) = peer_seed {
        let peer = Identity::from_seed(ps.as_bytes()).expect("invalid peer seed");
        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name(APP_NAME, ASPECTS, &mut name_buf).unwrap();
        let peer_dest = rete_core::destination_hash(expanded, Some(&peer.hash()));
        eprintln!("[rete] pre-registered peer: {}", hex::encode(peer_dest));
        node.register_peer(&peer, APP_NAME, ASPECTS);

        // If --auto-reply-ping, send the ping to the pre-registered peer immediately
        if auto_reply_ping {
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let msg = format!("ping:{ts}");
            eprintln!("[rete] will send on start: {msg}");
            node.send_on_start(peer_dest, msg.into_bytes());
        }
    } else if auto_reply_ping {
        // No peer-seed: fall back to sending ping on announce receipt
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

    // Create command channel + stdin reader
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel::<NodeCommand>(64);
    spawn_stdin_reader(cmd_tx);

    // Dispatch based on interface type
    if let Some(path) = serial_path {
        eprintln!("[rete] opening serial port {} at {} baud ...", path, baud);
        let mut iface = match SerialInterface::open(path, baud) {
            Ok(i) => i,
            Err(e) => {
                eprintln!("[rete] failed to open serial port: {e}");
                std::process::exit(1);
            }
        };
        eprintln!("[rete] serial port open");
        node.run_with_commands(&mut iface, cmd_rx, on_event).await;
    } else if addrs.len() > 1 {
        // Multi-interface mode: connect to multiple TCP endpoints
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel::<InboundMsg>(256);
        let mut senders = Vec::new();

        for (idx, addr) in addrs.iter().enumerate() {
            eprintln!("[rete] connecting to {} (iface {}) ...", addr, idx);
            let iface = match TcpInterface::connect(addr).await {
                Ok(i) => i,
                Err(e) => {
                    eprintln!("[rete] failed to connect to {}: {e}", addr);
                    std::process::exit(1);
                }
            };
            eprintln!("[rete] connected to {} (iface {})", addr, idx);
            let (tx, driver) = interface_task(iface, idx as u8, inbound_tx.clone());
            senders.push(tx);
            tokio::spawn(driver);
        }
        // Drop the original inbound_tx so the channel closes when all tasks exit
        drop(inbound_tx);

        node.run_multi_with_commands(senders, inbound_rx, cmd_rx, on_event)
            .await;
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
        eprintln!("[rete] connected");
        node.run_with_commands(&mut iface, cmd_rx, on_event).await;
    }
}

fn on_event(event: NodeEvent) {
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
            println!(
                "ANNOUNCE:{}:{}:{}",
                hex::encode(dest_hash),
                hex::encode(identity_hash),
                hops,
            );
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
            }
        }
        NodeEvent::LinkClosed { link_id } => {
            eprintln!("[rete] LINK closed: {}", hex::encode(link_id));
            println!("LINK_CLOSED:{}", hex::encode(link_id));
        }
        NodeEvent::Tick { expired_paths, .. } => {
            if expired_paths > 0 {
                eprintln!("[rete] tick: expired {expired_paths} paths");
            }
        }
    }
}
