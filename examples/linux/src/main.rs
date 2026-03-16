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

use rete_core::Identity;
use rete_iface_auto::{AutoInterface, AutoInterfaceConfig};
use rete_iface_serial::SerialInterface;
use rete_iface_tcp::TcpInterface;
use rete_tokio::local::{LocalClient, LocalServer};
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

fn parse_hex_16(hex_str: &str) -> Option<[u8; 16]> {
    let bytes = hex::decode(hex_str).ok()?;
    bytes.as_slice().try_into().ok()
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
            // channel <link_id_hex:32chars> <msg_type:hex_u16> <text>
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
        "resource" => {
            // resource <link_id_hex:32chars> <text>
            let parts: Vec<&str> = line.splitn(3, ' ').collect();
            if parts.len() < 3 {
                eprintln!("[rete] usage: resource <link_id_hex> <text>");
                return None;
            }
            let link_id = parse_hex_16(parts[1])?;
            Some(NodeCommand::SendResource {
                link_id,
                data: parts[2].as_bytes().to_vec(),
            })
        }
        "quit" => Some(NodeCommand::Shutdown),
        _ => {
            eprintln!("[rete] unknown command: {line}");
            eprintln!("[rete] commands: send <dest_hex> <text> | link <dest_hex> | channel <link_id> <msg_type> <text> | resource <link_id> <text> | path <dest_hex> | announce [data] | quit");
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
    if auto_enabled && addrs.is_empty() && serial_path.is_none() && local_client_name.is_none() && local_server_name.is_none() {
        // AutoInterface-only mode (single interface)
        let mut config = AutoInterfaceConfig::default();
        if let Some(ref gid) = auto_group {
            config.group_id = gid.as_bytes().to_vec();
        }
        eprintln!("[rete] starting AutoInterface (group={}) ...",
            String::from_utf8_lossy(&config.group_id));
        let mut iface = match AutoInterface::new(config).await {
            Ok(i) => i,
            Err(e) => {
                eprintln!("[rete] failed to start AutoInterface: {e}");
                std::process::exit(1);
            }
        };
        for info in iface.interfaces() {
            eprintln!("[rete]   interface: {} (index {}, addr {})", info.name, info.index, info.link_local);
        }
        eprintln!("[rete] AutoInterface ready, discovering peers ...");
        node.run_with_commands(&mut iface, cmd_rx, on_event).await;
    } else if let Some(ref client_name) = local_client_name {
        // Local client mode: connect to a shared instance server via Unix socket.
        // Uses single-interface mode (ReteInterface trait).
        eprintln!("[rete] connecting to local instance '{}' ...", client_name);
        let mut iface = match LocalClient::connect(client_name).await {
            Ok(i) => i,
            Err(e) => {
                eprintln!("[rete] failed to connect to local instance: {e}");
                std::process::exit(1);
            }
        };
        eprintln!("[rete] connected to local instance '{}'", client_name);
        node.run_with_commands(&mut iface, cmd_rx, on_event).await;
    } else if let Some(path) = serial_path {
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
    } else if local_server_name.is_some() || addrs.len() > 1 || (auto_enabled && !addrs.is_empty()) {
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
                let key = rete_core::IfacKey::derive(
                    ifac_netname.as_deref(),
                    ifac_netkey.as_deref(),
                )
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
                on_event,
            )
            .await;
        } else {
            node.run_multi_with_commands(senders, inbound_rx, cmd_rx, on_event)
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
            let key = rete_core::IfacKey::derive(
                ifac_netname.as_deref(),
                ifac_netkey.as_deref(),
            )
            .unwrap();
            iface.set_ifac(key);
        }
        eprintln!("[rete] connected");
        node.run_with_commands(&mut iface, cmd_rx, on_event).await;
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
    F: FnMut(NodeEvent),
{
    use rete_transport::{ANNOUNCE_INTERVAL_SECS, TICK_INTERVAL_SECS};

    let mut rng = rand::thread_rng();

    // Queue initial announce
    {
        let now = rete_tokio::current_time_secs();
        node.core.queue_announce(None, &mut rng, now);
        let announces = node.core.flush_announces(now);
        dispatch_with_local(&iface_senders, &announces, 0, &broadcaster, None).await;
    }
    eprintln!(
        "[rete] sent announce on {} TCP interfaces + local server",
        iface_senders.len()
    );

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
                let now = rete_tokio::current_time_secs();
                let outcome = node.core.handle_ingest(&msg.data, now, msg.iface_idx, &mut rng);
                // Determine if this came from a local client (track via client_id in data)
                // For simplicity: packets from the local iface are broadcast to other
                // local clients by the server's read task. We only need to forward to
                // TCP interfaces here.
                dispatch_with_local(
                    &iface_senders,
                    &outcome.packets,
                    msg.iface_idx,
                    &broadcaster,
                    None,
                ).await;
                if let Some(event) = outcome.event {
                    on_event(event);
                }
            }
            cmd = cmd_rx.recv() => {
                if let Some(cmd) = cmd {
                    let (packets, cont) = node.handle_command(cmd, &mut rng);
                    dispatch_with_local(&iface_senders, &packets, 0, &broadcaster, None).await;
                    if !cont { break; }
                }
            }
            _ = announce_timer.tick() => {
                let now = rete_tokio::current_time_secs();
                node.core.queue_announce(None, &mut rng, now);
                let announces = node.core.flush_announces(now);
                dispatch_with_local(&iface_senders, &announces, 0, &broadcaster, None).await;
            }
            _ = tick_timer.tick() => {
                let now = rete_tokio::current_time_secs();
                let outcome = node.core.handle_tick(now, &mut rng);
                dispatch_with_local(&iface_senders, &outcome.packets, 0, &broadcaster, None).await;
                if let Some(event) = outcome.event {
                    on_event(event);
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
                match std::str::from_utf8(payload) {
                    Ok(text) => println!("CHANNEL_MSG:{}:{:#06x}:{}", hex::encode(link_id), msg_type, text),
                    Err(_) => println!("CHANNEL_MSG:{}:{:#06x}:{}", hex::encode(link_id), msg_type, hex::encode(payload)),
                }
            }
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
    }
}
