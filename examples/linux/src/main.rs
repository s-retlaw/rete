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

use rete_daemon::{
    command::{spawn_signal_handler, spawn_stdin_reader},
    compression::AppHooks,
    config::{generate_default_config, load_config, parse_cli_args},
    event::{handle_lxmf_command, on_event},
    file_store::AnyMessageStore,
    identity::{default_data_dir, load_or_create_identity, JsonFileStore},
    monitoring::run_monitoring_server,
};

use rete_iface_auto::{AutoInterface, AutoInterfaceConfig};
use rete_iface_serial::SerialInterface;
use rete_iface_tcp::TcpInterface;
use rete_lxmf::LxmfRouter;
use rete_stack::{handler_fn, RequestHandler, RequestPolicy, ResponseCompressionPolicy};
use rete_tokio::local::{LocalServer, ReconnectingLocalClient};
use rete_tokio::tcp_server::TcpServer;
use rete_tokio::{interface_task, InboundMsg, InterfaceSlot, NodeCommand, TokioNode};
use rete_transport::SnapshotStore as _;

use std::cell::RefCell;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_ADDR: &str = "127.0.0.1:4242";
const APP_NAME: &str = "rete";
const ASPECTS: &[&str] = &["example", "v1"];

#[tokio::main]
async fn main() {
    rete_daemon::init_tracing();
    let args: Vec<String> = std::env::args().collect();

    // --generate-config: print default config to stdout and exit
    if args.iter().any(|a| a == "--generate-config") {
        print!("{}", generate_default_config());
        return;
    }

    // Resolve data directory and load TOML config
    let data_dir = args
        .windows(2)
        .find(|w| w[0] == "--data-dir")
        .map(|w| PathBuf::from(&w[1]))
        .unwrap_or_else(default_data_dir);
    tracing::info!("data dir: {}", data_dir.display());

    let config_path = data_dir.join("config.toml");
    let cfg = match load_config(&config_path) {
        Ok(c) => c.unwrap_or_default(),
        Err(e) => {
            tracing::error!("{e}");
            std::process::exit(1);
        }
    };

    // Merge CLI args with TOML config
    let c = parse_cli_args(&args, &cfg);

    if c.packet_log {
        tracing::info!("packet logging enabled");
    }

    // Resolve resource strategy
    let resource_strategy = match c.resource_strategy_str.as_deref() {
        Some("none") => rete_tokio::ResourceStrategy::AcceptNone,
        Some("app") => rete_tokio::ResourceStrategy::AcceptApp,
        Some("all") | None => rete_tokio::ResourceStrategy::AcceptAll,
        Some(other) => {
            tracing::warn!("unknown resource strategy '{other}', using AcceptAll");
            rete_tokio::ResourceStrategy::AcceptAll
        }
    };

    // Derive IFAC key once and reuse at each interface setup site.
    let ifac_key = if c.ifac_netname.is_some() || c.ifac_netkey.is_some() {
        let key = rete_core::IfacKey::derive(c.ifac_netname.as_deref(), c.ifac_netkey.as_deref())
            .expect("failed to derive IFAC key");
        tracing::info!(
            "IFAC enabled (netname={}, netkey={})",
            c.ifac_netname.as_deref().unwrap_or("<none>"),
            if c.ifac_netkey.is_some() { "<set>" } else { "<none>" },
        );
        Some(key)
    } else {
        None
    };

    // Create or load identity
    let id_path = data_dir.join("identity");
    let identity = match load_or_create_identity(&id_path) {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("{e}");
            std::process::exit(1);
        }
    };
    tracing::info!("identity hash: {}", hex::encode(identity.hash()));

    // Create node
    let mut node = TokioNode::new_boxed(identity, APP_NAME, ASPECTS).expect("valid app name");
    node.core.set_hooks(Box::new(AppHooks { packet_log: c.packet_log }));

    // Load snapshot
    let mut snapshot_store = JsonFileStore::new(data_dir.join("snapshot.json"));
    match snapshot_store.load() {
        Ok(Some(snap)) => {
            let (np, ni) = (snap.paths.len(), snap.identities.len());
            node.core.load_snapshot(&snap);
            tracing::info!("restored {np} paths, {ni} identities from snapshot");
        }
        Ok(None) => {}
        Err(e) => tracing::error!("failed to load snapshot: {e:?}"),
    }

    if c.transport_mode {
        node.core.enable_transport();
        tracing::info!("transport mode enabled");
    }

    node.set_resource_strategy(resource_strategy);
    if resource_strategy != rete_tokio::ResourceStrategy::AcceptAll {
        tracing::info!("resource strategy: {:?}", resource_strategy);
    }

    if c.auto_reply_ping {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let msg = format!("ping:{ts}");
        tracing::info!("auto-reply-ping: {msg}");
        node.core.set_auto_reply(Some(msg.into_bytes()));
    }
    if let Some(msg) = c.auto_reply {
        node.core.set_auto_reply(Some(msg.into_bytes()));
    }

    tracing::info!("destination hash: {}", hex::encode(node.core.dest_hash()));
    // Emit structured test event for interop test discovery.
    tracing::info!(target: "rete::test_event", event = "IDENTITY", hash = %hex::encode(node.core.dest_hash()));

    // Register /test/echo request handler
    {
        let dh = *node.core.dest_hash();
        node.core.register_request_handler(
            &dh,
            RequestHandler {
                path: "/test/echo".into(),
                handler: handler_fn(|_ctx, data| Some(data.to_vec())),
                policy: RequestPolicy::AllowAll,
                compression_policy: ResponseCompressionPolicy::Default,
            },
        );
        tracing::info!("registered /test/echo request handler");
    }

    // LXMF setup
    let mut lxmf_router = LxmfRouter::<AnyMessageStore>::register_with_store(&mut node.core);
    if let Some(name) = c.lxmf_name {
        lxmf_router.set_display_name(name.into_bytes());
    }
    tracing::info!("LXMF delivery hash: {}", hex::encode(lxmf_router.delivery_dest_hash()));

    if c.propagation_enabled {
        let messages_dir = data_dir.join("messages");
        match rete_daemon::file_store::FileMessageStore::open(messages_dir.clone()) {
            Ok(store) => {
                lxmf_router.register_propagation_with_store(
                    &mut node.core,
                    AnyMessageStore::File(store),
                );
                tracing::info!("propagation using file-backed store in {}", messages_dir.display());
            }
            Err(e) => {
                tracing::warn!("failed to open file store: {e}, falling back to in-memory");
                lxmf_router.register_propagation(&mut node.core);
            }
        }
        tracing::info!("LXMF propagation hash: {}", hex::encode(lxmf_router.propagation_dest_hash().unwrap()));
        let mut rng = rand::thread_rng();
        let now = rete_tokio::current_time_secs();
        lxmf_router.queue_propagation_announce(&mut node.core, &mut rng, now);
        tracing::info!("LXMF propagation announce queued");
    }

    if c.lxmf_announce && !c.propagation_enabled {
        let mut rng = rand::thread_rng();
        let now = rete_tokio::current_time_secs();
        lxmf_router.queue_delivery_announce(&mut node.core, &mut rng, now);
        tracing::info!("LXMF delivery announce queued");
    }

    if let Some(cost) = c.stamp_cost {
        lxmf_router.set_inbound_stamp_cost(Some(cost));
        tracing::info!("LXMF inbound stamp cost set to {cost}");
    }
    if c.enforce_stamps {
        lxmf_router.set_enforce_stamps(true);
        tracing::info!("LXMF stamp enforcement enabled");
    }
    if c.autopeer_enabled {
        lxmf_router.set_autopeer(true, 4);
        tracing::info!("auto-peering enabled (maxdepth=4)");
    }

    let lxmf_router = RefCell::new(lxmf_router);
    let snapshot_store = RefCell::new(snapshot_store);

    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel::<NodeCommand>(64);
    spawn_signal_handler(cmd_tx.clone());
    spawn_stdin_reader(cmd_tx);

    let (stats_tx, stats_rx) = tokio::sync::watch::channel::<Option<rete_stack::NodeStats>>(None);
    if let Some(ref addr) = c.monitoring_addr {
        let addr = addr.parse::<std::net::SocketAddr>().expect("invalid monitoring address");
        let rx = stats_rx.clone();
        tokio::spawn(async move { run_monitoring_server(addr, rx).await });
        tracing::info!("monitoring endpoint on http://{}", addr);
    }

    // Interface dispatch
    if c.auto_enabled && c.addrs.is_empty() && c.serial_path.is_none()
        && c.local_client_name.is_none() && c.local_server_name.is_none()
    {
        // AutoInterface-only mode
        let mut config = AutoInterfaceConfig::default();
        if let Some(ref gid) = c.auto_group { config.group_id = gid.as_bytes().to_vec(); }
        tracing::info!("starting AutoInterface (group={}) ...", String::from_utf8_lossy(&config.group_id));
        let mut iface = match AutoInterface::new(config).await {
            Ok(i) => i,
            Err(e) => { tracing::error!("failed to start AutoInterface: {e}"); std::process::exit(1); }
        };
        for info in iface.interfaces() {
            tracing::info!("  interface: {} (index {}, addr {})", info.name, info.index, info.link_local);
        }
        tracing::info!("AutoInterface ready, discovering peers ...");
        node.run_with_app_handler(&mut iface, cmd_rx,
            |e, core, rng| on_event(e, &lxmf_router, &snapshot_store, &stats_tx, core, rng),
            |cmd, core, rng| handle_lxmf_command(cmd, core, &lxmf_router, rng),
            rand::thread_rng(),
        ).await;
    } else if let Some(ref client_name) = c.local_client_name {
        tracing::info!("connecting to local instance '{}' ...", client_name);
        let mut iface = ReconnectingLocalClient::new(client_name.clone());
        tracing::info!("local client ready for instance '{}'", client_name);
        node.run_with_app_handler(&mut iface, cmd_rx,
            |e, core, rng| on_event(e, &lxmf_router, &snapshot_store, &stats_tx, core, rng),
            |cmd, core, rng| handle_lxmf_command(cmd, core, &lxmf_router, rng),
            rand::thread_rng(),
        ).await;
    } else if let Some(path) = c.serial_path.as_deref()
        .filter(|_| c.addrs.is_empty() && c.local_server_name.is_none())
    {
        tracing::info!("opening serial port {} at {} baud ...", path, c.baud);
        let mut iface = match SerialInterface::open(path, c.baud) {
            Ok(i) => i,
            Err(e) => { tracing::error!("failed to open serial port: {e}"); std::process::exit(1); }
        };
        tracing::info!("serial port open");
        node.run_with_app_handler(&mut iface, cmd_rx,
            |e, core, rng| on_event(e, &lxmf_router, &snapshot_store, &stats_tx, core, rng),
            |cmd, core, rng| handle_lxmf_command(cmd, core, &lxmf_router, rng),
            rand::thread_rng(),
        ).await;
    } else if c.local_server_name.is_some() || c.listen_addr.is_some()
        || c.addrs.len() > 1
        || (c.auto_enabled && !c.addrs.is_empty())
        || (c.serial_path.is_some() && !c.addrs.is_empty())
    {
        // Multi-interface mode
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel::<InboundMsg>(256);
        let mut slots: Vec<InterfaceSlot> = Vec::new();
        let mut next_idx: u8 = 0;

        for addr in &c.addrs {
            let idx = next_idx; next_idx += 1;
            tracing::info!("connecting to {} (iface {}) ...", addr, idx);
            let mut iface = match TcpInterface::connect(addr).await {
                Ok(i) => i,
                Err(e) => { tracing::error!("failed to connect to {}: {e}", addr); std::process::exit(1); }
            };
            if c.ifac_netname.is_some() || c.ifac_netkey.is_some() {
                let key = rete_core::IfacKey::derive(c.ifac_netname.as_deref(), c.ifac_netkey.as_deref())
                    .expect("failed to derive IFAC key");
                iface.set_ifac(key);
            }
            tracing::info!("connected to {} (iface {})", addr, idx);
            let (tx, driver) = interface_task(iface, idx, inbound_tx.clone());
            slots.push(InterfaceSlot::Direct(tx));
            tokio::spawn(driver);
        }

        if c.auto_enabled {
            let idx = next_idx; next_idx += 1;
            let mut config = AutoInterfaceConfig::default();
            if let Some(ref gid) = c.auto_group { config.group_id = gid.as_bytes().to_vec(); }
            tracing::info!("starting AutoInterface (iface {}, group={}) ...", idx, String::from_utf8_lossy(&config.group_id));
            match AutoInterface::new(config).await {
                Ok(iface) => {
                    for info in iface.interfaces() {
                        tracing::info!("  auto interface: {} (index {}, addr {})", info.name, info.index, info.link_local);
                    }
                    let (tx, driver) = interface_task(iface, idx, inbound_tx.clone());
                    slots.push(InterfaceSlot::Direct(tx));
                    tokio::spawn(driver);
                    tracing::info!("AutoInterface ready (iface {})", idx);
                }
                Err(e) => { tracing::error!("failed to start AutoInterface: {e}"); std::process::exit(1); }
            }
        }

        if let Some(ref path) = c.serial_path {
            let idx = next_idx; next_idx += 1;
            tracing::info!("opening serial port {} (iface {}) ...", path, idx);
            let iface = match SerialInterface::open(path, c.baud) {
                Ok(i) => i,
                Err(e) => { tracing::error!("failed to open serial port: {e}"); std::process::exit(1); }
            };
            let (tx, driver) = interface_task(iface, idx, inbound_tx.clone());
            slots.push(InterfaceSlot::Direct(tx));
            tokio::spawn(driver);
            tracing::info!("serial port open (iface {})", idx);
        }

        if let Some(ref server_name) = c.local_server_name {
            let idx = next_idx; next_idx += 1;
            tracing::info!("starting local server '{}' (iface {}) ...", server_name, idx);
            match LocalServer::bind(server_name, inbound_tx.clone(), idx) {
                Ok(server) => {
                    let broadcaster = server.broadcaster();
                    tokio::spawn(server.run());
                    slots.push(InterfaceSlot::Hub(broadcaster));
                    tracing::info!("local server '{}' listening on \\0rns/{}", server_name, server_name);
                }
                Err(e) => { tracing::error!("failed to start local server: {e}"); std::process::exit(1); }
            }
        }

        if let Some(ref addr) = c.listen_addr {
            let idx = next_idx; next_idx += 1;
            let ifac = ifac_key;
            match TcpServer::bind(addr, inbound_tx.clone(), idx, ifac, Default::default()).await {
                Ok(server) => {
                    let broadcaster = server.broadcaster();
                    tokio::spawn(server.run());
                    slots.push(InterfaceSlot::Hub(broadcaster));
                    tracing::info!("TCP server listening on {} (iface {})", addr, idx);
                }
                Err(e) => { tracing::error!("failed to bind TCP server on {}: {e}", addr); std::process::exit(1); }
            }
        }

        let _ = next_idx;
        drop(inbound_tx);
        node.run_multi_with_commands(slots, inbound_rx, cmd_rx,
            |e, core, rng| on_event(e, &lxmf_router, &snapshot_store, &stats_tx, core, rng),
        ).await;
    } else {
        let addr = c.addrs.first().map(|s| s.as_str()).unwrap_or(DEFAULT_ADDR);
        tracing::info!("connecting to {} ...", addr);
        let mut iface = match TcpInterface::connect(addr).await {
            Ok(i) => i,
            Err(e) => { tracing::error!("failed to connect: {e}"); std::process::exit(1); }
        };
        if let Some(key) = ifac_key {
            iface.set_ifac(key);
        }
        tracing::info!("connected");
        node.run_with_app_handler(&mut iface, cmd_rx,
            |e, core, rng| on_event(e, &lxmf_router, &snapshot_store, &stats_tx, core, rng),
            |cmd, core, rng| handle_lxmf_command(cmd, core, &lxmf_router, rng),
            rand::thread_rng(),
        ).await;
    }

    // Shutdown: save final snapshot, print marker, exit
    {
        let snap = node.core.save_snapshot(rete_transport::SnapshotDetail::Standard);
        if let Err(e) = snapshot_store.borrow_mut().save(&snap) {
            tracing::error!("failed to save final snapshot: {e:?}");
        } else {
            tracing::info!("final snapshot saved ({} paths, {} identities)", snap.paths.len(), snap.identities.len());
        }
    }
    tracing::info!(target: "rete::test_event", event = "SHUTDOWN_COMPLETE");
    // Force exit to avoid blocking on the stdin reader thread.
    std::process::exit(0);
}
