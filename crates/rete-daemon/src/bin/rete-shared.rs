//! rete-shared — Shared-instance Reticulum daemon.
//!
//! Replaces Python `rnsd` as the system shared instance. Stock Python
//! shared-mode clients attach unchanged over Unix sockets or TCP.

use rete_daemon::config::{has_flag, load_config, value_of, SharedInstanceConfig, SharedInstanceType};
use rete_daemon::daemon::SharedDaemonBuilder;
use rete_daemon::identity::default_data_dir;

use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if has_flag(&args, "--help") || has_flag(&args, "-h") {
        eprintln!("Usage: rete-shared [OPTIONS]");
        eprintln!();
        eprintln!("Options:");
        eprintln!("  --data-dir <PATH>           Data directory (default: ~/.rete)");
        eprintln!("  --instance-name <NAME>      Instance name (default: \"default\")");
        eprintln!("  --shared-instance-type <T>  \"unix\" or \"tcp\" (default: unix)");
        eprintln!("  --transport                 Enable transport mode");
        eprintln!("  --help                      Show this help");
        std::process::exit(0);
    }

    let data_dir = value_of(&args, "--data-dir")
        .map(PathBuf::from)
        .unwrap_or_else(default_data_dir);

    let config_path = data_dir.join("config.toml");

    let cfg = match load_config(&config_path) {
        Ok(Some(c)) => c,
        Ok(None) => Default::default(),
        Err(e) => {
            eprintln!("[rete-shared] {e}");
            std::process::exit(1);
        }
    };

    // Start with TOML config, apply CLI overrides.
    let mut shared = cfg.shared_instance;
    if let Some(name) = value_of(&args, "--instance-name") {
        shared.instance_name = name;
    }
    if let Some(t) = value_of(&args, "--shared-instance-type") {
        shared.shared_instance_type = match t.as_str() {
            "unix" => SharedInstanceType::Unix,
            "tcp" => SharedInstanceType::Tcp,
            other => {
                eprintln!("[rete-shared] invalid shared_instance_type: {other}");
                std::process::exit(1);
            }
        };
    }

    let transport = has_flag(&args, "--transport");

    // Run on a current-thread runtime (DaemonFuture is !Send).
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    rt.block_on(run(shared, data_dir, transport));
}

async fn run(config: SharedInstanceConfig, data_dir: PathBuf, transport: bool) {
    let builder = SharedDaemonBuilder::new(config)
        .data_dir(&data_dir)
        .transport_mode(transport);

    let (daemon, run_future) = match builder.start().await {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("[rete-shared] fatal: {e}");
            std::process::exit(1);
        }
    };

    // Wire signal handler for clean shutdown.
    rete_daemon::command::spawn_signal_handler(daemon.command_sender());

    run_future.await;
}
