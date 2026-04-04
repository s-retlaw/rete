//! TOML configuration file loading for hosted rete daemons.

use std::path::Path;

/// Top-level config file structure. All fields are `Option` so CLI flags
/// can override individual values while the rest come from the file.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub struct Config {
    pub node: NodeConfig,
    pub interfaces: InterfacesConfig,
    pub ifac: IfacConfig,
    pub logging: LoggingConfig,
    pub shared_instance: SharedInstanceConfig,
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct NodeConfig {
    pub transport: Option<bool>,
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct InterfacesConfig {
    pub tcp_server: Option<TcpServerConfig>,
    pub tcp_client: Option<TcpClientConfig>,
    pub serial: Option<SerialConfig>,
    pub auto: Option<AutoConfig>,
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct TcpServerConfig {
    pub listen: Option<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct TcpClientConfig {
    pub connect: Option<Vec<String>>,
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct SerialConfig {
    pub port: Option<String>,
    pub baud: Option<u32>,
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct AutoConfig {
    pub enabled: Option<bool>,
    pub group: Option<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct IfacConfig {
    pub netname: Option<String>,
    pub netkey: Option<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct LoggingConfig {
    pub packet_log: Option<bool>,
}

/// Transport type for the shared instance listener.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SharedInstanceType {
    #[default]
    Unix,
    Tcp,
}

/// Configuration for the `[shared_instance]` TOML section.
///
/// Frozen config keys from the shared-mode compatibility contract
/// (`contracts/SCOPE.md`).
#[derive(Debug, serde::Deserialize)]
#[serde(default)]
pub struct SharedInstanceConfig {
    /// Whether this node acts as a shared instance daemon.
    pub share_instance: bool,
    /// Instance name — maps to socket path `\0rns/{name}` (Unix mode).
    pub instance_name: String,
    /// Transport for shared attach: Unix domain socket or TCP.
    pub shared_instance_type: SharedInstanceType,
    /// Data socket port (TCP mode only). Default: 37428.
    pub shared_instance_port: u16,
    /// RPC/control socket port (TCP mode only). Default: 37429.
    pub instance_control_port: u16,
    /// HMAC auth key for RPC. If absent, derived from transport identity.
    pub rpc_key: Option<String>,
}

impl Default for SharedInstanceConfig {
    fn default() -> Self {
        SharedInstanceConfig {
            share_instance: true,
            instance_name: "default".to_string(),
            shared_instance_type: SharedInstanceType::Unix,
            shared_instance_port: 37428,
            instance_control_port: 37429,
            rpc_key: None,
        }
    }
}

/// Load a config file. Returns:
/// - `Ok(None)` if the file does not exist
/// - `Ok(Some(cfg))` if loaded successfully
/// - `Err(msg)` if the file exists but cannot be read or parsed
pub fn load_config(path: &Path) -> Result<Option<Config>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => match toml::from_str(&text) {
            Ok(cfg) => {
                eprintln!("[rete] loaded config from {}", path.display());
                Ok(Some(cfg))
            }
            Err(e) => Err(format!(
                "[rete] failed to parse config {}: {e}",
                path.display()
            )),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!(
            "[rete] failed to read config {}: {e}",
            path.display()
        )),
    }
}

// ---------------------------------------------------------------------------
// Resolved configuration (CLI overrides TOML)
// ---------------------------------------------------------------------------

/// Fully-resolved node configuration after merging CLI args with TOML config.
#[derive(Debug, Default)]
pub struct DaemonConfig {
    pub addrs: Vec<String>,
    pub serial_path: Option<String>,
    pub baud: u32,
    pub auto_reply: Option<String>,
    pub auto_reply_ping: bool,
    pub transport_mode: bool,
    pub resource_strategy_str: Option<String>,
    pub local_server_name: Option<String>,
    pub local_client_name: Option<String>,
    pub listen_addr: Option<String>,
    pub ifac_netname: Option<String>,
    pub ifac_netkey: Option<String>,
    pub packet_log: bool,
    pub auto_enabled: bool,
    pub auto_group: Option<String>,
    pub monitoring_addr: Option<String>,
    pub lxmf_name: Option<String>,
    pub propagation_enabled: bool,
    pub lxmf_announce: bool,
    pub stamp_cost: Option<u8>,
    pub enforce_stamps: bool,
    pub autopeer_enabled: bool,
}

/// Parse CLI args and merge with a loaded TOML config into a `DaemonConfig`.
///
/// CLI values take precedence over TOML values.
pub fn parse_cli_args(args: &[String], cfg: &Config) -> DaemonConfig {
    let flag = |name: &str| args.iter().any(|a| a == name);
    let value = |name: &str| -> Option<String> {
        args.windows(2)
            .find(|w| w[0] == name)
            .map(|w| w[1].clone())
    };
    let values = |name: &str| -> Vec<String> {
        args.windows(2)
            .filter(|w| w[0] == name)
            .map(|w| w[1].clone())
            .collect()
    };

    let cli_addrs = values("--connect");
    let addrs = if !cli_addrs.is_empty() {
        cli_addrs
    } else {
        cfg.interfaces
            .tcp_client
            .as_ref()
            .and_then(|c| c.connect.clone())
            .unwrap_or_default()
    };

    DaemonConfig {
        addrs,
        serial_path: value("--serial")
            .or_else(|| cfg.interfaces.serial.as_ref().and_then(|s| s.port.clone())),
        baud: value("--baud")
            .and_then(|v| v.parse().ok())
            .or_else(|| cfg.interfaces.serial.as_ref().and_then(|s| s.baud))
            .unwrap_or(115200),
        auto_reply: value("--auto-reply"),
        auto_reply_ping: flag("--auto-reply-ping"),
        transport_mode: flag("--transport") || cfg.node.transport.unwrap_or(false),
        resource_strategy_str: value("--resource-strategy"),
        local_server_name: value("--local-server"),
        local_client_name: value("--local-client"),
        listen_addr: value("--listen").or_else(|| {
            cfg.interfaces
                .tcp_server
                .as_ref()
                .and_then(|s| s.listen.clone())
        }),
        ifac_netname: value("--ifac-netname").or_else(|| cfg.ifac.netname.clone()),
        ifac_netkey: value("--ifac-netkey").or_else(|| cfg.ifac.netkey.clone()),
        packet_log: flag("--packet-log") || cfg.logging.packet_log.unwrap_or(false),
        auto_enabled: flag("--auto")
            || cfg
                .interfaces
                .auto
                .as_ref()
                .and_then(|a| a.enabled)
                .unwrap_or(false),
        auto_group: value("--auto-group")
            .or_else(|| cfg.interfaces.auto.as_ref().and_then(|a| a.group.clone())),
        monitoring_addr: value("--monitoring"),
        lxmf_name: value("--lxmf-name"),
        propagation_enabled: flag("--propagation"),
        lxmf_announce: flag("--lxmf-announce"),
        stamp_cost: value("--lxmf-stamp-cost").and_then(|v| v.parse().ok()),
        enforce_stamps: flag("--lxmf-enforce-stamps"),
        autopeer_enabled: flag("--autopeer"),
    }
}

// ---------------------------------------------------------------------------
// CLI helpers
// ---------------------------------------------------------------------------

/// Check if a flag (e.g. `--transport`) is present in args.
pub fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// Get the value following a named flag (e.g. `--data-dir /tmp`).
pub fn value_of(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].clone())
}

/// Return the default config file template as a static string.
pub fn generate_default_config() -> &'static str {
    r#"# rete node configuration
# CLI flags override values in this file.

[node]
# Enable transport mode (relay packets for other nodes)
# transport = true

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

[shared_instance]
# Enable shared instance daemon mode
# share_instance = true
# instance_name = "default"
# shared_instance_type = "unix"   # "unix" or "tcp"
# shared_instance_port = 37428    # TCP data port
# instance_control_port = 37429   # TCP control/RPC port
# rpc_key = ""                    # HMAC auth key (derived from identity if absent)
"#
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn generate_default_config_is_valid_toml() {
        let s = generate_default_config();
        let result: Result<Config, _> = toml::from_str(s);
        assert!(result.is_ok(), "default config template must be valid TOML");
    }

    #[test]
    fn load_config_missing_file_returns_ok_none() {
        let path = std::path::Path::new("/tmp/rete_daemon_test_nonexistent_42.toml");
        let result = load_config(path);
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn load_config_valid_toml() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "[node]\ntransport = true").unwrap();
        let result = load_config(f.path());
        let cfg = result.unwrap().unwrap();
        assert_eq!(cfg.node.transport, Some(true));
    }

    #[test]
    fn load_config_invalid_toml_returns_err() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "not valid toml !!!{{{{").unwrap();
        let result = load_config(f.path());
        assert!(result.is_err());
    }

    #[test]
    fn shared_instance_config_defaults() {
        let cfg: Config = toml::from_str("").unwrap();
        assert!(cfg.shared_instance.share_instance);
        assert_eq!(cfg.shared_instance.instance_name, "default");
        assert_eq!(
            cfg.shared_instance.shared_instance_type,
            SharedInstanceType::Unix
        );
        assert_eq!(cfg.shared_instance.shared_instance_port, 37428);
        assert_eq!(cfg.shared_instance.instance_control_port, 37429);
        assert!(cfg.shared_instance.rpc_key.is_none());
    }

    #[test]
    fn shared_instance_config_tcp_roundtrip() {
        let toml_str = r#"
[shared_instance]
share_instance = true
instance_name = "mynode"
shared_instance_type = "tcp"
shared_instance_port = 40000
instance_control_port = 40001
rpc_key = "deadbeef"
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.shared_instance.instance_name, "mynode");
        assert_eq!(
            cfg.shared_instance.shared_instance_type,
            SharedInstanceType::Tcp
        );
        assert_eq!(cfg.shared_instance.shared_instance_port, 40000);
        assert_eq!(cfg.shared_instance.instance_control_port, 40001);
        assert_eq!(cfg.shared_instance.rpc_key.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn load_config_tcp_client_connect() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"[interfaces.tcp_client]
connect = ["127.0.0.1:4242", "10.0.0.1:4242"]"#
        )
        .unwrap();
        let cfg = load_config(f.path()).unwrap().unwrap();
        let connects = cfg
            .interfaces
            .tcp_client
            .unwrap()
            .connect
            .unwrap();
        assert_eq!(connects.len(), 2);
        assert_eq!(connects[0], "127.0.0.1:4242");
    }
}
