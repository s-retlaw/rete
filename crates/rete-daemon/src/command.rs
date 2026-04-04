//! Stdin command parsing and async reader/signal tasks for hosted nodes.

use rete_core::{DestHash, LinkId};
use rete_tokio::NodeCommand;

// ---------------------------------------------------------------------------
// Hex parsing helpers
// ---------------------------------------------------------------------------

pub fn parse_hex_16(hex_str: &str) -> Option<[u8; 16]> {
    let bytes = hex::decode(hex_str).ok()?;
    bytes.as_slice().try_into().ok()
}

pub fn parse_dest_hash(hex_str: &str) -> Option<DestHash> {
    parse_hex_16(hex_str).map(DestHash::from)
}

pub fn parse_link_id(hex_str: &str) -> Option<LinkId> {
    parse_hex_16(hex_str).map(LinkId::from)
}

/// Parse `<cmd> <link_id_hex> <text>` into (link_id, payload).
fn parse_link_and_text(line: &str, cmd: &str) -> Option<(LinkId, Vec<u8>)> {
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() < 3 {
        eprintln!("[rete] usage: {cmd} <link_id_hex> <text>");
        return None;
    }
    let link_id = parse_link_id(parts[1])?;
    Some((link_id, parts[2].as_bytes().to_vec()))
}

// ---------------------------------------------------------------------------
// Command parser
// ---------------------------------------------------------------------------

/// Parse a line of stdin into a `NodeCommand`. Returns `None` for unknown or
/// malformed commands (already logged to stderr).
pub fn parse_command(line: &str) -> Option<NodeCommand> {
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    match parts.first().copied()? {
        "send" if parts.len() >= 3 => Some(NodeCommand::SendData {
            dest_hash: parse_dest_hash(parts[1])?,
            payload: parts[2].as_bytes().to_vec(),
        }),
        "link" if parts.len() >= 2 => Some(NodeCommand::InitiateLink {
            dest_hash: parse_dest_hash(parts[1])?,
        }),
        "channel" => {
            let parts: Vec<&str> = line.splitn(4, ' ').collect();
            if parts.len() < 4 {
                eprintln!("[rete] usage: channel <link_id_hex> <msg_type_hex> <text>");
                return None;
            }
            let link_id = parse_link_id(parts[1])?;
            let msg_type = u16::from_str_radix(parts[2].trim_start_matches("0x"), 16).ok()?;
            Some(NodeCommand::SendChannelMessage {
                link_id,
                message_type: msg_type,
                payload: parts[3].as_bytes().to_vec(),
            })
        }
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
        "linkdata" => {
            let (link_id, payload) = parse_link_and_text(line, "linkdata")?;
            Some(NodeCommand::SendLinkData { link_id, payload })
        }
        "resource" => {
            let (link_id, data) = parse_link_and_text(line, "resource")?;
            Some(NodeCommand::SendResource { link_id, data })
        }
        "accept" if parts.len() >= 3 => {
            let link_id = parse_link_id(parts[1])?;
            let resource_hash = parse_hex_16(parts[2])?;
            Some(NodeCommand::AcceptResource {
                link_id,
                resource_hash,
            })
        }
        "reject" if parts.len() >= 3 => {
            let link_id = parse_link_id(parts[1])?;
            let resource_hash = parse_hex_16(parts[2])?;
            Some(NodeCommand::RejectResource {
                link_id,
                resource_hash,
            })
        }
        "close" if parts.len() >= 2 => Some(NodeCommand::CloseLink {
            link_id: parse_link_id(parts[1])?,
        }),
        "request" => {
            let parts: Vec<&str> = line.splitn(4, ' ').collect();
            if parts.len() < 4 {
                eprintln!("[rete] usage: request <link_id_hex> <path> <data>");
                return None;
            }
            let link_id = parse_link_id(parts[1])?;
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
                dest_hash: Some(parse_dest_hash(parts[1])?),
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
                dest_hash: Some(parse_dest_hash(parts[2])?),
                link_id: Some(parse_link_id(parts[1])?),
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

// ---------------------------------------------------------------------------
// Async stdin reader and signal handler
// ---------------------------------------------------------------------------

/// Spawn a task that watches for SIGTERM and Ctrl-C and sends `Shutdown`.
pub fn spawn_signal_handler(cmd_tx: tokio::sync::mpsc::Sender<NodeCommand>) {
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

/// Spawn a blocking task that reads lines from stdin and sends parsed commands.
pub fn spawn_stdin_reader(cmd_tx: tokio::sync::mpsc::Sender<NodeCommand>) {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A canonical 32-char hex string representing 16 bytes (0x01 * 16).
    const HEX16: &str = "01010101010101010101010101010101";
    /// Another 32-char hex string (0x02 * 16).
    const HEX16B: &str = "02020202020202020202020202020202";

    #[test]
    fn parse_hex_16_valid() {
        let result = parse_hex_16(HEX16).unwrap();
        assert_eq!(result, [0x01u8; 16]);
    }

    #[test]
    fn parse_hex_16_wrong_length() {
        assert!(parse_hex_16("0102").is_none());
        assert!(parse_hex_16("").is_none());
    }

    #[test]
    fn parse_hex_16_invalid_hex() {
        assert!(parse_hex_16("0102030405060708090a0b0c0d0e0fgg").is_none());
    }

    #[test]
    fn parse_send_command() {
        let cmd = parse_command(&format!("send {HEX16} hello world")).unwrap();
        match cmd {
            NodeCommand::SendData { dest_hash, payload } => {
                assert_eq!(dest_hash.as_bytes(), &[0x01u8; 16]);
                assert_eq!(payload, b"hello world");
            }
            _ => panic!("wrong command type"),
        }
    }

    #[test]
    fn parse_link_command() {
        let cmd = parse_command(&format!("link {HEX16}")).unwrap();
        assert!(matches!(cmd, NodeCommand::InitiateLink { .. }));
    }

    #[test]
    fn parse_path_command() {
        let cmd = parse_command(&format!("path {HEX16}")).unwrap();
        assert!(matches!(cmd, NodeCommand::RequestPath { .. }));
    }

    #[test]
    fn parse_announce_no_data() {
        let cmd = parse_command("announce").unwrap();
        match cmd {
            NodeCommand::Announce { app_data } => assert!(app_data.is_none()),
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn parse_announce_with_data() {
        let cmd = parse_command("announce mydata").unwrap();
        match cmd {
            NodeCommand::Announce { app_data } => {
                assert_eq!(app_data.unwrap(), b"mydata");
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn parse_linkdata_command() {
        let cmd = parse_command(&format!("linkdata {HEX16} some text")).unwrap();
        match cmd {
            NodeCommand::SendLinkData { link_id, payload } => {
                assert_eq!(link_id.as_bytes(), &[0x01u8; 16]);
                assert_eq!(payload, b"some text");
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn parse_resource_command() {
        let cmd = parse_command(&format!("resource {HEX16} data")).unwrap();
        assert!(matches!(cmd, NodeCommand::SendResource { .. }));
    }

    #[test]
    fn parse_accept_command() {
        let cmd = parse_command(&format!("accept {HEX16} {HEX16B}")).unwrap();
        match cmd {
            NodeCommand::AcceptResource {
                link_id,
                resource_hash,
            } => {
                assert_eq!(link_id.as_bytes(), &[0x01u8; 16]);
                assert_eq!(resource_hash, [0x02u8; 16]);
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn parse_reject_command() {
        let cmd = parse_command(&format!("reject {HEX16} {HEX16B}")).unwrap();
        assert!(matches!(cmd, NodeCommand::RejectResource { .. }));
    }

    #[test]
    fn parse_close_command() {
        let cmd = parse_command(&format!("close {HEX16}")).unwrap();
        assert!(matches!(cmd, NodeCommand::CloseLink { .. }));
    }

    #[test]
    fn parse_request_command() {
        let cmd = parse_command(&format!("request {HEX16} /test/echo payload")).unwrap();
        match cmd {
            NodeCommand::SendRequest {
                link_id,
                path,
                payload,
            } => {
                assert_eq!(link_id.as_bytes(), &[0x01u8; 16]);
                assert_eq!(path, "/test/echo");
                assert_eq!(payload, b"payload");
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn parse_channel_command() {
        let cmd = parse_command(&format!("channel {HEX16} 0x0001 text message")).unwrap();
        match cmd {
            NodeCommand::SendChannelMessage {
                link_id,
                message_type,
                payload,
            } => {
                assert_eq!(link_id.as_bytes(), &[0x01u8; 16]);
                assert_eq!(message_type, 1);
                assert_eq!(payload, b"text message");
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn parse_lxmf_command() {
        let cmd = parse_command(&format!("lxmf {HEX16} my message")).unwrap();
        match cmd {
            NodeCommand::AppCommand {
                name, dest_hash, ..
            } => {
                assert_eq!(name, "lxmf-send");
                assert!(dest_hash.is_some());
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn parse_lxmf_link_command() {
        let cmd = parse_command(&format!("lxmf-link {HEX16} {HEX16B} message")).unwrap();
        match cmd {
            NodeCommand::AppCommand {
                name,
                link_id,
                dest_hash,
                ..
            } => {
                assert_eq!(name, "lxmf-link-send");
                assert!(link_id.is_some());
                assert!(dest_hash.is_some());
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn parse_lxmf_announce_command() {
        let cmd = parse_command("lxmf-announce").unwrap();
        match cmd {
            NodeCommand::AppCommand { name, .. } => assert_eq!(name, "lxmf-announce"),
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn parse_lxmf_prop_announce_command() {
        let cmd = parse_command("lxmf-prop-announce").unwrap();
        match cmd {
            NodeCommand::AppCommand { name, .. } => assert_eq!(name, "lxmf-prop-announce"),
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn parse_stats_command() {
        let cmd = parse_command("stats").unwrap();
        match cmd {
            NodeCommand::AppCommand { name, .. } => assert_eq!(name, "stats"),
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn parse_quit_command() {
        let cmd = parse_command("quit").unwrap();
        assert!(matches!(cmd, NodeCommand::Shutdown));
    }

    #[test]
    fn parse_unknown_command_returns_none() {
        assert!(parse_command("foobar").is_none());
        assert!(parse_command("").is_none());
    }

    #[test]
    fn parse_send_missing_payload_returns_none() {
        // "send <dest>" with no payload text — parts.len() < 3
        assert!(parse_command(&format!("send {HEX16}")).is_none());
    }
}
