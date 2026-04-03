//! HTTP monitoring server exposing `/health`, `/stats`, and `/metrics` endpoints.

pub async fn run_monitoring_server(
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

    let (reader, mut writer): (_, tokio::net::tcp::OwnedWriteHalf) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut request_line = String::new();

    // Read the first line of the HTTP request
    if buf_reader.read_line(&mut request_line).await.is_err() {
        return;
    }

    // Parse path from "GET /path HTTP/1.x"
    let path = request_line.split_whitespace().nth(1).unwrap_or("/");

    // HTTP requires consuming all request headers before writing the response
    // (RFC 7230 §6.3): some clients stall if the server starts sending before
    // the full request has been read.
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

/// Format a [`NodeStats`] snapshot as Prometheus text exposition.
pub fn format_prometheus(stats: &rete_stack::NodeStats) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_stats() -> rete_stack::NodeStats {
        rete_stack::NodeStats {
            identity_hash: "aabbccddeeff0011".to_string(),
            uptime_secs: 42,
            transport: Default::default(),
        }
    }

    #[test]
    fn format_prometheus_contains_node_info() {
        let stats = fake_stats();
        let output = format_prometheus(&stats);
        assert!(output.contains("rete_node_info{identity_hash=\"aabbccddeeff0011\"} 1"));
    }

    #[test]
    fn format_prometheus_contains_uptime() {
        let stats = fake_stats();
        let output = format_prometheus(&stats);
        assert!(output.contains("rete_uptime_seconds 42"));
    }

    #[test]
    fn format_prometheus_contains_required_counters() {
        let stats = fake_stats();
        let output = format_prometheus(&stats);
        assert!(output.contains("rete_packets_received_total"));
        assert!(output.contains("rete_packets_sent_total"));
        assert!(output.contains("rete_announces_received_total"));
        assert!(output.contains("rete_links_established_total"));
        assert!(output.contains("rete_paths_learned_total"));
    }

    #[test]
    fn format_prometheus_ends_with_newline() {
        let stats = fake_stats();
        let output = format_prometheus(&stats);
        assert!(output.ends_with('\n'));
    }
}
