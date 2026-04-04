//! Control plane: wire framing, HMAC auth, and RPC listener.
//!
//! Implements the Python `multiprocessing.connection` wire protocol used by
//! `rnstatus` and other RNS shared-mode utilities.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// ── Wire framing ────────────────────────────────────────────────────────────

/// Maximum message size (1 MiB) to prevent OOM from rogue clients.
const MAX_MESSAGE_SIZE: u32 = 1 << 20;

/// Read a 4-byte big-endian length-prefixed message.
pub async fn read_message<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message too large: {len} bytes"),
        ));
    }
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

/// Write a 4-byte big-endian length-prefixed message.
pub async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> io::Result<()> {
    let len = payload.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

// ── Auth handshake ──────────────────────────────────────────────────────────

const CHALLENGE_PREFIX: &[u8] = b"#CHALLENGE#";
const SHA256_TAG: &[u8] = b"{sha256}";
const WELCOME: &[u8] = b"#WELCOME#";
const FAILURE: &[u8] = b"#FAILURE#";

/// Derive the default RPC auth key from a transport identity's private key.
///
/// `authkey = SHA-256(private_key_bytes)` — matches Python RNS behaviour.
pub fn derive_authkey(private_key: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(private_key);
    hasher.finalize().into()
}

/// Run the server side of the `multiprocessing.connection` HMAC auth handshake.
///
/// Returns `Ok(true)` if the client authenticated successfully, `Ok(false)` if
/// the client sent a wrong digest (a `#FAILURE#` response is sent), or `Err`
/// on I/O errors.
pub async fn server_auth<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    authkey: &[u8],
) -> io::Result<bool> {
    // 1. Generate challenge: #CHALLENGE#{sha256} + 20 random bytes (hex-encoded to 40 chars).
    let mut rng_bytes = [0u8; 20];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut rng_bytes);
    let nonce_hex = hex::encode(rng_bytes); // 40 ASCII hex chars

    let mut challenge = Vec::with_capacity(11 + 8 + 40);
    challenge.extend_from_slice(CHALLENGE_PREFIX);
    challenge.extend_from_slice(SHA256_TAG);
    challenge.extend_from_slice(nonce_hex.as_bytes());

    write_message(stream, &challenge).await?;

    // 2. Read client digest: {sha256} + 32 raw HMAC-SHA256 bytes (40 bytes total).
    let digest_msg = read_message(stream).await?;

    if digest_msg.len() < SHA256_TAG.len() + 32 {
        write_message(stream, FAILURE).await?;
        return Ok(false);
    }

    // Verify {sha256} prefix.
    if &digest_msg[..SHA256_TAG.len()] != SHA256_TAG {
        write_message(stream, FAILURE).await?;
        return Ok(false);
    }

    let client_hmac = &digest_msg[SHA256_TAG.len()..];

    // Verify HMAC-SHA256(authkey, challenge) using constant-time comparison.
    let mut mac = Hmac::<Sha256>::new_from_slice(authkey).expect("HMAC accepts any key length");
    mac.update(&challenge);
    if mac.verify_slice(client_hmac).is_err() {
        write_message(stream, FAILURE).await?;
        return Ok(false);
    }

    // 3. Send welcome.
    write_message(stream, WELCOME).await?;
    Ok(true)
}

// ── RPC dispatch ────────────────────────────────────────────────────────────

use crate::config::{SharedInstanceConfig, SharedInstanceType};
use crate::pickle::{self, PickleValue};
use std::sync::Arc;

/// Static interface info known at daemon startup.
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    /// e.g. "Shared Instance[rns/default]" or "Shared Instance[37428]"
    pub name: String,
    /// SHA-256(name) — 32 bytes.
    pub hash: [u8; 32],
}

impl InterfaceInfo {
    /// Build interface info from a shared-instance config.
    pub fn from_config(config: &SharedInstanceConfig) -> Self {
        let name = match config.shared_instance_type {
            SharedInstanceType::Unix => {
                format!("Shared Instance[rns/{}]", config.instance_name)
            }
            SharedInstanceType::Tcp => {
                format!("Shared Instance[{}]", config.shared_instance_port)
            }
        };
        let hash = {
            use sha2::Digest;
            let mut h = Sha256::new();
            h.update(name.as_bytes());
            h.finalize().into()
        };
        InterfaceInfo { name, hash }
    }
}

/// Context shared with the control listener.
pub struct ControlContext {
    authkey: Vec<u8>,
    iface_info: InterfaceInfo,
}

impl ControlContext {
    /// Create a new control context.
    pub fn new(authkey: Vec<u8>, iface_info: InterfaceInfo) -> Self {
        Self {
            authkey,
            iface_info,
        }
    }
}

/// Handle a decoded RPC request dict and return a response dict.
fn handle_rpc_request(request: &PickleValue, ctx: &ControlContext) -> PickleValue {
    // Check for "get" key.
    if let Some(cmd) = request.get("get") {
        if let Some(cmd_str) = cmd.as_str() {
            return match cmd_str {
                "interface_stats" => build_interface_stats(&ctx.iface_info),
                "path_table" => build_path_table(),
                "rate_table" => build_rate_table(),
                "link_count" => PickleValue::Int(0),
                "blackholed_identities" => PickleValue::List(Vec::new()),
                _ => PickleValue::None,
            };
        }
    }
    // Check for "drop" key.
    if request.get("drop").is_some() {
        return PickleValue::String("ok".into());
    }
    PickleValue::None
}

/// Build the `interface_stats` response matching Python RNS format.
fn build_interface_stats(iface: &InterfaceInfo) -> PickleValue {
    let iface_dict = PickleValue::Dict(vec![
        (s("clients"), PickleValue::Int(0)),
        (s("bitrate"), PickleValue::Int(1_000_000_000)),
        (s("rxs"), PickleValue::Float(0.0)),
        (s("txs"), PickleValue::Float(0.0)),
        (s("ifac_signature"), PickleValue::None),
        (s("ifac_size"), PickleValue::None),
        (s("ifac_netname"), PickleValue::None),
        (s("autoconnect_source"), PickleValue::None),
        (s("name"), PickleValue::String(iface.name.clone())),
        (s("short_name"), s("Reticulum")),
        (s("hash"), PickleValue::Bytes(iface.hash.to_vec())),
        (s("type"), s("LocalServerInterface")),
        (s("rxb"), PickleValue::Int(0)),
        (s("txb"), PickleValue::Int(0)),
        (s("incoming_announce_frequency"), PickleValue::Int(0)),
        (s("outgoing_announce_frequency"), PickleValue::Int(0)),
        (s("held_announces"), PickleValue::Int(0)),
        (s("status"), PickleValue::Bool(true)),
        (s("mode"), PickleValue::Int(1)),
    ]);

    PickleValue::Dict(vec![
        (s("interfaces"), PickleValue::List(vec![iface_dict])),
        (s("rxb"), PickleValue::Int(0)),
        (s("txb"), PickleValue::Int(0)),
        (s("rxs"), PickleValue::Float(0.0)),
        (s("txs"), PickleValue::Float(0.0)),
        (s("rss"), PickleValue::None),
    ])
}

/// Build an empty path table response.
fn build_path_table() -> PickleValue {
    PickleValue::Dict(Vec::new())
}

/// Build an empty rate table response.
fn build_rate_table() -> PickleValue {
    PickleValue::Dict(Vec::new())
}

fn s(v: &str) -> PickleValue {
    PickleValue::String(v.into())
}

// ── Control listener ────────────────────────────────────────────────────────

/// Handle a single authenticated RPC connection.
async fn handle_rpc_connection<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    ctx: &ControlContext,
) -> io::Result<()> {
    // Read request pickle.
    let request_bytes = read_message(stream).await?;
    let request = pickle::decode(&request_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("pickle decode: {e}")))?;

    // Dispatch.
    let response = handle_rpc_request(&request, ctx);

    // Encode and send response.
    let response_bytes = pickle::encode(&response);
    write_message(stream, &response_bytes).await?;
    Ok(())
}

/// Run the Unix control listener accept loop.
#[cfg(unix)]
pub async fn run_unix_control_listener(
    instance_name: &str,
    ctx: Arc<ControlContext>,
) -> io::Result<()> {
    use tokio::net::UnixListener;

    let socket_path = format!("\0rns/{}/rpc", instance_name);
    let listener = UnixListener::bind(&socket_path)?;
    eprintln!(
        "[rete-shared] control listener bound (unix: rns/{}/rpc)",
        instance_name
    );

    loop {
        let (stream, _addr) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let mut stream = stream;
            if let Err(e) = handle_control_connection(&mut stream, &ctx).await {
                eprintln!("[rete-shared] control connection error: {e}");
            }
        });
    }
}

/// Run the TCP control listener accept loop.
pub async fn run_tcp_control_listener(port: u16, ctx: Arc<ControlContext>) -> io::Result<()> {
    use tokio::net::TcpListener;

    let addr = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&addr).await?;
    eprintln!("[rete-shared] control listener bound (tcp: {addr})");

    loop {
        let (mut stream, _addr) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_control_connection(&mut stream, &ctx).await {
                eprintln!("[rete-shared] control connection error: {e}");
            }
        });
    }
}

/// Handle a single control connection: auth → RPC request → response → close.
async fn handle_control_connection<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    ctx: &ControlContext,
) -> io::Result<()> {
    // Auth handshake.
    let authed = server_auth(stream, &ctx.authkey).await?;
    if !authed {
        return Ok(());
    }

    // Handle RPC request.
    handle_rpc_connection(stream, ctx).await
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a golden auth fixture into its length-prefixed messages.
    fn parse_auth_fixture(data: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
        let mut messages = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            if pos + 4 > data.len() {
                return Err("truncated length prefix");
            }
            let len = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                as usize;
            pos += 4;
            if pos + len > data.len() {
                return Err("truncated message payload");
            }
            messages.push(data[pos..pos + len].to_vec());
            pos += len;
        }
        Ok(messages)
    }

    const FIXTURE_DIR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/shared-instance/unix/control-status-query"
    );

    // ── Framing tests ───────────────────────────────────────────────────

    #[tokio::test]
    async fn framing_roundtrip() {
        let payload = b"hello world";
        let mut buf = Vec::new();
        write_message(&mut buf, payload).await.unwrap();

        // Check wire format: 4-byte BE length + payload.
        assert_eq!(buf.len(), 4 + payload.len());
        assert_eq!(&buf[..4], &(payload.len() as u32).to_be_bytes());

        let mut cursor = io::Cursor::new(buf);
        let decoded = read_message(&mut cursor).await.unwrap();
        assert_eq!(decoded, payload);
    }

    #[tokio::test]
    async fn framing_golden_auth_first_message() {
        // First 4 bytes of rpc_auth.bin should be 0x0000003b (59).
        let data = std::fs::read(format!("{FIXTURE_DIR}/rpc_auth.bin")).unwrap();
        assert_eq!(
            u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            59,
            "first auth message length should be 59"
        );
    }

    // ── Auth fixture parsing ────────────────────────────────────────────

    #[test]
    fn parse_golden_auth_messages() {
        let data = std::fs::read(format!("{FIXTURE_DIR}/rpc_auth.bin")).unwrap();
        assert_eq!(data.len(), 120);

        let messages = parse_auth_fixture(&data).unwrap();
        assert_eq!(messages.len(), 3, "auth fixture should have 3 messages");

        // Message 1: CHALLENGE — 59 bytes, starts with #CHALLENGE#{sha256}
        assert_eq!(messages[0].len(), 59);
        assert!(messages[0].starts_with(b"#CHALLENGE#{sha256}"));

        // Message 2: DIGEST — 40 bytes, starts with {sha256}
        assert_eq!(messages[1].len(), 40);
        assert!(messages[1].starts_with(b"{sha256}"));

        // Message 3: WELCOME — 9 bytes
        assert_eq!(messages[2].len(), 9);
        assert_eq!(&messages[2], b"#WELCOME#");
    }

    #[test]
    fn hmac_sha256_computation() {
        // Verify that we can compute the same HMAC as in the golden fixture.
        let data = std::fs::read(format!("{FIXTURE_DIR}/rpc_auth.bin")).unwrap();
        let messages = parse_auth_fixture(&data).unwrap();

        // We need the authkey to verify. Since we don't have the identity file
        // from the golden trace, we just verify the structure and that our
        // HMAC code produces consistent results with a known key.
        let test_key = b"test-auth-key-for-unit-test-only";
        let challenge = &messages[0];

        let mut mac = Hmac::<Sha256>::new_from_slice(test_key).unwrap();
        mac.update(challenge);
        let digest = mac.finalize().into_bytes();
        assert_eq!(digest.len(), 32);

        // Verify consistency: same key + same challenge = same digest.
        let mut mac2 = Hmac::<Sha256>::new_from_slice(test_key).unwrap();
        mac2.update(challenge);
        let digest2 = mac2.finalize().into_bytes();
        assert_eq!(digest, digest2);
    }

    // ── Live auth handshake test ────────────────────────────────────────

    #[tokio::test]
    async fn auth_success() {
        let authkey = derive_authkey(b"test-private-key-bytes");
        let (client, server) = tokio::io::duplex(1024);
        let (mut client_r, mut client_w) = tokio::io::split(client);
        let mut server = server;

        let server_task =
            tokio::spawn(async move { server_auth(&mut server, &authkey).await.unwrap() });

        // Client side: read challenge, compute HMAC, send digest.
        let challenge = read_message(&mut client_r).await.unwrap();
        assert!(challenge.starts_with(b"#CHALLENGE#{sha256}"));

        let mut mac = Hmac::<Sha256>::new_from_slice(&authkey).unwrap();
        mac.update(&challenge);
        let digest = mac.finalize().into_bytes();

        let mut response = Vec::with_capacity(8 + 32);
        response.extend_from_slice(b"{sha256}");
        response.extend_from_slice(&digest);
        write_message(&mut client_w, &response).await.unwrap();

        // Read welcome.
        let welcome = read_message(&mut client_r).await.unwrap();
        assert_eq!(welcome, b"#WELCOME#");

        assert!(server_task.await.unwrap());
    }

    #[tokio::test]
    async fn auth_failure_wrong_key() {
        let authkey = derive_authkey(b"correct-key");
        let (client, server) = tokio::io::duplex(1024);
        let (mut client_r, mut client_w) = tokio::io::split(client);
        let mut server = server;

        let server_task =
            tokio::spawn(async move { server_auth(&mut server, &authkey).await.unwrap() });

        // Client side: read challenge, compute HMAC with WRONG key.
        let challenge = read_message(&mut client_r).await.unwrap();

        let wrong_key = derive_authkey(b"wrong-key");
        let mut mac = Hmac::<Sha256>::new_from_slice(&wrong_key).unwrap();
        mac.update(&challenge);
        let digest = mac.finalize().into_bytes();

        let mut response = Vec::with_capacity(8 + 32);
        response.extend_from_slice(b"{sha256}");
        response.extend_from_slice(&digest);
        write_message(&mut client_w, &response).await.unwrap();

        // Read failure.
        let failure = read_message(&mut client_r).await.unwrap();
        assert_eq!(failure, b"#FAILURE#");

        assert!(!server_task.await.unwrap());
    }
}
