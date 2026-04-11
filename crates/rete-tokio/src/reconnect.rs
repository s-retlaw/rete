//! Auto-reconnecting interface wrappers with exponential backoff.
//!
//! These wrappers implement [`ReteInterface`] and transparently reconnect
//! when the underlying connection drops or isn't available at startup.
//! The daemon never exits due to a connection failure — it retries forever
//! with exponential backoff (1 s → 2 s → 4 s → … → 60 s).

use rete_core::ifac::IfacKey;
use rete_iface_serial::{SerialError, SerialInterface};
use rete_iface_tcp::{TcpError, TcpInterface};
use rete_stack::ReteInterface;
use std::time::Duration;

/// IFAC configuration — stored so we can re-derive the key on each reconnect
/// (IfacKey is intentionally non-Clone for security).
struct IfacConfig {
    netname: Option<String>,
    netkey: Option<String>,
}

impl IfacConfig {
    fn derive(&self) -> Option<IfacKey> {
        IfacKey::derive(self.netname.as_deref(), self.netkey.as_deref()).ok()
    }
}

// ---------------------------------------------------------------------------
// ReconnectingTcpClient
// ---------------------------------------------------------------------------

/// A [`TcpInterface`] wrapper that reconnects with exponential backoff.
///
/// If the remote is unavailable at startup or the connection drops at
/// runtime, this client will automatically re-establish the connection.
/// It retries forever — a configured `--connect` address is always desired.
pub struct ReconnectingTcpClient {
    addr: String,
    inner: Option<TcpInterface>,
    ifac: Option<IfacConfig>,
    base_delay: Duration,
    max_delay: Duration,
}

impl ReconnectingTcpClient {
    /// Create a reconnecting TCP client for the given address.
    ///
    /// No connection is attempted until the first send/recv.
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            inner: None,
            ifac: None,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
        }
    }

    /// Set IFAC parameters. The key is re-derived on each reconnect.
    pub fn set_ifac(&mut self, netname: Option<&str>, netkey: Option<&str>) {
        self.ifac = Some(IfacConfig {
            netname: netname.map(String::from),
            netkey: netkey.map(String::from),
        });
    }

    /// Attempt to connect (or reconnect) with exponential backoff.
    /// Retries forever — returns only on success.
    async fn ensure_connected(&mut self) {
        if self.inner.is_some() {
            return;
        }

        let mut delay = self.base_delay;
        loop {
            match TcpInterface::connect(&self.addr).await {
                Ok(mut iface) => {
                    if let Some(ref cfg) = self.ifac {
                        if let Some(key) = cfg.derive() {
                            iface.set_ifac(key);
                        }
                    }
                    tracing::info!("[rete-tcp] connected to {}", self.addr);
                    self.inner = Some(iface);
                    return;
                }
                Err(e) => {
                    tracing::debug!(
                        "[rete-tcp] connect to {} failed: {e}, retrying in {delay:?}",
                        self.addr,
                    );
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(self.max_delay);
                }
            }
        }
    }
}

impl ReteInterface for ReconnectingTcpClient {
    type Error = TcpError;

    async fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
        self.ensure_connected().await;
        let iface = self.inner.as_mut().unwrap();
        match iface.send(frame).await {
            Ok(()) => Ok(()),
            Err(e) => {
                tracing::debug!("[rete-tcp] send to {} failed, will reconnect: {e}", self.addr);
                self.inner = None;
                Err(e)
            }
        }
    }

    async fn recv<'a>(&mut self, buf: &'a mut [u8]) -> Result<&'a [u8], Self::Error> {
        loop {
            self.ensure_connected().await;
            let iface = self.inner.as_mut().unwrap();
            match iface.recv(buf).await {
                Ok(data) => {
                    let len = data.len();
                    return Ok(&buf[..len]);
                }
                Err(e) => {
                    tracing::debug!(
                        "[rete-tcp] recv from {} failed, will reconnect: {e}",
                        self.addr,
                    );
                    self.inner = None;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ReconnectingSerial
// ---------------------------------------------------------------------------

/// A [`SerialInterface`] wrapper that reconnects with exponential backoff.
///
/// If the serial port is unavailable at startup (USB device not yet
/// plugged in) or disconnects at runtime, this wrapper will retry
/// opening the port forever.
pub struct ReconnectingSerial {
    path: String,
    baud: u32,
    inner: Option<SerialInterface>,
    base_delay: Duration,
    max_delay: Duration,
}

impl ReconnectingSerial {
    /// Create a reconnecting serial interface for the given port.
    ///
    /// No port open is attempted until the first send/recv.
    pub fn new(path: impl Into<String>, baud: u32) -> Self {
        Self {
            path: path.into(),
            baud,
            inner: None,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
        }
    }

    /// Attempt to open (or reopen) with exponential backoff.
    /// Retries forever — returns only on success.
    async fn ensure_connected(&mut self) {
        if self.inner.is_some() {
            return;
        }

        let mut delay = self.base_delay;
        loop {
            match SerialInterface::open(&self.path, self.baud) {
                Ok(iface) => {
                    tracing::info!("[rete-serial] opened {} at {} baud", self.path, self.baud);
                    self.inner = Some(iface);
                    return;
                }
                Err(e) => {
                    tracing::debug!(
                        "[rete-serial] open {} failed: {e}, retrying in {delay:?}",
                        self.path,
                    );
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(self.max_delay);
                }
            }
        }
    }
}

impl ReteInterface for ReconnectingSerial {
    type Error = SerialError;

    async fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
        self.ensure_connected().await;
        let iface = self.inner.as_mut().unwrap();
        match iface.send(frame).await {
            Ok(()) => Ok(()),
            Err(e) => {
                tracing::debug!(
                    "[rete-serial] send on {} failed, will reconnect: {e}",
                    self.path,
                );
                self.inner = None;
                Err(e)
            }
        }
    }

    async fn recv<'a>(&mut self, buf: &'a mut [u8]) -> Result<&'a [u8], Self::Error> {
        loop {
            self.ensure_connected().await;
            let iface = self.inner.as_mut().unwrap();
            match iface.recv(buf).await {
                Ok(data) => {
                    let len = data.len();
                    return Ok(&buf[..len]);
                }
                Err(e) => {
                    tracing::debug!(
                        "[rete-serial] recv on {} failed, will reconnect: {e}",
                        self.path,
                    );
                    self.inner = None;
                }
            }
        }
    }
}
