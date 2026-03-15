//! rete-iface-tcp — TCP interface with HDLC framing for Reticulum.
//!
//! Connects to a Python `rnsd` or another Reticulum TCP transport node.
//! Packets are framed using HDLC byte-stuffing (FLAG=0x7E, ESC=0x7D).

use rete_core::hdlc::{self, HdlcDecoder};
use rete_stack::ReteInterface;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Maximum HDLC-encoded frame size (worst case: every byte escaped + 2 flags).
const MAX_ENCODED: usize = rete_core::MTU * 2 + 2;

/// TCP interface for Reticulum — HDLC-framed packets over a TCP stream.
pub struct TcpInterface {
    stream: TcpStream,
    decoder: HdlcDecoder<{ rete_core::MTU }>,
    read_buf: [u8; 1024],
}

/// Errors from the TCP interface.
#[derive(Debug)]
pub enum TcpError {
    /// Underlying I/O error.
    Io(std::io::Error),
    /// HDLC encoding error (buffer too small — shouldn't happen with MTU-sized packets).
    Encode(rete_core::Error),
    /// Connection closed by remote.
    Disconnected,
}

impl From<std::io::Error> for TcpError {
    fn from(e: std::io::Error) -> Self {
        TcpError::Io(e)
    }
}

impl core::fmt::Display for TcpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TcpError::Io(e) => write!(f, "TCP I/O error: {e}"),
            TcpError::Encode(e) => write!(f, "HDLC encode error: {e}"),
            TcpError::Disconnected => write!(f, "TCP connection closed"),
        }
    }
}

impl TcpInterface {
    /// Connect to a Reticulum TCP transport at the given address.
    pub async fn connect(addr: &str) -> Result<Self, TcpError> {
        let stream = TcpStream::connect(addr).await?;
        Ok(TcpInterface {
            stream,
            decoder: HdlcDecoder::new(),
            read_buf: [0u8; 1024],
        })
    }

    /// Create from an existing TcpStream.
    pub fn from_stream(stream: TcpStream) -> Self {
        TcpInterface {
            stream,
            decoder: HdlcDecoder::new(),
            read_buf: [0u8; 1024],
        }
    }
}

impl ReteInterface for TcpInterface {
    type Error = TcpError;

    async fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
        let mut encoded = [0u8; MAX_ENCODED];
        let n = hdlc::encode(frame, &mut encoded).map_err(TcpError::Encode)?;
        self.stream.write_all(&encoded[..n]).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn recv<'a>(&mut self, buf: &'a mut [u8]) -> Result<&'a [u8], Self::Error> {
        loop {
            let n = self.stream.read(&mut self.read_buf).await?;
            if n == 0 {
                return Err(TcpError::Disconnected);
            }

            for i in 0..n {
                if self.decoder.feed(self.read_buf[i]) {
                    // Complete frame available
                    if let Some(frame) = self.decoder.frame() {
                        let len = frame.len();
                        if len <= buf.len() {
                            buf[..len].copy_from_slice(frame);
                            return Ok(&buf[..len]);
                        }
                        // Frame too large for caller's buffer — skip it
                    }
                }
            }
        }
    }
}
