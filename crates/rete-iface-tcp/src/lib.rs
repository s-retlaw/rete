//! rete-iface-tcp — TCP interface with HDLC framing for Reticulum.
//!
//! Connects to a Python `rnsd` or another Reticulum TCP transport node.
//! Packets are framed using HDLC byte-stuffing (FLAG=0x7E, ESC=0x7D).
//!
//! Optionally supports Interface Access Codes (IFAC) for per-interface
//! packet authentication. When an [`IfacKey`] is set, outgoing packets are
//! signed and XOR-masked, and incoming packets are verified and unmasked.

use rete_core::hdlc::{self, HdlcDecoder, MAX_ENCODED};
use rete_core::ifac::IfacKey;
use rete_stack::ReteInterface;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// TCP interface for Reticulum — HDLC-framed packets over a TCP stream.
pub struct TcpInterface {
    stream: TcpStream,
    decoder: HdlcDecoder<{ rete_core::MTU + rete_core::DEFAULT_IFAC_SIZE }>,
    read_buf: [u8; 1024],
    read_pos: usize,
    read_len: usize,
    ifac: Option<IfacKey>,
}

/// Errors from the TCP interface.
#[derive(Debug)]
pub enum TcpError {
    /// Underlying I/O error.
    Io(std::io::Error),
    /// HDLC encoding error (buffer too small — shouldn't happen with MTU-sized packets).
    Encode(rete_core::Error),
    /// IFAC protection/verification error.
    Ifac(rete_core::Error),
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
            TcpError::Ifac(e) => write!(f, "IFAC error: {e}"),
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
            read_pos: 0,
            read_len: 0,
            ifac: None,
        })
    }

    /// Create from an existing TcpStream.
    pub fn from_stream(stream: TcpStream) -> Self {
        TcpInterface {
            stream,
            decoder: HdlcDecoder::new(),
            read_buf: [0u8; 1024],
            read_pos: 0,
            read_len: 0,
            ifac: None,
        }
    }

    /// Set the IFAC key for this interface.
    ///
    /// When set, all outgoing packets are IFAC-protected (signed + masked)
    /// and all incoming packets must pass IFAC verification (unmask + verify).
    /// Packets without valid IFAC tags are silently dropped on receive.
    pub fn set_ifac(&mut self, ifac: IfacKey) {
        self.ifac = Some(ifac);
    }
}

impl ReteInterface for TcpInterface {
    type Error = TcpError;

    async fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
        // If IFAC is enabled, protect (sign + mask) before HDLC encoding
        let to_encode: &[u8];
        let mut ifac_buf = [0u8; 600]; // MTU + max IFAC tag size
        let ifac_len;

        if let Some(ref ifac) = self.ifac {
            ifac_len = ifac.protect(frame, &mut ifac_buf).map_err(TcpError::Ifac)?;
            to_encode = &ifac_buf[..ifac_len];
        } else {
            to_encode = frame;
        }

        let mut encoded = [0u8; MAX_ENCODED];
        let n = hdlc::encode(to_encode, &mut encoded).map_err(TcpError::Encode)?;
        self.stream.write_all(&encoded[..n]).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn recv<'a>(&mut self, buf: &'a mut [u8]) -> Result<&'a [u8], Self::Error> {
        loop {
            // Drain leftover bytes from previous read
            while self.read_pos < self.read_len {
                let byte = self.read_buf[self.read_pos];
                self.read_pos += 1;
                if self.decoder.feed(byte) {
                    if let Some(frame) = self.decoder.frame() {
                        if let Some(ref ifac) = self.ifac {
                            // IFAC enabled: check flag and unprotect
                            if !IfacKey::has_ifac_flag(frame) {
                                // No IFAC flag on IFAC-enabled interface: drop
                                continue;
                            }
                            // Unprotect into buf
                            match ifac.unprotect(frame, buf) {
                                Ok(len) => return Ok(&buf[..len]),
                                Err(_) => {
                                    // Invalid IFAC: silently drop
                                    continue;
                                }
                            }
                        } else {
                            // No IFAC: drop packets with IFAC flag set
                            if IfacKey::has_ifac_flag(frame) {
                                continue;
                            }
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

            // Read more from transport
            let n = self.stream.read(&mut self.read_buf).await?;
            if n == 0 {
                return Err(TcpError::Disconnected);
            }
            self.read_pos = 0;
            self.read_len = n;
        }
    }
}
