//! rete-iface-serial — Serial port interface with HDLC framing for Reticulum.
//!
//! Connects to an ESP32 (or any device) running rete over a serial port.
//! Packets are framed using HDLC byte-stuffing, same as the TCP interface.
//!
//! Non-HDLC bytes (bootloader output, log messages) on the serial line are
//! silently ignored by the HDLC decoder.

use rete_core::hdlc::{self, HdlcDecoder};
use rete_stack::ReteInterface;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_serial::SerialStream;

/// Maximum HDLC-encoded frame size (worst case: every byte escaped + 2 flags).
const MAX_ENCODED: usize = rete_core::MTU * 2 + 2;

/// Serial interface for Reticulum — HDLC-framed packets over a serial port.
pub struct SerialInterface {
    port: SerialStream,
    decoder: HdlcDecoder<{ rete_core::MTU }>,
    read_buf: [u8; 256],
    read_pos: usize,
    read_len: usize,
}

/// Errors from the serial interface.
#[derive(Debug)]
pub enum SerialError {
    /// Underlying I/O error.
    Io(std::io::Error),
    /// HDLC encoding error (buffer too small).
    Encode(rete_core::Error),
    /// Port closed / EOF.
    Disconnected,
}

impl From<std::io::Error> for SerialError {
    fn from(e: std::io::Error) -> Self {
        SerialError::Io(e)
    }
}

impl From<tokio_serial::Error> for SerialError {
    fn from(e: tokio_serial::Error) -> Self {
        SerialError::Io(e.into())
    }
}

impl core::fmt::Display for SerialError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SerialError::Io(e) => write!(f, "serial I/O error: {e}"),
            SerialError::Encode(e) => write!(f, "HDLC encode error: {e}"),
            SerialError::Disconnected => write!(f, "serial port closed"),
        }
    }
}

impl SerialInterface {
    /// Open a serial port for Reticulum communication.
    ///
    /// `path` is the device path (e.g. `/dev/ttyACM0` on Linux).
    /// `baud_rate` is typically 115200 (ignored for USB-CDC devices).
    pub fn open(path: &str, baud_rate: u32) -> Result<Self, SerialError> {
        let builder = tokio_serial::new(path, baud_rate);
        let port = SerialStream::open(&builder)?;
        Ok(SerialInterface {
            port,
            decoder: HdlcDecoder::new(),
            read_buf: [0u8; 256],
            read_pos: 0,
            read_len: 0,
        })
    }
}

impl ReteInterface for SerialInterface {
    type Error = SerialError;

    async fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
        let mut encoded = [0u8; MAX_ENCODED];
        let n = hdlc::encode(frame, &mut encoded).map_err(SerialError::Encode)?;
        self.port.write_all(&encoded[..n]).await?;
        self.port.flush().await?;
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
                        let len = frame.len();
                        if len <= buf.len() {
                            buf[..len].copy_from_slice(frame);
                            return Ok(&buf[..len]);
                        }
                        // Frame too large — skip
                    }
                }
            }

            // Read more from serial port
            let n = self.port.read(&mut self.read_buf).await?;
            if n == 0 {
                return Err(SerialError::Disconnected);
            }
            self.read_pos = 0;
            self.read_len = n;
        }
    }
}
