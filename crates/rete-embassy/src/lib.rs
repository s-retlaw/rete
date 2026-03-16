//! rete-embassy — Embassy runtime harness for Reticulum.
//!
//! Provides [`EmbassyNode`] which drives transport + interfaces in an async
//! event loop using `embassy_futures::select::select3`.
//!
//! This crate is runtime-agnostic in the sense that it does not import any
//! specific executor — only `embassy-time` (for timers) and `embassy-futures`
//! (for `select3`). The executor is the caller's concern.

#![no_std]
extern crate alloc;

use alloc::vec::Vec;

use embassy_futures::select::{select3, Either3};
use embassy_time::{Duration, Instant, Timer};
use rand_core::{CryptoRng, RngCore};
use rete_core::hdlc::{self, HdlcDecoder, MAX_ENCODED};
use rete_core::{Identity, MTU};
pub use rete_stack::NodeEvent;
pub use rete_stack::ProofStrategy;
use rete_stack::{EmbeddedNodeCore, PacketRouting, ReteInterface};
use rete_transport::{ANNOUNCE_INTERVAL_SECS, TICK_INTERVAL_SECS};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors from an Embassy HDLC interface.
#[derive(Debug)]
pub enum EmbassyError<E> {
    /// Underlying transport I/O error.
    Io(E),
    /// HDLC encoding error (buffer too small).
    Encode(rete_core::Error),
    /// Connection closed by remote (read returned 0 bytes).
    Disconnected,
}

// ---------------------------------------------------------------------------
// EmbassyHdlcInterface — generic HDLC-framed interface
// ---------------------------------------------------------------------------

/// HDLC-framed interface generic over any `embedded_io_async` transport.
///
/// Works with `embassy_net::tcp::TcpSocket`, UART, or any async transport
/// that implements `embedded_io_async::Read + Write`.
pub struct EmbassyHdlcInterface<T> {
    transport: T,
    decoder: HdlcDecoder<{ MTU }>,
    read_buf: [u8; 256],
    /// Current read position within `read_buf` (unconsumed bytes start here).
    read_pos: usize,
    /// Number of valid bytes in `read_buf`.
    read_len: usize,
    /// Reusable HDLC encode buffer (avoids 1KB stack allocation per send).
    encode_buf: [u8; MAX_ENCODED],
}

impl<T> EmbassyHdlcInterface<T> {
    /// Wrap an async transport in HDLC framing.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            decoder: HdlcDecoder::new(),
            read_buf: [0u8; 256],
            read_pos: 0,
            read_len: 0,
            encode_buf: [0u8; MAX_ENCODED],
        }
    }
}

impl<T> ReteInterface for EmbassyHdlcInterface<T>
where
    T: embedded_io_async::Read + embedded_io_async::Write,
{
    type Error = EmbassyError<T::Error>;

    async fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
        let n = hdlc::encode(frame, &mut self.encode_buf).map_err(EmbassyError::Encode)?;
        self.transport
            .write_all(&self.encode_buf[..n])
            .await
            .map_err(EmbassyError::Io)?;
        self.transport.flush().await.map_err(EmbassyError::Io)?;
        Ok(())
    }

    async fn recv<'a>(&mut self, buf: &'a mut [u8]) -> Result<&'a [u8], Self::Error> {
        loop {
            // First drain any leftover bytes from previous read
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
                        // Frame too large for caller's buffer — skip it
                    }
                }
            }

            // Read more from transport
            let n = self
                .transport
                .read(&mut self.read_buf)
                .await
                .map_err(EmbassyError::Io)?;
            if n == 0 {
                return Err(EmbassyError::Disconnected);
            }
            self.read_pos = 0;
            self.read_len = n;
        }
    }
}

// ---------------------------------------------------------------------------
// EmbassyNode
// ---------------------------------------------------------------------------

/// A Reticulum node for Embassy-based targets.
///
/// Thin wrapper around [`EmbeddedNodeCore`] that provides the Embassy async
/// event loop with `select3` and timer management.
pub struct EmbassyNode {
    /// Shared node logic (identity, transport, packet processing).
    pub core: EmbeddedNodeCore,
    /// Epoch offset: seconds to add to monotonic uptime to approximate Unix time.
    epoch_offset: u64,
}

impl EmbassyNode {
    /// Create a new node with the given identity and destination.
    pub fn new(identity: Identity, app_name: &str, aspects: &[&str]) -> Self {
        EmbassyNode {
            core: EmbeddedNodeCore::new(identity, app_name, aspects),
            epoch_offset: 0,
        }
    }

    /// Set the epoch offset so announce timestamps approximate Unix time.
    pub fn set_epoch_offset(&mut self, offset: u64) {
        self.epoch_offset = offset;
    }

    /// Current time for announce timestamps: monotonic uptime + epoch offset.
    fn announce_time(&self) -> u64 {
        Instant::now().as_secs().wrapping_add(self.epoch_offset)
    }

    /// Build and return a raw announce packet for this node.
    pub fn build_announce<R: RngCore + CryptoRng>(
        &self,
        app_data: Option<&[u8]>,
        rng: &mut R,
    ) -> Vec<u8> {
        let now = self.announce_time();
        self.core.build_announce(app_data, rng, now)
    }

    /// Run the main event loop with a single interface.
    pub async fn run<I, R, F>(&mut self, iface: &mut I, rng: &mut R, mut on_event: F)
    where
        I: ReteInterface,
        R: RngCore + CryptoRng,
        F: FnMut(NodeEvent),
    {
        // Send initial announce
        let announce = self.build_announce(None, rng);
        let _ = iface.send(&announce).await;

        let mut recv_buf = [0u8; MTU];
        let mut next_announce = Instant::now() + Duration::from_secs(ANNOUNCE_INTERVAL_SECS);
        let mut next_tick = Instant::now() + Duration::from_secs(TICK_INTERVAL_SECS);

        loop {
            match select3(
                iface.recv(&mut recv_buf),
                Timer::at(next_announce),
                Timer::at(next_tick),
            )
            .await
            {
                Either3::First(result) => match result {
                    Ok(data) => {
                        let now = Instant::now().as_secs();
                        let outcome = self.core.handle_ingest(data, now, 0, rng);
                        for pkt in &outcome.packets {
                            // Single interface: skip AllExceptSource (would echo back to source)
                            if pkt.routing == PacketRouting::AllExceptSource {
                                continue;
                            }
                            let _ = iface.send(&pkt.data).await;
                        }
                        if let Some(event) = outcome.event {
                            on_event(event);
                        }
                    }
                    Err(_) => break,
                },
                Either3::Second(()) => {
                    next_announce = Instant::now() + Duration::from_secs(ANNOUNCE_INTERVAL_SECS);
                    let announce = self.build_announce(None, rng);
                    let _ = iface.send(&announce).await;
                }
                Either3::Third(()) => {
                    next_tick = Instant::now() + Duration::from_secs(TICK_INTERVAL_SECS);
                    let now = Instant::now().as_secs();
                    let outcome = self.core.handle_tick(now, rng);
                    for pkt in &outcome.packets {
                        let _ = iface.send(&pkt.data).await;
                    }
                    if let Some(event) = outcome.event {
                        on_event(event);
                    }
                }
            }
        }
    }
}
