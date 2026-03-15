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

use alloc::string::String;
use alloc::vec::Vec;

use embassy_futures::select::{select3, Either3};
use embassy_time::{Duration, Instant, Timer};
use rand_core::{CryptoRng, RngCore};
use rete_core::hdlc::{self, HdlcDecoder, MAX_ENCODED};
use rete_core::{
    DestType, HeaderType, Identity, PacketBuilder, PacketType, MTU, TRUNCATED_HASH_LEN,
};
use rete_stack::ReteInterface;
pub use rete_stack::NodeEvent;
use rete_transport::{EmbeddedTransport, IngestResult, Transport, ANNOUNCE_INTERVAL_SECS, TICK_INTERVAL_SECS};

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
/// Owns the transport state machine and drives one or more interfaces.
/// Uses [`EmbeddedTransport`] (conservative memory) suitable for MCUs.
pub struct EmbassyNode {
    /// The local identity for this node.
    pub identity: Identity,
    /// Transport state (path table, announce queue, dedup).
    pub transport: EmbeddedTransport,
    /// Application name for our destination.
    app_name: String,
    /// Destination aspects.
    aspects: Vec<String>,
    /// Our destination hash.
    dest_hash: [u8; TRUNCATED_HASH_LEN],
    /// Optional auto-reply message sent after receiving an announce.
    auto_reply: Option<Vec<u8>>,
    /// When true, echo received DATA back to sender with "echo:" prefix.
    echo_data: bool,
    /// Dest hash of the most recently announced peer (echo target).
    last_peer: Option<[u8; TRUNCATED_HASH_LEN]>,
    /// Epoch offset: seconds to add to monotonic uptime to approximate Unix time.
    /// Set via [`set_epoch_offset`] after obtaining wall-clock time (e.g. from NTP).
    /// Used only for announce timestamp bytes; path expiry uses monotonic time.
    epoch_offset: u64,
}

impl EmbassyNode {
    /// Create a new node with the given identity and destination.
    pub fn new(identity: Identity, app_name: &str, aspects: &[&str]) -> Self {
        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name(app_name, aspects, &mut name_buf)
            .expect("app_name + aspects must fit in 128 bytes");
        let id_hash = identity.hash();
        let dest_hash = rete_core::destination_hash(expanded, Some(&id_hash));

        EmbassyNode {
            identity,
            transport: Transport::new(),
            app_name: String::from(app_name),
            aspects: aspects.iter().map(|s| String::from(*s)).collect(),
            dest_hash,
            auto_reply: None,
            echo_data: false,
            last_peer: None,
            epoch_offset: 0,
        }
    }

    /// Returns our destination hash.
    pub fn dest_hash(&self) -> &[u8; TRUNCATED_HASH_LEN] {
        &self.dest_hash
    }

    /// Set an auto-reply message sent to any peer that announces.
    pub fn set_auto_reply(&mut self, msg: Option<Vec<u8>>) {
        self.auto_reply = msg;
    }

    /// Enable echo mode: received DATA is sent back to the sender with "echo:" prefix.
    pub fn set_echo_data(&mut self, echo: bool) {
        self.echo_data = echo;
    }

    /// Set the epoch offset so announce timestamps approximate Unix time.
    ///
    /// Call this after obtaining wall-clock time (e.g. from NTP or SNTP):
    /// ```ignore
    /// let unix_now: u64 = /* seconds since 1970-01-01 from NTP */;
    /// node.set_epoch_offset(unix_now - embassy_time::Instant::now().as_secs());
    /// ```
    ///
    /// If not set, announce timestamps use monotonic uptime (seconds since boot).
    /// Path expiry and announce backoff always use monotonic time regardless.
    pub fn set_epoch_offset(&mut self, offset: u64) {
        self.epoch_offset = offset;
    }

    /// Current time for announce timestamps: monotonic uptime + epoch offset.
    fn announce_time(&self) -> u64 {
        Instant::now().as_secs().wrapping_add(self.epoch_offset)
    }

    /// Build an encrypted DATA packet addressed to a known destination.
    fn build_data_packet<R: RngCore + CryptoRng>(
        &self,
        dest_hash: &[u8; TRUNCATED_HASH_LEN],
        plaintext: &[u8],
        rng: &mut R,
    ) -> Option<Vec<u8>> {
        let pub_key = self.transport.recall_identity(dest_hash)?;
        let recipient = Identity::from_public_key(pub_key).ok()?;
        let mut ct_buf = [0u8; MTU];
        let ct_len = recipient.encrypt(plaintext, rng, &mut ct_buf).ok()?;
        let via = self.transport.get_path(dest_hash).and_then(|p| p.via);
        let mut pkt_buf = [0u8; MTU];
        let builder = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Single)
            .destination_hash(dest_hash)
            .context(0x00)
            .payload(&ct_buf[..ct_len]);
        let builder = if let Some(transport_id) = via {
            builder
                .header_type(HeaderType::Header2)
                .transport_type(1)
                .transport_id(&transport_id)
        } else {
            builder
        };
        let pkt_len = builder.build().ok()?;
        Some(pkt_buf[..pkt_len].to_vec())
    }

    /// Build and return a raw announce packet for this node.
    pub fn build_announce<R: RngCore + CryptoRng>(
        &self,
        app_data: Option<&[u8]>,
        rng: &mut R,
    ) -> Vec<u8> {
        let aspects_refs: Vec<&str> = self.aspects.iter().map(|s| s.as_str()).collect();
        let now = self.announce_time();
        let mut buf = [0u8; MTU];
        let n = Transport::<1024, 256, 4096>::create_announce(
            &self.identity,
            &self.app_name,
            &aspects_refs,
            app_data,
            rng,
            now,
            &mut buf,
        )
        .expect("announce creation should not fail");
        buf[..n].to_vec()
    }

    /// Run the main event loop with a single interface.
    ///
    /// Uses `embassy_futures::select::select3` over three branches:
    /// - Receive packets from the interface -> ingest -> emit events
    /// - Periodically re-announce
    /// - Periodically tick (expire paths, retransmit announces)
    ///
    /// Timers use absolute deadlines (`Timer::at`) so they fire on schedule
    /// regardless of how often the recv branch wins.
    ///
    /// The `on_event` callback is invoked for each event.
    pub async fn run<I, R, F>(
        &mut self,
        iface: &mut I,
        rng: &mut R,
        mut on_event: F,
    ) where
        I: ReteInterface,
        R: RngCore + CryptoRng,
        F: FnMut(NodeEvent),
    {
        // Send initial announce
        let announce = self.build_announce(None, rng);
        let _ = iface.send(&announce).await;

        let mut recv_buf = [0u8; MTU];
        let mut pkt_buf = [0u8; MTU];
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
                        let len = data.len();
                        pkt_buf[..len].copy_from_slice(data);

                        let now = Instant::now().as_secs();
                        match self.transport.ingest(&mut pkt_buf[..len], now) {
                            IngestResult::AnnounceReceived {
                                dest_hash,
                                identity_hash,
                                hops,
                                app_data,
                            } => {
                                self.last_peer = Some(dest_hash);
                                on_event(NodeEvent::AnnounceReceived {
                                    dest_hash,
                                    identity_hash,
                                    hops,
                                    app_data: app_data.map(|d| d.to_vec()),
                                });
                                if let Some(ref msg) = self.auto_reply {
                                    if let Some(pkt) =
                                        self.build_data_packet(&dest_hash, msg, rng)
                                    {
                                        let _ = iface.send(&pkt).await;
                                    }
                                }
                            }
                            IngestResult::LocalData { dest_hash, payload } => {
                                let decrypted = if dest_hash == self.dest_hash {
                                    let mut dec_buf = [0u8; MTU];
                                    match self.identity.decrypt(payload, &mut dec_buf) {
                                        Ok(n) => dec_buf[..n].to_vec(),
                                        Err(_) => payload.to_vec(),
                                    }
                                } else {
                                    payload.to_vec()
                                };
                                // Echo data back to sender if echo mode is on
                                if self.echo_data {
                                    if let Some(peer) = self.last_peer {
                                        let mut echo_msg = Vec::with_capacity(5 + decrypted.len());
                                        echo_msg.extend_from_slice(b"echo:");
                                        echo_msg.extend_from_slice(&decrypted);
                                        if let Some(pkt) =
                                            self.build_data_packet(&peer, &echo_msg, rng)
                                        {
                                            let _ = iface.send(&pkt).await;
                                        }
                                    }
                                }
                                on_event(NodeEvent::DataReceived {
                                    dest_hash,
                                    payload: decrypted,
                                });
                            }
                            IngestResult::Forward { raw } => {
                                let _ = iface.send(raw).await;
                            }
                            IngestResult::Duplicate | IngestResult::Invalid => {}
                        }
                    }
                    Err(_) => break,
                },
                Either3::Second(()) => {
                    // Periodic announce
                    next_announce = Instant::now() + Duration::from_secs(ANNOUNCE_INTERVAL_SECS);
                    let announce = self.build_announce(None, rng);
                    let _ = iface.send(&announce).await;
                }
                Either3::Third(()) => {
                    // Periodic tick
                    next_tick = Instant::now() + Duration::from_secs(TICK_INTERVAL_SECS);
                    let now = Instant::now().as_secs();
                    let result = self.transport.tick(now);
                    on_event(NodeEvent::Tick {
                        expired_paths: result.expired_paths,
                    });

                    // Send pending outbound announces
                    let pending = self.transport.pending_outbound(now);
                    for ann_raw in pending {
                        let _ = iface.send(&ann_raw).await;
                    }
                }
            }
        }
    }
}
