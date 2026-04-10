//! TCP rete interface — accepts a single TCP peer on the STA network and
//! bridges HDLC-framed rete packets to/from the main node via channels.
//!
//! Architecture: a dedicated embassy task handles the TCP socket lifecycle
//! (accept, read/write, reconnect). Two static channels bridge packets between
//! this task and a `ChannelInterface` that implements `ReteInterface` for the
//! main dual-interface run loop.

use core::sync::atomic::Ordering;

use embassy_net::tcp::TcpSocket;
use embassy_time::{Duration, Timer};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::{Receiver, Sender};
use embedded_io_async::Write;
use esp_println::println;

use rete_core::hdlc::{self, HdlcDecoder, MAX_ENCODED};
use rete_core::MTU;
use rete_stack::ReteInterface;

/// Channel depth — 8 packets of up to 512 bytes each ≈ 4KB per direction.
pub const CHANNEL_DEPTH: usize = 8;

/// TCP listen port (matches standard rete/rnsd TCP port).
const TCP_PORT: u16 = 4242;

// ---------------------------------------------------------------------------
// PacketBuf — fixed-size packet buffer for channel transport (no heap)
// ---------------------------------------------------------------------------

pub struct PacketBuf {
    pub data: [u8; 512],
    pub len: usize,
}

impl PacketBuf {
    pub fn from_slice(src: &[u8]) -> Option<Self> {
        if src.len() > 512 {
            return None;
        }
        let mut buf = PacketBuf { data: [0u8; 512], len: src.len() };
        buf.data[..src.len()].copy_from_slice(src);
        Some(buf)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

// ---------------------------------------------------------------------------
// ChannelInterface — ReteInterface backed by embassy channels
// ---------------------------------------------------------------------------

pub struct ChannelInterface<'a> {
    rx: Receiver<'a, CriticalSectionRawMutex, PacketBuf, CHANNEL_DEPTH>,
    tx: Sender<'a, CriticalSectionRawMutex, PacketBuf, CHANNEL_DEPTH>,
}

impl<'a> ChannelInterface<'a> {
    pub fn new(
        rx: Receiver<'a, CriticalSectionRawMutex, PacketBuf, CHANNEL_DEPTH>,
        tx: Sender<'a, CriticalSectionRawMutex, PacketBuf, CHANNEL_DEPTH>,
    ) -> Self {
        Self { rx, tx }
    }
}

#[derive(Debug)]
pub struct ChannelError;

impl ReteInterface for ChannelInterface<'_> {
    type Error = ChannelError;

    async fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
        if let Some(pkt) = PacketBuf::from_slice(frame) {
            // Non-blocking: drop if channel full (TCP disconnected or slow)
            let _ = self.tx.try_send(pkt);
        }
        Ok(())
    }

    async fn recv<'b>(&mut self, buf: &'b mut [u8]) -> Result<&'b [u8], Self::Error> {
        let pkt = self.rx.receive().await;
        let len = pkt.len.min(buf.len());
        buf[..len].copy_from_slice(&pkt.data[..len]);
        Ok(&buf[..len])
    }
}

// ---------------------------------------------------------------------------
// TCP listener task
// ---------------------------------------------------------------------------

#[embassy_executor::task]
pub async fn tcp_rete_task(
    stack: embassy_net::Stack<'static>,
    inbound_tx: Sender<'static, CriticalSectionRawMutex, PacketBuf, CHANNEL_DEPTH>,
    outbound_rx: Receiver<'static, CriticalSectionRawMutex, PacketBuf, CHANNEL_DEPTH>,
) -> ! {
    // Wait for STA link up and IP assignment
    loop {
        if stack.is_link_up() {
            if stack.config_v4().is_some() {
                break;
            }
        }
        Timer::after(Duration::from_millis(500)).await;
    }
    println!("[tcp-rete] listening on :{}", TCP_PORT);

    let mut rx_buf = [0u8; 2048];
    let mut tx_buf = [0u8; 2048];

    loop {
        let mut socket = TcpSocket::new(stack, &mut rx_buf, &mut tx_buf);
        socket.set_timeout(Some(Duration::from_secs(60)));

        match socket.accept(TCP_PORT).await {
            Ok(()) => {
                println!("[tcp-rete] peer connected");
                crate::status::TCP_CONNECTED.store(true, Ordering::Relaxed);
            }
            Err(e) => {
                println!("[tcp-rete] accept error: {:?}", e);
                socket.abort();
                Timer::after(Duration::from_secs(1)).await;
                continue;
            }
        }

        // Service the connection
        let mut decoder: HdlcDecoder<{ MTU }> = HdlcDecoder::new();
        let mut read_buf = [0u8; 256];
        let mut encode_buf = [0u8; MAX_ENCODED];

        'connected: loop {
            use embassy_futures::select::{select, Either};

            match select(
                socket.read(&mut read_buf),
                outbound_rx.receive(),
            )
            .await
            {
                // TCP data arrived — decode HDLC frames
                Either::First(read_result) => {
                    let n = match read_result {
                        Ok(0) => break 'connected, // clean disconnect
                        Ok(n) => n,
                        Err(_) => break 'connected, // error
                    };
                    for &byte in &read_buf[..n] {
                        if decoder.feed(byte) {
                            if let Some(frame) = decoder.frame() {
                                if let Some(pkt) = PacketBuf::from_slice(frame) {
                                    let _ = inbound_tx.try_send(pkt);
                                }
                            }
                        }
                    }
                }
                // Outbound packet from node — HDLC encode and send over TCP
                Either::Second(pkt) => {
                    match hdlc::encode(pkt.as_slice(), &mut encode_buf) {
                        Ok(n) => {
                            if socket.write_all(&encode_buf[..n]).await.is_err() {
                                break 'connected;
                            }
                            if socket.flush().await.is_err() {
                                break 'connected;
                            }
                        }
                        Err(_) => {} // encode error (frame too large), skip
                    }
                }
            }
        }

        crate::status::TCP_CONNECTED.store(false, Ordering::Relaxed);
        socket.close();
        println!("[tcp-rete] peer disconnected");
        Timer::after(Duration::from_millis(500)).await;
    }
}
