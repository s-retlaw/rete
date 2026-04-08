//! rete-iface-lora — LoRa radio interface for Reticulum.
//!
//! Implements [`ReteInterface`] over a `lora-phy` LoRa radio driver,
//! providing direct SPI-to-RF packet transport without KISS or HDLC
//! framing. Handles LoRa's 255-byte MTU by splitting/reassembling
//! large RNS packets (up to 508 bytes) using the same protocol as the
//! RNode firmware.
//!
//! # Usage
//!
//! ```ignore
//! use rete_iface_lora::{LoRaInterface, LoRaConfig};
//! use lora_phy::LoRa;
//!
//! let lora = LoRa::new(sx1262, false, delay).await?;
//! let config = LoRaConfig::default();
//! let mut iface = LoRaInterface::new(lora, config, 0xDEAD_BEEF);
//!
//! // Use with EmbassyNode::run()
//! node.run(&mut iface, &mut rng, |event| { ... }).await;
//! ```

#![no_std]

pub mod csma;
pub mod split;

use lora_phy::mod_params::{
    Bandwidth, CodingRate, ModulationParams, PacketParams, PacketStatus, SpreadingFactor,
};
use lora_phy::mod_traits::RadioKind;
use lora_phy::{DelayNs, LoRa};
use rete_stack::ReteInterface;

pub use csma::{CsmaConfig, CsmaOutcome};
use csma::xorshift32;
use split::{SplitReassembler, SplitResult, LORA_HW_MTU, LORA_MTU};

/// LoRa radio configuration.
///
/// Default values match common Reticulum network settings.
pub struct LoRaConfig {
    /// Carrier frequency in Hz (default: 915_000_000 for US ISM band).
    pub frequency: u32,
    /// Spreading factor (default: SF8).
    pub spreading_factor: SpreadingFactor,
    /// Bandwidth (default: 125 kHz).
    pub bandwidth: Bandwidth,
    /// Coding rate (default: 4/5 — matches RNode default).
    pub coding_rate: CodingRate,
    /// TX power in dBm (default: 14).
    pub tx_power: i32,
    /// Preamble length in symbols (default: 18 — matches RNode).
    pub preamble_len: u16,
    /// TX timeout in milliseconds (default: 10_000).
    pub tx_timeout_ms: u32,
    /// CSMA/CA configuration for channel access before TX.
    pub csma: CsmaConfig,
}

impl Default for LoRaConfig {
    fn default() -> Self {
        Self {
            frequency: 915_000_000,
            spreading_factor: SpreadingFactor::_8,
            bandwidth: Bandwidth::_125KHz,
            coding_rate: CodingRate::_4_5,
            tx_power: 14,
            preamble_len: 18,
            tx_timeout_ms: 10_000,
            csma: CsmaConfig::default(),
        }
    }
}

/// Errors from the LoRa interface.
#[derive(Debug)]
pub enum LoRaError {
    /// Radio driver error.
    Radio,
    /// Packet too large for LoRa (> 508 bytes).
    PacketTooLarge,
}

/// LoRa radio interface implementing [`ReteInterface`].
///
/// Generic over `RK` (radio kind — e.g. `Sx126x`) and `DLY` (delay
/// provider). Handles split packet TX/RX transparently.
pub struct LoRaInterface<RK, DLY>
where
    RK: RadioKind,
    DLY: DelayNs,
{
    lora: LoRa<RK, DLY>,
    config: LoRaConfig,
    reassembler: SplitReassembler,
    /// Split sequence counter (incremented per split TX).
    seq: u8,
    /// CSMA PRNG state — xorshift32, seeded from initial entropy.
    /// Different from `seq` to avoid correlated slot decisions across nodes.
    csma_rng_state: u32,
    /// Cached modulation params (computed once from config).
    mdltn_params: Option<ModulationParams>,
    /// Cached TX packet params.
    tx_pkt_params: Option<PacketParams>,
    /// Cached RX packet params.
    rx_pkt_params: Option<PacketParams>,
}

impl<RK, DLY> LoRaInterface<RK, DLY>
where
    RK: RadioKind,
    DLY: DelayNs,
{
    /// Create a new LoRa interface.
    ///
    /// `rng_seed` provides initial entropy for the CSMA PRNG. On ESP32,
    /// use `esp_random()`; on nRF52, use the hardware RNG; on RP2040,
    /// use ROSC. The seed MUST differ between nodes to avoid correlated
    /// CSMA slot decisions and collisions.
    ///
    /// The `LoRa` instance should already be constructed with the correct
    /// sync word (`enable_public_network: false` for Reticulum private
    /// network, which sets sync word 0x1424 on SX126x).
    pub fn new(lora: LoRa<RK, DLY>, config: LoRaConfig, rng_seed: u32) -> Self {
        // Ensure nonzero seed for xorshift32
        let seed = if rng_seed == 0 { 0xDEAD_BEEF } else { rng_seed };
        Self {
            lora,
            config,
            reassembler: SplitReassembler::new(),
            seq: 0,
            csma_rng_state: seed,
            mdltn_params: None,
            tx_pkt_params: None,
            rx_pkt_params: None,
        }
    }

    /// Initialize radio parameters. Must be called once before send/recv.
    ///
    /// This is separate from `new()` because `create_modulation_params` is
    /// async and fallible in lora-phy.
    pub async fn init(&mut self) -> Result<(), LoRaError> {
        let mdltn = self
            .lora
            .create_modulation_params(
                self.config.spreading_factor,
                self.config.bandwidth,
                self.config.coding_rate,
                self.config.frequency,
            )
            .map_err(|_| LoRaError::Radio)?;

        let tx_pkt = self
            .lora
            .create_tx_packet_params(
                self.config.preamble_len,
                false, // explicit header mode
                true,  // CRC enabled (matches RNode)
                false, // IQ not inverted
                &mdltn,
            )
            .map_err(|_| LoRaError::Radio)?;

        let rx_pkt = self
            .lora
            .create_rx_packet_params(
                self.config.preamble_len,
                false, // explicit header
                LORA_MTU as u8,
                true,  // CRC enabled
                false, // IQ not inverted
                &mdltn,
            )
            .map_err(|_| LoRaError::Radio)?;

        self.mdltn_params = Some(mdltn);
        self.tx_pkt_params = Some(tx_pkt);
        self.rx_pkt_params = Some(rx_pkt);

        Ok(())
    }

    /// Next split sequence number (0..15).
    fn next_seq(&mut self) -> u8 {
        let s = self.seq & 0x0F;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    /// Transmit a single LoRa frame with CSMA/CA channel access.
    async fn tx_frame(&mut self, frame: &[u8]) -> Result<(), LoRaError> {
        // P-persistent CSMA/CA: wait for clear channel before transmitting
        let slottime = embassy_time::Duration::from_millis(self.config.csma.slottime_ms as u64);

        for _ in 0..self.config.csma.max_attempts {
            // CAD: check if channel is busy
            let busy = if let Some(mdltn) = self.mdltn_params.as_ref() {
                let cad_ok = self.lora.prepare_for_cad(mdltn).await.is_ok();
                if cad_ok {
                    self.lora.cad(mdltn).await.unwrap_or(true)
                } else {
                    // CAD setup failed — assume busy, retry after slot
                    true
                }
            } else {
                false // No modulation params = skip CSMA
            };

            if busy {
                embassy_time::Timer::after(slottime).await;
                continue;
            }

            // Channel is free — p-persistent decision using xorshift32
            self.csma_rng_state = xorshift32(self.csma_rng_state);
            let rand_byte = (self.csma_rng_state & 0xFF) as u8;
            if rand_byte < self.config.csma.persistence {
                break; // Won the slot — transmit
            }

            embassy_time::Timer::after(slottime).await;
        }

        let mdltn = self.mdltn_params.as_ref().ok_or(LoRaError::Radio)?;
        let tx_pkt = self.tx_pkt_params.as_mut().ok_or(LoRaError::Radio)?;

        self.lora
            .prepare_for_tx(mdltn, tx_pkt, self.config.tx_power, frame)
            .await
            .map_err(|_| LoRaError::Radio)?;

        self.lora
            .tx()
            .await
            .map_err(|_| LoRaError::Radio)?;

        Ok(())
    }

    /// Receive a single LoRa frame. Returns number of bytes received.
    async fn rx_frame(&mut self, buf: &mut [u8]) -> Result<(usize, PacketStatus), LoRaError> {
        let mdltn = self.mdltn_params.as_ref().ok_or(LoRaError::Radio)?;
        let rx_pkt = self.rx_pkt_params.as_ref().ok_or(LoRaError::Radio)?;

        self.lora
            .prepare_for_rx(lora_phy::RxMode::Continuous, mdltn, rx_pkt)
            .await
            .map_err(|_| LoRaError::Radio)?;

        let (len, status) = self
            .lora
            .rx(rx_pkt, buf)
            .await
            .map_err(|_| LoRaError::Radio)?;

        Ok((len as usize, status))
    }
}

impl<RK, DLY> ReteInterface for LoRaInterface<RK, DLY>
where
    RK: RadioKind,
    DLY: DelayNs,
{
    type Error = LoRaError;

    async fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
        if frame.len() > LORA_HW_MTU {
            return Err(LoRaError::PacketTooLarge);
        }

        let seq = self.next_seq();
        // We need to copy out the split result before calling tx_frame,
        // because split_for_tx borrows tx_buf and tx_frame borrows self.
        let mut local_buf = [0u8; LORA_MTU * 2];
        match split::split_for_tx(frame, &mut local_buf, seq) {
            Some(SplitResult::Single { frame: f }) => {
                self.tx_frame(f).await?;
            }
            Some(SplitResult::Split { frame1, frame2 }) => {
                // Copy frames to stack before tx_frame borrows self
                let mut f1 = [0u8; LORA_MTU];
                let mut f2 = [0u8; LORA_MTU];
                let f1_len = frame1.len();
                let f2_len = frame2.len();
                f1[..f1_len].copy_from_slice(frame1);
                f2[..f2_len].copy_from_slice(frame2);

                self.tx_frame(&f1[..f1_len]).await?;
                // Small delay between split frames for receiver to process
                embassy_time::Timer::after(embassy_time::Duration::from_millis(10)).await;
                self.tx_frame(&f2[..f2_len]).await?;
            }
            None => return Err(LoRaError::PacketTooLarge),
        }

        Ok(())
    }

    async fn recv<'a>(&mut self, buf: &'a mut [u8]) -> Result<&'a [u8], Self::Error> {
        let mut rx_buf = [0u8; LORA_MTU];

        loop {
            let (len, _status) = self.rx_frame(&mut rx_buf).await?;
            if len == 0 {
                continue;
            }

            if let Some(pkt_len) = self.reassembler.feed(&rx_buf[..len], buf) {
                return Ok(&buf[..pkt_len]);
            }
            // If feed returned None, we're waiting for a split continuation.
            // Loop back to receive the next frame.
        }
    }
}
