//! ESP32-S3 + SX1262 standalone Reticulum node over LoRa.
//!
//! Targets Heltec WiFi LoRa 32 V3/V4 boards. The ESP32-S3 runs the full
//! rete stack and drives the SX1262 directly via SPI — no KISS, no host,
//! no Python. Interoperable with standard RNodes on the same frequency.
//!
//! Build & flash:
//!   cargo +esp run --release
//!
//! Optionally override LoRa parameters at build time:
//!   LORA_FREQ="915000000" LORA_SF="8" LORA_BW="125000" \
//!     cargo +esp run --release

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use embassy_executor::Spawner;
use embassy_time::Delay;
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::clock::CpuClock;
use esp_hal::gpio::{Input, InputConfig, Level, Output, Pull};
use esp_hal::i2c::master::{Config as I2cConfig, I2c};
use esp_hal::spi::master::{Config as SpiConfig, Spi};
use esp_hal::spi::Mode as SpiMode;
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;
use lora_phy::iv::GenericSx126xInterfaceVariant;
use lora_phy::mod_params::{Bandwidth, CodingRate, SpreadingFactor};
use lora_phy::sx126x::{self, Sx1262, Sx126x, TcxoCtrlVoltage};
use lora_phy::LoRa;
use rete_embassy::{EmbassyNode, NodeEvent};
use rete_iface_lora::{CsmaConfig, LoRaConfig, LoRaInterface};

mod display;
mod rng;
use rng::EspRng;

esp_bootloader_esp_idf::esp_app_desc!();

// ---------------------------------------------------------------------------
// LoRa configuration — override at build time via environment variables.
// ---------------------------------------------------------------------------

/// Carrier frequency in Hz. Default: 915 MHz (US ISM band).
const LORA_FREQ: u32 = parse_u32_or(option_env!("LORA_FREQ"), 915_000_000);
/// Spreading factor (7-12). Default: 8.
const LORA_SF: u8 = parse_u8_or(option_env!("LORA_SF"), 8);
/// Bandwidth in Hz. Default: 125000 (125 kHz).
const LORA_BW: u32 = parse_u32_or(option_env!("LORA_BW"), 125_000);
/// TX power in dBm. Default: 14.
const LORA_TX_POWER: i32 = parse_i32_or(option_env!("LORA_TX_POWER"), 14);

const APP_NAME: &str = "rete";
const ASPECTS: &[&str] = &["lora", "v1"];

// Heltec V3/V4 SX1262 pin mapping:
//   SPI: NSS=GPIO8, SCK=GPIO9, MOSI=GPIO10, MISO=GPIO11
//   Control: RESET=GPIO12, BUSY=GPIO13, DIO1=GPIO14

#[esp_rtos::main]
async fn main(_spawner: Spawner) -> ! {
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    esp_alloc::heap_allocator!(size: 64 * 1024);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0);

    println!("[rete] Heltec LoRa V3/V4 — standalone Reticulum node");
    println!(
        "[rete] LoRa config: freq={}Hz SF={} BW={}Hz TX={}dBm",
        LORA_FREQ, LORA_SF, LORA_BW, LORA_TX_POWER
    );

    // -----------------------------------------------------------------------
    // OLED display (I2C, SDA=GPIO17, SCL=GPIO18, Vext power=GPIO21)
    // -----------------------------------------------------------------------

    // Heltec V3/V4: GPIO36 LOW = enable Vext power rail to OLED
    let _vext = Output::new(peripherals.GPIO36, Level::Low, Default::default());
    embassy_time::Timer::after(embassy_time::Duration::from_millis(50)).await;

    // GPIO21 = OLED reset: pulse LOW then release HIGH
    let mut oled_rst = Output::new(peripherals.GPIO21, Level::High, Default::default());
    oled_rst.set_low();
    embassy_time::Timer::after(embassy_time::Duration::from_millis(10)).await;
    oled_rst.set_high();
    embassy_time::Timer::after(embassy_time::Duration::from_millis(50)).await;

    let i2c = I2c::new(peripherals.I2C0, I2cConfig::default())
        .unwrap()
        .with_sda(peripherals.GPIO17)
        .with_scl(peripherals.GPIO18);

    let i2c_di = ssd1306::I2CDisplayInterface::new(i2c);
    let mut oled = display::init_display(i2c_di);
    display::draw_splash(&mut oled, LORA_FREQ, LORA_SF);
    println!("[rete] OLED display initialized");

    // -----------------------------------------------------------------------
    // SPI + GPIO setup for SX1262 (Heltec V3/V4 pin mapping)
    // -----------------------------------------------------------------------

    let spi = Spi::new(
        peripherals.SPI2,
        SpiConfig::default().with_mode(SpiMode::_0),
    )
    .unwrap()
    .with_sck(peripherals.GPIO9)
    .with_mosi(peripherals.GPIO10)
    .with_miso(peripherals.GPIO11)
    .into_async();

    let nss = Output::new(peripherals.GPIO8, Level::High, Default::default());
    let spi_dev = embedded_hal_bus::spi::ExclusiveDevice::new(spi, nss, Delay)
        .expect("SPI device creation");

    let reset = Output::new(peripherals.GPIO12, Level::High, Default::default());
    let dio1 = Input::new(peripherals.GPIO14, InputConfig::default().with_pull(Pull::Down));
    let busy = Input::new(peripherals.GPIO13, InputConfig::default().with_pull(Pull::Down));

    // -----------------------------------------------------------------------
    // LoRa radio init
    // -----------------------------------------------------------------------

    let iv = GenericSx126xInterfaceVariant::new(reset, dio1, busy, None, None)
        .expect("interface variant");

    let sx_config = sx126x::Config {
        chip: Sx1262,
        tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl1V7),
        use_dcdc: true,
        rx_boost: false,
    };

    let sx = Sx126x::new(spi_dev, iv, sx_config);
    let lora = LoRa::new(sx, false, Delay).await.expect("LoRa init");

    println!("[rete] SX1262 initialized (sync word: private/0x1424)");

    // -----------------------------------------------------------------------
    // Wrap in rete LoRaInterface
    // -----------------------------------------------------------------------

    let lora_config = LoRaConfig {
        frequency: LORA_FREQ,
        spreading_factor: sf_from_u8(LORA_SF),
        bandwidth: bw_from_hz(LORA_BW),
        coding_rate: CodingRate::_4_5,
        tx_power: LORA_TX_POWER,
        preamble_len: 18,
        tx_timeout_ms: 10_000,
        csma: CsmaConfig::default(),
    };

    // Seed CSMA PRNG from hardware RNG for non-correlated slot decisions
    let csma_seed = esp_hal::rng::Rng::new().random();
    let mut iface = LoRaInterface::new(lora, lora_config, csma_seed);
    iface.init().await.expect("LoRa interface init");
    println!("[rete] LoRa interface ready");

    // -----------------------------------------------------------------------
    // Generate identity and create node
    // -----------------------------------------------------------------------

    let mut rng = EspRng(esp_hal::rng::Rng::new());

    println!("[rete] generating identity from hardware RNG");
    let mut prv = [0u8; 64];
    use rand_core::RngCore;
    rng.0.fill_bytes(&mut prv);
    let identity = rete_core::Identity::from_private_key(&prv).expect("invalid key");

    let id_hash = identity.hash();
    let ih = id_hash.as_bytes();
    println!(
        "[rete] identity: {:02x}{:02x}{:02x}{:02x}...",
        ih[0], ih[1], ih[2], ih[3]
    );

    let mut node = EmbassyNode::new(identity, APP_NAME, ASPECTS).expect("valid app name");
    let dh = node.core.dest_hash();
    let dhb = dh.as_bytes();
    println!(
        "[rete] dest: {:02x}{:02x}{:02x}{:02x}...",
        dhb[0], dhb[1], dhb[2], dhb[3]
    );

    // -----------------------------------------------------------------------
    // Run the rete event loop
    // -----------------------------------------------------------------------

    println!("[rete] entering main loop — listening on LoRa");

    let mut disp_state = display::DisplayState::new();

    node.run_with_handler(&mut iface, &mut rng, |event, node_core, _rng| {
        match event {
            NodeEvent::AnnounceReceived {
                dest_hash, hops, ..
            } => {
                let d = dest_hash.as_bytes();
                println!(
                    "[rete] ANNOUNCE dest={:02x}{:02x}{:02x}{:02x}... hops={}",
                    d[0], d[1], d[2], d[3], hops,
                );
            }
            NodeEvent::DataReceived { payload, .. } => {
                if let Ok(text) = ::core::str::from_utf8(&payload) {
                    println!("[rete] DATA: {}", text);
                } else {
                    println!("[rete] DATA: {} bytes", payload.len());
                }
            }
            NodeEvent::Tick { expired_paths, .. } => {
                if expired_paths > 0 {
                    println!("[rete] tick: expired {} paths", expired_paths);
                }
                let now = embassy_time::Instant::now().as_secs();
                disp_state.update(&mut oled, node_core, now, LORA_FREQ, LORA_SF);
            }
            _ => {}
        }
        Vec::new()
    })
    .await;

    println!("[rete] loop exited (unexpected)");
    loop {
        embassy_time::Timer::after(embassy_time::Duration::from_secs(1)).await;
    }
}

// ---------------------------------------------------------------------------
// Compile-time helpers
// ---------------------------------------------------------------------------

fn sf_from_u8(sf: u8) -> SpreadingFactor {
    match sf {
        5 => SpreadingFactor::_5,
        6 => SpreadingFactor::_6,
        7 => SpreadingFactor::_7,
        8 => SpreadingFactor::_8,
        9 => SpreadingFactor::_9,
        10 => SpreadingFactor::_10,
        11 => SpreadingFactor::_11,
        12 => SpreadingFactor::_12,
        _ => SpreadingFactor::_8,
    }
}

fn bw_from_hz(hz: u32) -> Bandwidth {
    match hz {
        7800 => Bandwidth::_7KHz,
        10400 => Bandwidth::_10KHz,
        15600 => Bandwidth::_15KHz,
        20800 => Bandwidth::_20KHz,
        31250 => Bandwidth::_31KHz,
        41700 => Bandwidth::_41KHz,
        62500 => Bandwidth::_62KHz,
        125_000 => Bandwidth::_125KHz,
        250_000 => Bandwidth::_250KHz,
        500_000 => Bandwidth::_500KHz,
        _ => Bandwidth::_125KHz,
    }
}

const fn parse_u32_or(s: Option<&str>, default: u32) -> u32 {
    match s {
        Some(s) => {
            let b = s.as_bytes();
            let mut val: u64 = 0;
            let mut i = 0;
            while i < b.len() {
                val = val * 10 + (b[i] - b'0') as u64;
                i += 1;
            }
            val as u32
        }
        None => default,
    }
}

const fn parse_u8_or(s: Option<&str>, default: u8) -> u8 {
    parse_u32_or(s, default as u32) as u8
}

const fn parse_i32_or(s: Option<&str>, default: i32) -> i32 {
    match s {
        Some(s) => {
            let b = s.as_bytes();
            let (negative, start) = if b.len() > 0 && b[0] == b'-' {
                (true, 1)
            } else {
                (false, 0)
            };
            let mut val: i64 = 0;
            let mut i = start;
            while i < b.len() {
                val = val * 10 + (b[i] - b'0') as i64;
                i += 1;
            }
            if negative { -(val as i32) } else { val as i32 }
        }
        None => default,
    }
}
