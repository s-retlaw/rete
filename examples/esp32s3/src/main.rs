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

mod config;
mod dhcp;
mod display;
mod rng;
mod status;
mod tcp_iface;
mod web;
use rng::EspRng;

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;

/// Packets received from TCP peer → main node loop.
static TCP_INBOUND: Channel<CriticalSectionRawMutex, tcp_iface::PacketBuf, { tcp_iface::CHANNEL_DEPTH }> = Channel::new();
/// Packets from main node loop → TCP peer.
static TCP_OUTBOUND: Channel<CriticalSectionRawMutex, tcp_iface::PacketBuf, { tcp_iface::CHANNEL_DEPTH }> = Channel::new();

macro_rules! mk_static {
    ($t:ty, $val:expr) => {{
        static STATIC_CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        #[deny(unused_attributes)]
        let x = STATIC_CELL.uninit().write(($val));
        x
    }};
}

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
async fn main(spawner: Spawner) -> ! {
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    esp_alloc::heap_allocator!(size: 72 * 1024);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0);

    println!("[rete] Heltec LoRa V3/V4 — standalone Reticulum node");

    // -----------------------------------------------------------------------
    // Load or generate persistent config
    // -----------------------------------------------------------------------

    let node_config = mk_static!(config::NodeConfig, match config::load_config() {
        Some(cfg) => {
            println!("[rete] loaded config from flash");
            cfg
        }
        None => {
            println!("[rete] no config found — generating defaults");
            let cfg = config::NodeConfig::generate_default(&mut esp_hal::rng::Rng::new());
            config::save_config(&cfg);
            println!("[rete] config saved to flash");
            cfg
        }
    });

    // Cache config in memory so web handlers never touch flash (avoids stack overflow)
    config::init_cache(node_config);

    println!(
        "[rete] LoRa config: freq={}Hz SF={} BW={}Hz TX={}dBm",
        node_config.lora_freq, node_config.lora_sf, node_config.lora_bw, node_config.lora_tx_power
    );
    println!("[rete] admin password: {}", node_config.admin_pass_str());

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
    display::draw_splash(&mut oled, node_config.lora_freq, node_config.lora_sf);
    println!("[rete] OLED display initialized");

    // -----------------------------------------------------------------------
    // WiFi Access Point (+ optional STA upstream bridge)
    // -----------------------------------------------------------------------

    let esp_radio_ctrl =
        &*mk_static!(esp_radio::Controller<'static>, esp_radio::init().unwrap());
    let (mut controller, interfaces) =
        esp_radio::wifi::new(esp_radio_ctrl, peripherals.WIFI, Default::default()).unwrap();

    let sta_enabled = node_config.sta_enabled && node_config.sta_ssid_len > 0;

    // Configure WiFi mode: AP-only or AP+STA
    if sta_enabled {
        let sta_ssid = ::core::str::from_utf8(&node_config.sta_ssid[..node_config.sta_ssid_len as usize]).unwrap_or("");
        let sta_pass = ::core::str::from_utf8(&node_config.sta_pass[..node_config.sta_pass_len as usize]).unwrap_or("");
        let mode = esp_radio::wifi::ModeConfig::ApSta(
            esp_radio::wifi::ClientConfig::default()
                .with_ssid(sta_ssid.into())
                .with_password(sta_pass.into()),
            esp_radio::wifi::AccessPointConfig::default()
                .with_ssid(node_config.ap_ssid_str().into())
                .with_channel(6),
        );
        controller.set_config(&mode).unwrap();
        println!("[rete] WiFi AP+STA mode: AP={}, STA={}", node_config.ap_ssid_str(), sta_ssid);
    } else {
        let mode = esp_radio::wifi::ModeConfig::AccessPoint(
            esp_radio::wifi::AccessPointConfig::default()
                .with_ssid(node_config.ap_ssid_str().into())
                .with_channel(6),
        );
        controller.set_config(&mode).unwrap();
        println!("[rete] WiFi AP-only mode: {}", node_config.ap_ssid_str());
    }

    controller.start_async().await.unwrap();

    // AP network stack (always active): static 192.168.4.1
    let ap_net_config = embassy_net::Config::ipv4_static(embassy_net::StaticConfigV4 {
        address: embassy_net::Ipv4Cidr::new(embassy_net::Ipv4Address::new(192, 168, 4, 1), 24),
        gateway: None,
        dns_servers: Default::default(),
    });
    let hw_rng = esp_hal::rng::Rng::new();
    let seed1 = (hw_rng.random() as u64) << 32 | hw_rng.random() as u64;
    let (ap_stack, ap_runner) = embassy_net::new(
        interfaces.ap,
        ap_net_config,
        mk_static!(embassy_net::StackResources<12>, embassy_net::StackResources::<12>::new()),
        seed1,
    );

    spawner.spawn(net_task_ap(ap_runner)).ok();
    spawner.spawn(dhcp_task(ap_stack)).ok();
    spawner.spawn(reboot_task()).ok();
    spawner.spawn(web::http_listener(0, ap_stack)).ok();
    spawner.spawn(web::http_listener(1, ap_stack)).ok();
    spawner.spawn(web::http_listener(2, ap_stack)).ok();

    // STA network stack (optional): DHCP client to upstream
    if sta_enabled {
        let sta_net_config = embassy_net::Config::dhcpv4(Default::default());
        let seed2 = (hw_rng.random() as u64) << 32 | hw_rng.random() as u64;
        let (sta_stack, sta_runner) = embassy_net::new(
            interfaces.sta,
            sta_net_config,
            mk_static!(embassy_net::StackResources<4>, embassy_net::StackResources::<4>::new()),
            seed2,
        );
        spawner.spawn(net_task_sta(sta_runner)).ok();
        spawner.spawn(sta_connection_task(controller)).ok();
        spawner.spawn(sta_ip_monitor_task(sta_stack)).ok();
        spawner.spawn(tcp_iface::tcp_rete_task(
            sta_stack,
            TCP_INBOUND.sender(),
            TCP_OUTBOUND.receiver(),
        )).ok();
    }

    println!("[rete] WiFi started");

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
        frequency: node_config.lora_freq,
        spreading_factor: sf_from_u8(node_config.lora_sf),
        bandwidth: bw_from_hz(node_config.lora_bw),
        coding_rate: CodingRate::_4_5,
        tx_power: node_config.lora_tx_power,
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
    // Create identity from persistent key
    // -----------------------------------------------------------------------

    let mut rng = EspRng(esp_hal::rng::Rng::new());
    let identity = rete_core::Identity::from_private_key(&node_config.identity_key).expect("invalid key");

    let id_hash = identity.hash();
    let ih = id_hash.as_bytes();
    println!(
        "[rete] identity: {:02x}{:02x}{:02x}{:02x}...",
        ih[0], ih[1], ih[2], ih[3]
    );

    let mut node = EmbassyNode::new(identity, APP_NAME, ASPECTS).expect("valid app name");
    node.core.enable_transport();
    println!("[rete] transport mode ENABLED (forwarding between interfaces)");
    let dh = node.core.dest_hash();
    let dhb = dh.as_bytes();
    println!(
        "[rete] dest: {:02x}{:02x}{:02x}{:02x}...",
        dhb[0], dhb[1], dhb[2], dhb[3]
    );

    // -----------------------------------------------------------------------
    // Run the rete event loop
    // -----------------------------------------------------------------------

    let mut disp_state = display::DisplayState::new();

    // Macro to avoid duplicating the event handler closure across branches.
    macro_rules! event_handler {
        () => {
            |event, node_core: &mut rete_embassy::EmbeddedNodeCore, _rng: &mut EspRng| {
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
                        disp_state.update(&mut oled, node_core, now, node_config.lora_freq, node_config.lora_sf, node_config.admin_pass_str());
                        status::update_status(node_core, now, node_config.lora_freq, node_config.lora_sf, node_config.lora_bw, node_config.lora_tx_power);
                    }
                    _ => {}
                }
                Vec::new()
            }
        };
    }

    if sta_enabled {
        // Dual interface: LoRa + TCP over WiFi
        println!("[rete] entering main loop — LoRa + TCP (dual interface)");
        let mut tcp_iface = tcp_iface::ChannelInterface::new(
            TCP_INBOUND.receiver(),
            TCP_OUTBOUND.sender(),
        );
        node.run_multi_2_until_with_handler(
            &mut iface,
            &mut tcp_iface,
            &mut rng,
            event_handler!(),
            core::future::pending::<()>(),
        )
        .await;
    } else {
        // Single interface: LoRa only
        println!("[rete] entering main loop — listening on LoRa");
        node.run_with_handler(&mut iface, &mut rng, event_handler!()).await;
    }

    println!("[rete] loop exited (unexpected)");
    loop {
        embassy_time::Timer::after(embassy_time::Duration::from_secs(1)).await;
    }
}

// ---------------------------------------------------------------------------
// Spawned tasks
// ---------------------------------------------------------------------------

#[embassy_executor::task]
async fn net_task_ap(mut runner: embassy_net::Runner<'static, esp_radio::wifi::WifiDevice<'static>>) {
    runner.run().await
}

#[embassy_executor::task]
async fn net_task_sta(mut runner: embassy_net::Runner<'static, esp_radio::wifi::WifiDevice<'static>>) {
    runner.run().await
}

#[embassy_executor::task]
async fn sta_connection_task(mut controller: esp_radio::wifi::WifiController<'static>) {
    use esp_radio::wifi::{WifiEvent, WifiStaState};
    loop {
        if matches!(esp_radio::wifi::sta_state(), WifiStaState::Connected) {
            controller.wait_for_event(WifiEvent::StaDisconnected).await;
            println!("[wifi] STA disconnected, reconnecting...");
            status::STA_IP.store(0, core::sync::atomic::Ordering::Relaxed);
            embassy_time::Timer::after(embassy_time::Duration::from_secs(3)).await;
        }
        println!("[wifi] STA connecting...");
        match controller.connect_async().await {
            Ok(_) => println!("[wifi] STA connected!"),
            Err(e) => {
                println!("[wifi] STA connect failed: {:?}", e);
                embassy_time::Timer::after(embassy_time::Duration::from_secs(5)).await;
            }
        }
    }
}

#[embassy_executor::task]
async fn sta_ip_monitor_task(stack: embassy_net::Stack<'static>) {
    loop {
        if let Some(config) = stack.config_v4() {
            let addr = config.address.address();
            let octets = addr.octets();
            let packed = u32::from_be_bytes(octets);
            let prev = status::STA_IP.swap(packed, core::sync::atomic::Ordering::Relaxed);
            if prev != packed {
                println!("[wifi] STA IP: {}", addr);
            }
        } else {
            status::STA_IP.store(0, core::sync::atomic::Ordering::Relaxed);
        }
        embassy_time::Timer::after(embassy_time::Duration::from_secs(2)).await;
    }
}

#[embassy_executor::task]
async fn dhcp_task(stack: embassy_net::Stack<'static>) {
    dhcp::run(stack).await;
}

#[embassy_executor::task]
async fn reboot_task() {
    crate::status::REBOOT_SIGNAL.wait().await;
    println!("[rete] reboot signal received — resetting in 1s");
    embassy_time::Timer::after(embassy_time::Duration::from_secs(1)).await;
    esp_hal::system::software_reset();
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
