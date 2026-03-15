//! ESP32-C6 bare-metal Embassy example — Reticulum node over WiFi TCP.
//!
//! Connects to a Python `rnsd` node over TCP and participates in the
//! Reticulum network: sends announces, receives announces and data.
//!
//! Build & flash (ESP32-C6):
//!   SSID="MyNet" PASSWORD="MyPass" RNSD_HOST="192.168.1.42" \
//!     cargo +nightly run --release --features esp32c6
//!
//! Build for ESP32-C3 (swap feature + target in config.toml):
//!   cargo +nightly run --release --features esp32c3

#![no_std]
#![no_main]

extern crate alloc;

use core::net::Ipv4Addr;

use embassy_executor::Spawner;
use embassy_net::{Runner, StackResources, tcp::TcpSocket};
use embassy_time::{Duration, Timer};
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::{clock::CpuClock, ram, timer::timg::TimerGroup};
use esp_println::println;
use esp_radio::{
    Controller,
    wifi::{ClientConfig, ModeConfig, WifiController, WifiDevice, WifiEvent, WifiStaState},
};
use rand_core::{CryptoRng, RngCore};
use rete_embassy::{EmbassyHdlcInterface, EmbassyNode, NodeEvent};
use sha2::{Digest, Sha256};

/// Wrapper around ESP32 hardware RNG implementing rand_core 0.6 traits.
///
/// The ESP32-C6 HW RNG is cryptographically secure when WiFi is active
/// (the radio provides a hardware entropy source).
struct EspRng(esp_hal::rng::Rng);

impl RngCore for EspRng {
    fn next_u32(&mut self) -> u32 {
        self.0.random()
    }

    fn next_u64(&mut self) -> u64 {
        (self.next_u32() as u64) << 32 | self.next_u32() as u64
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.read(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for EspRng {}

esp_bootloader_esp_idf::esp_app_desc!();

macro_rules! mk_static {
    ($t:ty, $val:expr) => {{
        static STATIC_CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        #[deny(unused_attributes)]
        let x = STATIC_CELL.uninit().write(($val));
        x
    }};
}

const SSID: &str = env!("SSID");
const PASSWORD: &str = env!("PASSWORD");
const RNSD_HOST: &str = env!("RNSD_HOST");
const RNSD_PORT: &str = env!("RNSD_PORT");

const APP_NAME: &str = "rete";
const ASPECTS: &[&str] = &["example", "v1"];

#[esp_rtos::main]
async fn main(spawner: Spawner) -> ! {
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    esp_alloc::heap_allocator!(#[ram(reclaimed)] size: 64 * 1024);
    esp_alloc::heap_allocator!(size: 36 * 1024);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    #[cfg(target_arch = "riscv32")]
    let sw_int =
        esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(
        timg0.timer0,
        #[cfg(target_arch = "riscv32")]
        sw_int.software_interrupt0,
    );

    // WiFi init
    let esp_radio_ctrl = &*mk_static!(Controller<'static>, esp_radio::init().unwrap());
    let (controller, interfaces) =
        esp_radio::wifi::new(esp_radio_ctrl, peripherals.WIFI, Default::default()).unwrap();
    let wifi_interface = interfaces.sta;

    // Network stack init
    let net_config = embassy_net::Config::dhcpv4(Default::default());
    let hw_rng = esp_hal::rng::Rng::new();
    let seed = (hw_rng.random() as u64) << 32 | hw_rng.random() as u64;
    let (stack, runner) = embassy_net::new(
        wifi_interface,
        net_config,
        mk_static!(StackResources<3>, StackResources::<3>::new()),
        seed,
    );

    spawner.spawn(connection(controller)).ok();
    spawner.spawn(net_task(runner)).ok();

    // Wait for WiFi link up
    loop {
        if stack.is_link_up() {
            break;
        }
        Timer::after(Duration::from_millis(500)).await;
    }
    println!("[rete] WiFi link up");

    // Wait for DHCP
    loop {
        if let Some(config) = stack.config_v4() {
            println!("[rete] WiFi connected, IP: {}", config.address);
            break;
        }
        Timer::after(Duration::from_millis(500)).await;
    }

    // Connect TCP to rnsd
    let host: Ipv4Addr = parse_ipv4(RNSD_HOST);
    let port: u16 = parse_u16(RNSD_PORT);

    let mut rx_buf = [0u8; 2048];
    let mut tx_buf = [0u8; 2048];
    let mut socket = TcpSocket::new(stack, &mut rx_buf, &mut tx_buf);
    socket.set_timeout(Some(Duration::from_secs(30)));

    println!("[rete] connecting TCP to {}:{}", RNSD_HOST, RNSD_PORT);
    if let Err(e) = socket.connect((host, port)).await {
        println!("[rete] TCP connect failed: {:?}", e);
        loop {
            Timer::after(Duration::from_secs(1)).await;
        }
    }
    println!("[rete] TCP connected to {}:{}", RNSD_HOST, RNSD_PORT);

    // Wrap socket in HDLC interface
    let mut iface = EmbassyHdlcInterface::new(socket);

    // WARNING: Deterministic identity for reproducible interop testing.
    // Every device running this firmware has the same private key.
    // For production, generate from hardware RNG: rng.fill_bytes(&mut prv);
    println!("[rete] WARNING: using fixed test key (not for production)");
    let hash = Sha256::digest(b"rete-esp32c6-example");
    let mut prv = [0u8; 64];
    prv[..32].copy_from_slice(&hash);
    let hash2 = Sha256::digest(&hash);
    prv[32..].copy_from_slice(&hash2);
    let identity = rete_core::Identity::from_private_key(&prv).expect("invalid derived key");

    let id_hash = identity.hash();
    println!(
        "[rete] identity: {:02x}{:02x}{:02x}{:02x}...",
        id_hash[0], id_hash[1], id_hash[2], id_hash[3]
    );

    // Create node
    let mut node = EmbassyNode::new(identity, APP_NAME, ASPECTS);
    let dh = node.dest_hash();
    println!(
        "[rete] dest: {:02x}{:02x}{:02x}{:02x}...",
        dh[0], dh[1], dh[2], dh[3]
    );

    // Run the rete event loop
    let mut rng = EspRng(esp_hal::rng::Rng::new());
    node.run(&mut iface, &mut rng, |event| match event {
        NodeEvent::AnnounceReceived {
            dest_hash, hops, ..
        } => {
            println!(
                "[rete] ANNOUNCE dest={:02x}{:02x}{:02x}{:02x}... hops={}",
                dest_hash[0], dest_hash[1], dest_hash[2], dest_hash[3], hops,
            );
        }
        NodeEvent::DataReceived { payload, .. } => {
            if let Ok(text) = core::str::from_utf8(&payload) {
                println!("[rete] DATA: {}", text);
            } else {
                println!("[rete] DATA: {} bytes", payload.len());
            }
        }
        NodeEvent::Tick { expired_paths } => {
            if expired_paths > 0 {
                println!("[rete] tick: expired {} paths", expired_paths);
            }
        }
    })
    .await;

    // If run() returns (connection dropped), loop forever
    println!("[rete] disconnected");
    loop {
        Timer::after(Duration::from_secs(1)).await;
    }
}

#[embassy_executor::task]
async fn connection(mut controller: WifiController<'static>) {
    loop {
        if matches!(esp_radio::wifi::sta_state(), WifiStaState::Connected) {
            controller
                .wait_for_event(WifiEvent::StaDisconnected)
                .await;
            Timer::after(Duration::from_millis(5000)).await;
            continue;
        }
        if !matches!(controller.is_started(), Ok(true)) {
            let client_config = ModeConfig::Client(
                ClientConfig::default()
                    .with_ssid(SSID.into())
                    .with_password(PASSWORD.into()),
            );
            controller.set_config(&client_config).unwrap();
            println!("[rete] starting WiFi...");
            controller.start_async().await.unwrap();
            println!("[rete] WiFi started");
        }
        println!("[rete] connecting WiFi...");
        match controller.connect_async().await {
            Ok(_) => println!("[rete] WiFi connected!"),
            Err(e) => {
                println!("[rete] WiFi connect failed: {:?}", e);
                Timer::after(Duration::from_millis(5000)).await;
            }
        }
    }
}

#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, WifiDevice<'static>>) {
    runner.run().await
}

/// Parse an IPv4 address from a compile-time string (no alloc needed).
const fn parse_ipv4(s: &str) -> Ipv4Addr {
    let b = s.as_bytes();
    let (a, i) = parse_octet(b, 0);
    let (bb, i) = parse_octet(b, i + 1);
    let (c, i) = parse_octet(b, i + 1);
    let (d, _) = parse_octet(b, i + 1);
    Ipv4Addr::new(a, bb, c, d)
}

const fn parse_octet(b: &[u8], start: usize) -> (u8, usize) {
    let mut val: u16 = 0;
    let mut i = start;
    while i < b.len() && b[i] != b'.' {
        assert!(b[i] >= b'0' && b[i] <= b'9', "RNSD_HOST contains non-digit");
        val = val * 10 + (b[i] - b'0') as u16;
        i += 1;
    }
    assert!(val <= 255, "RNSD_HOST octet exceeds 255");
    (val as u8, i)
}

const fn parse_u16(s: &str) -> u16 {
    let b = s.as_bytes();
    let mut val: u32 = 0;
    let mut i = 0;
    while i < b.len() {
        assert!(b[i] >= b'0' && b[i] <= b'9', "RNSD_PORT contains non-digit");
        val = val * 10 + (b[i] - b'0') as u32;
        i += 1;
    }
    assert!(val <= 65535, "RNSD_PORT exceeds 65535");
    val as u16
}
