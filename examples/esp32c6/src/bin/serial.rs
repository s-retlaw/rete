//! ESP32-C6 serial example — Reticulum node over UART.
//!
//! HDLC-framed Reticulum packets over UART0 (connected to CP2102/USB bridge).
//! No WiFi needed — connect the host directly with `rete-linux --serial`.
//!
//! Build & flash:
//!   cd examples/esp32c6
//!   cargo +nightly build --release --features esp32c6 --bin rete-esp32c6-serial
//!   espflash flash --port /dev/ttyUSB0 \
//!     target/riscv32imac-unknown-none-elf/release/rete-esp32c6-serial
//!
//! Then on the host (DON'T toggle DTR — just open the port):
//!   cargo run -p rete-example-linux -- --serial /dev/ttyUSB0

#![no_std]
#![no_main]

extern crate alloc;

use embassy_executor::Spawner;
use embedded_io_async::Write;
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::uart::{self, Uart};
use esp_hal::{clock::CpuClock, ram, timer::timg::TimerGroup};
use esp_println::println;
use rand_core::{CryptoRng, RngCore};
use rete_embassy::{EmbassyHdlcInterface, EmbassyNode, NodeEvent};
use sha2::{Digest, Sha256};

struct EspRng(esp_hal::rng::Rng);
impl RngCore for EspRng {
    fn next_u32(&mut self) -> u32 { self.0.random() }
    fn next_u64(&mut self) -> u64 { (self.next_u32() as u64) << 32 | self.next_u32() as u64 }
    fn fill_bytes(&mut self, dest: &mut [u8]) { self.0.read(dest) }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest); Ok(())
    }
}
impl CryptoRng for EspRng {}

esp_bootloader_esp_idf::esp_app_desc!();

#[esp_rtos::main]
async fn main(_spawner: Spawner) -> ! {
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

    println!("[rete-serial] booted");

    // UART0 async — connected to CP2102 USB bridge
    let uart_config = uart::Config::default().with_baudrate(115_200);
    let mut uart0 = Uart::new(peripherals.UART0, uart_config)
        .expect("UART0 init failed")
        .into_async();

    // Send a text marker before HDLC so host can see we're alive
    let _ = uart0.write_all(b"[rete-serial] UART async ready\r\n").await;

    let mut iface = EmbassyHdlcInterface::new(uart0);

    // Deterministic identity for reproducible testing
    println!("[rete-serial] creating identity");
    let hash = Sha256::digest(b"rete-esp32c6-serial");
    let mut prv = [0u8; 64];
    prv[..32].copy_from_slice(&hash);
    let hash2 = Sha256::digest(&hash);
    prv[32..].copy_from_slice(&hash2);
    let identity = rete_core::Identity::from_private_key(&prv).expect("invalid key");

    let mut node = EmbassyNode::new(identity, "rete", &["example", "v1"]);
    node.set_auto_reply(Some(alloc::vec![b'h', b'e', b'l', b'l', b'o', b' ', b'f', b'r', b'o', b'm', b' ', b'e', b's', b'p', b'3', b'2']));
    let dh = node.dest_hash();
    println!(
        "[rete-serial] dest: {:02x}{:02x}{:02x}{:02x}",
        dh[0], dh[1], dh[2], dh[3]
    );

    let mut rng = EspRng(esp_hal::rng::Rng::new());

    println!("[rete-serial] running (announces + HDLC on UART0)");
    node.run(&mut iface, &mut rng, |event| match event {
        NodeEvent::AnnounceReceived { dest_hash, hops, .. } => {
            println!(
                "[rete-serial] ANNOUNCE {:02x}{:02x}.. hops={}",
                dest_hash[0], dest_hash[1], hops,
            );
        }
        NodeEvent::DataReceived { payload, .. } => {
            if let Ok(text) = core::str::from_utf8(&payload) {
                println!("[rete-serial] DATA: {}", text);
            } else {
                println!("[rete-serial] DATA: {} bytes", payload.len());
            }
        }
        NodeEvent::Tick { expired_paths } => {
            if expired_paths > 0 {
                println!("[rete-serial] tick: expired {}", expired_paths);
            }
        }
    })
    .await;

    println!("[rete-serial] disconnected");
    loop {
        embassy_time::Timer::after(embassy_time::Duration::from_secs(1)).await;
    }
}
