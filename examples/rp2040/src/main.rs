//! Raspberry Pi Pico 2W (RP2040) bare-metal Embassy example.
//!
//! Flash:
//!   cargo build -p rete-example-rp2040 --target thumbv6m-none-eabi --release
#![no_std]
#![no_main]

use cortex_m_rt::entry;

#[entry]
fn main() -> ! { loop {} }

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
