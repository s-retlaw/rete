//! ESP32-S3 bare-metal Embassy example.
//!
//! Flash:
//!   cargo build -p rete-example-esp32s3 --target xtensa-esp32s3-none-elf --release
//!   espflash flash target/xtensa-esp32s3-none-elf/release/rete-esp32s3
#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
