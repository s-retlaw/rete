//! ESP32-C6 comprehensive test firmware — exercises all NodeCore capabilities.
//!
//! HDLC-framed Reticulum packets over UART0 (connected to CP2102/USB bridge).
//! Handles all NodeEvent variants via `run_with_handler`, enabling tests for:
//! - Links (as responder and initiator)
//! - Channel messaging
//! - Request/response
//! - Resource transfer
//! - Proof of delivery
//! - Multiple destinations
//!
//! Build & flash:
//!   cd examples/esp32c6
//!   cargo +nightly build --release --features esp32c6 --bin rete-esp32c6-serial-test
//!   espflash flash --port /dev/ttyUSB0 \
//!     target/riscv32imac-unknown-none-elf/release/rete-esp32c6-serial-test

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;

use embassy_executor::Spawner;
use embassy_time::Instant;
use embedded_io_async::Write;
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::uart::{self, Uart};
use esp_hal::{clock::CpuClock, ram, timer::timg::TimerGroup};
use esp_println::println;
use rete_embassy::{
    EmbassyHdlcInterface, EmbassyNode, EmbeddedNodeCore, NodeEvent, OutboundPacket, ProofStrategy,
};

#[path = "../rng.rs"]
mod rng;
use rng::EspRng;

esp_bootloader_esp_idf::esp_app_desc!();

fn hex4(b: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    for (i, &byte) in b[..4].iter().enumerate() {
        let hi = byte >> 4;
        let lo = byte & 0x0f;
        out[i * 2] = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
        out[i * 2 + 1] = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
    }
    out
}

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

    println!("[serial-test] booted");

    // UART0 async — connected to CP2102 USB bridge
    let uart_config = uart::Config::default().with_baudrate(115_200);
    let mut uart0 = Uart::new(peripherals.UART0, uart_config)
        .expect("UART0 init failed")
        .into_async();

    let _ = uart0
        .write_all(b"[serial-test] UART async ready\r\n")
        .await;

    let mut iface = EmbassyHdlcInterface::new(uart0);

    // Deterministic identity for reproducible testing
    println!("[serial-test] creating identity");
    let identity = rete_core::Identity::from_seed(b"rete-esp32c6-test").expect("invalid key");

    let mut node = EmbassyNode::new(identity, "rete", &["example", "v1"]);
    node.core.set_echo_data(true);
    node.core.set_proof_strategy(ProofStrategy::ProveAll);

    // Register a secondary destination for multi-dest testing
    let secondary_hash = node
        .core
        .register_destination("rete", &["test", "secondary"]);
    let sh = hex4(&secondary_hash);
    println!(
        "[serial-test] secondary dest: {}",
        core::str::from_utf8(&sh).unwrap_or("????")
    );

    let dh = node.core.dest_hash();
    let dh_hex = hex4(dh);
    println!(
        "[serial-test] primary dest: {}",
        core::str::from_utf8(&dh_hex).unwrap_or("????")
    );

    let mut rng = EspRng(esp_hal::rng::Rng::new());

    println!("[serial-test] running (full handler mode)");
    node.run_with_handler(&mut iface, &mut rng, |event, core, rng| {
        handle_event(event, core, rng)
    })
    .await;

    println!("[serial-test] disconnected");
    loop {
        embassy_time::Timer::after(embassy_time::Duration::from_secs(1)).await;
    }
}

fn handle_event(
    event: NodeEvent,
    core: &mut EmbeddedNodeCore,
    rng: &mut EspRng,
) -> Vec<OutboundPacket> {
    let now = Instant::now().as_secs();
    let mut out = Vec::new();

    match event {
        NodeEvent::AnnounceReceived {
            dest_hash,
            hops,
            app_data,
            ..
        } => {
            let dh = hex4(&dest_hash);
            println!(
                "[serial-test] ANNOUNCE {:?} hops={}",
                core::str::from_utf8(&dh).unwrap_or("????"),
                hops,
            );

            // If app_data contains "LINK_ME", initiate a link to the announcer
            if let Some(ref data) = app_data {
                if data == b"LINK_ME" {
                    println!("[serial-test] LINK_ME detected, initiating link");
                    if let Some((pkt, link_id)) = core.initiate_link(dest_hash, now, rng) {
                        let lh = hex4(&link_id);
                        println!(
                            "[serial-test] link initiated: {}",
                            core::str::from_utf8(&lh).unwrap_or("????")
                        );
                        out.push(pkt);
                    } else {
                        println!("[serial-test] link initiation failed");
                    }
                }
            }
        }

        NodeEvent::DataReceived { payload, .. } => {
            if let Ok(text) = core::str::from_utf8(&payload) {
                println!("[serial-test] DATA: {}", text);
            } else {
                println!("[serial-test] DATA: {} bytes", payload.len());
            }
        }

        NodeEvent::LinkEstablished { link_id } => {
            let lh = hex4(&link_id);
            println!(
                "[serial-test] LINK_ESTABLISHED: {}",
                core::str::from_utf8(&lh).unwrap_or("????")
            );

            // Send a greeting channel message on link establishment
            if let Some(pkt) =
                core.send_channel_message(&link_id, 0x0001, b"esp32-hello", now, rng)
            {
                println!("[serial-test] sent channel greeting");
                out.push(pkt);
            }
        }

        NodeEvent::ChannelMessages { link_id, messages } => {
            for (msg_type, payload) in &messages {
                if let Ok(text) = core::str::from_utf8(payload) {
                    println!(
                        "[serial-test] CHANNEL_MSG type=0x{:04x}: {}",
                        msg_type, text
                    );
                } else {
                    println!(
                        "[serial-test] CHANNEL_MSG type=0x{:04x}: {} bytes",
                        msg_type,
                        payload.len()
                    );
                }

                // Echo back with "echo:" prefix
                let mut echo = b"echo:".to_vec();
                echo.extend_from_slice(payload);
                if let Some(pkt) = core.send_channel_message(&link_id, *msg_type, &echo, now, rng)
                {
                    out.push(pkt);
                }
            }
        }

        NodeEvent::LinkData {
            link_id,
            data,
            context,
        } => {
            if let Ok(text) = core::str::from_utf8(&data) {
                println!("[serial-test] LINK_DATA ctx={}: {}", context, text);
            } else {
                println!(
                    "[serial-test] LINK_DATA ctx={}: {} bytes",
                    context,
                    data.len()
                );
            }

            // Echo back with "echo:" prefix
            let mut echo = b"echo:".to_vec();
            echo.extend_from_slice(&data);
            if let Some(pkt) = core.send_link_data(&link_id, &echo, rng) {
                out.push(pkt);
            }
        }

        NodeEvent::RequestReceived {
            link_id,
            request_id,
            path_hash,
            data,
        } => {
            let ph = hex4(&path_hash);
            println!(
                "[serial-test] REQUEST path={}",
                core::str::from_utf8(&ph).unwrap_or("????")
            );

            // Respond with "esp32-response:<path_hash_hex>"
            let mut resp = b"esp32-response:".to_vec();
            resp.extend_from_slice(&ph);
            if let Some(pkt) = core.send_response(&link_id, &request_id, &resp, rng) {
                println!("[serial-test] sent response");
                out.push(pkt);
            }

            let _ = data; // used for logging
        }

        NodeEvent::ResponseReceived {
            link_id, data, ..
        } => {
            let lh = hex4(&link_id);
            if let Ok(text) = core::str::from_utf8(&data) {
                println!("[serial-test] RESPONSE on {}: {}",
                    core::str::from_utf8(&lh).unwrap_or("????"), text);
            }
        }

        NodeEvent::ResourceOffered {
            link_id,
            resource_hash,
            total_size,
        } => {
            let rh = hex4(&resource_hash);
            let lh = hex4(&link_id);
            println!(
                "[serial-test] RESOURCE_OFFERED link={} hash={} size={}",
                core::str::from_utf8(&lh).unwrap_or("????"),
                core::str::from_utf8(&rh).unwrap_or("????"),
                total_size,
            );
        }

        NodeEvent::ResourceProgress {
            resource_hash,
            current,
            total,
            ..
        } => {
            let rh = hex4(&resource_hash);
            println!(
                "[serial-test] RESOURCE_PROGRESS hash={} {}/{}",
                core::str::from_utf8(&rh).unwrap_or("????"),
                current,
                total,
            );
        }

        NodeEvent::ResourceComplete {
            link_id,
            resource_hash,
            data,
        } => {
            let rh = hex4(&resource_hash);
            let lh = hex4(&link_id);
            println!(
                "[serial-test] RESOURCE_COMPLETE link={} hash={} len={}",
                core::str::from_utf8(&lh).unwrap_or("????"),
                core::str::from_utf8(&rh).unwrap_or("????"),
                data.len(),
            );
        }

        NodeEvent::ResourceFailed {
            link_id,
            resource_hash,
        } => {
            let rh = hex4(&resource_hash);
            let lh = hex4(&link_id);
            println!(
                "[serial-test] RESOURCE_FAILED link={} hash={}",
                core::str::from_utf8(&lh).unwrap_or("????"),
                core::str::from_utf8(&rh).unwrap_or("????"),
            );
        }

        NodeEvent::LinkClosed { link_id } => {
            let lh = hex4(&link_id);
            println!(
                "[serial-test] LINK_CLOSED: {}",
                core::str::from_utf8(&lh).unwrap_or("????")
            );
        }

        NodeEvent::ProofReceived { packet_hash } => {
            let ph = hex4(&packet_hash);
            println!(
                "[serial-test] PROOF_RECEIVED: {}",
                core::str::from_utf8(&ph).unwrap_or("????")
            );
        }

        NodeEvent::Tick {
            expired_paths,
            closed_links,
        } => {
            if expired_paths > 0 || closed_links > 0 {
                println!(
                    "[serial-test] tick: expired={} closed_links={}",
                    expired_paths, closed_links,
                );
            }
        }

        NodeEvent::LinkIdentified { link_id, identity_hash, .. } => {
            let lh = hex4(&link_id);
            let ih = hex4(&identity_hash);
            println!(
                "[serial-test] LINK_IDENTIFIED link={} identity={}",
                core::str::from_utf8(&lh).unwrap_or("????"),
                core::str::from_utf8(&ih).unwrap_or("????"),
            );
        }
    }

    out
}
