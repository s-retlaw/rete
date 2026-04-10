//! OLED display driver for Heltec WiFi LoRa 32 V3/V4.
//!
//! Drives the onboard 128x64 SSD1306 over blocking I2C. Three screens:
//! - Splash: large "RETE" title (first 15 seconds)
//! - Identity page: hashes, paths, LoRa config
//! - Stats page: packet counters

use alloc::format;

use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{Line, PrimitiveStyle};
use embedded_graphics::text::{Alignment, Text};
use profont::{PROFONT_12_POINT, PROFONT_24_POINT, PROFONT_9_POINT};
use rete_embassy::EmbeddedNodeCore;
use ssd1306::mode::BufferedGraphicsMode;
use ssd1306::prelude::*;
use ssd1306::Ssd1306;

/// Concrete display type (blocking I2C, 128x64, buffered graphics).
pub type OledDisplay<DI> = Ssd1306<DI, DisplaySize128x64, BufferedGraphicsMode<DisplaySize128x64>>;

/// Tracks which page to show and the tick counter.
pub struct DisplayState {
    tick_count: u32,
}

impl DisplayState {
    pub fn new() -> Self {
        Self { tick_count: 0 }
    }

    /// Called every tick (~5s). Cycles through display pages.
    pub fn update<DI: WriteOnlyDataCommand>(
        &mut self,
        display: &mut OledDisplay<DI>,
        node_core: &EmbeddedNodeCore,
        now: u64,
        freq_hz: u32,
        sf: u8,
        admin_pw: &str,
    ) {
        self.tick_count += 1;

        if self.tick_count <= 3 {
            return;
        }

        let page = (self.tick_count - 3) % 2;
        match page {
            0 => draw_identity_page(display, node_core, now, freq_hz, sf, admin_pw),
            _ => draw_stats_page(display, node_core, now),
        }
    }
}

// ---------------------------------------------------------------------------
// Text styles
// ---------------------------------------------------------------------------

fn style_large() -> MonoTextStyle<'static, BinaryColor> {
    MonoTextStyle::new(&PROFONT_24_POINT, BinaryColor::On)
}

fn style_medium() -> MonoTextStyle<'static, BinaryColor> {
    MonoTextStyle::new(&PROFONT_12_POINT, BinaryColor::On)
}

fn style_small() -> MonoTextStyle<'static, BinaryColor> {
    MonoTextStyle::new(&PROFONT_9_POINT, BinaryColor::On)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create and initialise the SSD1306 in buffered graphics mode.
pub fn init_display<DI: WriteOnlyDataCommand>(di: DI) -> OledDisplay<DI> {
    let mut display = Ssd1306::new(di, DisplaySize128x64, DisplayRotation::Rotate0)
        .into_buffered_graphics_mode();
    display.init().unwrap();
    display.clear_buffer();
    display.flush().unwrap();
    display
}

/// Draw the splash screen: large "RETE", subtitle, LoRa params.
pub fn draw_splash<DI: WriteOnlyDataCommand>(display: &mut OledDisplay<DI>, freq_hz: u32, sf: u8) {
    display.clear_buffer();

    Text::with_alignment("RETE", Point::new(64, 27), style_large(), Alignment::Center)
        .draw(display)
        .ok();

    Text::with_alignment(
        "Reticulum Node",
        Point::new(64, 46),
        style_small(),
        Alignment::Center,
    )
    .draw(display)
    .ok();

    let freq_mhz = freq_hz / 1_000_000;
    let info_line = format!("LoRa {}MHz SF{}  WiFi AP", freq_mhz, sf);
    Text::with_alignment(&info_line, Point::new(64, 60), style_small(), Alignment::Center)
        .draw(display)
        .ok();

    display.flush().ok();
}

/// Draw the identity / network page.
pub fn draw_identity_page<DI: WriteOnlyDataCommand>(
    display: &mut OledDisplay<DI>,
    node_core: &EmbeddedNodeCore,
    now: u64,
    freq_hz: u32,
    sf: u8,
    admin_pw: &str,
) {
    display.clear_buffer();

    let stats = node_core.stats(now);
    draw_header(display, stats.uptime_secs);

    let ih = node_core.identity().hash();
    let mut ih_hex = [0u8; 12];
    format_hex(&ih.as_bytes()[..6], &mut ih_hex);
    let ih_str = ::core::str::from_utf8(&ih_hex).unwrap_or("?");
    let id_line = format!("ID: {}", ih_str);
    Text::new(&id_line, Point::new(0, 29), style_small())
        .draw(display)
        .ok();

    let dh = node_core.dest_hash();
    let mut dh_hex = [0u8; 12];
    format_hex(&dh.as_bytes()[..6], &mut dh_hex);
    let dh_str = ::core::str::from_utf8(&dh_hex).unwrap_or("?");
    let dh_line = format!("DH: {}", dh_str);
    Text::new(&dh_line, Point::new(0, 40), style_small())
        .draw(display)
        .ok();

    let paths = node_core.path_count();
    let links = stats.transport.links_established;
    let freq_mhz = freq_hz / 1_000_000;
    let pl_line = format!("P:{} L:{} {}MHz SF{}", paths, links, freq_mhz, sf);
    Text::new(&pl_line, Point::new(0, 51), style_small())
        .draw(display)
        .ok();

    let wifi_line = format!("PW:{}", admin_pw);
    Text::new(&wifi_line, Point::new(0, 62), style_small())
        .draw(display)
        .ok();

    display.flush().ok();
}

/// Draw the traffic stats page.
pub fn draw_stats_page<DI: WriteOnlyDataCommand>(
    display: &mut OledDisplay<DI>,
    node_core: &EmbeddedNodeCore,
    now: u64,
) {
    display.clear_buffer();

    let stats = node_core.stats(now);
    let t = &stats.transport;
    draw_header(display, stats.uptime_secs);

    let rx_tx = format!("RX:{} TX:{}", t.packets_received, t.packets_sent);
    Text::new(&rx_tx, Point::new(0, 29), style_small())
        .draw(display)
        .ok();

    let fwd_drp = format!(
        "FWD:{} DRP:{}",
        t.packets_forwarded,
        t.packets_dropped_dedup + t.packets_dropped_invalid,
    );
    Text::new(&fwd_drp, Point::new(0, 40), style_small())
        .draw(display)
        .ok();

    let ann = format!("ANN r:{} t:{} Lnk:{}", t.announces_received, t.announces_sent, t.links_established);
    Text::new(&ann, Point::new(0, 51), style_small())
        .draw(display)
        .ok();

    let tcp = if crate::status::TCP_CONNECTED.load(core::sync::atomic::Ordering::Relaxed) { " TCP" } else { "" };
    let wifi_line = match crate::status::sta_ip_str() {
        Some(ip) => format!("STA:{}{}", ip, tcp),
        None => format!("AP: 192.168.4.1"),
    };
    Text::new(&wifi_line, Point::new(0, 62), style_small())
        .draw(display)
        .ok();

    display.flush().ok();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Draw the shared header: "RETE" left, uptime right, separator line.
fn draw_header<DI: WriteOnlyDataCommand>(display: &mut OledDisplay<DI>, uptime_secs: u64) {
    Text::new("RETE", Point::new(0, 13), style_medium())
        .draw(display)
        .ok();

    let mut ut_buf = [0u8; 8];
    format_uptime(&mut ut_buf, uptime_secs);
    let ut_str = ::core::str::from_utf8(&ut_buf).unwrap_or("??:??:??");
    Text::new(ut_str, Point::new(72, 13), style_medium())
        .draw(display)
        .ok();

    Line::new(Point::new(0, 16), Point::new(127, 16))
        .into_styled(PrimitiveStyle::with_stroke(BinaryColor::On, 1))
        .draw(display)
        .ok();
}

/// Format seconds as "HH:MM:SS" into an 8-byte buffer.
fn format_uptime(buf: &mut [u8; 8], secs: u64) {
    let h = (secs / 3600) % 100;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    buf[0] = b'0' + (h / 10) as u8;
    buf[1] = b'0' + (h % 10) as u8;
    buf[2] = b':';
    buf[3] = b'0' + (m / 10) as u8;
    buf[4] = b'0' + (m % 10) as u8;
    buf[5] = b':';
    buf[6] = b'0' + (s / 10) as u8;
    buf[7] = b'0' + (s % 10) as u8;
}

/// Encode `bytes` as lowercase hex into `out`. `out.len()` must be `2 * bytes.len()`.
pub fn format_hex(bytes: &[u8], out: &mut [u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, &b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0F) as usize];
    }
}
