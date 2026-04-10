//! OLED display driver for Heltec WiFi LoRa 32 V3/V4.
//!
//! Drives the onboard 128x64 SSD1306 over blocking I2C. Five screens:
//! - Splash: large "RETE" title (first 15 seconds)
//! - IDENT: identity hashes, uptime, admin password
//! - LORA: radio config, paths, links, announces
//! - TRAFFIC: packet counters, forwarding, drops
//! - WIFI: AP SSID, STA IP, TCP status, uptime

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

/// Display configuration passed from main — avoids passing many individual fields.
pub struct DispConfig<'a> {
    pub freq_hz: u32,
    pub sf: u8,
    pub bw_hz: u32,
    pub tx_power: i32,
    pub admin_pw: &'a str,
    pub ap_ssid: &'a str,
    pub sta_enabled: bool,
}

const NUM_PAGES: u32 = 4;

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
        cfg: &DispConfig,
    ) {
        self.tick_count += 1;

        // Keep splash for first 3 ticks (~15s)
        if self.tick_count <= 3 {
            return;
        }

        let page = (self.tick_count - 3) % NUM_PAGES;
        match page {
            0 => draw_identity_page(display, node_core, now, cfg.admin_pw),
            1 => draw_lora_page(display, node_core, now, cfg.freq_hz, cfg.sf, cfg.bw_hz, cfg.tx_power),
            2 => draw_traffic_page(display, node_core, now),
            _ => draw_wifi_page(display, now, cfg.ap_ssid, cfg.sta_enabled),
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
    let info_line = format!("LoRa {}MHz SF{}", freq_mhz, sf);
    Text::with_alignment(&info_line, Point::new(64, 60), style_small(), Alignment::Center)
        .draw(display)
        .ok();

    display.flush().ok();
}

// ---------------------------------------------------------------------------
// Page 0 — IDENTITY
// ---------------------------------------------------------------------------

fn draw_identity_page<DI: WriteOnlyDataCommand>(
    display: &mut OledDisplay<DI>,
    node_core: &EmbeddedNodeCore,
    now: u64,
    admin_pw: &str,
) {
    display.clear_buffer();
    draw_header(display, "ID");

    let stats = node_core.stats(now);

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

    let mut ut_buf = [0u8; 8];
    let ut_len = format_uptime_compact(&mut ut_buf, stats.uptime_secs);
    let ut_str = ::core::str::from_utf8(&ut_buf[..ut_len]).unwrap_or("?");
    let up_line = format!("Up: {}", ut_str);
    Text::new(&up_line, Point::new(0, 51), style_small())
        .draw(display)
        .ok();

    let pw_line = format!("PW: {}", admin_pw);
    Text::new(&pw_line, Point::new(0, 62), style_small())
        .draw(display)
        .ok();

    display.flush().ok();
}

// ---------------------------------------------------------------------------
// Page 1 — LORA
// ---------------------------------------------------------------------------

fn draw_lora_page<DI: WriteOnlyDataCommand>(
    display: &mut OledDisplay<DI>,
    node_core: &EmbeddedNodeCore,
    now: u64,
    freq_hz: u32,
    sf: u8,
    bw_hz: u32,
    tx_power: i32,
) {
    display.clear_buffer();
    draw_header(display, "LORA");

    let stats = node_core.stats(now);
    let t = &stats.transport;

    let freq_mhz = freq_hz / 1_000_000;
    let bw_khz = bw_hz / 1_000;
    let radio_line = format!("{}MHz SF{} BW{}k", freq_mhz, sf, bw_khz);
    Text::new(&radio_line, Point::new(0, 29), style_small())
        .draw(display)
        .ok();

    let tx_line = format!("TX:{}dBm CR:4/5", tx_power);
    Text::new(&tx_line, Point::new(0, 40), style_small())
        .draw(display)
        .ok();

    let paths = node_core.path_count();
    let links = t.links_established;
    let pl_line = format!("Paths:{} Links:{}", paths, links);
    Text::new(&pl_line, Point::new(0, 51), style_small())
        .draw(display)
        .ok();

    let ann_line = format!("ANN r:{} t:{}", t.announces_received, t.announces_sent);
    Text::new(&ann_line, Point::new(0, 62), style_small())
        .draw(display)
        .ok();

    display.flush().ok();
}

// ---------------------------------------------------------------------------
// Page 2 — TRAFFIC
// ---------------------------------------------------------------------------

fn draw_traffic_page<DI: WriteOnlyDataCommand>(
    display: &mut OledDisplay<DI>,
    node_core: &EmbeddedNodeCore,
    now: u64,
) {
    display.clear_buffer();
    draw_header(display, "TRAFFIC");

    let stats = node_core.stats(now);
    let t = &stats.transport;

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

    let ann_line = format!("ANN rt:{} lim:{}", t.announces_retransmitted, t.announces_rate_limited);
    Text::new(&ann_line, Point::new(0, 51), style_small())
        .draw(display)
        .ok();

    let lnk_line = format!("Lnk ok:{} fail:{}", t.links_established, t.links_failed);
    Text::new(&lnk_line, Point::new(0, 62), style_small())
        .draw(display)
        .ok();

    display.flush().ok();
}

// ---------------------------------------------------------------------------
// Page 3 — WIFI
// ---------------------------------------------------------------------------

fn draw_wifi_page<DI: WriteOnlyDataCommand>(
    display: &mut OledDisplay<DI>,
    now: u64,
    ap_ssid: &str,
    sta_enabled: bool,
) {
    display.clear_buffer();
    draw_header(display, "WIFI");

    if sta_enabled {
        // STA mode: show network IP, TCP, AP as secondary
        let sta_line = match crate::status::sta_ip_str() {
            Some(ip) => format!("IP: {}", ip),
            None => format!("IP: connecting..."),
        };
        Text::new(&sta_line, Point::new(0, 29), style_small())
            .draw(display)
            .ok();

        let tcp_str = if crate::status::TCP_CONNECTED.load(core::sync::atomic::Ordering::Relaxed) {
            "TCP:4242 connected"
        } else {
            "TCP:4242 listening"
        };
        Text::new(tcp_str, Point::new(0, 40), style_small())
            .draw(display)
            .ok();

        let ap_line = format!("AP: {}", ap_ssid);
        Text::new(&ap_line, Point::new(0, 51), style_small())
            .draw(display)
            .ok();
    } else {
        // AP-only mode: show AP info prominently
        let ap_line = format!("AP: {}", ap_ssid);
        Text::new(&ap_line, Point::new(0, 29), style_small())
            .draw(display)
            .ok();

        Text::new("IP: 192.168.4.1", Point::new(0, 40), style_small())
            .draw(display)
            .ok();

        Text::new("Admin :80", Point::new(0, 51), style_small())
            .draw(display)
            .ok();
    }

    let mut ut_buf = [0u8; 8];
    let ut_len = format_uptime_compact(&mut ut_buf, now);
    let ut_str = ::core::str::from_utf8(&ut_buf[..ut_len]).unwrap_or("?");
    let up_line = format!("Up: {}", ut_str);
    Text::new(&up_line, Point::new(0, 62), style_small())
        .draw(display)
        .ok();

    display.flush().ok();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Draw the shared header: "RETE" left, page label right, separator line.
fn draw_header<DI: WriteOnlyDataCommand>(display: &mut OledDisplay<DI>, label: &str) {
    Text::new("RETE", Point::new(0, 13), style_medium())
        .draw(display)
        .ok();

    Text::with_alignment(label, Point::new(127, 13), style_medium(), Alignment::Right)
        .draw(display)
        .ok();

    Line::new(Point::new(0, 16), Point::new(127, 16))
        .into_styled(PrimitiveStyle::with_stroke(BinaryColor::On, 1))
        .draw(display)
        .ok();
}

/// Format seconds as compact uptime: "XXhXXm" or "XXdXXh" for >24h.
/// Returns the number of bytes written.
fn format_uptime_compact(buf: &mut [u8; 8], secs: u64) -> usize {
    if secs < 3600 {
        // Under 1 hour: "XXmXXs"
        let m = secs / 60;
        let s = secs % 60;
        let mut pos = 0;
        pos += write_u64(&mut buf[pos..], m);
        buf[pos] = b'm';
        pos += 1;
        pos += write_u64(&mut buf[pos..], s);
        buf[pos] = b's';
        pos += 1;
        pos
    } else if secs < 86400 {
        // Under 1 day: "XXhXXm"
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        let mut pos = 0;
        pos += write_u64(&mut buf[pos..], h);
        buf[pos] = b'h';
        pos += 1;
        pos += write_u64(&mut buf[pos..], m);
        buf[pos] = b'm';
        pos += 1;
        pos
    } else {
        // Over 1 day: "XXdXXh"
        let d = secs / 86400;
        let h = (secs % 86400) / 3600;
        let mut pos = 0;
        pos += write_u64(&mut buf[pos..], d);
        buf[pos] = b'd';
        pos += 1;
        pos += write_u64(&mut buf[pos..], h);
        buf[pos] = b'h';
        pos += 1;
        pos
    }
}

/// Write a u64 as decimal into buf, return bytes written.
fn write_u64(buf: &mut [u8], val: u64) -> usize {
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut n = val;
    let mut i = 0;
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    for j in 0..i {
        buf[j] = tmp[i - 1 - j];
    }
    i
}

/// Encode `bytes` as lowercase hex into `out`. `out.len()` must be `2 * bytes.len()`.
pub fn format_hex(bytes: &[u8], out: &mut [u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, &b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0F) as usize];
    }
}
