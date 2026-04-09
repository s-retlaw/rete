//! Hand-rolled async HTTP server with session cookie auth.
//!
//! Two embassy tasks (pool_size=2) for concurrent connections.
//! Session token stored in static, set via cookie on login.

extern crate alloc;
use alloc::format;
use alloc::string::String;

use embassy_net::tcp::TcpSocket;
use embassy_time::Duration;
use embedded_io_async::{Read, Write};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use esp_println::println;

use crate::config;
use crate::status::{NODE_STATUS, StatusSnapshot, REBOOT_SIGNAL};

const STATUS_HTML: &str = include_str!("web_page.html");
const LOGIN_HTML: &str = include_str!("login_page.html");
const ADMIN_HTML: &str = include_str!("admin_page.html");

/// Active session token (None = no one logged in).
static SESSION: Mutex<CriticalSectionRawMutex, Option<[u8; 16]>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// HTTP listener task — spawned twice via pool_size=2
// ---------------------------------------------------------------------------

#[embassy_executor::task(pool_size = 3)]
pub async fn http_listener(id: u8, stack: embassy_net::Stack<'static>) -> ! {
    // Wait for link up
    loop {
        if stack.is_link_up() { break; }
        embassy_time::Timer::after(Duration::from_millis(500)).await;
    }
    if id == 0 {
        println!("[web] HTTP server ready on 192.168.4.1:80");
    }

    let mut rx_buf = [0u8; 1024];
    let mut tx_buf = [0u8; 4608];

    loop {
        let mut socket = TcpSocket::new(stack, &mut rx_buf, &mut tx_buf);
        socket.set_timeout(Some(Duration::from_secs(5)));

        match socket.accept(80).await {
            Ok(()) => {
                println!("[web:{}] connection accepted", id);
            }
            Err(e) => {
                println!("[web:{}] accept error: {:?}", id, e);
                socket.abort();
                continue;
            }
        }

        handle_request(&mut socket).await;
        println!("[web:{}] request handled", id);
        let _ = socket.flush().await;
        socket.close();
        // Wait for the TCP FIN handshake to complete
        embassy_time::Timer::after(Duration::from_millis(100)).await;
    }
}

// ---------------------------------------------------------------------------
// Request handling
// ---------------------------------------------------------------------------

async fn handle_request(socket: &mut TcpSocket<'_>) {
    let mut buf = [0u8; 2048];
    let n = match read_request(socket, &mut buf).await {
        Some(n) => n,
        None => return,
    };

    let request = match core::str::from_utf8(&buf[..n]) {
        Ok(s) => s,
        Err(_) => return,
    };

    let first_line = request.lines().next().unwrap_or("");
    println!("[web] req: {}", first_line);
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let full_path = parts.next().unwrap_or("/");

    let path = match full_path.find('?') {
        Some(i) => &full_path[..i],
        None => full_path,
    };

    match (method, path) {
        // Public routes
        ("GET", "/") => send_html(socket, STATUS_HTML).await,
        ("GET", "/api/status") => send_json_status(socket).await,
        ("GET", "/login") | ("GET", "/admin/login") => send_html(socket, LOGIN_HTML).await,

        // Login: POST with password in body
        ("POST", "/admin/login") => handle_login(socket, request).await,

        // Auth-protected routes (check session cookie)
        ("GET", "/admin") => {
            if check_session(request) {
                send_admin_page(socket).await;
            } else {
                send_html(socket, LOGIN_HTML).await;
            }
        }
        ("POST", "/admin/lora") => {
            if check_session(request) {
                let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
                save_lora(socket, body).await;
            } else { send_unauthorized(socket).await; }
        }
        ("POST", "/admin/wifi") => {
            if check_session(request) {
                let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
                save_wifi(socket, body).await;
            } else { send_unauthorized(socket).await; }
        }
        ("POST", "/admin/sta") => {
            if check_session(request) {
                let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
                save_sta(socket, body).await;
            } else { send_unauthorized(socket).await; }
        }
        ("POST", "/api/reboot") => {
            if check_session(request) {
                println!("[web] REBOOT requested");
                let _ = send_all(socket, b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nRebooting...").await;
                REBOOT_SIGNAL.signal(());
            } else {
                send_unauthorized(socket).await;
            }
        }

        _ => {
            let _ = send_all(socket, b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n").await;
        }
    }
}

// ---------------------------------------------------------------------------
// Session auth
// ---------------------------------------------------------------------------

fn check_session(request: &str) -> bool {
    let cookie = extract_cookie(request, "session");
    if cookie.is_empty() { return false; }

    // try_lock to avoid blocking — if locked, deny (race is harmless)
    match SESSION.try_lock() {
        Ok(guard) => {
            guard.as_ref().map_or(false, |token| {
                let mut hex = [0u8; 32];
                crate::display::format_hex(token, &mut hex);
                let token_str = core::str::from_utf8(&hex).unwrap_or("");
                cookie == token_str
            })
        }
        Err(_) => false,
    }
}

async fn handle_login(socket: &mut TcpSocket<'_>, request: &str) {
    // Extract password from POST body
    let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
    let pw = extract_form_value(body, "pw");

    let valid = match config::cached_config() {
        Some(cfg) => pw == cfg.admin_pass_str(),
        None => false,
    };

    if !valid {
        // Re-show login page with error hint
        let _ = send_all(socket, b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n").await;
        let _ = send_all(socket, b"<html><body style='background:#111;color:#f00;font-family:monospace;text-align:center;padding:40px'><h2>Wrong password</h2><p><a href='/admin' style='color:#0a0'>Try again</a></p></body></html>").await;
        return;
    }

    // Generate session token
    let mut token = [0u8; 16];
    let rng = esp_hal::rng::Rng::new();
    for chunk in token.chunks_mut(4) {
        let r = rng.random().to_le_bytes();
        let len = chunk.len().min(4);
        chunk[..len].copy_from_slice(&r[..len]);
    }

    // Store token
    if let Ok(mut guard) = SESSION.try_lock() {
        *guard = Some(token);
    }

    // Format token as hex for cookie
    let mut hex = [0u8; 32];
    crate::display::format_hex(&token, &mut hex);
    let token_str = core::str::from_utf8(&hex).unwrap_or("");

    // Redirect to admin with Set-Cookie
    let header = format!(
        "HTTP/1.1 303 See Other\r\nSet-Cookie: session={}; Path=/; HttpOnly\r\nLocation: /admin\r\nConnection: close\r\n\r\n",
        token_str
    );
    let _ = send_all(socket, header.as_bytes()).await;
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn send_html(socket: &mut TcpSocket<'_>, html: &str) {
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        html.len()
    );
    let _ = send_all(socket, header.as_bytes()).await;
    let _ = send_all(socket, html.as_bytes()).await;
}

async fn send_unauthorized(socket: &mut TcpSocket<'_>) {
    let _ = send_all(socket, b"HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<html><body style='background:#111;color:#f00;font-family:monospace;text-align:center;padding:40px'><h2>Unauthorized</h2><p><a href='/admin' style='color:#0a0'>Login</a></p></body></html>").await;
}

async fn send_json_status(socket: &mut TcpSocket<'_>) {
    let snap = NODE_STATUS.lock().await.clone();
    let body = format_json(&snap);
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = send_all(socket, header.as_bytes()).await;
    let _ = send_all(socket, body.as_bytes()).await;
}

async fn send_admin_page(socket: &mut TcpSocket<'_>) {
    let cfg = config::cached_config()
        .unwrap_or_else(|| config::NodeConfig::generate_default(&mut esp_hal::rng::Rng::new()));

    let sta_ssid = core::str::from_utf8(&cfg.sta_ssid[..cfg.sta_ssid_len as usize]).unwrap_or("");

    // Stack-format numbers — zero heap allocations
    let mut freq_buf = [0u8; 12];
    let freq_s = fmt_u32(&mut freq_buf, cfg.lora_freq);
    let mut tx_buf = [0u8; 12];
    let tx_s = fmt_i32(&mut tx_buf, cfg.lora_tx_power);

    // Stream response: write template chunks + substituted values directly to
    // the socket buffer. No full-page String clone on the heap.
    let _ = socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n").await;

    let mut rest = ADMIN_HTML;
    while let Some(i) = rest.find("{{") {
        let _ = socket.write_all(rest[..i].as_bytes()).await;
        rest = &rest[i + 2..];
        if let Some(j) = rest.find("}}") {
            let key = &rest[..j];
            rest = &rest[j + 2..];
            let val: &str = match key {
                "freq" => freq_s,
                "tx" => tx_s,
                "ap_ssid" => cfg.ap_ssid_str(),
                "sta_enabled" => if cfg.sta_enabled { "checked" } else { "" },
                "sta_ssid" => sta_ssid,
                _ => "",
            };
            let _ = socket.write_all(val.as_bytes()).await;
        }
    }
    if !rest.is_empty() {
        let _ = socket.write_all(rest.as_bytes()).await;
    }
    let _ = socket.flush().await;
}

fn fmt_u32<'a>(buf: &'a mut [u8], val: u32) -> &'a str {
    let mut n = val;
    let mut pos = buf.len();
    if n == 0 {
        pos -= 1;
        buf[pos] = b'0';
    } else {
        while n > 0 && pos > 0 {
            pos -= 1;
            buf[pos] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }
    core::str::from_utf8(&buf[pos..]).unwrap_or("0")
}

fn fmt_i32<'a>(buf: &'a mut [u8], val: i32) -> &'a str {
    if val < 0 {
        let mut n = (-(val as i64)) as u32;
        let mut pos = buf.len();
        while n > 0 && pos > 0 {
            pos -= 1;
            buf[pos] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        if pos > 0 {
            pos -= 1;
            buf[pos] = b'-';
        }
        core::str::from_utf8(&buf[pos..]).unwrap_or("0")
    } else {
        fmt_u32(buf, val as u32)
    }
}

async fn save_lora(socket: &mut TcpSocket<'_>, body: &str) {
    if let Some(mut cfg) = config::cached_config() {
        for param in body.split('&') {
            let (k, v) = split_kv(param);
            match k {
                "freq" => { if let Ok(v) = v.parse::<u32>() { cfg.lora_freq = v; } }
                "sf" => { if let Ok(v) = v.parse::<u8>() { cfg.lora_sf = v; } }
                "bw" => { if let Ok(v) = v.parse::<u32>() { cfg.lora_bw = v; } }
                "tx" => { if let Ok(v) = v.parse::<i32>() { cfg.lora_tx_power = v; } }
                _ => {}
            }
        }
        config::save_config(&cfg);
    }
    send_saved_redirect(socket).await;
}

async fn save_wifi(socket: &mut TcpSocket<'_>, body: &str) {
    if let Some(mut cfg) = config::cached_config() {
        for param in body.split('&') {
            let (k, v) = split_kv(param);
            let v = url_decode(v);
            match k {
                "ssid" => { let b = v.as_bytes(); let l = b.len().min(32); cfg.ap_ssid[..l].copy_from_slice(&b[..l]); cfg.ap_ssid_len = l as u8; }
                "pass" => { let b = v.as_bytes(); let l = b.len().min(64); cfg.ap_pass[..l].copy_from_slice(&b[..l]); cfg.ap_pass_len = l as u8; }
                _ => {}
            }
        }
        config::save_config(&cfg);
    }
    send_saved_redirect(socket).await;
}

async fn save_sta(socket: &mut TcpSocket<'_>, body: &str) {
    if let Some(mut cfg) = config::cached_config() {
        cfg.sta_enabled = false;
        for param in body.split('&') {
            let (k, v) = split_kv(param);
            let v = url_decode(v);
            match k {
                "enabled" => cfg.sta_enabled = v == "on" || v == "1",
                "ssid" => { let b = v.as_bytes(); let l = b.len().min(32); cfg.sta_ssid[..l].copy_from_slice(&b[..l]); cfg.sta_ssid_len = l as u8; }
                "pass" => { let b = v.as_bytes(); let l = b.len().min(64); cfg.sta_pass[..l].copy_from_slice(&b[..l]); cfg.sta_pass_len = l as u8; }
                _ => {}
            }
        }
        config::save_config(&cfg);
    }
    send_saved_redirect(socket).await;
}

async fn send_saved_redirect(socket: &mut TcpSocket<'_>) {
    let _ = send_all(socket, b"HTTP/1.1 303 See Other\r\nLocation: /admin\r\nConnection: close\r\n\r\n").await;
}

async fn send_text(socket: &mut TcpSocket<'_>, msg: &str) {
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        msg.len()
    );
    let _ = send_all(socket, header.as_bytes()).await;
    let _ = send_all(socket, msg.as_bytes()).await;
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

fn format_json(s: &StatusSnapshot) -> String {
    let mut ih = [0u8; 32];
    crate::display::format_hex(&s.identity_hash, &mut ih);
    let ih_str = core::str::from_utf8(&ih).unwrap_or("");
    let mut dh = [0u8; 32];
    crate::display::format_hex(&s.dest_hash, &mut dh);
    let dh_str = core::str::from_utf8(&dh).unwrap_or("");

    format!(
        concat!(
            "{{\"identity\":\"{}\",\"dest_hash\":\"{}\",\"uptime_secs\":{},",
            "\"lora\":{{\"freq_mhz\":{},\"sf\":{},\"bw_khz\":{},\"tx_dbm\":{}}},",
            "\"transport\":{{\"rx\":{},\"tx\":{},\"fwd\":{},\"announces_rx\":{},\"announces_tx\":{},\"paths\":{},\"links\":{}}}}}"
        ),
        ih_str, dh_str, s.uptime_secs,
        s.freq_hz / 1_000_000, s.sf, s.bw_hz / 1_000, s.tx_power,
        s.packets_rx, s.packets_tx, s.packets_fwd,
        s.announces_rx, s.announces_tx, s.paths, s.links,
    )
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Read from socket until \r\n\r\n or buffer full.
async fn read_request(socket: &mut TcpSocket<'_>, buf: &mut [u8]) -> Option<usize> {
    let mut total = 0;
    loop {
        if total >= buf.len() { return Some(total); }
        let n = socket.read(&mut buf[total..]).await.ok()?;
        if n == 0 { return if total > 0 { Some(total) } else { None }; }
        total += n;
        if total >= 4 {
            for i in 0..total - 3 {
                if &buf[i..i + 4] == b"\r\n\r\n" {
                    // Only try to read body for POST requests
                    if total >= 5 && &buf[..5] == b"POST " && total < buf.len() {
                        if let Ok(Ok(extra)) = embassy_time::with_timeout(
                            Duration::from_millis(200),
                            socket.read(&mut buf[total..]),
                        ).await {
                            if extra > 0 { total += extra; }
                        }
                    }
                    return Some(total);
                }
            }
        }
    }
}

async fn send_all(socket: &mut TcpSocket<'_>, data: &[u8]) -> Result<(), ()> {
    if let Err(e) = socket.write_all(data).await {
        println!("[web] write_all failed ({} bytes): {:?}", data.len(), e);
        return Err(());
    }
    if let Err(e) = socket.flush().await {
        println!("[web] flush failed: {:?}", e);
        return Err(());
    }
    println!("[web] sent {} bytes ok", data.len());
    Ok(())
}

fn extract_cookie<'a>(request: &'a str, name: &str) -> &'a str {
    for line in request.lines() {
        if let Some(cookies) = line.strip_prefix("Cookie: ").or_else(|| line.strip_prefix("cookie: ")) {
            for cookie in cookies.split("; ") {
                if let Some(val) = cookie.strip_prefix(name).and_then(|s| s.strip_prefix('=')) {
                    return val.trim();
                }
            }
        }
    }
    ""
}

fn extract_form_value<'a>(body: &'a str, name: &str) -> &'a str {
    for param in body.split('&') {
        if let Some(val) = param.strip_prefix(name).and_then(|s| s.strip_prefix('=')) {
            return val.trim();
        }
    }
    ""
}

fn split_kv(param: &str) -> (&str, &str) {
    match param.find('=') {
        Some(i) => (&param[..i], &param[i + 1..]),
        None => (param, ""),
    }
}

fn url_decode(s: &str) -> String {
    let mut out = String::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => { out.push(' '); i += 1; }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(h), Some(l)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                    out.push((h << 4 | l) as char);
                }
                i += 3;
            }
            c => { out.push(c as char); i += 1; }
        }
    }
    out
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
