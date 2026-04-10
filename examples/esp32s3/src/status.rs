//! Shared node status snapshot — updated by the node tick, read by the HTTP server.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use rete_embassy::EmbeddedNodeCore;

/// STA IP address as a packed u32 (0 = not connected). Updated by the STA monitor task.
pub static STA_IP: AtomicU32 = AtomicU32::new(0);

/// TCP rete interface connected. Updated by tcp_rete_task.
pub static TCP_CONNECTED: AtomicBool = AtomicBool::new(false);

/// Signal for requesting a reboot. Web handler signals, reboot task waits.
pub static REBOOT_SIGNAL: embassy_sync::signal::Signal<CriticalSectionRawMutex, ()> =
    embassy_sync::signal::Signal::new();

/// Format the STA IP as a string, or return None if not connected.
pub fn sta_ip_str() -> Option<alloc::string::String> {
    let ip = STA_IP.load(Ordering::Relaxed);
    if ip == 0 {
        return None;
    }
    let bytes = ip.to_be_bytes();
    Some(alloc::format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]))
}

/// Snapshot of node state for the web status page.
#[derive(Clone, Default)]
pub struct StatusSnapshot {
    pub identity_hash: [u8; 16],
    pub dest_hash: [u8; 16],
    pub uptime_secs: u64,
    pub freq_hz: u32,
    pub sf: u8,
    pub bw_hz: u32,
    pub tx_power: i32,
    pub packets_rx: u64,
    pub packets_tx: u64,
    pub packets_fwd: u64,
    pub announces_rx: u64,
    pub announces_tx: u64,
    pub paths: usize,
    pub links: u64,
    pub sta_ip: u32,
    pub tcp_connected: bool,
}

pub static NODE_STATUS: Mutex<CriticalSectionRawMutex, StatusSnapshot> =
    Mutex::new(StatusSnapshot {
        identity_hash: [0; 16],
        dest_hash: [0; 16],
        uptime_secs: 0,
        freq_hz: 0,
        sf: 0,
        bw_hz: 0,
        tx_power: 0,
        packets_rx: 0,
        packets_tx: 0,
        packets_fwd: 0,
        announces_rx: 0,
        announces_tx: 0,
        paths: 0,
        links: 0,
        sta_ip: 0,
        tcp_connected: false,
    });

/// Update the shared snapshot from node core state. Called on each tick.
pub fn update_status(core: &EmbeddedNodeCore, now: u64, freq_hz: u32, sf: u8, bw_hz: u32, tx_power: i32) {
    let stats = core.stats(now);
    let t = &stats.transport;
    // try_lock to avoid blocking the node loop — skip update if HTTP is reading
    if let Ok(mut snap) = NODE_STATUS.try_lock() {
        snap.identity_hash = *core.identity().hash().as_bytes();
        snap.dest_hash = *core.dest_hash().as_bytes();
        snap.uptime_secs = stats.uptime_secs;
        snap.freq_hz = freq_hz;
        snap.sf = sf;
        snap.bw_hz = bw_hz;
        snap.tx_power = tx_power;
        snap.packets_rx = t.packets_received;
        snap.packets_tx = t.packets_sent;
        snap.packets_fwd = t.packets_forwarded;
        snap.announces_rx = t.announces_received;
        snap.announces_tx = t.announces_sent;
        snap.paths = core.path_count();
        snap.links = t.links_established;
        snap.sta_ip = STA_IP.load(Ordering::Relaxed);
        snap.tcp_connected = TCP_CONNECTED.load(Ordering::Relaxed);
    }
}
