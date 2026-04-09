//! Persistent node configuration stored in a dedicated flash sector.
//!
//! Uses a simple format: magic + version + data + CRC32. One sector (4KB)
//! at a fixed flash offset. Config survives firmware reflashes as long as
//! the sector isn't erased.

extern crate alloc;

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embedded_storage::nor_flash::{NorFlash, ReadNorFlash};

/// Flash offset for config sector. Must not overlap with app partition.
/// App partition: 0x10000..~0xFB0000. We use 0xF00000 (15MB mark).
const CONFIG_OFFSET: u32 = 0xF0_0000;
const CONFIG_MAGIC: u32 = 0x5245_5445; // "RETE" in ASCII
const CONFIG_VERSION: u8 = 1;
const SECTOR_SIZE: u32 = 4096;

/// Cached config — loaded once at boot, updated on save. Avoids 4KB stack
/// allocations from flash reads inside embassy tasks (which overflow the stack).
static CACHED_CONFIG: Mutex<CriticalSectionRawMutex, Option<NodeConfig>> = Mutex::new(None);

/// Initialize the cache from flash. Call once at boot before spawning web tasks.
pub fn init_cache(cfg: &NodeConfig) {
    if let Ok(mut guard) = CACHED_CONFIG.try_lock() {
        *guard = Some(cfg.clone());
    }
}

/// Read config from the in-memory cache (no flash access, no large stack buffer).
pub fn cached_config() -> Option<NodeConfig> {
    match CACHED_CONFIG.try_lock() {
        Ok(guard) => guard.clone(),
        Err(_) => None,
    }
}

/// Persistent node configuration.
#[derive(Clone)]
pub struct NodeConfig {
    // Identity
    pub identity_key: [u8; 64],
    // LoRa
    pub lora_freq: u32,
    pub lora_sf: u8,
    pub lora_bw: u32,
    pub lora_tx_power: i32,
    // WiFi AP
    pub ap_ssid: [u8; 32],
    pub ap_ssid_len: u8,
    pub ap_pass: [u8; 64],
    pub ap_pass_len: u8,
    // WiFi STA (upstream bridge)
    pub sta_enabled: bool,
    pub sta_ssid: [u8; 32],
    pub sta_ssid_len: u8,
    pub sta_pass: [u8; 64],
    pub sta_pass_len: u8,
    // Admin
    pub admin_pass: [u8; 16],
    pub admin_pass_len: u8,
}

impl NodeConfig {
    /// AP SSID as a string slice.
    pub fn ap_ssid_str(&self) -> &str {
        ::core::str::from_utf8(&self.ap_ssid[..self.ap_ssid_len as usize]).unwrap_or("ReteNode")
    }

    /// AP password as a string slice (empty = open network).
    pub fn ap_pass_str(&self) -> &str {
        ::core::str::from_utf8(&self.ap_pass[..self.ap_pass_len as usize]).unwrap_or("")
    }

    /// Admin password as a string slice.
    pub fn admin_pass_str(&self) -> &str {
        ::core::str::from_utf8(&self.admin_pass[..self.admin_pass_len as usize]).unwrap_or("")
    }

    /// Generate default config with random identity and admin password.
    pub fn generate_default(rng: &mut esp_hal::rng::Rng) -> Self {
        let mut identity_key = [0u8; 64];
        rng.read(&mut identity_key);

        // Generate 8-char hex admin password from random bytes
        let mut admin_raw = [0u8; 4];
        rng.read(&mut admin_raw);
        let mut admin_pass = [0u8; 16];
        crate::display::format_hex(&admin_raw, &mut admin_pass[..8]);

        // Default AP SSID: "ReteNode"
        let ssid = b"ReteNode";
        let mut ap_ssid = [0u8; 32];
        ap_ssid[..ssid.len()].copy_from_slice(ssid);

        NodeConfig {
            identity_key,
            lora_freq: 915_000_000,
            lora_sf: 8,
            lora_bw: 125_000,
            lora_tx_power: 14,
            ap_ssid,
            ap_ssid_len: ssid.len() as u8,
            ap_pass: [0u8; 64],
            ap_pass_len: 0,
            sta_enabled: false,
            sta_ssid: [0u8; 32],
            sta_ssid_len: 0,
            sta_pass: [0u8; 64],
            sta_pass_len: 0,
            admin_pass,
            admin_pass_len: 8,
        }
    }

    /// Serialize config to a byte buffer with magic + version + CRC.
    fn serialize(&self, buf: &mut [u8; SECTOR_SIZE as usize]) {
        buf.fill(0xFF); // flash erase value

        // Header
        buf[0..4].copy_from_slice(&CONFIG_MAGIC.to_le_bytes());
        buf[4] = CONFIG_VERSION;

        // Data starting at offset 8
        let mut pos = 8;

        buf[pos..pos + 64].copy_from_slice(&self.identity_key);
        pos += 64;

        buf[pos..pos + 4].copy_from_slice(&self.lora_freq.to_le_bytes());
        pos += 4;
        buf[pos] = self.lora_sf;
        pos += 1;
        buf[pos..pos + 4].copy_from_slice(&self.lora_bw.to_le_bytes());
        pos += 4;
        buf[pos..pos + 4].copy_from_slice(&self.lora_tx_power.to_le_bytes());
        pos += 4;

        buf[pos..pos + 32].copy_from_slice(&self.ap_ssid);
        pos += 32;
        buf[pos] = self.ap_ssid_len;
        pos += 1;
        buf[pos..pos + 64].copy_from_slice(&self.ap_pass);
        pos += 64;
        buf[pos] = self.ap_pass_len;
        pos += 1;

        buf[pos] = self.sta_enabled as u8;
        pos += 1;
        buf[pos..pos + 32].copy_from_slice(&self.sta_ssid);
        pos += 32;
        buf[pos] = self.sta_ssid_len;
        pos += 1;
        buf[pos..pos + 64].copy_from_slice(&self.sta_pass);
        pos += 64;
        buf[pos] = self.sta_pass_len;
        pos += 1;

        buf[pos..pos + 16].copy_from_slice(&self.admin_pass);
        pos += 16;
        buf[pos] = self.admin_pass_len;
        pos += 1;

        // CRC32 over header + data (everything up to pos)
        let crc = crc32(&buf[..pos]);
        buf[pos..pos + 4].copy_from_slice(&crc.to_le_bytes());
    }

    /// Deserialize config from a flash sector buffer.
    fn deserialize(buf: &[u8; SECTOR_SIZE as usize]) -> Option<Self> {
        // Check magic
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != CONFIG_MAGIC {
            return None;
        }
        let version = buf[4];
        if version != CONFIG_VERSION {
            return None;
        }

        let mut pos = 8;

        let mut identity_key = [0u8; 64];
        identity_key.copy_from_slice(&buf[pos..pos + 64]);
        pos += 64;

        let lora_freq = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
        pos += 4;
        let lora_sf = buf[pos];
        pos += 1;
        let lora_bw = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
        pos += 4;
        let lora_tx_power = i32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
        pos += 4;

        let mut ap_ssid = [0u8; 32];
        ap_ssid.copy_from_slice(&buf[pos..pos + 32]);
        pos += 32;
        let ap_ssid_len = buf[pos];
        pos += 1;
        let mut ap_pass = [0u8; 64];
        ap_pass.copy_from_slice(&buf[pos..pos + 64]);
        pos += 64;
        let ap_pass_len = buf[pos];
        pos += 1;

        let sta_enabled = buf[pos] != 0;
        pos += 1;
        let mut sta_ssid = [0u8; 32];
        sta_ssid.copy_from_slice(&buf[pos..pos + 32]);
        pos += 32;
        let sta_ssid_len = buf[pos];
        pos += 1;
        let mut sta_pass = [0u8; 64];
        sta_pass.copy_from_slice(&buf[pos..pos + 64]);
        pos += 64;
        let sta_pass_len = buf[pos];
        pos += 1;

        let mut admin_pass = [0u8; 16];
        admin_pass.copy_from_slice(&buf[pos..pos + 16]);
        pos += 16;
        let admin_pass_len = buf[pos];
        pos += 1;

        // Verify CRC
        let stored_crc = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
        let computed_crc = crc32(&buf[..pos]);
        if stored_crc != computed_crc {
            return None;
        }

        Some(NodeConfig {
            identity_key,
            lora_freq,
            lora_sf,
            lora_bw,
            lora_tx_power,
            ap_ssid,
            ap_ssid_len,
            ap_pass,
            ap_pass_len,
            sta_enabled,
            sta_ssid,
            sta_ssid_len,
            sta_pass,
            sta_pass_len,
            admin_pass,
            admin_pass_len,
        })
    }
}

/// Load config from flash. Returns None if no valid config found.
pub fn load_config() -> Option<NodeConfig> {
    let mut flash = unsafe { esp_storage::FlashStorage::new(esp_hal::peripherals::FLASH::steal()) };
    let mut buf = [0u8; SECTOR_SIZE as usize];
    flash.read(CONFIG_OFFSET, &mut buf).ok()?;
    NodeConfig::deserialize(&buf)
}

/// Save config to flash (erases sector first) and update the in-memory cache.
///
/// Uses a heap-allocated buffer (Box) instead of a 4KB stack array to avoid
/// overflowing the shared embassy task stack.
pub fn save_config(config: &NodeConfig) {
    let mut flash = unsafe { esp_storage::FlashStorage::new(esp_hal::peripherals::FLASH::steal()) };
    let mut buf = alloc::boxed::Box::new([0u8; SECTOR_SIZE as usize]);
    config.serialize(&mut *buf);
    // erase takes (from, to) range
    flash.erase(CONFIG_OFFSET, CONFIG_OFFSET + SECTOR_SIZE).ok();
    flash.write(CONFIG_OFFSET, &*buf).ok();
    // Update cache so web handlers see the new config immediately
    if let Ok(mut guard) = CACHED_CONFIG.try_lock() {
        *guard = Some(config.clone());
    }
}

/// Simple CRC32 (no lookup table — small code size for embedded).
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}
