//! File-backed MessageStore — one file per message with a JSON metadata index.
//!
//! Layout:
//! ```text
//! {dir}/
//!   index.json          # lightweight metadata (dest_hash, timestamp per message)
//!   {hex(message_hash)} # raw LXMF message bytes
//! ```
//!
//! On startup, loads `index.json` into memory. If the index is missing or corrupt,
//! it rebuilds from message files on disk.
//!
//! Metadata lookups (`has_message`, `hashes_for`, `count_for`) are in-memory only.
//! Message data (`get_data`) reads from disk each time — keeps RAM usage small.

use rete_lxmf::MessageStore;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use rete_core::{DestHash, TRUNCATED_HASH_LEN};

/// Metadata for a stored message (kept in-memory index).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MessageMeta {
    /// Hex-encoded destination hash.
    dest: String,
    /// Unix epoch timestamp when deposited.
    timestamp: u64,
}

/// File-backed LXMF message store.
#[derive(Debug)]
pub struct FileMessageStore {
    dir: PathBuf,
    /// message_hash (as [u8;32]) -> metadata
    index: HashMap<[u8; 32], MessageMeta>,
    /// dest_hash -> list of message_hashes
    by_dest: HashMap<DestHash, Vec<[u8; 32]>>,
}

impl FileMessageStore {
    /// Open or create a file-backed message store at the given directory.
    ///
    /// If `index.json` exists, loads it. If missing or corrupt, rebuilds
    /// the index by scanning message files.
    pub fn open(dir: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;

        let index_path = dir.join("index.json");
        let mut store = FileMessageStore {
            dir,
            index: HashMap::new(),
            by_dest: HashMap::new(),
        };

        if index_path.exists() {
            match store.load_index(&index_path) {
                Ok(()) => return Ok(store),
                Err(_) => {
                    // Corrupt index — rebuild from files
                    store.rebuild_index();
                }
            }
        } else {
            // No index — rebuild from files (handles first-run and missing index)
            store.rebuild_index();
        }

        Ok(store)
    }

    /// Load index from JSON file.
    fn load_index(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let data = std::fs::read_to_string(path)?;
        let raw: HashMap<String, MessageMeta> = serde_json::from_str(&data)?;

        self.index.clear();
        self.by_dest.clear();

        for (hex_hash, meta) in raw {
            let hash = hex_to_array::<32>(&hex_hash)?;
            let dest = DestHash::from(hex_to_array::<16>(&meta.dest)?);

            self.by_dest.entry(dest).or_default().push(hash);
            self.index.insert(hash, meta);
        }

        Ok(())
    }

    /// Rebuild index by scanning message files on disk.
    fn rebuild_index(&mut self) {
        self.index.clear();
        self.by_dest.clear();

        let entries = match std::fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Skip non-message files
            if name_str == "index.json" || name_str.len() != 64 {
                continue;
            }

            let hash = match hex_to_array::<32>(&name_str) {
                Ok(h) => h,
                Err(_) => continue,
            };

            // Read first 16 bytes to get dest_hash (avoid loading entire file)
            let mut dest = [0u8; TRUNCATED_HASH_LEN];
            {
                use std::io::Read;
                let mut file = match std::fs::File::open(entry.path()) {
                    Ok(f) => f,
                    Err(_) => continue,
                };
                if file.read_exact(&mut dest).is_err() {
                    continue;
                }
            }

            // Use file modification time as timestamp fallback
            let timestamp = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let meta = MessageMeta {
                dest: hex::encode(dest),
                timestamp,
            };

            self.by_dest.entry(DestHash::from(dest)).or_default().push(hash);
            self.index.insert(hash, meta);
        }

        // Save reconstructed index
        let _ = self.flush_index();
    }

    /// Write index to disk.
    fn flush_index(&self) -> std::io::Result<()> {
        let raw: HashMap<String, &MessageMeta> = self
            .index
            .iter()
            .map(|(hash, meta)| (hex::encode(hash), meta))
            .collect();

        let json = serde_json::to_string_pretty(&raw)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let index_path = self.dir.join("index.json");
        std::fs::write(index_path, json)
    }

    /// Get the file path for a message hash.
    fn message_path(&self, hash: &[u8; 32]) -> PathBuf {
        self.dir.join(hex::encode(hash))
    }
}

impl MessageStore for FileMessageStore {
    fn store(
        &mut self,
        dest_hash: DestHash,
        message_hash: [u8; 32],
        data: &[u8],
        timestamp: u64,
    ) -> bool {
        if self.index.contains_key(&message_hash) {
            return false; // Dedup
        }

        // Write message file
        let path = self.message_path(&message_hash);
        if std::fs::write(&path, data).is_err() {
            return false;
        }

        // Update in-memory index
        let meta = MessageMeta {
            dest: hex::encode(dest_hash),
            timestamp,
        };
        self.index.insert(message_hash, meta);
        self.by_dest
            .entry(dest_hash)
            .or_default()
            .push(message_hash);

        // Flush index to disk
        let _ = self.flush_index();

        true
    }

    fn has_message(&self, message_hash: &[u8; 32]) -> bool {
        self.index.contains_key(message_hash)
    }

    fn hashes_for(&self, dest_hash: &DestHash) -> Vec<[u8; 32]> {
        self.by_dest.get(dest_hash).cloned().unwrap_or_default()
    }

    fn get_data(&self, message_hash: &[u8; 32]) -> Option<Vec<u8>> {
        let path = self.message_path(message_hash);
        std::fs::read(path).ok()
    }

    fn mark_delivered(&mut self, message_hash: &[u8; 32]) -> bool {
        if let Some(meta) = self.index.remove(message_hash) {
            // Remove from by_dest index
            if let Ok(dest) = hex_to_array::<16>(&meta.dest) {
                let dest = DestHash::from(dest);
                if let Some(hashes) = self.by_dest.get_mut(&dest) {
                    hashes.retain(|h| h != message_hash);
                    if hashes.is_empty() {
                        self.by_dest.remove(&dest);
                    }
                }
            }

            // Delete file
            let path = self.message_path(message_hash);
            let _ = std::fs::remove_file(path);

            // Flush index
            let _ = self.flush_index();

            true
        } else {
            false
        }
    }

    fn prune(&mut self, now: u64, max_age_secs: u64) -> usize {
        let cutoff = now.saturating_sub(max_age_secs);

        let expired: Vec<[u8; 32]> = self
            .index
            .iter()
            .filter(|(_, meta)| meta.timestamp < cutoff)
            .map(|(hash, _)| *hash)
            .collect();

        let count = expired.len();
        for hash in &expired {
            // Delete file
            let path = self.message_path(hash);
            let _ = std::fs::remove_file(path);

            // Remove from index
            if let Some(meta) = self.index.remove(hash) {
                if let Ok(dest) = hex_to_array::<16>(&meta.dest) {
                    let dest = DestHash::from(dest);
                    if let Some(hashes) = self.by_dest.get_mut(&dest) {
                        hashes.retain(|h| h != hash);
                        if hashes.is_empty() {
                            self.by_dest.remove(&dest);
                        }
                    }
                }
            }
        }

        if count > 0 {
            let _ = self.flush_index();
        }

        count
    }

    fn destinations_with_messages(&self) -> Vec<DestHash> {
        self.by_dest.keys().copied().collect()
    }

    fn message_count(&self) -> usize {
        self.index.len()
    }

    fn count_for(&self, dest_hash: &DestHash) -> usize {
        self.by_dest.get(dest_hash).map_or(0, |v| v.len())
    }

    fn all_message_hashes(&self) -> Vec<[u8; 32]> {
        self.index.keys().copied().collect()
    }
}

// ---------------------------------------------------------------------------
// AnyMessageStore — runtime dispatch between InMemory and File
// ---------------------------------------------------------------------------

/// Runtime-dispatched message store: either in-memory or file-backed.
pub enum AnyMessageStore {
    InMemory(rete_lxmf::InMemoryMessageStore),
    File(FileMessageStore),
}

impl Default for AnyMessageStore {
    fn default() -> Self {
        AnyMessageStore::InMemory(rete_lxmf::InMemoryMessageStore::new())
    }
}

impl MessageStore for AnyMessageStore {
    fn store(
        &mut self,
        dest_hash: DestHash,
        message_hash: [u8; 32],
        data: &[u8],
        timestamp: u64,
    ) -> bool {
        match self {
            Self::InMemory(s) => s.store(dest_hash, message_hash, data, timestamp),
            Self::File(s) => s.store(dest_hash, message_hash, data, timestamp),
        }
    }
    fn has_message(&self, hash: &[u8; 32]) -> bool {
        match self {
            Self::InMemory(s) => s.has_message(hash),
            Self::File(s) => s.has_message(hash),
        }
    }
    fn hashes_for(&self, dest: &DestHash) -> Vec<[u8; 32]> {
        match self {
            Self::InMemory(s) => s.hashes_for(dest),
            Self::File(s) => s.hashes_for(dest),
        }
    }
    fn get_data(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        match self {
            Self::InMemory(s) => s.get_data(hash),
            Self::File(s) => s.get_data(hash),
        }
    }
    fn mark_delivered(&mut self, hash: &[u8; 32]) -> bool {
        match self {
            Self::InMemory(s) => s.mark_delivered(hash),
            Self::File(s) => s.mark_delivered(hash),
        }
    }
    fn prune(&mut self, now: u64, max_age_secs: u64) -> usize {
        match self {
            Self::InMemory(s) => s.prune(now, max_age_secs),
            Self::File(s) => s.prune(now, max_age_secs),
        }
    }
    fn destinations_with_messages(&self) -> Vec<DestHash> {
        match self {
            Self::InMemory(s) => s.destinations_with_messages(),
            Self::File(s) => s.destinations_with_messages(),
        }
    }
    fn message_count(&self) -> usize {
        match self {
            Self::InMemory(s) => s.message_count(),
            Self::File(s) => s.message_count(),
        }
    }
    fn count_for(&self, dest: &DestHash) -> usize {
        match self {
            Self::InMemory(s) => s.count_for(dest),
            Self::File(s) => s.count_for(dest),
        }
    }
    fn all_message_hashes(&self) -> Vec<[u8; 32]> {
        match self {
            Self::InMemory(s) => s.all_message_hashes(),
            Self::File(s) => s.all_message_hashes(),
        }
    }
}

fn hex_to_array<const N: usize>(hex_str: &str) -> Result<[u8; N], Box<dyn std::error::Error>> {
    let bytes = hex::decode(hex_str)?;
    let arr: [u8; N] = bytes
        .try_into()
        .map_err(|_| format!("expected {N} bytes"))?;
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("rete_file_store_test_{}_{id}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    // ---------------------------------------------------------------
    // Conformance tests (same behavior as InMemoryMessageStore)
    // ---------------------------------------------------------------

    #[test]
    fn test_store_and_get_data_roundtrip() {
        let dir = temp_dir();
        let mut store = FileMessageStore::open(dir.clone()).unwrap();
        let data = &[1u8, 2, 3, 4, 5];
        assert!(store.store([0x01; 16].into(), [0x02; 32], data, 1000));
        assert_eq!(store.get_data(&[0x02; 32]), Some(vec![1, 2, 3, 4, 5]));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_dedup() {
        let dir = temp_dir();
        let mut store = FileMessageStore::open(dir.clone()).unwrap();
        assert!(store.store([0x01; 16].into(), [0x02; 32], &[1, 2, 3], 1000));
        assert!(!store.store([0x01; 16].into(), [0x02; 32], &[1, 2, 3], 1001));
        assert_eq!(store.message_count(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_has_message() {
        let dir = temp_dir();
        let mut store = FileMessageStore::open(dir.clone()).unwrap();
        assert!(!store.has_message(&[0x02; 32]));
        store.store([0x01; 16].into(), [0x02; 32], &[1], 1000);
        assert!(store.has_message(&[0x02; 32]));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_hashes_for() {
        let dir = temp_dir();
        let mut store = FileMessageStore::open(dir.clone()).unwrap();
        let dest = DestHash::from([0x01; 16]);
        store.store(dest, [0xAA; 32], &[1], 1000);
        store.store(dest, [0xBB; 32], &[2], 1001);
        store.store([0x02; 16].into(), [0xCC; 32], &[3], 1002);
        let hashes = store.hashes_for(&dest);
        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains(&[0xAA; 32]));
        assert!(hashes.contains(&[0xBB; 32]));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mark_delivered() {
        let dir = temp_dir();
        let mut store = FileMessageStore::open(dir.clone()).unwrap();
        store.store([0x01; 16].into(), [0x02; 32], &[1, 2, 3], 1000);
        assert!(store.mark_delivered(&[0x02; 32]));
        assert_eq!(store.message_count(), 0);
        assert!(!store.has_message(&[0x02; 32]));
        assert!(store.hashes_for(&DestHash::from([0x01; 16])).is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_prune() {
        let dir = temp_dir();
        let mut store = FileMessageStore::open(dir.clone()).unwrap();
        let dest = DestHash::from([0x01; 16]);
        store.store(dest, [0x01; 32], &[1], 1000);
        store.store(dest, [0x02; 32], &[2], 2000);
        store.store(dest, [0x03; 32], &[3], 3000);
        let pruned = store.prune(4000, 1500);
        assert_eq!(pruned, 2);
        assert_eq!(store.message_count(), 1);
        assert!(store.has_message(&[0x03; 32]));
        assert!(!store.has_message(&[0x01; 32]));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_destinations_with_messages() {
        let dir = temp_dir();
        let mut store = FileMessageStore::open(dir.clone()).unwrap();
        store.store([0x01; 16].into(), [0x01; 32], &[1], 1000);
        store.store([0x02; 16].into(), [0x02; 32], &[2], 1000);
        let dests = store.destinations_with_messages();
        assert_eq!(dests.len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_all_message_hashes() {
        let dir = temp_dir();
        let mut store = FileMessageStore::open(dir.clone()).unwrap();
        store.store([0x01; 16].into(), [0xAA; 32], &[1], 1000);
        store.store([0x02; 16].into(), [0xBB; 32], &[2], 1000);
        let hashes = store.all_message_hashes();
        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains(&[0xAA; 32]));
        assert!(hashes.contains(&[0xBB; 32]));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_count_for() {
        let dir = temp_dir();
        let mut store = FileMessageStore::open(dir.clone()).unwrap();
        let dest = DestHash::from([0x01; 16]);
        assert_eq!(store.count_for(&dest), 0);
        store.store(dest, [0xAA; 32], &[1], 1000);
        store.store(dest, [0xBB; 32], &[2], 1001);
        assert_eq!(store.count_for(&dest), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    // ---------------------------------------------------------------
    // Persistence-specific tests
    // ---------------------------------------------------------------

    #[test]
    fn test_survives_drop_and_reopen() {
        let dir = temp_dir();

        // Store messages, then drop
        {
            let mut store = FileMessageStore::open(dir.clone()).unwrap();
            store.store([0x01; 16].into(), [0xAA; 32], &[10, 20, 30], 1000);
            store.store([0x01; 16].into(), [0xBB; 32], &[40, 50], 2000);
        }

        // Reopen — messages should still be there
        let store = FileMessageStore::open(dir.clone()).unwrap();
        assert_eq!(store.message_count(), 2);
        assert!(store.has_message(&[0xAA; 32]));
        assert!(store.has_message(&[0xBB; 32]));
        assert_eq!(store.get_data(&[0xAA; 32]), Some(vec![10, 20, 30]));
        assert_eq!(store.get_data(&[0xBB; 32]), Some(vec![40, 50]));

        let hashes = store.hashes_for(&DestHash::from([0x01; 16]));
        assert_eq!(hashes.len(), 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_rebuilds_index_from_files() {
        let dir = temp_dir();
        let dest = DestHash::from([0x42; 16]);
        let dest_bytes: [u8; 16] = dest.into();

        // Build data that starts with dest_hash (like real LXMF messages)
        let mut data1 = Vec::from(dest_bytes);
        data1.extend_from_slice(&[1, 2, 3]);
        let mut data2 = Vec::from(dest_bytes);
        data2.extend_from_slice(&[4, 5, 6]);

        // Store messages
        {
            let mut store = FileMessageStore::open(dir.clone()).unwrap();
            store.store(dest, [0xAA; 32], &data1, 1000);
            store.store(dest, [0xBB; 32], &data2, 2000);
        }

        // Delete index.json
        fs::remove_file(dir.join("index.json")).unwrap();

        // Reopen — should rebuild from message files
        let store = FileMessageStore::open(dir.clone()).unwrap();
        assert_eq!(store.message_count(), 2);
        assert!(store.has_message(&[0xAA; 32]));
        assert!(store.has_message(&[0xBB; 32]));
        assert_eq!(store.get_data(&[0xAA; 32]), Some(data1));

        // dest_hash is reconstructed from first 16 bytes of message data
        let hashes = store.hashes_for(&dest);
        assert_eq!(hashes.len(), 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mark_delivered_removes_file() {
        let dir = temp_dir();
        let mut store = FileMessageStore::open(dir.clone()).unwrap();
        let hash = [0xAA; 32];
        store.store([0x01; 16].into(), hash, &[1, 2, 3], 1000);

        let file_path = dir.join(hex::encode(hash));
        assert!(file_path.exists());

        store.mark_delivered(&hash);
        assert!(!file_path.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_prune_removes_old_files() {
        let dir = temp_dir();
        let mut store = FileMessageStore::open(dir.clone()).unwrap();
        let old_hash = [0x01; 32];
        let new_hash = [0x02; 32];
        store.store([0x01; 16].into(), old_hash, &[1], 1000);
        store.store([0x01; 16].into(), new_hash, &[2], 5000);

        store.prune(6000, 2000);

        assert!(!dir.join(hex::encode(old_hash)).exists());
        assert!(dir.join(hex::encode(new_hash)).exists());
        assert_eq!(store.message_count(), 1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_delivered_persists_after_reopen() {
        let dir = temp_dir();

        {
            let mut store = FileMessageStore::open(dir.clone()).unwrap();
            store.store([0x01; 16].into(), [0xAA; 32], &[1], 1000);
            store.store([0x01; 16].into(), [0xBB; 32], &[2], 2000);
            store.mark_delivered(&[0xAA; 32]);
        }

        let store = FileMessageStore::open(dir.clone()).unwrap();
        assert_eq!(store.message_count(), 1);
        assert!(!store.has_message(&[0xAA; 32]));
        assert!(store.has_message(&[0xBB; 32]));

        let _ = fs::remove_dir_all(&dir);
    }
}
