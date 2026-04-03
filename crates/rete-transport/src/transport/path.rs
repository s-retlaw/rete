//! Path table CRUD operations.

use crate::path::Path;
use crate::snapshot;
use crate::storage::StorageMap;
use rete_core::DestHash;

use super::Transport;

impl<S: crate::storage::TransportStorage> Transport<S> {
    /// Look up a learned path to `dest`.
    pub fn get_path(&self, dest: &DestHash) -> Option<&Path> {
        self.paths.get(dest)
    }

    /// Update `last_accessed` on a path (call when the path is used for routing).
    pub fn touch_path(&mut self, dest: &DestHash, now: u64) {
        if let Some(p) = self.paths.get_mut(dest) {
            p.last_accessed = now;
        }
    }

    /// Store a learned path.  If the table is full, evicts the
    /// least-recently-used entry first.  Always succeeds.
    pub fn insert_path(&mut self, dest: DestHash, path: Path) -> bool {
        match self.paths.insert(dest, path) {
            Ok(_) => true,
            Err((dest, path)) => {
                // Table full — evict LRU entry
                if let Some(lru_key) = self
                    .paths
                    .iter()
                    .min_by_key(|(_, p)| p.last_accessed)
                    .map(|(k, _)| *k)
                {
                    self.paths.remove(&lru_key);
                    self.paths.insert(dest, path).is_ok()
                } else {
                    false
                }
            }
        }
    }

    /// Remove a path entry (expiry or explicit reset).
    pub fn remove_path(&mut self, dest: &DestHash) {
        self.paths.remove(dest);
    }

    /// Number of known paths.
    pub fn path_count(&self) -> usize {
        self.paths.len()
    }

    /// Return cached raw announce packets from the path table.
    ///
    /// When a new interface connects, the node should forward these so the
    /// new peer learns about destinations we already know. This eliminates
    /// the need for synthetic announces via `--peer-seed`.
    pub fn cached_announces(&self) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        let mut out = alloc::vec::Vec::new();
        for (_dest, path) in self.paths.iter() {
            if let Some(ref raw) = path.announce_raw {
                out.push(raw.clone());
            }
        }
        out
    }

    /// Store a raw announce packet on an existing path entry.
    ///
    /// Used by `register_peer_with_announce` to cache a synthetic announce so
    /// that `cached_announces()` includes it for new-interface flush.
    pub fn store_announce_raw(&mut self, dest: &DestHash, raw: &[u8]) {
        if let Some(path) = self.paths.get_mut(dest) {
            path.announce_raw = Some(raw.to_vec());
        }
    }

    /// Look up a previously announced identity's public key by destination hash.
    pub fn recall_identity(&self, dest: &DestHash) -> Option<&[u8; 64]> {
        self.known_identities.get(dest)
    }

    /// Pre-register a peer's identity and path (for use with deterministic seeds).
    pub fn register_identity(
        &mut self,
        dest_hash: DestHash,
        pub_key: [u8; 64],
        now: u64,
    ) {
        self.insert_identity(dest_hash, pub_key);
        let _ = self.insert_path(dest_hash, Path::direct(now));
    }

    /// Store a known identity.  If the table is full, evicts the entry
    /// whose matching path has the oldest `last_accessed` (or `0` for
    /// identities with no corresponding path — evicted first).
    pub(super) fn insert_identity(&mut self, dest_hash: DestHash, pub_key: [u8; 64]) {
        match self.known_identities.insert(dest_hash, pub_key) {
            Ok(_) => {}
            Err((dest_hash, pub_key)) => {
                if let Some(lru_key) = self
                    .known_identities
                    .keys()
                    .min_by_key(|k| self.paths.get(*k).map(|p| p.last_accessed).unwrap_or(0))
                    .copied()
                {
                    self.known_identities.remove(&lru_key);
                    let _ = self.known_identities.insert(dest_hash, pub_key);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Snapshot — save / load
    // -----------------------------------------------------------------------

    /// Capture the current path table and known identities into a [`Snapshot`].
    ///
    /// `detail` controls whether the announce cache is included (see
    /// [`SnapshotDetail`]).
    pub fn save_snapshot(
        &self,
        detail: snapshot::SnapshotDetail,
    ) -> snapshot::Snapshot {
        use crate::snapshot::{IdentityEntry, PathEntry, Snapshot, SnapshotDetail};

        let include_announce = matches!(detail, SnapshotDetail::Standard | SnapshotDetail::Full);

        let paths = self
            .paths
            .iter()
            .map(|(k, p)| PathEntry {
                dest_hash: *k,
                via: p.via,
                learned_at: p.learned_at,
                last_accessed: p.last_accessed,
                last_snr: p.last_snr,
                hops: p.hops,
                announce_raw: if include_announce {
                    p.announce_raw.clone()
                } else {
                    None
                },
            })
            .collect();

        let identities = self
            .known_identities
            .iter()
            .map(|(k, v)| IdentityEntry {
                dest_hash: *k,
                pub_key: *v,
            })
            .collect();

        Snapshot {
            version: 1,
            paths,
            identities,
        }
    }

    /// Restore paths and identities from a previously saved [`Snapshot`].
    ///
    /// Entries that would overflow the tables are silently dropped.
    pub fn load_snapshot(&mut self, snap: &snapshot::Snapshot) {
        for pe in &snap.paths {
            let path = Path {
                via: pe.via,
                learned_at: pe.learned_at,
                last_accessed: pe.last_accessed,
                last_snr: pe.last_snr,
                hops: pe.hops,
                announce_raw: pe.announce_raw.clone(),
                interface_mode: crate::path::InterfaceMode::Default,
                received_on: None,
            };
            self.insert_path(pe.dest_hash, path);
        }
        for ie in &snap.identities {
            self.insert_identity(ie.dest_hash, ie.pub_key);
        }
    }
}
