//! Identity persistence and path-table snapshot store for hosted nodes.

use rete_core::Identity;
use std::path::{Path, PathBuf};

/// Return the default data directory (`$HOME/.rete`).
pub fn default_data_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".rete")
}

/// Load an existing identity from `path`, or generate and save a new one.
///
/// Returns `Err(message)` on I/O or format errors so callers can exit cleanly.
pub fn load_or_create_identity(path: &Path) -> Result<Identity, String> {
    match std::fs::read(path) {
        Ok(data) => {
            if data.len() != 64 {
                return Err(format!(
                    "[rete] invalid identity file (expected 64 bytes, got {})",
                    data.len()
                ));
            }
            eprintln!("[rete] loaded identity from {}", path.display());
            Identity::from_private_key(&data)
                .map_err(|e| format!("[rete] invalid identity file: {e}"))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut rng = rand::thread_rng();
            let mut prv = [0u8; 64];
            rand::RngCore::fill_bytes(&mut rng, &mut prv);
            let identity = Identity::from_private_key(&prv)
                .map_err(|e| format!("[rete] failed to generate identity: {e}"))?;

            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("[rete] failed to create identity directory: {e}"))?;
            }
            std::fs::write(path, identity.private_key())
                .map_err(|e| format!("[rete] failed to write identity file: {e}"))?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| format!("[rete] failed to set identity file permissions: {e}"))?;
            }

            eprintln!("[rete] created new identity at {}", path.display());
            Ok(identity)
        }
        Err(e) => Err(format!("[rete] failed to read identity file: {e}")),
    }
}

// ---------------------------------------------------------------------------
// JSON file-based snapshot store
// ---------------------------------------------------------------------------

/// JSON file-based snapshot store for hosted/desktop nodes.
pub struct JsonFileStore {
    path: PathBuf,
}

impl JsonFileStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl rete_transport::SnapshotStore for JsonFileStore {
    type Error = std::io::Error;

    fn save(&mut self, snapshot: &rete_transport::Snapshot) -> Result<(), Self::Error> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::File::create(&self.path)?;
        serde_json::to_writer(file, snapshot)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    fn load(&mut self) -> Result<Option<rete_transport::Snapshot>, Self::Error> {
        match std::fs::read_to_string(&self.path) {
            Ok(json) => {
                let snap: rete_transport::Snapshot = serde_json::from_str(&json)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                eprintln!("[rete] loaded snapshot from {}", self.path.display());
                Ok(Some(snap))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rete_transport::SnapshotStore;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "rete_daemon_identity_test_{}_{}",
            std::process::id(),
            name
        ))
    }

    #[test]
    fn default_data_dir_is_under_home() {
        let dir = default_data_dir();
        // Should end with ".rete"
        assert_eq!(dir.file_name().unwrap(), ".rete");
    }

    #[test]
    fn load_or_create_creates_new_identity() {
        let path = temp_path("new_identity");
        let _ = std::fs::remove_file(&path);

        let identity = load_or_create_identity(&path).expect("must create identity");
        assert!(path.exists(), "identity file must be created");

        // Re-loading should give the same identity (same public key)
        let identity2 = load_or_create_identity(&path).expect("must load identity");
        assert_eq!(identity.hash(), identity2.hash());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_or_create_rejects_wrong_size() {
        let path = temp_path("bad_identity");
        std::fs::write(&path, &[0u8; 32]).unwrap();
        let result = load_or_create_identity(&path);
        assert!(result.is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn json_file_store_save_load_roundtrip() {
        let path = temp_path("snapshot.json");
        let _ = std::fs::remove_file(&path);

        let mut store = JsonFileStore::new(path.clone());
        let snap = rete_transport::Snapshot {
            version: 1,
            paths: Default::default(),
            identities: Default::default(),
        };
        store.save(&snap).expect("must save snapshot");
        let loaded = store
            .load()
            .expect("must load snapshot")
            .expect("must be Some");
        assert_eq!(loaded.paths.len(), 0);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn json_file_store_missing_returns_none() {
        let path = temp_path("nonexistent_snapshot.json");
        let _ = std::fs::remove_file(&path);
        let mut store = JsonFileStore::new(path);
        let result = store.load().expect("must not error on missing file");
        assert!(result.is_none());
    }
}
