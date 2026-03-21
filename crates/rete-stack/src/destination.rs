//! Destination — the Reticulum addressing abstraction.
//!
//! A `Destination` ties together an identity, a human-readable name,
//! destination hashing, encryption mode, and proof strategy into one
//! coherent type.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use rete_core::{Identity, Token, NAME_HASH_LEN, TRUNCATED_HASH_LEN};
use sha2::{Digest, Sha256};

use crate::node_core::RequestHandler;
use crate::ProofStrategy;

/// Destination type matching Python RNS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationType {
    /// Addressed to a single identity (encrypted).
    Single,
    /// Group destination with shared symmetric key.
    Group,
    /// Broadcast / plain (unencrypted).
    Plain,
    /// Link-layer session endpoint (internal use).
    Link,
}

/// Whether we are listening or sending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Inbound: we own this destination and can receive packets for it.
    In,
    /// Outbound: we can send packets to this destination.
    Out,
}

/// A Reticulum destination — the addressing abstraction.
///
/// Wraps identity, name hashing, encryption, and proof strategy
/// into a single coherent type.
pub struct Destination {
    /// The type of destination (Single, Group, Plain, Link).
    pub dest_type: DestinationType,
    /// Whether this destination is for receiving or sending.
    pub direction: Direction,
    identity: Option<Identity>,
    /// Application name (e.g. "testapp").
    pub app_name: String,
    /// Aspect strings (e.g. ["aspect1"]).
    pub aspects: Vec<String>,
    /// The 16-byte destination hash.
    pub dest_hash: [u8; TRUNCATED_HASH_LEN],
    /// The 10-byte name hash.
    pub name_hash: [u8; NAME_HASH_LEN],
    /// Proof generation strategy for incoming packets.
    pub proof_strategy: ProofStrategy,
    /// Whether this destination accepts link requests.
    pub accepts_links: bool,
    /// Default application data included in announces.
    pub default_app_data: Option<Vec<u8>>,
    group_token: Option<Token>,
    /// Registered request handlers, keyed by path_hash.
    request_handlers: Vec<([u8; TRUNCATED_HASH_LEN], RequestHandler)>,
}

impl Destination {
    /// Create a new destination.
    ///
    /// # Panics
    /// - If `dest_type` is Single or Link and no identity is provided.
    /// - If `dest_type` is Plain and an identity IS provided.
    pub fn new(
        identity: Option<Identity>,
        direction: Direction,
        dest_type: DestinationType,
        app_name: &str,
        aspects: &[&str],
    ) -> Self {
        // Validate identity requirements per destination type
        match dest_type {
            DestinationType::Single | DestinationType::Link => {
                assert!(
                    identity.is_some(),
                    "Single and Link destinations require an identity"
                );
            }
            DestinationType::Plain => {
                assert!(
                    identity.is_none(),
                    "Plain destinations must not have an identity"
                );
            }
            DestinationType::Group => {
                // Group can optionally have an identity
            }
        }

        // Compute expanded name for hashing
        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name(app_name, aspects, &mut name_buf)
            .expect("app_name + aspects must fit in 128 bytes");

        // name_hash = SHA-256(expanded)[0:10]
        let name_hash_full = Sha256::digest(expanded.as_bytes());
        let mut name_hash = [0u8; NAME_HASH_LEN];
        name_hash.copy_from_slice(&name_hash_full[..NAME_HASH_LEN]);

        // dest_hash uses rete_core::destination_hash
        let id_hash = identity.as_ref().map(|id| id.hash());
        let dest_hash = rete_core::destination_hash(expanded, id_hash.as_ref());

        Destination {
            dest_type,
            direction,
            identity,
            app_name: String::from(app_name),
            aspects: aspects.iter().map(|s| String::from(*s)).collect(),
            dest_hash,
            name_hash,
            proof_strategy: ProofStrategy::ProveNone,
            accepts_links: true,
            default_app_data: None,
            group_token: None,
            request_handlers: Vec::new(),
        }
    }

    /// Create a destination from pre-computed hashes.
    ///
    /// Use this when the identity is stored elsewhere (e.g. on `NodeCore`)
    /// and you want a `Destination` purely for addressing metadata without
    /// taking ownership of the identity.
    pub fn from_hashes(
        dest_type: DestinationType,
        direction: Direction,
        app_name: &str,
        aspects: &[&str],
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        name_hash: [u8; NAME_HASH_LEN],
    ) -> Self {
        Destination {
            dest_type,
            direction,
            identity: None,
            app_name: String::from(app_name),
            aspects: aspects.iter().map(|s| String::from(*s)).collect(),
            dest_hash,
            name_hash,
            proof_strategy: ProofStrategy::ProveNone,
            accepts_links: true,
            default_app_data: None,
            group_token: None,
            request_handlers: Vec::new(),
        }
    }

    /// Get the 16-byte destination hash.
    pub fn hash(&self) -> &[u8; TRUNCATED_HASH_LEN] {
        &self.dest_hash
    }

    /// Get the 10-byte name hash.
    pub fn name_hash(&self) -> &[u8; NAME_HASH_LEN] {
        &self.name_hash
    }

    /// Get a reference to the identity (if any).
    pub fn identity(&self) -> Option<&Identity> {
        self.identity.as_ref()
    }

    /// Set the proof strategy.
    pub fn set_proof_strategy(&mut self, strategy: ProofStrategy) {
        self.proof_strategy = strategy;
    }

    /// Set default app data for announces.
    pub fn set_default_app_data(&mut self, data: Option<Vec<u8>>) {
        self.default_app_data = data;
    }

    /// Register a request handler for a given path.
    ///
    /// The `path_hash` is `SHA-256(path.as_bytes())[0:16]` — matching Python's
    /// `Identity.truncated_hash(path.encode("utf-8"))`.
    pub fn register_request_handler(&mut self, handler: RequestHandler) {
        let ph = rete_transport::path_hash(&handler.path);
        // Replace existing handler for same path
        if let Some(entry) = self.request_handlers.iter_mut().find(|(h, _)| *h == ph) {
            entry.1 = handler;
        } else {
            self.request_handlers.push((ph, handler));
        }
    }

    /// Deregister a request handler by path string.
    pub fn deregister_request_handler(&mut self, path: &str) -> bool {
        let ph = rete_transport::path_hash(path);
        let before = self.request_handlers.len();
        self.request_handlers.retain(|(h, _)| *h != ph);
        self.request_handlers.len() < before
    }

    /// Look up a request handler by path_hash.
    pub fn lookup_request_handler(
        &self,
        path_hash: &[u8; TRUNCATED_HASH_LEN],
    ) -> Option<&RequestHandler> {
        self.request_handlers
            .iter()
            .find(|(h, _)| h == path_hash)
            .map(|(_, handler)| handler)
    }

    /// Encrypt plaintext for this destination.
    ///
    /// For SINGLE: uses Identity asymmetric encryption.
    /// For GROUP: uses Token symmetric encryption.
    /// For PLAIN: returns plaintext unchanged (copies to out).
    /// For LINK: returns an error (link encryption is handled separately).
    pub fn encrypt<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        plaintext: &[u8],
        rng: &mut R,
        out: &mut [u8],
    ) -> Result<usize, rete_core::Error> {
        match self.dest_type {
            DestinationType::Single => {
                let id = self
                    .identity
                    .as_ref()
                    .ok_or(rete_core::Error::CryptoError)?;
                id.encrypt(plaintext, rng, out)
            }
            DestinationType::Group => {
                let token = self
                    .group_token
                    .as_ref()
                    .ok_or(rete_core::Error::CryptoError)?;
                token.encrypt(plaintext, rng, out)
            }
            DestinationType::Plain => {
                if out.len() < plaintext.len() {
                    return Err(rete_core::Error::BufferTooSmall);
                }
                out[..plaintext.len()].copy_from_slice(plaintext);
                Ok(plaintext.len())
            }
            DestinationType::Link => Err(rete_core::Error::CryptoError),
        }
    }

    /// Decrypt ciphertext from this destination.
    ///
    /// For SINGLE: uses Identity asymmetric decryption.
    /// For GROUP: uses Token symmetric decryption.
    /// For PLAIN: copies ciphertext unchanged.
    /// For LINK: returns an error.
    pub fn decrypt(&self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize, rete_core::Error> {
        match self.dest_type {
            DestinationType::Single => {
                let id = self
                    .identity
                    .as_ref()
                    .ok_or(rete_core::Error::CryptoError)?;
                id.decrypt(ciphertext, out)
            }
            DestinationType::Group => {
                let token = self
                    .group_token
                    .as_ref()
                    .ok_or(rete_core::Error::CryptoError)?;
                token.decrypt(ciphertext, out)
            }
            DestinationType::Plain => {
                if out.len() < ciphertext.len() {
                    return Err(rete_core::Error::BufferTooSmall);
                }
                out[..ciphertext.len()].copy_from_slice(ciphertext);
                Ok(ciphertext.len())
            }
            DestinationType::Link => Err(rete_core::Error::CryptoError),
        }
    }

    /// Create group keys for a GROUP destination.
    ///
    /// Generates 64 random bytes and constructs a symmetric `Token` from them.
    ///
    /// # Errors
    /// Returns [`rete_core::Error::CryptoError`] if this is not a Group destination.
    pub fn create_group_keys<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<(), rete_core::Error> {
        if self.dest_type != DestinationType::Group {
            return Err(rete_core::Error::CryptoError);
        }
        let mut key_bytes = [0u8; 64];
        rng.fill_bytes(&mut key_bytes);
        self.group_token = Some(Token::new(&key_bytes)?);
        Ok(())
    }

    /// Load a group key from raw bytes (64 bytes).
    ///
    /// # Errors
    /// Returns [`rete_core::Error::CryptoError`] if this is not a Group destination,
    /// or [`rete_core::Error::InvalidKey`] if the key is not 64 bytes.
    pub fn load_group_key(&mut self, key: &[u8]) -> Result<(), rete_core::Error> {
        if self.dest_type != DestinationType::Group {
            return Err(rete_core::Error::CryptoError);
        }
        self.group_token = Some(Token::new(key)?);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rete_core::Identity;

    #[test]
    fn test_destination_hash_matches_core() {
        // Compute expected hash independently, then verify Destination matches.
        let identity = Identity::from_seed(b"dest-test-identity").unwrap();
        let id_hash = identity.hash();

        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name("testapp", &["aspect1"], &mut name_buf).unwrap();
        let expected = rete_core::destination_hash(expanded, Some(&id_hash));

        // Now create the Destination (consumes identity).
        let dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["aspect1"],
        );
        assert_eq!(*dest.hash(), expected);
    }

    #[test]
    #[should_panic(expected = "Single and Link destinations require an identity")]
    fn test_single_requires_identity() {
        Destination::new(
            None,
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["aspect1"],
        );
    }

    #[test]
    fn test_plain_no_identity() {
        let dest = Destination::new(
            None,
            Direction::In,
            DestinationType::Plain,
            "testapp",
            &["aspect1"],
        );
        assert_eq!(dest.dest_type, DestinationType::Plain);
        assert!(dest.identity().is_none());
    }

    #[test]
    #[should_panic(expected = "Plain destinations must not have an identity")]
    fn test_plain_rejects_identity() {
        let identity = Identity::from_seed(b"plain-reject").unwrap();
        Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Plain,
            "testapp",
            &["aspect1"],
        );
    }

    #[test]
    fn test_group_encrypt_decrypt() {
        let mut dest = Destination::new(
            None,
            Direction::In,
            DestinationType::Group,
            "testapp",
            &["group1"],
        );
        let mut rng = rand::thread_rng();
        dest.create_group_keys(&mut rng).unwrap();

        let plaintext = b"group message";
        let mut ct = [0u8; 256];
        let ct_len = dest.encrypt(plaintext, &mut rng, &mut ct).unwrap();

        let mut pt = [0u8; 256];
        let pt_len = dest.decrypt(&ct[..ct_len], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len], plaintext);
    }

    #[test]
    fn test_proof_strategy_default() {
        let identity = Identity::from_seed(b"proof-default").unwrap();
        let dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["aspect1"],
        );
        assert_eq!(dest.proof_strategy, ProofStrategy::ProveNone);
    }

    #[test]
    fn test_default_app_data() {
        let identity = Identity::from_seed(b"app-data-test").unwrap();
        let mut dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["aspect1"],
        );
        assert!(dest.default_app_data.is_none());
        dest.set_default_app_data(Some(b"my app data".to_vec()));
        assert_eq!(
            dest.default_app_data.as_deref(),
            Some(b"my app data".as_slice())
        );
    }

    #[test]
    #[should_panic(expected = "Single and Link destinations require an identity")]
    fn test_link_requires_identity() {
        Destination::new(
            None,
            Direction::In,
            DestinationType::Link,
            "testapp",
            &["link1"],
        );
    }

    #[test]
    fn test_group_without_keys_fails_encrypt() {
        let dest = Destination::new(
            None,
            Direction::In,
            DestinationType::Group,
            "testapp",
            &["group1"],
        );
        let mut rng = rand::thread_rng();
        let mut ct = [0u8; 256];
        let result = dest.encrypt(b"test", &mut rng, &mut ct);
        assert_eq!(result, Err(rete_core::Error::CryptoError));
    }

    #[test]
    fn test_plain_encrypt_passthrough() {
        let dest = Destination::new(
            None,
            Direction::In,
            DestinationType::Plain,
            "testapp",
            &["plain1"],
        );
        let mut rng = rand::thread_rng();
        let plaintext = b"hello plain";
        let mut out = [0u8; 256];
        let len = dest.encrypt(plaintext, &mut rng, &mut out).unwrap();
        assert_eq!(&out[..len], plaintext);
    }

    #[test]
    fn test_plain_decrypt_passthrough() {
        let dest = Destination::new(
            None,
            Direction::In,
            DestinationType::Plain,
            "testapp",
            &["plain1"],
        );
        let data = b"hello plain";
        let mut out = [0u8; 256];
        let len = dest.decrypt(data, &mut out).unwrap();
        assert_eq!(&out[..len], data);
    }

    #[test]
    fn test_load_group_key() {
        let mut dest = Destination::new(
            None,
            Direction::In,
            DestinationType::Group,
            "testapp",
            &["group1"],
        );

        // Create a 64-byte key
        let mut key = [0u8; 64];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        dest.load_group_key(&key).unwrap();

        // Encrypt and decrypt should now work
        let mut rng = rand::thread_rng();
        let plaintext = b"loaded key test";
        let mut ct = [0u8; 256];
        let ct_len = dest.encrypt(plaintext, &mut rng, &mut ct).unwrap();

        let mut pt = [0u8; 256];
        let pt_len = dest.decrypt(&ct[..ct_len], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len], plaintext);
    }

    #[test]
    fn test_create_group_keys_rejects_non_group() {
        let identity = Identity::from_seed(b"not-group").unwrap();
        let mut dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["aspect1"],
        );
        let mut rng = rand::thread_rng();
        assert_eq!(
            dest.create_group_keys(&mut rng),
            Err(rete_core::Error::CryptoError)
        );
    }

    #[test]
    fn test_name_hash_computed() {
        let identity = Identity::from_seed(b"name-hash-test").unwrap();
        let dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["aspect1"],
        );

        // Verify name_hash is SHA-256("testapp.aspect1")[0:10]
        let expected_full = Sha256::digest(b"testapp.aspect1");
        let mut expected = [0u8; NAME_HASH_LEN];
        expected.copy_from_slice(&expected_full[..NAME_HASH_LEN]);
        assert_eq!(*dest.name_hash(), expected);
    }
}
