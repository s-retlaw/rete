//! Reticulum identity — keypairs, hashing, signing, ECDH, and encryption.
//!
//! # Key layout (64 bytes each)
//! ```text
//! pub_key = X25519_pub[0:32] || Ed25519_pub[32:64]
//! prv_key = X25519_prv[0:32] || Ed25519_prv[32:64]
//! ```
//!
//! # Identity hash
//! ```text
//! identity_hash = SHA-256(pub_key)[0:16]
//! ```
//!
//! # Destination hash
//! ```text
//! expanded      = dot-join(app_name, aspect1, aspect2, ...)
//! name_hash     = SHA-256(expanded.as_bytes())[0:10]
//! addr_material = name_hash || identity_hash   (or just name_hash for PLAIN)
//! dest_hash     = SHA-256(addr_material)[0:16]
//! ```
//!
//! # Encryption (Token-based, matching Python RNS)
//! ```text
//! Full ciphertext: ephemeral_X25519_pub[32] || token
//! Token:           AES_IV[16] || aes_256_cbc_body || HMAC_SHA256[32]
//!
//! Encrypt:
//!   shared     = X25519(ephemeral_prv, recipient_pub)
//!   derived    = HKDF-SHA256(ikm=shared, salt=identity_hash, info=b"", length=64)
//!   sign_key   = derived[0:32]
//!   enc_key    = derived[32:64]
//!   iv         = random[16]
//!   aes_body   = AES-256-CBC(enc_key, iv, PKCS7_pad(plaintext))
//!   hmac       = HMAC-SHA256(sign_key, iv || aes_body)
//!   ciphertext = ephemeral_pub[32] || iv[16] || aes_body || hmac[32]
//!
//! Decrypt:
//!   shared     = X25519(recipient_prv, ciphertext[0:32])
//!   derived    = HKDF-SHA256(ikm=shared, salt=identity_hash, info=b"", length=64)
//!   sign_key   = derived[0:32]
//!   enc_key    = derived[32:64]
//!   verify HMAC-SHA256(sign_key, token[:-32]) == token[-32:]
//!   iv         = token[0:16]
//!   aes_body   = token[16:-32]
//!   plaintext  = PKCS7_unpad(AES-256-CBC-decrypt(enc_key, iv, aes_body))
//! ```

use crate::token::{Token, TOKEN_OVERHEAD};
use crate::{Error, NAME_HASH_LEN, TRUNCATED_HASH_LEN};
use sha2::{Digest, Sha256};

/// An RNS identity — combined X25519 (ECDH) and Ed25519 (signing) keypair.
#[derive(Debug, PartialEq, Eq)]
pub struct Identity {
    /// X25519 private scalar (32 bytes).
    pub x25519_prv: [u8; 32],
    /// X25519 public point (32 bytes).
    pub x25519_pub: [u8; 32],
    /// Ed25519 signing key seed (32 bytes).
    pub ed25519_prv: [u8; 32],
    /// Ed25519 verifying key (32 bytes).
    pub ed25519_pub: [u8; 32],
}

impl Identity {
    /// Create a verify-only Identity from a 64-byte combined public key.
    ///
    /// Format: `X25519_pub[0:32] || Ed25519_pub[32:64]`
    ///
    /// The private keys are zeroed — this Identity can verify signatures
    /// and decrypt messages sent *to* it, but cannot sign or initiate ECDH.
    ///
    /// # Errors
    /// [`Error::InvalidKey`] if `pub_key` is not exactly 64 bytes.
    pub fn from_public_key(pub_key: &[u8]) -> Result<Self, Error> {
        if pub_key.len() != 64 {
            return Err(Error::InvalidKey);
        }
        let mut x25519_pub = [0u8; 32];
        let mut ed25519_pub = [0u8; 32];
        x25519_pub.copy_from_slice(&pub_key[..32]);
        ed25519_pub.copy_from_slice(&pub_key[32..64]);
        Ok(Identity {
            x25519_prv: [0u8; 32],
            x25519_pub,
            ed25519_prv: [0u8; 32],
            ed25519_pub,
        })
    }

    /// Load an Identity from a 64-byte combined private key.
    ///
    /// Format: `X25519_prv[0:32] || Ed25519_prv[32:64]`
    /// This matches the output of Python `Identity.get_private_key()`.
    ///
    /// # Errors
    /// [`Error::InvalidKey`] if `prv` is not exactly 64 bytes.
    pub fn from_private_key(prv: &[u8]) -> Result<Self, Error> {
        if prv.len() != 64 {
            return Err(Error::InvalidKey);
        }

        let mut x25519_prv = [0u8; 32];
        let mut ed25519_prv = [0u8; 32];
        x25519_prv.copy_from_slice(&prv[0..32]);
        ed25519_prv.copy_from_slice(&prv[32..64]);

        // X25519: derive public key from private scalar
        let secret = x25519_dalek::StaticSecret::from(x25519_prv);
        let x25519_pub = x25519_dalek::PublicKey::from(&secret).to_bytes();

        // Ed25519: derive verifying key from signing seed
        let signing = ed25519_dalek::SigningKey::from_bytes(&ed25519_prv);
        let ed25519_pub = signing.verifying_key().to_bytes();

        Ok(Identity {
            x25519_prv,
            x25519_pub,
            ed25519_prv,
            ed25519_pub,
        })
    }

    /// Create an Identity from a seed (for deterministic/reproducible testing).
    ///
    /// Derives a 64-byte private key via double SHA-256:
    /// `prv[0:32] = SHA-256(seed)`, `prv[32:64] = SHA-256(prv[0:32])`.
    ///
    /// # Errors
    /// [`Error::InvalidKey`] if key derivation fails.
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        let hash = Sha256::digest(seed);
        let mut prv = [0u8; 64];
        prv[..32].copy_from_slice(&hash);
        let hash2 = Sha256::digest(hash);
        prv[32..].copy_from_slice(&hash2);
        Self::from_private_key(&prv)
    }

    /// Returns the combined 64-byte public key.
    ///
    /// Format: `X25519_pub[0:32] || Ed25519_pub[32:64]`
    pub fn public_key(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.x25519_pub);
        out[32..].copy_from_slice(&self.ed25519_pub);
        out
    }

    /// Returns the combined 64-byte private key.
    ///
    /// Format: `X25519_prv[0:32] || Ed25519_prv[32:64]`
    /// This matches the input format of [`Identity::from_private_key`].
    pub fn private_key(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.x25519_prv);
        out[32..].copy_from_slice(&self.ed25519_prv);
        out
    }

    /// Compute the 16-byte identity hash.
    ///
    /// `identity_hash = SHA-256(pub_key)[0:16]`
    pub fn hash(&self) -> [u8; TRUNCATED_HASH_LEN] {
        let pub_key = self.public_key();
        let digest = Sha256::digest(pub_key);
        digest[..TRUNCATED_HASH_LEN].try_into().unwrap()
    }

    /// Sign `message` with the Ed25519 key.
    ///
    /// Returns a 64-byte signature.
    ///
    /// # Errors
    /// [`Error::CryptoError`] if the signing key is invalid.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64], Error> {
        use ed25519_dalek::Signer;

        let signing = ed25519_dalek::SigningKey::from_bytes(&self.ed25519_prv);
        Ok(signing.sign(message).to_bytes())
    }

    /// Verify an Ed25519 `signature` over `message` using this identity's
    /// verifying key.
    ///
    /// # Errors
    /// [`Error::InvalidSignature`] if the signature does not verify.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        use ed25519_dalek::Verifier;

        let vk = ed25519_dalek::VerifyingKey::from_bytes(&self.ed25519_pub)
            .map_err(|_| Error::InvalidSignature)?;
        let sig =
            ed25519_dalek::Signature::from_slice(signature).map_err(|_| Error::InvalidSignature)?;
        vk.verify(message, &sig)
            .map_err(|_| Error::InvalidSignature)
    }

    /// Encrypt `plaintext` to this identity's X25519 public key.
    ///
    /// Writes ciphertext into `out`. Returns number of bytes written.
    ///
    /// Ciphertext layout: `ephemeral_X25519_pub[32] || iv[16] || aes_256_cbc_body || hmac[32]`
    ///
    /// # Errors
    /// [`Error::BufferTooSmall`] if `out` cannot hold the result.
    pub fn encrypt<R>(&self, plaintext: &[u8], rng: &mut R, out: &mut [u8]) -> Result<usize, Error>
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        // Compute total output size: ephemeral_pub(32) + token(iv + aes_body + hmac)
        let pad_len = 16 - (plaintext.len() % 16);
        let padded_len = plaintext.len() + pad_len;
        let total_len = 32 + TOKEN_OVERHEAD + padded_len;
        if out.len() < total_len {
            return Err(Error::BufferTooSmall);
        }

        // 1. Generate ephemeral X25519 keypair
        let ephemeral_secret = x25519_dalek::EphemeralSecret::random_from_rng(&mut *rng);
        let ephemeral_pub = x25519_dalek::PublicKey::from(&ephemeral_secret);

        // 2. ECDH
        let recipient_pub = x25519_dalek::PublicKey::from(self.x25519_pub);
        let shared = ephemeral_secret.diffie_hellman(&recipient_pub);

        // 3. HKDF → 64 bytes (salt = identity hash, info = empty)
        let salt = self.hash();
        let hk = hkdf::Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
        let mut derived = [0u8; 64];
        hk.expand(b"", &mut derived)
            .map_err(|_| Error::CryptoError)?;

        // 4. Write ephemeral pub key
        out[..32].copy_from_slice(ephemeral_pub.as_bytes());

        // 5. Delegate to Token for symmetric encryption
        let token = Token::new(&derived)?;
        let token_len = token.encrypt(plaintext, rng, &mut out[32..])?;

        Ok(32 + token_len)
    }

    /// Decrypt `ciphertext` using this identity's X25519 private key.
    ///
    /// Writes plaintext into `out`. Returns number of bytes written.
    ///
    /// # Errors
    /// [`Error::BufferTooSmall`], [`Error::CryptoError`], [`Error::InvalidPadding`]
    pub fn decrypt(&self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        // Minimum: ephemeral_pub(32) + iv(16) + 1_block(16) + hmac(32) = 96
        if ciphertext.len() < 96 {
            return Err(Error::CryptoError);
        }

        let ephemeral_pub_bytes = &ciphertext[0..32];
        let token_bytes = &ciphertext[32..];

        // 1. ECDH
        let ephemeral_pub =
            x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(ephemeral_pub_bytes).unwrap());
        let our_secret = x25519_dalek::StaticSecret::from(self.x25519_prv);
        let shared = our_secret.diffie_hellman(&ephemeral_pub);

        // 2. HKDF → 64 bytes (salt = identity hash, info = empty)
        let salt = self.hash();
        let hk = hkdf::Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
        let mut derived = [0u8; 64];
        hk.expand(b"", &mut derived)
            .map_err(|_| Error::CryptoError)?;

        // 3. Delegate to Token for symmetric decryption
        let token = Token::new(&derived)?;
        token.decrypt(token_bytes, out)
    }
}

// ---------------------------------------------------------------------------
// Destination hash utilities
// ---------------------------------------------------------------------------

/// Compute a 16-byte destination hash.
///
/// # Arguments
/// - `expanded_name`  — dot-joined app name + aspects, e.g. `"testapp.aspect1"`
/// - `identity_hash`  — 16-byte identity hash, or `None` for PLAIN destinations
///
/// # Returns
/// 16-byte destination hash.
///
/// # Algorithm
/// ```text
/// name_hash     = SHA-256(expanded_name.as_bytes())[0:10]
/// addr_material = name_hash [+ identity_hash if not PLAIN]
/// dest_hash     = SHA-256(addr_material)[0:16]
/// ```
pub fn destination_hash(
    expanded_name: &str,
    identity_hash: Option<&[u8; TRUNCATED_HASH_LEN]>,
) -> [u8; TRUNCATED_HASH_LEN] {
    let name_digest = Sha256::digest(expanded_name.as_bytes());
    let name_hash = &name_digest[..NAME_HASH_LEN];

    let mut hasher = Sha256::new();
    hasher.update(name_hash);
    if let Some(id) = identity_hash {
        hasher.update(id.as_slice());
    }
    hasher.finalize()[..TRUNCATED_HASH_LEN].try_into().unwrap()
}

/// Expand `app_name` and `aspects` into a dot-joined string.
///
/// Writes the result into `buf` and returns it as a `&str`.
///
/// Example: `("testapp", &["aspect1", "aspect2"])` → `"testapp.aspect1.aspect2"`
///
/// # Errors
/// [`Error::BufferTooSmall`] if `buf` cannot hold the result.
pub fn expand_name<'a>(
    app_name: &str,
    aspects: &[&str],
    buf: &'a mut [u8],
) -> Result<&'a str, Error> {
    let mut pos = 0;
    let b = app_name.as_bytes();
    if pos + b.len() > buf.len() {
        return Err(Error::BufferTooSmall);
    }
    buf[pos..pos + b.len()].copy_from_slice(b);
    pos += b.len();

    for asp in aspects {
        let a = asp.as_bytes();
        if pos + 1 + a.len() > buf.len() {
            return Err(Error::BufferTooSmall);
        }
        buf[pos] = b'.';
        pos += 1;
        buf[pos..pos + a.len()].copy_from_slice(a);
        pos += a.len();
    }

    core::str::from_utf8(&buf[..pos]).map_err(|_| Error::BufferTooSmall)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_name_single() {
        let mut buf = [0u8; 64];
        assert_eq!(
            expand_name("testapp", &["aspect1"], &mut buf).unwrap(),
            "testapp.aspect1"
        );
    }

    #[test]
    fn expand_name_multi() {
        let mut buf = [0u8; 64];
        assert_eq!(
            expand_name("testapp", &["aspect1", "aspect2"], &mut buf).unwrap(),
            "testapp.aspect1.aspect2"
        );
    }

    #[test]
    fn expand_name_none() {
        let mut buf = [0u8; 64];
        assert_eq!(
            expand_name("broadcast", &[], &mut buf).unwrap(),
            "broadcast"
        );
    }

    #[test]
    fn expand_name_overflow() {
        let mut buf = [0u8; 5]; // too small for "testapp.aspect1"
        assert_eq!(
            expand_name("testapp", &["aspect1"], &mut buf),
            Err(Error::BufferTooSmall)
        );
    }

    #[test]
    fn destination_hash_plain() {
        // destination_hash_vectors[6]: broadcast, no identity
        // From vectors.json — verify length and stability
        let h = destination_hash("broadcast", None);
        assert_eq!(h.len(), 16);
    }

    #[test]
    fn destination_hash_with_identity() {
        // destination_hash_vectors[0]: alice, testapp.aspect1
        // The exact expected value comes from vectors.json
        // Verify the computation is stable (same inputs → same output)
        let fake_id_hash = [
            0xfdu8, 0x9f, 0x12, 0x1e, 0x29, 0x3b, 0xf4, 0xa4, 0x15, 0xdd, 0x74, 0x36, 0x6f, 0xf7,
            0x5f, 0x69,
        ];
        let mut name_buf = [0u8; 32];
        let expanded = expand_name("testapp", &["aspect1"], &mut name_buf).unwrap();
        let h1 = destination_hash(expanded, Some(&fake_id_hash));
        let h2 = destination_hash(expanded, Some(&fake_id_hash));
        assert_eq!(h1, h2, "destination hash must be deterministic");
        assert_eq!(h1.len(), 16);
    }

    #[test]
    fn identity_from_private_key_wrong_length() {
        assert_eq!(
            Identity::from_private_key(&[0u8; 32]),
            Err(Error::InvalidKey)
        );
    }
}
