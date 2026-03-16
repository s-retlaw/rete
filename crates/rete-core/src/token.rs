//! Symmetric AES-256-CBC + HMAC-SHA256 token encryption.
//!
//! Used directly by Identity (after ECDH+HKDF) and by Link sessions
//! (with pre-derived keys).
//!
//! # Token format
//! ```text
//! iv[16] || aes_256_cbc_body || hmac_sha256[32]
//! ```
//!
//! Key material is 64 bytes split as:
//! - `signing_key  = key[0:32]`  — HMAC-SHA256 key
//! - `encryption_key = key[32:64]` — AES-256-CBC key

use crate::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Overhead added by token encryption: IV (16) + HMAC (32) = 48 bytes.
pub const TOKEN_OVERHEAD: usize = 48;

/// Symmetric token encryptor/decryptor.
///
/// Wraps a 64-byte derived key and provides AES-256-CBC + HMAC-SHA256
/// encrypt/decrypt. `no_std`, no alloc. Key material is zeroized on drop.
#[derive(Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Token {
    signing_key: [u8; 32],
    encryption_key: [u8; 32],
}

impl Token {
    /// Create a Token from a 64-byte derived key.
    ///
    /// `key[0:32]` = signing key (HMAC), `key[32:64]` = encryption key (AES).
    ///
    /// # Errors
    /// [`Error::InvalidKey`] if `key` is not exactly 64 bytes.
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        if key.len() != 64 {
            return Err(Error::InvalidKey);
        }
        let mut signing_key = [0u8; 32];
        let mut encryption_key = [0u8; 32];
        signing_key.copy_from_slice(&key[..32]);
        encryption_key.copy_from_slice(&key[32..64]);
        Ok(Token {
            signing_key,
            encryption_key,
        })
    }

    /// Encrypt `plaintext` into `out`.
    ///
    /// Output format: `iv[16] || aes_256_cbc_body || hmac_sha256[32]`
    ///
    /// Returns the number of bytes written.
    ///
    /// # Errors
    /// [`Error::BufferTooSmall`] if `out` cannot hold the result.
    pub fn encrypt<R>(&self, plaintext: &[u8], rng: &mut R, out: &mut [u8]) -> Result<usize, Error>
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        use aes::cipher::{generic_array::GenericArray, BlockEncryptMut, KeyIvInit};
        use aes::Aes256;
        use hmac::{Hmac, Mac};

        let pad_len = 16 - (plaintext.len() % 16);
        let padded_len = plaintext.len() + pad_len;
        let total_len = TOKEN_OVERHEAD + padded_len; // iv + aes_body + hmac
        if out.len() < total_len {
            return Err(Error::BufferTooSmall);
        }

        // 1. Random IV
        let mut iv = [0u8; 16];
        rng.fill_bytes(&mut iv);

        // 2. Write IV
        out[..16].copy_from_slice(&iv);

        // 3. PKCS7-pad plaintext
        out[16..16 + plaintext.len()].copy_from_slice(plaintext);
        for b in &mut out[16 + plaintext.len()..16 + padded_len] {
            *b = pad_len as u8;
        }

        // 4. AES-256-CBC encrypt in-place
        let mut enc = cbc::Encryptor::<Aes256>::new(
            GenericArray::from_slice(&self.encryption_key),
            GenericArray::from_slice(&iv),
        );
        for chunk in out[16..16 + padded_len].chunks_exact_mut(16) {
            enc.encrypt_block_mut(GenericArray::from_mut_slice(chunk));
        }

        // 5. HMAC-SHA256(signing_key, iv || aes_body)
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&self.signing_key)
            .map_err(|_| Error::CryptoError)?;
        mac.update(&out[..16 + padded_len]);
        let hmac_result = mac.finalize().into_bytes();
        out[16 + padded_len..total_len].copy_from_slice(&hmac_result);

        Ok(total_len)
    }

    /// Decrypt `ciphertext` (token format) into `out`.
    ///
    /// Input format: `iv[16] || aes_256_cbc_body || hmac_sha256[32]`
    ///
    /// Returns the number of plaintext bytes written.
    ///
    /// # Errors
    /// [`Error::CryptoError`] on HMAC mismatch or invalid ciphertext.
    /// [`Error::InvalidPadding`] on bad PKCS7 padding.
    /// [`Error::BufferTooSmall`] if `out` is too small.
    pub fn decrypt(&self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        use aes::cipher::{generic_array::GenericArray, BlockDecryptMut, KeyIvInit};
        use aes::Aes256;
        use hmac::{Hmac, Mac};

        // Minimum: iv(16) + 1_block(16) + hmac(32) = 64
        if ciphertext.len() < 64 {
            return Err(Error::CryptoError);
        }

        // 1. Verify HMAC
        let hmac_offset = ciphertext.len() - 32;
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&self.signing_key)
            .map_err(|_| Error::CryptoError)?;
        mac.update(&ciphertext[..hmac_offset]);
        mac.verify_slice(&ciphertext[hmac_offset..])
            .map_err(|_| Error::CryptoError)?;

        // 2. Extract IV and AES body
        let iv = &ciphertext[..16];
        let aes_body = &ciphertext[16..hmac_offset];
        if aes_body.is_empty() || !aes_body.len().is_multiple_of(16) {
            return Err(Error::CryptoError);
        }
        if out.len() < aes_body.len() {
            return Err(Error::BufferTooSmall);
        }

        // 3. Copy and decrypt in-place
        out[..aes_body.len()].copy_from_slice(aes_body);
        let mut dec = cbc::Decryptor::<Aes256>::new(
            GenericArray::from_slice(&self.encryption_key),
            GenericArray::from_slice(iv),
        );
        for chunk in out[..aes_body.len()].chunks_exact_mut(16) {
            dec.decrypt_block_mut(GenericArray::from_mut_slice(chunk));
        }

        // 4. PKCS7 unpad
        pkcs7_unpad(&out[..aes_body.len()])
    }
}

/// Validate and strip PKCS#7 padding, returning the unpadded data length.
pub(crate) fn pkcs7_unpad(data: &[u8]) -> Result<usize, Error> {
    if data.is_empty() {
        return Err(Error::InvalidPadding);
    }
    let pad_byte = data[data.len() - 1];
    let pad_len = pad_byte as usize;
    if pad_byte == 0 || pad_len > 16 || pad_len > data.len() {
        return Err(Error::InvalidPadding);
    }
    for &b in &data[data.len() - pad_len..] {
        if b != pad_byte {
            return Err(Error::InvalidPadding);
        }
    }
    Ok(data.len() - pad_len)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_key() -> [u8; 64] {
        let mut key = [0u8; 64];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        key
    }

    #[test]
    fn token_encrypt_decrypt_round_trip() {
        let key = make_test_key();
        let token = Token::new(&key).unwrap();
        let mut rng = rand_core::OsRng;

        let plaintext = b"hello";
        let mut ct = [0u8; 256];
        let ct_len = token.encrypt(plaintext, &mut rng, &mut ct).unwrap();

        let mut pt = [0u8; 256];
        let pt_len = token.decrypt(&ct[..ct_len], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len], plaintext);
    }

    #[test]
    fn token_output_format() {
        let key = make_test_key();
        let token = Token::new(&key).unwrap();
        let mut rng = rand_core::OsRng;

        let plaintext = b"test data here";
        let mut ct = [0u8; 256];
        let ct_len = token.encrypt(plaintext, &mut rng, &mut ct).unwrap();

        // Format: iv(16) + aes_body(multiple of 16) + hmac(32)
        assert!(ct_len >= TOKEN_OVERHEAD + 16); // at least one block
        let aes_body_len = ct_len - TOKEN_OVERHEAD;
        assert_eq!(aes_body_len % 16, 0, "AES body must be multiple of 16");
    }

    #[test]
    fn token_hmac_tamper_rejected() {
        let key = make_test_key();
        let token = Token::new(&key).unwrap();
        let mut rng = rand_core::OsRng;

        let mut ct = [0u8; 256];
        let ct_len = token.encrypt(b"tamper test", &mut rng, &mut ct).unwrap();

        // Flip a byte in the AES body
        ct[20] ^= 0xFF;

        let mut pt = [0u8; 256];
        assert_eq!(
            token.decrypt(&ct[..ct_len], &mut pt),
            Err(Error::CryptoError)
        );
    }

    #[test]
    fn token_wrong_key_rejected() {
        let key1 = make_test_key();
        let mut key2 = make_test_key();
        key2[0] = 0xFF; // different key
        let token1 = Token::new(&key1).unwrap();
        let token2 = Token::new(&key2).unwrap();
        let mut rng = rand_core::OsRng;

        let mut ct = [0u8; 256];
        let ct_len = token1.encrypt(b"wrong key", &mut rng, &mut ct).unwrap();

        let mut pt = [0u8; 256];
        assert_eq!(
            token2.decrypt(&ct[..ct_len], &mut pt),
            Err(Error::CryptoError)
        );
    }

    #[test]
    fn token_invalid_key_length() {
        assert_eq!(Token::new(&[0u8; 32]), Err(Error::InvalidKey));
    }

    #[test]
    fn test_token_exact_one_block_plaintext() {
        // Plaintext of exactly 16 bytes (one AES block) — round-trip.
        // PKCS7 adds a full padding block, so ciphertext body = 32 bytes.
        let key = make_test_key();
        let token = Token::new(&key).unwrap();
        let mut rng = rand_core::OsRng;

        let plaintext = [0x42u8; 16]; // exactly one AES block
        let mut ct = [0u8; 256];
        let ct_len = token.encrypt(&plaintext, &mut rng, &mut ct).unwrap();

        // iv(16) + aes_body(32: 16 data + 16 padding) + hmac(32) = 80
        assert_eq!(ct_len, 80, "16B plaintext should produce 80B token");

        let mut pt = [0u8; 256];
        let pt_len = token.decrypt(&ct[..ct_len], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len], &plaintext);
    }

    #[test]
    fn test_token_empty_plaintext() {
        // Zero-byte plaintext (empty) — round-trip.
        let key = make_test_key();
        let token = Token::new(&key).unwrap();
        let mut rng = rand_core::OsRng;

        let mut ct = [0u8; 256];
        let ct_len = token.encrypt(&[], &mut rng, &mut ct).unwrap();

        // iv(16) + aes_body(16: full padding block) + hmac(32) = 64
        assert_eq!(ct_len, 64, "empty plaintext should produce 64B token");

        let mut pt = [0u8; 256];
        let pt_len = token.decrypt(&ct[..ct_len], &mut pt).unwrap();
        assert_eq!(pt_len, 0, "decrypted empty plaintext should be 0 bytes");
    }

    #[test]
    fn test_token_truncated_ciphertext() {
        // Truncated ciphertext (less than 64 bytes) should return CryptoError.
        let key = make_test_key();
        let token = Token::new(&key).unwrap();

        let short_ct = [0u8; 63];
        let mut pt = [0u8; 256];
        assert_eq!(
            token.decrypt(&short_ct, &mut pt),
            Err(Error::CryptoError),
            "ciphertext shorter than 64 bytes must fail"
        );

        // Also try even shorter
        let tiny_ct = [0u8; 16];
        assert_eq!(
            token.decrypt(&tiny_ct, &mut pt),
            Err(Error::CryptoError),
            "16-byte ciphertext must fail"
        );
    }
}
