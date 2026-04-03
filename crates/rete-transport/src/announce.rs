//! Announce handling — validation and pending outbound announces.

extern crate alloc;

use alloc::vec::Vec;
use rete_core::{DestHash, IdentityHash, NAME_HASH_LEN, TRUNCATED_HASH_LEN};
use sha2::{Digest, Sha256};

/// Minimum announce payload without ratchet: pub_key(64) + name_hash(10) + random_hash(10) + signature(64) = 148.
pub const MIN_ANNOUNCE_PAYLOAD: usize = 148;

/// Minimum announce payload with ratchet (context_flag=1): pub_key(64) + name_hash(10) + random_hash(10) + ratchet(32) + signature(64) = 180.
pub const MIN_RATCHET_ANNOUNCE_PAYLOAD: usize = 180;

/// Size of an X25519 ratchet public key in bytes.
pub const RATCHET_KEY_LEN: usize = 32;

/// Validated announce information extracted from a packet payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnounceInfo<'a> {
    /// 16-byte identity hash (SHA-256(pub_key)[0:16]).
    pub identity_hash: IdentityHash,
    /// 64-byte combined public key (X25519[32] || Ed25519[32]).
    pub pub_key: &'a [u8],
    /// 10-byte name hash.
    pub name_hash: &'a [u8],
    /// 10-byte random hash (5 random + 5 timestamp bytes).
    pub random_hash: &'a [u8],
    /// 64-byte Ed25519 signature.
    pub signature: &'a [u8],
    /// Optional 32-byte X25519 ratchet public key (present when context_flag=1).
    pub ratchet: Option<&'a [u8]>,
    /// Optional application data (after signature in payload).
    pub app_data: Option<&'a [u8]>,
}

/// Validate an announce packet's payload.
///
/// Extracts the public key, name hash, random hash, optional ratchet key,
/// and signature from the announce payload. Verifies the Ed25519 signature
/// and recomputes the destination hash to ensure consistency.
///
/// # Arguments
/// - `dest_hash` — the 16-byte destination hash from the packet header
/// - `payload` — the announce payload bytes (starting after the context byte)
/// - `context_flag` — when true, a 32-byte ratchet key is present at payload[84..116]
///
/// # Returns
/// `Ok(AnnounceInfo)` if the announce is cryptographically valid.
///
/// # Errors
/// - Payload too short
/// - Ed25519 signature verification failure
/// - Destination hash mismatch
pub fn validate_announce<'a>(
    dest_hash: &[u8],
    payload: &'a [u8],
    context_flag: bool,
) -> Result<AnnounceInfo<'a>, AnnounceError> {
    // When context_flag is set, 32 ratchet bytes are present after random_hash
    let min_len = if context_flag {
        MIN_RATCHET_ANNOUNCE_PAYLOAD
    } else {
        MIN_ANNOUNCE_PAYLOAD
    };
    if payload.len() < min_len {
        return Err(AnnounceError::PayloadTooShort);
    }

    let pub_key = &payload[0..64];
    let name_hash = &payload[64..74];
    let random_hash = &payload[74..84];

    let (ratchet, signature, app_data_start) = if context_flag {
        // Ratchet at [84..116], signature at [116..180], app_data at [180..]
        (Some(&payload[84..116]), &payload[116..180], 180usize)
    } else {
        // No ratchet, signature at [84..148], app_data at [148..]
        (None, &payload[84..148], 148usize)
    };

    let app_data = if payload.len() > app_data_start {
        Some(&payload[app_data_start..])
    } else {
        None
    };

    // Compute identity hash from public key
    let id_digest = Sha256::digest(pub_key);
    let identity_hash = IdentityHash::from_slice(&id_digest[..TRUNCATED_HASH_LEN]);

    // Recompute destination hash: SHA-256(name_hash || identity_hash)[0:16]
    let mut hasher = Sha256::new();
    hasher.update(name_hash);
    hasher.update(identity_hash.as_ref());
    let computed_dest: [u8; TRUNCATED_HASH_LEN] =
        hasher.finalize()[..TRUNCATED_HASH_LEN].try_into().unwrap();

    if dest_hash.len() < TRUNCATED_HASH_LEN || computed_dest != dest_hash[..TRUNCATED_HASH_LEN] {
        return Err(AnnounceError::DestHashMismatch);
    }

    // Build signed_data: dest_hash || pub_key || name_hash || random_hash [|| ratchet] [|| app_data]
    let mut signed_data = [0u8; rete_core::MTU];
    let mut pos = 0;
    signed_data[pos..pos + TRUNCATED_HASH_LEN].copy_from_slice(&computed_dest);
    pos += TRUNCATED_HASH_LEN;
    signed_data[pos..pos + 64].copy_from_slice(pub_key);
    pos += 64;
    signed_data[pos..pos + NAME_HASH_LEN].copy_from_slice(name_hash);
    pos += NAME_HASH_LEN;
    signed_data[pos..pos + 10].copy_from_slice(random_hash);
    pos += 10;
    if let Some(r) = ratchet {
        signed_data[pos..pos + RATCHET_KEY_LEN].copy_from_slice(r);
        pos += RATCHET_KEY_LEN;
    }
    if let Some(ad) = app_data {
        signed_data[pos..pos + ad.len()].copy_from_slice(ad);
        pos += ad.len();
    }

    // Verify Ed25519 signature using Identity from public key
    let identity = rete_core::Identity::from_public_key(pub_key)
        .map_err(|_| AnnounceError::InvalidPublicKey)?;
    identity
        .verify(&signed_data[..pos], signature)
        .map_err(|_| AnnounceError::InvalidSignature)?;

    Ok(AnnounceInfo {
        identity_hash,
        pub_key,
        name_hash,
        random_hash,
        signature,
        ratchet,
        app_data,
    })
}

/// Errors from announce validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnnounceError {
    /// Payload is shorter than the minimum 148 bytes.
    PayloadTooShort,
    /// The public key in the payload is invalid.
    InvalidPublicKey,
    /// Ed25519 signature verification failed.
    InvalidSignature,
    /// Recomputed destination hash doesn't match the packet header.
    DestHashMismatch,
}

impl core::fmt::Display for AnnounceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PayloadTooShort => write!(f, "announce payload too short"),
            Self::InvalidPublicKey => write!(f, "invalid public key in announce"),
            Self::InvalidSignature => write!(f, "announce signature verification failed"),
            Self::DestHashMismatch => write!(f, "announce destination hash mismatch"),
        }
    }
}

/// An announce pending outbound transmission.
#[derive(Debug, Clone)]
pub struct PendingAnnounce {
    /// Destination hash this announce is for.
    pub dest_hash: DestHash,
    /// Complete raw packet bytes (header + payload).
    pub raw: Vec<u8>,
    /// Number of times transmitted so far (retries).
    pub tx_count: u8,
    /// Timestamp when retransmission is due (monotonic seconds).
    pub retransmit_timeout: u64,
    /// Whether this is a local announce (not a retransmission).
    pub local: bool,
    /// Number of times we've heard our own rebroadcast at the same hop count.
    pub local_rebroadcasts: u8,
    /// If true, suppress further retransmissions (path response or local rebroadcast limit reached).
    pub block_rebroadcasts: bool,
    /// Hop count at which this announce was received (for rebroadcast detection).
    pub received_hops: u8,
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec::Vec;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn validate_announce_alice_no_appdata() {
        let dest_hash = unhex("2b7fa6842783252974dc5fcaff22b808");
        let payload = unhex("80ffd69d6399c09c790748a2783b9bd5198652b2e14d496eaf4d29ce06a0ea0fa175c596dc0558fd271c185e89f2c85f8bc490c0e7dd25da0b0142246da9628ffca709a4818d4e0c78a00000000000006553f10050fe696f35b4fc3c4e43e2269372ae2b603ac90dd64757c8ac224bb80f0cabd4e2863f7bc593cd3a785d360ba48485fad67a39617880214dd16086c6e53d8205");

        let info = validate_announce(&dest_hash, &payload, false).unwrap();
        assert_eq!(
            info.identity_hash.as_ref(),
            unhex("fd9f121e293bf4a415dd74366ff75f69").as_slice()
        );
        assert!(info.app_data.is_none());
    }

    #[test]
    fn validate_announce_alice_with_appdata() {
        let dest_hash = unhex("2b7fa6842783252974dc5fcaff22b808");
        let payload = unhex("80ffd69d6399c09c790748a2783b9bd5198652b2e14d496eaf4d29ce06a0ea0fa175c596dc0558fd271c185e89f2c85f8bc490c0e7dd25da0b0142246da9628ffca709a4818d4e0c78a00000000000006553f1006950faa92732c50c127e4101ee07eff43657b7a0f72d5841c53eb146d1c2b79ed287fbdd16b0f80549e86777fe1a971109c8137492519c63a6f22803e91bfb096e6f64653a73656e736f723a6f7574646f6f723a7631");

        let info = validate_announce(&dest_hash, &payload, false).unwrap();
        assert_eq!(info.app_data.unwrap(), b"node:sensor:outdoor:v1");
    }

    #[test]
    fn validate_announce_bob_no_appdata() {
        let dest_hash = unhex("22da01f03d8c743d2483fce46f093bf5");
        let payload = unhex("9c5ea4c9ed8f7f3559c32f8e563507724748e3d1c3eafd6ce1752920eeb325711abf893af86c64a5e23b9cd3904ef689ac228b31f272941367a4ac9c93410416fca709a4818d4e0c78a00000000000006553f100311fcc6eaa3af38005714bfad1d792aed129f9cb9ad1a798116a7db2c6d432610ea238ccc170deee66f84de7c9692c36bffdf5649e48aae01c00b41a41c7d60c");

        let info = validate_announce(&dest_hash, &payload, false).unwrap();
        assert_eq!(
            info.identity_hash.as_ref(),
            unhex("236d5c3f7d7a9ca0388ca355cb71080b").as_slice()
        );
    }

    #[test]
    fn validate_announce_bad_signature() {
        let dest_hash = unhex("2b7fa6842783252974dc5fcaff22b808");
        // Use alice's announce but flip a byte in the signature
        let mut payload = unhex("80ffd69d6399c09c790748a2783b9bd5198652b2e14d496eaf4d29ce06a0ea0fa175c596dc0558fd271c185e89f2c85f8bc490c0e7dd25da0b0142246da9628ffca709a4818d4e0c78a00000000000006553f10050fe696f35b4fc3c4e43e2269372ae2b603ac90dd64757c8ac224bb80f0cabd4e2863f7bc593cd3a785d360ba48485fad67a39617880214dd16086c6e53d8205");
        payload[84] ^= 0xFF; // corrupt signature
        assert_eq!(
            validate_announce(&dest_hash, &payload, false),
            Err(AnnounceError::InvalidSignature)
        );
    }

    #[test]
    fn validate_announce_wrong_dest_hash() {
        let dest_hash = unhex("0000000000000000000000000000dead");
        let payload = unhex("80ffd69d6399c09c790748a2783b9bd5198652b2e14d496eaf4d29ce06a0ea0fa175c596dc0558fd271c185e89f2c85f8bc490c0e7dd25da0b0142246da9628ffca709a4818d4e0c78a00000000000006553f10050fe696f35b4fc3c4e43e2269372ae2b603ac90dd64757c8ac224bb80f0cabd4e2863f7bc593cd3a785d360ba48485fad67a39617880214dd16086c6e53d8205");
        assert_eq!(
            validate_announce(&dest_hash, &payload, false),
            Err(AnnounceError::DestHashMismatch)
        );
    }

    #[test]
    fn validate_announce_too_short() {
        let dest_hash = unhex("2b7fa6842783252974dc5fcaff22b808");
        assert_eq!(
            validate_announce(&dest_hash, &[0u8; 100], false),
            Err(AnnounceError::PayloadTooShort)
        );
    }
}
