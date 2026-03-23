//! Link — encrypted session state machine.
//!
//! A Link provides a bidirectional encrypted channel between two Reticulum
//! identities. The handshake uses ephemeral X25519 keys for forward secrecy.
//!
//! # Handshake (responder perspective)
//! 1. Receive LINKREQUEST: extract peer's X25519_pub, Ed25519_pub, and signalling[3]
//! 2. Compute link_id from hashable part of the request
//! 3. Generate our ephemeral X25519 keypair
//! 4. ECDH(our_prv, peer_pub) → shared_key
//! 5. HKDF-SHA256(ikm=shared_key, salt=link_id, info=b"", length=64) → derived_key
//! 6. Create Token from derived_key
//! 7. Build LRPROOF: sign(link_id || our_x25519_pub || our_ed25519_pub || signalling) || our_x25519_pub || signalling
//!
//! # Handshake (initiator perspective)
//! 1. Generate ephemeral X25519 keypair
//! 2. Build LINKREQUEST: our_x25519_pub[32] || our_ed25519_pub[32] || signalling[3]
//! 3. Send LINKREQUEST to destination
//! 4. Receive LRPROOF: extract signature[64] || responder_x25519_pub[32] [|| signalling[3]]
//! 5. Verify signature over (link_id || responder_x25519_pub || responder_ed25519_pub [|| signalling])
//! 6. ECDH(our_prv, responder_pub) → shared_key
//! 7. HKDF-SHA256(ikm=shared_key, salt=link_id, info=b"", length=64) → derived_key
//! 8. Create Token from derived_key

use crate::channel::Channel;
use rand_core::{CryptoRng, RngCore};
use rete_core::{Identity, Token, TRUNCATED_HASH_LEN};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Link state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// Waiting for LINKREQUEST to be sent or received.
    Pending,
    /// Handshake in progress (LINKREQUEST received, proof not yet validated).
    Handshake,
    /// Link is active — encrypted data can flow.
    Active,
    /// Link has gone stale (no traffic for stale_time).
    Stale,
    /// Link is closed.
    Closed,
}

/// Whether we initiated or responded to this link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkRole {
    /// We sent the LINKREQUEST.
    Initiator,
    /// We received the LINKREQUEST and responded.
    Responder,
}

/// Teardown reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeardownReason {
    /// Timeout with no traffic.
    Timeout,
    /// Initiator closed the link.
    InitiatorClosed,
    /// Destination closed the link.
    DestinationClosed,
}

/// Default keepalive interval in seconds (6 minutes, matches Python RNS).
pub const KEEPALIVE_INTERVAL_SECS: u64 = 360;
/// Default stale timeout in seconds (2x keepalive = 720s, matches Python RNS).
/// Python: `STALE_FACTOR = 2`, `STALE_TIME = STALE_FACTOR * KEEPALIVE = 2 * 360 = 720`.
pub const STALE_TIMEOUT_SECS: u64 = 720;

/// Maximum RTT that produces the maximum keepalive interval.
/// Python: `Link.KEEPALIVE_TIMEOUT_FACTOR = 4` → `360 / (4/1.75*1) = 1.75` effectively.
/// Formula: `keepalive = rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT)`.
pub const KEEPALIVE_MAX_RTT: f32 = 1.75;
/// Maximum keepalive interval in seconds.
pub const KEEPALIVE_MAX: f32 = 360.0;
/// Minimum keepalive interval in seconds.
pub const KEEPALIVE_MIN: f32 = 5.0;
/// Stale timeout multiplier relative to keepalive interval.
pub const STALE_FACTOR: f32 = 2.0;
/// Grace period added to stale detection (seconds). Python: `STALE_GRACE = 5`.
pub const STALE_GRACE: u64 = 5;
/// Minimum traffic timeout in milliseconds. Python: `TRAFFIC_TIMEOUT_MIN_MS = 5`.
pub const TRAFFIC_TIMEOUT_MIN_MS: u64 = 5;
/// Traffic timeout multiplier for receipt timeouts. Python: `TRAFFIC_TIMEOUT_FACTOR = 6`.
pub const TRAFFIC_TIMEOUT_FACTOR: u64 = 6;
/// Keepalive timeout factor. Python: `KEEPALIVE_TIMEOUT_FACTOR = 4`.
pub const KEEPALIVE_TIMEOUT_FACTOR: f32 = 4.0;
/// Establishment timeout per hop (seconds). Python: `DEFAULT_PER_HOP_TIMEOUT = 6`.
pub const ESTABLISHMENT_TIMEOUT_PER_HOP: u64 = 6;

/// An encrypted link session.
pub struct Link {
    /// Unique 16-byte link identifier.
    pub link_id: [u8; TRUNCATED_HASH_LEN],
    /// Current state.
    pub state: LinkState,
    /// Our role in this link.
    pub role: LinkRole,
    /// Symmetric cipher for encrypt/decrypt.
    token: Option<Token>,
    /// Peer's X25519 public key (from LINKREQUEST or LRPROOF).
    pub peer_x25519_pub: [u8; 32],
    /// Peer's Ed25519 public key.
    pub peer_ed25519_pub: [u8; 32],
    /// Our ephemeral X25519 private key.
    our_x25519_prv: [u8; 32],
    /// Our ephemeral X25519 public key.
    pub our_x25519_pub: [u8; 32],
    /// Our Ed25519 public key (sent in LINKREQUEST for initiator).
    #[allow(dead_code)]
    our_ed25519_pub: [u8; 32],
    /// Measured round-trip time (seconds).
    pub rtt: f32,
    /// Last activity timestamp (monotonic seconds).
    pub last_inbound: u64,
    /// Last outbound timestamp.
    pub last_outbound: u64,
    /// Keepalive interval in seconds.
    pub keepalive_interval: u64,
    /// Stale timeout = keepalive × 2.
    pub stale_time: u64,
    /// Destination hash this link is associated with.
    pub destination_hash: [u8; TRUNCATED_HASH_LEN],
    /// MTU signalling bytes (3 bytes: MTU + encryption mode).
    /// Included in LINKREQUEST and LRPROOF for protocol completeness.
    pub signalling: [u8; LINK_MTU_SIZE],
    /// Reliable ordered channel (lazy-initialized on first channel message).
    pub(crate) channel: Option<Channel>,
}

impl Link {
    /// Create a Link as responder from a received LINKREQUEST.
    ///
    /// Extracts the peer's keys, generates our ephemeral key, performs ECDH+HKDF,
    /// and creates the Token for symmetric encryption.
    ///
    /// # Arguments
    /// - `link_id` — computed from the hashable part of the LINKREQUEST
    /// - `request_payload` — the LINKREQUEST payload (64+ bytes)
    /// - `our_identity` — our Identity (for signing the proof)
    /// - `rng` — cryptographic RNG
    /// - `now` — current monotonic time
    pub fn from_request<R: RngCore + CryptoRng>(
        link_id: [u8; TRUNCATED_HASH_LEN],
        request_payload: &[u8],
        rng: &mut R,
        now: u64,
    ) -> Result<Self, rete_core::Error> {
        if request_payload.len() < 64 {
            return Err(rete_core::Error::PacketTooShort);
        }

        let mut peer_x25519_pub = [0u8; 32];
        let mut peer_ed25519_pub = [0u8; 32];
        peer_x25519_pub.copy_from_slice(&request_payload[..32]);
        peer_ed25519_pub.copy_from_slice(&request_payload[32..64]);

        // Extract signalling bytes if present (payload >= 67 bytes)
        let mut peer_signalling = [0u8; LINK_MTU_SIZE];
        if request_payload.len() >= 64 + LINK_MTU_SIZE {
            peer_signalling.copy_from_slice(&request_payload[64..64 + LINK_MTU_SIZE]);
        }

        // Generate our ephemeral X25519 keypair
        let our_secret = x25519_dalek::StaticSecret::random_from_rng(&mut *rng);
        let our_public = x25519_dalek::PublicKey::from(&our_secret);
        let our_x25519_prv = our_secret.to_bytes();
        let our_x25519_pub = our_public.to_bytes();

        // ECDH
        let peer_pub = x25519_dalek::PublicKey::from(peer_x25519_pub);
        let shared = our_secret.diffie_hellman(&peer_pub);

        // HKDF-SHA256(ikm=shared, salt=link_id, info=b"", length=64)
        let hk = hkdf::Hkdf::<Sha256>::new(Some(&link_id), shared.as_bytes());
        let mut derived = [0u8; 64];
        hk.expand(b"", &mut derived)
            .map_err(|_| rete_core::Error::CryptoError)?;

        let token = Token::new(&derived)?;
        derived.zeroize();

        // Ephemeral private key no longer needed — Token holds the session key.
        let mut zeroed_prv = our_x25519_prv;
        zeroed_prv.zeroize();

        Ok(Link {
            link_id,
            state: LinkState::Handshake,
            role: LinkRole::Responder,
            token: Some(token),
            peer_x25519_pub,
            peer_ed25519_pub,
            our_x25519_prv: zeroed_prv,
            our_x25519_pub,
            our_ed25519_pub: [0u8; 32], // not needed for responder
            rtt: 0.0,
            last_inbound: now,
            last_outbound: now,
            keepalive_interval: KEEPALIVE_INTERVAL_SECS,
            stale_time: STALE_TIMEOUT_SECS,
            destination_hash: [0u8; TRUNCATED_HASH_LEN],
            signalling: peer_signalling,
            channel: None,
        })
    }

    /// Build the LRPROOF payload for the responder.
    ///
    /// Format: `Ed25519_signature[64] || X25519_responder_pub[32] || signalling[3]`
    /// Signature covers: `link_id || responder_x25519_pub || responder_ed25519_pub || signalling`
    ///
    /// The signed data uses the responder's own keys (not the initiator's peer keys).
    /// This matches the Python reference: `Link.prove()` signs
    /// `self.link_id + self.pub_bytes + self.sig_pub_bytes + self.signalling_bytes`.
    ///
    /// Returns a 99-byte proof (64 sig + 32 x25519_pub + 3 signalling).
    /// Python's `validate_proof` handles both 96-byte and 99-byte proofs.
    pub fn build_proof(
        &self,
        owner_identity: &Identity,
    ) -> Result<[u8; 96 + LINK_MTU_SIZE], rete_core::Error> {
        // Build signed data: link_id || our_x25519_pub || owner_ed25519_pub || signalling
        let mut signed_data = [0u8; 80 + LINK_MTU_SIZE]; // 16 + 32 + 32 + 3
        signed_data[..16].copy_from_slice(&self.link_id);
        signed_data[16..48].copy_from_slice(&self.our_x25519_pub);
        signed_data[48..80].copy_from_slice(owner_identity.ed25519_pub());
        signed_data[80..80 + LINK_MTU_SIZE].copy_from_slice(&self.signalling);

        let signature = owner_identity.sign(&signed_data)?;

        // LRPROOF: signature[64] || our_x25519_pub[32] || signalling[3]
        let mut proof = [0u8; 96 + LINK_MTU_SIZE];
        proof[..64].copy_from_slice(&signature);
        proof[64..96].copy_from_slice(&self.our_x25519_pub);
        proof[96..96 + LINK_MTU_SIZE].copy_from_slice(&self.signalling);
        Ok(proof)
    }

    /// Create a Link as initiator.
    ///
    /// Generates our ephemeral X25519 keypair and returns the LINKREQUEST payload
    /// as a 67-byte array: `x25519_pub[32] || ed25519_pub[32] || signalling[3]`.
    ///
    /// The 3 signalling bytes encode MTU and encryption mode, matching Python's
    /// `Link.LINK_MTU_SIZE` format.
    pub fn new_initiator<R: RngCore + CryptoRng>(
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        our_ed25519_pub: &[u8; 32],
        rng: &mut R,
        now: u64,
    ) -> (Self, [u8; 64 + LINK_MTU_SIZE]) {
        // Generate ephemeral X25519
        let our_secret = x25519_dalek::StaticSecret::random_from_rng(&mut *rng);
        let our_public = x25519_dalek::PublicKey::from(&our_secret);
        let our_x25519_prv = our_secret.to_bytes();
        let our_x25519_pub = our_public.to_bytes();

        // Compute signalling bytes: default MTU + AES-CBC mode
        let sig_bytes = signalling_bytes(rete_core::MTU as u32, MODE_AES_CBC);

        // Build LINKREQUEST payload: x25519_pub[32] || ed25519_pub[32] || signalling[3]
        let mut payload = [0u8; 64 + LINK_MTU_SIZE];
        payload[..32].copy_from_slice(&our_x25519_pub);
        payload[32..64].copy_from_slice(our_ed25519_pub);
        payload[64..64 + LINK_MTU_SIZE].copy_from_slice(&sig_bytes);

        let link = Link {
            link_id: [0u8; TRUNCATED_HASH_LEN], // will be computed after send
            state: LinkState::Pending,
            role: LinkRole::Initiator,
            token: None,
            peer_x25519_pub: [0u8; 32],
            peer_ed25519_pub: [0u8; 32],
            our_x25519_prv,
            our_x25519_pub,
            our_ed25519_pub: *our_ed25519_pub,
            rtt: 0.0,
            last_inbound: now,
            last_outbound: now,
            keepalive_interval: KEEPALIVE_INTERVAL_SECS,
            stale_time: STALE_TIMEOUT_SECS,
            destination_hash: dest_hash,
            signalling: sig_bytes,
            channel: None,
        };

        (link, payload)
    }

    /// Set the link_id (called after sending the LINKREQUEST and computing the hash).
    pub fn set_link_id(&mut self, link_id: [u8; TRUNCATED_HASH_LEN]) {
        self.link_id = link_id;
        self.state = LinkState::Handshake;
    }

    /// Validate the LRPROOF as initiator.
    ///
    /// Proof format: `signature[64] || responder_x25519_pub[32]`
    /// Verifies signature over (link_id || responder_x25519_pub || responder_ed25519_pub),
    /// performs ECDH+HKDF, and creates the Token.
    ///
    /// The signed data uses the responder's own keys. This matches the Python reference:
    /// `Link.validate_proof()` verifies `link_id + peer_pub_bytes + peer_sig_pub_bytes`.
    pub fn validate_proof(
        &mut self,
        proof_payload: &[u8],
        dest_identity: &Identity,
    ) -> Result<(), rete_core::Error> {
        if proof_payload.len() < 96 {
            return Err(rete_core::Error::PacketTooShort);
        }

        let signature = &proof_payload[..64];
        let mut responder_x25519_pub = [0u8; 32];
        responder_x25519_pub.copy_from_slice(&proof_payload[64..96]);
        // Signalling bytes: 0 bytes (no MTU signalling) or 3 bytes (Link.LINK_MTU_SIZE).
        // Reject anything outside this range to prevent buffer overflow.
        let signalling = &proof_payload[96..];
        if signalling.len() > 3 {
            return Err(rete_core::Error::PacketTooShort);
        }

        // Verify signature: responder signed
        // (link_id || responder_x25519_pub || responder_ed25519_pub [|| signalling_bytes])
        // Python includes signalling_bytes in the signed data when present (Link.py:373).
        let mut signed_data = [0u8; 83]; // max: 16+32+32+3
        let signed_len = 80 + signalling.len();
        signed_data[..16].copy_from_slice(&self.link_id);
        signed_data[16..48].copy_from_slice(&responder_x25519_pub);
        signed_data[48..80].copy_from_slice(dest_identity.ed25519_pub());
        signed_data[80..signed_len].copy_from_slice(signalling);

        dest_identity.verify(&signed_data[..signed_len], signature)?;

        // ECDH with responder's X25519 pub
        let our_secret = x25519_dalek::StaticSecret::from(self.our_x25519_prv);
        let peer_pub = x25519_dalek::PublicKey::from(responder_x25519_pub);
        let shared = our_secret.diffie_hellman(&peer_pub);

        // HKDF-SHA256(ikm=shared, salt=link_id, info=b"", length=64)
        let hk = hkdf::Hkdf::<Sha256>::new(Some(&self.link_id), shared.as_bytes());
        let mut derived = [0u8; 64];
        hk.expand(b"", &mut derived)
            .map_err(|_| rete_core::Error::CryptoError)?;

        self.token = Some(Token::new(&derived)?);
        derived.zeroize();
        self.our_x25519_prv.zeroize(); // no longer needed
        self.peer_x25519_pub = responder_x25519_pub;
        self.peer_ed25519_pub
            .copy_from_slice(dest_identity.ed25519_pub());
        self.state = LinkState::Handshake; // will become Active after RTT

        Ok(())
    }

    /// Encrypt plaintext using the link's Token.
    pub fn encrypt<R: RngCore + CryptoRng>(
        &self,
        plaintext: &[u8],
        rng: &mut R,
        out: &mut [u8],
    ) -> Result<usize, rete_core::Error> {
        self.token
            .as_ref()
            .ok_or(rete_core::Error::CryptoError)?
            .encrypt(plaintext, rng, out)
    }

    /// Decrypt ciphertext using the link's Token.
    pub fn decrypt(&self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize, rete_core::Error> {
        self.token
            .as_ref()
            .ok_or(rete_core::Error::CryptoError)?
            .decrypt(ciphertext, out)
    }

    /// Update keepalive and stale timers based on measured RTT.
    ///
    /// Matches Python `Link.__update_keepalive()`:
    /// ```python
    /// self.keepalive = max(min(rtt * (360/1.75), 360), 5)
    /// self.stale_time = self.keepalive * 2
    /// ```
    pub fn update_keepalive(&mut self, rtt: f32) {
        if rtt <= 0.0 {
            return; // Don't update if RTT not measured
        }
        self.rtt = rtt;
        let ka = (rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT)).clamp(KEEPALIVE_MIN, KEEPALIVE_MAX);
        // Ensure at least 1 second to prevent zero-interval issues
        self.keepalive_interval = (ka as u64).max(1);
        self.stale_time = ((ka * STALE_FACTOR) as u64).max(2);
    }

    /// Activate the link (after RTT measurement completes).
    pub fn activate(&mut self, now: u64) {
        self.state = LinkState::Active;
        self.last_inbound = now;
    }

    /// Mark the link as closed.
    pub fn close(&mut self) {
        self.state = LinkState::Closed;
    }

    /// Check if the link is active.
    pub fn is_active(&self) -> bool {
        self.state == LinkState::Active
    }

    /// Access the channel (if initialized).
    pub fn channel(&self) -> Option<&Channel> {
        self.channel.as_ref()
    }

    /// Update last inbound timestamp.
    pub fn touch_inbound(&mut self, now: u64) {
        self.last_inbound = now;
        if self.state == LinkState::Stale {
            self.state = LinkState::Active;
        }
    }

    /// Process an inbound keepalive payload.
    ///
    /// Returns `Some(response)` if a keepalive response should be sent.
    /// Keepalive request = 0xFF, response = 0xFE.
    pub fn handle_keepalive(&mut self, payload: &[u8], now: u64) -> Option<u8> {
        self.touch_inbound(now);
        if payload.first() == Some(&0xFF) {
            Some(0xFE) // respond to request
        } else {
            None // 0xFE response, no action needed
        }
    }

    /// Process a LINKCLOSE payload. Returns true if the link should be closed.
    ///
    /// The payload should be the encrypted link_id (16 bytes after decryption).
    pub fn handle_close(&mut self, decrypted_payload: &[u8]) -> bool {
        if decrypted_payload.len() >= TRUNCATED_HASH_LEN
            && decrypted_payload[..TRUNCATED_HASH_LEN] == self.link_id
        {
            self.state = LinkState::Closed;
            true
        } else {
            false
        }
    }

    /// Build LINKCLOSE payload (encrypt link_id).
    pub fn build_close<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        out: &mut [u8],
    ) -> Result<usize, rete_core::Error> {
        self.encrypt(&self.link_id, rng, out)
    }

    /// Whether a keepalive should be sent proactively.
    ///
    /// Returns true if the link is active (or stale) and half the keepalive
    /// interval has elapsed since our last outbound packet. Also sends
    /// keepalives on stale links to attempt revival.
    pub fn needs_keepalive(&self, now: u64) -> bool {
        (self.state == LinkState::Active || self.state == LinkState::Stale)
            && now.saturating_sub(self.last_outbound) > self.keepalive_interval / 2
    }

    /// Check for staleness. Returns true if the link should be closed.
    pub fn check_stale(&mut self, now: u64) -> bool {
        if self.state == LinkState::Active
            && now.saturating_sub(self.last_inbound) > self.keepalive_interval
        {
            self.state = LinkState::Stale;
        }
        if self.state == LinkState::Stale && now.saturating_sub(self.last_inbound) > self.stale_time
        {
            self.state = LinkState::Closed;
            return true;
        }
        false
    }
}

/// Maximum data unit for link-encrypted payloads.
///
/// Computed as: `floor((MTU - 1 - HEADER_1_OVERHEAD - TOKEN_OVERHEAD) / 16) * 16 - 1`
/// where TOKEN_OVERHEAD = 48 (32-byte FERNET token header + 16-byte IV).
/// This gives 431 bytes — the largest plaintext that fits in one link packet.
pub const LINK_MDU: usize = 431;

/// Compute link MDU from a given MTU.
///
/// Python: `math.floor((mtu - IFAC_MIN_SIZE - HEADER_MINSIZE - TOKEN_OVERHEAD) / 16) * 16 - 1`
/// where IFAC_MIN_SIZE=1, HEADER_MINSIZE=19, TOKEN_OVERHEAD=48 → overhead=68.
/// For radio (500) = 431; for TCP (8192) = 8111.
pub fn compute_link_mdu(mtu: usize) -> usize {
    const OVERHEAD: usize = 68; // IFAC_MIN_SIZE(1) + HEADER_MINSIZE(19) + TOKEN_OVERHEAD(48)
    if mtu <= OVERHEAD {
        return 0;
    }
    ((mtu - OVERHEAD) / 16) * 16 - 1
}

/// Compute resource SDU from a given MTU.
///
/// Python: `mtu - HEADER_MAXSIZE - IFAC_MIN_SIZE` (35 + 1 = 36).
/// For radio (500) = 464; for TCP (8192) = 8156.
pub fn compute_resource_sdu(mtu: usize) -> usize {
    const OVERHEAD: usize = 36; // HEADER_MAXSIZE(35) + IFAC_MIN_SIZE(1)
    if mtu <= OVERHEAD {
        return 0;
    }
    mtu - OVERHEAD
}

/// Compute keepalive interval and stale time from RTT.
///
/// Returns `(keepalive_interval_s, stale_time_s)` as floats.
/// Python: `max(KEEPALIVE_MIN, min(KEEPALIVE_MAX, rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT)))`
pub fn compute_keepalive(rtt: f32) -> (f32, f32) {
    let keepalive = if rtt <= 0.0 {
        KEEPALIVE_MIN
    } else {
        let ka = rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT);
        ka.clamp(KEEPALIVE_MIN, KEEPALIVE_MAX)
    };
    let stale = keepalive * STALE_FACTOR + STALE_GRACE as f32;
    (keepalive, stale)
}

/// Compute traffic timeout in milliseconds from RTT.
///
/// Python: `max(TRAFFIC_TIMEOUT_MIN_MS, rtt_ms * TRAFFIC_TIMEOUT_FACTOR)`
pub fn compute_traffic_timeout_ms(rtt: f32) -> f32 {
    let rtt_ms = rtt * 1000.0;
    let timeout = rtt_ms * TRAFFIC_TIMEOUT_FACTOR as f32;
    if timeout < TRAFFIC_TIMEOUT_MIN_MS as f32 {
        TRAFFIC_TIMEOUT_MIN_MS as f32
    } else {
        timeout
    }
}

/// Compute establishment timeout from hop count.
///
/// Python: `hops * ESTABLISHMENT_TIMEOUT_PER_HOP`
pub fn compute_establishment_timeout(hops: u64) -> u64 {
    hops * ESTABLISHMENT_TIMEOUT_PER_HOP
}

/// Size of MTU signalling bytes appended to LINKREQUEST and LRPROOF.
/// Python: `Link.LINK_MTU_SIZE = 3`.
pub const LINK_MTU_SIZE: usize = 3;

/// Encryption mode: AES-256-CBC (Python: `Link.ENCRYPT_AES = 0x01`).
const MODE_AES_CBC: u8 = 0x01;

/// Encode MTU and encryption mode into 3 signalling bytes.
///
/// Matches Python's encoding:
/// ```python
/// struct.pack("!I", (mtu & 0x1FFFFF) | ((mode & 0x07) << 21))[1:]
/// ```
/// This packs a 32-bit big-endian integer with MTU in bits 0..20 and mode in
/// bits 21..23, then drops the leading byte to produce 3 bytes.
pub fn signalling_bytes(mtu: u32, mode: u8) -> [u8; LINK_MTU_SIZE] {
    let packed = (mtu & 0x1F_FFFF) | ((mode as u32 & 0x07) << 21);
    let be = packed.to_be_bytes(); // [0] is MSB, we drop it
    [be[1], be[2], be[3]]
}

/// Decode MTU from 3 signalling bytes.
///
/// Inverse of `signalling_bytes`: extracts the 21-bit MTU field.
pub fn decode_mtu(sig: &[u8; LINK_MTU_SIZE]) -> u32 {
    let packed = u32::from_be_bytes([0, sig[0], sig[1], sig[2]]);
    packed & 0x1F_FFFF
}

/// Compute the link_id from a LINKREQUEST packet's raw bytes.
///
/// ```text
/// hashable_part = (flags & 0x0F) || raw[2:]   (HEADER_1)
/// If payload > 64 bytes (MTU signalling), strip extra bytes from hashable_part.
/// link_id = SHA-256(hashable_part)[0:16]
/// ```
///
/// # Errors
/// Returns an error if the raw bytes cannot be parsed as a valid packet.
pub fn compute_link_id(raw: &[u8]) -> Result<[u8; TRUNCATED_HASH_LEN], rete_core::Error> {
    let pkt = rete_core::Packet::parse(raw)?;
    let mut hashable_buf = [0u8; rete_core::MTU];
    let hashable_len = pkt.write_hashable_part(&mut hashable_buf)?;

    // Strip MTU signalling bytes (if payload > 64 bytes)
    let signalling_len = if pkt.payload.len() > 64 {
        pkt.payload.len() - 64
    } else {
        0
    };
    let effective_len = hashable_len - signalling_len;

    let digest = Sha256::digest(&hashable_buf[..effective_len]);
    let mut link_id = [0u8; TRUNCATED_HASH_LEN];
    link_id.copy_from_slice(&digest[..TRUNCATED_HASH_LEN]);
    Ok(link_id)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use rete_core::{DestType, PacketBuilder, PacketType, MTU};

    #[test]
    fn link_id_computation() {
        // Build a LINKREQUEST
        let dest_hash = [0xAAu8; TRUNCATED_HASH_LEN];
        let x25519_pub = [0xBBu8; 32];
        let ed25519_pub = [0xCCu8; 32];
        let mut payload = [0u8; 64];
        payload[..32].copy_from_slice(&x25519_pub);
        payload[32..].copy_from_slice(&ed25519_pub);

        let mut buf = [0u8; MTU];
        let n = PacketBuilder::new(&mut buf)
            .packet_type(PacketType::LinkRequest)
            .dest_type(DestType::Single)
            .destination_hash(&dest_hash)
            .context(0x00)
            .payload(&payload)
            .build()
            .unwrap();

        let link_id = compute_link_id(&buf[..n]).unwrap();
        assert_eq!(link_id.len(), 16);

        // Same input → same link_id
        let link_id2 = compute_link_id(&buf[..n]).unwrap();
        assert_eq!(link_id, link_id2);
    }

    #[test]
    fn link_from_request_state() {
        let mut rng = rand_core::OsRng;
        let x25519_pub = [0xBBu8; 32];
        let ed25519_pub = [0xCCu8; 32];
        let mut payload = [0u8; 64];
        payload[..32].copy_from_slice(&x25519_pub);
        payload[32..].copy_from_slice(&ed25519_pub);

        let link_id = [0xAAu8; TRUNCATED_HASH_LEN];
        let link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();

        assert_eq!(link.state, LinkState::Handshake);
        assert_eq!(link.role, LinkRole::Responder);
        assert_eq!(link.peer_x25519_pub, x25519_pub);
        assert_eq!(link.peer_ed25519_pub, ed25519_pub);
    }

    #[test]
    fn link_handshake_derives_key() {
        // Simulate both sides of the handshake with known keys
        let mut rng = rand_core::OsRng;

        // Initiator generates ephemeral key
        let initiator_secret = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
        let initiator_pub = x25519_dalek::PublicKey::from(&initiator_secret);

        let ed25519_pub = [0xCCu8; 32]; // dummy ed25519 pub
        let mut payload = [0u8; 64];
        payload[..32].copy_from_slice(initiator_pub.as_bytes());
        payload[32..].copy_from_slice(&ed25519_pub);

        let link_id = [0x11u8; TRUNCATED_HASH_LEN];

        // Responder creates link
        let link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();

        // Initiator derives same key
        let shared =
            initiator_secret.diffie_hellman(&x25519_dalek::PublicKey::from(link.our_x25519_pub));
        let hk = hkdf::Hkdf::<Sha256>::new(Some(&link_id), shared.as_bytes());
        let mut derived = [0u8; 64];
        hk.expand(b"", &mut derived).unwrap();
        let initiator_token = Token::new(&derived).unwrap();

        // Both should encrypt/decrypt symmetrically
        let mut ct = [0u8; 256];
        let ct_len = link
            .encrypt(b"hello from responder", &mut rng, &mut ct)
            .unwrap();

        let mut pt = [0u8; 256];
        let pt_len = initiator_token.decrypt(&ct[..ct_len], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len], b"hello from responder");

        // And the other direction
        let ct_len2 = initiator_token
            .encrypt(b"hello from initiator", &mut rng, &mut ct)
            .unwrap();
        let pt_len2 = link.decrypt(&ct[..ct_len2], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len2], b"hello from initiator");
    }

    #[test]
    fn link_build_proof_signature_valid() {
        let mut rng = rand_core::OsRng;
        let owner = Identity::from_seed(b"link-responder-identity").unwrap();

        // 67-byte payload: x25519[32] || ed25519[32] || signalling[3]
        let identity = Identity::from_seed(b"peer-for-proof-test").unwrap();
        let dest_hash = [0xAAu8; TRUNCATED_HASH_LEN];
        let (_peer_link, request_payload) =
            Link::new_initiator(dest_hash, identity.ed25519_pub(), &mut rng, 100);

        let link_id = [0x11u8; TRUNCATED_HASH_LEN];
        let link = Link::from_request(link_id, &request_payload, &mut rng, 100).unwrap();

        let proof = link.build_proof(&owner).unwrap();
        assert_eq!(proof.len(), 99); // sig[64] + x25519_pub[32] + signalling[3]

        // Verify the signature: covers link_id || x25519_pub || ed25519_pub || signalling
        let sig = &proof[..64];
        let responder_x25519_pub = &proof[64..96];
        let signalling = &proof[96..99];
        let mut signed_data = [0u8; 83];
        signed_data[..16].copy_from_slice(&link_id);
        signed_data[16..48].copy_from_slice(responder_x25519_pub);
        signed_data[48..80].copy_from_slice(owner.ed25519_pub());
        signed_data[80..83].copy_from_slice(signalling);

        assert!(owner.verify(&signed_data, sig).is_ok());
    }

    #[test]
    fn link_encrypt_decrypt_round_trip() {
        let mut rng = rand_core::OsRng;
        let payload = [0xBBu8; 64]; // dummy LINKREQUEST payload
        let link_id = [0x11u8; TRUNCATED_HASH_LEN];

        let link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();

        let mut ct = [0u8; 256];
        let ct_len = link.encrypt(b"test data", &mut rng, &mut ct).unwrap();

        let mut pt = [0u8; 256];
        let pt_len = link.decrypt(&ct[..ct_len], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len], b"test data");
    }

    #[test]
    fn full_handshake_both_sides() {
        let mut rng = rand_core::OsRng;
        let responder_identity = Identity::from_seed(b"responder-full").unwrap();
        let dest_hash = [0xAAu8; TRUNCATED_HASH_LEN];

        // Initiator creates link
        let initiator_identity = Identity::from_seed(b"initiator-full").unwrap();
        let (mut initiator_link, request_payload) =
            Link::new_initiator(dest_hash, initiator_identity.ed25519_pub(), &mut rng, 100);

        // Build LINKREQUEST packet to compute link_id
        let mut pkt_buf = [0u8; MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::LinkRequest)
            .dest_type(DestType::Single)
            .destination_hash(&dest_hash)
            .context(0x00)
            .payload(&request_payload)
            .build()
            .unwrap();
        let link_id = compute_link_id(&pkt_buf[..pkt_len]).unwrap();
        initiator_link.set_link_id(link_id);

        // Responder receives LINKREQUEST
        let responder_link = Link::from_request(link_id, &request_payload, &mut rng, 100).unwrap();

        // Responder builds proof
        let proof_payload = responder_link.build_proof(&responder_identity).unwrap();

        // Initiator validates proof
        initiator_link
            .validate_proof(&proof_payload, &responder_identity)
            .unwrap();

        // Both should derive the same key — test encrypt/decrypt
        let mut ct = [0u8; 256];
        let ct_len = responder_link
            .encrypt(b"from responder", &mut rng, &mut ct)
            .unwrap();
        let mut pt = [0u8; 256];
        let pt_len = initiator_link.decrypt(&ct[..ct_len], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len], b"from responder");

        let ct_len2 = initiator_link
            .encrypt(b"from initiator", &mut rng, &mut ct)
            .unwrap();
        let pt_len2 = responder_link.decrypt(&ct[..ct_len2], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len2], b"from initiator");
    }

    #[test]
    fn validate_proof_bad_sig_rejected() {
        let mut rng = rand_core::OsRng;
        let responder_identity = Identity::from_seed(b"responder-bad-sig").unwrap();
        let wrong_identity = Identity::from_seed(b"wrong-identity").unwrap();
        let dest_hash = [0xAAu8; TRUNCATED_HASH_LEN];

        let initiator_identity = Identity::from_seed(b"initiator-bad-sig").unwrap();
        let (mut initiator_link, request_payload) =
            Link::new_initiator(dest_hash, initiator_identity.ed25519_pub(), &mut rng, 100);

        let mut pkt_buf = [0u8; MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::LinkRequest)
            .dest_type(DestType::Single)
            .destination_hash(&dest_hash)
            .context(0x00)
            .payload(&request_payload)
            .build()
            .unwrap();
        let link_id = compute_link_id(&pkt_buf[..pkt_len]).unwrap();
        initiator_link.set_link_id(link_id);

        let responder_link = Link::from_request(link_id, &request_payload, &mut rng, 100).unwrap();

        // Sign with wrong identity
        let proof_payload = responder_link.build_proof(&wrong_identity).unwrap();

        // Should fail verification (signed with wrong_identity, verified against responder_identity)
        assert!(initiator_link
            .validate_proof(&proof_payload, &responder_identity)
            .is_err());
    }

    #[test]
    fn initiate_link_creates_pending() {
        let mut rng = rand_core::OsRng;
        let identity = Identity::from_seed(b"initiator-pending").unwrap();
        let dest_hash = [0xAAu8; TRUNCATED_HASH_LEN];

        let (link, payload) = Link::new_initiator(dest_hash, identity.ed25519_pub(), &mut rng, 100);

        assert_eq!(link.state, LinkState::Pending);
        assert_eq!(link.role, LinkRole::Initiator);
        assert_eq!(payload.len(), 67); // 64 keys + 3 signalling
        assert_eq!(&payload[..32], &link.our_x25519_pub);
    }

    #[test]
    fn link_stale_detection() {
        let mut rng = rand_core::OsRng;
        let payload = [0xBBu8; 64];
        let link_id = [0x11u8; TRUNCATED_HASH_LEN];
        let mut link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();
        link.activate(100);

        // Not stale yet
        assert!(!link.check_stale(200));
        assert_eq!(link.state, LinkState::Active);

        // Goes stale after keepalive_interval
        assert!(!link.check_stale(100 + link.keepalive_interval + 1));
        assert_eq!(link.state, LinkState::Stale);

        // Closed after stale_time
        assert!(link.check_stale(100 + link.stale_time + 1));
        assert_eq!(link.state, LinkState::Closed);
    }

    #[test]
    fn keepalive_request_response() {
        let mut rng = rand_core::OsRng;
        let payload = [0xBBu8; 64];
        let link_id = [0x11u8; TRUNCATED_HASH_LEN];
        let mut link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();
        link.activate(100);

        // Receive keepalive request (0xFF) → should respond with 0xFE
        let response = link.handle_keepalive(&[0xFF], 200);
        assert_eq!(response, Some(0xFE));

        // Receive keepalive response (0xFE) → no response needed
        let response = link.handle_keepalive(&[0xFE], 200);
        assert_eq!(response, None);
    }

    #[test]
    fn linkclose_tears_down() {
        let mut rng = rand_core::OsRng;
        let payload = [0xBBu8; 64];
        let link_id = [0x11u8; TRUNCATED_HASH_LEN];
        let mut link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();
        link.activate(100);

        // Receive LINKCLOSE with encrypted link_id
        let mut close_buf = [0u8; 256];
        let close_len = link.build_close(&mut rng, &mut close_buf).unwrap();

        // Decrypt and verify
        let mut pt = [0u8; 256];
        let pt_len = link.decrypt(&close_buf[..close_len], &mut pt).unwrap();
        assert!(link.handle_close(&pt[..pt_len]));
        assert_eq!(link.state, LinkState::Closed);
    }

    #[test]
    fn linkclose_wrong_id_rejected() {
        let mut rng = rand_core::OsRng;
        let payload = [0xBBu8; 64];
        let link_id = [0x11u8; TRUNCATED_HASH_LEN];
        let mut link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();
        link.activate(100);

        // Wrong link_id
        let wrong_id = [0xFFu8; TRUNCATED_HASH_LEN];
        assert!(!link.handle_close(&wrong_id));
        assert_eq!(link.state, LinkState::Active);
    }

    #[test]
    fn test_keepalive_on_pending_link() {
        // handle_keepalive on a non-active (Pending) link should still work.
        let mut rng = rand_core::OsRng;
        let identity = Identity::from_seed(b"keepalive-pending").unwrap();
        let dest_hash = [0xAAu8; TRUNCATED_HASH_LEN];

        let (mut link, _payload) =
            Link::new_initiator(dest_hash, identity.ed25519_pub(), &mut rng, 100);

        assert_eq!(link.state, LinkState::Pending);

        // handle_keepalive on a Pending link — should not panic and should respond
        let response = link.handle_keepalive(&[0xFF], 200);
        assert_eq!(
            response,
            Some(0xFE),
            "should respond to keepalive request even when Pending"
        );
        // touch_inbound doesn't change Pending to Active (it only revives Stale)
        assert_eq!(link.last_inbound, 200);
    }

    #[test]
    fn test_double_close() {
        // close() twice should not panic, state should be Closed.
        let mut rng = rand_core::OsRng;
        let payload = [0xBBu8; 64];
        let link_id = [0x11u8; TRUNCATED_HASH_LEN];
        let mut link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();
        link.activate(100);

        assert_eq!(link.state, LinkState::Active);

        link.close();
        assert_eq!(link.state, LinkState::Closed);

        link.close(); // second close should not panic
        assert_eq!(link.state, LinkState::Closed);
    }

    #[test]
    fn test_linkrequest_with_oversized_payload() {
        // LINKREQUEST with payload > 64 bytes (MTU signalling).
        // compute_link_id should still work — it strips the extra bytes.
        let dest_hash = [0xAAu8; TRUNCATED_HASH_LEN];
        let x25519_pub = [0xBBu8; 32];
        let ed25519_pub = [0xCCu8; 32];

        // 64 bytes standard + 4 bytes MTU signalling
        let mut payload = [0u8; 68];
        payload[..32].copy_from_slice(&x25519_pub);
        payload[32..64].copy_from_slice(&ed25519_pub);
        payload[64..68].copy_from_slice(&[0x01, 0xF4, 0x00, 0x00]); // MTU signalling

        let mut buf = [0u8; MTU];
        let n = PacketBuilder::new(&mut buf)
            .packet_type(PacketType::LinkRequest)
            .dest_type(DestType::Single)
            .destination_hash(&dest_hash)
            .context(0x00)
            .payload(&payload)
            .build()
            .unwrap();

        // compute_link_id should not fail
        let link_id = compute_link_id(&buf[..n]).unwrap();
        assert_eq!(link_id.len(), 16);

        // Also compute with standard 64-byte payload for comparison
        let mut buf2 = [0u8; MTU];
        let n2 = PacketBuilder::new(&mut buf2)
            .packet_type(PacketType::LinkRequest)
            .dest_type(DestType::Single)
            .destination_hash(&dest_hash)
            .context(0x00)
            .payload(&payload[..64])
            .build()
            .unwrap();

        let link_id2 = compute_link_id(&buf2[..n2]).unwrap();
        // The link_ids should be the same (MTU signalling is stripped)
        assert_eq!(
            link_id, link_id2,
            "link_id should be same with or without MTU signalling"
        );
    }

    // -----------------------------------------------------------------------
    // Dynamic keepalive tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_update_keepalive_low_rtt() {
        // RTT=0.05s (loopback) → keepalive ≈ 10s, stale ≈ 20s
        let mut rng = rand_core::OsRng;
        let payload = [0xBBu8; 64];
        let link_id = [0x11u8; TRUNCATED_HASH_LEN];
        let mut link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();

        link.update_keepalive(0.05);
        // 0.05 * (360/1.75) ≈ 10.28, clamped to max(5, min(360, 10.28)) = 10
        assert_eq!(link.keepalive_interval, 10);
        assert_eq!(link.stale_time, 20);
        assert!((link.rtt - 0.05).abs() < 0.001);
    }

    #[test]
    fn test_update_keepalive_high_rtt() {
        // RTT=2.0s → keepalive = 360 (clamped to max), stale = 720
        let mut rng = rand_core::OsRng;
        let payload = [0xBBu8; 64];
        let link_id = [0x11u8; TRUNCATED_HASH_LEN];
        let mut link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();

        link.update_keepalive(2.0);
        // 2.0 * (360/1.75) ≈ 411.4 → clamped to 360
        assert_eq!(link.keepalive_interval, 360);
        assert_eq!(link.stale_time, 720);
    }

    #[test]
    fn test_update_keepalive_medium_rtt() {
        // RTT=0.5s → keepalive ≈ 102, stale ≈ 205
        let mut rng = rand_core::OsRng;
        let payload = [0xBBu8; 64];
        let link_id = [0x11u8; TRUNCATED_HASH_LEN];
        let mut link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();

        link.update_keepalive(0.5);
        // 0.5 * (360/1.75) ≈ 102.86 → 102 (truncated to u64)
        assert_eq!(link.keepalive_interval, 102);
        assert_eq!(link.stale_time, 205);
    }

    #[test]
    fn test_update_keepalive_very_low_rtt() {
        // RTT=0.001s → keepalive = 5 (clamped to min)
        let mut rng = rand_core::OsRng;
        let payload = [0xBBu8; 64];
        let link_id = [0x11u8; TRUNCATED_HASH_LEN];
        let mut link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();

        link.update_keepalive(0.001);
        // 0.001 * (360/1.75) ≈ 0.206 → clamped to max(5, ...) = 5
        assert_eq!(link.keepalive_interval, 5);
        assert_eq!(link.stale_time, 10);
    }

    #[test]
    fn test_update_keepalive_zero_rtt_no_change() {
        // RTT=0.0 → should not change defaults
        let mut rng = rand_core::OsRng;
        let payload = [0xBBu8; 64];
        let link_id = [0x11u8; TRUNCATED_HASH_LEN];
        let mut link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();

        let orig_ka = link.keepalive_interval;
        let orig_stale = link.stale_time;
        link.update_keepalive(0.0);
        assert_eq!(link.keepalive_interval, orig_ka);
        assert_eq!(link.stale_time, orig_stale);
    }

    #[test]
    fn test_check_stale_with_dynamic_keepalive() {
        // After update_keepalive(0.05), stale triggers at ~10s not 360s
        let mut rng = rand_core::OsRng;
        let payload = [0xBBu8; 64];
        let link_id = [0x11u8; TRUNCATED_HASH_LEN];
        let mut link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();
        link.update_keepalive(0.05);
        link.activate(100);

        // At 109 (9s elapsed) — should still be active
        assert!(!link.check_stale(109));
        assert_eq!(link.state, LinkState::Active);

        // At 111 (11s elapsed, > keepalive_interval=10) — should be stale
        assert!(!link.check_stale(111));
        assert_eq!(link.state, LinkState::Stale);

        // At 121 (21s elapsed, > stale_time=20) — should be closed
        assert!(link.check_stale(121));
        assert_eq!(link.state, LinkState::Closed);
    }

    #[test]
    fn test_needs_keepalive_with_dynamic_keepalive() {
        // After update_keepalive(0.05), needs_keepalive triggers at ~5s not 180s
        let mut rng = rand_core::OsRng;
        let payload = [0xBBu8; 64];
        let link_id = [0x11u8; TRUNCATED_HASH_LEN];
        let mut link = Link::from_request(link_id, &payload, &mut rng, 100).unwrap();
        link.update_keepalive(0.05);
        link.activate(100);

        // keepalive_interval=10, half=5
        // At 104 (4s since last_outbound=100) — not yet
        assert!(!link.needs_keepalive(104));

        // At 106 (6s since last_outbound=100, > 5) — should need keepalive
        assert!(link.needs_keepalive(106));
    }

    #[test]
    fn link_data_decrypt_deliver() {
        // Full handshake + data exchange
        let mut rng = rand_core::OsRng;
        let responder_identity = Identity::from_seed(b"responder-data").unwrap();
        let initiator_identity = Identity::from_seed(b"initiator-data").unwrap();
        let dest_hash = [0xAAu8; TRUNCATED_HASH_LEN];

        let (mut initiator, request_payload) =
            Link::new_initiator(dest_hash, initiator_identity.ed25519_pub(), &mut rng, 100);

        let mut pkt_buf = [0u8; MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::LinkRequest)
            .dest_type(DestType::Single)
            .destination_hash(&dest_hash)
            .context(0x00)
            .payload(&request_payload)
            .build()
            .unwrap();
        let link_id = compute_link_id(&pkt_buf[..pkt_len]).unwrap();
        initiator.set_link_id(link_id);

        let responder = Link::from_request(link_id, &request_payload, &mut rng, 100).unwrap();
        let proof = responder.build_proof(&responder_identity).unwrap();
        initiator
            .validate_proof(&proof, &responder_identity)
            .unwrap();

        // Send data from initiator to responder
        let message = b"encrypted message via link";
        let mut ct = [0u8; 256];
        let ct_len = initiator.encrypt(message, &mut rng, &mut ct).unwrap();

        let mut pt = [0u8; 256];
        let pt_len = responder.decrypt(&ct[..ct_len], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len], message);
    }

    // -----------------------------------------------------------------------
    // MTU signalling tests
    // -----------------------------------------------------------------------

    #[test]
    fn signalling_bytes_encoding() {
        // Python: struct.pack("!I", (500 & 0x1FFFFF) | ((1 & 0x07) << 21))[1:]
        // = struct.pack("!I", 500 | (1 << 21))[1:] = struct.pack("!I", 0x2001F4)[1:]
        // = b'\x20\x01\xf4'
        let sb = signalling_bytes(500, 0x01);
        assert_eq!(sb, [0x20, 0x01, 0xF4]);

        // Zero MTU, zero mode
        let sb0 = signalling_bytes(0, 0);
        assert_eq!(sb0, [0x00, 0x00, 0x00]);

        // Max MTU (21 bits) = 0x1FFFFF = 2097151
        let sb_max = signalling_bytes(0x1FFFFF, 0x07);
        // (0x1FFFFF | (0x07 << 21)) = 0xFFFFFF
        assert_eq!(sb_max, [0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn initiator_payload_includes_signalling() {
        let mut rng = rand_core::OsRng;
        let identity = Identity::from_seed(b"signalling-test").unwrap();
        let dest_hash = [0xAAu8; TRUNCATED_HASH_LEN];

        let (_link, payload) =
            Link::new_initiator(dest_hash, identity.ed25519_pub(), &mut rng, 100);

        assert_eq!(payload.len(), 67);
        // Last 3 bytes should be signalling for MTU=500, mode=1
        let expected = signalling_bytes(rete_core::MTU as u32, MODE_AES_CBC);
        assert_eq!(&payload[64..67], &expected);
    }

    #[test]
    fn proof_signed_data_is_83_bytes() {
        let mut rng = rand_core::OsRng;
        let owner = Identity::from_seed(b"proof-83-test-owner").unwrap();
        let peer_id = Identity::from_seed(b"proof-83-test-peer").unwrap();
        let dest_hash = [0xAAu8; TRUNCATED_HASH_LEN];

        // Build initiator payload (67 bytes with signalling)
        let (_peer_link, request_payload) =
            Link::new_initiator(dest_hash, peer_id.ed25519_pub(), &mut rng, 100);

        let link_id = [0x22u8; TRUNCATED_HASH_LEN];
        let link = Link::from_request(link_id, &request_payload, &mut rng, 100).unwrap();

        let proof = link.build_proof(&owner).unwrap();

        // Independently verify the signature covers exactly 83 bytes
        let sig = &proof[..64];
        let resp_x25519_pub = &proof[64..96];
        let signalling = &proof[96..99];

        let mut signed_data = [0u8; 83];
        signed_data[..16].copy_from_slice(&link_id);
        signed_data[16..48].copy_from_slice(resp_x25519_pub);
        signed_data[48..80].copy_from_slice(owner.ed25519_pub());
        signed_data[80..83].copy_from_slice(signalling);

        assert!(owner.verify(&signed_data, sig).is_ok());

        // Verify truncated 80-byte data does NOT match
        assert!(owner.verify(&signed_data[..80], sig).is_err());
    }

    #[test]
    fn validate_proof_backward_compat_96_bytes() {
        // When responder returns a 96-byte proof (no signalling),
        // initiator should still validate it.
        let mut rng = rand_core::OsRng;
        let responder_identity = Identity::from_seed(b"compat-responder").unwrap();
        let initiator_identity = Identity::from_seed(b"compat-initiator").unwrap();
        let dest_hash = [0xAAu8; TRUNCATED_HASH_LEN];

        let (mut initiator_link, request_payload) =
            Link::new_initiator(dest_hash, initiator_identity.ed25519_pub(), &mut rng, 100);

        let mut pkt_buf = [0u8; MTU];
        let pkt_len = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::LinkRequest)
            .dest_type(DestType::Single)
            .destination_hash(&dest_hash)
            .context(0x00)
            .payload(&request_payload)
            .build()
            .unwrap();
        let link_id = compute_link_id(&pkt_buf[..pkt_len]).unwrap();
        initiator_link.set_link_id(link_id);

        // Simulate a Python node that accepts 67-byte request but returns 96-byte proof
        // (backward compat: no signalling in proof)
        let responder_link = Link::from_request(link_id, &request_payload, &mut rng, 100).unwrap();

        // Manually build 96-byte proof (old format, no signalling in signed data)
        let mut signed_data_80 = [0u8; 80];
        signed_data_80[..16].copy_from_slice(&link_id);
        signed_data_80[16..48].copy_from_slice(&responder_link.our_x25519_pub);
        signed_data_80[48..80].copy_from_slice(responder_identity.ed25519_pub());
        let sig = responder_identity.sign(&signed_data_80).unwrap();
        let mut proof_96 = [0u8; 96];
        proof_96[..64].copy_from_slice(&sig);
        proof_96[64..96].copy_from_slice(&responder_link.our_x25519_pub);

        // Initiator should accept 96-byte proof (signalling slice is empty → 80-byte signed_data)
        assert!(initiator_link
            .validate_proof(&proof_96, &responder_identity)
            .is_ok());
    }
}
