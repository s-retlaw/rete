//! rete-core — Reticulum Network Stack (RNS) core layer.
//!
//! Provides wire-format packet parsing/serialization and all cryptographic
//! primitives required by the Reticulum protocol.
//!
//! # Constraints
//! - `no_std` — runs on bare-metal microcontrollers
//! - No async — all operations are synchronous; the runtime calls into this
//! - `no alloc` by default; enable the `alloc` feature for owned types
//!
//! # Wire format
//! All parsing and serialization is validated against test vectors generated
//! from the Python reference. See `tests/interop/vectors.json`.
//!
//! # Protocol constants
//! - **MTU:** 500 bytes — must not change for interoperability
//! - **Truncated hash:** 16 bytes (128-bit)
//! - **Name hash:** 10 bytes (80-bit)

#![no_std]
#![deny(missing_docs)]
#![deny(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod error;
pub mod hdlc;
pub mod identity;
pub mod ifac;
pub mod packet;
pub mod token;

pub use error::Error;
pub use identity::{destination_hash, expand_name, generate_ratchet, ratchet_id, Identity};
pub use ifac::{IfacKey, DEFAULT_IFAC_SIZE, IFAC_FLAG, IFAC_SALT};
pub use packet::{
    DestType, HeaderType, Packet, PacketBuilder, PacketType, CONTEXT_CHANNEL, CONTEXT_KEEPALIVE,
    CONTEXT_LINKCLOSE, CONTEXT_LINKIDENTIFY, CONTEXT_LINKPROOF, CONTEXT_LRPROOF, CONTEXT_LRRTT,
    CONTEXT_CACHE_REQUEST, CONTEXT_COMMAND, CONTEXT_COMMAND_STATUS, CONTEXT_NONE,
    CONTEXT_PATH_RESPONSE, CONTEXT_REQUEST, CONTEXT_RESOURCE, CONTEXT_RESOURCE_ADV,
    CONTEXT_RESOURCE_HMU, CONTEXT_RESOURCE_ICL, CONTEXT_RESOURCE_PRF, CONTEXT_RESOURCE_RCL,
    CONTEXT_RESOURCE_REQ, CONTEXT_RESPONSE, TRANSPORT_TYPE_BROADCAST, TRANSPORT_TYPE_TRANSPORT,
};
pub use token::Token;

// ---------------------------------------------------------------------------
// Protocol constants — must match Python reference exactly
// ---------------------------------------------------------------------------

/// Maximum transmission unit. All packets must fit within 500 bytes.
/// Changing this breaks interoperability with all other Reticulum nodes.
pub const MTU: usize = 500;

/// Truncated hash length used for identity and destination addressing (bytes).
/// Corresponds to `TRUNCATED_HASHLENGTH // 8` in the Python reference.
pub const TRUNCATED_HASH_LEN: usize = 16;

/// Destination name hash length (bytes).
/// Corresponds to `NAME_HASH_LENGTH // 8` in the Python reference.
pub const NAME_HASH_LEN: usize = 10;

/// Maximum data unit for unencrypted (PLAIN) packets.
pub const PLAIN_MDU: usize = 464;

/// Maximum data unit for encrypted (SINGLE) packets.
pub const ENCRYPTED_MDU: usize = 383;

/// Wire overhead for HEADER_1: flags(1) + hops(1) + dest_hash(16) + context(1).
pub const HEADER_1_OVERHEAD: usize = 1 + 1 + TRUNCATED_HASH_LEN + 1;

/// Wire overhead for HEADER_2: adds transport_id(16) over HEADER_1.
pub const HEADER_2_OVERHEAD: usize = HEADER_1_OVERHEAD + TRUNCATED_HASH_LEN;
