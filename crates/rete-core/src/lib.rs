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
pub mod packet;

pub use error::Error;
pub use identity::{Identity, destination_hash, expand_name};
pub use packet::{Packet, PacketBuilder, PacketType, HeaderType, DestType};

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
