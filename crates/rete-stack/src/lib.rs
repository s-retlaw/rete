//! rete-stack — runtime-agnostic async interface traits and shared types.
//!
//! This crate defines the `ReteInterface` trait that all physical layer
//! adapters implement, and the `NodeEvent` type used by all runtime harnesses.
//! It has no dependency on any specific async runtime —
//! Embassy, Tokio, or anything else can implement it.

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use rete_core::TRUNCATED_HASH_LEN;

/// Physical layer interface — implemented by all transport adapters.
///
/// `rete-embassy` and `rete-tokio` provide task harnesses that drive
/// implementors of this trait.
#[allow(async_fn_in_trait)]
pub trait ReteInterface {
    /// The error type for send/receive failures.
    type Error: core::fmt::Debug;

    /// Send a frame. Blocks (async) until the interface accepts it.
    async fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error>;

    /// Receive a frame into `buf`. Returns a slice of the received bytes.
    async fn recv<'a>(&mut self, buf: &'a mut [u8]) -> Result<&'a [u8], Self::Error>;
}

/// Proof generation strategy for incoming data packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProofStrategy {
    /// Never generate proofs automatically.
    #[default]
    ProveNone,
    /// Automatically prove all received data packets.
    ProveAll,
    /// Only prove packets for specific destinations (application decides).
    /// Reserved for future use — not yet handled by NodeCore.
    ProveApp,
}

/// Event emitted by a node's run loop.
///
/// Used by both `rete-tokio` and `rete-embassy` runtime harnesses.
#[derive(Debug)]
#[cfg(feature = "alloc")]
pub enum NodeEvent {
    /// A valid announce was received.
    AnnounceReceived {
        /// Destination hash of the announcing identity.
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        /// Identity hash of the announcer.
        identity_hash: [u8; TRUNCATED_HASH_LEN],
        /// Hop count at time of receipt.
        hops: u8,
        /// Application data from the announce (owned copy).
        app_data: Option<alloc::vec::Vec<u8>>,
    },
    /// A data packet addressed to one of our destinations was received.
    DataReceived {
        /// Destination hash the packet was addressed to.
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        /// Payload data (owned copy).
        payload: alloc::vec::Vec<u8>,
    },
    /// A proof was received for a packet we sent.
    ProofReceived {
        /// The full 32-byte packet hash the proof covers.
        packet_hash: [u8; 32],
    },
    /// A link was established.
    LinkEstablished {
        /// The link_id (16 bytes).
        link_id: [u8; TRUNCATED_HASH_LEN],
    },
    /// Decrypted data received on an active link.
    LinkData {
        /// The link_id.
        link_id: [u8; TRUNCATED_HASH_LEN],
        /// Decrypted payload data.
        data: alloc::vec::Vec<u8>,
        /// Context byte.
        context: u8,
    },
    /// A link was closed.
    LinkClosed {
        /// The link_id.
        link_id: [u8; TRUNCATED_HASH_LEN],
    },
    /// Periodic tick completed.
    Tick {
        /// Number of paths expired.
        expired_paths: usize,
        /// Number of links closed due to staleness.
        closed_links: usize,
    },
}

#[cfg(feature = "alloc")]
pub mod node_core;

#[cfg(feature = "alloc")]
pub use node_core::{
    EmbeddedNodeCore, HostedNodeCore, IngestOutcome, NodeCore, OutboundPacket, PacketRouting,
};
