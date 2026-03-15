//! rete-stack — runtime-agnostic async interface traits and shared types.
//!
//! This crate defines the `ReteInterface` trait that all physical layer
//! adapters implement, and the `NodeEvent` type used by all runtime harnesses.
//! It has no dependency on any specific async runtime —
//! Embassy, Tokio, or anything else can implement it.

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

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
    /// Periodic tick completed.
    Tick {
        /// Number of paths expired.
        expired_paths: usize,
    },
}
