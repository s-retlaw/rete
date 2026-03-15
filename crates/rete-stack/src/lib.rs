//! rete-stack — runtime-agnostic async interface traits.
//!
//! This crate defines the `ReteInterface` trait that all physical layer
//! adapters implement. It has no dependency on any specific async runtime —
//! Embassy, Tokio, or anything else can implement it.

#![no_std]

/// Physical layer interface — implemented by all transport adapters.
///
/// `rete-embassy` and `rete-tokio` provide task harnesses that drive
/// implementors of this trait.
pub trait ReteInterface {
    /// The error type for send/receive failures.
    type Error: core::fmt::Debug;

    /// Send a frame. Blocks (async) until the interface accepts it.
    async fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error>;

    /// Receive a frame into `buf`. Returns a slice of the received bytes.
    async fn recv<'a>(&mut self, buf: &'a mut [u8]) -> Result<&'a [u8], Self::Error>;
}
