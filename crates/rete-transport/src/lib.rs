//! rete-transport — Reticulum routing, path tables, and announce handling.
//!
//! Fully synchronous — the async runtime drives it by calling `tick()`
//! periodically and passing inbound packets to `ingest()`.
//!
//! # Memory model
//! All collections are const-generic bounded for bare-metal targets.

#![no_std]
extern crate alloc;

pub mod announce;
pub mod dedup;
pub mod path;
pub mod transport;

pub use announce::{validate_announce, AnnounceError, AnnounceInfo, PendingAnnounce};
pub use dedup::DedupWindow;
pub use path::Path;
pub use transport::{IngestResult, TickResult, Transport};

/// Transport for embedded targets (conservative memory).
pub type EmbeddedTransport = Transport<64, 16, 128>;

/// Transport for hosted/gateway targets.
pub type HostedTransport = Transport<1024, 256, 4096>;

/// Default announce interval in seconds.
pub const ANNOUNCE_INTERVAL_SECS: u64 = 300;

/// Tick interval in seconds (path expiry, announce retransmission).
pub const TICK_INTERVAL_SECS: u64 = 60;
