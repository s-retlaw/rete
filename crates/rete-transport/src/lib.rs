//! rete-transport — Reticulum routing, path tables, announce handling, and links.
//!
//! Fully synchronous — the async runtime drives it by calling `tick()`
//! periodically and passing inbound packets to `ingest()`.
//!
//! # Memory model
//! All collections are const-generic bounded for bare-metal targets.

#![no_std]
extern crate alloc;

pub mod announce;
pub mod buffer;
pub mod channel;
pub mod dedup;
pub mod link;
pub mod path;
pub mod receipt;
pub mod transport;

pub use announce::{validate_announce, AnnounceError, AnnounceInfo, PendingAnnounce};
pub use buffer::{StreamBuffer, StreamDataMessage};
pub use channel::{Channel, ChannelEnvelope, DEFAULT_WINDOW, ENVELOPE_HEADER_SIZE, MSG_TYPE_STREAM};
pub use dedup::DedupWindow;
pub use link::{compute_link_id, Link, LinkRole, LinkState, TeardownReason};
pub use path::Path;
pub use receipt::{PacketReceipt, ReceiptStatus, ReceiptTable};
pub use transport::{
    IngestResult, ReverseEntry, TickResult, Transport, PATH_REQUEST_DEST, REVERSE_TIMEOUT,
};

/// Transport for embedded targets (conservative memory).
/// Generics: MAX_PATHS=64, MAX_ANNOUNCES=16, DEDUP_WINDOW=128, MAX_LINKS=4
pub type EmbeddedTransport = Transport<64, 16, 128, 4>;

/// Transport for hosted/gateway targets.
/// Generics: MAX_PATHS=1024, MAX_ANNOUNCES=256, DEDUP_WINDOW=4096, MAX_LINKS=32
pub type HostedTransport = Transport<1024, 256, 4096, 32>;

/// Default announce interval in seconds.
pub const ANNOUNCE_INTERVAL_SECS: u64 = 300;

/// Tick interval in seconds (path expiry, announce retransmission).
pub const TICK_INTERVAL_SECS: u64 = 60;
