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
pub mod resource;
pub mod transport;

pub use announce::{validate_announce, AnnounceError, AnnounceInfo, PendingAnnounce};
pub use buffer::{StreamBuffer, StreamDataMessage};
pub use channel::{
    Channel, ChannelEnvelope, DEFAULT_WINDOW, ENVELOPE_HEADER_SIZE, MSG_TYPE_STREAM,
};
pub use dedup::DedupWindow;
pub use link::{compute_link_id, Link, LinkRole, LinkState, TeardownReason, LINK_MDU};
pub use path::Path;
pub use receipt::{PacketReceipt, ReceiptStatus, ReceiptTable};
pub use resource::{Resource, ResourceFlags, ResourceState};
pub use transport::{
    IngestResult, ReverseEntry, TickResult, Transport, PATH_REQUEST_DEST, RECEIPT_TIMEOUT,
    REVERSE_TIMEOUT,
};

// ---------------------------------------------------------------------------
// Transport sizing constants — shared by Transport and NodeCore type aliases
// ---------------------------------------------------------------------------

/// Embedded: max learned destination paths.
pub const EMBEDDED_MAX_PATHS: usize = 64;
/// Embedded: max pending outbound announces.
pub const EMBEDDED_MAX_ANNOUNCES: usize = 16;
/// Embedded: duplicate-detection window size.
pub const EMBEDDED_DEDUP_WINDOW: usize = 128;
/// Embedded: max concurrent link sessions.
pub const EMBEDDED_MAX_LINKS: usize = 4;

/// Hosted: max learned destination paths.
pub const HOSTED_MAX_PATHS: usize = 1024;
/// Hosted: max pending outbound announces.
pub const HOSTED_MAX_ANNOUNCES: usize = 256;
/// Hosted: duplicate-detection window size.
pub const HOSTED_DEDUP_WINDOW: usize = 4096;
/// Hosted: max concurrent link sessions.
pub const HOSTED_MAX_LINKS: usize = 32;

/// Transport for embedded targets (conservative memory).
pub type EmbeddedTransport = Transport<
    EMBEDDED_MAX_PATHS,
    EMBEDDED_MAX_ANNOUNCES,
    EMBEDDED_DEDUP_WINDOW,
    EMBEDDED_MAX_LINKS,
>;

/// Transport for hosted/gateway targets.
pub type HostedTransport =
    Transport<HOSTED_MAX_PATHS, HOSTED_MAX_ANNOUNCES, HOSTED_DEDUP_WINDOW, HOSTED_MAX_LINKS>;

/// Default announce interval in seconds.
pub const ANNOUNCE_INTERVAL_SECS: u64 = 300;

/// Tick interval in seconds (path expiry, announce retransmission, channel retransmit).
pub const TICK_INTERVAL_SECS: u64 = 5;
