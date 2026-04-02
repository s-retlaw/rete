//! rete-transport — Reticulum routing, path tables, announce handling, and links.
//!
//! Fully synchronous — the async runtime drives it by calling `tick()`
//! periodically and passing inbound packets to `ingest()`.
//!
//! # Memory model
//! All collections are const-generic bounded for bare-metal targets.

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod announce;
pub mod buffer;
pub mod channel;
pub mod dedup;
pub mod link;
pub mod path;
pub mod receipt;
pub mod request;
pub mod resource;
pub mod snapshot;
pub mod storage;
#[cfg(feature = "hosted")]
pub mod storage_std;
pub mod transport;

pub use announce::{
    validate_announce, AnnounceError, AnnounceInfo, PendingAnnounce, RATCHET_KEY_LEN,
};
pub use buffer::{StreamBuffer, StreamDataMessage};
pub use channel::{
    Channel, ChannelEnvelope, DEFAULT_WINDOW, ENVELOPE_HEADER_SIZE, MSG_TYPE_STREAM,
};
pub use dedup::DedupWindow;
pub use link::{
    compute_establishment_timeout, compute_keepalive, compute_link_id, compute_link_mdu,
    compute_resource_sdu, compute_traffic_timeout_ms, signalling_bytes, Link, LinkRole, LinkState,
    TeardownReason, LINK_MDU, LINK_MTU_SIZE,
};
pub use path::{InterfaceMode, Path, PATH_EXPIRES_AP, PATH_EXPIRES_ROAMING};
pub use receipt::{PacketReceipt, ReceiptStatus, ReceiptTable};
pub use request::{
    build_request, build_response, parse_request, parse_response, path_hash, request_id,
    RequestError, PATH_HASH_LEN, REQUEST_ID_LEN,
};
pub use resource::{
    hashmap_max_len, Resource, ResourceError, ResourceFlags, ResourceState,
    HASHMAP_MAX_LEN_DEFAULT,
};
pub use snapshot::{IdentityEntry, PathEntry, Snapshot, SnapshotDetail, SnapshotStore};
pub use storage::{
    HeaplessStorage, StorageDeque, StorageMap, TransportStorage,
};
#[cfg(feature = "hosted")]
pub use storage_std::StdStorage;
pub use transport::{
    AnnounceRateEntry, IngestResult, ReverseEntry, SendError, TickResult, Transport,
    TransportStats, PATH_REQUEST_DEST, RECEIPT_TIMEOUT, REVERSE_TIMEOUT,
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

/// Transport for embedded targets (conservative memory, fixed-size).
pub type EmbeddedTransport = Transport<
    HeaplessStorage<
        EMBEDDED_MAX_PATHS,
        EMBEDDED_MAX_ANNOUNCES,
        EMBEDDED_DEDUP_WINDOW,
        EMBEDDED_MAX_LINKS,
    >,
>;

/// Transport for hosted/gateway targets (heap-allocated, growable).
#[cfg(feature = "hosted")]
pub type HostedTransport = Transport<storage_std::StdStorage>;

/// Default announce interval in seconds.
pub const ANNOUNCE_INTERVAL_SECS: u64 = 300;

/// Tick interval in seconds (path expiry, announce retransmission, channel retransmit).
pub const TICK_INTERVAL_SECS: u64 = 5;
