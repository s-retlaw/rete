//! rete-lxmf — LXMF (Lightweight Extensible Message Format) for Reticulum.
//!
//! Provides message creation, packing, unpacking, signing, and verification
//! for the LXMF protocol used by Sideband, NomadNet, and MeshChat.
//!
//! With the `router` feature (default), also provides [`LxmfRouter`] for
//! wiring LXMF delivery through [`rete_stack::NodeCore`].
//!
//! # Portability
//!
//! This crate requires `std` (via `sha2/std`, `bzip2`). For `no_std` message
//! encoding/decoding, use `rete-lxmf-core` directly.

// Core types re-exported from rete-lxmf-core (no_std compatible).
pub use rete_lxmf_core::message;
pub use rete_lxmf_core::stamp;

pub use rete_lxmf_core::message::{
    DeliveryMethod, LXMessage, LXMessageState, LxmfMessageError, FIELD_AUDIO, FIELD_COMMANDS,
    FIELD_EMBEDDED_LXMS, FIELD_FILE_ATTACHMENTS, FIELD_IMAGE, FIELD_TELEMETRY, FIELD_THREAD,
    FIELD_TICKET,
};

#[cfg(feature = "router")]
pub mod peer;

#[cfg(feature = "router")]
pub mod propagation;

#[cfg(feature = "router")]
pub mod router;

#[cfg(feature = "router")]
pub use propagation::{InMemoryMessageStore, MessageStore, PropagationNode};

#[cfg(feature = "router")]
pub use router::{DefaultLxmfRouter, LxmfEvent, LxmfRouter, PropagationRetrievalResult};
