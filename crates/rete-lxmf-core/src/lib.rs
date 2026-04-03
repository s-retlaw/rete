//! rete-lxmf-core — no_std LXMF core types for Reticulum.
//!
//! Provides message creation, packing, unpacking, signing, verification,
//! and proof-of-work stamps. Suitable for WASM and embedded targets.

#![no_std]
extern crate alloc;

pub mod message;
pub mod stamp;

pub use message::{
    DeliveryMethod, LXMessage, LXMessageState, FIELD_AUDIO, FIELD_COMMANDS, FIELD_EMBEDDED_LXMS,
    FIELD_FILE_ATTACHMENTS, FIELD_IMAGE, FIELD_TELEMETRY, FIELD_THREAD, FIELD_TICKET,
};
