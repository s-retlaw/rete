//! rete-lxmf — LXMF (Lightweight Extensible Message Format) for Reticulum.
//!
//! Provides message creation, packing, unpacking, signing, and verification
//! for the LXMF protocol used by Sideband, NomadNet, and MeshChat.

pub mod message;

pub use message::{
    DeliveryMethod, LXMessage, LXMessageState,
    FIELD_AUDIO, FIELD_COMMANDS, FIELD_EMBEDDED_LXMS, FIELD_FILE_ATTACHMENTS,
    FIELD_IMAGE, FIELD_TELEMETRY, FIELD_THREAD,
};
