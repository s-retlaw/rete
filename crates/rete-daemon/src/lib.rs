//! rete-daemon — Reusable hosted-node building blocks.
//!
//! Extracts configuration loading, identity persistence, compression,
//! command parsing, HTTP monitoring, event formatting, and file-backed
//! message storage from the `rete-linux` example into a reusable library.
//!
//! This crate is **hosted-only**: it requires `std`, `tokio`, and `serde`.
//! For embedded nodes use `rete-core` and `rete-transport` directly.

pub mod command;
pub mod compression;
pub mod config;
pub mod control;
pub mod daemon;
pub mod event;
pub mod file_store;
pub mod identity;
pub mod monitoring;
pub mod pickle;
pub mod session;
