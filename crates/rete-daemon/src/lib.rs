//! rete-daemon — Reusable hosted-node building blocks.
//!
//! Configuration loading, identity persistence, compression, command parsing,
//! HTTP monitoring, event formatting, shared-instance daemon, and file-backed
//! message storage for the `rete` daemon binary.
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
pub mod rete_event;
pub mod session;
pub mod subscriber;

/// Initialize the tracing subscriber for hosted binaries.
///
/// Installs a lightweight stderr subscriber filtered by `RUST_LOG` env var
/// (default: `info`).  Test protocol output goes directly to stdout via
/// [`rete_event::ReteEvent::emit`], not through the subscriber.
pub fn init_tracing() {
    let level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|s| match s.to_lowercase().as_str() {
            "trace" => Some(tracing::Level::TRACE),
            "debug" => Some(tracing::Level::DEBUG),
            "info" => Some(tracing::Level::INFO),
            "warn" | "warning" => Some(tracing::Level::WARN),
            "error" => Some(tracing::Level::ERROR),
            _ => None,
        })
        .unwrap_or(tracing::Level::INFO);
    tracing::subscriber::set_global_default(subscriber::ReteSubscriber::new(level)).ok();
}
