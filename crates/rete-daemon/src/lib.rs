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
pub mod test_subscriber;

/// Target string for structured test protocol events.
///
/// Tracing events emitted with this target are captured by
/// [`test_subscriber::TestEventLayer`] and formatted as `EVENT:field1:field2`
/// lines on stdout for the Python E2E test harness.
pub const TEST_EVENT_TARGET: &str = "rete::test_event";

/// Initialize the tracing subscriber for hosted binaries.
///
/// Installs a stderr formatter (no ANSI, filterable via `RUST_LOG`) and,
/// when the `test-output` feature is enabled, adds the [`TestEventLayer`]
/// that writes structured test protocol events to stdout.
pub fn init_tracing() {
    use tracing_subscriber::prelude::*;
    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_ansi(false);
    #[cfg(feature = "test-output")]
    let subscriber = tracing_subscriber::registry()
        .with(
            stderr_layer.with_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "rete=info".parse().unwrap()),
            ),
        )
        .with(test_subscriber::TestEventLayer);
    #[cfg(not(feature = "test-output"))]
    let subscriber = tracing_subscriber::registry().with(
        stderr_layer.with_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rete=info".parse().unwrap()),
        ),
    );
    tracing::subscriber::set_global_default(subscriber).ok();
}
