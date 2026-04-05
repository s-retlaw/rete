//! Lightweight tracing subscriber that writes to stderr.
//!
//! Replaces the `tracing_subscriber::fmt` + `EnvFilter` + `TestEventLayer`
//! stack with a single struct.  `enabled()` is a plain integer comparison
//! so filtered-out calls (e.g. `tracing::debug!()` at the default INFO level)
//! return in nanoseconds with no allocation.

use std::io::Write as _;

use tracing::field::{Field, Visit};
use tracing::span;
use tracing::{Event, Level, Metadata, Subscriber};

/// A minimal tracing subscriber that formats events to stderr.
pub struct ReteSubscriber {
    max_level: Level,
}

impl ReteSubscriber {
    pub fn new(max_level: Level) -> Self {
        Self { max_level }
    }
}

impl Subscriber for ReteSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        *metadata.level() <= self.max_level
    }

    fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}
    fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}
    fn enter(&self, _span: &span::Id) {}
    fn exit(&self, _span: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        let meta = event.metadata();
        let level = meta.level();

        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let msg = visitor.message.unwrap_or_default();

        let now = chrono_lite_now();
        let level_str = match *level {
            Level::ERROR => "ERROR",
            Level::WARN => " WARN",
            Level::INFO => " INFO",
            Level::DEBUG => "DEBUG",
            Level::TRACE => "TRACE",
        };

        let _ = writeln!(std::io::stderr(), "{now}  {level_str} {msg}");
    }
}

/// Extract the `message` field from a tracing event.
#[derive(Default)]
struct MessageVisitor {
    message: Option<String>,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        }
    }
}

/// Minimal timestamp without pulling in the `chrono` crate.
fn chrono_lite_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();

    // Convert to UTC date-time components.
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Simplified Gregorian calendar (good from 1970 to 2099).
    let mut y = 1970i32;
    let mut remaining = days as i32;
    loop {
        let year_days = if y % 4 == 0 { 366 } else { 365 };
        if remaining < year_days {
            break;
        }
        remaining -= year_days;
        y += 1;
    }
    let leap = y % 4 == 0;
    let month_days: [i32; 12] = [
        31,
        if leap { 29 } else { 28 },
        31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
    ];
    let mut m = 0usize;
    while m < 12 && remaining >= month_days[m] {
        remaining -= month_days[m];
        m += 1;
    }

    format!(
        "{y:04}-{:02}-{:02}T{hours:02}:{minutes:02}:{seconds:02}.{millis:03}Z",
        m + 1,
        remaining + 1,
    )
}
