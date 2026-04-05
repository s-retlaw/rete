//! Feature-gated stdout subscriber for test protocol events.
//!
//! When the `test-output` feature is enabled, this module provides
//! [`TestEventLayer`] — a `tracing_subscriber::Layer` that listens for
//! events on the `rete::test_event` target and formats them as
//! `EVENT_NAME:field1:field2:...` lines on stdout.
//!
//! This reproduces the exact format that the Python E2E test harness
//! parses via `InteropTest.wait_for_line()`.

#[cfg(feature = "test-output")]
pub use layer::TestEventLayer;

#[cfg(feature = "test-output")]
mod layer {
    use std::fmt::Write as _;
    use tracing::field::{Field, Visit};
    use tracing::Subscriber;
    use tracing_subscriber::layer::Context;
    use tracing_subscriber::Layer;

    /// A tracing layer that formats `rete::test_event` events as
    /// colon-separated stdout lines for the E2E test harness.
    pub struct TestEventLayer;

    impl<S: Subscriber> Layer<S> for TestEventLayer {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            if event.metadata().target() != crate::TEST_EVENT_TARGET {
                return;
            }
            let mut visitor = EventVisitor::default();
            event.record(&mut visitor);
            if let Some(line) = visitor.format() {
                println!("{line}");
            }
        }
    }

    /// Collects fields from a tracing event into an ordered list.
    #[derive(Default)]
    struct EventVisitor {
        event_name: Option<String>,
        fields: Vec<String>,
    }

    impl EventVisitor {
        /// Format as `EVENT_NAME:field1:field2:...` or `EVENT_NAME` if no fields.
        fn format(&self) -> Option<String> {
            let name = self.event_name.as_ref()?;
            if self.fields.is_empty() {
                Some(name.clone())
            } else {
                let mut out = name.clone();
                for f in &self.fields {
                    out.push(':');
                    out.push_str(f);
                }
                Some(out)
            }
        }
    }

    impl Visit for EventVisitor {
        fn record_str(&mut self, field: &Field, value: &str) {
            if field.name() == "event" {
                self.event_name = Some(value.to_string());
            } else if field.name() != "message" {
                self.fields.push(value.to_string());
            }
        }

        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "event" {
                self.event_name = Some(format!("{value:?}").trim_matches('"').to_string());
            } else if field.name() != "message" {
                let s = format!("{value:?}");
                // Strip surrounding quotes from Debug-formatted strings
                let trimmed = s.trim_matches('"');
                self.fields.push(trimmed.to_string());
            }
        }

        fn record_u64(&mut self, field: &Field, value: u64) {
            if field.name() == "event" {
                self.event_name = Some(value.to_string());
            } else if field.name() != "message" {
                self.fields.push(value.to_string());
            }
        }

        fn record_i64(&mut self, field: &Field, value: i64) {
            if field.name() != "message" {
                self.fields.push(value.to_string());
            }
        }

        fn record_bool(&mut self, field: &Field, value: bool) {
            if field.name() != "message" {
                self.fields.push(value.to_string());
            }
        }
    }
}
