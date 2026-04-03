//! Trait-based hooks for NodeCore extensibility.
//!
//! Hooks are stored as `Box<dyn Trait>` trait objects, matching the
//! [`RatchetStore`](super::RatchetStore) pattern, allowing implementations
//! to capture state (database connections, counters, config, etc.).

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use rete_core::TRUNCATED_HASH_LEN;

use super::RequestContext;

/// Application-level hooks for compression, proof policy, and diagnostics.
///
/// Stored as `Option<Box<dyn NodeHooks>>` on [`NodeCore`](super::NodeCore).
/// All methods have default no-op implementations so callers only override
/// what they need.
///
/// # Example
///
/// ```ignore
/// struct AppHooks { log_enabled: bool }
///
/// impl NodeHooks for AppHooks {
///     fn log_packet(&self, raw: &[u8], direction: &str, iface: u8) {
///         if self.log_enabled {
///             println!("[{direction}] iface={iface} len={}", raw.len());
///         }
///     }
/// }
///
/// core.set_hooks(Box::new(AppHooks { log_enabled: true }));
/// ```
pub trait NodeHooks: Send {
    /// Compress data for outbound resources/responses.
    /// Return `None` to skip compression.
    fn compress(&self, _data: &[u8]) -> Option<Vec<u8>> {
        None
    }

    /// Decompress data from inbound resources.
    /// Return `None` on decompression failure.
    fn decompress(&self, _data: &[u8]) -> Option<Vec<u8>> {
        None
    }

    /// Decide whether to generate a proof for a received packet (ProveApp strategy).
    ///
    /// Arguments: destination hash, packet hash, decrypted payload.
    /// Return `true` to generate and send proof, `false` to skip.
    fn prove_app(
        &self,
        _dest_hash: &[u8; TRUNCATED_HASH_LEN],
        _packet_hash: &[u8; 32],
        _payload: &[u8],
    ) -> bool {
        false
    }

    /// Log an inbound packet for diagnostics.
    fn log_packet(&self, _raw: &[u8], _direction: &str, _iface: u8) {}
}

/// Callback trait for per-path request handlers on a destination.
///
/// Stored as `Box<dyn RequestCallback>` in [`RequestHandler`](super::RequestHandler).
///
/// Use [`handler_fn`] to create a `Box<dyn RequestCallback>` from a closure.
pub trait RequestCallback: Send {
    /// Handle an inbound request.
    ///
    /// Return `Some(response_data)` to send a response, or `None` for no response.
    fn handle(&self, ctx: &RequestContext<'_>, data: &[u8]) -> Option<Vec<u8>>;
}

/// Wrapper that implements [`RequestCallback`] for closures.
struct ClosureHandler<F>(F);

impl<F> RequestCallback for ClosureHandler<F>
where
    F: Fn(&RequestContext<'_>, &[u8]) -> Option<Vec<u8>> + Send,
{
    fn handle(&self, ctx: &RequestContext<'_>, data: &[u8]) -> Option<Vec<u8>> {
        (self.0)(ctx, data)
    }
}

/// Create a boxed [`RequestCallback`] from a closure.
///
/// This helper handles the higher-ranked lifetime coercion that
/// `Box::new(|ctx, data| ...)` cannot always infer on its own.
///
/// ```ignore
/// use rete_stack::{RequestHandler, RequestPolicy, ResponseCompressionPolicy, handler_fn};
///
/// let counter = Arc::new(AtomicUsize::new(0));
/// let c = counter.clone();
/// RequestHandler {
///     path: "/echo".into(),
///     handler: handler_fn(move |_ctx, data| {
///         c.fetch_add(1, Ordering::SeqCst);
///         Some(data.to_vec())
///     }),
///     policy: RequestPolicy::AllowAll,
///     compression_policy: ResponseCompressionPolicy::Default,
/// };
/// ```
pub fn handler_fn(
    f: impl Fn(&RequestContext<'_>, &[u8]) -> Option<Vec<u8>> + Send + 'static,
) -> Box<dyn RequestCallback> {
    Box::new(ClosureHandler(f))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec;
    use core::sync::atomic::{AtomicUsize, Ordering};

    // --- NodeHooks: state capture ---

    struct LogCapture {
        count: AtomicUsize,
    }

    impl NodeHooks for LogCapture {
        fn log_packet(&self, _raw: &[u8], _direction: &str, _iface: u8) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn node_hooks_captures_state() {
        let hooks = LogCapture {
            count: AtomicUsize::new(0),
        };
        hooks.log_packet(&[0xAA, 0xBB], "IN", 0);
        hooks.log_packet(&[0xCC], "IN", 1);

        assert_eq!(hooks.count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn node_hooks_default_methods_are_noop() {
        struct Empty;
        impl NodeHooks for Empty {}

        let h = Empty;
        assert_eq!(h.compress(b"data"), None);
        assert_eq!(h.decompress(b"data"), None);
        assert!(!h.prove_app(&[0; 16], &[0; 32], b"payload"));
        h.log_packet(b"raw", "IN", 0); // should not panic
    }

    #[test]
    fn node_hooks_as_boxed_trait_object() {
        let counter = Arc::new(AtomicUsize::new(0));

        struct ArcCapture(Arc<AtomicUsize>);
        impl NodeHooks for ArcCapture {
            fn log_packet(&self, _raw: &[u8], _direction: &str, _iface: u8) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let hooks: Box<dyn NodeHooks> = Box::new(ArcCapture(counter.clone()));
        hooks.log_packet(b"test", "IN", 0);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    // --- RequestCallback: state capture via handler_fn ---

    fn dummy_ctx() -> RequestContext<'static> {
        RequestContext {
            destination_hash: [0; 16],
            path: "/test",
            path_hash: [0; 16],
            link_id: [0; 16],
            request_id: [0; 16],
            requested_at: 0.0,
            remote_identity: None,
        }
    }

    #[test]
    fn request_callback_captures_state() {
        let counter = alloc::sync::Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let cb: Box<dyn RequestCallback> = handler_fn(move |_ctx, data| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
            Some(data.to_vec())
        });

        let ctx = dummy_ctx();

        let result = cb.handle(&ctx, b"hello");
        assert_eq!(result, Some(b"hello".to_vec()));
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        cb.handle(&ctx, b"world");
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn request_callback_handler_fn_works() {
        let cb: Box<dyn RequestCallback> = handler_fn(|_ctx, data| Some(vec![data.len() as u8]));
        let ctx = dummy_ctx();

        assert_eq!(cb.handle(&ctx, b"abc"), Some(vec![3]));
    }
}
