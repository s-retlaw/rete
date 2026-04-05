//! Shared helpers for rete-daemon integration tests.

use rete_daemon::config::{SharedInstanceConfig, SharedInstanceType};

/// Run a test on a thread with 16 MB stack.
///
/// Debug builds may materialise large structs on the stack before moving
/// them to the heap (`Box::new(T::new())`), so integration tests that
/// construct `SharedDaemonBuilder` / `TokioNode` need extra headroom.
pub fn big_stack_test(f: fn()) {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

/// Run an async test on a thread with 16 MB stack using a single-threaded
/// Tokio runtime.  Eliminates the 8-line boilerplate pattern used in all
/// daemon integration tests.
pub fn big_stack_async_test<F>(f: impl FnOnce() -> F + Send + 'static)
where
    F: std::future::Future<Output = ()>,
{
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(f())
        })
        .unwrap()
        .join()
        .unwrap();
}

pub fn make_unix_config(name: &str) -> SharedInstanceConfig {
    SharedInstanceConfig {
        share_instance: true,
        instance_name: name.to_string(),
        shared_instance_type: SharedInstanceType::Unix,
        ..Default::default()
    }
}

pub fn make_tcp_config(port: u16) -> SharedInstanceConfig {
    make_tcp_config_with_control(port, port + 1)
}

pub fn make_tcp_config_with_control(port: u16, control_port: u16) -> SharedInstanceConfig {
    SharedInstanceConfig {
        share_instance: true,
        instance_name: "default".to_string(),
        shared_instance_type: SharedInstanceType::Tcp,
        shared_instance_port: port,
        instance_control_port: control_port,
        ..Default::default()
    }
}
