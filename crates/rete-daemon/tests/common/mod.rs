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

pub fn make_unix_config(name: &str) -> SharedInstanceConfig {
    SharedInstanceConfig {
        share_instance: true,
        instance_name: name.to_string(),
        shared_instance_type: SharedInstanceType::Unix,
        ..Default::default()
    }
}

pub fn make_tcp_config(port: u16) -> SharedInstanceConfig {
    SharedInstanceConfig {
        share_instance: true,
        instance_name: "default".to_string(),
        shared_instance_type: SharedInstanceType::Tcp,
        shared_instance_port: port,
        ..Default::default()
    }
}
