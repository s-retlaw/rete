//! Integration tests for SharedDaemon boot, exclusivity, and shutdown.

use rete_daemon::config::{SharedInstanceConfig, SharedInstanceType};
use rete_daemon::daemon::{DaemonError, SharedDaemonBuilder};

use rete_tokio::local::LocalClient;

use tokio::time::{timeout, Duration};

/// Run an async test on a thread with 16 MB stack.
///
/// In debug builds, `Box::new(T::new())` may materialise the struct on the
/// stack before moving it to the heap, so we need a generous stack.
fn big_stack_test(f: fn()) {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

fn make_unix_config(name: &str) -> SharedInstanceConfig {
    SharedInstanceConfig {
        share_instance: true,
        instance_name: name.to_string(),
        shared_instance_type: SharedInstanceType::Unix,
        ..Default::default()
    }
}

fn make_tcp_config(port: u16) -> SharedInstanceConfig {
    SharedInstanceConfig {
        share_instance: true,
        instance_name: "default".to_string(),
        shared_instance_type: SharedInstanceType::Tcp,
        shared_instance_port: port,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Test 1: daemon starts from shared config and accepts a client
// ---------------------------------------------------------------------------

#[test]
fn test_daemon_starts_from_shared_config() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let name = format!("test_boot_{}", std::process::id());
                let data_dir = tempfile::tempdir().unwrap();

                let config = make_unix_config(&name);
                let (daemon, run_future) = SharedDaemonBuilder::new(config)
                    .data_dir(data_dir.path())
                    .start()
                    .await
                    .expect("daemon must start");

                // Pin the future so we can select! on it.
                tokio::pin!(run_future);

                // Let the daemon event loop run briefly.
                tokio::time::sleep(Duration::from_millis(100)).await;

                // Verify a client can connect to the daemon's socket.
                let client = LocalClient::connect(&name).await;
                assert!(client.is_ok(), "client must connect to daemon");
                drop(client);

                // Request shutdown and wait for the future to complete.
                daemon.shutdown().await;
                let result = timeout(Duration::from_secs(5), &mut run_future).await;
                assert!(result.is_ok(), "daemon must shut down within 5s");
            });
    });
}

// ---------------------------------------------------------------------------
// Test 2: duplicate daemon bind fails (Unix + TCP)
// ---------------------------------------------------------------------------

#[test]
fn test_duplicate_daemon_bind_fails_unix() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let name = format!("test_dup_{}", std::process::id());
                let data_dir1 = tempfile::tempdir().unwrap();
                let data_dir2 = tempfile::tempdir().unwrap();

                let config1 = make_unix_config(&name);
                let (daemon1, run1) = SharedDaemonBuilder::new(config1)
                    .data_dir(data_dir1.path())
                    .start()
                    .await
                    .expect("first daemon must start");

                tokio::pin!(run1);

                // Second daemon with same name must fail (bind happens in start()).
                let config2 = make_unix_config(&name);
                let result = SharedDaemonBuilder::new(config2)
                    .data_dir(data_dir2.path())
                    .start()
                    .await;

                match result {
                    Err(DaemonError::Bind(_)) => {} // expected
                    Err(other) => panic!("expected Bind error, got: {other}"),
                    Ok(_) => panic!("second daemon must fail to start"),
                }

                daemon1.shutdown().await;
                let _ = timeout(Duration::from_secs(5), &mut run1).await;
            });
    });
}

#[test]
fn test_duplicate_daemon_bind_fails_tcp() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let data_dir1 = tempfile::tempdir().unwrap();
                let data_dir2 = tempfile::tempdir().unwrap();

                // Use port 0 to get an OS-assigned port, then try to rebind.
                // Actually, with port 0 each bind gets a different port, so we
                // need a fixed port. Use a high ephemeral port.
                let port = 48900 + (std::process::id() % 100) as u16;

                let config1 = make_tcp_config(port);
                let (daemon1, run1) = SharedDaemonBuilder::new(config1)
                    .data_dir(data_dir1.path())
                    .start()
                    .await
                    .expect("first TCP daemon must start");

                tokio::pin!(run1);

                let config2 = make_tcp_config(port);
                let result = SharedDaemonBuilder::new(config2)
                    .data_dir(data_dir2.path())
                    .start()
                    .await;

                match result {
                    Err(DaemonError::Bind(_)) => {} // expected
                    Err(other) => panic!("expected Bind error, got: {other}"),
                    Ok(_) => panic!("second TCP daemon must fail to start"),
                }

                daemon1.shutdown().await;
                let _ = timeout(Duration::from_secs(5), &mut run1).await;
            });
    });
}

// ---------------------------------------------------------------------------
// Test 3: clean shutdown persists identity and releases socket
// ---------------------------------------------------------------------------

#[test]
fn test_daemon_shutdown_clean() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let name = format!("test_shut_{}", std::process::id());
                let data_dir = tempfile::tempdir().unwrap();

                let config = make_unix_config(&name);
                let (daemon, run_future) = SharedDaemonBuilder::new(config)
                    .data_dir(data_dir.path())
                    .start()
                    .await
                    .expect("daemon must start");

                tokio::pin!(run_future);
                tokio::time::sleep(Duration::from_millis(100)).await;

                // Request shutdown.
                daemon.shutdown().await;

                // Must complete within timeout.
                let result = timeout(Duration::from_secs(5), &mut run_future).await;
                assert!(result.is_ok(), "daemon must shut down within 5s");

                // Identity file should have been created.
                assert!(
                    data_dir.path().join("identity").exists(),
                    "identity file must exist after daemon ran"
                );

                // Socket should be released — another daemon can bind the same name.
                let data_dir2 = tempfile::tempdir().unwrap();
                let config2 = make_unix_config(&name);
                let (daemon2, run2) = SharedDaemonBuilder::new(config2)
                    .data_dir(data_dir2.path())
                    .start()
                    .await
                    .expect("must rebind after shutdown");

                tokio::pin!(run2);
                daemon2.shutdown().await;
                let _ = timeout(Duration::from_secs(5), &mut run2).await;
            });
    });
}
