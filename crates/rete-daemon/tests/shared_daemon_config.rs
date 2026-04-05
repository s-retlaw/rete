//! Integration tests for SharedDaemon config validation.
//!
//! Covers parity row S2-GEN-OPER-001.

mod common;

use common::{big_stack_test, make_tcp_config_with_control};
use rete_daemon::config::SharedInstanceConfig;
use rete_daemon::daemon::{DaemonError, SharedDaemonBuilder};

/// Assert that a config is rejected at startup with an error containing `substring`.
async fn expect_config_error(config: SharedInstanceConfig, substring: &str) {
    let data_dir = tempfile::tempdir().unwrap();
    let result = SharedDaemonBuilder::new(config)
        .data_dir(data_dir.path())
        .start()
        .await;
    match result {
        Err(DaemonError::Config(msg)) => {
            assert!(msg.contains(substring), "expected '{substring}' in: {msg}");
        }
        Err(other) => panic!("expected Config error, got: {other}"),
        Ok(_) => panic!("expected Config error, got Ok"),
    }
}

#[test]
fn test_config_validation_rejects_share_instance_false() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let config = SharedInstanceConfig {
                    share_instance: false,
                    ..Default::default()
                };
                expect_config_error(config, "share_instance").await;
            });
    });
}

#[test]
fn test_config_validation_rejects_empty_instance_name() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let config = SharedInstanceConfig {
                    instance_name: "".into(),
                    ..Default::default()
                };
                expect_config_error(config, "instance_name").await;
            });
    });
}

#[test]
fn test_config_validation_rejects_tcp_same_ports() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let config = make_tcp_config_with_control(5000, 5000);
                expect_config_error(config, "must differ").await;
            });
    });
}

#[test]
fn test_config_validation_rejects_tcp_port_zero() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let config = make_tcp_config_with_control(0, 37429);
                expect_config_error(config, "shared_instance_port").await;
            });
    });
}
