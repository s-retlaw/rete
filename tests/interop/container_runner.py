#!/usr/bin/env python3
"""Unified container runner for all rete E2E interop tests.

Each test runs in its own Docker container with a dedicated network
namespace, eliminating port conflicts entirely.  Rust binaries and test
scripts are bind-mounted into the container at runtime.

Usage:
    # Single original interop test
    uv run python container_runner.py live_interop.py

    # Single shared-mode test
    uv run python container_runner.py shared_mode/unix/announce.py

    # All original interop tests
    uv run python container_runner.py --suite original

    # All shared-mode tests
    uv run python container_runner.py --suite shared

    # Every test
    uv run python container_runner.py --all

    # Parallel execution (4 containers at once)
    uv run python container_runner.py --all --parallel 4
"""

import argparse
import concurrent.futures
import os
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
_DOCKERFILE = os.path.join(_REPO_ROOT, "tests", "docker", "e2e-unified.Dockerfile")
_DEFAULT_RETE_LINUX = os.path.join(_REPO_ROOT, "target", "debug", "rete-linux")
_DEFAULT_RETE_SHARED = os.path.join(_REPO_ROOT, "target", "debug", "rete-shared")

IMAGE_TAG = "rete-e2e-unified:latest"

# ---------------------------------------------------------------------------
# Test discovery
# ---------------------------------------------------------------------------

# Original interop tests that can run inside a container.
# Excluded: docker_* (manage their own containers), esp32* (need hardware),
#           py_*_baseline* (no Rust binary), local_ipc_interop (tests host
#           Unix sockets), serial_interop (needs /dev/ttyUSB0).
ORIGINAL_TESTS = [
    "live_interop.py",
    "link_interop.py",
    "channel_interop.py",
    "resource_interop.py",
    "relay_interop.py",
    "transport_relay_interop.py",
    "path_request_interop.py",
    "proof_routing_interop.py",
    "ifac_interop.py",
    "robustness_interop.py",
    "link_initiate_interop.py",
    "link_initiate_relay_interop.py",
    "link_rust_relay_interop.py",
    "link_3node_relay_interop.py",
    "link_relay_interop.py",
    "link_burst_interop.py",
    "link_teardown_race_interop.py",
    "link_stale_interop.py",
    "link_cycle_interop.py",
    "concurrent_links_interop.py",
    "keepalive_interop.py",
    "channel_relay_interop.py",
    "channel_ordering_interop.py",
    "resource_multiseg_interop.py",
    "resource_multiwindow_interop.py",
    "resource_concurrent_interop.py",
    "resource_large_interop.py",
    "resource_1mb_interop.py",
    "resource_relay_interop.py",
    "resource_initiate_relay_interop.py",
    "resource_cancel_interop.py",
    "resource_reject_interop.py",
    "lxmf_direct_interop.py",
    "lxmf_opportunistic_interop.py",
    "lxmf_bidirectional_interop.py",
    "lxmf_propagation_interop.py",
    "lxmf_store_forward_interop.py",
    "lxmf_auto_forward_interop.py",
    "lxmf_retrieval_interop.py",
    "lxmf_peering_interop.py",
    "lxmf_persistence_interop.py",
    "lxmf_outbound_interop.py",
    "lxmf_stamp_interop.py",
    "lxmf_outbound_retry_interop.py",
    "announce_appdata_interop.py",
    "announce_dedup_e2e_interop.py",
    "announce_flood_interop.py",
    "malformed_announce_interop.py",
    "tcp_disconnect_interop.py",
    "hdlc_recovery_interop.py",
    "dual_interface_interop.py",
    "multi_hop_relay_interop.py",
    "auto_interop.py",
    "auto_data_interop.py",
    "auto_group_isolation_interop.py",
    "proof_chain_interop.py",
    "concurrent_traffic_interop.py",
    "data_integrity_interop.py",
    "mtu_boundary_interop.py",
    "mixed_stress_interop.py",
    "path_expiry_interop.py",
    "stability_interop.py",
    "stats_interop.py",
    "monitoring_interop.py",
    "shutdown_interop.py",
    "config_file_interop.py",
    "audit_constants_interop.py",
]

SHARED_UNIX_TESTS = [
    "shared_mode/unix/announce.py",
    "shared_mode/unix/data.py",
    "shared_mode/unix/link.py",
    "shared_mode/unix/request.py",
    "shared_mode/unix/resource_small.py",
    "shared_mode/unix/resource_large.py",
    "shared_mode/unix/resource_corrupt.py",
    "shared_mode/unix/lxmf_direct.py",
    "shared_mode/unix/lxmf_opportunistic.py",
    "shared_mode/unix/lxmf_propagation.py",
]

SHARED_TCP_TESTS = [
    "shared_mode/tcp/announce.py",
    "shared_mode/tcp/data.py",
    "shared_mode/tcp/link.py",
    "shared_mode/tcp/request.py",
    "shared_mode/tcp/resource_small.py",
    "shared_mode/tcp/resource_large.py",
    "shared_mode/tcp/resource_corrupt.py",
    "shared_mode/tcp/lxmf_direct.py",
    "shared_mode/tcp/lxmf_opportunistic.py",
    "shared_mode/tcp/lxmf_propagation.py",
]

SHARED_TESTS = SHARED_UNIX_TESTS + SHARED_TCP_TESTS
ALL_TESTS = ORIGINAL_TESTS + SHARED_TESTS

# ---------------------------------------------------------------------------
# Docker helpers
# ---------------------------------------------------------------------------


def build_image():
    """Build the unified E2E Docker image (cached)."""
    print(f"[runner] Building image {IMAGE_TAG} ...")
    result = subprocess.run(
        ["docker", "build", "-t", IMAGE_TAG, "-f", _DOCKERFILE, "."],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        print(f"[runner] Docker build failed:\n{result.stderr}")
        sys.exit(1)
    print(f"[runner] Image {IMAGE_TAG} ready.")


def _is_shared_mode_test(test_path):
    """Return True if test_path is a shared-mode test."""
    return test_path.startswith("shared_mode/")


def run_test(test_path, rete_linux, rete_shared, timeout=120):
    """Run a single test inside a Docker container.  Returns (test_path, exit_code, elapsed)."""
    is_shared = _is_shared_mode_test(test_path)

    # Pick the right binary
    if is_shared:
        binary = os.path.abspath(rete_shared)
        container_binary = "/opt/rete/rete-shared"
    else:
        binary = os.path.abspath(rete_linux)
        container_binary = "/opt/rete/rete-linux"

    if not os.path.isfile(binary):
        print(f"[runner] ERROR: binary not found: {binary}")
        return (test_path, 1, 0.0)

    print(f"\n{'='*60}")
    print(f"[runner] Running: {test_path}")
    print(f"{'='*60}")

    cmd = [
        "docker", "run", "--rm",
        # Bind-mount the binary
        "-v", f"{binary}:{container_binary}:ro",
        # Bind-mount the entire interop test tree
        "-v", f"{_THIS_DIR}:/opt/tests:ro",
        # Environment
        "-e", "RETE_CONTAINERIZED=1",
        "-e", f"RETE_BINARY={container_binary}",
        # Image and command
        IMAGE_TAG,
        f"/opt/tests/{test_path}",
        "--rust-binary", container_binary,
    ]

    t0 = time.monotonic()
    try:
        result = subprocess.run(cmd, timeout=timeout)
        rc = result.returncode
    except subprocess.TimeoutExpired:
        print(f"[runner] TIMEOUT: {test_path} (>{timeout}s)")
        rc = 124
    elapsed = time.monotonic() - t0

    status = "PASS" if rc == 0 else "FAIL"
    print(f"[runner] {status}: {test_path} ({elapsed:.1f}s)")
    return (test_path, rc, elapsed)


def run_test_wrapper(args):
    """Wrapper for parallel execution (unpacks tuple args)."""
    return run_test(*args)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Run rete E2E interop tests in isolated Docker containers",
    )
    parser.add_argument(
        "test", nargs="?",
        help="Test file relative to tests/interop/ (e.g. live_interop.py or shared_mode/unix/announce.py)",
    )
    parser.add_argument(
        "--suite",
        choices=["original", "shared", "shared-unix", "shared-tcp"],
        help="Run all tests in a suite",
    )
    parser.add_argument("--all", action="store_true", help="Run all tests")
    parser.add_argument(
        "--rete-linux", default=_DEFAULT_RETE_LINUX,
        help="Path to rete-linux binary (for original interop tests)",
    )
    parser.add_argument(
        "--rete-shared", default=_DEFAULT_RETE_SHARED,
        help="Path to rete-shared binary (for shared-mode tests)",
    )
    parser.add_argument(
        "--timeout", type=int, default=120,
        help="Per-test timeout in seconds (default: 120)",
    )
    parser.add_argument(
        "--parallel", type=int, default=1,
        help="Number of tests to run concurrently (default: 1)",
    )
    args = parser.parse_args()

    # Determine test list
    if args.all:
        tests = list(ALL_TESTS)
    elif args.suite == "original":
        tests = list(ORIGINAL_TESTS)
    elif args.suite == "shared":
        tests = list(SHARED_TESTS)
    elif args.suite == "shared-unix":
        tests = list(SHARED_UNIX_TESTS)
    elif args.suite == "shared-tcp":
        tests = list(SHARED_TCP_TESTS)
    elif args.test:
        tests = [args.test]
    else:
        parser.print_help()
        sys.exit(1)

    # Check which binaries are needed
    needs_linux = any(not _is_shared_mode_test(t) for t in tests)
    needs_shared = any(_is_shared_mode_test(t) for t in tests)

    if needs_linux and not os.path.isfile(args.rete_linux):
        print(f"[runner] ERROR: rete-linux not found at {args.rete_linux}")
        print("  Build it with: cargo build -p rete-example-linux")
        sys.exit(1)

    if needs_shared and not os.path.isfile(args.rete_shared):
        print(f"[runner] ERROR: rete-shared not found at {args.rete_shared}")
        print("  Build it with: cargo build -p rete-daemon --bin rete-shared")
        sys.exit(1)

    # Build image
    build_image()

    # Run tests
    results = []
    if args.parallel > 1:
        task_args = [
            (t, args.rete_linux, args.rete_shared, args.timeout)
            for t in tests
        ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as pool:
            results = list(pool.map(run_test_wrapper, task_args))
    else:
        for test_path in tests:
            result = run_test(test_path, args.rete_linux, args.rete_shared, args.timeout)
            results.append(result)

    # Summary
    passed = sum(1 for _, rc, _ in results if rc == 0)
    failed = sum(1 for _, rc, _ in results if rc != 0)
    total = len(results)
    total_time = sum(elapsed for _, _, elapsed in results)

    print(f"\n{'='*60}")
    print(f"[runner] Results: {passed}/{total} passed, {failed} failed  ({total_time:.1f}s total)")
    print(f"{'─'*60}")
    for test_path, rc, elapsed in results:
        status = "PASS" if rc == 0 else "FAIL"
        print(f"  [{status}] {test_path:<50s} {elapsed:6.1f}s")
    print(f"{'='*60}")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
