#!/usr/bin/env python3
"""Run shared-mode E2E tests inside isolated Docker containers.

Each test runs in its own container with a dedicated network namespace,
eliminating port conflicts entirely. The rete-shared binary and test
scripts are bind-mounted into the container.

Usage:
    # Single test
    uv run python shared_mode/container_runner.py unix/announce.py

    # All Unix tests
    uv run python shared_mode/container_runner.py --suite unix

    # All TCP tests
    uv run python shared_mode/container_runner.py --suite tcp

    # All tests
    uv run python shared_mode/container_runner.py --all

    # Custom binary path
    uv run python shared_mode/container_runner.py --rust-binary path/to/rete-shared unix/data.py
"""

import argparse
import os
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_INTEROP_DIR = os.path.dirname(_THIS_DIR)
_REPO_ROOT = os.path.abspath(os.path.join(_INTEROP_DIR, "..", ".."))
_DOCKERFILE = os.path.join(_REPO_ROOT, "tests", "docker", "shared-mode-e2e.Dockerfile")
_DEFAULT_BINARY = os.path.join(_REPO_ROOT, "target", "debug", "rete-shared")

IMAGE_TAG = "rete-shared-e2e:latest"

# ---------------------------------------------------------------------------
# Test discovery
# ---------------------------------------------------------------------------

UNIX_TESTS = [
    "unix/announce.py",
    "unix/data.py",
    "unix/link.py",
    "unix/request.py",
    "unix/resource_small.py",
    "unix/resource_large.py",
    "unix/resource_corrupt.py",
    "unix/lxmf_direct.py",
    "unix/lxmf_opportunistic.py",
    "unix/lxmf_propagation.py",
]

TCP_TESTS = [
    "tcp/announce.py",
    "tcp/data.py",
    "tcp/link.py",
    "tcp/request.py",
    "tcp/resource_small.py",
    "tcp/resource_large.py",
    "tcp/resource_corrupt.py",
    "tcp/lxmf_direct.py",
    "tcp/lxmf_opportunistic.py",
    "tcp/lxmf_propagation.py",
]

ROBUSTNESS_TESTS = [
    "unix/robustness.py",
    "tcp/robustness.py",
]

SOAK_TESTS = [
    "unix/soak.py",
    "tcp/soak.py",
]

CUTOVER_TESTS = [
    "unix/cutover.py",
    "tcp/cutover.py",
]

ALL_TESTS = UNIX_TESTS + TCP_TESTS + ROBUSTNESS_TESTS + SOAK_TESTS + CUTOVER_TESTS

# ---------------------------------------------------------------------------
# Docker helpers
# ---------------------------------------------------------------------------


def build_image():
    """Build the shared-mode E2E Docker image (cached)."""
    print(f"[container_runner] Building image {IMAGE_TAG} ...")
    result = subprocess.run(
        ["docker", "build", "-t", IMAGE_TAG, "-f", _DOCKERFILE, "."],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        print(f"[container_runner] Docker build failed:\n{result.stderr}")
        sys.exit(1)
    print(f"[container_runner] Image {IMAGE_TAG} ready.")


def run_test(test_path, rust_binary, timeout=120):
    """Run a single test inside a Docker container. Returns exit code."""
    binary = os.path.abspath(rust_binary)
    if not os.path.isfile(binary):
        print(f"[container_runner] ERROR: binary not found: {binary}")
        return 1

    # The test script path relative to shared_mode/
    test_file = f"shared_mode/{test_path}"

    print(f"\n{'='*60}")
    print(f"[container_runner] Running: {test_path}")
    print(f"{'='*60}")

    cmd = [
        "docker", "run", "--rm",
        # Bind-mount the binary
        "-v", f"{binary}:/opt/rete/rete-shared:ro",
        # Bind-mount the entire interop test tree
        "-v", f"{_INTEROP_DIR}:/opt/tests:ro",
        # Environment: tell helpers we're containerized
        "-e", "RETE_CONTAINERIZED=1",
        "-e", "RETE_BINARY=/opt/rete/rete-shared",
        # Image and command
        IMAGE_TAG,
        f"/opt/tests/{test_file}",
        "--rust-binary", "/opt/rete/rete-shared",
    ]

    t0 = time.monotonic()
    result = subprocess.run(
        cmd,
        timeout=timeout,
        # Stream output directly to terminal
    )
    elapsed = time.monotonic() - t0
    status = "PASS" if result.returncode == 0 else "FAIL"
    print(f"[container_runner] {status}: {test_path} ({elapsed:.1f}s)")
    return result.returncode


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Run shared-mode E2E tests in Docker containers")
    parser.add_argument("test", nargs="?", help="Test file relative to shared_mode/ (e.g. unix/announce.py)")
    parser.add_argument("--suite", choices=["unix", "tcp", "robustness", "soak", "cutover"],
                        help="Run all tests in a suite")
    parser.add_argument("--all", action="store_true", help="Run all tests")
    parser.add_argument("--rust-binary", default=_DEFAULT_BINARY, help="Path to rete-shared binary")
    parser.add_argument("--timeout", type=int, default=120, help="Per-test timeout in seconds")
    args = parser.parse_args()

    # Determine test list
    if args.all:
        tests = ALL_TESTS
    elif args.suite == "unix":
        tests = UNIX_TESTS
    elif args.suite == "tcp":
        tests = TCP_TESTS
    elif args.suite == "robustness":
        tests = ROBUSTNESS_TESTS
    elif args.suite == "soak":
        tests = SOAK_TESTS
    elif args.suite == "cutover":
        tests = CUTOVER_TESTS
    elif args.test:
        tests = [args.test]
    else:
        parser.print_help()
        sys.exit(1)

    # Verify binary exists
    if not os.path.isfile(args.rust_binary):
        print(f"[container_runner] ERROR: rete-shared not found at {args.rust_binary}")
        print("  Build it with: cargo build -p rete-daemon --bin rete-shared")
        sys.exit(1)

    # Build image
    build_image()

    # Run tests
    results = []
    for test_path in tests:
        rc = run_test(test_path, args.rust_binary, timeout=args.timeout)
        results.append((test_path, rc))

    # Summary
    passed = sum(1 for _, rc in results if rc == 0)
    total = len(results)
    print(f"\n{'='*60}")
    print(f"[container_runner] Results: {passed}/{total} tests passed")
    for test_path, rc in results:
        status = "PASS" if rc == 0 else "FAIL"
        print(f"  [{status}] {test_path}")
    print(f"{'='*60}")

    if passed < total:
        sys.exit(1)


if __name__ == "__main__":
    main()
