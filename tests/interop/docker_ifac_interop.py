#!/usr/bin/env python3
"""Docker-isolated IFAC interop test.

Runs three sequential sub-tests with different IFAC configurations:

Sub-test 1: Matching IFAC — Rust and Python can communicate
Sub-test 2: No IFAC on Rust — Rust should not see IFAC-protected traffic
Sub-test 3: Wrong IFAC on Rust — Rust should not see valid announces

Each sub-test uses its own Docker Compose stack.

Usage:
  cd tests/interop
  uv run python docker_ifac_interop.py
"""

import time

from docker_helpers import DockerTopologyTest

IFAC_NETNAME = "rete-test-network"

total_passed = 0
total_failed = 0


def run_subtest_matching():
    """Sub-test 1: Matching IFAC — bidirectional communication."""
    global total_passed, total_failed

    print("=" * 60)
    print("SUB-TEST 1: Matching IFAC — bidirectional communication")
    print("=" * 60)

    with DockerTopologyTest("ifac-match", "tcp-3node-ifac.yml", timeout=60) as t:
        t.start(env={
            "RNSD_IFAC_NETNAME": IFAC_NETNAME,
            "RUST_ARGS": f"--connect rnsd:4242 --ifac-netname {IFAC_NETNAME} --auto-reply 'hello from rust'",
            "PY_CMD": f"/opt/tests/docker_py_helpers/tcp_node.py --host rnsd --port 4242 --ifac-netname {IFAC_NETNAME}",
        })

        t.wait_for_line("rust-node", "IDENTITY:", timeout=30)
        t.wait_for_line("python-node", "PY_DONE", timeout=45)
        time.sleep(2)

        t.check(
            t.has_line("python-node", "PY_INTEROP_OK"),
            "Matching IFAC: Python discovered Rust announce",
        )
        t.check(
            t.has_line("rust-node", "ANNOUNCE:"),
            "Matching IFAC: Rust received Python announce",
        )
        t.check(
            t.has_line("python-node", "PY_DATA_RECEIVED:"),
            "Matching IFAC: Python received DATA from Rust",
        )
        t.check(
            t.has_line("rust-node", "DATA:"),
            "Matching IFAC: Rust received DATA from Python",
        )
        # Check IFAC enabled in Rust logs
        t.check(
            t.has_line("rust-node", "IFAC enabled"),
            "Matching IFAC: Rust reports IFAC enabled",
        )

        if t.failed > 0:
            t.dump_logs("rust-node", "Rust node")
            t.dump_logs("python-node", "Python node")

        total_passed += t.passed
        total_failed += t.failed


def run_subtest_no_ifac():
    """Sub-test 2: Rust WITHOUT IFAC cannot see IFAC-protected traffic."""
    global total_passed, total_failed

    print()
    print("=" * 60)
    print("SUB-TEST 2: Rust WITHOUT IFAC cannot see IFAC-protected traffic")
    print("=" * 60)

    with DockerTopologyTest("ifac-none", "tcp-3node-ifac.yml", timeout=45) as t:
        t.start(env={
            "RNSD_IFAC_NETNAME": IFAC_NETNAME,
            "RUST_ARGS": "--connect rnsd:4242 --auto-reply 'hello from rust'",
            "PY_CMD": f"/opt/tests/docker_py_helpers/tcp_node.py --host rnsd --port 4242 --ifac-netname {IFAC_NETNAME} --timeout 10",
        })

        t.wait_for_line("python-node", "PY_DONE", timeout=25)
        time.sleep(2)

        rust_announces = [l for l in t.get_lines("rust-node") if "ANNOUNCE:" in l and "IDENTITY:" not in l]
        t.check(
            len(rust_announces) == 0,
            "No IFAC: Rust without IFAC saw 0 announces (IFAC packets dropped)",
            detail=f"Saw {len(rust_announces)} announces" if rust_announces else None,
        )

        if t.failed > 0:
            t.dump_logs("rust-node", "Rust node")
            t.dump_logs("python-node", "Python node")

        total_passed += t.passed
        total_failed += t.failed


def run_subtest_wrong_ifac():
    """Sub-test 3: Rust with WRONG IFAC key cannot communicate."""
    global total_passed, total_failed

    print()
    print("=" * 60)
    print("SUB-TEST 3: Rust with WRONG IFAC key cannot communicate")
    print("=" * 60)

    with DockerTopologyTest("ifac-wrong", "tcp-3node-ifac.yml", timeout=45) as t:
        t.start(env={
            "RNSD_IFAC_NETNAME": IFAC_NETNAME,
            "RUST_ARGS": "--connect rnsd:4242 --ifac-netname wrong-network-name --auto-reply 'hello from rust'",
            "PY_CMD": f"/opt/tests/docker_py_helpers/tcp_node.py --host rnsd --port 4242 --ifac-netname {IFAC_NETNAME} --timeout 10",
        })

        t.wait_for_line("python-node", "PY_DONE", timeout=25)
        time.sleep(2)

        rust_announces = [l for l in t.get_lines("rust-node") if "ANNOUNCE:" in l and "IDENTITY:" not in l]
        t.check(
            len(rust_announces) == 0,
            "Wrong IFAC: Rust with wrong IFAC key saw 0 announces",
            detail=f"Saw {len(rust_announces)} announces" if rust_announces else None,
        )

        if t.failed > 0:
            t.dump_logs("rust-node", "Rust node")
            t.dump_logs("python-node", "Python node")

        total_passed += t.passed
        total_failed += t.failed


def main():
    global total_passed, total_failed

    run_subtest_matching()
    run_subtest_no_ifac()
    run_subtest_wrong_ifac()

    total = total_passed + total_failed
    print()
    print(f"[docker-ifac] Overall results: {total_passed}/{total} passed, {total_failed}/{total} failed")
    if total_failed > 0:
        print("[docker-ifac] SOME TESTS FAILED")
        import sys
        sys.exit(1)
    else:
        print("[docker-ifac] ALL TESTS PASSED")


if __name__ == "__main__":
    main()
