#!/usr/bin/env python3
"""S1-TCP-ATTACH-003: Client reconnects to rete-shared after drop (TCP).

Topology:
  Rust daemon (rete-shared) in TCP shared mode
  + 1 stock Python client (crash + reconnect)

Usage:
  cargo build -p rete-daemon --bin rete-shared
  cd tests/interop
  uv run python shared_mode/tcp/reconnect.py [--rust-binary PATH]
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shared_mode_helpers import (
    SharedModeTest,
    CLIENT_CRASH_SCRIPT,
    CLIENT_ATTACH_SCRIPT,
    run_shared_client,
    wait_client,
    read_result,
    parse_args,
)

PORT = 49000 + (os.getpid() % 1000) + 2


def main():
    args = parse_args()
    t = SharedModeTest("S1-TCP-ATTACH-003", rust_binary=args.rust_binary)

    try:
        print(f"Starting rete-shared daemon (TCP mode, port {PORT})...")
        t.start_daemon(instance_type="tcp", port=PORT)

        ports = {"data_port": PORT}

        # --- Phase A: client attaches and crashes ---
        print("Phase A: starting client that will crash...")
        crash_dir = t.make_client_dir("crash_client", mode="tcp", ports=ports)
        crash_result_file = os.path.join(t.tmpdir, "crash_result.json")

        crash_proc = run_shared_client(
            CLIENT_CRASH_SCRIPT,
            [crash_dir, crash_result_file, "probe", "crash"],
        )
        _, _ = wait_client(crash_proc, timeout=args.timeout)

        crash_result = read_result(crash_result_file)
        t.check(crash_result is not None, "Phase A: crash client wrote result")
        if crash_result:
            t.check(
                crash_result.get("attached") is True,
                "Phase A: crash client was attached before exit",
            )

        # Wait for daemon to detect disconnect (EOF on TCP close).
        time.sleep(0.5)
        t.check(
            t.daemon_proc.poll() is None,
            "Daemon still alive after client crash",
        )

        # --- Phase B: new client reconnects ---
        print("Phase B: starting fresh client...")
        reconnect_dir = t.make_client_dir("reconnect_client", mode="tcp", ports=ports)
        reconnect_result_file = os.path.join(t.tmpdir, "reconnect_result.json")

        reconnect_proc = run_shared_client(
            CLIENT_ATTACH_SCRIPT,
            [reconnect_dir, reconnect_result_file, "probe", "reconnect", "3"],
        )
        _, stderr = wait_client(reconnect_proc, timeout=args.timeout)

        if reconnect_proc.returncode != 0:
            print(f"  Reconnect client stderr: {stderr[-500:]}")

        t.check(reconnect_proc.returncode == 0, "Phase B: reconnect client exited cleanly")

        reconnect_result = read_result(reconnect_result_file)
        t.check(reconnect_result is not None, "Phase B: reconnect client wrote result")
        if reconnect_result:
            t.check(
                reconnect_result.get("attached") is True,
                "Phase B: reconnect client attached=True",
            )

        t.check(
            t.daemon_proc.poll() is None,
            "Daemon still alive after reconnect",
        )

    finally:
        t.finish()


if __name__ == "__main__":
    main()
