#!/usr/bin/env python3
"""E2E: Daemon restart and client reattach over TCP.

Covers parity rows S2-TCP-RESTART-001 and S2-TCP-RESTART-002.

Flow:
  1. Start daemon (TCP mode)
  2. Python client A attaches and announces
  3. Stop daemon
  4. Verify snapshot.json persists
  5. Restart daemon with same data_dir and ports
  6. Python client B attaches after restart
  7. Verify identity survives restart
"""

import hashlib
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared_mode_helpers import (
    SharedModeTest,
    CLIENT_ATTACH_SCRIPT,
    parse_args,
    read_result,
    run_shared_client,
    stop_daemon,
    wait_client,
)

DATA_PORT = 49400 + (os.getpid() % 200)
CTRL_PORT = DATA_PORT + 1


def main():
    args = parse_args()
    t = SharedModeTest("S2-TCP-RESTART", rust_binary=args.rust_binary)

    try:
        # --- Phase 1: Start daemon, attach client A ---
        t.start_daemon(
            instance_type="tcp",
            port=DATA_PORT,
            control_port=CTRL_PORT,
        )

        ports = {"data_port": DATA_PORT, "ctrl_port": CTRL_PORT}
        client_a_dir = t.make_client_dir("client_a", mode="tcp", ports=ports)
        result_a_path = os.path.join(t.tmpdir, "result_a.json")
        proc_a = run_shared_client(
            CLIENT_ATTACH_SCRIPT,
            [client_a_dir, result_a_path, "restartapp", "aspect1", "3"],
        )
        _, stderr_a = wait_client(proc_a, timeout=args.timeout)
        result_a = read_result(result_a_path)

        t.check(result_a is not None, "Client A produced result")
        t.check(
            result_a and result_a.get("attached"),
            "Client A attached to TCP daemon",
        )

        # Record identity hash from daemon's identity file.
        identity_path = os.path.join(t.data_dir, "identity")
        t.check(os.path.exists(identity_path), "Identity file exists before restart")
        identity_before = open(identity_path, "rb").read()
        identity_hash_before = hashlib.sha256(identity_before).hexdigest()[:32]

        # --- Phase 2: Stop daemon, verify persistence ---
        # Stop manually to inspect snapshot state before restart.
        stop_daemon(t.daemon_proc)
        t.daemon_proc = None

        snapshot_path = os.path.join(t.data_dir, "snapshot.json")
        t.check(
            os.path.exists(snapshot_path),
            "snapshot.json exists after daemon shutdown",
        )
        snap_size = os.path.getsize(snapshot_path) if os.path.exists(snapshot_path) else 0
        t.check(snap_size > 10, f"snapshot.json is non-trivial ({snap_size} bytes)")

        # --- Phase 3: Restart daemon, attach client B ---
        # Brief delay to ensure TCP ports are released.
        time.sleep(1)

        t.restart_daemon(
            instance_type="tcp",
            port=DATA_PORT,
            control_port=CTRL_PORT,
        )

        time.sleep(0.5)

        client_b_dir = t.make_client_dir("client_b", mode="tcp", ports=ports)
        result_b_path = os.path.join(t.tmpdir, "result_b.json")
        proc_b = run_shared_client(
            CLIENT_ATTACH_SCRIPT,
            [client_b_dir, result_b_path, "restartapp", "aspect2", "3"],
        )
        _, stderr_b = wait_client(proc_b, timeout=args.timeout)
        result_b = read_result(result_b_path)

        t.check(result_b is not None, "Client B produced result after restart")
        t.check(
            result_b and result_b.get("attached"),
            "Client B attached to restarted TCP daemon",
        )

        # Verify identity survived restart.
        identity_after = open(identity_path, "rb").read()
        identity_hash_after = hashlib.sha256(identity_after).hexdigest()[:32]
        t.check(
            identity_hash_before == identity_hash_after,
            "Daemon identity survives TCP restart",
        )

        t.check(t.daemon_proc.poll() is None, "Daemon still alive after client B")

    finally:
        t.finish()


if __name__ == "__main__":
    main()
