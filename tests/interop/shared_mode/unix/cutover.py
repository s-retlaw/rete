#!/usr/bin/env python3
"""
S3-UNX-CUTOVER-001: Cutover dry run Python rnsd → Rust daemon (Unix).
S3-UNX-CUTOVER-002: Rollback dry run Rust daemon → Python rnsd (Unix).

Validates that operators can switch between Python rnsd and Rust rete-shared
without client breakage. Clients reconnect to whichever daemon is running.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared_mode_helpers import (
    CLIENT_ATTACH_SCRIPT,
    SharedModeTest,
    daemon_is_alive,
    parse_args,
    read_result,
    run_shared_client,
    start_python_rnsd,
    stop_daemon,
    wait_client,
)


def main():
    args = parse_args()
    t = SharedModeTest("S3-UNX-CUTOVER unix_cutover", rust_binary=args.rust_binary)

    try:
        # ── Cutover: Python rnsd → Rust daemon ──────────────────────────

        # Step 1: Start Python rnsd.
        rnsd_config = os.path.join(t.tmpdir, "rnsd_config")
        rnsd_proc = start_python_rnsd(rnsd_config)
        t.check(rnsd_proc.poll() is None, "Python rnsd started")

        # Step 2: Connect a Python client to rnsd.
        client_dir_1 = os.path.join(t.tmpdir, "client_cutover_1")
        os.makedirs(client_dir_1, exist_ok=True)
        config_path = os.path.join(client_dir_1, "config")
        with open(config_path, "w") as f:
            f.write("[reticulum]\n  share_instance = Yes\n  enable_transport = No\n")
        result_1 = os.path.join(client_dir_1, "result.json")
        proc_1 = run_shared_client(
            CLIENT_ATTACH_SCRIPT,
            [client_dir_1, result_1, "cutover", "client1", "3"],
        )
        wait_client(proc_1, timeout=15)
        res_1 = read_result(result_1)
        t.check(
            res_1 is not None and res_1.get("attached"),
            "Client attached to Python rnsd",
        )

        # Step 3: Stop Python rnsd.
        stop_daemon(rnsd_proc)
        t.check(rnsd_proc.poll() is not None, "Python rnsd stopped")

        # Brief delay for socket cleanup.
        time.sleep(1)

        # Step 4: Start Rust daemon (default instance name).
        t.start_daemon(transport=True)

        # Step 5: Connect a new client to the Rust daemon.
        client_dir_2 = t.make_client_dir("client_cutover_2")
        result_2 = os.path.join(client_dir_2, "result.json")
        proc_2 = run_shared_client(
            CLIENT_ATTACH_SCRIPT,
            [client_dir_2, result_2, "cutover", "client2", "3"],
        )
        wait_client(proc_2, timeout=15)
        res_2 = read_result(result_2)
        t.check(
            res_2 is not None and res_2.get("attached"),
            "Client attached to Rust daemon after cutover",
        )
        t.check(daemon_is_alive(t.daemon_proc), "Rust daemon alive after cutover")

        # ── Rollback: Rust daemon → Python rnsd ────────────────────────

        # Step 6: Stop Rust daemon.
        stop_daemon(t.daemon_proc)
        t.daemon_proc = None
        time.sleep(1)

        # Step 7: Start Python rnsd again.
        rnsd_config_2 = os.path.join(t.tmpdir, "rnsd_config_rollback")
        rnsd_proc_2 = start_python_rnsd(rnsd_config_2)
        t.check(rnsd_proc_2.poll() is None, "Python rnsd restarted for rollback")

        # Step 8: Connect a client to the rolled-back rnsd.
        client_dir_3 = os.path.join(t.tmpdir, "client_rollback")
        os.makedirs(client_dir_3, exist_ok=True)
        config_path_3 = os.path.join(client_dir_3, "config")
        with open(config_path_3, "w") as f:
            f.write("[reticulum]\n  share_instance = Yes\n  enable_transport = No\n")
        result_3 = os.path.join(client_dir_3, "result.json")
        proc_3 = run_shared_client(
            CLIENT_ATTACH_SCRIPT,
            [client_dir_3, result_3, "cutover", "rollback", "3"],
        )
        wait_client(proc_3, timeout=15)
        res_3 = read_result(result_3)
        t.check(
            res_3 is not None and res_3.get("attached"),
            "Client attached to Python rnsd after rollback",
        )

        # Cleanup rnsd.
        stop_daemon(rnsd_proc_2)

    finally:
        t.finish()


if __name__ == "__main__":
    main()
