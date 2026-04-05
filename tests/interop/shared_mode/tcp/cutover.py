#!/usr/bin/env python3
"""
S3-TCP-CUTOVER-001: Cutover dry run Python rnsd → Rust daemon (TCP).
S3-TCP-CUTOVER-002: Rollback dry run Rust daemon → Python rnsd (TCP).

Validates that operators can switch between Python rnsd and Rust rete-shared
over TCP without client breakage.
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
    tcp_ports,
    wait_client,
    write_shared_client_config,
)


def main():
    args = parse_args()
    t = SharedModeTest("S3-TCP-CUTOVER tcp_cutover", rust_binary=args.rust_binary)

    try:
        data_port, ctrl_port = tcp_ports()
        ports = {"data_port": data_port, "ctrl_port": ctrl_port}

        # ── Cutover: Python rnsd → Rust daemon ──────────────────────────

        # Step 1: Start Python rnsd (TCP).
        rnsd_config = os.path.join(t.tmpdir, "rnsd_tcp_config")
        rnsd_proc = start_python_rnsd(rnsd_config, instance_type="tcp", port=data_port, control_port=ctrl_port)
        t.check(rnsd_proc.poll() is None, "Python rnsd started (TCP)")

        # Step 2: Connect client to rnsd.
        client_dir_1 = os.path.join(t.tmpdir, "client_tcp_cutover_1")
        os.makedirs(client_dir_1, exist_ok=True)
        write_shared_client_config(client_dir_1, mode="tcp", ports=ports)
        result_1 = os.path.join(client_dir_1, "result.json")
        proc_1 = run_shared_client(
            CLIENT_ATTACH_SCRIPT,
            [client_dir_1, result_1, "cutover", "client1", "3"],
        )
        wait_client(proc_1, timeout=15)
        res_1 = read_result(result_1)
        t.check(
            res_1 is not None and res_1.get("attached"),
            "Client attached to Python rnsd (TCP)",
        )

        # Step 3: Stop Python rnsd.
        stop_daemon(rnsd_proc)
        t.check(rnsd_proc.poll() is not None, "Python rnsd stopped")

        # TCP needs more time for port release (TIME_WAIT).
        time.sleep(2)

        # Step 4: Start Rust daemon (TCP, same ports).
        t.start_daemon(
            instance_type="tcp",
            transport=True,
            port=data_port,
            control_port=ctrl_port,
        )

        # Step 5: Connect new client to Rust daemon.
        client_dir_2 = t.make_client_dir("client_tcp_cutover_2", mode="tcp", ports=ports)
        result_2 = os.path.join(client_dir_2, "result.json")
        proc_2 = run_shared_client(
            CLIENT_ATTACH_SCRIPT,
            [client_dir_2, result_2, "cutover", "client2", "3"],
        )
        wait_client(proc_2, timeout=15)
        res_2 = read_result(result_2)
        t.check(
            res_2 is not None and res_2.get("attached"),
            "Client attached to Rust daemon after TCP cutover",
        )
        t.check(daemon_is_alive(t.daemon_proc), "Rust daemon alive after cutover")

        # ── Rollback: Rust daemon → Python rnsd ────────────────────────

        # Step 6: Stop Rust daemon.
        stop_daemon(t.daemon_proc)
        t.daemon_proc = None
        time.sleep(2)

        # Step 7: Start Python rnsd again.
        rnsd_config_2 = os.path.join(t.tmpdir, "rnsd_tcp_rollback")
        rnsd_proc_2 = start_python_rnsd(rnsd_config_2, instance_type="tcp", port=data_port, control_port=ctrl_port)
        t.check(rnsd_proc_2.poll() is None, "Python rnsd restarted (TCP) for rollback")

        # Step 8: Connect client.
        client_dir_3 = os.path.join(t.tmpdir, "client_tcp_rollback")
        os.makedirs(client_dir_3, exist_ok=True)
        write_shared_client_config(client_dir_3, mode="tcp", ports=ports)
        result_3 = os.path.join(client_dir_3, "result.json")
        proc_3 = run_shared_client(
            CLIENT_ATTACH_SCRIPT,
            [client_dir_3, result_3, "cutover", "rollback", "3"],
        )
        wait_client(proc_3, timeout=15)
        res_3 = read_result(result_3)
        t.check(
            res_3 is not None and res_3.get("attached"),
            "Client attached to Python rnsd after TCP rollback",
        )

        # Cleanup.
        stop_daemon(rnsd_proc_2)

    finally:
        t.finish()


if __name__ == "__main__":
    main()
