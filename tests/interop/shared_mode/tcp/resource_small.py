#!/usr/bin/env python3
"""
S1-TCP-RSRC-001: Small resource transfer through TCP shared daemon.

~1KB resource sent over a link. Byte-for-byte data match assertion.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared_mode_helpers import (
    CLIENT_LINK_SERVER_SCRIPT,
    CLIENT_LINK_CLIENT_SCRIPT,
    SharedModeTest,
    parse_args,
    run_shared_client,
    wait_client,
    read_result,
    wait_for_ready_file,
    tcp_ports,
)


def main():
    args = parse_args()
    t = SharedModeTest("S1-TCP-RSRC-001 resource_small", rust_binary=args.rust_binary)
    data_port, ctrl_port = tcp_ports()
    ports = {"data_port": data_port, "ctrl_port": ctrl_port}

    payload = os.urandom(1024)
    payload_hex = payload.hex()

    try:
        t.start_daemon(instance_type="tcp", port=data_port, control_port=ctrl_port,
                       transport=True)

        dir_b = t.make_client_dir("server", mode="tcp", ports=ports)
        result_b = os.path.join(dir_b, "result.json")
        ready_b = os.path.join(dir_b, "ready.json")
        proc_b = run_shared_client(
            CLIENT_LINK_SERVER_SCRIPT,
            [dir_b, result_b, "rsrc_test", "endpoint", "30", "resource", ready_b],
        )

        ready = wait_for_ready_file(ready_b, timeout=10)
        t.check(ready is not None, "Server wrote ready file")
        b_dest_hash = ready["dest_hash"] if ready else ""

        time.sleep(2)

        dir_a = t.make_client_dir("client", mode="tcp", ports=ports)
        result_a = os.path.join(dir_a, "result.json")
        proc_a = run_shared_client(
            CLIENT_LINK_CLIENT_SCRIPT,
            [dir_a, result_a, "rsrc_test", "endpoint", b_dest_hash, "20",
             "resource", payload_hex],
        )

        wait_client(proc_a, timeout=40)
        wait_client(proc_b, timeout=40)

        res_a = read_result(result_a)
        t.check(res_a is not None, "Client wrote result")
        t.check(res_a and res_a.get("attached"), "Client attached")
        t.check(res_a and res_a.get("link_established"), "Client link established")
        t.check(res_a and res_a.get("resource_sent"), "Client resource sent successfully")

        res_b = read_result(result_b)
        t.check(res_b is not None, "Server wrote result")
        t.check(res_b and res_b.get("attached"), "Server attached")
        t.check(res_b and res_b.get("link_established"), "Server link established")
        t.check(res_b and res_b.get("resource_completed"), "Server resource completed")
        t.check(
            res_b and res_b.get("resource_size") == len(payload),
            f"Resource size matches ({res_b.get('resource_size') if res_b else 0} == {len(payload)})",
        )
        if res_b and res_b.get("resource_data_hex"):
            t.check(
                res_b["resource_data_hex"] == payload_hex,
                "Resource data matches byte-for-byte",
            )
        else:
            t.check(False, "Resource data matches byte-for-byte")

        t.check(t.daemon_proc.poll() is None, "Daemon alive after resource transfer")

    finally:
        t.finish()


if __name__ == "__main__":
    main()
