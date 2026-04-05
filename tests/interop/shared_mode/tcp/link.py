#!/usr/bin/env python3
"""
S1-TCP-LINK-001: Link establish / data / teardown through TCP shared daemon.

Client B creates a destination with link callbacks, announces.
Client A discovers B, establishes a link, sends data, tears down.
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
    t = SharedModeTest("S1-TCP-LINK-001 link", rust_binary=args.rust_binary)
    data_port, ctrl_port = tcp_ports()
    ports = {"data_port": data_port, "ctrl_port": ctrl_port}

    payload = b"Hello via link!"
    payload_hex = payload.hex()

    try:
        t.start_daemon(instance_type="tcp", port=data_port, control_port=ctrl_port,
                       transport=True)

        dir_b = t.make_client_dir("server", mode="tcp", ports=ports)
        result_b = os.path.join(dir_b, "result.json")
        ready_b = os.path.join(dir_b, "ready.json")
        proc_b = run_shared_client(
            CLIENT_LINK_SERVER_SCRIPT,
            [dir_b, result_b, "link_test", "endpoint", "30", "echo", ready_b],
        )

        ready = wait_for_ready_file(ready_b, timeout=10)
        t.check(ready is not None, "Server wrote ready file")
        b_dest_hash = ready["dest_hash"] if ready else ""

        time.sleep(2)

        dir_a = t.make_client_dir("client", mode="tcp", ports=ports)
        result_a = os.path.join(dir_a, "result.json")
        proc_a = run_shared_client(
            CLIENT_LINK_CLIENT_SCRIPT,
            [dir_a, result_a, "link_test", "endpoint", b_dest_hash, "20",
             "echo", payload_hex],
        )

        wait_client(proc_a, timeout=35)
        wait_client(proc_b, timeout=35)

        res_a = read_result(result_a)
        t.check(res_a is not None, "Client wrote result")
        t.check(res_a and res_a.get("attached"), "Client attached")
        t.check(res_a and res_a.get("identity_found"), "Client discovered server identity")
        t.check(res_a and res_a.get("link_established"), "Client link established")

        res_b = read_result(result_b)
        t.check(res_b is not None, "Server wrote result")
        t.check(res_b and res_b.get("attached"), "Server attached")
        t.check(res_b and res_b.get("link_established"), "Server link established")
        t.check(
            res_b and len(res_b.get("link_data_received", [])) >= 1,
            "Server received link data",
        )

        t.check(t.daemon_proc.poll() is None, "Daemon alive after link lifecycle")

    finally:
        t.finish()


if __name__ == "__main__":
    main()
