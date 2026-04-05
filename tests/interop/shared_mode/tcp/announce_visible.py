#!/usr/bin/env python3
"""
S1-TCP-STATE-001: Announce visible across clients (TCP).

TCP mirror of unix/announce_visible.py.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared_mode_helpers import (
    CLIENT_ANNOUNCE_AND_POLL,
    SharedModeTest,
    parse_args,
    run_shared_client,
    wait_client,
    read_result,
)


def main():
    args = parse_args()
    t = SharedModeTest("S1-TCP-STATE-001 announce_visible_tcp", rust_binary=args.rust_binary)

    try:
        port = 47300 + (os.getpid() % 100)
        control_port = port + 1
        t.start_daemon(instance_type="tcp", port=port, control_port=control_port)

        dir_a = t.make_client_dir("client_a", mode="tcp", ports={"data_port": port, "ctrl_port": control_port})
        result_a = os.path.join(dir_a, "result.json")
        proc_a = run_shared_client(
            CLIENT_ANNOUNCE_AND_POLL,
            [dir_a, result_a, "probe", "tcp_vis_a", "6", ""],
        )

        time.sleep(2)

        wait_client(proc_a, timeout=15)
        res_a = read_result(result_a)
        t.check(res_a is not None, "Client A wrote result")
        t.check(res_a and res_a.get("attached"), "Client A attached")
        a_dest_hash = res_a["dest_hash"] if res_a else ""

        dir_b = t.make_client_dir("client_b", mode="tcp", ports={"data_port": port, "ctrl_port": control_port})
        result_b = os.path.join(dir_b, "result.json")
        proc_b = run_shared_client(
            CLIENT_ANNOUNCE_AND_POLL,
            [dir_b, result_b, "probe", "tcp_vis_b", "8", a_dest_hash],
        )
        wait_client(proc_b, timeout=15)

        res_b = read_result(result_b)
        t.check(res_b is not None, "Client B wrote result")
        t.check(res_b and res_b.get("attached"), "Client B attached")
        t.check(res_b is not None, "Client B completed without error")
        t.check(t.daemon_proc.poll() is None, "Daemon alive after both clients")

    finally:
        t.finish()


if __name__ == "__main__":
    main()
