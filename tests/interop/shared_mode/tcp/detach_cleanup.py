#!/usr/bin/env python3
"""
S1-TCP-STATE-002: Client detach cleanup (TCP).

TCP mirror of unix/detach_cleanup.py.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared_mode_helpers import (
    CLIENT_ATTACH_SCRIPT,
    CLIENT_CRASH_SCRIPT,
    SharedModeTest,
    parse_args,
    read_result,
    run_shared_client,
    wait_client,
)


def main():
    args = parse_args()
    t = SharedModeTest("S1-TCP-STATE-002 detach_cleanup_tcp", rust_binary=args.rust_binary)

    try:
        port = 47400 + (os.getpid() % 100)
        control_port = port + 1
        t.start_daemon(instance_type="tcp", port=port, control_port=control_port)

        # Client A crashes
        dir_a = t.make_client_dir("client_a", mode="tcp", ports={"data_port": port, "ctrl_port": control_port})
        result_a = os.path.join(dir_a, "result.json")
        proc_a = run_shared_client(
            CLIENT_CRASH_SCRIPT,
            [dir_a, result_a, "probe", "tcp_crash_a"],
        )
        wait_client(proc_a, timeout=10)
        res_a = read_result(result_a)
        t.check(res_a is not None, "Client A wrote result before crash")
        t.check(res_a and res_a.get("attached"), "Client A was attached")

        time.sleep(0.5)
        t.check(t.daemon_proc.poll() is None, "Daemon alive after client A crash")

        # Client B attaches
        dir_b = t.make_client_dir("client_b", mode="tcp", ports={"data_port": port, "ctrl_port": control_port})
        result_b = os.path.join(dir_b, "result.json")
        proc_b = run_shared_client(
            CLIENT_ATTACH_SCRIPT,
            [dir_b, result_b, "probe", "tcp_alive_b", "3"],
        )
        wait_client(proc_b, timeout=10)
        res_b = read_result(result_b)
        t.check(res_b is not None, "Client B wrote result")
        t.check(res_b and res_b.get("attached"), "Client B attached after A's crash")

        t.check(t.daemon_proc.poll() is None, "Daemon alive after client B detach")

        # Client C fresh attach
        dir_c = t.make_client_dir("client_c", mode="tcp", ports={"data_port": port, "ctrl_port": control_port})
        result_c = os.path.join(dir_c, "result.json")
        proc_c = run_shared_client(
            CLIENT_ATTACH_SCRIPT,
            [dir_c, result_c, "probe", "tcp_fresh_c", "2"],
        )
        wait_client(proc_c, timeout=10)
        res_c = read_result(result_c)
        t.check(res_c is not None, "Client C wrote result")
        t.check(res_c and res_c.get("attached"), "Client C attached after churn")

        t.check(t.daemon_proc.poll() is None, "Daemon alive after all clients")

    finally:
        t.finish()


if __name__ == "__main__":
    main()
