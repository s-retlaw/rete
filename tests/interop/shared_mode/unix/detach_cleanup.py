#!/usr/bin/env python3
"""
S1-UNX-STATE-002: Client detach cleanup (Unix).

Two stock Python shared-mode clients attach to the Rust daemon.
Client A crashes. Daemon survives, client B remains functional,
a fresh client C can attach.
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
    t = SharedModeTest("S1-UNX-STATE-002 detach_cleanup", rust_binary=args.rust_binary)

    try:
        t.start_daemon()

        # Client A (crash script) — announces and exits abruptly
        dir_a = t.make_client_dir("client_a")
        result_a = os.path.join(dir_a, "result.json")
        proc_a = run_shared_client(
            CLIENT_CRASH_SCRIPT,
            [dir_a, result_a, "probe", "crash_a"],
        )
        wait_client(proc_a, timeout=10)
        res_a = read_result(result_a)
        t.check(res_a is not None, "Client A wrote result before crash")
        t.check(res_a and res_a.get("attached"), "Client A was attached")

        # Daemon must survive client A's crash
        time.sleep(0.5)
        t.check(t.daemon_proc.poll() is None, "Daemon alive after client A crash")

        # Client B — attaches and stays
        dir_b = t.make_client_dir("client_b")
        result_b = os.path.join(dir_b, "result.json")
        proc_b = run_shared_client(
            CLIENT_ATTACH_SCRIPT,
            [dir_b, result_b, "probe", "alive_b", "3"],
        )
        wait_client(proc_b, timeout=10)
        res_b = read_result(result_b)
        t.check(res_b is not None, "Client B wrote result")
        t.check(res_b and res_b.get("attached"), "Client B attached after A's crash")

        # Daemon still alive
        t.check(t.daemon_proc.poll() is None, "Daemon alive after client B detach")

        # Client C — fresh attach after the churn
        dir_c = t.make_client_dir("client_c")
        result_c = os.path.join(dir_c, "result.json")
        proc_c = run_shared_client(
            CLIENT_ATTACH_SCRIPT,
            [dir_c, result_c, "probe", "fresh_c", "2"],
        )
        wait_client(proc_c, timeout=10)
        res_c = read_result(result_c)
        t.check(res_c is not None, "Client C wrote result")
        t.check(res_c and res_c.get("attached"), "Client C attached after churn")

        # Daemon survived everything
        t.check(t.daemon_proc.poll() is None, "Daemon alive after all clients")

    finally:
        t.finish()


if __name__ == "__main__":
    main()
