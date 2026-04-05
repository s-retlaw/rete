#!/usr/bin/env python3
"""
S1-TCP-LXMF-002: LXMF opportunistic delivery through TCP shared daemon.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared_mode_helpers import (
    CLIENT_LXMF_RECEIVER_SCRIPT,
    CLIENT_LXMF_SENDER_SCRIPT,
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
    t = SharedModeTest("S1-TCP-LXMF-002 lxmf_opportunistic", rust_binary=args.rust_binary)
    data_port, ctrl_port = tcp_ports()
    ports = {"data_port": data_port, "ctrl_port": ctrl_port}

    try:
        t.start_daemon(instance_type="tcp", port=data_port, control_port=ctrl_port,
                       transport=True)

        dir_b = t.make_client_dir("receiver", mode="tcp", ports=ports)
        result_b = os.path.join(dir_b, "result.json")
        ready_b = os.path.join(dir_b, "ready.json")
        proc_b = run_shared_client(
            CLIENT_LXMF_RECEIVER_SCRIPT,
            [dir_b, result_b, "30", "Receiver", "direct", ready_b],
        )

        ready = wait_for_ready_file(ready_b, timeout=15)
        t.check(ready is not None, "Receiver wrote ready file")
        b_dest_hash = ready["dest_hash"] if ready else ""

        time.sleep(3)

        dir_a = t.make_client_dir("sender", mode="tcp", ports=ports)
        result_a = os.path.join(dir_a, "result.json")
        proc_a = run_shared_client(
            CLIENT_LXMF_SENDER_SCRIPT,
            [dir_a, result_a, b_dest_hash, "Opp Title", "Hello opportunistic!",
             "20", "opportunistic"],
        )

        wait_client(proc_a, timeout=30)
        wait_client(proc_b, timeout=35)

        res_a = read_result(result_a)
        t.check(res_a is not None, "Sender wrote result")
        t.check(res_a and res_a.get("attached"), "Sender attached")
        t.check(res_a and res_a.get("identity_found"), "Sender discovered receiver")
        t.check(res_a and res_a.get("sent"), "LXMF message sent (opportunistic)")

        res_b = read_result(result_b)
        t.check(res_b is not None, "Receiver wrote result")
        t.check(res_b and res_b.get("attached"), "Receiver attached")
        t.check(
            res_b and res_b.get("message_count", 0) >= 1,
            f"Receiver got message (count={res_b.get('message_count', 0) if res_b else 0})",
        )

        t.check(t.daemon_proc.poll() is None, "Daemon alive")

    finally:
        t.finish()


if __name__ == "__main__":
    main()
