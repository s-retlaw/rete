#!/usr/bin/env python3
"""
S1-TCP-DATA-001: Encrypted data send/receive through TCP shared daemon.

Client B creates a SINGLE destination with a packet callback, announces.
Client A discovers B via the daemon-relayed announce, sends encrypted data.
B verifies decrypted content matches.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared_mode_helpers import (
    CLIENT_RECEIVER_SCRIPT,
    CLIENT_SENDER_SCRIPT,
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
    t = SharedModeTest("S1-TCP-DATA-001 data", rust_binary=args.rust_binary)
    data_port, ctrl_port = tcp_ports()
    ports = {"data_port": data_port, "ctrl_port": ctrl_port}

    payload = b"Hello from rete shared daemon test!"
    payload_hex = payload.hex()

    try:
        t.start_daemon(instance_type="tcp", port=data_port, control_port=ctrl_port,
                       transport=True)

        # Client B (receiver)
        dir_b = t.make_client_dir("client_b", mode="tcp", ports=ports)
        result_b = os.path.join(dir_b, "result.json")
        ready_b = os.path.join(dir_b, "ready.json")
        proc_b = run_shared_client(
            CLIENT_RECEIVER_SCRIPT,
            [dir_b, result_b, "data_test", "endpoint", "20", ready_b],
        )

        ready = wait_for_ready_file(ready_b, timeout=10)
        t.check(ready is not None, "Receiver wrote ready file")
        b_dest_hash = ready["dest_hash"] if ready else ""

        time.sleep(2)

        # Client A (sender)
        dir_a = t.make_client_dir("client_a", mode="tcp", ports=ports)
        result_a = os.path.join(dir_a, "result.json")
        proc_a = run_shared_client(
            CLIENT_SENDER_SCRIPT,
            [dir_a, result_a, "data_test", "endpoint", b_dest_hash, payload_hex, "15"],
        )

        wait_client(proc_a, timeout=25)
        wait_client(proc_b, timeout=25)

        res_a = read_result(result_a)
        t.check(res_a is not None, "Sender wrote result")
        t.check(res_a and res_a.get("attached"), "Sender attached")
        t.check(res_a and res_a.get("identity_found"), "Sender discovered receiver identity")
        t.check(res_a and res_a.get("sent"), "Sender sent packet")

        res_b = read_result(result_b)
        t.check(res_b is not None, "Receiver wrote result")
        t.check(res_b and res_b.get("attached"), "Receiver attached")
        t.check(
            res_b and res_b.get("received_count", 0) >= 1,
            f"Receiver got data (count={res_b.get('received_count', 0) if res_b else 0})",
        )
        if res_b and res_b.get("received_data"):
            t.check(
                res_b["received_data"][0] == payload_hex,
                "Received data matches sent payload",
            )
        else:
            t.check(False, "Received data matches sent payload")

        t.check(t.daemon_proc.poll() is None, "Daemon alive after data transfer")

    finally:
        t.finish()


if __name__ == "__main__":
    main()
