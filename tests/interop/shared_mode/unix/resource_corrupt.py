#!/usr/bin/env python3
"""
S1-UNX-RSRC-003: Corrupt resource handling through Unix shared daemon.

Verify the daemon does not corrupt resource data in transit.
A valid resource is transferred and its integrity verified (positive test).
"""

import hashlib
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
)


def main():
    args = parse_args()
    t = SharedModeTest("S1-UNX-RSRC-003 resource_corrupt", rust_binary=args.rust_binary)

    # Use a payload with known patterns to detect corruption
    payload = bytes(range(256)) * 16  # 4KB repeating pattern
    payload_hex = payload.hex()
    payload_sha256 = hashlib.sha256(payload).hexdigest()

    try:
        t.start_daemon(transport=True)

        dir_b = t.make_client_dir("server")
        result_b = os.path.join(dir_b, "result.json")
        ready_b = os.path.join(dir_b, "ready.json")
        proc_b = run_shared_client(
            CLIENT_LINK_SERVER_SCRIPT,
            [dir_b, result_b, "corrupt_test", "endpoint", "30", "resource", ready_b],
        )

        ready = wait_for_ready_file(ready_b, timeout=10)
        t.check(ready is not None, "Server wrote ready file")
        b_dest_hash = ready["dest_hash"] if ready else ""

        time.sleep(2)

        dir_a = t.make_client_dir("client")
        result_a = os.path.join(dir_a, "result.json")
        proc_a = run_shared_client(
            CLIENT_LINK_CLIENT_SCRIPT,
            [dir_a, result_a, "corrupt_test", "endpoint", b_dest_hash, "20",
             "resource", payload_hex],
        )

        wait_client(proc_a, timeout=40)
        wait_client(proc_b, timeout=40)

        res_a = read_result(result_a)
        t.check(res_a is not None, "Client wrote result")
        t.check(res_a and res_a.get("resource_sent"), "Client resource sent successfully")

        res_b = read_result(result_b)
        t.check(res_b is not None, "Server wrote result")
        t.check(res_b and res_b.get("resource_completed"), "Server resource completed")

        # Verify the daemon did not corrupt data in transit
        if res_b and res_b.get("resource_data_hex"):
            received_sha256 = hashlib.sha256(
                bytes.fromhex(res_b["resource_data_hex"])
            ).hexdigest()
            t.check(
                received_sha256 == payload_sha256,
                "Resource integrity: SHA-256 matches (no corruption in transit)",
            )
            t.check(
                res_b["resource_data_hex"] == payload_hex,
                "Resource integrity: byte-for-byte match",
            )
        else:
            t.check(False, "Resource integrity: SHA-256 matches (no corruption in transit)")
            t.check(False, "Resource integrity: byte-for-byte match")

        # RNS internally verifies resource hashes — a completed resource
        # with matching hash proves the daemon did not corrupt data.
        t.check(
            res_b and res_b.get("resource_completed") and res_b.get("resource_size") == len(payload),
            "RNS resource hash verification passed (no false resource_completed)",
        )

        t.check(t.daemon_proc.poll() is None, "Daemon alive after integrity test")

    finally:
        t.finish()


if __name__ == "__main__":
    main()
