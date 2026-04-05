#!/usr/bin/env python3
"""
S1-UNX-LXMF-001: LXMF direct delivery through Unix shared daemon.

Client B runs LXMRouter with delivery identity.
Client A discovers B's LXMF announce and sends a direct LXMF message.
B verifies receipt and content.

Both clients start simultaneously. The receiver delays its announce by
5 seconds so the sender is already connected when the announce propagates.
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
)


def main():
    args = parse_args()
    t = SharedModeTest("S1-UNX-LXMF-001 lxmf_direct", rust_binary=args.rust_binary)

    try:
        t.start_daemon(transport=True)

        # Start receiver — it waits 5s internally before announcing
        # (built into CLIENT_LXMF_RECEIVER_SCRIPT's time.sleep(wait_secs))
        # Actually the receiver announces immediately. We need the SENDER
        # to be connected first. So start both, but the receiver's announce
        # reaches the sender because our daemon replays cached announces.

        dir_b = t.make_client_dir("receiver")
        result_b = os.path.join(dir_b, "result.json")
        ready_b = os.path.join(dir_b, "ready.json")
        proc_b = run_shared_client(
            CLIENT_LXMF_RECEIVER_SCRIPT,
            [dir_b, result_b, "50", "Receiver", "direct", ready_b],
        )

        # Wait for receiver to announce and give us its hash
        ready = wait_for_ready_file(ready_b, timeout=15)
        t.check(ready is not None, "Receiver wrote ready file")
        b_dest_hash = ready["dest_hash"] if ready else ""

        # Give announce time to propagate + cached announce replay
        time.sleep(3)

        # Sender — connects, gets cached announce, discovers, delivers
        dir_a = t.make_client_dir("sender")
        result_a = os.path.join(dir_a, "result.json")
        large_content = "LXMF direct delivery test. " * 5
        proc_a = run_shared_client(
            CLIENT_LXMF_SENDER_SCRIPT,
            [dir_a, result_a, b_dest_hash, "Test Title", large_content,
             "35", "direct"],
        )

        wait_client(proc_a, timeout=55)
        wait_client(proc_b, timeout=60)

        res_a = read_result(result_a)
        t.check(res_a is not None, "Sender wrote result")
        t.check(res_a and res_a.get("attached"), "Sender attached")
        t.check(res_a and res_a.get("identity_found"), "Sender discovered receiver")
        t.check(res_a and res_a.get("sent"), "LXMF message sent")

        res_b = read_result(result_b)
        t.check(res_b is not None, "Receiver wrote result")
        t.check(res_b and res_b.get("attached"), "Receiver attached")
        t.check(
            res_b and res_b.get("message_count", 0) >= 1,
            f"Receiver got message (count={res_b.get('message_count', 0) if res_b else 0})",
        )
        if res_b and res_b.get("messages_received"):
            msg = res_b["messages_received"][0]
            t.check(
                large_content in msg.get("content", ""),
                "Message content matches",
            )

        t.check(t.daemon_proc.poll() is None, "Daemon alive")

    finally:
        t.finish()


if __name__ == "__main__":
    main()
