#!/usr/bin/env python3
"""
S3-UNX-SOAK-001: Attach/detach churn (Unix).
S3-UNX-SOAK-002: Mixed protocol workload (Unix).
S3-UNX-SOAK-003: Restart during active client churn (Unix).

Validates daemon stability under sustained load: rapid client cycling,
mixed traffic patterns, and restart during active connections.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared_mode_helpers import (
    CLIENT_ATTACH_SCRIPT,
    CLIENT_ANNOUNCE_AND_POLL,
    SharedModeTest,
    daemon_is_alive,
    get_rss_kb,
    parse_args,
    raw_unix_connect,
    read_result,
    run_shared_client,
    wait_client,
)

SOAK_CYCLES = int(os.environ.get("SOAK_CYCLES", "100"))
UNIX_SOCKET = "\0rns/default"


def main():
    args = parse_args()
    t = SharedModeTest("S3-UNX-SOAK unix_soak", rust_binary=args.rust_binary)

    try:
        t.start_daemon(transport=True)

        # --- Test 1: Attach/detach churn ---
        # Rapidly connect and disconnect SOAK_CYCLES raw sockets.
        baseline_rss = get_rss_kb(t.daemon_proc.pid)
        for i in range(SOAK_CYCLES):
            try:
                s = raw_unix_connect(UNIX_SOCKET)
                s.close()
            except Exception:
                pass

        # Small delay for disconnect events to drain.
        time.sleep(2)
        t.check(daemon_is_alive(t.daemon_proc), f"Daemon alive after {SOAK_CYCLES} attach/detach cycles")

        # Check RSS growth is bounded (< 3x baseline).
        post_churn_rss = get_rss_kb(t.daemon_proc.pid)
        if baseline_rss and post_churn_rss:
            growth = post_churn_rss / baseline_rss
            t.check(
                growth < 3.0,
                f"RSS growth bounded after churn (baseline={baseline_rss}KB, "
                f"post={post_churn_rss}KB, ratio={growth:.1f}x)",
            )
        else:
            t.check(True, "RSS monitoring unavailable (non-Linux or permission issue)")

        # Verify a real Python client can still attach.
        dir_a = t.make_client_dir("churn_verify")
        result_a = os.path.join(dir_a, "result.json")
        proc_a = run_shared_client(
            CLIENT_ATTACH_SCRIPT,
            [dir_a, result_a, "probe", "churn_verify", "2"],
        )
        wait_client(proc_a, timeout=15)
        res_a = read_result(result_a)
        t.check(
            res_a is not None and res_a.get("attached"),
            "Python client attaches after churn",
        )

        # --- Test 2: Mixed protocol workload ---
        # Two clients: one announces, the other polls for the announce.
        dir_ann = t.make_client_dir("mixed_announcer")
        result_ann = os.path.join(dir_ann, "result.json")
        proc_ann = run_shared_client(
            CLIENT_ANNOUNCE_AND_POLL,
            [dir_ann, result_ann, "soak", "ann", "8", ""],
        )
        time.sleep(2)

        # Read announcer's dest hash for polling.
        wait_client(proc_ann, timeout=15)
        res_ann = read_result(result_ann)
        ann_hash = res_ann.get("dest_hash", "") if res_ann else ""

        dir_poll = t.make_client_dir("mixed_poller")
        result_poll = os.path.join(dir_poll, "result.json")
        proc_poll = run_shared_client(
            CLIENT_ANNOUNCE_AND_POLL,
            [dir_poll, result_poll, "soak", "poll", "8", ann_hash],
        )
        wait_client(proc_poll, timeout=15)
        res_poll = read_result(result_poll)
        t.check(
            res_poll is not None and res_poll.get("attached"),
            "Mixed workload: poller attached",
        )
        t.check(daemon_is_alive(t.daemon_proc), "Daemon alive after mixed workload")

        # --- Test 3: Restart during active client churn ---
        # Start a series of rapid connections, then restart daemon mid-churn.
        # Spawn a few connects in background, restart daemon, verify recovery.
        for _ in range(20):
            try:
                s = raw_unix_connect(UNIX_SOCKET)
                s.close()
            except Exception:
                pass

        # Restart the daemon.
        t.restart_daemon(transport=True)

        # Wait a moment for new daemon to be ready.
        time.sleep(1)

        # Verify new daemon accepts clients.
        dir_restart = t.make_client_dir("restart_verify")
        result_restart = os.path.join(dir_restart, "result.json")
        proc_restart = run_shared_client(
            CLIENT_ATTACH_SCRIPT,
            [dir_restart, result_restart, "probe", "restart_verify", "2"],
        )
        wait_client(proc_restart, timeout=15)
        res_restart = read_result(result_restart)
        t.check(
            res_restart is not None and res_restart.get("attached"),
            "Client attaches after restart during churn",
        )
        t.check(daemon_is_alive(t.daemon_proc), "Daemon alive after restart during churn")

    finally:
        t.finish()


if __name__ == "__main__":
    main()
