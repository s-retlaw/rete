#!/usr/bin/env python3
"""
S3-UNX-ROBUST-001: Malformed attach traffic (Unix).
S3-UNX-ROBUST-002: Half-open client session recovery (Unix).

Validates daemon resilience to garbage data, abrupt client disconnects,
half-open connections, and rapid connect/disconnect churn over Unix sockets.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared_mode_helpers import (
    CLIENT_ATTACH_SCRIPT,
    CLIENT_CRASH_SCRIPT,
    SharedModeTest,
    daemon_is_alive,
    parse_args,
    raw_unix_connect,
    read_result,
    run_shared_client,
    wait_client,
)

UNIX_SOCKET = "\0rns/default"


def main():
    args = parse_args()
    t = SharedModeTest("S3-UNX-ROBUST unix_robustness", rust_binary=args.rust_binary)

    try:
        t.start_daemon(transport=True)

        # --- Test 1: Garbage bytes to data socket ---
        try:
            s = raw_unix_connect(UNIX_SOCKET)
            s.sendall(os.urandom(256))
            time.sleep(0.5)
            s.close()
        except Exception:
            pass
        t.check(daemon_is_alive(t.daemon_proc), "Daemon alive after garbage bytes")

        # --- Test 2: Partial HDLC frame then disconnect ---
        try:
            s = raw_unix_connect(UNIX_SOCKET)
            # HDLC flag + partial data (no closing flag)
            s.sendall(b"\x7e\x00\x01\x02\x03")
            time.sleep(0.3)
            s.close()
        except Exception:
            pass
        t.check(daemon_is_alive(t.daemon_proc), "Daemon alive after partial HDLC")

        # --- Test 3: Oversized HDLC-like frame ---
        try:
            s = raw_unix_connect(UNIX_SOCKET)
            # HDLC flag + large payload + flag
            s.sendall(b"\x7e" + (b"\xAA" * 500_000) + b"\x7e")
            time.sleep(0.5)
            s.close()
        except Exception:
            pass
        t.check(daemon_is_alive(t.daemon_proc), "Daemon alive after oversized HDLC")

        # --- Test 4: Client crash (kill -9 equivalent) cleans up session ---
        dir_crash = t.make_client_dir("crash_client")
        result_crash = os.path.join(dir_crash, "result.json")
        proc = run_shared_client(
            CLIENT_CRASH_SCRIPT,
            [dir_crash, result_crash, "probe", "crash", ],
        )
        wait_client(proc, timeout=15)
        res = read_result(result_crash)
        t.check(res is not None and res.get("attached"), "Crash client attached before exit")

        # Verify daemon can still serve new clients after the crash.
        time.sleep(1)
        dir_after = t.make_client_dir("after_crash")
        result_after = os.path.join(dir_after, "result.json")
        proc2 = run_shared_client(
            CLIENT_ATTACH_SCRIPT,
            [dir_after, result_after, "probe", "after", "2"],
        )
        wait_client(proc2, timeout=15)
        res2 = read_result(result_after)
        t.check(
            res2 is not None and res2.get("attached"),
            "New client attaches after crash client exit",
        )
        t.check(daemon_is_alive(t.daemon_proc), "Daemon alive after crash client cleanup")

        # --- Test 5: Half-open connection (connect, don't send data) ---
        try:
            s = raw_unix_connect(UNIX_SOCKET)
            # Just hold the socket open for a bit, send nothing.
            time.sleep(2)
            s.close()
        except Exception:
            pass
        t.check(daemon_is_alive(t.daemon_proc), "Daemon alive after half-open connection")

        # --- Test 6: Rapid connect/disconnect cycles ---
        for i in range(50):
            try:
                s = raw_unix_connect(UNIX_SOCKET)
                s.close()
            except Exception:
                pass
        time.sleep(1)
        t.check(daemon_is_alive(t.daemon_proc), "Daemon alive after 50 rapid connect/disconnect cycles")

        # Final verification: a real Python RNS client can still attach.
        dir_final = t.make_client_dir("final_client")
        result_final = os.path.join(dir_final, "result.json")
        proc_final = run_shared_client(
            CLIENT_ATTACH_SCRIPT,
            [dir_final, result_final, "probe", "final", "2"],
        )
        wait_client(proc_final, timeout=15)
        res_final = read_result(result_final)
        t.check(
            res_final is not None and res_final.get("attached"),
            "Final client attaches after all robustness tests",
        )

    finally:
        t.finish()


if __name__ == "__main__":
    main()
