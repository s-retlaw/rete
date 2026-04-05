#!/usr/bin/env python3
"""
S3-TCP-ROBUST-001: Malformed attach traffic (TCP).
S3-TCP-ROBUST-002: Half-open client session recovery (TCP).
S3-TCP-ROBUST-003: Invalid auth resilience (TCP).

Validates daemon resilience to garbage data, abrupt client disconnects,
half-open connections, invalid auth, and rapid churn over TCP sockets.
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
    raw_tcp_connect,
    read_result,
    read_wire_message,
    run_shared_client,
    tcp_ports,
    wait_client,
    write_wire_message,
)


def main():
    args = parse_args()
    t = SharedModeTest("S3-TCP-ROBUST tcp_robustness", rust_binary=args.rust_binary)

    try:
        data_port, ctrl_port = tcp_ports()
        t.start_daemon(
            instance_type="tcp",
            transport=True,
            port=data_port,
            control_port=ctrl_port,
        )

        # --- Test 1: Garbage bytes to data socket ---
        try:
            s = raw_tcp_connect("127.0.0.1", data_port)
            s.sendall(os.urandom(256))
            time.sleep(0.5)
            s.close()
        except Exception:
            pass
        t.check(daemon_is_alive(t.daemon_proc), "Daemon alive after garbage to data port")

        # --- Test 2: Partial HDLC frame then disconnect ---
        try:
            s = raw_tcp_connect("127.0.0.1", data_port)
            s.sendall(b"\x7e\x00\x01\x02\x03")
            time.sleep(0.3)
            s.close()
        except Exception:
            pass
        t.check(daemon_is_alive(t.daemon_proc), "Daemon alive after partial HDLC")

        # --- Test 3: Oversized HDLC-like frame ---
        try:
            s = raw_tcp_connect("127.0.0.1", data_port)
            s.sendall(b"\x7e" + (b"\xAA" * 500_000) + b"\x7e")
            time.sleep(0.5)
            s.close()
        except Exception:
            pass
        t.check(daemon_is_alive(t.daemon_proc), "Daemon alive after oversized HDLC")

        # --- Test 4: Client crash cleans up session ---
        dir_crash = t.make_client_dir("crash_client", mode="tcp",
                                       ports={"data_port": data_port, "ctrl_port": ctrl_port})
        result_crash = os.path.join(dir_crash, "result.json")
        proc = run_shared_client(
            CLIENT_CRASH_SCRIPT,
            [dir_crash, result_crash, "probe", "crash"],
        )
        wait_client(proc, timeout=15)
        res = read_result(result_crash)
        t.check(res is not None and res.get("attached"), "Crash client attached before exit")
        time.sleep(1)
        t.check(daemon_is_alive(t.daemon_proc), "Daemon alive after crash client")

        # --- Test 5: Half-open data connection ---
        try:
            s = raw_tcp_connect("127.0.0.1", data_port)
            time.sleep(2)
            s.close()
        except Exception:
            pass
        t.check(daemon_is_alive(t.daemon_proc), "Daemon alive after half-open data connection")

        # --- Test 6: Rapid connect/disconnect on data port ---
        for _ in range(50):
            try:
                s = raw_tcp_connect("127.0.0.1", data_port)
                s.close()
            except Exception:
                pass
        time.sleep(1)
        t.check(daemon_is_alive(t.daemon_proc), "Daemon alive after 50 rapid data cycles")

        # --- Test 7: Garbage bytes to control port ---
        try:
            s = raw_tcp_connect("127.0.0.1", ctrl_port)
            s.sendall(os.urandom(128))
            time.sleep(0.5)
            s.close()
        except Exception:
            pass
        t.check(daemon_is_alive(t.daemon_proc), "Daemon alive after garbage to control port")

        # --- Test 8: Invalid auth — wrong HMAC response ---
        try:
            s = raw_tcp_connect("127.0.0.1", ctrl_port)
            challenge = read_wire_message(s)
            assert challenge.startswith(b"#CHALLENGE#")
            # Send a bogus HMAC response.
            write_wire_message(s, b"{sha256}" + os.urandom(32))
            result_msg = read_wire_message(s)
            t.check(result_msg == b"#FAILURE#", "Invalid auth gets FAILURE response")
            s.close()
        except Exception as e:
            t.check(False, f"Invalid auth test failed: {e}")
        t.check(daemon_is_alive(t.daemon_proc), "Daemon alive after invalid auth")

        # --- Test 9: Auth timeout (connect control, don't send anything) ---
        try:
            s = raw_tcp_connect("127.0.0.1", ctrl_port)
            # Read the challenge but never respond.
            challenge = read_wire_message(s)
            time.sleep(2)
            s.close()
        except Exception:
            pass
        t.check(daemon_is_alive(t.daemon_proc), "Daemon alive after auth timeout")

        # --- Final: verify a real Python RNS client can still attach ---
        dir_final = t.make_client_dir("final_client", mode="tcp",
                                       ports={"data_port": data_port, "ctrl_port": ctrl_port})
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
