#!/usr/bin/env python3
"""HDLC recovery E2E test: partial frames, FLAG storms, zero-length payloads.

Extends robustness testing with HDLC-specific edge cases that could trip up
the framing layer.

Topology:
  rnsd (transport=yes, TCP server on localhost:4310)
  Rust node connects as TCP client
  Python valid client connects as TCP client (for recovery probes)
  Raw TCP socket injects malformed HDLC sequences

Assertions:
  1. Rust survived partial HDLC + valid frame recovery
  2. Rust survived zero-length DATA
  3. Rust survived FLAG storm
  4. Rust still processing valid announces after abuse

Usage:
  cd tests/interop
  uv run python hdlc_recovery_interop.py --rust-binary ../../target/debug/rete-linux
"""

import os
import socket
import subprocess
import sys
import threading
import time

from interop_helpers import InteropTest, read_stdout_lines

# ---------------------------------------------------------------------------
# HDLC framing
# ---------------------------------------------------------------------------

FLAG = 0x7E
ESC = 0x7D
ESC_MASK = 0x20


def hdlc_encode(data: bytes) -> bytes:
    """HDLC-encode a packet (FLAG + escaped payload + FLAG)."""
    out = bytearray([FLAG])
    for b in data:
        if b == FLAG or b == ESC:
            out.append(ESC)
            out.append(b ^ ESC_MASK)
        else:
            out.append(b)
    out.append(FLAG)
    return bytes(out)


def send_raw(sock: socket.socket, data: bytes):
    """Send raw bytes to a socket, ignoring broken pipe."""
    try:
        sock.sendall(data)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass


def main():
    with InteropTest("hdlc-recovery", default_port=4310) as t:
        t.start_rnsd()
        rust = t.start_rust(seed="hdlc-recovery-test-seed-55")
        time.sleep(2)

        # Verify Rust node started
        t.check(t._rust_proc and t._rust_proc.poll() is None,
                "Rust node started and is running")

        # Start Python valid client for recovery probes
        py_valid_script = os.path.join(t.tmpdir, "py_valid_client.py")
        with open(py_valid_script, "w") as f:
            f.write(f"""\
import RNS
import time
import os
import sys
import threading

config_dir = os.path.join("{t.tmpdir}", "py_valid_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config()}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

identity = RNS.Identity()
dest = RNS.Destination(
    identity,
    RNS.Destination.IN,
    RNS.Destination.SINGLE,
    "rete", "hdlc", "v1",
)

print(f"PY_VALID_DEST:{{dest.hexhash}}", flush=True)

def announce_on_signal():
    for line in sys.stdin:
        line = line.strip()
        if line == "ANNOUNCE":
            dest.announce()
            print("PY_VALID_ANNOUNCED", flush=True)
        elif line == "QUIT":
            break

t = threading.Thread(target=announce_on_signal, daemon=True)
t.start()

# Initial announce
dest.announce()
print("PY_VALID_ANNOUNCED", flush=True)

deadline = time.time() + {t.timeout + 30}
while time.time() < deadline:
    time.sleep(0.5)

print("PY_VALID_DONE", flush=True)
""")

        py_valid_proc = subprocess.Popen(
            [sys.executable, py_valid_script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        t._procs.append(py_valid_proc)

        py_valid_lines = []
        py_reader = threading.Thread(
            target=read_stdout_lines,
            args=(py_valid_proc, py_valid_lines, t._stop),
            daemon=True,
        )
        py_reader.start()

        time.sleep(3)  # Let valid client connect and send initial announce

        # Connect raw TCP socket
        raw_sock = socket.create_connection(("127.0.0.1", t.port), timeout=5.0)
        raw_sock.settimeout(2.0)
        time.sleep(1)

        # Helper: trigger a valid announce and verify Rust is still alive
        def verify_rust_alive(test_name):
            try:
                py_valid_proc.stdin.write(b"ANNOUNCE\n")
                py_valid_proc.stdin.flush()
            except (BrokenPipeError, OSError):
                pass
            time.sleep(1.5)
            return t._rust_proc and t._rust_proc.poll() is None

        # ---- TEST 1: Partial HDLC frame (FLAG + 10 bytes, no closing FLAG) ----
        # Then immediately send a valid HDLC frame
        partial = bytes([FLAG]) + os.urandom(10)  # No closing FLAG
        send_raw(raw_sock, partial)
        time.sleep(0.3)

        # Build a valid-looking packet and HDLC-encode it
        valid_flags = 0x08  # HEADER_1, BROADCAST, PLAIN, DATA
        valid_pkt = bytes([valid_flags, 0]) + os.urandom(16) + bytes([0x00]) + b"recovery"
        send_raw(raw_sock, hdlc_encode(valid_pkt))
        time.sleep(0.5)
        t.check(verify_rust_alive("partial-hdlc"),
                "Rust survived partial HDLC + valid frame recovery")

        # ---- TEST 2: Zero-length-payload packet ----
        # Valid header (19 bytes minimum for HEADER_1) but no payload
        zero_flags = 0x08  # HEADER_1, BROADCAST, PLAIN, DATA
        zero_pkt = bytes([zero_flags, 0]) + os.urandom(16) + bytes([0x00])
        send_raw(raw_sock, hdlc_encode(zero_pkt))
        time.sleep(0.5)
        t.check(verify_rust_alive("zero-length"),
                "Rust survived zero-length DATA payload")

        # ---- TEST 3: FLAG storm (50 consecutive FLAG bytes) ----
        flag_storm = bytes([FLAG] * 50)
        send_raw(raw_sock, flag_storm)
        time.sleep(0.5)
        t.check(verify_rust_alive("flag-storm"),
                "Rust survived FLAG storm (50 consecutive FLAGs)")

        # ---- TEST 4: Valid announces still work after all abuse ----
        # Send multiple announces to ensure processing is intact
        for _ in range(3):
            try:
                py_valid_proc.stdin.write(b"ANNOUNCE\n")
                py_valid_proc.stdin.flush()
            except (BrokenPipeError, OSError):
                pass
            time.sleep(1)

        time.sleep(2)

        # Close raw socket
        try:
            raw_sock.close()
        except Exception:
            pass

        # Terminate valid Python client
        try:
            py_valid_proc.stdin.write(b"QUIT\n")
            py_valid_proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        time.sleep(1)

        # Collect output
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Rust node stdout", rust)
        t.dump_output("Rust node stderr (last 1000)", rust_stderr.strip().split("\n"))
        t.dump_output("Python valid client stdout", py_valid_lines)

        announce_lines = [l for l in rust if l.startswith("ANNOUNCE:")]
        t.check(
            len(announce_lines) >= 1,
            f"Rust still processing valid announces after abuse ({len(announce_lines)} received)",
        )


if __name__ == "__main__":
    main()
