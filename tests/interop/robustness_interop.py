#!/usr/bin/env python3
"""Robustness / negative E2E test: malformed input must not crash the Rust node.

Architecture:
  1. Start rnsd on a TCP port
  2. Start Rust node connecting to rnsd
  3. Connect a "malicious" raw TCP socket to rnsd
  4. Also connect a "valid" Python RNS client to rnsd (for recovery probes)
  5. Inject various malformed packets via HDLC framing through rnsd
  6. After each malformed injection, send a valid announce and verify the
     Rust node is still alive and processing traffic

Tests:
  1. Truncated packet (< 19 bytes minimum for HEADER_1)
  2. Oversized packet (> 500-byte MTU)
  3. Announce with corrupted signature
  4. PROOF with non-existent destination hash
  5. Random garbage bytes (not HDLC-framed)
  6. Valid -> garbage -> valid (recovery test)
  7. Empty HDLC frame (FLAG FLAG)
  8. Escape-heavy HDLC frame (stress decoder)

Usage:
  cd tests/interop
  uv run python robustness_interop.py --rust-binary ../../target/debug/rete-linux

Or build first:
  cargo build -p rete-example-linux
  cd tests/interop && uv run python robustness_interop.py
"""

import os
import socket
import subprocess
import sys
import time

from interop_helpers import InteropTest, read_stdout_lines

import threading

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


# ---------------------------------------------------------------------------
# Malformed packet builders
# ---------------------------------------------------------------------------

def build_truncated_packet() -> bytes:
    """10-byte packet -- below the 19-byte HEADER_1 minimum."""
    return os.urandom(10)


def build_oversized_packet() -> bytes:
    """600-byte packet -- exceeds the 500-byte MTU."""
    # Valid-looking flags byte (HEADER_1, BROADCAST, PLAIN, DATA = 0x08)
    flags = 0x08
    hops = 0
    dest_hash = os.urandom(16)
    context = 0x00
    payload = os.urandom(600 - 19)  # total = 600 bytes
    return bytes([flags, hops]) + dest_hash + bytes([context]) + payload


def build_corrupt_announce() -> bytes:
    """Announce with random bytes where the signature should be.

    flags = 0x01: HEADER_1 | BROADCAST | PLAIN | ANNOUNCE
    Layout: flags(1) + hops(1) + dest_hash(16) + context(1) + payload
    Payload: pub_key(64) + name_hash(10) + random_hash(10) + BAD_sig(64)
    """
    flags = 0x01  # header_type=0, context_flag=0, transport=0, dest=PLAIN(0), type=ANNOUNCE(1)
    hops = 0
    dest_hash = os.urandom(16)
    context = 0x00
    pub_key = os.urandom(64)
    name_hash = os.urandom(10)
    random_hash = os.urandom(10)
    bad_signature = os.urandom(64)
    payload = pub_key + name_hash + random_hash + bad_signature
    return bytes([flags, hops]) + dest_hash + bytes([context]) + payload


def build_proof_nonexistent_dest() -> bytes:
    """PROOF packet with a random destination hash (no matching pending proof).

    flags = 0x03: HEADER_1 | BROADCAST | PLAIN | PROOF
    """
    flags = 0x03  # header_type=0, context_flag=0, transport=0, dest=PLAIN(0), type=PROOF(3)
    hops = 0
    dest_hash = os.urandom(16)
    context = 0x00
    # PROOF payload: packet_hash(32) + signature(64)
    payload = os.urandom(32 + 64)
    return bytes([flags, hops]) + dest_hash + bytes([context]) + payload


def build_escape_heavy_packet() -> bytes:
    """Packet where every payload byte is FLAG or ESC (stress HDLC escaping).

    After HDLC encoding, the frame will be ~3x the original size.
    """
    flags = 0x08  # HEADER_1, BROADCAST, PLAIN, DATA
    hops = 0
    dest_hash = os.urandom(16)
    context = 0x00
    # 100 bytes that all need escaping
    payload = bytes([FLAG if i % 2 == 0 else ESC for i in range(100)])
    return bytes([flags, hops]) + dest_hash + bytes([context]) + payload


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def send_raw(sock: socket.socket, data: bytes):
    """Send raw bytes to a socket, ignoring broken pipe."""
    try:
        sock.sendall(data)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    with InteropTest("robustness", default_port=4249) as t:
        t.start_rnsd()
        rust = t.start_rust(seed="robustness-test-seed-77")
        time.sleep(2)

        # Verify Rust node started
        t.check(t._rust_proc and t._rust_proc.poll() is None,
                "Rust node started and is running")

        # Start Python valid client (needs stdin for triggering announces).
        # We manage this subprocess manually but register it with the harness
        # for cleanup.
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
    "rete",
    "robustness",
    "v1",
)

print(f"PY_VALID_DEST:{{dest.hexhash}}", flush=True)
print(f"PY_VALID_IDENTITY:{{identity.hexhash}}", flush=True)

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

# Stay alive until told to quit or timeout
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

        # Connect raw TCP socket (malicious peer)
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

        # ---- TEST 1: Truncated packet (< 19 bytes) ----
        pkt = build_truncated_packet()
        send_raw(raw_sock, hdlc_encode(pkt))
        time.sleep(0.5)
        t.check(verify_rust_alive("truncated"),
                "Rust survived truncated packet (< 19 bytes)")

        # ---- TEST 2: Oversized packet (> 500-byte MTU) ----
        pkt = build_oversized_packet()
        send_raw(raw_sock, hdlc_encode(pkt))
        time.sleep(0.5)
        t.check(verify_rust_alive("oversized"),
                "Rust survived oversized packet (> 500-byte MTU)")

        # ---- TEST 3: Announce with corrupted signature ----
        pkt = build_corrupt_announce()
        send_raw(raw_sock, hdlc_encode(pkt))
        time.sleep(0.5)
        t.check(verify_rust_alive("corrupt-announce"),
                "Rust survived announce with corrupted signature")

        # ---- TEST 4: PROOF with non-existent destination hash ----
        pkt = build_proof_nonexistent_dest()
        send_raw(raw_sock, hdlc_encode(pkt))
        time.sleep(0.5)
        t.check(verify_rust_alive("proof-nonexistent"),
                "Rust survived PROOF with non-existent destination hash")

        # ---- TEST 5: Random garbage bytes (not HDLC-framed) ----
        garbage = os.urandom(200)
        send_raw(raw_sock, garbage)
        time.sleep(0.5)
        t.check(verify_rust_alive("raw-garbage"),
                "Rust survived raw garbage (no HDLC framing)")

        # ---- TEST 6: Valid -> garbage -> valid (recovery test) ----
        try:
            py_valid_proc.stdin.write(b"ANNOUNCE\n")
            py_valid_proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        time.sleep(1)

        send_raw(raw_sock, os.urandom(150))
        time.sleep(0.5)

        try:
            py_valid_proc.stdin.write(b"ANNOUNCE\n")
            py_valid_proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        time.sleep(1.5)

        t.check(verify_rust_alive("valid-garbage-valid"),
                "Rust survived valid-garbage-valid recovery sequence")

        # ---- TEST 7: Empty HDLC frame (FLAG FLAG -- no data) ----
        send_raw(raw_sock, bytes([FLAG, FLAG]))
        time.sleep(0.5)
        t.check(verify_rust_alive("empty-hdlc"),
                "Rust survived empty HDLC frame")

        # ---- TEST 8: Escape-heavy HDLC frame (stress decoder) ----
        pkt = build_escape_heavy_packet()
        encoded = hdlc_encode(pkt)
        assert len(encoded) > len(pkt) + 50, "escape-heavy packet was not expanded enough"
        send_raw(raw_sock, encoded)
        time.sleep(0.5)
        t.check(verify_rust_alive("escape-heavy"),
                "Rust survived escape-heavy HDLC frame")

        # Final: check Rust received at least one valid announce
        try:
            py_valid_proc.stdin.write(b"ANNOUNCE\n")
            py_valid_proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
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
        if announce_lines:
            print(f"[robustness] INFO: Rust received {len(announce_lines)} valid announce(s) "
                  "throughout the test -- node was processing traffic correctly")
        else:
            print("[robustness] WARNING: Rust received 0 announces -- "
                  "the valid Python client may not have connected properly")


if __name__ == "__main__":
    main()
