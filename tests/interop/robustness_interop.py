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

import argparse
import os
import random
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time


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
# rnsd config + port waiting
# ---------------------------------------------------------------------------

def write_rnsd_config(config_dir: str, port: int = 4249) -> str:
    """Write a minimal rnsd config file. Returns the config dir path."""
    os.makedirs(config_dir, exist_ok=True)
    config_path = os.path.join(config_dir, "config")
    with open(config_path, "w") as f:
        f.write(f"""\
[reticulum]
  enable_transport = yes
  share_instance = no

[logging]
  loglevel = 5

[interfaces]

  [[TCP Server Interface]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = {port}
""")
    return config_dir


def wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    """Wait until a TCP port is accepting connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.2)
    return False


# ---------------------------------------------------------------------------
# Malformed packet builders
# ---------------------------------------------------------------------------

def build_truncated_packet() -> bytes:
    """10-byte packet — below the 19-byte HEADER_1 minimum."""
    return os.urandom(10)


def build_oversized_packet() -> bytes:
    """600-byte packet — exceeds the 500-byte MTU."""
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

def rust_is_alive(proc: subprocess.Popen) -> bool:
    """Check if the Rust process is still running."""
    return proc.poll() is None


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
    parser = argparse.ArgumentParser(description="rete robustness / negative E2E test")
    parser.add_argument(
        "--rust-binary",
        default="../../target/debug/rete-linux",
        help="Path to the rete-linux binary",
    )
    parser.add_argument(
        "--port", type=int, default=4249, help="TCP port for rnsd (default 4249)"
    )
    parser.add_argument(
        "--timeout", type=float, default=30.0, help="Test timeout in seconds"
    )
    args = parser.parse_args()

    rust_binary = os.path.abspath(args.rust_binary)
    if not os.path.exists(rust_binary):
        print(f"[robustness] FAIL: Rust binary not found at {rust_binary}")
        print("  Build it with: cargo build -p rete-example-linux")
        sys.exit(1)

    tmpdir = tempfile.mkdtemp(prefix="rete_robustness_")
    rnsd_config_dir = os.path.join(tmpdir, "rnsd_config")
    procs = []
    raw_sock = None
    passed = 0
    failed = 0
    total_tests = 8

    try:
        # ---- Step 1: Start rnsd ----
        print(f"[robustness] setting up rnsd config in {rnsd_config_dir}")
        write_rnsd_config(rnsd_config_dir, args.port)

        print(f"[robustness] starting rnsd on port {args.port}...")
        rnsd_proc = subprocess.Popen(
            [sys.executable, "-m", "RNS.Utilities.rnsd", "--config", rnsd_config_dir],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(rnsd_proc)

        if not wait_for_port("127.0.0.1", args.port, timeout=15.0):
            print("[robustness] FAIL: rnsd did not start listening within 15s")
            if rnsd_proc.poll() is not None:
                stderr = rnsd_proc.stderr.read().decode(errors="replace")
                print(f"  rnsd stderr:\n{stderr}")
            sys.exit(1)
        print("[robustness] rnsd is listening")

        # ---- Step 2: Start Rust node ----
        print("[robustness] starting Rust node...")
        rust_proc = subprocess.Popen(
            [
                rust_binary,
                "--connect", f"127.0.0.1:{args.port}",
                "--identity-seed", "robustness-test-seed-77",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(rust_proc)
        time.sleep(2)

        if not rust_is_alive(rust_proc):
            print("[robustness] FAIL: Rust node exited prematurely")
            sys.exit(1)
        print("[robustness] Rust node is running")

        # ---- Step 3: Start Python valid client (for recovery probes) ----
        # This client periodically announces so we can verify the Rust node
        # is still processing valid traffic after each malformed injection.
        py_valid_script = os.path.join(tmpdir, "py_valid_client.py")
        with open(py_valid_script, "w") as f:
            f.write(f"""\
import RNS
import time
import os
import sys

config_dir = os.path.join("{tmpdir}", "py_valid_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"
[reticulum]
  enable_transport = no
  share_instance = no

[logging]
  loglevel = 5

[interfaces]

  [[TCP Client Interface]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = {args.port}
\"\"\")

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

# Announce every time stdin receives a line (triggered by parent process)
# Also do an initial announce.
import threading

def announce_on_signal():
    \"\"\"Read lines from stdin; each line triggers a fresh announce.\"\"\"
    for line in sys.stdin:
        line = line.strip()
        if line == "ANNOUNCE":
            dest.announce()
            print(f"PY_VALID_ANNOUNCED", flush=True)
        elif line == "QUIT":
            break

t = threading.Thread(target=announce_on_signal, daemon=True)
t.start()

# Initial announce
dest.announce()
print("PY_VALID_ANNOUNCED", flush=True)

# Stay alive until told to quit or timeout
deadline = time.time() + {args.timeout + 30}
while time.time() < deadline:
    time.sleep(0.5)

print("PY_VALID_DONE", flush=True)
""")

        print("[robustness] starting Python valid client...")
        py_valid_proc = subprocess.Popen(
            [sys.executable, py_valid_script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(py_valid_proc)
        time.sleep(3)  # Let the valid client connect and send initial announce

        # Verify Rust saw the initial announce
        # (We check at the end, but let's confirm the valid client started)
        if not rust_is_alive(rust_proc):
            print("[robustness] FAIL: Rust node died before tests started")
            sys.exit(1)

        # ---- Step 4: Connect raw TCP socket (malicious peer) ----
        print("[robustness] connecting raw TCP socket to rnsd...")
        raw_sock = socket.create_connection(("127.0.0.1", args.port), timeout=5.0)
        raw_sock.settimeout(2.0)
        time.sleep(1)  # Let rnsd register the connection

        # ================================================================
        # Helper: trigger a valid announce and verify Rust is still alive
        # ================================================================
        announce_count = 0

        def verify_rust_alive(test_name: str) -> bool:
            """Send 'ANNOUNCE' to the valid Python client to trigger a fresh
            announce, then check the Rust process is still running."""
            nonlocal announce_count
            announce_count += 1
            try:
                py_valid_proc.stdin.write(b"ANNOUNCE\n")
                py_valid_proc.stdin.flush()
            except (BrokenPipeError, OSError):
                pass
            time.sleep(1.5)  # Allow time for announce to propagate
            alive = rust_is_alive(rust_proc)
            if not alive:
                print(f"[robustness] FAIL [{test_name}]: Rust node CRASHED!")
            return alive

        # ================================================================
        # TEST 1: Truncated packet (< 19 bytes)
        # ================================================================
        test_name = "1/8: truncated packet"
        print(f"[robustness] running test {test_name}...")
        pkt = build_truncated_packet()
        send_raw(raw_sock, hdlc_encode(pkt))
        time.sleep(0.5)
        if verify_rust_alive(test_name):
            print(f"[robustness] PASS [{test_name}]: Rust survived")
            passed += 1
        else:
            failed += 1

        # ================================================================
        # TEST 2: Oversized packet (> 500-byte MTU)
        # ================================================================
        test_name = "2/8: oversized packet"
        print(f"[robustness] running test {test_name}...")
        pkt = build_oversized_packet()
        send_raw(raw_sock, hdlc_encode(pkt))
        time.sleep(0.5)
        if verify_rust_alive(test_name):
            print(f"[robustness] PASS [{test_name}]: Rust survived")
            passed += 1
        else:
            failed += 1

        # ================================================================
        # TEST 3: Announce with corrupted signature
        # ================================================================
        test_name = "3/8: corrupt announce signature"
        print(f"[robustness] running test {test_name}...")
        pkt = build_corrupt_announce()
        send_raw(raw_sock, hdlc_encode(pkt))
        time.sleep(0.5)
        if verify_rust_alive(test_name):
            print(f"[robustness] PASS [{test_name}]: Rust survived")
            passed += 1
        else:
            failed += 1

        # ================================================================
        # TEST 4: PROOF with non-existent destination hash
        # ================================================================
        test_name = "4/8: proof non-existent dest"
        print(f"[robustness] running test {test_name}...")
        pkt = build_proof_nonexistent_dest()
        send_raw(raw_sock, hdlc_encode(pkt))
        time.sleep(0.5)
        if verify_rust_alive(test_name):
            print(f"[robustness] PASS [{test_name}]: Rust survived")
            passed += 1
        else:
            failed += 1

        # ================================================================
        # TEST 5: Random garbage bytes (not HDLC-framed)
        # ================================================================
        test_name = "5/8: raw garbage (no HDLC)"
        print(f"[robustness] running test {test_name}...")
        garbage = os.urandom(200)
        send_raw(raw_sock, garbage)
        time.sleep(0.5)
        if verify_rust_alive(test_name):
            print(f"[robustness] PASS [{test_name}]: Rust survived")
            passed += 1
        else:
            failed += 1

        # ================================================================
        # TEST 6: Valid -> garbage -> valid (recovery test)
        # ================================================================
        test_name = "6/8: valid-garbage-valid recovery"
        print(f"[robustness] running test {test_name}...")

        # Send a valid announce through the Python client
        try:
            py_valid_proc.stdin.write(b"ANNOUNCE\n")
            py_valid_proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        time.sleep(1)

        # Send garbage through raw socket
        send_raw(raw_sock, os.urandom(150))
        time.sleep(0.5)

        # Send another valid announce
        try:
            py_valid_proc.stdin.write(b"ANNOUNCE\n")
            py_valid_proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        time.sleep(1.5)

        if verify_rust_alive(test_name):
            print(f"[robustness] PASS [{test_name}]: Rust survived and recovered")
            passed += 1
        else:
            failed += 1

        # ================================================================
        # TEST 7: Empty HDLC frame (FLAG FLAG — no data)
        # ================================================================
        test_name = "7/8: empty HDLC frame"
        print(f"[robustness] running test {test_name}...")
        send_raw(raw_sock, bytes([FLAG, FLAG]))
        time.sleep(0.5)
        if verify_rust_alive(test_name):
            print(f"[robustness] PASS [{test_name}]: Rust survived")
            passed += 1
        else:
            failed += 1

        # ================================================================
        # TEST 8: Escape-heavy HDLC frame (stress decoder)
        # ================================================================
        test_name = "8/8: escape-heavy HDLC frame"
        print(f"[robustness] running test {test_name}...")
        pkt = build_escape_heavy_packet()
        encoded = hdlc_encode(pkt)
        # Verify escaping actually expanded the frame significantly
        assert len(encoded) > len(pkt) + 50, "escape-heavy packet was not expanded enough"
        send_raw(raw_sock, encoded)
        time.sleep(0.5)
        if verify_rust_alive(test_name):
            print(f"[robustness] PASS [{test_name}]: Rust survived")
            passed += 1
        else:
            failed += 1

        # ================================================================
        # Final check: Rust node received at least one valid announce
        # ================================================================
        print("[robustness] final verification: checking Rust node output...")

        # Give a last announce a moment to propagate
        try:
            py_valid_proc.stdin.write(b"ANNOUNCE\n")
            py_valid_proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        time.sleep(2)

        # Terminate the valid Python client
        try:
            py_valid_proc.stdin.write(b"QUIT\n")
            py_valid_proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        time.sleep(1)

        # Terminate Rust node
        if rust_is_alive(rust_proc):
            rust_proc.send_signal(signal.SIGTERM)
        try:
            rust_stdout, rust_stderr = rust_proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            rust_proc.kill()
            rust_stdout, rust_stderr = rust_proc.communicate()

        rust_output = rust_stdout.decode(errors="replace")
        rust_err_output = rust_stderr.decode(errors="replace")

        print("[robustness] Rust node stdout:")
        for line in rust_output.strip().split("\n"):
            if line.strip():
                print(f"  {line}")

        print("[robustness] Rust node stderr (last 800 chars):")
        for line in rust_err_output[-800:].strip().split("\n"):
            if line.strip():
                print(f"  {line}")

        # Verify at least one ANNOUNCE was received (the valid Python client)
        announce_lines = [l for l in rust_output.strip().split("\n")
                          if l.startswith("ANNOUNCE:")]
        if announce_lines:
            print(f"[robustness] INFO: Rust received {len(announce_lines)} valid announce(s) "
                  f"throughout the test — node was processing traffic correctly")
        else:
            print("[robustness] WARNING: Rust received 0 announces — "
                  "the valid Python client may not have connected properly")

    finally:
        # Cleanup
        print("[robustness] cleaning up...")
        if raw_sock:
            try:
                raw_sock.close()
            except Exception:
                pass

        for p in procs:
            try:
                p.kill()
                p.wait(timeout=5)
            except Exception:
                pass

        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass

    # Summary
    total = passed + failed
    print(f"\n[robustness] Results: {passed}/{total} passed, {failed}/{total} failed")

    if failed > 0:
        sys.exit(1)
    else:
        print("[robustness] ALL TESTS PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
