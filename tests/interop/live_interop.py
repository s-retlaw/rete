#!/usr/bin/env python3
"""Live interop test: Rust rete node <-> Python rnsd over TCP.

Tests:
  1. Python sends an announce, Rust node receives and validates it
  2. Rust sends an announce, Python sees it via Transport.has_path()

Usage:
  cd tests/interop
  uv run python live_interop.py --rust-binary ../../target/debug/rete-linux

Or build first:
  cargo build -p rete-example-linux
  cd tests/interop && uv run python live_interop.py
"""

import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time


def write_rnsd_config(config_dir: str, port: int = 4242) -> str:
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
    import socket

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.2)
    return False


def main():
    parser = argparse.ArgumentParser(description="rete live interop test")
    parser.add_argument(
        "--rust-binary",
        default="../../target/debug/rete-linux",
        help="Path to the rete-linux binary",
    )
    parser.add_argument(
        "--port", type=int, default=4242, help="TCP port for rnsd"
    )
    parser.add_argument(
        "--timeout", type=float, default=30.0, help="Test timeout in seconds"
    )
    args = parser.parse_args()

    rust_binary = os.path.abspath(args.rust_binary)
    if not os.path.exists(rust_binary):
        print(f"FAIL: Rust binary not found at {rust_binary}")
        print("  Build it with: cargo build -p rete-example-linux")
        sys.exit(1)

    tmpdir = tempfile.mkdtemp(prefix="rete_interop_")
    rnsd_config_dir = os.path.join(tmpdir, "rnsd_config")
    procs = []
    passed = 0
    failed = 0

    try:
        # --- Step 1: Start rnsd ---
        print(f"[interop] setting up rnsd config in {rnsd_config_dir}")
        write_rnsd_config(rnsd_config_dir, args.port)

        print(f"[interop] starting rnsd on port {args.port}...")
        rnsd_proc = subprocess.Popen(
            [sys.executable, "-m", "RNS.Utilities.rnsd", "--config", rnsd_config_dir],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(rnsd_proc)

        if not wait_for_port("127.0.0.1", args.port, timeout=15.0):
            print("FAIL: rnsd did not start listening within 15s")
            # Print any stderr from rnsd for debugging
            if rnsd_proc.poll() is not None:
                stderr = rnsd_proc.stderr.read().decode(errors="replace")
                print(f"  rnsd stderr:\n{stderr}")
            sys.exit(1)
        print("[interop] rnsd is listening")

        # --- Step 2: Create a Python destination and announce ---
        print("[interop] creating Python identity and destination...")
        # We do this in a subprocess to avoid conflicts with rnsd's
        # shared instance model — rnsd is the primary instance, we
        # connect to it as a client.
        #
        # Actually, since share_instance=no, we can't use the shared
        # instance model. Instead, we'll create a separate Python
        # script that connects as a TCP client and announces.
        #
        # For simplicity, let's write a helper script.
        py_helper = os.path.join(tmpdir, "py_announce.py")
        with open(py_helper, "w") as f:
            f.write(f"""\
import RNS
import time
import sys
import os
import threading

# Create a separate Reticulum config that connects as a TCP client
config_dir = os.path.join("{tmpdir}", "py_client_config")
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

# Initialize
reticulum = RNS.Reticulum(configdir=config_dir)

# Track received data
data_received = threading.Event()

def packet_callback(data, packet):
    text = data.decode("utf-8", errors="replace")
    print(f"PY_DATA_RECEIVED:{{text}}", flush=True)
    data_received.set()

# Create identity and destination
identity = RNS.Identity()
dest = RNS.Destination(
    identity,
    RNS.Destination.IN,
    RNS.Destination.SINGLE,
    "rete",
    "example",
    "v1",
)
dest.set_packet_callback(packet_callback)

print(f"PY_DEST_HASH:{{dest.hexhash}}", flush=True)
print(f"PY_IDENTITY_HASH:{{identity.hexhash}}", flush=True)

# Send announce
dest.announce()
print("PY_ANNOUNCE_SENT", flush=True)

# Wait for Rust announce to appear
timeout = {args.timeout}
deadline = time.time() + timeout
rust_dest_hash = None

while time.time() < deadline:
    known = RNS.Transport.path_table
    for h in known:
        if h != dest.hash:
            rust_dest_hash = h
            print(f"PY_DISCOVERED:{{h.hex()}}", flush=True)
            break
    if rust_dest_hash:
        break
    time.sleep(0.5)

if rust_dest_hash:
    print("PY_INTEROP_OK", flush=True)

    # Send DATA to Rust node
    rust_identity = RNS.Identity.recall(rust_dest_hash)
    if rust_identity:
        out_dest = RNS.Destination(
            rust_identity,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            "rete",
            "example",
            "v1",
        )
        pkt = RNS.Packet(out_dest, b"hello from python")
        pkt.send()
        print("PY_DATA_SENT", flush=True)
    else:
        print("PY_DATA_SEND_FAIL:identity_not_recalled", flush=True)

    # Wait for DATA from Rust (auto-reply)
    if data_received.wait(timeout=10):
        print("PY_DATA_RECV_OK", flush=True)
    else:
        print("PY_DATA_RECV_FAIL:timeout", flush=True)
else:
    print("PY_INTEROP_FAIL:timeout_waiting_for_rust_announce", flush=True)

# Keep alive briefly for any remaining data exchange
time.sleep(2)
print("PY_DONE", flush=True)
""")

        # --- Step 3: Start Rust node ---
        print("[interop] starting Rust node...")
        rust_proc = subprocess.Popen(
            [
                rust_binary,
                "--connect", f"127.0.0.1:{args.port}",
                "--identity-seed", "interop-test-seed-42",
                "--auto-reply", "hello from rust",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(rust_proc)
        # Give the Rust node a moment to connect and announce
        time.sleep(2)

        # --- Step 4: Start Python client ---
        print("[interop] starting Python client...")
        py_proc = subprocess.Popen(
            [sys.executable, py_helper],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(py_proc)

        # --- Step 5: Collect results ---
        print(f"[interop] waiting up to {args.timeout}s for results...")

        # Wait for Python helper to complete
        try:
            py_stdout, py_stderr = py_proc.communicate(timeout=args.timeout + 10)
        except subprocess.TimeoutExpired:
            py_proc.kill()
            py_stdout, py_stderr = py_proc.communicate()

        py_output = py_stdout.decode(errors="replace")
        py_err_output = py_stderr.decode(errors="replace")

        print("[interop] Python helper output:")
        for line in py_output.strip().split("\n"):
            print(f"  {line}")

        # Check Python results
        if "PY_ANNOUNCE_SENT" in py_output:
            print("[interop] PASS: Python announce sent")
            passed += 1
        else:
            print("[interop] FAIL: Python announce not sent")
            failed += 1

        if "PY_INTEROP_OK" in py_output:
            print("[interop] PASS: Python discovered Rust announce")
            passed += 1
        else:
            print("[interop] FAIL: Python did not discover Rust announce")
            if py_err_output:
                print(f"  Python stderr (last 500 chars):\n  {py_err_output[-500:]}")
            failed += 1

        # Give the Rust node a moment to process the Python announce
        time.sleep(2)

        # Check Rust output (terminate it first)
        rust_proc.send_signal(signal.SIGTERM)
        try:
            rust_stdout, rust_stderr = rust_proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            rust_proc.kill()
            rust_stdout, rust_stderr = rust_proc.communicate()

        rust_output = rust_stdout.decode(errors="replace")
        rust_err_output = rust_stderr.decode(errors="replace")

        print("[interop] Rust node stdout:")
        for line in rust_output.strip().split("\n"):
            if line.strip():
                print(f"  {line}")

        print("[interop] Rust node stderr (last 500 chars):")
        for line in rust_err_output[-500:].strip().split("\n"):
            if line.strip():
                print(f"  {line}")

        # Check if Rust received an announce
        if "ANNOUNCE:" in rust_output:
            print("[interop] PASS: Rust received Python announce")
            passed += 1
        else:
            print("[interop] FAIL: Rust did not receive Python announce")
            failed += 1

        # Check if Python received DATA from Rust (auto-reply)
        if "PY_DATA_RECEIVED:" in py_output:
            print("[interop] PASS: Rust->Python DATA received by Python")
            passed += 1
        else:
            print("[interop] FAIL: Python did not receive DATA from Rust")
            failed += 1

        # Check if Rust received DATA from Python
        rust_data_lines = [l for l in rust_output.strip().split("\n")
                           if l.startswith("DATA:")]
        if any("hello from python" in l for l in rust_data_lines):
            print("[interop] PASS: Python->Rust DATA received by Rust")
            passed += 1
        else:
            print("[interop] FAIL: Rust did not receive DATA from Python")
            if rust_data_lines:
                print(f"  Rust DATA lines: {rust_data_lines}")
            failed += 1

    finally:
        # Cleanup
        print("[interop] cleaning up...")
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
    print(f"\n[interop] Results: {passed}/{total} passed, {failed}/{total} failed")

    if failed > 0:
        sys.exit(1)
    else:
        print("[interop] ALL TESTS PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
