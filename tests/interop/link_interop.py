#!/usr/bin/env python3
"""Link E2E interop test: Python client establishes a Link to Rust node via rnsd.

Topology:
  rnsd (transport=yes, TCP server on localhost:4244)
  Rust node connects as TCP client to rnsd
  Python client connects as TCP client to rnsd
  Python discovers Rust via announce, then establishes a Link

Assertions:
  1. Rust announce received by Python
  2. Link established (Rust prints LINK_ESTABLISHED)
  3. Python sends data over link, Rust receives LINK_DATA
  4. Link teardown works (Rust prints LINK_CLOSED)

Usage:
  cd tests/interop
  uv run python link_interop.py --rust-binary ../../target/debug/rete-linux

Or build first:
  cargo build -p rete-example-linux
  cd tests/interop && uv run python link_interop.py
"""

import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

from interop_helpers import write_rnsd_config, wait_for_port, read_stdout_lines


def main():
    parser = argparse.ArgumentParser(description="rete link interop test")
    parser.add_argument(
        "--rust-binary",
        default="../../target/debug/rete-linux",
        help="Path to the rete-linux binary",
    )
    parser.add_argument(
        "--port", type=int, default=4244, help="TCP port for rnsd"
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

    tmpdir = tempfile.mkdtemp(prefix="rete_link_interop_")
    rnsd_config_dir = os.path.join(tmpdir, "rnsd_config")
    procs = []
    passed = 0
    failed = 0
    stop_event = threading.Event()

    try:
        # --- Step 1: Start rnsd ---
        print(f"[link-interop] setting up rnsd config in {rnsd_config_dir}")
        write_rnsd_config(rnsd_config_dir, args.port)

        print(f"[link-interop] starting rnsd on port {args.port}...")
        rnsd_proc = subprocess.Popen(
            [sys.executable, "-m", "RNS.Utilities.rnsd", "--config", rnsd_config_dir],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(rnsd_proc)

        if not wait_for_port("127.0.0.1", args.port, timeout=15.0):
            print("[link-interop] FAIL: rnsd did not start listening within 15s")
            if rnsd_proc.poll() is not None:
                stderr = rnsd_proc.stderr.read().decode(errors="replace")
                print(f"  rnsd stderr:\n{stderr}")
            sys.exit(1)
        print("[link-interop] rnsd is listening")

        # --- Step 2: Start Rust node with stdin piped ---
        print("[link-interop] starting Rust node...")
        rust_proc = subprocess.Popen(
            [
                rust_binary,
                "--connect", f"127.0.0.1:{args.port}",
                "--identity-seed", "link-interop-test-seed-77",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(rust_proc)

        # Start thread to collect Rust stdout
        rust_lines = []
        rust_reader = threading.Thread(
            target=read_stdout_lines, args=(rust_proc, rust_lines, stop_event)
        )
        rust_reader.daemon = True
        rust_reader.start()

        # Give the Rust node time to connect and send its announce
        time.sleep(3)

        # --- Step 3: Write and start Python client helper ---
        py_helper = os.path.join(tmpdir, "py_link_client.py")
        with open(py_helper, "w") as f:
            f.write(f"""\
import RNS
import time
import sys
import os
import threading

# Create a Reticulum config that connects as a TCP client
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

# Track link events
link_established = threading.Event()
link_data_received = threading.Event()
link_closed = threading.Event()
received_data = [None]
active_link = [None]

def link_established_cb(link):
    print(f"PY_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
    active_link[0] = link
    link_established.set()

def link_closed_cb(link):
    print(f"PY_LINK_CLOSED:{{link.link_id.hex()}}", flush=True)
    link_closed.set()

# Create our own identity and destination (for Rust to link to us)
py_identity = RNS.Identity()
py_dest = RNS.Destination(
    py_identity,
    RNS.Destination.IN,
    RNS.Destination.SINGLE,
    "rete",
    "example",
    "v1",
)

# Set link established callback on OUR destination (for inbound links)
def inbound_link_established(link):
    print(f"PY_INBOUND_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
    active_link[0] = link
    link.set_link_closed_callback(link_closed_cb)
    # Set packet callback on the link
    def link_packet_cb(data, packet):
        text = data.decode("utf-8", errors="replace")
        print(f"PY_LINK_DATA_RECEIVED:{{text}}", flush=True)
        link_data_received.set()
    link.set_packet_callback(link_packet_cb)
    link_established.set()

py_dest.set_link_established_callback(inbound_link_established)

# Announce our destination so Rust can discover us
py_dest.announce()
print(f"PY_DEST_HASH:{{py_dest.hexhash}}", flush=True)
print(f"PY_IDENTITY_HASH:{{py_identity.hexhash}}", flush=True)
print("PY_ANNOUNCE_SENT", flush=True)

# Also try to discover Rust and establish an outbound link
timeout = {args.timeout}
deadline = time.time() + timeout
rust_dest_hash = None

print("PY_WAITING_FOR_ANNOUNCE", flush=True)

while time.time() < deadline:
    known = RNS.Transport.path_table
    for h in known:
        if h != py_dest.hash:
            rust_dest_hash = h
            print(f"PY_DISCOVERED:{{h.hex()}}", flush=True)
            break
    if rust_dest_hash:
        break
    time.sleep(0.5)

if not rust_dest_hash:
    print("PY_FAIL:timeout_waiting_for_rust_announce", flush=True)
    # Still wait for possible inbound link from Rust
    if link_established.wait(timeout=10):
        print("PY_INBOUND_LINK_OK", flush=True)
    else:
        print("PY_FAIL:no_link_established", flush=True)
        sys.exit(1)

# Try outbound link from Python to Rust
if rust_dest_hash:
    rust_identity = RNS.Identity.recall(rust_dest_hash)
    if rust_identity:
        rust_dest = RNS.Destination(
            rust_identity,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            "rete",
            "example",
            "v1",
        )
        print(f"PY_RUST_DEST_HASH:{{rust_dest.hexhash}}", flush=True)
        print("PY_INITIATING_LINK", flush=True)
        link = RNS.Link(rust_dest, established_callback=link_established_cb, closed_callback=link_closed_cb)

        # Wait for link establishment
        if not link_established.wait(timeout=15):
            print(f"PY_LINK_TIMEOUT:status={{link.status}}", flush=True)
        else:
            print("PY_LINK_ACTIVE", flush=True)

            # Send data over the link
            pkt = RNS.Packet(link, b"hello via link from python")
            pkt.send()
            print("PY_LINK_DATA_SENT", flush=True)

            # Give time for data to arrive
            time.sleep(3)

            # Teardown the link
            link.teardown()
            print("PY_LINK_TEARDOWN_SENT", flush=True)
            time.sleep(2)
    else:
        print("PY_FAIL:identity_not_recalled", flush=True)

print("PY_DONE", flush=True)
""")

        print("[link-interop] starting Python client...")
        py_proc = subprocess.Popen(
            [sys.executable, py_helper],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(py_proc)

        # --- Step 4: Collect results ---
        print(f"[link-interop] waiting up to {args.timeout}s for results...")

        # Wait for Python helper to complete
        try:
            py_stdout, py_stderr = py_proc.communicate(timeout=args.timeout + 15)
        except subprocess.TimeoutExpired:
            py_proc.kill()
            py_stdout, py_stderr = py_proc.communicate()

        py_output = py_stdout.decode(errors="replace")
        py_err_output = py_stderr.decode(errors="replace")

        print("[link-interop] Python helper output:")
        for line in py_output.strip().split("\n"):
            print(f"  {line}")

        # Give the Rust node a moment to finish processing
        time.sleep(2)

        # Stop reader, terminate Rust node, collect remaining output
        stop_event.set()
        rust_proc.send_signal(signal.SIGTERM)
        try:
            _, rust_stderr = rust_proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            rust_proc.kill()
            _, rust_stderr = rust_proc.communicate()

        rust_err_output = rust_stderr.decode(errors="replace")
        rust_output = "\n".join(rust_lines)

        print("[link-interop] Rust node stdout:")
        for line in rust_lines:
            if line.strip():
                print(f"  {line}")

        print("[link-interop] Rust node stderr (last 1000 chars):")
        for line in rust_err_output[-1000:].strip().split("\n"):
            if line.strip():
                print(f"  {line}")

        # --- Assertion 1: Python discovered Rust announce ---
        if "PY_DISCOVERED:" in py_output:
            print("[link-interop] PASS [1/4]: Python discovered Rust announce")
            passed += 1
        else:
            print("[link-interop] FAIL [1/4]: Python did not discover Rust announce")
            if py_err_output:
                print(f"  Python stderr (last 500 chars):\n  {py_err_output[-500:]}")
            failed += 1

        # --- Assertion 2: Link established ---
        rust_link_established = any(l.startswith("LINK_ESTABLISHED:") for l in rust_lines)
        py_link_established = "PY_LINK_ESTABLISHED:" in py_output or "PY_LINK_ACTIVE" in py_output or "PY_INBOUND_LINK_ESTABLISHED:" in py_output

        if rust_link_established and py_link_established:
            print("[link-interop] PASS [2/4]: Link established (both sides)")
            passed += 1
        elif rust_link_established:
            # Rust side established but Python timed out.
            # This indicates the LRPROOF may not be routing through rnsd correctly.
            print("[link-interop] FAIL [2/4]: Link established on Rust but Python timed out")
            print("  This may indicate LRPROOF routing through rnsd is not working.")
            if "PY_LINK_TIMEOUT:" in py_output:
                for line in py_output.split("\n"):
                    if "PY_LINK_TIMEOUT:" in line:
                        print(f"  {line}")
            failed += 1
        elif py_link_established:
            print("[link-interop] FAIL [2/4]: Link established on Python but not Rust")
            failed += 1
        else:
            print("[link-interop] FAIL [2/4]: Link not established on either side")
            failed += 1

        # --- Assertion 3: Python sends data, Rust receives LINK_DATA ---
        rust_link_data = [l for l in rust_lines if l.startswith("LINK_DATA:")]
        if any("hello via link from python" in l for l in rust_link_data):
            print("[link-interop] PASS [3/4]: Rust received link data from Python")
            passed += 1
        else:
            print("[link-interop] FAIL [3/4]: Rust did not receive link data from Python")
            if rust_link_data:
                print(f"  Rust LINK_DATA lines: {rust_link_data}")
            elif not (rust_link_established and py_link_established):
                print("  (link was not established on both sides)")
            failed += 1

        # --- Assertion 4: Link teardown ---
        rust_link_closed = any(l.startswith("LINK_CLOSED:") for l in rust_lines)
        if rust_link_closed:
            print("[link-interop] PASS [4/4]: Link teardown confirmed (Rust received LINK_CLOSED)")
            passed += 1
        else:
            print("[link-interop] FAIL [4/4]: Rust did not receive link close")
            if not (rust_link_established and py_link_established):
                print("  (link was not established on both sides)")
            failed += 1

    finally:
        # Cleanup
        print("[link-interop] cleaning up...")
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
    print(f"\n[link-interop] Results: {passed}/{total} passed, {failed}/{total} failed")

    if failed > 0:
        sys.exit(1)
    else:
        print("[link-interop] ALL TESTS PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
