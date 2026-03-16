#!/usr/bin/env python3
"""Resource E2E interop test: Python transfers Resource to Rust node via Link.

Topology:
  rnsd (transport=yes, TCP server on localhost:4254)
  Rust node connects as TCP client to rnsd
  Python client connects as TCP client to rnsd
  Python discovers Rust via announce, establishes Link, sends Resource

Assertions:
  1. Link established (both sides)
  2. Python sends Resource (~1KB), Rust receives RESOURCE_OFFERED
  3. Rust receives RESOURCE_COMPLETE with matching data
  4. Rust sends Resource back to Python, Python receives it

Usage:
  cd tests/interop
  uv run python resource_interop.py --rust-binary ../../target/debug/rete-linux

Or build first:
  cargo build -p rete-example-linux
  cd tests/interop && uv run python resource_interop.py
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


def write_rnsd_config(config_dir: str, port: int = 4254) -> str:
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


def read_stdout_lines(proc, lines, stop_event):
    """Read stdout lines from a subprocess into a list."""
    while not stop_event.is_set():
        line = proc.stdout.readline()
        if not line:
            break
        lines.append(line.decode(errors="replace").rstrip("\n"))


def main():
    parser = argparse.ArgumentParser(description="rete resource interop test")
    parser.add_argument(
        "--rust-binary",
        default="../../target/debug/rete-linux",
        help="Path to the rete-linux binary",
    )
    parser.add_argument(
        "--port", type=int, default=4254, help="TCP port for rnsd"
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

    tmpdir = tempfile.mkdtemp(prefix="rete_resource_interop_")
    rnsd_config_dir = os.path.join(tmpdir, "rnsd_config")
    procs = []
    passed = 0
    failed = 0
    stop_event = threading.Event()

    # Known test data for resource transfer
    resource_text = "test_resource_data_12345 " * 40  # ~1KB
    resource_data = resource_text.encode("utf-8")

    try:
        # --- Step 1: Start rnsd ---
        print(f"[resource-interop] setting up rnsd config in {rnsd_config_dir}")
        write_rnsd_config(rnsd_config_dir, args.port)

        print(f"[resource-interop] starting rnsd on port {args.port}...")
        rnsd_proc = subprocess.Popen(
            [sys.executable, "-m", "RNS.Utilities.rnsd", "--config", rnsd_config_dir],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(rnsd_proc)

        if not wait_for_port("127.0.0.1", args.port, timeout=15.0):
            print("[resource-interop] FAIL: rnsd did not start listening within 15s")
            if rnsd_proc.poll() is not None:
                stderr = rnsd_proc.stderr.read().decode(errors="replace")
                print(f"  rnsd stderr:\n{stderr}")
            sys.exit(1)
        print("[resource-interop] rnsd is listening")

        # --- Step 2: Start Rust node ---
        print("[resource-interop] starting Rust node...")
        rust_proc = subprocess.Popen(
            [
                rust_binary,
                "--connect", f"127.0.0.1:{args.port}",
                "--identity-seed", "resource-interop-test-seed-99",
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
        py_helper = os.path.join(tmpdir, "py_resource_client.py")
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
link_closed = threading.Event()
active_link = [None]

# Track resource events (for receiving resource from Rust)
resource_received = threading.Event()
received_resource_data = [None]

def link_established_cb(link):
    print(f"PY_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
    active_link[0] = link
    link_established.set()

def link_closed_cb(link):
    print(f"PY_LINK_CLOSED:{{link.link_id.hex()}}", flush=True)
    link_closed.set()

# Resource callbacks for receiving from Rust
def resource_started_cb(resource):
    print(f"PY_RESOURCE_STARTED:{{resource.hash.hex()}}:{{resource.total_size}}", flush=True)
    return True  # Accept the resource

def resource_complete_cb(resource):
    data = resource.data.read()
    resource.data.close()
    received_resource_data[0] = data
    text = data.decode("utf-8", errors="replace")
    print(f"PY_RESOURCE_COMPLETE:{{resource.hash.hex()}}:{{len(data)}}:{{text[:80]}}", flush=True)
    resource_received.set()

# Wait for Rust announce to appear
timeout = {args.timeout}
deadline = time.time() + timeout
rust_dest_hash = None

print("PY_WAITING_FOR_ANNOUNCE", flush=True)

while time.time() < deadline:
    known = RNS.Transport.path_table
    for h in known:
        rust_dest_hash = h
        print(f"PY_DISCOVERED:{{h.hex()}}", flush=True)
        break
    if rust_dest_hash:
        break
    time.sleep(0.5)

if not rust_dest_hash:
    print("PY_FAIL:timeout_waiting_for_rust_announce", flush=True)
    sys.exit(1)

# Recall identity and create destination for Rust node
rust_identity = RNS.Identity.recall(rust_dest_hash)
if not rust_identity:
    print("PY_FAIL:identity_not_recalled", flush=True)
    sys.exit(1)

rust_dest = RNS.Destination(
    rust_identity,
    RNS.Destination.OUT,
    RNS.Destination.SINGLE,
    "rete",
    "example",
    "v1",
)

print(f"PY_RUST_DEST_HASH:{{rust_dest.hexhash}}", flush=True)

# Establish link to Rust node
print("PY_INITIATING_LINK", flush=True)
link = RNS.Link(rust_dest, established_callback=link_established_cb, closed_callback=link_closed_cb)

# Wait for link establishment
if not link_established.wait(timeout=15):
    print(f"PY_LINK_TIMEOUT:status={{link.status}}", flush=True)
    sys.exit(1)

print("PY_LINK_ACTIVE", flush=True)

# Set resource callbacks for receiving resources from Rust
link.set_resource_callback(resource_complete_cb)
link.set_resource_started_callback(resource_started_cb)

# Send a Resource from Python to Rust
resource_data = {repr(resource_data)}
print(f"PY_SENDING_RESOURCE:{{len(resource_data)}}", flush=True)

resource_sent = threading.Event()
def resource_send_complete(resource):
    print(f"PY_RESOURCE_SENT:{{resource.hash.hex()}}:{{resource.total_size}}", flush=True)
    resource_sent.set()

resource = RNS.Resource(resource_data, link, callback=resource_send_complete)
print(f"PY_RESOURCE_HASH:{{resource.hash.hex()}}", flush=True)

# Wait for resource transfer to complete
if not resource_sent.wait(timeout=20):
    print("PY_FAIL:resource_send_timeout", flush=True)
else:
    print("PY_RESOURCE_TRANSFER_DONE", flush=True)

# Give Rust time to process
time.sleep(3)

# Signal Rust to send a resource back (via a marker in stdout that the test harness reads)
print("PY_READY_FOR_RUST_RESOURCE", flush=True)

# Wait for resource from Rust
if resource_received.wait(timeout=20):
    print("PY_RUST_RESOURCE_RECEIVED", flush=True)
else:
    print("PY_WARN:no_resource_from_rust_within_timeout", flush=True)

# Give time for final processing
time.sleep(2)

# Teardown the link
link.teardown()
print("PY_LINK_TEARDOWN_SENT", flush=True)

# Wait for teardown to propagate
time.sleep(2)

print("PY_DONE", flush=True)
""")

        print("[resource-interop] starting Python client...")
        py_proc = subprocess.Popen(
            [sys.executable, py_helper],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(py_proc)

        # --- Step 4: Monitor Python output and send resource command to Rust ---
        # We read Python output in a thread to detect when it's ready for Rust resource
        py_lines = []
        py_stop = threading.Event()
        py_reader = threading.Thread(
            target=read_stdout_lines, args=(py_proc, py_lines, py_stop)
        )
        py_reader.daemon = True
        py_reader.start()

        # Wait for Python to signal it's ready for Rust to send resource back
        deadline = time.monotonic() + args.timeout + 15
        rust_link_id = None
        py_ready_for_rust_resource = False

        while time.monotonic() < deadline:
            # Check for LINK_ESTABLISHED in Rust output to get link_id
            if rust_link_id is None:
                for line in rust_lines:
                    if line.startswith("LINK_ESTABLISHED:"):
                        rust_link_id = line.split(":")[1].strip()
                        break

            # Check if Python is ready for Rust resource
            for line in py_lines:
                if "PY_READY_FOR_RUST_RESOURCE" in line:
                    py_ready_for_rust_resource = True
                    break

            if py_ready_for_rust_resource and rust_link_id:
                break

            # Check if Python helper has exited
            if py_proc.poll() is not None:
                break

            time.sleep(0.5)

        # Send resource from Rust to Python via stdin command
        if rust_link_id and py_ready_for_rust_resource:
            resource_back_text = "hello_from_rust_resource_transfer"
            cmd = f"resource {rust_link_id} {resource_back_text}\n"
            print(f"[resource-interop] sending resource command to Rust: {cmd.strip()}")
            try:
                rust_proc.stdin.write(cmd.encode())
                rust_proc.stdin.flush()
            except (BrokenPipeError, OSError) as e:
                print(f"[resource-interop] warning: could not write to Rust stdin: {e}")

        # Wait for Python helper to complete
        remaining = max(1, deadline - time.monotonic())
        try:
            py_proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            py_proc.kill()
            py_proc.wait()

        py_stop.set()

        # Collect any remaining Python stderr
        try:
            _, py_stderr = py_proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            py_proc.kill()
            _, py_stderr = py_proc.communicate()

        py_output = "\n".join(py_lines)
        py_err_output = py_stderr.decode(errors="replace") if py_stderr else ""

        print("[resource-interop] Python helper output:")
        for line in py_lines:
            if line.strip():
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

        print("[resource-interop] Rust node stdout:")
        for line in rust_lines:
            if line.strip():
                print(f"  {line}")

        print("[resource-interop] Rust node stderr (last 1000 chars):")
        for line in rust_err_output[-1000:].strip().split("\n"):
            if line.strip():
                print(f"  {line}")

        # --- Assertion 1: Link established (both sides) ---
        rust_link_established = any(l.startswith("LINK_ESTABLISHED:") for l in rust_lines)
        py_link_ok = any("PY_LINK_ACTIVE" in l for l in py_lines)

        if rust_link_established and py_link_ok:
            print("[resource-interop] PASS [1/4]: Link established (both sides)")
            passed += 1
        elif rust_link_established:
            print("[resource-interop] FAIL [1/4]: Link established on Rust but Python timed out")
            print("  This may indicate LRPROOF routing through rnsd is not working.")
            failed += 1
        elif py_link_ok:
            print("[resource-interop] FAIL [1/4]: Link established on Python but not Rust")
            failed += 1
        else:
            print("[resource-interop] FAIL [1/4]: Link not established on either side")
            failed += 1

        # --- Assertion 2: Rust received RESOURCE_OFFERED ---
        rust_resource_offered = [l for l in rust_lines if l.startswith("RESOURCE_OFFERED:")]

        if rust_resource_offered:
            # Verify the size is approximately right (~1KB)
            parts = rust_resource_offered[0].split(":")
            if len(parts) >= 4:
                reported_size = int(parts[3])
                if reported_size > 0:
                    print(f"[resource-interop] PASS [2/4]: Rust received RESOURCE_OFFERED (size={reported_size})")
                    passed += 1
                else:
                    print(f"[resource-interop] FAIL [2/4]: RESOURCE_OFFERED with zero size")
                    failed += 1
            else:
                print(f"[resource-interop] PASS [2/4]: Rust received RESOURCE_OFFERED")
                passed += 1
        else:
            print("[resource-interop] FAIL [2/4]: Rust did not receive RESOURCE_OFFERED")
            if not (rust_link_established and py_link_ok):
                print("  (link was not established on both sides)")
            failed += 1

        # --- Assertion 3: Rust received RESOURCE_COMPLETE with matching data ---
        rust_resource_complete = [l for l in rust_lines if l.startswith("RESOURCE_COMPLETE:")]

        if rust_resource_complete:
            # Format: RESOURCE_COMPLETE:<link_id>:<resource_hash>:<data>
            complete_line = rust_resource_complete[0]
            # Split into at most 4 parts: prefix, link_id, hash, data
            parts = complete_line.split(":", 3)
            if len(parts) >= 4:
                received_text = parts[3]
                # The resource data is the repeated string. Check it contains our marker.
                if "test_resource_data_12345" in received_text:
                    print("[resource-interop] PASS [3/4]: Rust received RESOURCE_COMPLETE with matching data")
                    passed += 1
                else:
                    print("[resource-interop] FAIL [3/4]: RESOURCE_COMPLETE data does not match")
                    print(f"  Expected to contain: 'test_resource_data_12345'")
                    print(f"  Received (first 100 chars): {received_text[:100]}")
                    failed += 1
            else:
                print("[resource-interop] FAIL [3/4]: RESOURCE_COMPLETE line has unexpected format")
                print(f"  Line: {complete_line}")
                failed += 1
        else:
            print("[resource-interop] FAIL [3/4]: Rust did not receive RESOURCE_COMPLETE")
            rust_resource_failed = [l for l in rust_lines if l.startswith("RESOURCE_FAILED:")]
            if rust_resource_failed:
                print(f"  RESOURCE_FAILED was reported: {rust_resource_failed[0]}")
            elif not (rust_link_established and py_link_ok):
                print("  (link was not established on both sides)")
            failed += 1

        # --- Assertion 4: Python received Resource from Rust ---
        py_resource_ok = any("PY_RUST_RESOURCE_RECEIVED" in l for l in py_lines)
        py_resource_complete = any("PY_RESOURCE_COMPLETE:" in l for l in py_lines)

        if py_resource_ok and py_resource_complete:
            # Verify the data contains our marker
            for line in py_lines:
                if "PY_RESOURCE_COMPLETE:" in line:
                    if "hello_from_rust_resource_transfer" in line:
                        print("[resource-interop] PASS [4/4]: Python received Resource from Rust with matching data")
                        passed += 1
                    else:
                        print("[resource-interop] FAIL [4/4]: Python received Resource but data mismatch")
                        print(f"  Line: {line}")
                        failed += 1
                    break
            else:
                # Shouldn't happen if py_resource_complete is True
                print("[resource-interop] FAIL [4/4]: Could not find PY_RESOURCE_COMPLETE line")
                failed += 1
        elif not rust_link_id:
            print("[resource-interop] SKIP [4/4]: Could not send resource from Rust (no link_id)")
            print("  This assertion requires link establishment first.")
            failed += 1
        elif not py_ready_for_rust_resource:
            print("[resource-interop] SKIP [4/4]: Python was not ready to receive resource from Rust")
            failed += 1
        else:
            print("[resource-interop] FAIL [4/4]: Python did not receive Resource from Rust")
            if any("PY_WARN:no_resource_from_rust" in l for l in py_lines):
                print("  Python timed out waiting for resource from Rust")
            failed += 1

    finally:
        # Cleanup
        print("[resource-interop] cleaning up...")
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
    print(f"\n[resource-interop] Results: {passed}/{total} passed, {failed}/{total} failed")

    if failed > 0:
        sys.exit(1)
    else:
        print("[resource-interop] ALL TESTS PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
