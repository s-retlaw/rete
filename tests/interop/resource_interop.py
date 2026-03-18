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
  4. Rust sends Resource to Python (ACCEPT_ALL strategy), Python receives it
  5. Rust sends Resource to Python (ACCEPT_APP strategy), Python's callback invoked and resource received

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

from interop_helpers import write_rnsd_config, wait_for_port, read_stdout_lines


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
        "--timeout", type=float, default=120.0, help="Test timeout in seconds"
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

def ts():
    return f"[{{time.time():.3f}}]"

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
resource_received_accept_all = threading.Event()
resource_received_accept_app = threading.Event()
received_resource_data_all = [None]
received_resource_data_app = [None]
adv_callback_invoked = [False]

# Which phase are we in?
phase = ["accept_all"]  # switches to "accept_app" after first resource

def link_established_cb(link):
    print(f"{{ts()}} PY_LINK_ESTABLISHED:{{link.link_id.hex()}} rtt={{link.rtt:.6f}} keepalive={{link.keepalive:.1f}} stale={{link.stale_time:.1f}}", flush=True)
    active_link[0] = link
    link_established.set()

def link_closed_cb(link):
    print(f"{{ts()}} PY_LINK_CLOSED:{{link.link_id.hex()}} status={{link.status}}", flush=True)
    link_closed.set()

# Resource callbacks for receiving from Rust
def resource_started_cb(resource):
    print(f"{{ts()}} PY_RESOURCE_STARTED:{{resource.hash.hex()}}:{{resource.total_size}}", flush=True)

def resource_concluded_cb(resource):
    data = b""
    try:
        status_name = {{0x06: "COMPLETE", 0x07: "FAILED", 0x08: "CORRUPT"}}.get(resource.status, f"status={{resource.status}}")
        print(f"{{ts()}} PY_RESOURCE_CONCLUDED:{{resource.hash.hex()}}:{{status_name}}", flush=True)
        if resource.status == 0x06:
            # Try to read the data from the storage file
            if hasattr(resource, 'storagepath') and os.path.isfile(resource.storagepath):
                with open(resource.storagepath, "rb") as f:
                    data = f.read()
            elif hasattr(resource, 'data') and resource.data is not None:
                if hasattr(resource.data, 'read'):
                    data = resource.data.read()
                    resource.data.close()
                elif isinstance(resource.data, (bytes, bytearray)):
                    data = resource.data
                else:
                    data = b""
            else:
                data = b""
            text = data.decode("utf-8", errors="replace")
            print(f"{{ts()}} PY_RESOURCE_COMPLETE:{{resource.hash.hex()}}:{{len(data)}}:{{text[:80]}}", flush=True)
    except Exception as e:
        print(f"{{ts()}} PY_RESOURCE_CB_ERROR:{{type(e).__name__}}:{{e}}", flush=True)
    # Signal the event regardless of success/failure
    if phase[0] == "accept_all":
        received_resource_data_all[0] = data
        resource_received_accept_all.set()
    else:
        received_resource_data_app[0] = data
        resource_received_accept_app.set()

def adv_callback(resource_advertisement):
    \"\"\"Called with ACCEPT_APP strategy. Receives ResourceAdvertisement, returns True to accept.\"\"\"
    print(f"PY_ADV_CALLBACK:hash={{resource_advertisement.h.hex()}}:size={{resource_advertisement.d}}", flush=True)
    adv_callback_invoked[0] = True
    return True

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

print(f"{{ts()}} PY_LINK_ACTIVE", flush=True)

# Override keepalive to prevent premature stale-out during slow resource transfers
# On localhost with low RTT, the default keepalive can be as short as 5s, but
# the resource transfer involves retries that can take 30+ seconds.
link.keepalive = 120
link.stale_time = 240

# Send a Resource from Python to Rust
resource_data = {repr(resource_data)}
print(f"PY_SENDING_RESOURCE:{{len(resource_data)}}", flush=True)

resource_sent = threading.Event()
def resource_send_complete(resource):
    print(f"{{ts()}} PY_RESOURCE_SENT:{{resource.hash.hex()}}:{{resource.total_size}}", flush=True)
    resource_sent.set()

resource = RNS.Resource(resource_data, link, callback=resource_send_complete)
print(f"PY_RESOURCE_HASH:{{resource.hash.hex()}}", flush=True)

# Wait for resource transfer to complete (allow up to 45s for slow links)
if not resource_sent.wait(timeout=45):
    print("PY_FAIL:resource_send_timeout", flush=True)
else:
    print(f"{{ts()}} PY_RESOURCE_TRANSFER_DONE", flush=True)

# Give Rust time to fully process the resource before starting a new one
time.sleep(5)

# --- Phase 1: ACCEPT_ALL ---
# Set resource strategy to ACCEPT_ALL so Python auto-accepts incoming resources
phase[0] = "accept_all"
link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
link.set_resource_started_callback(resource_started_cb)
link.set_resource_concluded_callback(resource_concluded_cb)
print(f"{{ts()}} PY_READY_ACCEPT_ALL", flush=True)

# Wait for resource from Rust (ACCEPT_ALL)
if resource_received_accept_all.wait(timeout=60):
    print("PY_RUST_RESOURCE_RECEIVED_ACCEPT_ALL", flush=True)
else:
    print("PY_WARN:no_resource_from_rust_accept_all_timeout", flush=True)

# --- Phase 2: ACCEPT_APP ---
# Wait for the first resource transfer to fully clean up
time.sleep(2)
# Switch to ACCEPT_APP strategy with a proper advertisement callback
phase[0] = "accept_app"
link.set_resource_strategy(RNS.Link.ACCEPT_APP)
link.set_resource_callback(adv_callback)
print("PY_READY_ACCEPT_APP", flush=True)

# Wait for resource from Rust (ACCEPT_APP)
if resource_received_accept_app.wait(timeout=60):
    if adv_callback_invoked[0]:
        print("PY_RUST_RESOURCE_RECEIVED_ACCEPT_APP", flush=True)
    else:
        print("PY_WARN:resource_received_but_adv_callback_not_invoked", flush=True)
else:
    print("PY_WARN:no_resource_from_rust_accept_app_timeout", flush=True)

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

        # Wait for Rust to receive the resource (RESOURCE_COMPLETE), then send resources back
        deadline = time.monotonic() + args.timeout + 15
        rust_link_id = None
        rust_resource_complete = False
        sent_accept_all = False
        sent_accept_app = False

        while time.monotonic() < deadline:
            # Check for LINK_ESTABLISHED in Rust output to get link_id
            if rust_link_id is None:
                for line in rust_lines:
                    if line.startswith("LINK_ESTABLISHED:"):
                        rust_link_id = line.split(":")[1].strip()
                        break

            # Check if Rust received the resource from Python
            if not rust_resource_complete:
                for line in rust_lines:
                    if line.startswith("RESOURCE_COMPLETE:"):
                        rust_resource_complete = True
                        break

            # Send first resource (ACCEPT_ALL) when Python is ready
            if not sent_accept_all and rust_link_id and rust_resource_complete:
                if any("PY_READY_ACCEPT_ALL" in l for l in py_lines):
                    cmd = f"resource {rust_link_id} hello_accept_all\n"
                    print(f"[resource-interop] sending ACCEPT_ALL resource: {cmd.strip()}")
                    try:
                        rust_proc.stdin.write(cmd.encode())
                        rust_proc.stdin.flush()
                        sent_accept_all = True
                    except (BrokenPipeError, OSError) as e:
                        print(f"[resource-interop] warning: could not write to Rust stdin: {e}")
                        break

            # Send second resource (ACCEPT_APP) when Python is ready
            # Wait for the first resource to fully complete before sending the second
            if not sent_accept_app and sent_accept_all:
                if any("PY_RUST_RESOURCE_RECEIVED_ACCEPT_ALL" in l for l in py_lines) and any("PY_READY_ACCEPT_APP" in l for l in py_lines):
                    cmd = f"resource {rust_link_id} hello_accept_app\n"
                    print(f"[resource-interop] sending ACCEPT_APP resource: {cmd.strip()}")
                    try:
                        rust_proc.stdin.write(cmd.encode())
                        rust_proc.stdin.flush()
                        sent_accept_app = True
                    except (BrokenPipeError, OSError) as e:
                        print(f"[resource-interop] warning: could not write to Rust stdin: {e}")
                        break

            # Done when both resources sent and Python is done (or exited)
            if sent_accept_app:
                # Give Python time to process the second resource
                time.sleep(3)
                break

            # Check if Python helper has exited
            if py_proc.poll() is not None:
                break

            time.sleep(0.5)

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

        if py_err_output:
            # Show last 2000 chars of Python stderr (RNS logs) for debugging
            print("[resource-interop] Python helper stderr (last 2000 chars):")
            for line in py_err_output[-2000:].strip().split("\n"):
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
            print("[resource-interop] PASS [1/5]: Link established (both sides)")
            passed += 1
        elif rust_link_established:
            print("[resource-interop] FAIL [1/5]: Link established on Rust but Python timed out")
            print("  This may indicate LRPROOF routing through rnsd is not working.")
            failed += 1
        elif py_link_ok:
            print("[resource-interop] FAIL [1/5]: Link established on Python but not Rust")
            failed += 1
        else:
            print("[resource-interop] FAIL [1/5]: Link not established on either side")
            failed += 1

        # --- Assertion 2: Rust received RESOURCE_OFFERED ---
        rust_resource_offered = [l for l in rust_lines if l.startswith("RESOURCE_OFFERED:")]

        if rust_resource_offered:
            # Verify the size is approximately right (~1KB)
            parts = rust_resource_offered[0].split(":")
            if len(parts) >= 4:
                reported_size = int(parts[3])
                if reported_size > 0:
                    print(f"[resource-interop] PASS [2/5]: Rust received RESOURCE_OFFERED (size={reported_size})")
                    passed += 1
                else:
                    print(f"[resource-interop] FAIL [2/5]: RESOURCE_OFFERED with zero size")
                    failed += 1
            else:
                print(f"[resource-interop] PASS [2/5]: Rust received RESOURCE_OFFERED")
                passed += 1
        else:
            print("[resource-interop] FAIL [2/5]: Rust did not receive RESOURCE_OFFERED")
            if not (rust_link_established and py_link_ok):
                print("  (link was not established on both sides)")
            failed += 1

        # --- Assertion 3: Rust received RESOURCE_COMPLETE with matching data ---
        rust_resource_complete_lines = [l for l in rust_lines if l.startswith("RESOURCE_COMPLETE:")]

        if rust_resource_complete_lines:
            # Format: RESOURCE_COMPLETE:<link_id>:<resource_hash>:<data>
            complete_line = rust_resource_complete_lines[0]
            # Split into at most 4 parts: prefix, link_id, hash, data
            parts = complete_line.split(":", 3)
            if len(parts) >= 4:
                received_text = parts[3]
                # The resource data is the repeated string. Check it contains our marker.
                if "test_resource_data_12345" in received_text:
                    print("[resource-interop] PASS [3/5]: Rust received RESOURCE_COMPLETE with matching data")
                    passed += 1
                else:
                    print("[resource-interop] FAIL [3/5]: RESOURCE_COMPLETE data does not match")
                    print(f"  Expected to contain: 'test_resource_data_12345'")
                    print(f"  Received (first 100 chars): {received_text[:100]}")
                    failed += 1
            else:
                print("[resource-interop] FAIL [3/5]: RESOURCE_COMPLETE line has unexpected format")
                print(f"  Line: {complete_line}")
                failed += 1
        else:
            print("[resource-interop] FAIL [3/5]: Rust did not receive RESOURCE_COMPLETE")
            rust_resource_failed = [l for l in rust_lines if l.startswith("RESOURCE_FAILED:")]
            if rust_resource_failed:
                print(f"  RESOURCE_FAILED was reported: {rust_resource_failed[0]}")
            elif not (rust_link_established and py_link_ok):
                print("  (link was not established on both sides)")
            failed += 1

        # --- Assertion 4: Rust→Python with ACCEPT_ALL ---
        py_resource_all_ok = any("PY_RUST_RESOURCE_RECEIVED_ACCEPT_ALL" in l for l in py_lines)
        py_resource_all_complete = [l for l in py_lines if "PY_RESOURCE_COMPLETE:" in l and "hello_accept_all" in l]

        if py_resource_all_ok and py_resource_all_complete:
            print("[resource-interop] PASS [4/5]: Rust→Python with ACCEPT_ALL — Python received resource")
            passed += 1
        elif not sent_accept_all:
            print("[resource-interop] FAIL [4/5]: Could not send ACCEPT_ALL resource from Rust")
            if not rust_link_id:
                print("  (no link_id available)")
            failed += 1
        elif py_resource_all_ok:
            print("[resource-interop] FAIL [4/5]: ACCEPT_ALL resource received but data mismatch")
            failed += 1
        else:
            print("[resource-interop] FAIL [4/5]: Python did not receive ACCEPT_ALL resource from Rust")
            if any("PY_WARN:no_resource_from_rust_accept_all" in l for l in py_lines):
                print("  Python timed out waiting for ACCEPT_ALL resource")
            failed += 1

        # --- Assertion 5: Rust→Python with ACCEPT_APP ---
        py_resource_app_ok = any("PY_RUST_RESOURCE_RECEIVED_ACCEPT_APP" in l for l in py_lines)
        py_adv_invoked = any("PY_ADV_CALLBACK:" in l for l in py_lines)
        py_resource_app_complete = [l for l in py_lines if "PY_RESOURCE_COMPLETE:" in l and "hello_accept_app" in l]

        if py_resource_app_ok and py_adv_invoked and py_resource_app_complete:
            print("[resource-interop] PASS [5/5]: Rust→Python with ACCEPT_APP — callback invoked and resource received")
            passed += 1
        elif not sent_accept_app:
            print("[resource-interop] FAIL [5/5]: Could not send ACCEPT_APP resource from Rust")
            failed += 1
        elif py_resource_app_ok and not py_adv_invoked:
            print("[resource-interop] FAIL [5/5]: ACCEPT_APP resource received but advertisement callback not invoked")
            failed += 1
        elif py_adv_invoked and not py_resource_app_ok:
            print("[resource-interop] FAIL [5/5]: ACCEPT_APP callback invoked but resource not received")
            failed += 1
        else:
            print("[resource-interop] FAIL [5/5]: Python did not receive ACCEPT_APP resource from Rust")
            if any("PY_WARN:no_resource_from_rust_accept_app" in l for l in py_lines):
                print("  Python timed out waiting for ACCEPT_APP resource")
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
