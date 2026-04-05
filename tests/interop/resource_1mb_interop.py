#!/usr/bin/env python3
"""E2E: 1.5MB split resource transfer with data integrity verification.

Stress-tests split resource transfer: data exceeding MAX_EFFICIENT_SIZE
(1,048,575 bytes) is automatically split into multiple independent segment
transfers by Python RNS. The Rust receiver must reassemble segments.

Phase 1: Python sends 1.5MB to Rust (tests Rust receiver split support)
Phase 2: Rust sends 1.5MB to Python (tests Rust sender split support)

Topology:
  rnsd (transport=yes, TCP server on localhost:4355)
  Rust node connects as TCP client to rnsd
  Python client connects as TCP client to rnsd

Usage:
  cd tests/interop
  uv run python resource_1mb_interop.py --rust-binary ../../target/debug/rete
"""

import hashlib
import time

from interop_helpers import InteropTest

# Generate 1,572,864 bytes (1.5 × 2^20) of incompressible pseudo-random text.
# This exceeds MAX_EFFICIENT_SIZE (1,048,575) so Python RNS will split into 2 segments.
DATA_SIZE = 1_572_864
BLOCKS = [hashlib.sha256(f"res1mb-{i}".encode()).hexdigest() for i in range(25000)]
RESOURCE_TEXT = "SPLIT_" + "".join(BLOCKS)[:DATA_SIZE - 6]  # 6 + rest = DATA_SIZE
assert len(RESOURCE_TEXT) == DATA_SIZE


def main():
    with InteropTest("resource-1mb", default_port=4355, default_timeout=240) as t:
        t.start_rnsd()
        rust = t.start_rust()

        time.sleep(3)

        py = t.start_py_helper(f"""\
import RNS, time, sys, os, hashlib, threading

def ts():
    return f"[{{time.time():.3f}}]"

config_dir = os.path.join("{t.tmpdir}", "py_1mb_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config(transport=False)}\"\"\")

reticulum = RNS.Reticulum(config_dir)
time.sleep(2)

# Discover Rust node via path table
deadline = time.time() + 20
rust_dest_hash = None
while time.time() < deadline:
    for h in RNS.Transport.path_table:
        rust_dest_hash = h
        break
    if rust_dest_hash:
        break
    time.sleep(0.5)

if not rust_dest_hash:
    print("PY_NO_PATH", flush=True)
    sys.exit(1)

print("PY_PATH_FOUND", flush=True)
rust_id = RNS.Identity.recall(rust_dest_hash)
rust_dest = RNS.Destination(
    rust_id, RNS.Destination.OUT, RNS.Destination.SINGLE,
    "rete", "example", "v1",
)

link_established = threading.Event()
link_closed = threading.Event()
active_link = [None]

resource_received = threading.Event()
received_resource_data = [None]

def link_established_cb(link):
    print(f"{{ts()}} PY_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
    active_link[0] = link
    link_established.set()

def link_closed_cb(link):
    print(f"{{ts()}} PY_LINK_CLOSED", flush=True)
    link_closed.set()

def resource_started_cb(resource):
    print(f"{{ts()}} PY_RESOURCE_STARTED:{{resource.hash.hex()}}:{{resource.total_size}}", flush=True)

def resource_concluded_cb(resource):
    data = b""
    try:
        status_name = {{0x06: "COMPLETE", 0x07: "FAILED", 0x08: "CORRUPT"}}.get(
            resource.status, f"status={{resource.status}}")
        print(f"{{ts()}} PY_RESOURCE_CONCLUDED:{{resource.hash.hex()}}:{{status_name}}", flush=True)
        if resource.status == 0x06:
            if hasattr(resource, 'storagepath') and os.path.isfile(resource.storagepath):
                with open(resource.storagepath, "rb") as f:
                    data = f.read()
            elif hasattr(resource, 'data') and resource.data is not None:
                if hasattr(resource.data, 'read'):
                    data = resource.data.read()
                    resource.data.close()
                elif isinstance(resource.data, (bytes, bytearray)):
                    data = resource.data
            text = data.decode("utf-8", errors="replace")
            print(f"{{ts()}} PY_RESOURCE_COMPLETE:{{resource.hash.hex()}}:{{len(data)}}:{{text[:80]}}", flush=True)
    except Exception as e:
        print(f"{{ts()}} PY_RESOURCE_CB_ERROR:{{type(e).__name__}}:{{e}}", flush=True)
    received_resource_data[0] = data
    resource_received.set()

link = RNS.Link(rust_dest, established_callback=link_established_cb, closed_callback=link_closed_cb)

if not link_established.wait(timeout=20):
    print("PY_LINK_FAIL", flush=True)
    sys.exit(1)

print("PY_LINK_ACTIVE", flush=True)
link.keepalive = 300
link.stale_time = 600
time.sleep(1)

# --- Phase 1: Python sends 1.5MB to Rust ---
data_size = {DATA_SIZE}
blocks = [hashlib.sha256(f"res1mb-{{i}}".encode()).hexdigest() for i in range(25000)]
resource_data = ("SPLIT_" + "".join(blocks)[:data_size - 6]).encode("utf-8")
print(f"PY_SENDING_RESOURCE:size={{len(resource_data)}}", flush=True)

resource_sent = threading.Event()
def send_complete(resource):
    status_name = {{0x06: "COMPLETE", 0x07: "FAILED", 0x08: "CORRUPT"}}.get(
        resource.status, f"status={{resource.status}}")
    print(f"{{ts()}} PY_RESOURCE_SENT:{{status_name}}", flush=True)
    resource_sent.set()

resource = RNS.Resource(resource_data, link, callback=send_complete)

start_time = time.time()
if resource_sent.wait(timeout={t.timeout}):
    elapsed = time.time() - start_time
    print(f"PY_RESOURCE_COMPLETE:elapsed={{elapsed:.1f}}", flush=True)
else:
    elapsed = time.time() - start_time
    print(f"PY_RESOURCE_FAIL:timeout:elapsed={{elapsed:.1f}}", flush=True)

time.sleep(5)

# --- Phase 2: Accept resource from Rust ---
link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
link.set_resource_started_callback(resource_started_cb)
link.set_resource_concluded_callback(resource_concluded_cb)
print("PY_READY_ACCEPT_ALL", flush=True)

if resource_received.wait(timeout={t.timeout}):
    print("PY_RUST_RESOURCE_RECEIVED", flush=True)
else:
    print("PY_WARN:no_resource_from_rust_timeout", flush=True)

time.sleep(2)
link.teardown()
print("PY_DONE", flush=True)
""")

        path = t.wait_for_line(py, "PY_PATH_FOUND", timeout=25)
        t.check(path is not None, "Python found Rust path")

        active = t.wait_for_line(py, "PY_LINK_ACTIVE")
        t.check(active is not None, "Link established")

        sending = t.wait_for_line(py, "PY_SENDING_RESOURCE")
        t.check(sending is not None, "Resource send started")

        # --- Phase 1: Python → Rust (split resource receive) ---
        complete = t.wait_for_line(py, "PY_RESOURCE_COMPLETE", timeout=t.timeout)
        t.check(complete is not None, "1.5MB resource transfer completed (Python)")

        # RESOURCE_COMPLETE format: RESOURCE_COMPLETE:<link_id>:<hash>:<data>
        resource_line = t.wait_for_line(rust, "RESOURCE_COMPLETE", timeout=15)
        t.check(resource_line is not None, "Rust confirmed resource receipt")

        received_size = 0
        received_prefix = ""
        received_suffix = ""
        for line in rust:
            if "RESOURCE_COMPLETE:" in line:
                parts = line.split(":", 3)
                if len(parts) >= 4:
                    data = parts[3]
                    received_size = len(data)
                    received_prefix = data[:100]
                    received_suffix = data[-100:]
                break

        t.check(
            received_size == DATA_SIZE,
            f"Received data size matches ({DATA_SIZE} bytes)",
            detail=f"got {received_size} bytes" if received_size != DATA_SIZE else None,
        )

        expected_prefix = RESOURCE_TEXT[:100]
        expected_suffix = RESOURCE_TEXT[-100:]
        t.check(
            received_prefix == expected_prefix and received_suffix == expected_suffix,
            "Data integrity verified (prefix and suffix match)",
            detail=(
                f"prefix_ok={received_prefix == expected_prefix} "
                f"suffix_ok={received_suffix == expected_suffix}"
            ) if received_prefix != expected_prefix or received_suffix != expected_suffix else None,
        )

        # --- Phase 2: Rust → Python (split resource send) ---
        # Wait for Python to be ready to accept, then send from Rust
        rust_link_id = None
        for line in rust:
            if line.startswith("LINK_ESTABLISHED:"):
                rust_link_id = line.split(":")[1].strip()
                break

        py_ready = t.wait_for_line(py, "PY_READY_ACCEPT_ALL", timeout=15)
        t.check(py_ready is not None, "Python ready to accept Rust resource")

        if rust_link_id:
            # Generate the same data on Rust side via the "resource" command
            # The resource command takes: resource <link_id> <text_data>
            # For 1.5MB we send via the resource command
            t.send_rust(f"resource {rust_link_id} {RESOURCE_TEXT}")

            py_recv = t.wait_for_line(py, "PY_RUST_RESOURCE_RECEIVED", timeout=t.timeout)
            t.check(py_recv is not None, "Python received 1.5MB resource from Rust")

            # Check data integrity on Python side
            # Line format: [timestamp] PY_RESOURCE_COMPLETE:<hash>:<size>:<prefix>
            # parts[0]="[ts] PY_RESOURCE_COMPLETE" parts[1]=hash parts[2]=size parts[3]=prefix
            py_resource_ok = False
            for line in py:
                if "PY_RESOURCE_COMPLETE:" in line and "SPLIT_" in line:
                    parts = line.split(":", 4)
                    if len(parts) >= 3:
                        try:
                            py_recv_size = int(parts[2])
                            py_resource_ok = py_recv_size == DATA_SIZE
                        except (ValueError, IndexError):
                            pass
                    break
            t.check(py_resource_ok, f"Python received correct size ({DATA_SIZE} bytes)")
        else:
            t.check(False, "Python ready to accept Rust resource", detail="No link_id found")
            t.check(False, "Python received 1.5MB resource from Rust")
            t.check(False, f"Python received correct size ({DATA_SIZE} bytes)")

        done = t.wait_for_line(py, "PY_DONE")
        t.check(done is not None, "Test completed")


if __name__ == "__main__":
    main()
