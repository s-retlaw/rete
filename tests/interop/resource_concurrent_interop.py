#!/usr/bin/env python3
"""Sequential resource transfer E2E test: two resources on the same link.

Python RNS serializes resource transfers per-link. This test verifies that
Rust can handle two sequential resource transfers on the same link.

Topology:
  rnsd (transport=yes, TCP server on localhost:4316)
  Rust node connects as TCP client
  Python establishes link, sends Resource_A then Resource_B

Assertions:
  1. Link established
  2. First resource complete
  3. Second resource complete
  4. No crash

Usage:
  cd tests/interop
  uv run python resource_concurrent_interop.py --rust-binary ../../target/debug/rete-linux
"""

import time

from interop_helpers import InteropTest


def main():
    resource_a_text = "RESOURCE_A_DATA_" * 31  # ~496 bytes
    resource_b_text = "RESOURCE_B_DATA_" * 50  # ~800 bytes

    with InteropTest("resource-concurrent", default_port=4316, default_timeout=60.0) as t:
        t.start_rnsd()
        rust = t.start_rust()

        # Give Rust time to connect and announce
        time.sleep(3)

        py = t.start_py_helper(f"""\
import RNS
import time
import sys
import os
import threading

def ts():
    return f"[{{time.time():.3f}}]"

config_dir = os.path.join("{t.tmpdir}", "py_client_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config(transport=False)}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

link_established = threading.Event()
link_closed = threading.Event()
active_link = [None]

def link_established_cb(link):
    print(f"{{ts()}} PY_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
    active_link[0] = link
    link_established.set()

def link_closed_cb(link):
    print(f"{{ts()}} PY_LINK_CLOSED:{{link.link_id.hex()}}", flush=True)
    link_closed.set()

# Wait for Rust announce
timeout = {t.timeout}
deadline = time.time() + timeout
rust_dest_hash = None

while time.time() < deadline:
    for h in RNS.Transport.path_table:
        rust_dest_hash = h
        break
    if rust_dest_hash:
        break
    time.sleep(0.5)

if not rust_dest_hash:
    print("PY_FAIL:timeout_waiting_for_rust_announce", flush=True)
    print("PY_DONE", flush=True)
    sys.exit(1)

rust_identity = RNS.Identity.recall(rust_dest_hash)
if not rust_identity:
    print("PY_FAIL:identity_not_recalled", flush=True)
    print("PY_DONE", flush=True)
    sys.exit(1)

rust_dest = RNS.Destination(
    rust_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
    "rete", "example", "v1",
)

link = RNS.Link(rust_dest, established_callback=link_established_cb, closed_callback=link_closed_cb)

if not link_established.wait(timeout=15):
    print(f"PY_LINK_TIMEOUT:status={{link.status}}", flush=True)
    print("PY_DONE", flush=True)
    sys.exit(1)

print("PY_LINK_ACTIVE", flush=True)

# Extend keepalive for longer test
link.keepalive = 120
link.stale_time = 240

# --- Resource A ---
resource_a_data = {repr(resource_a_text.encode('utf-8'))}
resource_a_sent = threading.Event()

def resource_a_complete(resource):
    status_name = {{0x06: "COMPLETE", 0x07: "FAILED", 0x08: "CORRUPT"}}.get(resource.status, f"status={{resource.status}}")
    print(f"{{ts()}} PY_RESOURCE_A_SENT:{{resource.hash.hex()}}:{{resource.total_size}}:{{status_name}}", flush=True)
    resource_a_sent.set()

print(f"{{ts()}} PY_SENDING_RESOURCE_A:{{len(resource_a_data)}}", flush=True)
ra = RNS.Resource(resource_a_data, link, callback=resource_a_complete)

if not resource_a_sent.wait(timeout=45):
    print("PY_FAIL:resource_a_send_timeout", flush=True)
    print("PY_DONE", flush=True)
    sys.exit(1)

print(f"{{ts()}} PY_RESOURCE_A_TRANSFER_DONE", flush=True)
time.sleep(3)

# --- Resource B ---
resource_b_data = {repr(resource_b_text.encode('utf-8'))}
resource_b_sent = threading.Event()

def resource_b_complete(resource):
    status_name = {{0x06: "COMPLETE", 0x07: "FAILED", 0x08: "CORRUPT"}}.get(resource.status, f"status={{resource.status}}")
    print(f"{{ts()}} PY_RESOURCE_B_SENT:{{resource.hash.hex()}}:{{resource.total_size}}:{{status_name}}", flush=True)
    resource_b_sent.set()

print(f"{{ts()}} PY_SENDING_RESOURCE_B:{{len(resource_b_data)}}", flush=True)
rb = RNS.Resource(resource_b_data, link, callback=resource_b_complete)

if not resource_b_sent.wait(timeout=45):
    print("PY_FAIL:resource_b_send_timeout", flush=True)
    print("PY_DONE", flush=True)
    sys.exit(1)

print(f"{{ts()}} PY_RESOURCE_B_TRANSFER_DONE", flush=True)
time.sleep(3)

link.teardown()
print("PY_TEARDOWN_SENT", flush=True)
time.sleep(2)

print("PY_DONE", flush=True)
""")

        # Wait for Python to finish
        t.wait_for_line(py, "PY_DONE", timeout=t.timeout + 15)

        # Wait for Rust to process both resources — give it time to print
        # RESOURCE_COMPLETE for both before killing. Poll for up to 15s.
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            complete_lines = [l for l in rust if l.startswith("RESOURCE_COMPLETE:")]
            if len(complete_lines) >= 2:
                break
            time.sleep(0.5)
        time.sleep(2)

        # Collect output
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Python output", py)
        t.dump_output("Rust stdout", rust)
        t.dump_output("Rust stderr (last 1000)", rust_stderr.strip().split("\n"))

        # --- Assertion 1: Link established ---
        t.check(
            t.has_line(rust, "LINK_ESTABLISHED:") and t.has_line(py, "PY_LINK_ACTIVE"),
            "Link established (both sides)",
        )

        # --- Assertion 2: First resource complete (Rust received and assembled) ---
        resource_complete_lines = [l for l in rust if l.startswith("RESOURCE_COMPLETE:")]
        resource_a_ok = any("RESOURCE_A_DATA_" in l for l in resource_complete_lines)
        t.check(
            resource_a_ok,
            "First resource (A) received by Rust",
            detail=f"RESOURCE_COMPLETE lines: {resource_complete_lines}" if not resource_a_ok else None,
        )

        # --- Assertion 3: Second resource (B) ---
        resource_b_ok = any("RESOURCE_B_DATA_" in l for l in resource_complete_lines)
        t.check(
            resource_b_ok,
            "Second resource (B) received by Rust",
            detail=f"RESOURCE_COMPLETE lines: {resource_complete_lines}" if not resource_b_ok else None,
        )

        # --- Assertion 4: No crash ---
        has_panic = "panicked" in rust_stderr.lower() or "sigsegv" in rust_stderr.lower()
        t.check(
            not has_panic,
            "No crash (no panic/SIGSEGV in stderr)",
        )


if __name__ == "__main__":
    main()
