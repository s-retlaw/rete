#!/usr/bin/env python3
"""E2E: Large resource transfer -- 10KB single-segment resource transfer.

Validates resource transfer with logically large data (10KB) that compresses
to fit in a single resource segment. Multi-segment resource transfers are
tracked as a known limitation (see GAP_ANALYSIS.md).

The test verifies:
  1. Path discovery
  2. Link establishment
  3. 10KB resource transfer (compresses to ~160 bytes)
  4. Data integrity check on Rust side
"""

import time
from interop_helpers import InteropTest


def main():
    with InteropTest("resource-large", default_port=4347, default_timeout=60) as t:
        t.start_rnsd()
        rust = t.start_rust(seed="resource-large-test-1")

        time.sleep(3)

        py = t.start_py_helper(f"""\
import RNS, time, sys, os

config_dir = os.path.join("{t.tmpdir}", "py_large_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config()}\"\"\")

reticulum = RNS.Reticulum(config_dir)
time.sleep(2)

# Discover Rust node via path table
deadline = time.time() + 15
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

link = RNS.Link(rust_dest)
start = time.time()
while link.status != RNS.Link.ACTIVE and time.time() - start < 15:
    time.sleep(0.2)

if link.status != RNS.Link.ACTIVE:
    print("PY_LINK_FAIL", flush=True)
    sys.exit(1)

print("PY_LINK_ACTIVE", flush=True)
time.sleep(1)

# Send a 10KB resource using highly compressible text pattern.
# This compresses to ~160 bytes (single segment), testing the full
# resource protocol flow without requiring multi-segment HMU exchange.
large_data = ("test_resource_data_12345 " * 400).encode()  # 10000 bytes
print(f"PY_SENDING_RESOURCE:size={{len(large_data)}}", flush=True)

resource = RNS.Resource(large_data, link)
start_time = time.time()
while resource.status < RNS.Resource.COMPLETE and time.time() - start_time < 30:
    time.sleep(0.5)
    if resource.status == RNS.Resource.FAILED:
        break

elapsed = time.time() - start_time
if resource.status == RNS.Resource.COMPLETE:
    print(f"PY_RESOURCE_COMPLETE:elapsed={{elapsed:.1f}}", flush=True)
else:
    print(f"PY_RESOURCE_FAIL:status={{resource.status}}:elapsed={{elapsed:.1f}}", flush=True)

time.sleep(2)
link.teardown()
print("PY_DONE", flush=True)
""")

        path = t.wait_for_line(py, "PY_PATH_FOUND", timeout=20)
        t.check(path is not None, "Python found Rust path")

        active = t.wait_for_line(py, "PY_LINK_ACTIVE")
        t.check(active is not None, "Link established")

        sending = t.wait_for_line(py, "PY_SENDING_RESOURCE")
        t.check(sending is not None, "Resource send started")

        # Wait for Python to confirm complete
        complete = t.wait_for_line(py, "PY_RESOURCE_COMPLETE", timeout=45)
        t.check(complete is not None, "10KB resource transfer completed (Python)")

        # Verify Rust received it
        resource_complete = t.wait_for_line(rust, "RESOURCE_COMPLETE", timeout=10)
        t.check(resource_complete is not None, "Rust confirmed resource receipt")

        # Check data integrity -- the Rust RESOURCE_COMPLETE line should contain the text
        rust_data_ok = False
        for line in rust:
            if "RESOURCE_COMPLETE" in line and "test_resource_data_12345" in line:
                rust_data_ok = True
                break
        t.check(rust_data_ok, "Resource data integrity verified on Rust side")

        done = t.wait_for_line(py, "PY_DONE")
        t.check(done is not None, "Test completed")


if __name__ == "__main__":
    main()
