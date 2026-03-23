#!/usr/bin/env python3
"""E2E: Link stale — establish, data, close, second link reuse.

Topology: Python -> rnsd -> Rust

Tests:
  1. Python establishes link to Rust, sends data
  2. Python closes the link cleanly
  3. Python opens a second link (slot reuse), sends data again
  4. Second link closes cleanly
"""

import time
from interop_helpers import InteropTest


def main():
    with InteropTest("link-stale", default_port=4340, default_timeout=45) as t:
        t.start_rnsd()
        rust = t.start_rust()

        time.sleep(3)

        py = t.start_py_helper(f"""\
import RNS, time, sys, os

config_dir = os.path.join("{t.tmpdir}", "py_link_stale_config")
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

# --- First link ---
link = RNS.Link(rust_dest)
start = time.time()
while link.status != RNS.Link.ACTIVE and time.time() - start < 15:
    time.sleep(0.2)

if link.status != RNS.Link.ACTIVE:
    print("PY_LINK_FAIL", flush=True)
    sys.exit(1)

print("PY_LINK_ACTIVE", flush=True)
time.sleep(1)

RNS.Packet(link, b"stale-test-ping").send()
time.sleep(1)
print("PY_DATA_SENT", flush=True)

link.teardown()
print("PY_LINK_CLOSED", flush=True)
time.sleep(2)

# --- Second link (slot reuse) ---
link2 = RNS.Link(rust_dest)
start2 = time.time()
while link2.status != RNS.Link.ACTIVE and time.time() - start2 < 15:
    time.sleep(0.2)

if link2.status == RNS.Link.ACTIVE:
    print("PY_LINK2_ACTIVE", flush=True)
    RNS.Packet(link2, b"reuse-test-ping").send()
    time.sleep(1)
    link2.teardown()
    print("PY_LINK2_CLOSED", flush=True)
else:
    print("PY_LINK2_FAIL", flush=True)

time.sleep(2)
print("PY_DONE", flush=True)
""")

        path = t.wait_for_line(py, "PY_PATH_FOUND", timeout=20)
        t.check(path is not None, "Python found Rust path")

        # Check first link
        link_active = t.wait_for_line(py, "PY_LINK_ACTIVE")
        t.check(link_active is not None, "First link established")

        data_sent = t.wait_for_line(py, "PY_DATA_SENT")
        t.check(data_sent is not None, "Data sent on first link")

        data_recv = t.wait_for_line(rust, "LINK_DATA")
        t.check(data_recv is not None, "Rust received data on first link")

        link_closed = t.wait_for_line(py, "PY_LINK_CLOSED")
        t.check(link_closed is not None, "First link cleanly closed")

        # Check second link (slot reuse)
        link2_active = t.wait_for_line(py, "PY_LINK2_ACTIVE")
        t.check(link2_active is not None, "Second link established (slot reuse)")

        link2_closed = t.wait_for_line(py, "PY_LINK2_CLOSED")
        t.check(link2_closed is not None, "Second link cleanly closed")

        done = t.wait_for_line(py, "PY_DONE")
        t.check(done is not None, "Test completed without timeout")

        # Verify Rust saw both link establishments
        link_count = sum(1 for l in rust if "LINK_ESTABLISHED" in l)
        t.check(link_count >= 2, f"Rust saw {link_count} link establishments (need 2)")


if __name__ == "__main__":
    main()
