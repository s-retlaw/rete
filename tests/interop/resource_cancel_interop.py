#!/usr/bin/env python3
"""E2E: Resource cancel -- start large resource, cancel, then send recovery resource.

Tests:
  1. Python establishes link to Rust
  2. Python starts sending a large resource (~10KB)
  3. Python cancels mid-transfer
  4. Rust handles the cancel gracefully (no crash, no hang)
  5. A subsequent small resource transfer succeeds (state cleanup)
"""

import time
from interop_helpers import InteropTest


def main():
    with InteropTest("resource-cancel", default_port=4343, default_timeout=60) as t:
        t.start_rnsd()
        rust = t.start_rust()

        time.sleep(3)

        py = t.start_py_helper(f"""\
import RNS, time, sys, os

config_dir = os.path.join("{t.tmpdir}", "py_cancel_config")
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

# Start a large resource (>10KB, multi-segment)
large_data = b"X" * 10000
resource = RNS.Resource(large_data, link)
print("PY_RESOURCE_STARTED", flush=True)

# Cancel after a short delay (before transfer completes)
time.sleep(0.5)
resource.cancel()
print("PY_RESOURCE_CANCELLED", flush=True)

# Wait a bit for cleanup
time.sleep(3)

# Now send a small successful resource to verify state is clean
small_data = b"recovery-data-ok"
resource2 = RNS.Resource(small_data, link)
start2 = time.time()
while resource2.status < RNS.Resource.COMPLETE and time.time() - start2 < 30:
    time.sleep(0.5)
    if resource2.status == RNS.Resource.FAILED:
        break

if resource2.status == RNS.Resource.COMPLETE:
    print("PY_RECOVERY_OK", flush=True)
else:
    print(f"PY_RECOVERY_FAIL:status={{resource2.status}}", flush=True)

link.teardown()
print("PY_DONE", flush=True)
""")

        path = t.wait_for_line(py, "PY_PATH_FOUND", timeout=20)
        t.check(path is not None, "Python found Rust path")

        active = t.wait_for_line(py, "PY_LINK_ACTIVE")
        t.check(active is not None, "Link established")

        started = t.wait_for_line(py, "PY_RESOURCE_STARTED")
        t.check(started is not None, "Resource transfer started")

        cancelled = t.wait_for_line(py, "PY_RESOURCE_CANCELLED")
        t.check(cancelled is not None, "Resource cancelled")

        # Verify Rust didn't crash
        time.sleep(2)
        t.check(t._rust_proc.poll() is None, "Rust node still alive after cancel")

        # Check recovery resource
        recovery = t.wait_for_line(py, "PY_RECOVERY_OK", timeout=40)
        t.check(recovery is not None, "Recovery resource transfer succeeded")

        done = t.wait_for_line(py, "PY_DONE")
        t.check(done is not None, "Test completed")


if __name__ == "__main__":
    main()
