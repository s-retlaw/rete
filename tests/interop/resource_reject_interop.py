#!/usr/bin/env python3
"""Resource rejection E2E interop test: Rust node rejects Resource from Python.

Topology:
  rnsd (transport=yes, TCP server on localhost:4260)
  Rust node connects as TCP client to rnsd (with --resource-strategy none)
  Python client connects as TCP client to rnsd
  Python discovers Rust via announce, establishes Link, sends Resource

Assertions:
  1. Link established (both sides)
  2. Rust receives RESOURCE_OFFERED event (strategy check fires)
  3. Python resource is REJECTED (receives RESOURCE_RCL)
  4. Rust does NOT receive RESOURCE_COMPLETE

Usage:
  cd tests/interop
  uv run python resource_reject_interop.py --rust-binary ../../target/debug/rete-linux
"""

import time

from interop_helpers import InteropTest


def main():
    resource_text = "reject_me_data " * 40  # ~600 bytes
    resource_data = resource_text.encode("utf-8")

    with InteropTest("resource-reject-interop", default_port=4260, default_timeout=60.0) as t:
        t.start_rnsd()
        rust = t.start_rust(extra_args=["--resource-strategy", "none"])

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
active_link = [None]
resource_status = [None]
resource_concluded = threading.Event()

def link_established_cb(link):
    print(f"{{ts()}} PY_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
    active_link[0] = link
    link_established.set()

def resource_send_complete(resource):
    status_names = {{0x00: "REJECTED", 0x06: "COMPLETE", 0x07: "FAILED", 0x08: "CORRUPT"}}
    status_name = status_names.get(resource.status, f"status={{resource.status}}")
    print(f"{{ts()}} PY_RESOURCE_CONCLUDED:{{resource.hash.hex()}}:{{status_name}}", flush=True)
    resource_status[0] = resource.status
    resource_concluded.set()

# Wait for Rust announce
timeout = {t.timeout}
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

print("PY_INITIATING_LINK", flush=True)
link = RNS.Link(rust_dest, established_callback=link_established_cb)

if not link_established.wait(timeout=15):
    print(f"PY_FAIL:link_timeout:status={{link.status}}", flush=True)
    sys.exit(1)

print(f"{{ts()}} PY_LINK_ACTIVE", flush=True)
link.keepalive = 120
link.stale_time = 240

# Send Resource from Python to Rust (Rust should reject it)
resource_data = {repr(resource_data)}
print(f"PY_SENDING_RESOURCE:{{len(resource_data)}}", flush=True)

resource = RNS.Resource(resource_data, link, callback=resource_send_complete)
print(f"PY_RESOURCE_HASH:{{resource.hash.hex()}}", flush=True)

if resource_concluded.wait(timeout=45):
    if resource_status[0] == 0x00:
        print("PY_RESOURCE_WAS_REJECTED", flush=True)
    else:
        print(f"PY_RESOURCE_STATUS:{{resource_status[0]}}", flush=True)
else:
    print("PY_WARN:resource_conclude_timeout", flush=True)

time.sleep(2)
link.teardown()
print("PY_DONE", flush=True)
time.sleep(1)
""")

        # Wait for Python to complete
        deadline = time.monotonic() + t.timeout + 10
        while time.monotonic() < deadline:
            if any("PY_DONE" in l for l in py):
                break
            time.sleep(0.5)

        time.sleep(2)

        # Collect output
        rust_stderr = t.collect_rust_stderr(last_chars=1000)
        t.dump_output("Python helper output", py)
        t.dump_output("Rust node stdout", rust)
        t.dump_output("Rust node stderr (last 1000)", rust_stderr.strip().split("\n"))

        # --- Assertion 1: Link established (both sides) ---
        rust_link_ok = t.has_line(rust, "LINK_ESTABLISHED:")
        py_link_ok = any("PY_LINK_ACTIVE" in l for l in py)
        t.check(
            rust_link_ok and py_link_ok,
            "Link established (both sides)",
            detail=f"Rust={rust_link_ok} Python={py_link_ok}",
        )

        # --- Assertion 2: Rust received RESOURCE_OFFERED ---
        rust_resource_offered = [l for l in rust if l.startswith("RESOURCE_OFFERED:")]
        t.check(
            len(rust_resource_offered) > 0,
            "Rust received RESOURCE_OFFERED (strategy fired)",
        )

        # --- Assertion 3: Python resource was REJECTED ---
        py_rejected = any("PY_RESOURCE_WAS_REJECTED" in l for l in py)
        py_concluded = [l for l in py if "PY_RESOURCE_CONCLUDED:" in l]
        detail = None
        if not py_rejected and py_concluded:
            detail = f"Resource concluded but not rejected: {py_concluded[0]}"
        t.check(
            py_rejected,
            "Python resource was REJECTED by Rust (RESOURCE_RCL received)",
            detail=detail,
        )

        # --- Assertion 4: Rust did NOT receive RESOURCE_COMPLETE ---
        rust_resource_complete = [l for l in rust if l.startswith("RESOURCE_COMPLETE:")]
        t.check(
            len(rust_resource_complete) == 0,
            "Rust did NOT receive RESOURCE_COMPLETE (correctly rejected)",
            detail=f"Got {len(rust_resource_complete)} RESOURCE_COMPLETE lines" if rust_resource_complete else None,
        )


if __name__ == "__main__":
    main()
