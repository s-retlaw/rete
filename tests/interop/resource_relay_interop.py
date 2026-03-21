#!/usr/bin/env python3
"""Resource relay interop: Python sends resource to Rust through rnsd relay.

Topology:
  Python (initiator) <-TCP-> rnsd (transport) <-TCP-> Rust (responder)

Tests that resource transfers complete through a relay. Python establishes a
link to Rust through rnsd, sends a resource, and verifies RESOURCE_COMPLETE.

Usage:
  cd tests/interop
  uv run python resource_relay_interop.py --rust-binary ../../target/debug/rete-linux
"""

import time

from interop_helpers import InteropTest


RNSD_PORT = 4275


def main():
    with InteropTest("resource-relay-interop", default_port=RNSD_PORT) as t:
        # Start rnsd transport relay
        t.start_rnsd(port=RNSD_PORT)

        # Start Rust node connected to rnsd
        rust_lines = t.start_rust(seed="resource-relay-rust-42", port=RNSD_PORT)

        # Wait for Rust to connect and announce
        time.sleep(3.0)

        # Python client: discover Rust, establish link, send resource
        py = t.start_py_helper(f"""\
import RNS
import time
import sys
import os
import threading

config_dir = os.path.join("{t.tmpdir}", "py_client_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config(port=RNSD_PORT)}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

link_established = threading.Event()
resource_complete = threading.Event()

def link_established_cb(link):
    print(f"PY_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
    link_established.set()

def link_closed_cb(link):
    print(f"PY_LINK_CLOSED:{{link.link_id.hex()}}", flush=True)

def resource_concluded(resource):
    if resource.status == RNS.Resource.COMPLETE:
        print(f"PY_RESOURCE_COMPLETE:{{resource.hash.hex()}}", flush=True)
        resource_complete.set()
    else:
        print(f"PY_RESOURCE_FAIL:{{resource.status}}", flush=True)

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
    sys.exit(1)

print(f"PY_ANNOUNCE_RECV:{{rust_dest_hash.hex()}}", flush=True)

rust_identity = RNS.Identity.recall(rust_dest_hash)
rust_dest = RNS.Destination(
    rust_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
    "rete", "example", "v1",
)

link = RNS.Link(rust_dest, established_callback=link_established_cb, closed_callback=link_closed_cb)

if not link_established.wait(timeout=15):
    print(f"PY_LINK_TIMEOUT:status={{link.status}}", flush=True)
    sys.exit(1)

time.sleep(2.0)  # LRRTT stabilization

# Send small resource
test_data = b"resource-relay-test-payload-" + (b"X" * 100)
resource = RNS.Resource(test_data, link, callback=resource_concluded)
print(f"PY_RESOURCE_SENT:{{len(test_data)}}", flush=True)

if not resource_complete.wait(timeout=20):
    print("PY_RESOURCE_TIMEOUT", flush=True)

# Teardown
link.teardown()
print("PY_TEARDOWN", flush=True)
time.sleep(2)

print("PY_DONE", flush=True)
""")

        # Wait for Python to finish
        t.wait_for_line(py, "PY_DONE", timeout=t.timeout + 15)
        time.sleep(2)

        # Collect output
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Python helper output", py)
        t.dump_output("Rust node stdout", rust_lines)

        # Assertions
        t.check(
            t.has_line(py, "PY_LINK_ESTABLISHED:"),
            "Link established through relay",
        )

        t.check(
            t.has_line(py, "PY_RESOURCE_COMPLETE:"),
            "Resource transfer completed through relay",
        )

        t.check(
            t.has_line(rust_lines, "RESOURCE_COMPLETE:"),
            "Rust received resource through relay",
        )

        t.check(
            t.has_line(rust_lines, "LINK_CLOSED:"),
            "Link closed cleanly",
        )


if __name__ == "__main__":
    main()
