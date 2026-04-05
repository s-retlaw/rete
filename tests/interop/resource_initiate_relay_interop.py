#!/usr/bin/env python3
"""Rust-initiates resource transfer through rnsd relay.

Topology:
  Rust (initiator) <-TCP-> rnsd (transport) <-TCP-> Python (responder)

Rust discovers Python via announce through rnsd relay, initiates a link,
then sends a resource. Verifies both sides see completion.

This is the reverse direction of resource_relay_interop.py (where Python
initiates). Together they cover both initiation directions through relay.

Usage:
  cd tests/interop
  uv run python resource_initiate_relay_interop.py --rust-binary ../../target/debug/rete
"""

import time

from interop_helpers import InteropTest


RNSD_PORT = 4278


def main():
    with InteropTest("resource-init-relay", default_port=RNSD_PORT, default_timeout=60.0) as t:
        # Start rnsd transport relay
        t.start_rnsd(port=RNSD_PORT)

        # Start Rust node connected to rnsd
        rust_lines = t.start_rust(port=RNSD_PORT)

        # Give Rust time to connect and announce
        time.sleep(3.0)

        # Python responder: accept links, accept resources, report results
        py = t.start_py_helper(f"""\
import RNS
import time
import sys
import os
import threading

config_dir = os.path.join("{t.tmpdir}", "py_responder_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config(port=RNSD_PORT)}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

link_established = threading.Event()
resource_received = threading.Event()
active_link = [None]
received_data = [None]

def inbound_link_established(link):
    print(f"PY_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
    active_link[0] = link
    link.set_resource_strategy(RNS.Link.ACCEPT_ALL)

    def resource_started(resource):
        print(f"PY_RESOURCE_STARTED:{{resource.hash.hex()}}:{{resource.total_size}}", flush=True)

    def resource_concluded(resource):
        if resource.status == RNS.Resource.COMPLETE:
            data = b""
            if hasattr(resource, 'data') and resource.data is not None:
                if hasattr(resource.data, 'read'):
                    data = resource.data.read()
                    resource.data.close()
                elif isinstance(resource.data, (bytes, bytearray)):
                    data = resource.data
            text = data.decode("utf-8", errors="replace")
            print(f"PY_RESOURCE_COMPLETE:{{resource.hash.hex()}}:{{len(data)}}:{{text[:80]}}", flush=True)
            received_data[0] = data
            resource_received.set()
        else:
            print(f"PY_RESOURCE_FAIL:{{resource.status}}", flush=True)

    link.set_resource_started_callback(resource_started)
    link.set_resource_concluded_callback(resource_concluded)
    link_established.set()

def link_closed_cb(link):
    print(f"PY_LINK_CLOSED:{{link.link_id.hex()}}", flush=True)

py_identity = RNS.Identity()
py_dest = RNS.Destination(
    py_identity,
    RNS.Destination.IN,
    RNS.Destination.SINGLE,
    "rete",
    "example",
    "v1",
)
py_dest.set_link_established_callback(inbound_link_established)

py_dest.announce()
print(f"PY_DEST_HASH:{{py_dest.hexhash}}", flush=True)
print("PY_ANNOUNCE_SENT", flush=True)

# Wait for link
if not link_established.wait(timeout={t.timeout}):
    print("PY_FAIL:no_link_established", flush=True)
    sys.exit(1)

# Wait for resource
if resource_received.wait(timeout=30):
    print("PY_RESOURCE_OK", flush=True)
else:
    print("PY_RESOURCE_TIMEOUT", flush=True)

time.sleep(2)
if active_link[0]:
    active_link[0].teardown()
time.sleep(2)

print("PY_DONE", flush=True)
""")

        # Wait for Python's dest hash
        py_dest_hash = t.wait_for_line(py, "PY_DEST_HASH:")
        if not py_dest_hash:
            t.check(False, "Python reported dest hash")
            return

        t._log(f"Python dest hash: {py_dest_hash}")

        # Wait for Rust to discover Python's announce
        rust_saw_announce = t.wait_for_line(rust_lines, f"ANNOUNCE:{py_dest_hash}") is not None
        t.check(rust_saw_announce, "Rust discovered Python's announce through relay")

        if not rust_saw_announce:
            t.dump_output("Rust stdout", rust_lines)
            t.dump_output("Python stdout", py)
            return

        # Rust initiates link to Python
        t.send_rust(f"link {py_dest_hash}")

        # Wait for link on Rust side
        rust_link_id = t.wait_for_line(rust_lines, "LINK_ESTABLISHED:", timeout=15)
        t.check(rust_link_id is not None, "Link established (Rust side)")

        if not rust_link_id:
            t.dump_output("Rust stdout", rust_lines)
            t.dump_output("Python stdout", py)
            return

        rust_link_id = rust_link_id.strip()
        time.sleep(2.0)  # LRRTT stabilization

        # Rust sends resource to Python through relay
        t.send_rust(f"resource {rust_link_id} resource-from-rust-through-relay-test")

        # Wait for Python to receive resource
        t.wait_for_line(py, "PY_DONE", timeout=t.timeout)
        time.sleep(2)

        # Collect output
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Python stdout", py)
        t.dump_output("Rust stdout", rust_lines)

        # Assertions
        t.check(
            t.has_line(py, "PY_LINK_ESTABLISHED:"),
            "Link established (Python side)",
        )

        t.check(
            t.has_line(py, "PY_RESOURCE_COMPLETE:", contains="resource-from-rust"),
            "Python received resource from Rust through relay",
        )

        # Verify no resource failure on Rust side (sender doesn't emit
        # RESOURCE_COMPLETE — that's receiver-only — but RESOURCE_FAILED
        # would indicate a problem)
        no_failure = not t.has_line(rust_lines, "RESOURCE_FAILED:")
        t.check(no_failure, "No resource failure on Rust sender side")

        t.check(
            t.has_line(rust_lines, "LINK_CLOSED:"),
            "Link closed cleanly",
        )


if __name__ == "__main__":
    main()
