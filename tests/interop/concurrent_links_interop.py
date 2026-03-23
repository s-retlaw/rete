#!/usr/bin/env python3
"""Concurrent links E2E test: two Python nodes establish links to same Rust dest.

Topology:
  rnsd (transport=yes, TCP server on localhost:4304)
  Rust node connects as TCP client to rnsd
  Python_A and Python_B connect as TCP clients to rnsd
  Both establish separate links to Rust

Assertions:
  1. First link established (unique link_id)
  2. Second link established (different link_id)
  3. Rust received data from A on first link
  4. Rust received data from B on second link
  5. Both links closed cleanly

Usage:
  cd tests/interop
  uv run python concurrent_links_interop.py --rust-binary ../../target/debug/rete-linux
"""

import time

from interop_helpers import InteropTest


def _py_link_script(tmpdir, port, label, timeout, send_msg):
    """Generate a Python script that establishes a link and sends data."""
    return f"""\
import RNS
import time
import sys
import os
import threading

config_dir = os.path.join("{tmpdir}", "{label}_config")
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
    target_port = {port}
\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

link_established = threading.Event()
link_closed = threading.Event()
active_link = [None]

def link_established_cb(link):
    print(f"{label.upper()}_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
    active_link[0] = link
    link_established.set()

def link_closed_cb(link):
    print(f"{label.upper()}_LINK_CLOSED:{{link.link_id.hex()}}", flush=True)
    link_closed.set()

# Wait for Rust announce
timeout = {timeout}
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
    print(f"{label.upper()}_FAIL:timeout_waiting_for_rust_announce", flush=True)
    print(f"{label.upper()}_DONE", flush=True)
    sys.exit(1)

print(f"{label.upper()}_DISCOVERED:{{rust_dest_hash.hex()}}", flush=True)

rust_identity = RNS.Identity.recall(rust_dest_hash)
if not rust_identity:
    print(f"{label.upper()}_FAIL:identity_not_recalled", flush=True)
    print(f"{label.upper()}_DONE", flush=True)
    sys.exit(1)

rust_dest = RNS.Destination(
    rust_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
    "rete", "example", "v1",
)

link = RNS.Link(rust_dest, established_callback=link_established_cb, closed_callback=link_closed_cb)

if not link_established.wait(timeout=15):
    print(f"{label.upper()}_LINK_TIMEOUT:status={{link.status}}", flush=True)
    print(f"{label.upper()}_DONE", flush=True)
    sys.exit(1)

print(f"{label.upper()}_LINK_ACTIVE", flush=True)

# Extend keepalive
link.keepalive = 120
link.stale_time = 240

# Send data
pkt = RNS.Packet(link, b"{send_msg}")
pkt.send()
print(f"{label.upper()}_DATA_SENT", flush=True)

time.sleep(5)

link.teardown()
print(f"{label.upper()}_TEARDOWN_SENT", flush=True)
time.sleep(2)

print(f"{label.upper()}_DONE", flush=True)
"""


def main():
    with InteropTest("concurrent-links", default_port=4304) as t:
        t.start_rnsd()
        rust = t.start_rust()

        # Give Rust time to connect and announce
        time.sleep(3)

        # Start Python_A
        py_a = t.start_py_helper(_py_link_script(
            t.tmpdir, t.port, "client_a", t.timeout, "from_A",
        ))

        # Stagger by 500ms to avoid race
        time.sleep(0.5)

        # Start Python_B (different identity)
        py_b = t.start_py_helper(_py_link_script(
            t.tmpdir, t.port, "client_b", t.timeout, "from_B",
        ))

        # Wait for both to finish
        t.wait_for_line(py_a, "CLIENT_A_DONE", timeout=t.timeout + 15)
        t.wait_for_line(py_b, "CLIENT_B_DONE", timeout=t.timeout + 15)
        time.sleep(2)

        # Collect output
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Client A output", py_a)
        t.dump_output("Client B output", py_b)
        t.dump_output("Rust stdout", rust)
        t.dump_output("Rust stderr (last 1000)", rust_stderr.strip().split("\n"))

        # Extract link IDs from Rust output
        link_established_lines = [l for l in rust if l.startswith("LINK_ESTABLISHED:")]
        link_ids = [l.split(":")[1].strip() for l in link_established_lines if ":" in l]

        # --- Assertion 1: First link established ---
        t.check(
            len(link_ids) >= 1,
            "First link established",
            detail=f"link_ids={link_ids}" if link_ids else "No LINK_ESTABLISHED lines",
        )

        # --- Assertion 2: Second link established (different link_id) ---
        t.check(
            len(link_ids) >= 2 and link_ids[0] != link_ids[1],
            "Second link established (different link_id)",
            detail=f"link_ids={link_ids}",
        )

        # --- Assertion 3: Rust received data from A ---
        t.check(
            t.has_line(rust, "LINK_DATA:", contains="from_A"),
            "Rust received data from client A",
        )

        # --- Assertion 4: Rust received data from B ---
        t.check(
            t.has_line(rust, "LINK_DATA:", contains="from_B"),
            "Rust received data from client B",
        )

        # --- Assertion 5: Both links closed cleanly ---
        link_closed_lines = [l for l in rust if l.startswith("LINK_CLOSED:")]
        t.check(
            len(link_closed_lines) >= 2,
            f"Both links closed cleanly ({len(link_closed_lines)} LINK_CLOSED events)",
        )


if __name__ == "__main__":
    main()
