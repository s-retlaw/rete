#!/usr/bin/env python3
"""Link teardown race E2E test: data + teardown sent in rapid succession.

Tests close ordering when data and teardown packets arrive nearly simultaneously.

Topology:
  rnsd (transport=yes, TCP server on localhost:4314)
  Rust node connects as TCP client
  Python establishes link, sends 3 packets, immediately teardown (no sleep)

Assertions:
  1. Link established
  2. Rust received >= 1 data packet
  3. Link closed
  4. No crash

Usage:
  cd tests/interop
  uv run python link_teardown_race_interop.py --rust-binary ../../target/debug/rete
"""

import time

from interop_helpers import InteropTest


def main():
    with InteropTest("link-teardown-race", default_port=4314) as t:
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

config_dir = os.path.join("{t.tmpdir}", "py_client_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config(transport=False)}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

link_established = threading.Event()
link_closed = threading.Event()

def link_established_cb(link):
    print(f"PY_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
    link_established.set()

def link_closed_cb(link):
    print(f"PY_LINK_CLOSED:{{link.link_id.hex()}}", flush=True)
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

# Send 3 packets and immediately teardown (NO sleep between)
for i in range(3):
    pkt = RNS.Packet(link, f"race-{{i}}".encode())
    pkt.send()
print("PY_DATA_SENT:3", flush=True)

# Immediately teardown — no sleep!
link.teardown()
print("PY_TEARDOWN_SENT", flush=True)

time.sleep(3)
print("PY_DONE", flush=True)
""")

        # Wait for Python to finish
        t.wait_for_line(py, "PY_DONE", timeout=t.timeout + 15)
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

        # --- Assertion 2: Rust received >= 1 data packet ---
        race_lines = [l for l in rust if l.startswith("LINK_DATA:") and "race-" in l]
        t.check(
            len(race_lines) >= 1,
            f"Rust received >= 1 data packet ({len(race_lines)} received)",
        )

        # --- Assertion 3: Link closed ---
        t.check(
            t.has_line(rust, "LINK_CLOSED:"),
            "Link closed (Rust received LINK_CLOSED)",
        )

        # --- Assertion 4: No crash ---
        has_panic = "panicked" in rust_stderr.lower() or "sigsegv" in rust_stderr.lower()
        t.check(
            not has_panic,
            "No crash (no panic/SIGSEGV in stderr)",
        )


if __name__ == "__main__":
    main()
