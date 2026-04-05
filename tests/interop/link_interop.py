#!/usr/bin/env python3
"""Link E2E interop test: Python client establishes a Link to Rust node via rnsd.

Topology:
  rnsd (transport=yes, TCP server on localhost:4244)
  Rust node connects as TCP client to rnsd
  Python client connects as TCP client to rnsd
  Python discovers Rust via announce, then establishes a Link

Assertions:
  1. Rust announce received by Python
  2. Link established (Rust prints LINK_ESTABLISHED)
  3. Python sends data over link, Rust receives LINK_DATA
  4. Link teardown works (Rust prints LINK_CLOSED)

Usage:
  cd tests/interop
  uv run python link_interop.py --rust-binary ../../target/debug/rete

Or build first:
  cargo build -p rete
  cd tests/interop && uv run python link_interop.py
"""

import time

from interop_helpers import InteropTest


def main():
    with InteropTest("link-interop", default_port=4244) as t:
        t.start_rnsd()
        rust = t.start_rust()

        # Give Rust time to connect and announce
        time.sleep(3)

        # Start Python client that discovers Rust and establishes a link
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
link_data_received = threading.Event()
link_closed = threading.Event()
received_data = [None]
active_link = [None]

def link_established_cb(link):
    print(f"PY_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
    active_link[0] = link
    link_established.set()

def link_closed_cb(link):
    print(f"PY_LINK_CLOSED:{{link.link_id.hex()}}", flush=True)
    link_closed.set()

py_identity = RNS.Identity()
py_dest = RNS.Destination(
    py_identity,
    RNS.Destination.IN,
    RNS.Destination.SINGLE,
    "rete",
    "example",
    "v1",
)

def inbound_link_established(link):
    print(f"PY_INBOUND_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
    active_link[0] = link
    link.set_link_closed_callback(link_closed_cb)
    def link_packet_cb(data, packet):
        text = data.decode("utf-8", errors="replace")
        print(f"PY_LINK_DATA_RECEIVED:{{text}}", flush=True)
        link_data_received.set()
    link.set_packet_callback(link_packet_cb)
    link_established.set()

py_dest.set_link_established_callback(inbound_link_established)

py_dest.announce()
print(f"PY_DEST_HASH:{{py_dest.hexhash}}", flush=True)
print(f"PY_IDENTITY_HASH:{{py_identity.hexhash}}", flush=True)
print("PY_ANNOUNCE_SENT", flush=True)

timeout = {t.timeout}
deadline = time.time() + timeout
rust_dest_hash = None

print("PY_WAITING_FOR_ANNOUNCE", flush=True)

while time.time() < deadline:
    known = RNS.Transport.path_table
    for h in known:
        if h != py_dest.hash:
            rust_dest_hash = h
            print(f"PY_DISCOVERED:{{h.hex()}}", flush=True)
            break
    if rust_dest_hash:
        break
    time.sleep(0.5)

if not rust_dest_hash:
    print("PY_FAIL:timeout_waiting_for_rust_announce", flush=True)
    if link_established.wait(timeout=10):
        print("PY_INBOUND_LINK_OK", flush=True)
    else:
        print("PY_FAIL:no_link_established", flush=True)
        sys.exit(1)

if rust_dest_hash:
    rust_identity = RNS.Identity.recall(rust_dest_hash)
    if rust_identity:
        rust_dest = RNS.Destination(
            rust_identity,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            "rete",
            "example",
            "v1",
        )
        print(f"PY_RUST_DEST_HASH:{{rust_dest.hexhash}}", flush=True)
        print("PY_INITIATING_LINK", flush=True)
        link = RNS.Link(rust_dest, established_callback=link_established_cb, closed_callback=link_closed_cb)

        if not link_established.wait(timeout=15):
            print(f"PY_LINK_TIMEOUT:status={{link.status}}", flush=True)
        else:
            print("PY_LINK_ACTIVE", flush=True)

            pkt = RNS.Packet(link, b"hello via link from python")
            pkt.send()
            print("PY_LINK_DATA_SENT", flush=True)

            time.sleep(3)

            link.teardown()
            print("PY_LINK_TEARDOWN_SENT", flush=True)
            time.sleep(2)
    else:
        print("PY_FAIL:identity_not_recalled", flush=True)

print("PY_DONE", flush=True)
""")

        # Wait for Python to finish
        t.wait_for_line(py, "PY_DONE", timeout=t.timeout + 15)

        # Give Rust time to process
        time.sleep(2)

        # Collect output
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Python helper output", py)
        t.dump_output("Rust node stdout", rust)
        t.dump_output("Rust node stderr (last 1000)", rust_stderr.strip().split("\n"))

        # --- Assertion 1: Python discovered Rust announce ---
        t.check(
            t.has_line(py, "PY_DISCOVERED:"),
            "Python discovered Rust announce",
        )

        # --- Assertion 2: Link established (both sides) ---
        rust_link_ok = t.has_line(rust, "LINK_ESTABLISHED:")
        py_link_ok = (t.has_line(py, "PY_LINK_ESTABLISHED:")
                      or t.has_line(py, "PY_LINK_ACTIVE")
                      or t.has_line(py, "PY_INBOUND_LINK_ESTABLISHED:"))
        t.check(
            rust_link_ok and py_link_ok,
            "Link established (both sides)",
            detail=f"Rust={rust_link_ok} Python={py_link_ok}",
        )

        # --- Assertion 3: Rust received link data from Python ---
        t.check(
            t.has_line(rust, "LINK_DATA:", contains="hello via link from python"),
            "Rust received link data from Python",
        )

        # --- Assertion 4: Link teardown ---
        t.check(
            t.has_line(rust, "LINK_CLOSED:"),
            "Link teardown confirmed (Rust received LINK_CLOSED)",
        )


if __name__ == "__main__":
    main()
