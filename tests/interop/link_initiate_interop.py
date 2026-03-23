#!/usr/bin/env python3
"""Link-initiation E2E interop test: Rust initiates a Link to a Python node via rnsd.

Topology:
  rnsd (transport=yes, TCP server on localhost:4250)
  Rust node connects as TCP client to rnsd
  Python node connects as TCP client to rnsd
  Rust discovers Python via announce, then initiates a Link

Assertions:
  1. Rust discovered Python's announce
  2. Link established (both sides)
  3. Python received data from Rust over the link
  4. Rust received data from Python over the link
  5. Link teardown (Rust prints LINK_CLOSED)

Usage:
  cd tests/interop
  uv run python link_initiate_interop.py --rust-binary ../../target/debug/rete-linux
"""

import time

from interop_helpers import InteropTest


def main():
    with InteropTest("link-init-interop", default_port=4250) as t:
        t.start_rnsd()
        rust = t.start_rust()

        # Give Rust time to connect and announce
        time.sleep(3)

        # Start Python responder that accepts inbound links
        py = t.start_py_helper(f"""\
import RNS
import time
import sys
import os
import threading

config_dir = os.path.join("{t.tmpdir}", "py_responder_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config()}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

link_established = threading.Event()
link_data_received = threading.Event()
received_data_text = [None]
active_link = [None]

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
    print(f"PY_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
    active_link[0] = link
    link_established.set()

    def link_packet_cb(data, packet):
        text = data.decode("utf-8", errors="replace")
        print(f"PY_LINK_DATA_RECEIVED:{{text}}", flush=True)
        received_data_text[0] = text
        link_data_received.set()

    link.set_packet_callback(link_packet_cb)

    # Send data back to Rust over the link
    time.sleep(0.5)
    pkt = RNS.Packet(link, b"hello from python via link")
    pkt.send()
    print("PY_LINK_DATA_SENT", flush=True)

py_dest.set_link_established_callback(inbound_link_established)

# Announce so Rust can discover us
py_dest.announce()
print(f"PY_DEST_HASH:{{py_dest.hexhash}}", flush=True)
print("PY_ANNOUNCE_SENT", flush=True)

# Wait for link establishment
if not link_established.wait(timeout={t.timeout}):
    print("PY_FAIL:no_link_established", flush=True)
    sys.exit(1)

# Wait for data from Rust
if not link_data_received.wait(timeout=15):
    print("PY_FAIL:no_data_received", flush=True)
else:
    print(f"PY_DATA_OK:{{received_data_text[0]}}", flush=True)

# Give time for Rust to receive our data
time.sleep(3)

# Teardown the link
if active_link[0]:
    active_link[0].teardown()
    print("PY_LINK_TEARDOWN_SENT", flush=True)
    time.sleep(2)

print("PY_DONE", flush=True)
""")

        # Wait for Python's dest hash, then Rust's announce discovery
        py_dest_hash = t.wait_for_line(py, "PY_DEST_HASH:")
        if not py_dest_hash:
            print("[link-init-interop] FAIL: Python did not report dest hash")
            return

        rust_saw_announce = t.wait_for_line(rust, f"ANNOUNCE:{py_dest_hash}") is not None

        # Tell Rust to initiate a link
        t.send_rust(f"link {py_dest_hash}")

        # Wait for Rust link establishment
        rust_link_id = t.wait_for_line(rust, "LINK_ESTABLISHED:")
        if rust_link_id:
            time.sleep(1)  # let link settle
            t.send_rust(f"linkdata {rust_link_id} hello from rust via link")

        # Wait for Python to finish
        t.wait_for_line(py, "PY_DONE", timeout=t.timeout)
        time.sleep(2)

        # Collect output for diagnostics
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Python responder stdout", py)
        t.dump_output("Rust node stdout", rust)
        t.dump_output("Rust node stderr (last 1000)", rust_stderr.strip().split("\n"))

        # Assertions
        t.check(rust_saw_announce, "Rust discovered Python's announce")

        t.check(
            t.has_line(rust, "LINK_ESTABLISHED:") and t.has_line(py, "PY_LINK_ESTABLISHED:"),
            "Link established (both sides)",
            detail=f"Rust={t.has_line(rust, 'LINK_ESTABLISHED:')} Python={t.has_line(py, 'PY_LINK_ESTABLISHED:')}",
        )

        t.check(
            t.has_line(py, "PY_LINK_DATA_RECEIVED:", contains="hello from rust via link"),
            "Python received data from Rust",
        )

        t.check(
            t.has_line(rust, "LINK_DATA:", contains="hello from python via link"),
            "Rust received data from Python",
        )

        t.check(t.has_line(rust, "LINK_CLOSED:"), "Link teardown confirmed")


if __name__ == "__main__":
    main()
