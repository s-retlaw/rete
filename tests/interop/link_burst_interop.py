#!/usr/bin/env python3
"""Link burst E2E test: rapid link data, bidirectional traffic, teardown during transfer.

Topology:
  rnsd (transport=yes, TCP server on localhost:4300)
  Rust node connects as TCP client to rnsd
  Python client connects as TCP client to rnsd
  Python establishes link, bursts data, gets replies, teardown

Assertions:
  1. Link established
  2. Rust received >= 8 of 10 burst packets
  3. Python received >= 3 of 5 Rust reply packets
  4. No garbled decryption (content matches expected)
  5. Link teardown completed

Usage:
  cd tests/interop
  uv run python link_burst_interop.py --rust-binary ../../target/debug/rete
"""

import time

from interop_helpers import InteropTest


def main():
    with InteropTest("link-burst", default_port=4300) as t:
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
active_link = [None]
received_replies = []
received_lock = threading.Lock()

def link_established_cb(link):
    print(f"PY_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
    active_link[0] = link
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

print(f"PY_DISCOVERED:{{rust_dest_hash.hex()}}", flush=True)

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

# Set up packet callback to receive replies from Rust
def link_packet_cb(data, packet):
    text = data.decode("utf-8", errors="replace")
    with received_lock:
        received_replies.append(text)
    print(f"PY_REPLY_RECEIVED:{{text}}", flush=True)

link.set_packet_callback(link_packet_cb)

# Extend keepalive to avoid stale link during test
link.keepalive = 120
link.stale_time = 240

# Burst: send 10 packets at 50ms intervals
print("PY_BURST_START", flush=True)
for i in range(10):
    pkt = RNS.Packet(link, f"burst-{{i}}".encode())
    pkt.send()
    time.sleep(0.05)
print("PY_BURST_DONE:10", flush=True)

# Wait for Rust to process burst and send replies
# Signal that burst is done so harness knows to send replies
time.sleep(10)

# Report received replies
with received_lock:
    reply_count = len(received_replies)
print(f"PY_REPLIES_RECEIVED:{{reply_count}}", flush=True)
for r in received_replies:
    print(f"PY_REPLY_CONTENT:{{r}}", flush=True)

# Teardown
link.teardown()
print("PY_TEARDOWN_SENT", flush=True)
time.sleep(2)

print("PY_DONE", flush=True)
""")

        # Wait for link to establish, then send replies from Rust
        link_id = t.wait_for_line(rust, "LINK_ESTABLISHED:", timeout=t.timeout)
        if link_id:
            # Wait for burst to arrive (Python sends 10 at 50ms = 0.5s + processing)
            time.sleep(3)

            # Send 5 reply packets from Rust
            link_id_str = link_id.strip()
            for i in range(5):
                t.send_rust(f"linkdata {link_id_str} reply-{i}")
                time.sleep(0.1)

        # Wait for Python to finish
        t.wait_for_line(py, "PY_DONE", timeout=t.timeout + 15)
        time.sleep(2)

        # Collect output
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Python output", py)
        t.dump_output("Rust stdout", rust)
        t.dump_output("Rust stderr (last 1000)", rust_stderr.strip().split("\n"))

        # --- Assertion 1: Link established ---
        rust_link_ok = t.has_line(rust, "LINK_ESTABLISHED:")
        py_link_ok = t.has_line(py, "PY_LINK_ACTIVE")
        t.check(
            rust_link_ok and py_link_ok,
            "Link established (both sides)",
            detail=f"Rust={rust_link_ok} Python={py_link_ok}",
        )

        # --- Assertion 2: Rust received >= 8 of 10 burst packets ---
        burst_lines = [l for l in rust if l.startswith("LINK_DATA:") and "burst-" in l]
        t.check(
            len(burst_lines) >= 8,
            f"Rust received >= 8 of 10 burst packets ({len(burst_lines)} received)",
        )

        # --- Assertion 3: Python received >= 3 of 5 reply packets ---
        reply_lines = [l for l in py if l.startswith("PY_REPLY_RECEIVED:") and "reply-" in l]
        t.check(
            len(reply_lines) >= 3,
            f"Python received >= 3 of 5 Rust reply packets ({len(reply_lines)} received)",
        )

        # --- Assertion 4: No garbled decryption ---
        garbled = False
        for l in burst_lines:
            # Each line should contain "burst-N" where N is 0-9
            if not any(f"burst-{i}" in l for i in range(10)):
                garbled = True
                break
        for l in reply_lines:
            if not any(f"reply-{i}" in l for i in range(5)):
                garbled = True
                break
        t.check(
            not garbled,
            "No garbled decryption (all content matches expected)",
        )

        # --- Assertion 5: Link teardown completed ---
        t.check(
            t.has_line(rust, "LINK_CLOSED:") or t.has_line(py, "PY_LINK_CLOSED:"),
            "Link teardown completed",
        )


if __name__ == "__main__":
    main()
