#!/usr/bin/env python3
"""E2E: Mixed stress -- 2 concurrent Python nodes doing different things.

Phase 1: 2 nodes connect, discover Rust path, then announce
Phase 2: Both establish links to Rust
Phase 3: Even nodes send channel messages, all send plain data
Phase 4: Everyone tears down

Note: Python nodes discover the Rust path BEFORE announcing. When Python
RNS clients send announces through rnsd, it can trigger rnsd announce
rate-limiting that prevents the Rust announce from being relayed. By
discovering the Rust path first, we avoid this timing issue.
"""

import time
from interop_helpers import InteropTest


def main():
    with InteropTest("mixed-stress", default_port=4352, default_timeout=60) as t:
        t.start_rnsd()

        # Start Python nodes FIRST so they are connected to rnsd
        # when the Rust announce arrives.
        nodes = []
        for node_id in range(2):
            py = t.start_py_helper(f"""\
import RNS, RNS.Channel, time, sys, os

config_dir = os.path.join("{t.tmpdir}", "py_stress{node_id}_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config()}\"\"\")

reticulum = RNS.Reticulum(config_dir)
print("N{node_id}_CONNECTED", flush=True)

# Wait for Rust announce BEFORE announcing ourselves.
# rnsd announce rate-limiting can prevent the Rust announce from
# reaching us if we announce first.
deadline = time.time() + 30
rust_dest_hash = None
while time.time() < deadline:
    for h in list(RNS.Transport.path_table.keys()):
        recalled = RNS.Identity.recall(h)
        if recalled is None:
            continue
        try:
            test_dest = RNS.Destination(recalled, RNS.Destination.OUT,
                                         RNS.Destination.SINGLE,
                                         "rete", "example", "v1")
            if test_dest.hash == h:
                rust_dest_hash = h
                break
        except Exception:
            continue
    if rust_dest_hash:
        break
    time.sleep(0.5)

if not rust_dest_hash:
    print("N{node_id}_NO_PATH", flush=True)
    time.sleep(3)
    sys.exit(1)

print("N{node_id}_PATH_FOUND", flush=True)

# NOW announce (so Rust sees our announce for bidirectional test)
identity = RNS.Identity()
dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                       "stress", "node{node_id}")
dest.announce(app_data=b"stress-node-{node_id}")
print("N{node_id}_ANNOUNCED", flush=True)

rust_identity = RNS.Identity.recall(rust_dest_hash)
rust_dest = RNS.Destination(rust_identity, RNS.Destination.OUT,
                             RNS.Destination.SINGLE, "rete", "example", "v1")

# Establish link
link = RNS.Link(rust_dest)
start = time.time()
while link.status != RNS.Link.ACTIVE and time.time() - start < 20:
    time.sleep(0.2)

if link.status != RNS.Link.ACTIVE:
    print("N{node_id}_LINK_FAIL", flush=True)
    time.sleep(10)
    sys.exit(1)

print("N{node_id}_LINK_ACTIVE", flush=True)

# Send a mix of data types
for i in range(3):
    RNS.Packet(link, f"stress-n{node_id}-data-{{i}}".encode()).send()
    time.sleep(0.3)

if {node_id} % 2 == 0:
    channel = link.get_channel()

    class StressMsg(RNS.Channel.MessageBase):
        MSGTYPE = 0x0500
        def __init__(self):
            self.data = b""
        def pack(self):
            return self.data
        def unpack(self, raw):
            self.data = raw

    channel.register_message_type(StressMsg)

    for i in range(3):
        msg = StressMsg()
        msg.data = f"stress-n{node_id}-chan-{{i}}".encode()
        channel.send(msg)
        time.sleep(0.3)

print("N{node_id}_DATA_SENT", flush=True)
time.sleep(3)
link.teardown()
print("N{node_id}_DONE", flush=True)
""")
            nodes.append(py)

        # Wait for Python nodes to connect
        for i, py in enumerate(nodes):
            connected = t.wait_for_line(py, f"N{i}_CONNECTED")
            t.check(connected is not None, f"Node {i} connected")

        # Wait for connections to settle
        time.sleep(2)

        # NOW start Rust node -- its announce will reach all connected Python nodes
        rust = t.start_rust(seed="mixed-stress-test-1")

        # All should find path
        for i, py in enumerate(nodes):
            path = t.wait_for_line(py, f"N{i}_PATH_FOUND", timeout=40)
            t.check(path is not None, f"Node {i} found path")

        # All should announce (after finding path)
        for i, py in enumerate(nodes):
            announced = t.wait_for_line(py, f"N{i}_ANNOUNCED", timeout=10)
            t.check(announced is not None, f"Node {i} announced")

        # All should establish links
        for i, py in enumerate(nodes):
            active = t.wait_for_line(py, f"N{i}_LINK_ACTIVE", timeout=30)
            t.check(active is not None, f"Node {i} link established")

        # All should send data
        for i, py in enumerate(nodes):
            sent = t.wait_for_line(py, f"N{i}_DATA_SENT", timeout=15)
            t.check(sent is not None, f"Node {i} data sent")

        # All should complete
        for i, py in enumerate(nodes):
            done = t.wait_for_line(py, f"N{i}_DONE", timeout=15)
            t.check(done is not None, f"Node {i} completed")

        # Rust should still be alive
        t.check(t._rust_proc.poll() is None, "Rust survived 2-node mixed stress")

        # Count total received data
        all_data = [l for l in rust if "LINK_DATA" in l or "CHANNEL_MSG" in l]
        t.check(len(all_data) >= 6, f"Received >= 6 total messages ({len(all_data)})")


if __name__ == "__main__":
    main()
