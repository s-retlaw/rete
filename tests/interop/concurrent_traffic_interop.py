#!/usr/bin/env python3
"""E2E: Concurrent traffic -- 2 Python clients with concurrent links.

Topology: Two Python clients -> rnsd -> Rust
  - Client A: link + channel messages
  - Client B: link + plain data
  - Both: simultaneous announce discovery
"""

import time
from interop_helpers import InteropTest


def main():
    with InteropTest("concurrent-traffic", default_port=4345, default_timeout=45) as t:
        t.start_rnsd()
        rust = t.start_rust()

        time.sleep(3)

        # Client A: channel messages
        py_a = t.start_py_helper(f"""\
import RNS, RNS.Channel, time, sys, os

config_dir = os.path.join("{t.tmpdir}", "py_client_a_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config()}\"\"\")

reticulum = RNS.Reticulum(config_dir)
time.sleep(2)

# Discover Rust node
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
    print("A_NO_PATH", flush=True)
    sys.exit(1)

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
    print("A_LINK_FAIL", flush=True)
    sys.exit(1)

print("A_LINK_ACTIVE", flush=True)
time.sleep(0.5)

# Send channel messages
channel = link.get_channel()

class ChanMsgA(RNS.Channel.MessageBase):
    MSGTYPE = 0x0400
    def __init__(self):
        self.data = b""
    def pack(self):
        return self.data
    def unpack(self, raw):
        self.data = raw

channel.register_message_type(ChanMsgA)

for i in range(5):
    msg = ChanMsgA()
    msg.data = f"clientA-msg-{{i}}".encode()
    channel.send(msg)
    time.sleep(0.2)

print("A_CHANNELS_SENT", flush=True)
time.sleep(3)

link.teardown()
print("A_DONE", flush=True)
""")

        # Client B: plain link data (slight delay to overlap)
        time.sleep(0.5)
        py_b = t.start_py_helper(f"""\
import RNS, time, sys, os

config_dir = os.path.join("{t.tmpdir}", "py_client_b_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config()}\"\"\")

reticulum = RNS.Reticulum(config_dir)
time.sleep(2)

# Discover Rust node
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
    print("B_NO_PATH", flush=True)
    sys.exit(1)

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
    print("B_LINK_FAIL", flush=True)
    sys.exit(1)

print("B_LINK_ACTIVE", flush=True)
time.sleep(0.5)

# Send plain link data
for i in range(5):
    RNS.Packet(link, f"clientB-data-{{i}}".encode()).send()
    time.sleep(0.2)

print("B_DATA_SENT", flush=True)
time.sleep(3)

link.teardown()
print("B_DONE", flush=True)
""")

        # Both should establish links
        a_active = t.wait_for_line(py_a, "A_LINK_ACTIVE")
        t.check(a_active is not None, "Client A link established")

        b_active = t.wait_for_line(py_b, "B_LINK_ACTIVE")
        t.check(b_active is not None, "Client B link established")

        # Both should send data
        a_sent = t.wait_for_line(py_a, "A_CHANNELS_SENT")
        t.check(a_sent is not None, "Client A channel messages sent")

        b_sent = t.wait_for_line(py_b, "B_DATA_SENT")
        t.check(b_sent is not None, "Client B plain data sent")

        # Both should complete
        a_done = t.wait_for_line(py_a, "A_DONE")
        t.check(a_done is not None, "Client A completed")

        b_done = t.wait_for_line(py_b, "B_DONE")
        t.check(b_done is not None, "Client B completed")

        # Rust should still be alive
        t.check(t._rust_proc.poll() is None, "Rust node survived concurrent traffic")

        # Count received data
        channel_msgs = [l for l in rust if "CHANNEL_MSG" in l and "clientA" in l]
        link_data = [l for l in rust if "LINK_DATA" in l and "clientB" in l]
        t.check(len(channel_msgs) >= 3, f"Received >= 3/5 channel msgs from A ({len(channel_msgs)})")
        t.check(len(link_data) >= 3, f"Received >= 3/5 data pkts from B ({len(link_data)})")


if __name__ == "__main__":
    main()
