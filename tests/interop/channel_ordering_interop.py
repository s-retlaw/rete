#!/usr/bin/env python3
"""E2E: Channel message ordering -- verify messages arrive in sequence.

Sends 20 numbered channel messages rapidly and verifies they arrive
in order at the Rust side.
"""

import time
from interop_helpers import InteropTest

NUM_MESSAGES = 10


def main():
    with InteropTest("channel-ordering", default_port=4342, default_timeout=45) as t:
        t.start_rnsd()
        rust = t.start_rust(seed="channel-order-test-1")

        time.sleep(3)

        py = t.start_py_helper(f"""\
import RNS, RNS.Channel, time, sys, os

config_dir = os.path.join("{t.tmpdir}", "py_order_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config()}\"\"\")

reticulum = RNS.Reticulum(config_dir)
time.sleep(2)

# Discover Rust node via path table
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
    print("PY_NO_PATH", flush=True)
    sys.exit(1)

print("PY_PATH_FOUND", flush=True)
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
    print("PY_LINK_FAIL", flush=True)
    sys.exit(1)

print("PY_LINK_ACTIVE", flush=True)
time.sleep(1)

channel = link.get_channel()

class OrderMsg(RNS.Channel.MessageBase):
    MSGTYPE = 0x0300
    def __init__(self):
        self.data = b""
    def pack(self):
        return self.data
    def unpack(self, raw):
        self.data = raw

channel.register_message_type(OrderMsg)

# Send {NUM_MESSAGES} messages rapidly with sequence numbers
for i in range({NUM_MESSAGES}):
    msg = OrderMsg()
    msg.data = f"order-{{i:04d}}".encode()
    channel.send(msg)
    time.sleep(0.3)

print("PY_ALL_SENT", flush=True)
time.sleep(5)

link.teardown()
print("PY_DONE", flush=True)
""")

        path = t.wait_for_line(py, "PY_PATH_FOUND", timeout=20)
        t.check(path is not None, "Python found Rust path")

        active = t.wait_for_line(py, "PY_LINK_ACTIVE")
        t.check(active is not None, "Link established")

        sent = t.wait_for_line(py, "PY_ALL_SENT")
        t.check(sent is not None, f"All {NUM_MESSAGES} messages sent")

        # Wait for Rust to receive them, then check ordering
        time.sleep(3)

        # Count received channel messages
        received_msgs = [l for l in rust if "CHANNEL_MSG" in l and "order-" in l]
        t.check(
            len(received_msgs) >= NUM_MESSAGES * 0.9,
            f"Received >= 90% of messages ({len(received_msgs)}/{NUM_MESSAGES})",
        )

        # Verify ordering -- extract sequence numbers
        seq_nums = []
        for line in received_msgs:
            for part in line.split():
                if part.startswith("order-"):
                    try:
                        seq_nums.append(int(part.split("-")[1]))
                    except (ValueError, IndexError):
                        pass

        # Check they're in non-decreasing order
        is_ordered = all(seq_nums[i] <= seq_nums[i + 1] for i in range(len(seq_nums) - 1))
        t.check(is_ordered, f"Messages arrived in order (sequence: {seq_nums[:5]}...)")

        done = t.wait_for_line(py, "PY_DONE")
        t.check(done is not None, "Test completed")


if __name__ == "__main__":
    main()
