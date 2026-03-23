#!/usr/bin/env python3
"""Channel E2E interop test: Python client sends Channel messages to Rust node via Link.

Topology:
  rnsd (transport=yes, TCP server on localhost:4245)
  Rust node connects as TCP client to rnsd
  Python client connects as TCP client to rnsd
  Python discovers Rust via announce, establishes a Link, then sends Channel messages

Assertions:
  1. Link established (both sides)
  2. Python sends channel message, Rust receives CHANNEL_MSG
  3. Second channel message also received
  4. Link teardown works

Usage:
  cd tests/interop
  uv run python channel_interop.py --rust-binary ../../target/debug/rete-linux
"""

import time

from interop_helpers import InteropTest


def main():
    with InteropTest("channel-interop", default_port=4245) as t:
        t.start_rnsd()
        rust = t.start_rust()

        # Give Rust time to connect and announce
        time.sleep(3)

        # Start Python client that discovers Rust, links, and sends channel messages
        py = t.start_py_helper(f"""\
import RNS
import RNS.Channel
import time
import sys
import os
import threading

config_dir = os.path.join("{t.tmpdir}", "py_client_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config()}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

class TestMessage(RNS.Channel.MessageBase):
    MSGTYPE = 0x0100
    def __init__(self):
        self.data = b""
    def pack(self):
        return self.data
    def unpack(self, raw):
        self.data = raw

class TestMessage2(RNS.Channel.MessageBase):
    MSGTYPE = 0x0200
    def __init__(self):
        self.data = b""
    def pack(self):
        return self.data
    def unpack(self, raw):
        self.data = raw

link_established = threading.Event()
active_link = [None]

def link_established_cb(link):
    print(f"PY_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
    active_link[0] = link
    link_established.set()

def link_closed_cb(link):
    print(f"PY_LINK_CLOSED:{{link.link_id.hex()}}", flush=True)

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

rust_identity = RNS.Identity.recall(rust_dest_hash)
if not rust_identity:
    print("PY_FAIL:identity_not_recalled", flush=True)
    sys.exit(1)

rust_dest = RNS.Destination(
    rust_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
    "rete", "example", "v1",
)

link = RNS.Link(rust_dest, established_callback=link_established_cb, closed_callback=link_closed_cb)

if not link_established.wait(timeout=15):
    print(f"PY_LINK_TIMEOUT:status={{link.status}}", flush=True)
    sys.exit(1)

print("PY_LINK_ACTIVE", flush=True)

channel = link.get_channel()
channel.register_message_type(TestMessage)
channel.register_message_type(TestMessage2)

msg1 = TestMessage()
msg1.data = b"channel msg from python"
channel.send(msg1)
print("PY_CHANNEL_MSG1_SENT:0x0100", flush=True)
time.sleep(3)

msg2 = TestMessage2()
msg2.data = b"second channel message"
channel.send(msg2)
print("PY_CHANNEL_MSG2_SENT:0x0200", flush=True)
time.sleep(3)

link.teardown()
print("PY_LINK_TEARDOWN_SENT", flush=True)
time.sleep(2)

print("PY_DONE", flush=True)
""")

        # Wait for Python to finish
        t.wait_for_line(py, "PY_DONE", timeout=t.timeout + 15)
        time.sleep(2)

        # Collect output
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Python helper output", py)
        t.dump_output("Rust node stdout", rust)
        t.dump_output("Rust node stderr (last 1000)", rust_stderr.strip().split("\n"))

        # Assertions
        t.check(
            t.has_line(rust, "LINK_ESTABLISHED:") and t.has_line(py, "PY_LINK_ACTIVE"),
            "Link established (both sides)",
        )

        t.check(
            t.has_line(rust, "CHANNEL_MSG:", contains="channel msg from python"),
            "Rust received first channel message (type=0x0100)",
        )

        t.check(
            t.has_line(rust, "CHANNEL_MSG:", contains="second channel message"),
            "Rust received second channel message (type=0x0200)",
        )

        t.check(t.has_line(rust, "LINK_CLOSED:"), "Link teardown confirmed")


if __name__ == "__main__":
    main()
