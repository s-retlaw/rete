#!/usr/bin/env python3
"""Channel relay interop: Python sends channel messages to Rust through rnsd relay.

Topology:
  Python-A (initiator) <-TCP-> rnsd (transport) <-TCP-> Rust (responder)

Tests that channel messages work through a relay when Python initiates a link
to the Rust node through rnsd. Rust echoes channel messages back (esp32-test
firmware behavior replicated by rete-linux's echo mode).

Usage:
  cd tests/interop
  uv run python channel_relay_interop.py --rust-binary ../../target/debug/rete-linux
"""

import time

from interop_helpers import InteropTest


RNSD_PORT = 4270


def main():
    with InteropTest("channel-relay-interop", default_port=RNSD_PORT) as t:
        # Start rnsd transport relay
        t.start_rnsd(port=RNSD_PORT)

        # Start Rust node connected to rnsd (not as transport — just a client)
        rust_lines = t.start_rust(port=RNSD_PORT)

        # Wait for Rust to connect and announce
        time.sleep(3.0)

        # Python client discovers Rust, establishes link, sends channel messages
        py = t.start_py_helper(f"""\
import RNS
import RNS.Channel
import time
import sys
import os

config_dir = os.path.join("{t.tmpdir}", "py_client_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config(port=RNSD_PORT)}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

class TestMessage(RNS.Channel.MessageBase):
    MSGTYPE = 0x0001
    def __init__(self):
        self.data = b""
    def pack(self):
        return self.data
    def unpack(self, raw):
        self.data = raw

import threading

link_established = threading.Event()
received_channel_msgs = []

def link_established_cb(link):
    print(f"PY_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
    link_established.set()

def link_closed_cb(link):
    print(f"PY_LINK_CLOSED:{{link.link_id.hex()}}", flush=True)

def channel_msg_handler(message):
    received_channel_msgs.append(message.data)
    print(f"PY_CHANNEL_RECV:{{message.data}}", flush=True)

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

print(f"PY_ANNOUNCE_RECV:{{rust_dest_hash.hex()}}", flush=True)

rust_identity = RNS.Identity.recall(rust_dest_hash)
rust_dest = RNS.Destination(
    rust_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
    "rete", "example", "v1",
)

link = RNS.Link(rust_dest, established_callback=link_established_cb, closed_callback=link_closed_cb)

if not link_established.wait(timeout=15):
    print(f"PY_LINK_TIMEOUT:status={{link.status}}", flush=True)
    sys.exit(1)

# Set up channel
channel = link.get_channel()
channel.register_message_type(TestMessage)
channel.add_message_handler(channel_msg_handler)

time.sleep(2.0)  # LRRTT stabilization

# Send channel messages
msg1 = TestMessage()
msg1.data = b"relay-channel-test-1"
channel.send(msg1)
print("PY_CHANNEL_SENT:1", flush=True)

time.sleep(3.0)

msg2 = TestMessage()
msg2.data = b"relay-channel-test-2"
channel.send(msg2)
print("PY_CHANNEL_SENT:2", flush=True)

time.sleep(3.0)

link.teardown()
print("PY_TEARDOWN", flush=True)
time.sleep(2)

print("PY_DONE", flush=True)
""")

        # Wait for Python to finish
        t.wait_for_line(py, "PY_DONE", timeout=t.timeout + 15)
        time.sleep(2)

        # Collect output
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Python helper output", py)
        t.dump_output("Rust node stdout", rust_lines)

        # Assertions
        t.check(
            t.has_line(py, "PY_LINK_ESTABLISHED:"),
            "Link established through relay",
        )

        t.check(
            t.has_line(rust_lines, "CHANNEL_MSG:", contains="relay-channel-test-1"),
            "Rust received first channel message through relay",
        )

        t.check(
            t.has_line(rust_lines, "CHANNEL_MSG:", contains="relay-channel-test-2"),
            "Rust received second channel message through relay",
        )

        t.check(
            t.has_line(rust_lines, "LINK_CLOSED:"),
            "Link closed cleanly",
        )


if __name__ == "__main__":
    main()
