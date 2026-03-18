#!/usr/bin/env python3
"""Rust-initiates-link-through-relay E2E interop test.

Topology:
  Rust (initiator) --TCP client--> rnsd (transport=yes, port 4275) <--TCP client-- Python (responder)

Rust discovers Python via announce through rnsd relay, then initiates a Link
using the `link <dest_hex>` stdin command. Verifies link establishment,
channel message exchange, and teardown.

Assertions:
  1. Rust discovers Python's announce (via relay)
  2. Link established (both sides)
  3. Rust sends channel message, Python receives it
  4. Python sends data back, Rust receives it
  5. Link teardown works

Usage:
  cd tests/interop
  uv run python link_initiate_relay_interop.py --rust-binary ../../target/debug/rete-linux
"""

import time

from interop_helpers import InteropTest


def main():
    with InteropTest("link-init-relay", default_port=4275) as t:
        t.start_rnsd()
        rust = t.start_rust(seed="link-init-relay-seed-03")

        # Give Rust time to connect and announce
        time.sleep(3)

        # Start Python responder that accepts inbound links
        py = t.start_py_helper(f"""\
import RNS
import RNS.Channel
import time
import sys
import os
import threading

config_dir = os.path.join("{t.tmpdir}", "py_responder_config")
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

link_established = threading.Event()
channel_msg_received = threading.Event()
received_channel_data = [None]
active_link = [None]

def inbound_link_established(link):
    print(f"PY_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
    active_link[0] = link
    link_established.set()

    # Set up channel handler to receive messages from Rust
    channel = link.get_channel()
    channel.register_message_type(TestMessage)

    def msg_handler(msg):
        text = msg.data.decode("utf-8", errors="replace")
        print(f"PY_CHANNEL_MSG_RECEIVED:{{text}}", flush=True)
        received_channel_data[0] = text
        channel_msg_received.set()

    channel.add_message_handler(msg_handler)

    # Also set up packet callback for link data
    def link_packet_cb(data, packet):
        text = data.decode("utf-8", errors="replace")
        print(f"PY_LINK_DATA_RECEIVED:{{text}}", flush=True)

    link.set_packet_callback(link_packet_cb)

    # Send data back to Rust over the link
    time.sleep(0.5)
    pkt = RNS.Packet(link, b"hello from python via relay link")
    pkt.send()
    print("PY_LINK_DATA_SENT", flush=True)

def link_closed_cb(link):
    print(f"PY_LINK_CLOSED:{{link.link_id.hex()}}", flush=True)

py_identity = RNS.Identity()
py_dest = RNS.Destination(
    py_identity,
    RNS.Destination.IN,
    RNS.Destination.SINGLE,
    "rete",
    "example",
    "v1",
)
py_dest.set_link_established_callback(inbound_link_established)

# Announce so Rust can discover us
py_dest.announce()
print(f"PY_DEST_HASH:{{py_dest.hexhash}}", flush=True)
print("PY_ANNOUNCE_SENT", flush=True)

# Wait for link establishment
if not link_established.wait(timeout={t.timeout}):
    print("PY_FAIL:no_link_established", flush=True)
    sys.exit(1)

# Wait for channel message from Rust
if channel_msg_received.wait(timeout=15):
    print(f"PY_CHANNEL_OK:{{received_channel_data[0]}}", flush=True)
else:
    print("PY_CHANNEL_TIMEOUT", flush=True)

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
            t._log("FAIL: Python did not report dest hash")
            t.check(False, "Python reported dest hash")
            return

        t._log(f"Python dest hash: {py_dest_hash}")

        # Wait for Rust to discover Python's announce
        rust_saw_announce = t.wait_for_line(rust, f"ANNOUNCE:{py_dest_hash}") is not None

        # Tell Rust to initiate a link
        t.send_rust(f"link {py_dest_hash}")

        # Wait for Rust link establishment
        rust_link_id = t.wait_for_line(rust, "LINK_ESTABLISHED:")
        if rust_link_id:
            time.sleep(1)  # let link settle
            # Send channel message from Rust
            t.send_rust(f"channel {rust_link_id} 0x0100 hello from rust via relay link")

        # Wait for Python to finish
        t.wait_for_line(py, "PY_DONE", timeout=t.timeout)
        time.sleep(2)

        # Collect output for diagnostics
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Python responder stdout", py)
        t.dump_output("Rust node stdout", rust)
        t.dump_output("Rust node stderr (last 1000)", rust_stderr.strip().split("\n"))

        # Assertions
        t.check(rust_saw_announce, "Rust discovered Python's announce (via relay)")

        t.check(
            t.has_line(rust, "LINK_ESTABLISHED:") and t.has_line(py, "PY_LINK_ESTABLISHED:"),
            "Link established (both sides)",
            detail=f"Rust={t.has_line(rust, 'LINK_ESTABLISHED:')} Python={t.has_line(py, 'PY_LINK_ESTABLISHED:')}",
        )

        t.check(
            t.has_line(py, "PY_CHANNEL_MSG_RECEIVED:", contains="hello from rust via relay link"),
            "Python received channel message from Rust (via relay)",
        )

        t.check(
            t.has_line(rust, "LINK_DATA:", contains="hello from python via relay link"),
            "Rust received data from Python (via relay)",
        )

        t.check(
            t.has_line(rust, "LINK_CLOSED:"),
            "Link teardown confirmed",
        )


if __name__ == "__main__":
    main()
