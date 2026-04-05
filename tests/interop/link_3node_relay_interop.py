#!/usr/bin/env python3
"""Link establishment through a 2-relay chain where rete is the SECOND relay.

Topology:
  Python_A (initiator) --TCP--> rnsd_1 (relay, port 4296) --TCP--> rete (relay, --transport) --TCP--> rnsd_2 (port 4297) <--TCP-- Python_B (responder)

This tests the same relay configuration as the ESP32 3-node test but purely over TCP.
rnsd_1 is the first relay (closest to initiator), rete is the second relay
(closest to responder).

Assertions:
  1. Python_B announce received by Python_A through relay chain
  2. Link established through 2-relay chain
  3. Channel message delivered through relay chain
  4. Link teardown works

Usage:
  cd tests/interop
  uv run python link_3node_relay_interop.py --rust-binary ../../target/debug/rete
"""

import time

from interop_helpers import InteropTest


def main():
    with InteropTest("link-3node-relay", default_port=4296) as t:
        port1 = t.port       # 4296
        port2 = t.port + 1   # 4297

        # 1. Start two rnsd instances (both as transport nodes)
        t.start_rnsd(port=port1)
        t.start_rnsd(port=port2)

        # 2. Start rete connecting to BOTH rnsd instances with --transport
        rust = t.start_rust(
            port=port1,
            extra_args=[
                "--connect", f"127.0.0.1:{port2}",
                "--transport",
            ],
        )

        # Get the Rust transport node's dest hash from stdout so Python nodes can filter it out
        rust_dest_hex = t.wait_for_line(rust, "IDENTITY:", timeout=10) or ""
        t._log(f"Rust transport dest hash: {rust_dest_hex}")

        # Give Rust time to connect and announce on both interfaces
        time.sleep(3)

        # 3. Start Python_B (responder) — connects to rnsd_2, announces, waits for link
        py_b = t.start_py_helper(f"""\
import RNS
import RNS.Channel
import time
import sys
import os
import threading

config_dir = os.path.join("{t.tmpdir}", "py_b_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config(port=port2)}\"\"\")

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
    print(f"PY_B_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
    active_link[0] = link
    link_established.set()

    channel = link.get_channel()
    channel.register_message_type(TestMessage)

    def msg_handler(msg):
        text = msg.data.decode("utf-8", errors="replace")
        print(f"PY_B_CHANNEL_MSG_RECEIVED:{{text}}", flush=True)
        received_channel_data[0] = text
        channel_msg_received.set()

        # Echo back with prefix
        echo = TestMessage()
        echo.data = ("echo:" + text).encode("utf-8")
        channel.send(echo)
        print(f"PY_B_ECHO_SENT:echo:{{text}}", flush=True)

    channel.add_message_handler(msg_handler)

def link_closed_cb(link):
    print(f"PY_B_LINK_CLOSED:{{link.link_id.hex()}}", flush=True)

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

# Announce so others can discover us
py_dest.announce()
print(f"PY_B_DEST_HASH:{{py_dest.hexhash}}", flush=True)
print("PY_B_ANNOUNCED", flush=True)

# Wait for link establishment
if not link_established.wait(timeout={t.timeout}):
    print("PY_B_FAIL:no_link_established", flush=True)
    sys.exit(1)

# Wait for channel message
if channel_msg_received.wait(timeout=15):
    print(f"PY_B_CHANNEL_OK:{{received_channel_data[0]}}", flush=True)
else:
    print("PY_B_CHANNEL_FAIL:timeout", flush=True)

# Give time for teardown
time.sleep(5)
print("PY_B_DONE", flush=True)
""")

        # Wait for Python_B to announce
        t.wait_for_line(py_b, "PY_B_ANNOUNCED")
        time.sleep(5)  # Allow announce to propagate through rnsd_2 -> Rust -> rnsd_1

        # 4. Start Python_A (initiator) — connects to rnsd_1, discovers B, initiates link
        # Also includes LRPROOF diagnostic monkey-patching on the rnsd_1 side
        py_a = t.start_py_helper(f"""\
import RNS
import RNS.Channel
import time
import sys
import os
import threading
import struct

config_dir = os.path.join("{t.tmpdir}", "py_a_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config(port=port1)}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

# Monkey-patch Transport.inbound to log LRPROOF handling at rnsd_1
original_inbound = RNS.Transport.inbound.__func__ if hasattr(RNS.Transport.inbound, '__func__') else RNS.Transport.inbound

def patched_inbound(raw, interface=None):
    if len(raw) >= 19:
        flags = raw[0]
        pkt_type = flags & 0x03
        if pkt_type == 3:  # PROOF
            header_type = (flags >> 6) & 0x03
            hops = raw[1]
            if header_type == 0:  # H1
                dest_hash = raw[2:18]
                ctx = raw[18] if len(raw) > 18 else 0
            else:  # H2
                dest_hash = raw[18:34]
                ctx = raw[34] if len(raw) > 34 else 0
            if ctx == 0xFF:  # LRPROOF
                lid_hex = dest_hash.hex()[:16]
                in_lt = dest_hash in RNS.Transport.link_table
                lt_info = ""
                if in_lt:
                    lte = RNS.Transport.link_table[dest_hash]
                    lt_info = f" rem_hops={{lte[3]}} taken_hops={{lte[5]}} nh_if={{lte[2]}} rcvd_if={{lte[4]}}"
                print(f"[DIAG-LRPROOF] hops={{hops}} lid={{lid_hex}} in_link_table={{in_lt}}{{lt_info}} iface={{interface}}", flush=True)
    return original_inbound(raw, interface)

RNS.Transport.inbound = staticmethod(patched_inbound)

# Dest hashes to exclude (Rust transport node and rnsd nodes)
exclude_hex = "{rust_dest_hex}"
exclude_hash = bytes.fromhex(exclude_hex) if exclude_hex else None

class TestMessage(RNS.Channel.MessageBase):
    MSGTYPE = 0x0100
    def __init__(self):
        self.data = b""
    def pack(self):
        return self.data
    def unpack(self, raw):
        self.data = raw

link_established = threading.Event()
echo_received = threading.Event()
echo_data = [None]
active_link = [None]

def link_established_cb(link):
    print(f"PY_A_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
    active_link[0] = link
    link_established.set()

def link_closed_cb(link):
    print(f"PY_A_LINK_CLOSED:{{link.link_id.hex()}}", flush=True)

print("PY_A_READY", flush=True)

# Wait for Python_B's announce to appear in path table (via relay chain)
timeout = {t.timeout}
deadline = time.time() + timeout
target_hash = None

while time.time() < deadline:
    for h in RNS.Transport.path_table:
        if exclude_hash and h == exclude_hash:
            continue
        target_hash = h
        print(f"PY_A_DISCOVERED_B:{{h.hex()}}", flush=True)
        break
    if target_hash:
        break
    time.sleep(0.5)

if not target_hash:
    print("PY_A_FAIL:timeout_waiting_for_b_announce", flush=True)
    sys.exit(1)

target_identity = RNS.Identity.recall(target_hash)
if not target_identity:
    print("PY_A_FAIL:identity_not_recalled", flush=True)
    sys.exit(1)

target_dest = RNS.Destination(
    target_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
    "rete", "example", "v1",
)

link = RNS.Link(target_dest, established_callback=link_established_cb, closed_callback=link_closed_cb)

if not link_established.wait(timeout=20):
    print(f"PY_A_LINK_TIMEOUT:status={{link.status}}", flush=True)
    sys.exit(1)

print("PY_A_LINK_ACTIVE", flush=True)

# Set up channel for sending and receiving echo
channel = link.get_channel()
channel.register_message_type(TestMessage)

def echo_handler(msg):
    text = msg.data.decode("utf-8", errors="replace")
    print(f"PY_A_ECHO_RECEIVED:{{text}}", flush=True)
    echo_data[0] = text
    echo_received.set()

channel.add_message_handler(echo_handler)

msg = TestMessage()
msg.data = b"hello from A through 2-relay chain"
channel.send(msg)
print("PY_A_CHANNEL_MSG_SENT", flush=True)

# Wait for echo response
if echo_received.wait(timeout=10):
    print(f"PY_A_ECHO_OK:{{echo_data[0]}}", flush=True)
else:
    print("PY_A_ECHO_TIMEOUT", flush=True)

time.sleep(2)

link.teardown()
print("PY_A_LINK_TEARDOWN_SENT", flush=True)
time.sleep(2)

print("PY_A_DONE", flush=True)
""")

        # Wait for both Python nodes to finish
        t.wait_for_line(py_a, "PY_A_DONE", timeout=t.timeout + 15)
        t.wait_for_line(py_b, "PY_B_DONE", timeout=t.timeout + 15)
        time.sleep(2)

        # Collect output
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Python_A output", py_a)
        t.dump_output("Python_B output", py_b)
        t.dump_output("Rust transport stdout", rust)
        t.dump_output("Rust transport stderr (last 1000)", rust_stderr.strip().split("\n"))

        # Assertions
        t.check(
            t.has_line(py_a, "PY_A_DISCOVERED_B"),
            "Python_B announce received by Python_A through relay chain",
        )

        link_established = (
            t.has_line(py_a, "PY_A_LINK_ACTIVE")
            and t.has_line(py_b, "PY_B_LINK_ESTABLISHED:")
        )
        t.check(
            link_established,
            "Link established through 2-relay chain",
            detail=f"Python_A={t.has_line(py_a, 'PY_A_LINK_ACTIVE')} Python_B={t.has_line(py_b, 'PY_B_LINK_ESTABLISHED:')}",
        )

        if link_established:
            t.check(
                t.has_line(py_b, "PY_B_CHANNEL_MSG_RECEIVED:", contains="hello from A through 2-relay chain"),
                "Channel message delivered through relay chain",
            )
        else:
            t.check(False, "Channel message delivered through relay chain (skipped: no link)")

        if link_established:
            t.check(
                t.has_line(py_a, "PY_A_LINK_CLOSED:") or t.has_line(py_b, "PY_B_LINK_CLOSED:"),
                "Link teardown works",
            )
        else:
            t.check(False, "Link teardown works (skipped: no link)")


if __name__ == "__main__":
    main()
