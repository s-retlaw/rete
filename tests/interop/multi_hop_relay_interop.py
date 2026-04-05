#!/usr/bin/env python3
"""Multi-hop relay E2E test: DATA + Link + Channel through Rust relay.

Most complete relay test — verifies DATA, Link, and Channel all work
through the Rust transport relay.

Topology:
  Python_A <-TCP:4318-> rnsd_1 <-TCP-> Rust (--transport) <-TCP-> rnsd_2 <-TCP:4319-> Python_B

Steps:
  1. Python_A announces, Python_B discovers through Rust relay
  2. Python_B sends DATA to Python_A (relayed)
  3. Python_B establishes link to Python_A through relay
  4. Python_B sends channel message over the link

Assertions:
  1. Python_B discovers Python_A's announce
  2. DATA reaches Python_A through relay
  3. Link established through relay
  4. Channel message delivered
  5. Link teardown works

Usage:
  cd tests/interop
  uv run python multi_hop_relay_interop.py --rust-binary ../../target/debug/rete
"""

import time

from interop_helpers import InteropTest


def main():
    with InteropTest("multi-hop-relay", default_port=4318, default_timeout=60.0) as t:
        port1 = t.port
        port2 = t.port + 1

        # Start two rnsd instances
        t.start_rnsd(port=port1)
        t.start_rnsd(port=port2)

        # Start Rust transport node connecting to both rnsd instances
        rust = t.start_rust(
            port=port1,
            extra_args=["--connect", f"127.0.0.1:{port2}", "--transport"],
        )

        # Get Rust transport node's dest hash for filtering
        rust_dest_hex = t.wait_for_line(rust, "IDENTITY:", timeout=10) or ""
        print(f"[multi-hop-relay] Rust transport dest hash: {rust_dest_hex}")
        time.sleep(5)

        # Python_A: server side (announces, receives DATA, accepts incoming link)
        py_a = t.start_py_helper(f"""\
import RNS
import RNS.Channel
import time
import sys
import os
import threading

config_dir = os.path.join("{t.tmpdir}", "node_a_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"
[reticulum]
  enable_transport = no
  share_instance = no

[logging]
  loglevel = 5

[interfaces]

  [[TCP Client Interface]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = {port1}
    ingress_control = false
\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

data_received = threading.Event()
link_established_evt = threading.Event()
channel_msg_received = threading.Event()
link_closed_evt = threading.Event()
received_data_text = [None]
received_channel_text = [None]

class TestMessage(RNS.Channel.MessageBase):
    MSGTYPE = 0x0100
    def __init__(self):
        self.data = b""
    def pack(self):
        return self.data
    def unpack(self, raw):
        self.data = raw

def packet_callback(data, packet):
    text = data.decode("utf-8", errors="replace")
    received_data_text[0] = text
    print(f"NODE_A_DATA_RECEIVED:{{text}}", flush=True)
    data_received.set()

def inbound_link_established(link):
    print(f"NODE_A_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
    link.set_link_closed_callback(lambda l: (print(f"NODE_A_LINK_CLOSED:{{l.link_id.hex()}}", flush=True), link_closed_evt.set()))

    channel = link.get_channel()
    channel.register_message_type(TestMessage)

    def channel_msg_cb(message):
        text = message.data.decode("utf-8", errors="replace")
        received_channel_text[0] = text
        print(f"NODE_A_CHANNEL_MSG:{{text}}", flush=True)
        channel_msg_received.set()

    channel.add_message_handler(channel_msg_cb)
    link_established_evt.set()

identity = RNS.Identity()
dest = RNS.Destination(
    identity,
    RNS.Destination.IN,
    RNS.Destination.SINGLE,
    "rete", "example", "v1",
)
dest.set_packet_callback(packet_callback)
dest.set_link_established_callback(inbound_link_established)

dest.announce()
print(f"NODE_A_DEST_HASH:{{dest.hexhash}}", flush=True)
print(f"NODE_A_IDENTITY_HASH:{{identity.hexhash}}", flush=True)
print("NODE_A_ANNOUNCE_SENT", flush=True)

# Wait for DATA, link, and channel message
timeout = {t.timeout}

if data_received.wait(timeout=timeout):
    print("NODE_A_DATA_OK", flush=True)
else:
    print("NODE_A_DATA_TIMEOUT", flush=True)

if link_established_evt.wait(timeout={t.timeout}):
    print("NODE_A_LINK_OK", flush=True)
else:
    print("NODE_A_LINK_TIMEOUT", flush=True)

if channel_msg_received.wait(timeout=15):
    print("NODE_A_CHANNEL_OK", flush=True)
else:
    print("NODE_A_CHANNEL_TIMEOUT", flush=True)

# Wait for link close
link_closed_evt.wait(timeout=10)

time.sleep(2)
print("NODE_A_DONE", flush=True)
""")

        time.sleep(2)

        # Python_B: client side (discovers A, sends DATA, establishes link, sends channel msg)
        py_b = t.start_py_helper(f"""\
import RNS
import RNS.Channel
import time
import sys
import os
import threading

config_dir = os.path.join("{t.tmpdir}", "node_b_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"
[reticulum]
  enable_transport = no
  share_instance = no

[logging]
  loglevel = 5

[interfaces]

  [[TCP Client Interface]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = {port2}
    ingress_control = false
\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

# Dest hash to exclude (the Rust transport relay)
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
link_closed = threading.Event()

def link_established_cb(link):
    print(f"NODE_B_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
    link_established.set()

def link_closed_cb(link):
    print(f"NODE_B_LINK_CLOSED:{{link.link_id.hex()}}", flush=True)
    link_closed.set()

identity = RNS.Identity()

# Wait for Node A's announce (relayed through Rust)
timeout = {t.timeout}
deadline = time.time() + timeout
peer_dest_hash = None

while time.time() < deadline:
    known = RNS.Transport.path_table
    for h in known:
        if exclude_hash and h == exclude_hash:
            continue
        peer_dest_hash = h
        print(f"NODE_B_DISCOVERED:{{h.hex()}}", flush=True)
        break
    if peer_dest_hash:
        time.sleep(1)  # Allow transport nodes to fully propagate path before sending link request
        break
    time.sleep(0.5)

if not peer_dest_hash:
    print("NODE_B_FAIL:timeout_waiting_for_announce", flush=True)
    print("NODE_B_DONE", flush=True)
    sys.exit(1)

print("NODE_B_PEER_FOUND", flush=True)

# Send DATA to Node A through relay
peer_identity = RNS.Identity.recall(peer_dest_hash)
if not peer_identity:
    print("NODE_B_FAIL:identity_not_recalled", flush=True)
    print("NODE_B_DONE", flush=True)
    sys.exit(1)

out_dest = RNS.Destination(
    peer_identity,
    RNS.Destination.OUT,
    RNS.Destination.SINGLE,
    "rete", "example", "v1",
)
pkt = RNS.Packet(out_dest, b"relayed DATA from B")
pkt.send()
print("NODE_B_DATA_SENT", flush=True)

time.sleep(3)

# Establish link to Node A through relay
link = RNS.Link(out_dest, established_callback=link_established_cb, closed_callback=link_closed_cb)

if not link_established.wait(timeout={t.timeout}):
    print(f"NODE_B_LINK_TIMEOUT:status={{link.status}}", flush=True)
    print("NODE_B_DONE", flush=True)
    sys.exit(1)

print("NODE_B_LINK_ACTIVE", flush=True)

# Send channel message
channel = link.get_channel()
channel.register_message_type(TestMessage)

msg = TestMessage()
msg.data = b"channel relay msg from B"
channel.send(msg)
print("NODE_B_CHANNEL_MSG_SENT", flush=True)

time.sleep(5)

link.teardown()
print("NODE_B_TEARDOWN_SENT", flush=True)
time.sleep(2)

print("NODE_B_DONE", flush=True)
""")

        # Wait for both nodes to finish
        t.wait_for_line(py_a, "NODE_A_DONE", timeout=t.timeout + 15)
        t.wait_for_line(py_b, "NODE_B_DONE", timeout=t.timeout + 15)
        time.sleep(1)

        # Collect output
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Node A output", py_a)
        t.dump_output("Node B output", py_b)
        t.dump_output("Rust transport stdout", rust)
        t.dump_output("Rust transport stderr (last 800)", rust_stderr.strip().split("\n"))

        # --- Assertion 1: Python_B discovers Python_A's announce ---
        t.check(
            t.has_line(py_b, "NODE_B_PEER_FOUND"),
            "Python_B discovered Python_A's announce (relayed through Rust)",
        )

        # --- Assertion 2: DATA reaches Python_A through relay ---
        t.check(
            t.has_line(py_a, "NODE_A_DATA_RECEIVED:", contains="relayed DATA from B"),
            "DATA from Python_B reached Python_A through Rust relay",
        )

        # --- Assertion 3: Link established through relay ---
        a_link_ok = t.has_line(py_a, "NODE_A_LINK_ESTABLISHED:") or t.has_line(py_a, "NODE_A_LINK_OK")
        b_link_ok = t.has_line(py_b, "NODE_B_LINK_ACTIVE")
        t.check(
            a_link_ok and b_link_ok,
            "Link established through Rust relay (both sides)",
            detail=f"A={a_link_ok} B={b_link_ok}",
        )

        # --- Assertion 4: Channel message delivered ---
        t.check(
            t.has_line(py_a, "NODE_A_CHANNEL_MSG:", contains="channel relay msg from B"),
            "Channel message delivered through Rust relay",
        )

        # --- Assertion 5: Link teardown works ---
        t.check(
            t.has_line(py_a, "NODE_A_LINK_CLOSED:") or t.has_line(py_b, "NODE_B_LINK_CLOSED:"),
            "Link teardown works",
        )


if __name__ == "__main__":
    main()
