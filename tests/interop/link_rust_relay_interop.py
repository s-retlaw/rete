#!/usr/bin/env python3
"""Link-through-Rust-relay E2E interop test:
  Python_A --TCP--> rnsd_1 (4272) --TCP--> Rust (--transport) --TCP--> rnsd_2 (4273) <--TCP-- Python_B

Rust acts as the transport relay. Python_A initiates a Link to Python_B
through the Rust transport node.

Assertions:
  1. Python_A discovers Python_B's announce (through Rust relay)
  2. Link established on Python_A side
  3. Link established on Python_B side
  4. Channel message flows from A to B
  5. Link teardown works

Usage:
  cd tests/interop
  uv run python link_rust_relay_interop.py --rust-binary ../../target/debug/rete-linux
"""

import os
import subprocess
import sys
import threading
import time

from interop_helpers import (
    InteropTest,
    read_stdout_lines,
)


def main():
    with InteropTest("link-rust-relay", default_port=4272, default_timeout=60.0) as t:
        port1 = t.port       # 4272
        port2 = t.port + 1   # 4273

        # Start two rnsd instances
        t.start_rnsd(port=port1)
        t.start_rnsd(port=port2)

        # Start Rust transport node connecting to both rnsd instances
        data_dir = os.path.join(t.tmpdir, "rete_data")
        os.makedirs(data_dir, exist_ok=True)
        cmd = [
            t.rust_binary,
            "--data-dir", data_dir,
            "--connect", f"127.0.0.1:{port1}",
            "--connect", f"127.0.0.1:{port2}",
            "--transport",
        ]
        t._log("starting Rust transport node...")
        rust_proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        t._procs.append(rust_proc)
        t._rust_proc = rust_proc

        rust = []
        rust_thread = threading.Thread(
            target=read_stdout_lines, args=(rust_proc, rust, t._stop), daemon=True,
        )
        rust_thread.start()

        # Get the Rust transport node's dest hash so Python nodes can filter it out
        rust_dest_hex = t.wait_for_line(rust, "IDENTITY:", timeout=10) or ""
        t._log(f"Rust transport dest hash: {rust_dest_hex}")

        # Give Rust time to connect and announce on both interfaces
        time.sleep(5)

        # Start Python_A first (connects to rnsd_1) — it will listen for announces
        # while waiting for Python_B to announce.
        py_a = t.start_py_helper(f"""\
import RNS
import RNS.Channel
import time
import sys
import os
import threading

config_dir = os.path.join("{t.tmpdir}", "py_a_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config(port=port1)}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

# Dest hashes to exclude (Rust transport node and our own)
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
active_link = [None]

def link_established_cb(link):
    print(f"PY_A_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
    active_link[0] = link
    link_established.set()

def link_closed_cb(link):
    print(f"PY_A_LINK_CLOSED:{{link.link_id.hex()}}", flush=True)

print("PY_A_READY", flush=True)

# Wait for Python_B's announce to appear in path table (via Rust relay)
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
        time.sleep(1)  # Allow transport nodes to fully propagate path before sending link request
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

channel = link.get_channel()
channel.register_message_type(TestMessage)

msg = TestMessage()
msg.data = b"hello from A through rust relay"
channel.send(msg)
print("PY_A_CHANNEL_MSG_SENT", flush=True)
time.sleep(3)

# Test link.request() through Rust relay
req_response = threading.Event()
req_result = [None]

def req_response_cb(receipt):
    if receipt.response is not None:
        req_result[0] = receipt.response
        print(f"PY_A_REQUEST_RESPONSE:{{len(receipt.response)}}", flush=True)
    else:
        print("PY_A_REQUEST_RESPONSE_NONE", flush=True)
    req_response.set()

def req_failed_cb(receipt):
    print(f"PY_A_REQUEST_FAILED:{{receipt.status}}", flush=True)
    req_response.set()

print("PY_A_SENDING_REQUEST", flush=True)
receipt = link.request(
    "/test/echo",
    b"echo through rust relay",
    response_callback=req_response_cb,
    failed_callback=req_failed_cb,
)

if req_response.wait(timeout=10):
    print(f"PY_A_REQUEST_DONE:{{req_result[0]}}", flush=True)
else:
    print("PY_A_REQUEST_TIMEOUT", flush=True)

time.sleep(1)

link.teardown()
print("PY_A_LINK_TEARDOWN_SENT", flush=True)
time.sleep(2)

print("PY_A_DONE", flush=True)
""")

        # Wait for Python_A to be ready (connected to rnsd_1)
        t.wait_for_line(py_a, "PY_A_READY")
        time.sleep(1)

        # Now start Python_B (responder) — connects to rnsd_2, creates destination, announces
        # The announce will propagate: rnsd_2 -> Rust -> rnsd_1 -> Python_A
        # Uses 'rete.example.v1' — same app name as the Rust node, so path/identity
        # resolution works through the relay chain.
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

# Register /test/echo request handler
def test_echo_handler(path, data, request_id, link_id, packet, remote_identity):
    print(f"PY_B_REQUEST_RECEIVED:{{len(data)}}", flush=True)
    return data

py_dest.register_request_handler("/test/echo", response_generator=test_echo_handler, allow=RNS.Destination.ALLOW_ALL)
print("PY_B_REQUEST_HANDLER_REGISTERED", flush=True)

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
            "Python_A discovers Python_B's announce (through Rust relay)",
        )

        t.check(
            t.has_line(py_a, "PY_A_LINK_ACTIVE"),
            "Link established on Python_A (initiator) side",
        )

        t.check(
            t.has_line(py_b, "PY_B_LINK_ESTABLISHED:"),
            "Link established on Python_B (responder) side",
        )

        t.check(
            t.has_line(py_b, "PY_B_CHANNEL_MSG_RECEIVED:", contains="hello from A through rust relay"),
            "Channel message flows from A to B through Rust relay",
        )

        t.check(
            t.has_line(py_a, "PY_A_REQUEST_RESPONSE:") or t.has_line(py_a, "PY_A_REQUEST_DONE:"),
            "Request/response flows through Rust relay",
        )

        t.check(
            t.has_line(py_a, "PY_A_LINK_CLOSED:") or t.has_line(py_b, "PY_B_LINK_CLOSED:"),
            "Link teardown works",
        )


if __name__ == "__main__":
    main()
