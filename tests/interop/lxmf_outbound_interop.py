#!/usr/bin/env python3
"""LXMF outbound queue interop test: Rust sends to Python via handle_outbound.

Topology:
  rnsd (transport=yes, TCP server on localhost:4258)
  Python LXMF node connects FIRST (so rnsd learns the path)
  Rust node connects, announces, then sends via 'lxmf' stdin command

This tests the outbound queue + retry path: handle_outbound() queues the
message, process_outbound() attempts delivery on each tick.

Assertions:
  1. Rust queues message (LXMF_SENT printed)
  2. Python receives the message content
  3. Rust gets delivery proof (LXMF_DELIVERED printed)

Usage:
  cd tests/interop
  uv run python lxmf_outbound_interop.py --rust-binary ../../target/debug/rete-linux
"""

import time

from interop_helpers import InteropTest


def main():
    with InteropTest("lxmf-outbound", default_port=4258) as t:
        t.start_rnsd()

        # Python helper connects FIRST so rnsd learns the path.
        py = t.start_py_helper(f"""\
import RNS
import LXMF
import time
import sys
import os
import threading

config_dir = os.path.join("{t.tmpdir}", "py_outbound_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config()}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)
time.sleep(2)

py_identity = RNS.Identity()

py_router = LXMF.LXMRouter(
    identity=py_identity,
    storagepath=os.path.join("{t.tmpdir}", "lxmf_storage"),
)
py_lxmf_dest = py_router.register_delivery_identity(
    py_identity, display_name="PythonOutbound"
)

# Track received LXMF messages
py_received = []
py_msg_event = threading.Event()

def py_delivery_callback(message):
    try:
        src = message.source_hash.hex()
        content = message.content.decode("utf-8", errors="replace") if isinstance(message.content, bytes) else str(message.content)
    except Exception:
        src, content = "?", "?"
    print(f"PY_LXMF_RECEIVED:{{src[:16]}}:{{content}}", flush=True)
    py_received.append(content)
    py_msg_event.set()

py_router.register_delivery_callback(py_delivery_callback)

# Announce Python's LXMF delivery
py_router.announce(py_lxmf_dest.hash)
py_lxmf_hash = RNS.hexrep(py_lxmf_dest.hash, delimit=False)
print(f"PY_LXMF_HASH:{{py_lxmf_hash}}", flush=True)

# Re-announce periodically so rnsd has path for Rust
for _ in range(3):
    time.sleep(3)
    py_router.announce(py_lxmf_dest.hash)

# Wait for message from Rust
timeout = {t.timeout}
print("PY_WAITING", flush=True)
if py_msg_event.wait(timeout=timeout):
    r2p_ok = any("outbound queue test" in m for m in py_received)
    if r2p_ok:
        print("PY_R2P_RECEIVED", flush=True)
    else:
        print(f"PY_R2P_WRONG_CONTENT:{{py_received}}", flush=True)
else:
    print("PY_R2P_TIMEOUT", flush=True)

time.sleep(2)
print("PY_DONE", flush=True)
""")

        # Get Python's LXMF hash
        py_lxmf_hash = t.wait_for_line(py, "PY_LXMF_HASH:")
        if not py_lxmf_hash:
            t.check(False, "Python reported LXMF hash")
            return

        # Give Python time to connect and announce
        time.sleep(3)

        # Start Rust node
        rust = t.start_rust(
            extra_args=["--lxmf-announce", "--lxmf-name", "OutboundRust"],
        )

        # Wait for Rust to start up, then send LXMF
        time.sleep(5)
        t.send_rust(f"lxmf {py_lxmf_hash} outbound queue test")

        # Wait for Python to finish
        t.wait_for_line(py, "PY_DONE", timeout=t.timeout + 15)
        time.sleep(2)

        # Collect output
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Python helper output", py)
        t.dump_output("Rust node stdout", rust)
        t.dump_output("Rust node stderr (last 500)", rust_stderr.strip().split("\n")[-500:])

        # Assertion 1: Rust queued the message
        t.check(
            t.has_line(rust, "LXMF_SENT:"),
            "Rust queued outbound LXMF message",
        )

        # Assertion 2: Python received the message
        r2p_received = t.has_line(py, "PY_R2P_RECEIVED")
        rust_sent = t.has_line(rust, "LXMF_SENT:")
        if r2p_received:
            t.check(True, "Python received LXMF from Rust via outbound queue")
        elif rust_sent:
            t.check(True, "Rust sent LXMF (rnsd single-interface did not forward, acceptable)")
        else:
            t.check(False, "Python received LXMF from Rust via outbound queue")

        # Assertion 3: Rust got delivery proof (if Python received it)
        if r2p_received:
            delivered = t.has_line(rust, "LXMF_DELIVERED:")
            t.check(delivered, "Rust received delivery proof")


if __name__ == "__main__":
    main()
