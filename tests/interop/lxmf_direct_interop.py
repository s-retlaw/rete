#!/usr/bin/env python3
"""LXMF direct (Link+Resource/Packet) interop test: Python LXMF -> Rust rete node.

Topology:
  rnsd (transport=yes, TCP server on localhost:4253)
  Rust node connects as TCP client to rnsd, announces LXMF delivery
  Python LXMF helper connects as TCP client to rnsd

Assertions:
  1. Rust LXMF announce received by Python
  2. Small LXMF via DIRECT (Link+Packet) delivered to Rust
  3. Large LXMF via DIRECT (Link+Resource) delivered to Rust

Usage:
  cd tests/interop
  uv run python lxmf_direct_interop.py --rust-binary ../../target/debug/rete-linux

Requires:
  pip install rns lxmf
"""

import time

from interop_helpers import InteropTest


def main():
    with InteropTest("lxmf-direct", default_port=4253) as t:
        t.start_rnsd()

        rust = t.start_rust(
            extra_args=["--lxmf-announce", "--lxmf-name", "DirectRust"],
        )

        # Give Rust time to connect and announce
        time.sleep(3)

        # Python LXMF helper: discovers Rust, sends small + large DIRECT LXMF.
        py = t.start_py_helper(f"""\
import RNS
import LXMF
import time
import sys
import os
import threading

config_dir = os.path.join("{t.tmpdir}", "py_lxmf_config")
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
    py_identity, display_name="PythonDirect"
)
time.sleep(1)

# Wait for Rust LXMF announce in path table
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

print(f"PY_RUST_ANNOUNCED:{{rust_dest_hash.hex()}}", flush=True)

rust_recalled = RNS.Identity.recall(rust_dest_hash)
if not rust_recalled:
    print("PY_FAIL:identity_not_recalled", flush=True)
    sys.exit(1)

lxmf_dest = RNS.Destination(
    rust_recalled, RNS.Destination.OUT, RNS.Destination.SINGLE,
    "lxmf", "delivery"
)

# --- Small LXMF via DIRECT (Link+Packet) ---
small_msg = LXMF.LXMessage(
    lxmf_dest, py_lxmf_dest,
    "Small direct message",
    title="Direct Small",
    desired_method=LXMF.LXMessage.DIRECT,
)
small_msg.try_propagation_on_fail = False

small_delivered = threading.Event()
def on_small_delivery(msg):
    print("PY_SMALL_DELIVERED", flush=True)
    small_delivered.set()
small_msg.delivery_callback = on_small_delivery

py_router.handle_outbound(small_msg)
print("PY_SMALL_SENT", flush=True)

# Wait for small delivery
deadline = time.time() + 20.0
while time.time() < deadline and not small_delivered.is_set():
    time.sleep(0.5)
time.sleep(2)

# --- Large LXMF via DIRECT (Link+Resource) ---
large_content = "A" * 1000  # > LINK_PACKET_MAX_CONTENT, forces Resource
large_msg = LXMF.LXMessage(
    lxmf_dest, py_lxmf_dest,
    large_content,
    title="Direct Large",
    desired_method=LXMF.LXMessage.DIRECT,
)
large_msg.try_propagation_on_fail = False

large_delivered = threading.Event()
def on_large_delivery(msg):
    print("PY_LARGE_DELIVERED", flush=True)
    large_delivered.set()
large_msg.delivery_callback = on_large_delivery

py_router.handle_outbound(large_msg)
print("PY_LARGE_SENT", flush=True)

# Wait for large delivery
deadline = time.time() + 25.0
while time.time() < deadline and not large_delivered.is_set():
    time.sleep(0.5)
time.sleep(2)

print("PY_DONE", flush=True)
""")

        # Wait for Python helper to finish
        t.wait_for_line(py, "PY_DONE", timeout=t.timeout + 30)
        time.sleep(2)

        # Collect output
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Python helper output", py)
        t.dump_output("Rust node stdout", rust)
        t.dump_output("Rust node stderr (last 1000)", rust_stderr.strip().split("\n"))

        # Assertion 1: Rust announce received by Python
        t.check(
            t.has_line(py, "PY_RUST_ANNOUNCED:"),
            "Rust LXMF announce received by Python",
        )

        # Assertion 2: Small LXMF via DIRECT received by Rust
        t.check(
            t.has_line(rust, "LXMF_RECEIVED:", contains="Direct Small"),
            "Small LXMF received via DIRECT (Link+Packet)",
        )

        # Assertion 3: Large LXMF via DIRECT received by Rust
        t.check(
            t.has_line(rust, "LXMF_RECEIVED:", contains="Direct Large"),
            "Large LXMF received via DIRECT (Link+Resource)",
        )


if __name__ == "__main__":
    main()
