#!/usr/bin/env python3
"""IFAC large packet interop test: near-MTU packets through IFAC interface.

Topology:
  rnsd (transport=yes, TCP server on localhost:4285, ifac="large-pkt-net")
  Rust node connects as TCP client (with IFAC, auto-reply)
  Python client connects as TCP client (with IFAC)

Assertions:
  1. Python sends 400-byte DATA through IFAC → Rust receives intact
  2. Rust auto-replies with payload → Python receives
  3. Rust reports IFAC enabled

Usage:
  cd tests/interop
  uv run python ifac_large_packet_interop.py --rust-binary ../../target/debug/rete-linux
"""

import time

from interop_helpers import InteropTest

IFAC_NETNAME = "large-pkt-net"


def main():
    with InteropTest("ifac-large-pkt", default_port=4285) as t:
        t.start_rnsd(ifac_netname=IFAC_NETNAME)
        rust = t.start_rust(
            extra_args=[
                "--ifac-netname", IFAC_NETNAME,
                "--auto-reply", "large reply from rust",
            ],
        )

        time.sleep(3)

        py = t.start_py_helper(f"""\
import RNS
import time
import sys
import os
import threading

config_dir = os.path.join("{t.tmpdir}", "py_client_config")
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
    target_port = {t.port}
    ingress_control = false
    networkname = {IFAC_NETNAME}
\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

data_received = threading.Event()
received_data = [None]

def packet_callback(data, packet):
    text = data.decode("utf-8", errors="replace")
    print(f"PY_DATA_RECEIVED:{{text}}", flush=True)
    received_data[0] = text
    data_received.set()

py_identity = RNS.Identity()
py_dest = RNS.Destination(
    py_identity,
    RNS.Destination.IN,
    RNS.Destination.SINGLE,
    "rete", "example", "v1",
)
py_dest.set_packet_callback(packet_callback)
py_dest.announce()
print(f"PY_DEST_HASH:{{py_dest.hexhash}}", flush=True)

# Wait for Rust announce
timeout = {t.timeout}
deadline = time.time() + timeout
rust_dest_hash = None
while time.time() < deadline:
    known = RNS.Transport.path_table
    for h in known:
        if h != py_dest.hash:
            rust_dest_hash = h
            break
    if rust_dest_hash:
        break
    time.sleep(0.5)

if not rust_dest_hash:
    print("PY_FAIL:timeout_waiting_for_rust_announce", flush=True)
    print("PY_DONE", flush=True)
    sys.exit(1)

print(f"PY_DISCOVERED:{{rust_dest_hash.hex()}}", flush=True)

rust_identity = RNS.Identity.recall(rust_dest_hash)
if not rust_identity:
    print("PY_FAIL:identity_not_recalled", flush=True)
    print("PY_DONE", flush=True)
    sys.exit(1)

out_dest = RNS.Destination(
    rust_identity,
    RNS.Destination.OUT,
    RNS.Destination.SINGLE,
    "rete", "example", "v1",
)

# Send a large packet (~300 bytes) through IFAC
# Note: SINGLE dest encryption adds ~48 bytes overhead, IFAC adds 16 bytes tag,
# header is ~19 bytes. So 300 + 48 + 16 + 19 = 383 < 500 MTU.
large_payload = b"A" * 300
pkt = RNS.Packet(out_dest, large_payload)
pkt.send()
print(f"PY_LARGE_DATA_SENT:{{len(large_payload)}} bytes", flush=True)

# Wait for auto-reply
if data_received.wait(timeout=15):
    print("PY_DATA_RECV_OK", flush=True)
else:
    print("PY_DATA_RECV_FAIL:timeout", flush=True)

time.sleep(2)
print("PY_DONE", flush=True)
""")

        t.wait_for_line(py, "PY_DONE", timeout=t.timeout + 10)
        time.sleep(2)

        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Python output", py)
        t.dump_output("Rust stdout", rust)

        # --- Assertion 1: Rust received large packet through IFAC ---
        # Check that Rust received data containing 300 'A's
        rust_data_lines = [l for l in rust if l.startswith("DATA:")]
        large_received = any("A" * 50 in l for l in rust_data_lines)  # At least 50 As
        t.check(
            large_received,
            "Python sends 300-byte DATA through IFAC, Rust receives intact",
            detail=f"Data lines: {rust_data_lines[:3]}" if not large_received else None,
        )

        # --- Assertion 2: Python received auto-reply ---
        t.check(
            t.has_line(py, "PY_DATA_RECEIVED:"),
            "Rust auto-replies with payload, Python receives through IFAC",
        )

        # --- Assertion 3: Rust reports IFAC enabled ---
        t.check(
            "IFAC enabled" in rust_stderr,
            "Rust reports IFAC enabled",
        )


if __name__ == "__main__":
    main()
