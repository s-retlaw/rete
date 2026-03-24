#!/usr/bin/env python3
"""Dual interface E2E test: Rust connects to two rnsd instances simultaneously.

Tests the multi-interface recv loop — Rust must process traffic from both
interfaces without blocking or starving either one.

Topology:
  Python_A <-TCP:4308-> rnsd_1 <-TCP-> Rust <-TCP-> rnsd_2 <-TCP:4309-> Python_B

Assertions:
  1. Rust received announce from Python_A
  2. Rust received announce from Python_B
  3. Rust received DATA from Python_A
  4. Rust received DATA from Python_B
  5. No crash

Usage:
  cd tests/interop
  uv run python dual_interface_interop.py --rust-binary ../../target/debug/rete-linux
"""

import time

from interop_helpers import InteropTest


def _py_node_script(tmpdir, port, label, timeout, send_to_rust_msg, rust_dest_hex):
    """Python script that announces, discovers Rust by known hash, sends DATA."""
    return f"""\
import RNS
import time
import sys
import os
import threading

config_dir = os.path.join("{tmpdir}", "{label}_config")
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
    target_port = {port}
    ingress_control = false
\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

data_received = threading.Event()
received_text = [None]

def packet_callback(data, packet):
    text = data.decode("utf-8", errors="replace")
    received_text[0] = text
    print(f"{label.upper()}_DATA_RECEIVED:{{text}}", flush=True)
    data_received.set()

identity = RNS.Identity()
dest = RNS.Destination(
    identity,
    RNS.Destination.IN,
    RNS.Destination.SINGLE,
    "rete", "example", "v1",
)
dest.set_packet_callback(packet_callback)

print(f"{label.upper()}_DEST_HASH:{{dest.hexhash}}", flush=True)
print(f"{label.upper()}_IDENTITY_HASH:{{identity.hexhash}}", flush=True)

dest.announce()
print(f"{label.upper()}_ANNOUNCE_SENT", flush=True)

# Wait specifically for the Rust node's announce (known dest hash)
rust_dest_hex = "{rust_dest_hex}"
rust_dest_hash_target = bytes.fromhex(rust_dest_hex) if rust_dest_hex else None
timeout = {timeout}
deadline = time.time() + timeout
rust_dest_hash = None

while time.time() < deadline:
    known = RNS.Transport.path_table
    if rust_dest_hash_target and rust_dest_hash_target in known:
        rust_dest_hash = rust_dest_hash_target
        print(f"{label.upper()}_DISCOVERED_RUST:{{rust_dest_hash.hex()}}", flush=True)
        break
    time.sleep(0.5)

if not rust_dest_hash:
    print(f"{label.upper()}_FAIL:timeout_waiting_for_rust_announce", flush=True)
    print(f"{label.upper()}_DONE", flush=True)
    sys.exit(1)

rust_identity = RNS.Identity.recall(rust_dest_hash)
if rust_identity:
    out_dest = RNS.Destination(
        rust_identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        "rete", "example", "v1",
    )
    pkt = RNS.Packet(out_dest, b"{send_to_rust_msg}")
    pkt.send()
    print(f"{label.upper()}_DATA_SENT", flush=True)
else:
    print(f"{label.upper()}_FAIL:identity_not_recalled", flush=True)

time.sleep(3)
print(f"{label.upper()}_DONE", flush=True)
"""


def main():
    with InteropTest("dual-interface", default_port=4308) as t:
        port1 = t.port
        port2 = t.port + 1

        # Start two rnsd instances
        t.start_rnsd(port=port1)
        t.start_rnsd(port=port2)

        # Now start Rust — its initial announce will reach both Python nodes
        # through their respective rnsd instances
        rust = t.start_rust(
            port=port1,
            extra_args=["--connect", f"127.0.0.1:{port2}"],
        )

        # Get Rust dest hash from stdout so Python nodes target the right peer
        rust_dest_hex = t.wait_for_line(rust, "IDENTITY:", timeout=10) or ""
        print(f"[dual-interface] Rust dest hash: {rust_dest_hex}")

        # Start Python nodes — they need to discover Rust's announce
        py_a = t.start_py_helper(_py_node_script(
            t.tmpdir, port1, "node_a", t.timeout, "hello from A", rust_dest_hex,
        ))
        time.sleep(1)
        py_b = t.start_py_helper(_py_node_script(
            t.tmpdir, port2, "node_b", t.timeout, "hello from B", rust_dest_hex,
        ))

        # Give Python nodes time to connect to their rnsd instances
        time.sleep(3)

        # Give Rust time to connect and announce on both interfaces
        time.sleep(3)

        # Wait for both to finish
        t.wait_for_line(py_a, "NODE_A_DONE", timeout=t.timeout + 15)
        t.wait_for_line(py_b, "NODE_B_DONE", timeout=t.timeout + 15)
        time.sleep(2)

        # Collect output
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Node A output", py_a)
        t.dump_output("Node B output", py_b)
        t.dump_output("Rust stdout", rust)
        t.dump_output("Rust stderr (last 1000)", rust_stderr.strip().split("\n"))

        # --- Assertion 1: Rust received announce from Python_A ---
        a_dest = None
        for l in py_a:
            if l.startswith("NODE_A_DEST_HASH:"):
                a_dest = l.split(":")[1].strip()
                break
        t.check(
            a_dest and t.has_line(rust, "ANNOUNCE:", contains=a_dest),
            "Rust received announce from Python_A",
            detail=f"a_dest={a_dest}" if a_dest else "Could not get Node A dest hash",
        )

        # --- Assertion 2: Rust received announce from Python_B ---
        b_dest = None
        for l in py_b:
            if l.startswith("NODE_B_DEST_HASH:"):
                b_dest = l.split(":")[1].strip()
                break
        t.check(
            b_dest and t.has_line(rust, "ANNOUNCE:", contains=b_dest),
            "Rust received announce from Python_B",
            detail=f"b_dest={b_dest}" if b_dest else "Could not get Node B dest hash",
        )

        # --- Assertion 3: Rust received DATA from Python_A ---
        t.check(
            t.has_line(rust, "DATA:", contains="hello from A"),
            "Rust received DATA from Python_A",
        )

        # --- Assertion 4: Rust received DATA from Python_B ---
        t.check(
            t.has_line(rust, "DATA:", contains="hello from B"),
            "Rust received DATA from Python_B",
        )

        # --- Assertion 5: No crash ---
        has_panic = "panicked" in rust_stderr.lower() or "sigsegv" in rust_stderr.lower()
        t.check(
            not has_panic,
            "No crash (no panic/SIGSEGV in stderr)",
        )


if __name__ == "__main__":
    main()
