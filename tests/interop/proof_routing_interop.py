#!/usr/bin/env python3
"""Proof routing E2E test: proofs route back through Rust transport relay.

Topology:
  Python_A <-TCP:4247-> rnsd_1 <-TCP-> Rust_Transport <-TCP-> rnsd_2 <-TCP:4248-> Python_B

Flow:
  1. Python_B sets PROVE_ALL on its destination
  2. Python_A discovers Python_B (via Rust relay), sends DATA
  3. Python_B receives DATA, automatically generates a PROOF
  4. PROOF routes back through rnsd_2 -> Rust -> rnsd_1 -> Python_A
  5. Python_A's PacketReceipt fires delivery callback

This tests Sprint 3 (proof routing via reverse table) end-to-end against
the Python reference implementation.

Assertions:
  1. Python_B received DATA from Python_A (relayed through Rust)
  2. Python_A received delivery proof (routed back through Rust)

Usage:
  cd tests/interop
  uv run python proof_routing_interop.py
"""

import time

from interop_helpers import InteropTest


def main():
    with InteropTest("proof-routing", default_port=4247) as t:
        port1 = t.port
        port2 = t.port + 1  # 4248

        # Start both rnsd instances
        t.start_rnsd(port=port1)
        t.start_rnsd(port=port2)

        # Start Rust transport node connecting to both rnsd instances
        rust = t.start_rust(
            port=port1,
            extra_args=[
                "--connect", f"127.0.0.1:{port2}",
                "--transport",
            ],
        )

        # Get Rust transport dest hash for filtering
        rust_dest_hex = t.wait_for_line(rust, "IDENTITY:", timeout=10) or ""
        time.sleep(3)

        # --- Start Python_A FIRST so it is already connected to rnsd_1
        # when Python_B's announce propagates through the relay chain.
        # This avoids a race where rnsd_1 forwards the announce before
        # Python_A has connected. ---
        py_a = t.start_py_helper(f"""\
import RNS
import time
import os
import threading

config_dir = os.path.join("{t.tmpdir}", "py_a_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config(port=port1, transport=False)}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

exclude_hex = "{rust_dest_hex}"
exclude_hash = bytes.fromhex(exclude_hex) if exclude_hex else None

identity = RNS.Identity()
dest = RNS.Destination(
    identity, RNS.Destination.IN, RNS.Destination.SINGLE,
    "rete", "example", "v1",
)
dest.announce()
print("PY_A_READY", flush=True)

# Wait for Python_B's announce (relayed through Rust)
deadline = time.time() + {t.timeout}
peer_hash = None
while time.time() < deadline:
    for h in RNS.Transport.path_table:
        if h == dest.hash:
            continue
        if exclude_hash and h == exclude_hash:
            continue
        peer_hash = h
        break
    if peer_hash:
        break
    time.sleep(0.5)

if not peer_hash:
    print("PY_A_PEER_NOT_FOUND", flush=True)
    time.sleep(1)
    exit(0)

print(f"PY_A_PEER_FOUND:{{peer_hash.hex()}}", flush=True)

peer_identity = RNS.Identity.recall(peer_hash)
if not peer_identity:
    print("PY_A_IDENTITY_NOT_RECALLED", flush=True)
    time.sleep(1)
    exit(0)

out_dest = RNS.Destination(
    peer_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
    "rete", "example", "v1",
)

packet = RNS.Packet(out_dest, b"prove this")
receipt = packet.send()

proof_received = threading.Event()

def delivery_callback(receipt):
    print("PY_A_PROOF_RECEIVED", flush=True)
    proof_received.set()

def timeout_callback(receipt):
    print("PY_A_PROOF_TIMEOUT", flush=True)

receipt.set_delivery_callback(delivery_callback)
receipt.set_timeout_callback(timeout_callback)
receipt.set_timeout(15)

print("PY_A_DATA_SENT", flush=True)

if proof_received.wait(timeout=20):
    print("PY_A_PROOF_OK", flush=True)
else:
    print("PY_A_PROOF_WAIT_TIMEOUT", flush=True)

time.sleep(2)
print("PY_A_DONE", flush=True)
""")

        # Wait for Python_A to be connected before starting Python_B
        t.wait_for_line(py_a, "PY_A_READY", timeout=15)
        time.sleep(1)

        # --- Python_B: receiver with PROVE_ALL (connects to rnsd_2) ---
        py_b = t.start_py_helper(f"""\
import RNS
import time
import os
import threading

config_dir = os.path.join("{t.tmpdir}", "py_b_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config(port=port2, transport=False)}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

data_received = threading.Event()

def packet_callback(data, packet):
    text = data.decode("utf-8", errors="replace")
    print(f"PY_B_DATA_RECEIVED:{{text}}", flush=True)
    data_received.set()

identity = RNS.Identity()
dest = RNS.Destination(
    identity, RNS.Destination.IN, RNS.Destination.SINGLE,
    "rete", "example", "v1",
)
dest.set_proof_strategy(RNS.Destination.PROVE_ALL)
dest.set_packet_callback(packet_callback)
dest.announce()

print(f"PY_B_DEST_HASH:{{dest.hexhash}}", flush=True)
print("PY_B_PROVE_ALL_SET", flush=True)

if data_received.wait(timeout={t.timeout}):
    print("PY_B_DATA_OK", flush=True)
else:
    print("PY_B_DATA_TIMEOUT", flush=True)

# Keep alive for proof to propagate back
time.sleep(5)
print("PY_B_DONE", flush=True)
""")

        # Wait for both Python helpers to finish
        t.wait_for_line(py_a, "PY_A_DONE", timeout=t.timeout + 15)
        t.wait_for_line(py_b, "PY_B_DONE", timeout=t.timeout + 15)

        time.sleep(1)
        rust_stderr = t.collect_rust_stderr()

        # Dump output
        t.dump_output("Python_A output", py_a)
        t.dump_output("Python_B output", py_b)
        t.dump_output("Rust stderr (last 500)", rust_stderr.strip().split("\n"))

        # --- Assertions ---

        # 1. Python_B received DATA
        t.check(
            t.has_line(py_b, "PY_B_DATA_RECEIVED:", contains="prove this"),
            "Python_B received DATA via Rust relay",
        )

        # 2. Python_A received proof (routed back through Rust)
        t.check(
            t.has_line(py_a, "PY_A_PROOF_RECEIVED"),
            "Python_A received delivery proof via Rust relay",
            detail="proof timed out" if t.has_line(py_a, "PY_A_PROOF_TIMEOUT") else None,
        )


if __name__ == "__main__":
    main()
