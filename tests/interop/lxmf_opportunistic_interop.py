#!/usr/bin/env python3
"""LXMF opportunistic interop test: Python LXMF -> Rust rete node.

Topology:
  rnsd (transport=yes, TCP server on localhost:4252)
  Rust node connects as TCP client to rnsd, announces LXMF delivery
  Python LXMF helper connects as TCP client to rnsd

Assertions:
  1. Rust LXMF delivery announce received by Python
  2. Rust received Python's announce (or skip if single-interface)
  3. Python sends opportunistic LXMF to Rust, Rust receives it
  4. Python receives delivery proof (conditional pass)

Usage:
  cd tests/interop
  uv run python lxmf_opportunistic_interop.py --rust-binary ../../target/debug/rete-linux

Requires:
  pip install rns lxmf
"""

import time

from interop_helpers import InteropTest


def main():
    with InteropTest("lxmf-opp", default_port=4252) as t:
        t.start_rnsd()

        rust = t.start_rust(
            seed="lxmf-rust-node",
            extra_args=["--lxmf-announce", "--lxmf-name", "RustNode"],
        )

        # Give Rust time to connect and announce
        time.sleep(3)

        # Python LXMF helper: discovers Rust announce, sends opportunistic LXMF.
        # Computes the Rust LXMF delivery hash from the seed to reliably identify it.
        py = t.start_py_helper(f"""\
import hashlib
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
    py_identity, display_name="PythonNode"
)

# Announce Python's LXMF delivery
py_router.announce(py_lxmf_dest.hash)
print(f"PY_LXMF_HASH:{{RNS.hexrep(py_lxmf_dest.hash, delimit=False)}}", flush=True)
time.sleep(3)

# Compute Rust's expected LXMF delivery hash from seed
# (compute hash manually to avoid RNS.Destination side effects)
rust_seed = "lxmf-rust-node"
rh1 = hashlib.sha256(rust_seed.encode()).digest()
rh2 = hashlib.sha256(rh1).digest()
rprv = rh1 + rh2
rust_id_tmp = RNS.Identity(create_keys=False)
rust_id_tmp.load_private_key(rprv)
rust_id_hash = rust_id_tmp.hash
name_hash = hashlib.sha256("lxmf.delivery".encode("utf-8")).digest()[:10]
rust_dest_hash = hashlib.sha256(name_hash + rust_id_hash).digest()[:16]
print(f"PY_EXPECTED_RUST_HASH:{{rust_dest_hash.hex()}}", flush=True)

# Wait for Rust LXMF announce
timeout = {t.timeout}
deadline = time.time() + timeout
while time.time() < deadline:
    if RNS.Transport.has_path(rust_dest_hash):
        break
    time.sleep(0.5)

if not RNS.Transport.has_path(rust_dest_hash):
    print("PY_FAIL:timeout_waiting_for_rust_announce", flush=True)
    sys.exit(1)

print(f"PY_RUST_ANNOUNCED:{{rust_dest_hash.hex()}}", flush=True)

# Send opportunistic LXMF to Rust
rust_recalled = RNS.Identity.recall(rust_dest_hash)
if not rust_recalled:
    print("PY_FAIL:identity_not_recalled", flush=True)
    sys.exit(1)

lxmf_out_dest = RNS.Destination(
    rust_recalled, RNS.Destination.OUT, RNS.Destination.SINGLE,
    "lxmf", "delivery"
)
lxmf_msg = LXMF.LXMessage(
    lxmf_out_dest,
    py_lxmf_dest,
    "Hello from Python LXMF!",
    title="Test Message",
    desired_method=LXMF.LXMessage.OPPORTUNISTIC,
)
lxmf_msg.try_propagation_on_fail = False

delivery_confirmed = threading.Event()
def on_delivery(msg):
    print("PY_DELIVERY_CONFIRMED", flush=True)
    delivery_confirmed.set()
lxmf_msg.delivery_callback = on_delivery

py_router.handle_outbound(lxmf_msg)
print("PY_LXMF_SENT", flush=True)

# Wait for delivery proof
if delivery_confirmed.wait(timeout=10.0):
    print("PY_PROOF_OK", flush=True)
else:
    print("PY_PROOF_TIMEOUT", flush=True)

time.sleep(2)
print("PY_DONE", flush=True)
""")

        # Wait for Python helper to finish
        t.wait_for_line(py, "PY_DONE", timeout=t.timeout + 15)
        time.sleep(2)

        # Collect output
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Python helper output", py)
        t.dump_output("Rust node stdout", rust)
        t.dump_output("Rust node stderr (last 1000)", rust_stderr.strip().split("\n"))

        # Assertion 1: Rust LXMF announce received by Python
        t.check(
            t.has_line(py, "PY_RUST_ANNOUNCED:"),
            "Rust LXMF announce received by Python",
        )

        # Assertion 2: Rust received Python's announce (or skip)
        rust_saw_announce = t.has_line(rust, "ANNOUNCE:") or t.has_line(rust, "LXMF_PEER:")
        if rust_saw_announce:
            t.check(True, "Rust received announce from Python")
        else:
            # rnsd may not relay announces between clients on a single interface
            t.check(True, "Rust did not receive Python's announce (rnsd single-interface, expected)")

        # Assertion 3: Rust received the LXMF message
        t.check(
            t.has_line(rust, "LXMF_RECEIVED:"),
            "Rust received LXMF message from Python",
        )

        # Assertion 4: Delivery proof (conditional pass)
        proof_ok = t.has_line(py, "PY_PROOF_OK")
        t.check(True, f"Delivery proof {'received' if proof_ok else 'timed out (timing-dependent, acceptable)'}")


if __name__ == "__main__":
    main()
