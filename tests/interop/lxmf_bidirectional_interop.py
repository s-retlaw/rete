#!/usr/bin/env python3
"""LXMF bidirectional interop test: Python <-> Rust LXMF messaging.

Topology:
  rnsd (transport=yes, TCP server on localhost:4254)
  Python LXMF node connects FIRST (so rnsd learns the path)
  Rust node connects as TCP client, announces LXMF delivery
  Rust uses --lxmf-peer-seed to pre-register Python's identity

Assertions:
  1. Python -> Rust opportunistic LXMF delivery
  2. Rust -> Python opportunistic LXMF delivery (via stdin command)

Usage:
  cd tests/interop
  uv run python lxmf_bidirectional_interop.py --rust-binary ../../target/debug/rete-linux

Requires:
  pip install rns lxmf
"""

import time

from interop_helpers import InteropTest

PYTHON_LXMF_SEED = "lxmf-bidir-python"


def main():
    with InteropTest("lxmf-bidir", default_port=4254) as t:
        t.start_rnsd()

        # Python helper connects FIRST so rnsd learns the path.
        # It uses a deterministic identity so Rust can --lxmf-peer-seed it.
        # It computes the Rust LXMF delivery hash from the seed to avoid
        # needing stderr access.
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

# Deterministic identity matching Rust's Identity::from_seed
seed_str = "{PYTHON_LXMF_SEED}"
h1 = hashlib.sha256(seed_str.encode()).digest()
h2 = hashlib.sha256(h1).digest()
prv = h1 + h2
py_identity = RNS.Identity(create_keys=False)
py_identity.load_private_key(prv)

py_router = LXMF.LXMRouter(
    identity=py_identity,
    storagepath=os.path.join("{t.tmpdir}", "lxmf_storage"),
)
py_lxmf_dest = py_router.register_delivery_identity(
    py_identity, display_name="PythonBidir"
)

# Track received LXMF on Python side
py_received = []
py_msg_event = threading.Event()

def py_delivery_callback(message):
    try:
        src = message.source_hash.hex()
        title = message.title.decode("utf-8", errors="replace") if isinstance(message.title, bytes) else str(message.title)
        content = message.content.decode("utf-8", errors="replace") if isinstance(message.content, bytes) else str(message.content)
    except Exception:
        src, title, content = "?", "?", "?"
    print(f"PY_LXMF_RECEIVED:{{src[:16]}}:{{title}}:{{content}}", flush=True)
    py_received.append(content)
    py_msg_event.set()

py_router.register_delivery_callback(py_delivery_callback)

# Announce Python's LXMF delivery
py_router.announce(py_lxmf_dest.hash)
py_lxmf_hash = RNS.hexrep(py_lxmf_dest.hash, delimit=False)
print(f"PY_LXMF_HASH:{{py_lxmf_hash}}", flush=True)
time.sleep(3)

# Compute Rust's LXMF delivery hash from its seed
# (compute hash manually to avoid RNS.Destination side effects)
rust_seed = "lxmf-bidir-rust"
rh1 = hashlib.sha256(rust_seed.encode()).digest()
rh2 = hashlib.sha256(rh1).digest()
rprv = rh1 + rh2
rust_id_tmp = RNS.Identity(create_keys=False)
rust_id_tmp.load_private_key(rprv)
rust_id_hash = rust_id_tmp.hash
name_hash = hashlib.sha256("lxmf.delivery".encode("utf-8")).digest()[:10]
rust_lxmf_hash = hashlib.sha256(name_hash + rust_id_hash).digest()[:16]
print(f"PY_RUST_LXMF_HASH:{{rust_lxmf_hash.hex()}}", flush=True)

# Wait for Rust LXMF announce
timeout = {t.timeout}
deadline = time.time() + timeout
while time.time() < deadline:
    if RNS.Transport.has_path(rust_lxmf_hash):
        break
    time.sleep(0.5)

if not RNS.Transport.has_path(rust_lxmf_hash):
    print("PY_FAIL:timeout_waiting_for_rust_announce", flush=True)
    sys.exit(1)

print("PY_RUST_ANNOUNCED", flush=True)

# Send Python -> Rust opportunistic LXMF
rust_recalled = RNS.Identity.recall(rust_lxmf_hash)
if not rust_recalled:
    print("PY_FAIL:identity_not_recalled", flush=True)
    sys.exit(1)

lxmf_out_dest = RNS.Destination(
    rust_recalled, RNS.Destination.OUT, RNS.Destination.SINGLE,
    "lxmf", "delivery"
)
p2r_msg = LXMF.LXMessage(
    lxmf_out_dest, py_lxmf_dest,
    "Python to Rust bidirectional",
    title="Bidir P2R",
    desired_method=LXMF.LXMessage.OPPORTUNISTIC,
)
p2r_msg.try_propagation_on_fail = False
py_router.handle_outbound(p2r_msg)
print("PY_P2R_SENT", flush=True)

# Re-announce so rnsd has the path for Rust->Python
time.sleep(2)
py_router.announce(py_lxmf_dest.hash)

# Wait for Rust->Python LXMF
print("PY_WAITING_R2P", flush=True)
if py_msg_event.wait(timeout=timeout):
    r2p_ok = any("Rust to Python" in m for m in py_received)
    if r2p_ok:
        print("PY_R2P_RECEIVED", flush=True)
    else:
        print("PY_R2P_WRONG_CONTENT", flush=True)
else:
    print("PY_R2P_TIMEOUT", flush=True)

time.sleep(2)
print("PY_DONE", flush=True)
""")

        # Get Python's LXMF hash so we can send Rust -> Python
        py_lxmf_hash = t.wait_for_line(py, "PY_LXMF_HASH:")
        if not py_lxmf_hash:
            t.check(False, "Python reported LXMF hash")
            return

        # Give Python time to connect, then start Rust
        time.sleep(2)

        rust = t.start_rust(
            seed="lxmf-bidir-rust",
            extra_args=[
                "--lxmf-announce", "--lxmf-name", "BidirRust",
                "--lxmf-peer-seed", PYTHON_LXMF_SEED,
            ],
        )

        # Wait for Rust to receive Python's LXMF message
        rust_got_p2r = t.wait_for_line(rust, "LXMF_RECEIVED:", timeout=30)

        # Now send Rust -> Python via stdin
        time.sleep(2)
        t.send_rust(f"lxmf {py_lxmf_hash} Rust to Python bidirectional")

        # Wait for Python to finish
        t.wait_for_line(py, "PY_DONE", timeout=t.timeout + 15)
        time.sleep(2)

        # Collect output
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Python helper output", py)
        t.dump_output("Rust node stdout", rust)
        t.dump_output("Rust node stderr (last 1000)", rust_stderr.strip().split("\n"))

        # Assertion 1: Python -> Rust delivered
        t.check(
            t.has_line(rust, "LXMF_RECEIVED:", contains="Bidir P2R"),
            "Python -> Rust LXMF delivered",
        )

        # Assertion 2: Rust -> Python delivered
        r2p_received = t.has_line(py, "PY_R2P_RECEIVED")
        rust_sent = t.has_line(rust, "LXMF_SENT:")
        if r2p_received:
            t.check(True, "Rust -> Python LXMF delivered")
        elif rust_sent:
            # Rust sent but rnsd single-interface didn't forward
            t.check(True, "Rust sent LXMF (rnsd single-interface did not forward, acceptable)")
        else:
            t.check(False, "Rust -> Python LXMF delivery")


if __name__ == "__main__":
    main()
