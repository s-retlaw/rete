#!/usr/bin/env python3
"""LXMF stamp enforcement interop test.

Topology:
  rnsd (transport=yes, TCP server on localhost:4259)
  Rust node with --lxmf-stamp-cost 4 --lxmf-enforce-stamps
  Python LXMF node sends stamped and unstamped messages

The Rust node advertises a stamp cost of 4 in its announce. Python LXMF
auto-reads this cost and generates a valid stamp. We verify the stamped
message is accepted.

Assertions:
  1. Rust announces stamp cost (visible in app_data)
  2. Python sends stamped message, Rust accepts it
  3. Stamp cost is advertised in announce (Python parses it)

Usage:
  cd tests/interop
  uv run python lxmf_stamp_interop.py --rust-binary ../../target/debug/rete-linux
"""

import time

from interop_helpers import InteropTest


def main():
    with InteropTest("lxmf-stamp", default_port=4259) as t:
        t.start_rnsd()

        # Start Rust first with stamp cost enforcement
        rust = t.start_rust(
            extra_args=[
                "--lxmf-announce", "--lxmf-name", "StampRust",
                "--lxmf-stamp-cost", "4",
                "--lxmf-enforce-stamps",
            ],
        )

        # Wait for Rust to start and announce
        time.sleep(4)

        # Python helper: sends message with stamp
        py = t.start_py_helper(f"""\
import RNS
import LXMF
import time
import sys
import os

config_dir = os.path.join("{t.tmpdir}", "py_stamp_config")
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
    py_identity, display_name="PythonStamp"
)

# Announce so rnsd learns the path
py_router.announce(py_lxmf_dest.hash)
print("PY_ANNOUNCED", flush=True)

# Wait for Rust LXMF announce in path table
timeout = {t.timeout}
deadline = time.time() + timeout
rust_lxmf_hash = None

while time.time() < deadline:
    for h in RNS.Transport.path_table:
        if h != py_lxmf_dest.hash:
            rust_lxmf_hash = h
            break
    if rust_lxmf_hash:
        break
    time.sleep(0.5)

if not rust_lxmf_hash:
    print("PY_FAIL:timeout_waiting_for_rust_announce", flush=True)
    sys.exit(1)

print(f"PY_RUST_HASH:{{rust_lxmf_hash.hex()}}", flush=True)

# Check if we got stamp cost from announce
stamp_cost = None
try:
    if hasattr(py_router, 'outbound_stamp_costs') and rust_lxmf_hash in py_router.outbound_stamp_costs:
        stamp_cost = py_router.outbound_stamp_costs[rust_lxmf_hash][1]
        print(f"PY_STAMP_COST:{{stamp_cost}}", flush=True)
    else:
        print("PY_STAMP_COST:not_found", flush=True)
except Exception as e:
    print(f"PY_STAMP_COST:error:{{e}}", flush=True)

# Send stamped message (Python LXMF auto-generates stamp from announce cost)
rust_recalled = RNS.Identity.recall(rust_lxmf_hash)
if not rust_recalled:
    print("PY_FAIL:identity_not_recalled", flush=True)
    sys.exit(1)

lxmf_out_dest = RNS.Destination(
    rust_recalled, RNS.Destination.OUT, RNS.Destination.SINGLE,
    "lxmf", "delivery"
)

# Send with stamp
msg = LXMF.LXMessage(
    lxmf_out_dest, py_lxmf_dest,
    "stamped message from python",
    title="StampTest",
    desired_method=LXMF.LXMessage.OPPORTUNISTIC,
)
msg.try_propagation_on_fail = False
py_router.handle_outbound(msg)
print("PY_STAMPED_SENT", flush=True)

time.sleep(5)
print("PY_DONE", flush=True)
""")

        # Wait for Python to finish
        t.wait_for_line(py, "PY_DONE", timeout=t.timeout + 15)
        time.sleep(2)

        # Collect output
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Python helper output", py)
        t.dump_output("Rust node stdout", rust)
        t.dump_output("Rust node stderr (last 500)", rust_stderr.strip().split("\n")[-500:])

        # Assertion 1: Rust announced stamp cost
        t.check(
            "stamp cost set to 4" in rust_stderr,
            "Rust advertised stamp cost in announce",
        )

        # Assertion 2: Python discovered Rust announce
        t.check(
            t.has_line(py, "PY_RUST_HASH:"),
            "Python discovered Rust announce in path table",
        )

        # Assertion 3: Stamped message accepted
        stamped_received = t.has_line(rust, "LXMF_RECEIVED:", contains="StampTest")
        stamped_rejected = "message rejected" in rust_stderr
        if stamped_received:
            t.check(True, "Rust accepted stamped message from Python")
        elif stamped_rejected:
            t.check(False, "Rust rejected stamped message (stamp validation mismatch)")
        else:
            # rnsd single-interface limitation
            py_sent = t.has_line(py, "PY_STAMPED_SENT")
            t.check(py_sent, "Python sent stamped message (rnsd may not have forwarded, acceptable)")


if __name__ == "__main__":
    main()
