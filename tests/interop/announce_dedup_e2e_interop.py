#!/usr/bin/env python3
"""Announce dedup E2E test: Python rapidly re-announces 5 times.

Validates the dedup pipeline prevents announce floods from reaching
the application layer repeatedly.

Topology:
  rnsd (transport=yes, TCP server on localhost:4312)
  Rust node connects as TCP client
  Python sends 5 rapid announces (200ms apart)

Assertions:
  1. Rust received at least 1 announce
  2. Rust received at most 2 announces (dedup prevented flood)
  3. No crash

Usage:
  cd tests/interop
  uv run python announce_dedup_e2e_interop.py --rust-binary ../../target/debug/rete-linux
"""

import time

from interop_helpers import InteropTest


def main():
    with InteropTest("announce-dedup-e2e", default_port=4312) as t:
        t.start_rnsd()
        rust = t.start_rust(seed="announce-dedup-e2e-test-seed-42")

        # Give Rust time to connect and announce
        time.sleep(3)

        py = t.start_py_helper(f"""\
import RNS
import time
import sys
import os

config_dir = os.path.join("{t.tmpdir}", "py_client_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config(transport=False)}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

identity = RNS.Identity()
dest = RNS.Destination(
    identity,
    RNS.Destination.IN,
    RNS.Destination.SINGLE,
    "rete", "example", "v1",
)

print(f"PY_DEST_HASH:{{dest.hexhash}}", flush=True)
print(f"PY_IDENTITY_HASH:{{identity.hexhash}}", flush=True)

# Rapid-fire 5 announces at 200ms intervals
for i in range(5):
    dest.announce()
    print(f"PY_ANNOUNCE_SENT:{{i}}", flush=True)
    time.sleep(0.2)

print("PY_BURST_DONE", flush=True)
time.sleep(5)
print("PY_DONE", flush=True)
""")

        # Wait for Python to finish
        t.wait_for_line(py, "PY_DONE", timeout=t.timeout + 10)
        time.sleep(2)

        # Collect output
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Python output", py)
        t.dump_output("Rust stdout", rust)
        t.dump_output("Rust stderr (last 1000)", rust_stderr.strip().split("\n"))

        # Get Python's dest hash to count announces for that specific dest
        py_dest = None
        for l in py:
            if l.startswith("PY_DEST_HASH:"):
                py_dest = l.split(":")[1].strip()
                break

        # Count announces from Python's specific dest hash
        if py_dest:
            matching_announces = [
                l for l in rust
                if l.startswith("ANNOUNCE:") and py_dest in l
            ]
            announce_count = len(matching_announces)
        else:
            announce_lines = [l for l in rust if l.startswith("ANNOUNCE:")]
            announce_count = len(announce_lines)

        # --- Assertion 1: At least 1 announce received ---
        t.check(
            announce_count >= 1,
            f"Rust received at least 1 announce ({announce_count} total)",
        )

        # --- Assertion 2: At most 2 (dedup working) ---
        # RNS may let the first through and deduplicate the rest.
        # Allowing 2 accounts for timing/race conditions.
        t.check(
            announce_count <= 2,
            f"Rust received at most 2 announces (dedup working, got {announce_count})",
            detail=f"Expected <= 2, got {announce_count}. Dedup may not be working." if announce_count > 2 else None,
        )

        # --- Assertion 3: No crash ---
        has_panic = "panicked" in rust_stderr.lower() or "sigsegv" in rust_stderr.lower()
        t.check(
            not has_panic,
            "No crash (no panic/SIGSEGV in stderr)",
        )


if __name__ == "__main__":
    main()
