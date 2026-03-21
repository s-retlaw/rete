#!/usr/bin/env python3
"""E2E: Repeated link cycles — establish, exchange data, teardown, repeat.

Tests that links can be established, used, and torn down 5x without
resource leaks or state corruption.
"""

import time
from interop_helpers import InteropTest

NUM_CYCLES = 5


def main():
    with InteropTest("link-cycle", default_port=4341, default_timeout=90) as t:
        t.start_rnsd()
        rust = t.start_rust(seed="link-cycle-test-42")

        time.sleep(3)

        py = t.start_py_helper(f"""\
import RNS, time, sys, os, threading

config_dir = os.path.join("{t.tmpdir}", "py_cycle_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config()}\"\"\")

reticulum = RNS.Reticulum(config_dir)
time.sleep(2)

# Discover Rust node
deadline = time.time() + 15
rust_dest_hash = None
while time.time() < deadline:
    for h in RNS.Transport.path_table:
        rust_dest_hash = h
        break
    if rust_dest_hash:
        break
    time.sleep(0.5)

if not rust_dest_hash:
    print("PY_NO_PATH", flush=True)
    sys.exit(1)

print("PY_PATH_FOUND", flush=True)
rust_id = RNS.Identity.recall(rust_dest_hash)
rust_dest = RNS.Destination(
    rust_id, RNS.Destination.OUT, RNS.Destination.SINGLE,
    "rete", "example", "v1",
)

for cycle in range({NUM_CYCLES}):
    link = RNS.Link(rust_dest)
    start = time.time()
    while link.status != RNS.Link.ACTIVE and time.time() - start < 15:
        time.sleep(0.2)

    if link.status != RNS.Link.ACTIVE:
        print(f"PY_CYCLE_{{cycle}}_LINK_FAIL:status={{link.status}}", flush=True)
        time.sleep(2)
        continue

    time.sleep(1)  # LRRTT handshake stabilization
    RNS.Packet(link, f"cycle-{{cycle}}-data".encode()).send()
    time.sleep(1)
    link.teardown()
    time.sleep(2)
    print(f"PY_CYCLE_{{cycle}}_OK", flush=True)

print("PY_ALL_DONE", flush=True)
""")

        path = t.wait_for_line(py, "PY_PATH_FOUND", timeout=20)
        t.check(path is not None, "Python found Rust path")

        for i in range(NUM_CYCLES):
            result = t.wait_for_line(py, f"PY_CYCLE_{i}_OK", timeout=25)
            t.check(result is not None, f"Link cycle {i} completed")

        done = t.wait_for_line(py, "PY_ALL_DONE", timeout=10)
        t.check(done is not None, f"All {NUM_CYCLES} cycles completed")

        link_count = sum(1 for l in rust if "LINK_ESTABLISHED" in l)
        t.check(link_count >= NUM_CYCLES, f"Rust saw {link_count} link establishments (need {NUM_CYCLES})")


if __name__ == "__main__":
    main()
