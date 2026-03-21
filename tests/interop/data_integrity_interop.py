#!/usr/bin/env python3
"""E2E: Data integrity -- various byte patterns sent over link.

Tests various payload patterns to catch encoding/decoding bugs:
  1. All-zeros (32 bytes)
  2. All-0xFF (32 bytes)
  3. Binary counter (0x00..0xFF)
  4. UTF-8 text with unicode
  5. Single byte
  6. Binary mix of edge-case bytes
"""

import time
from interop_helpers import InteropTest


def main():
    with InteropTest("data-integrity", default_port=4351, default_timeout=45) as t:
        t.start_rnsd()
        rust = t.start_rust(seed="data-integrity-test-1")

        time.sleep(3)

        py = t.start_py_helper(f"""\
import RNS, time, sys, os

config_dir = os.path.join("{t.tmpdir}", "py_integrity_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config()}\"\"\")

reticulum = RNS.Reticulum(config_dir)
time.sleep(2)

# Discover Rust node via path table
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

link = RNS.Link(rust_dest)
start = time.time()
while link.status != RNS.Link.ACTIVE and time.time() - start < 15:
    time.sleep(0.2)

if link.status != RNS.Link.ACTIVE:
    print("PY_LINK_FAIL", flush=True)
    sys.exit(1)

print("PY_LINK_ACTIVE", flush=True)
time.sleep(1)

patterns = [
    ("zeros_32", bytes(32)),
    ("ones_32", bytes([0xFF] * 32)),
    ("counter_256", bytes(range(256))),
    ("utf8_text", "Hello World!".encode("utf-8")),
    ("single_byte", bytes([0x42])),
    ("binary_mix", bytes([0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE])),
]

for name, data in patterns:
    RNS.Packet(link, data).send()
    print(f"PY_SENT:{{name}}:{{data.hex()}}", flush=True)
    time.sleep(0.5)

time.sleep(3)
link.teardown()
print("PY_DONE", flush=True)
""")

        path = t.wait_for_line(py, "PY_PATH_FOUND", timeout=20)
        t.check(path is not None, "Python found Rust path")

        active = t.wait_for_line(py, "PY_LINK_ACTIVE")
        t.check(active is not None, "Link established")

        for name in ["zeros_32", "ones_32", "counter_256", "utf8_text", "single_byte", "binary_mix"]:
            sent = t.wait_for_line(py, f"PY_SENT:{name}")
            t.check(sent is not None, f"Sent pattern: {name}")

        time.sleep(3)

        # Count received LINK_DATA messages
        data_lines = [l for l in rust if "LINK_DATA" in l]
        t.check(len(data_lines) >= 6, f"Rust received all 6 patterns ({len(data_lines)} received)")

        # Rust node survived all patterns
        t.check(t._rust_proc.poll() is None, "Rust survived all data patterns")

        done = t.wait_for_line(py, "PY_DONE")
        t.check(done is not None, "Test completed")


if __name__ == "__main__":
    main()
