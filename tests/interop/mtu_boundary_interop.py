#!/usr/bin/env python3
"""E2E: MTU boundary -- send data at various sizes (1, 16, MDU/2, MDU-1, MDU).

Verifies that packets at the maximum data unit boundary are handled
correctly over a link.
"""

import time
from interop_helpers import InteropTest


def main():
    with InteropTest("mtu-boundary", default_port=4344, default_timeout=45) as t:
        t.start_rnsd()
        rust = t.start_rust()

        time.sleep(3)

        py = t.start_py_helper(f"""\
import RNS, time, sys, os

config_dir = os.path.join("{t.tmpdir}", "py_mtu_config")
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

# Link MDU is typically 431 bytes
mdu = link.MDU
print(f"PY_MDU:{{mdu}}", flush=True)

# Send at various sizes relative to MDU
sizes = [
    ("tiny", 1),
    ("small", 16),
    ("half_mdu", mdu // 2),
    ("mdu_minus_1", mdu - 1),
    ("exact_mdu", mdu),
]

for name, size in sizes:
    data = bytes([ord('A') + (i % 26) for i in range(size)])
    try:
        RNS.Packet(link, data).send()
        print(f"PY_SENT_{{name}}:{{size}}", flush=True)
    except Exception as e:
        print(f"PY_SEND_FAIL_{{name}}:{{e}}", flush=True)
    time.sleep(0.5)

time.sleep(3)
link.teardown()
print("PY_DONE", flush=True)
""")

        path = t.wait_for_line(py, "PY_PATH_FOUND", timeout=20)
        t.check(path is not None, "Python found Rust path")

        active = t.wait_for_line(py, "PY_LINK_ACTIVE")
        t.check(active is not None, "Link established")

        mdu = t.wait_for_line(py, "PY_MDU")
        t.check(mdu is not None, f"MDU reported: {mdu}")

        for name in ["tiny", "small", "half_mdu", "mdu_minus_1", "exact_mdu"]:
            sent = t.wait_for_line(py, f"PY_SENT_{name}")
            t.check(sent is not None, f"Sent {name} packet")

        # Wait for Rust to receive all
        time.sleep(3)

        # Count received LINK_DATA messages
        link_data_lines = [l for l in rust if "LINK_DATA" in l]
        t.check(len(link_data_lines) >= 5, f"Rust received all 5 size variants ({len(link_data_lines)} received)")

        done = t.wait_for_line(py, "PY_DONE")
        t.check(done is not None, "Test completed")


if __name__ == "__main__":
    main()
