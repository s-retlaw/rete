#!/usr/bin/env python3
"""E2E: Path expiry -- announce, send data, re-announce, send again.

Tests:
  1. Python announces, Rust learns path
  2. Rust sends data to Python via stdin command
  3. Python re-announces
  4. Rust sends data again after re-learning the path
"""

import time
from interop_helpers import InteropTest


def main():
    with InteropTest("path-expiry", default_port=4349, default_timeout=45) as t:
        t.start_rnsd()
        rust = t.start_rust()

        time.sleep(3)

        py = t.start_py_helper(f"""\
import RNS, time, sys, os

config_dir = os.path.join("{t.tmpdir}", "py_path_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config()}\"\"\")

reticulum = RNS.Reticulum(config_dir)

identity = RNS.Identity()
dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                       "pathtest", "node")

received = []
def packet_callback(data, packet):
    msg = data.decode()
    received.append(msg)
    print(f"PY_RECV:{{msg}}", flush=True)

dest.set_packet_callback(packet_callback)

# First announce
dest.announce(app_data=b"first-announce")
print(f"PY_DEST:{{dest.hexhash}}", flush=True)
time.sleep(3)

# Wait for first data
for _ in range(20):
    if received:
        break
    time.sleep(1)

if received:
    print("PY_FIRST_DATA_OK", flush=True)
else:
    print("PY_FIRST_DATA_FAIL", flush=True)

# Re-announce (simulating path refresh)
time.sleep(2)
dest.announce(app_data=b"second-announce")
print("PY_REANNOUNCED", flush=True)
time.sleep(3)

# Wait for second data
initial_count = len(received)
for _ in range(20):
    if len(received) > initial_count:
        break
    time.sleep(1)

if len(received) > initial_count:
    print("PY_SECOND_DATA_OK", flush=True)
else:
    print("PY_SECOND_DATA_FAIL", flush=True)

print("PY_DONE", flush=True)
""")

        py_dest = t.wait_for_line(py, "PY_DEST")
        t.check(py_dest is not None, "Python announced")

        # Wait for Rust to learn path, then send data
        announce = t.wait_for_line(rust, "ANNOUNCE")
        t.check(announce is not None, "Rust received announce")
        time.sleep(1)

        # Send data via Rust stdin
        t.send_rust(f"send {py_dest} first-msg-to-python")
        first_ok = t.wait_for_line(py, "PY_FIRST_DATA_OK", timeout=20)
        t.check(first_ok is not None, "First data delivery succeeded")

        # Wait for re-announce
        reannounced = t.wait_for_line(py, "PY_REANNOUNCED")
        t.check(reannounced is not None, "Python re-announced")
        time.sleep(3)

        # Send data again after re-announce
        t.send_rust(f"send {py_dest} second-msg-to-python")
        second_ok = t.wait_for_line(py, "PY_SECOND_DATA_OK", timeout=20)
        t.check(second_ok is not None, "Second data delivery after re-announce succeeded")

        done = t.wait_for_line(py, "PY_DONE")
        t.check(done is not None, "Test completed")


if __name__ == "__main__":
    main()
