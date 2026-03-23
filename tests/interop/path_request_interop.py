#!/usr/bin/env python3
"""Path request E2E test: Rust transport node responds to path requests.

Topology:
  Python_A <-TCP:4246-> rnsd <-TCP-> Rust_Transport
  Python_C connects later and requests path to Python_A via Rust.

Flow:
  1. Start rnsd + Rust transport node
  2. Python_A connects, announces, then disconnects
  3. Python_C connects and calls request_path(A's dest hash)
  4. Rust should respond with the cached announce for A
  5. Python_C discovers A's path

Assertions:
  1. Rust received Python_A's announce
  2. Python_C discovers Python_A via path request (without seeing the original announce)

Usage:
  cd tests/interop
  uv run python path_request_interop.py
"""

import time

from interop_helpers import InteropTest


def main():
    with InteropTest("path-request", default_port=4246) as t:
        t.start_rnsd()
        rust = t.start_rust(
            extra_args=["--transport"],
        )

        # Give Rust time to connect
        time.sleep(2)

        # --- Python_A: connect, announce, capture dest hash, stay alive briefly ---
        py_a = t.start_py_helper(f"""\
import RNS
import time
import os

config_dir = os.path.join("{t.tmpdir}", "py_a_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config(transport=False)}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)
identity = RNS.Identity()
dest = RNS.Destination(
    identity, RNS.Destination.IN, RNS.Destination.SINGLE,
    "rete", "example", "v1",
)
dest.announce()
print(f"PY_A_DEST_HASH:{{dest.hexhash}}", flush=True)
# Keep alive long enough for Rust to receive and cache the announce
time.sleep(5)
print("PY_A_DONE", flush=True)
""")

        # Wait for Python_A to report its dest hash and finish
        a_dest_hex = t.wait_for_line(py_a, "PY_A_DEST_HASH:", timeout=15)
        t.wait_for_line(py_a, "PY_A_DONE", timeout=15)

        if not a_dest_hex:
            t.check(False, "Could not get Python_A dest hash")
            return

        t.dump_output("Python_A output", py_a)
        print(f"[path-request] Python_A dest hash: {a_dest_hex}")

        # Give Rust time to cache the announce
        time.sleep(2)

        # Check Rust received the announce before proceeding
        rust_saw_announce = t.has_line(rust, f"ANNOUNCE:{a_dest_hex}")

        # Get Rust transport dest hash for filtering from stdout
        rust_dest_hex = ""
        for line in rust:
            if line.startswith("IDENTITY:"):
                rust_dest_hex = line.split(":")[1].strip()
                break

        # --- Python_C: connect, request path, check discovery ---
        py_c = t.start_py_helper(f"""\
import RNS
import time
import os

config_dir = os.path.join("{t.tmpdir}", "py_c_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config(transport=False)}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

target_hex = "{a_dest_hex}"
target_hash = bytes.fromhex(target_hex)
exclude_hex = "{rust_dest_hex}"
exclude_hash = bytes.fromhex(exclude_hex) if exclude_hex else None

# First check: we should NOT have the path yet (Python_A already disconnected)
has_path_before = RNS.Transport.has_path(target_hash)
print(f"PY_C_HAS_PATH_BEFORE:{{has_path_before}}", flush=True)

# Request the path
print("PY_C_REQUESTING_PATH", flush=True)
RNS.Transport.request_path(target_hash)

# Wait for path to appear
deadline = time.time() + 15
found = False
while time.time() < deadline:
    if RNS.Transport.has_path(target_hash):
        found = True
        print("PY_C_PATH_FOUND", flush=True)
        break
    time.sleep(0.5)

if not found:
    print("PY_C_PATH_NOT_FOUND", flush=True)

time.sleep(1)
print("PY_C_DONE", flush=True)
""")

        # Wait for Python_C to finish
        t.wait_for_line(py_c, "PY_C_DONE", timeout=t.timeout)

        # Collect output
        time.sleep(1)
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Python_C output", py_c)
        t.dump_output("Rust node stdout", rust)
        t.dump_output("Rust node stderr (last 500)", rust_stderr.strip().split("\n"))

        # --- Assertions ---

        # 1. Rust received Python_A's announce
        t.check(
            t.has_line(rust, f"ANNOUNCE:{a_dest_hex}"),
            "Rust received Python_A's announce",
        )

        # 2. Python_C discovered Python_A via path request
        t.check(
            t.has_line(py_c, "PY_C_PATH_FOUND"),
            "Python_C discovered Python_A via path request through Rust",
        )


if __name__ == "__main__":
    main()
