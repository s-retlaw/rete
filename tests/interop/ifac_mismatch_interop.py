#!/usr/bin/env python3
"""IFAC mismatch rejection E2E test: nodes with different IFAC netnames cannot communicate.

Topology:
  rnsd (port 4280, ifac="alpha")
  ├── Rust (ifac="alpha")         — same IFAC, should communicate
  ├── Python_right (ifac="alpha") — same IFAC, should communicate with Rust
  └── Python_wrong (ifac="beta")  — different IFAC, should NOT see Rust's announce

Assertions:
  1. Python_right discovers Rust's announce (same IFAC works)
  2. Python_right's DATA reaches Rust
  3. Python_wrong does NOT discover Rust's announce (different IFAC blocks)
  4. Rust received Python_right's announce

Usage:
  cd tests/interop
  uv run python ifac_mismatch_interop.py --rust-binary ../../target/debug/rete-linux
"""

import os
import time

from interop_helpers import InteropTest


def main():
    with InteropTest("ifac-mismatch", default_port=4280) as t:
        # Start rnsd with IFAC "alpha"
        t.start_rnsd(ifac_netname="alpha")

        # Start Rust node with IFAC "alpha"
        rust = t.start_rust(
            seed="ifac-mismatch-seed-01",
            extra_args=["--ifac-netname", "alpha", "--auto-reply", "hello from rust"],
        )

        # Give Rust time to connect and announce
        time.sleep(3)

        # Start Python_right with IFAC "alpha" (should communicate)
        py_right_config_dir = os.path.join(t.tmpdir, "py_right_config")
        os.makedirs(py_right_config_dir, exist_ok=True)
        with open(os.path.join(py_right_config_dir, "config"), "w") as cf:
            cf.write(f"""\
[reticulum]
  enable_transport = no
  share_instance = no

[logging]
  loglevel = 5

[interfaces]

  [[TCP Client Interface]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = {t.port}
    networkname = alpha
""")

        py_right = t.start_py_helper(f"""\
import RNS
import time
import sys
import os
import threading

config_dir = "{py_right_config_dir}"
reticulum = RNS.Reticulum(configdir=config_dir)

data_received = threading.Event()

def packet_callback(data, packet):
    text = data.decode("utf-8", errors="replace")
    print(f"PY_RIGHT_DATA_RECEIVED:{{text}}", flush=True)
    data_received.set()

identity = RNS.Identity()
dest = RNS.Destination(
    identity,
    RNS.Destination.IN,
    RNS.Destination.SINGLE,
    "rete",
    "example",
    "v1",
)
dest.set_packet_callback(packet_callback)

print(f"PY_RIGHT_DEST_HASH:{{dest.hexhash}}", flush=True)

dest.announce()
print("PY_RIGHT_ANNOUNCE_SENT", flush=True)

# Wait for Rust announce
timeout = {t.timeout}
deadline = time.time() + timeout
rust_dest_hash = None

while time.time() < deadline:
    known = RNS.Transport.path_table
    for h in known:
        if h != dest.hash:
            rust_dest_hash = h
            print(f"PY_RIGHT_DISCOVERED:{{h.hex()}}", flush=True)
            break
    if rust_dest_hash:
        break
    time.sleep(0.5)

if rust_dest_hash:
    print("PY_RIGHT_INTEROP_OK", flush=True)

    rust_identity = RNS.Identity.recall(rust_dest_hash)
    if rust_identity:
        out_dest = RNS.Destination(
            rust_identity,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            "rete",
            "example",
            "v1",
        )
        pkt = RNS.Packet(out_dest, b"hello from python right")
        pkt.send()
        print("PY_RIGHT_DATA_SENT", flush=True)
    else:
        print("PY_RIGHT_DATA_SEND_FAIL:identity_not_recalled", flush=True)

    if data_received.wait(timeout=10):
        print("PY_RIGHT_DATA_RECV_OK", flush=True)
    else:
        print("PY_RIGHT_DATA_RECV_FAIL:timeout", flush=True)
else:
    print("PY_RIGHT_INTEROP_FAIL:timeout_waiting_for_rust_announce", flush=True)

time.sleep(2)
print("PY_RIGHT_DONE", flush=True)
""")

        # Wait for Python_right to finish discovering and exchanging data
        t.wait_for_line(py_right, "PY_RIGHT_DONE", timeout=t.timeout + 10)

        # Now start Python_wrong with IFAC "beta" (should NOT see Rust's announce)
        py_wrong_config_dir = os.path.join(t.tmpdir, "py_wrong_config")
        os.makedirs(py_wrong_config_dir, exist_ok=True)
        with open(os.path.join(py_wrong_config_dir, "config"), "w") as cf:
            cf.write(f"""\
[reticulum]
  enable_transport = no
  share_instance = no

[logging]
  loglevel = 5

[interfaces]

  [[TCP Client Interface]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = {t.port}
    networkname = beta
""")

        py_wrong = t.start_py_helper(f"""\
import RNS
import time
import sys
import os

config_dir = "{py_wrong_config_dir}"
reticulum = RNS.Reticulum(configdir=config_dir)

identity = RNS.Identity()
dest = RNS.Destination(
    identity,
    RNS.Destination.IN,
    RNS.Destination.SINGLE,
    "rete",
    "example",
    "v1",
)

print(f"PY_WRONG_DEST_HASH:{{dest.hexhash}}", flush=True)

# Wait a reasonable time to see if any announces arrive (they should NOT)
wait_secs = 12
deadline = time.time() + wait_secs
found_any = False

while time.time() < deadline:
    known = RNS.Transport.path_table
    for h in known:
        if h != dest.hash:
            print(f"PY_WRONG_DISCOVERED:{{h.hex()}}", flush=True)
            found_any = True
            break
    if found_any:
        break
    time.sleep(0.5)

if not found_any:
    print("PY_WRONG_NO_ANNOUNCES", flush=True)

print("PY_WRONG_DONE", flush=True)
""")

        # Wait for Python_wrong to finish its wait period
        t.wait_for_line(py_wrong, "PY_WRONG_DONE", timeout=20)
        time.sleep(2)

        # Collect Rust stderr
        rust_stderr = t.collect_rust_stderr()

        # Debug output
        t.dump_output("Python_right output", py_right)
        t.dump_output("Python_wrong output", py_wrong)
        t.dump_output("Rust stdout", rust)

        # --- Assertions ---

        # 1. Python_right discovers Rust's announce (same IFAC works)
        t.check(
            t.has_line(py_right, "PY_RIGHT_INTEROP_OK"),
            "Python_right discovers Rust announce (same IFAC)",
        )

        # 2. Python_right's DATA reaches Rust
        rust_data_lines = [l for l in rust if l.startswith("DATA:")]
        t.check(
            any("hello from python right" in l for l in rust_data_lines),
            "Python_right's DATA reaches Rust",
            detail=f"Rust DATA lines: {rust_data_lines}" if rust_data_lines else "no DATA lines",
        )

        # 3. Python_wrong does NOT discover Rust's announce (different IFAC blocks)
        t.check(
            t.has_line(py_wrong, "PY_WRONG_NO_ANNOUNCES"),
            "Python_wrong does NOT discover Rust announce (different IFAC)",
            detail="Python_wrong saw announces despite mismatched IFAC"
            if not t.has_line(py_wrong, "PY_WRONG_NO_ANNOUNCES")
            else None,
        )

        # 4. Rust received Python_right's announce
        t.check(
            t.has_line(rust, "ANNOUNCE:"),
            "Rust received Python_right's announce",
        )


if __name__ == "__main__":
    main()
