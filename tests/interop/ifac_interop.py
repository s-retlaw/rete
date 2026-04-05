#!/usr/bin/env python3
"""IFAC interop test: Rust rete node <-> Python rnsd with Interface Access Codes.

Topology (per sub-test):
  rnsd (transport=yes, TCP server on localhost:<port>, optional IFAC)
  Rust node connects as TCP client (with optional IFAC)
  Python client connects as TCP client (with optional IFAC)

Assertions:
  1. Matching IFAC: Python discovers Rust announce
  2. Matching IFAC: Rust receives Python announce
  3. Matching IFAC: Python receives DATA from Rust (auto-reply)
  4. Matching IFAC: Rust receives DATA from Python
  5. Matching IFAC: Rust reports IFAC enabled
  6. No IFAC on Rust: Rust sees no announces (IFAC packets dropped)
  7. Wrong IFAC on Rust: Rust sees no valid announces

Usage:
  cd tests/interop
  uv run python ifac_interop.py --rust-binary ../../target/debug/rete
"""

import time

from interop_helpers import InteropTest


IFAC_NETNAME = "rete-test-network"


def py_ifac_client_script(tmpdir, port, ifac_netname=None, timeout=30.0):
    """Generate a Python IFAC client script."""
    ifac_config = ""
    if ifac_netname:
        ifac_config = f"\\n    networkname = {ifac_netname}"

    return f"""\
import RNS
import time
import sys
import os
import threading

config_dir = os.path.join("{tmpdir}", "py_client_config_{port}")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"
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
    target_port = {port}{ifac_config}
    ingress_control = false
\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

data_received = threading.Event()

def packet_callback(data, packet):
    text = data.decode("utf-8", errors="replace")
    print(f"PY_DATA_RECEIVED:{{text}}", flush=True)
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

print(f"PY_DEST_HASH:{{dest.hexhash}}", flush=True)
print(f"PY_IDENTITY_HASH:{{identity.hexhash}}", flush=True)

dest.announce()
print("PY_ANNOUNCE_SENT", flush=True)

timeout = {timeout}
deadline = time.time() + timeout
rust_dest_hash = None

while time.time() < deadline:
    known = RNS.Transport.path_table
    for h in known:
        if h != dest.hash:
            rust_dest_hash = h
            print(f"PY_DISCOVERED:{{h.hex()}}", flush=True)
            break
    if rust_dest_hash:
        break
    time.sleep(0.5)

if rust_dest_hash:
    print("PY_INTEROP_OK", flush=True)

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
        pkt = RNS.Packet(out_dest, b"hello from python")
        pkt.send()
        print("PY_DATA_SENT", flush=True)
    else:
        print("PY_DATA_SEND_FAIL:identity_not_recalled", flush=True)

    if data_received.wait(timeout=10):
        print("PY_DATA_RECV_OK", flush=True)
    else:
        print("PY_DATA_RECV_FAIL:timeout", flush=True)
else:
    print("PY_INTEROP_FAIL:timeout_waiting_for_rust_announce", flush=True)

time.sleep(2)
print("PY_DONE", flush=True)
"""


def main():
    with InteropTest("ifac", default_port=4252) as t:

        # ==================================================================
        # SUB-TEST 1: Matching IFAC — Rust and Python can communicate
        # ==================================================================
        t._log("=" * 60)
        t._log("SUB-TEST 1: Matching IFAC — bidirectional communication")
        t._log("=" * 60)

        t.start_rnsd(port=t.port, ifac_netname=IFAC_NETNAME)
        rust1 = t.start_rust(
            port=t.port,
            extra_args=["--ifac-netname", IFAC_NETNAME, "--auto-reply", "hello from rust"],
        )
        time.sleep(2)

        py1 = t.start_py_helper(
            py_ifac_client_script(t.tmpdir, t.port, ifac_netname=IFAC_NETNAME, timeout=t.timeout)
        )

        t.wait_for_line(py1, "PY_DONE", timeout=t.timeout + 10)
        time.sleep(2)

        # Collect Rust output (need to stop to get stderr)
        rust1_stderr = t.collect_rust_stderr()

        # Check 1: Python discovered Rust announce
        t.check(
            t.has_line(py1, "PY_INTEROP_OK"),
            "Matching IFAC: Python discovered Rust announce",
        )

        # Check 2: Rust received Python announce
        t.check(
            t.has_line(rust1, "ANNOUNCE:"),
            "Matching IFAC: Rust received Python announce",
        )

        # Check 3: Python received DATA from Rust (auto-reply)
        t.check(
            t.has_line(py1, "PY_DATA_RECEIVED:"),
            "Matching IFAC: Python received DATA from Rust",
        )

        # Check 4: Rust received DATA from Python
        t.check(
            t.has_line(rust1, "DATA:", contains="hello from python"),
            "Matching IFAC: Rust received DATA from Python",
        )

        # Check 5: Rust reports IFAC enabled
        t.check(
            "IFAC enabled" in rust1_stderr,
            "Matching IFAC: Rust reports IFAC enabled",
        )

        # Allow cleanup time before next sub-test
        time.sleep(1)

        # ==================================================================
        # SUB-TEST 2: No IFAC on Rust — should not see IFAC traffic
        # ==================================================================
        port2 = t.port + 1
        t._log("=" * 60)
        t._log("SUB-TEST 2: Rust WITHOUT IFAC cannot see IFAC-protected traffic")
        t._log("=" * 60)

        t.start_rnsd(port=port2, ifac_netname=IFAC_NETNAME)
        rust2 = t.start_rust(
            port=port2,
            extra_args=["--auto-reply", "hello from rust"],
            # No --ifac-netname
        )
        time.sleep(2)

        py2 = t.start_py_helper(
            py_ifac_client_script(t.tmpdir, port2, ifac_netname=IFAC_NETNAME, timeout=10)
        )

        t.wait_for_line(py2, "PY_DONE", timeout=25)
        time.sleep(2)

        # Check 6: Rust without IFAC sees no announces
        rust2_announces = [l for l in rust2 if l.startswith("ANNOUNCE:")]
        t.check(
            len(rust2_announces) == 0,
            "No IFAC: Rust without IFAC saw 0 announces (IFAC packets dropped)",
            detail=f"Saw {len(rust2_announces)} announces" if rust2_announces else None,
        )

        time.sleep(1)

        # ==================================================================
        # SUB-TEST 3: Wrong IFAC key — should not communicate
        # ==================================================================
        port3 = t.port + 2
        t._log("=" * 60)
        t._log("SUB-TEST 3: Rust with WRONG IFAC key cannot communicate")
        t._log("=" * 60)

        t.start_rnsd(port=port3, ifac_netname=IFAC_NETNAME)
        rust3 = t.start_rust(
            port=port3,
            extra_args=["--ifac-netname", "wrong-network-name", "--auto-reply", "hello from rust"],
        )
        time.sleep(2)

        py3 = t.start_py_helper(
            py_ifac_client_script(t.tmpdir, port3, ifac_netname=IFAC_NETNAME, timeout=10)
        )

        t.wait_for_line(py3, "PY_DONE", timeout=25)
        time.sleep(2)

        # Check 7: Rust with wrong IFAC key sees no valid announces
        rust3_announces = [l for l in rust3 if l.startswith("ANNOUNCE:")]
        t.check(
            len(rust3_announces) == 0,
            "Wrong IFAC: Rust with wrong IFAC key saw 0 announces",
            detail=f"Saw {len(rust3_announces)} announces" if rust3_announces else None,
        )


if __name__ == "__main__":
    main()
