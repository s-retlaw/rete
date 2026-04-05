#!/usr/bin/env python3
"""IFAC + transport relay E2E test: IFAC protection works through a relay chain.

Topology:
  Python_A --TCP--> rnsd_1 (port 4282, ifac="secure-net")
                        |
                    Rust (--transport, ifac="secure-net")
                        |
                    rnsd_2 (port 4283, ifac="secure-net") <--TCP-- Python_B

Both Python nodes announce, discover each other through the Rust relay, and
exchange DATA — all over IFAC-protected interfaces.

Assertions:
  1. Python_B's announce reaches Rust (through IFAC-protected rnsd_2)
  2. Python_B's announce reaches Python_A (through IFAC-protected relay chain)
  3. Python_A's DATA reaches Python_B (through IFAC-protected relay)

Usage:
  cd tests/interop
  uv run python ifac_relay_interop.py --rust-binary ../../target/debug/rete
"""

import os
import time

from interop_helpers import InteropTest


def write_py_node_script(tmpdir, config_dir, port, ifac, node_label, send_msg,
                         timeout, exclude_dest_hex=""):
    """Write a Python RNS node script that announces, discovers a peer,
    sends DATA, and waits for DATA. Returns the script text."""
    return f"""\
import RNS
import time
import sys
import os
import threading

config_dir = "{config_dir}"
reticulum = RNS.Reticulum(configdir=config_dir)

exclude_hex = "{exclude_dest_hex}"
exclude_hash = bytes.fromhex(exclude_hex) if exclude_hex else None

data_received = threading.Event()
received_text = [None]

def packet_callback(data, packet):
    text = data.decode("utf-8", errors="replace")
    received_text[0] = text
    print(f"{node_label.upper()}_DATA_RECEIVED:{{text}}", flush=True)
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

print(f"{node_label.upper()}_DEST_HASH:{{dest.hexhash}}", flush=True)

dest.announce()
print(f"{node_label.upper()}_ANNOUNCE_SENT", flush=True)

# Wait for peer announce (skip our own hash and the transport relay)
timeout = {timeout}
deadline = time.time() + timeout
peer_dest_hash = None

while time.time() < deadline:
    known = RNS.Transport.path_table
    for h in known:
        if h == dest.hash:
            continue
        if exclude_hash and h == exclude_hash:
            continue
        peer_dest_hash = h
        print(f"{node_label.upper()}_DISCOVERED:{{h.hex()}}", flush=True)
        break
    if peer_dest_hash:
        break
    time.sleep(0.5)

if peer_dest_hash:
    print(f"{node_label.upper()}_PEER_FOUND", flush=True)

    peer_identity = RNS.Identity.recall(peer_dest_hash)
    if peer_identity:
        out_dest = RNS.Destination(
            peer_identity,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            "rete",
            "example",
            "v1",
        )
        pkt = RNS.Packet(out_dest, b"{send_msg}")
        pkt.send()
        print(f"{node_label.upper()}_DATA_SENT", flush=True)
    else:
        print(f"{node_label.upper()}_DATA_SEND_FAIL:identity_not_recalled", flush=True)

    if data_received.wait(timeout=15):
        print(f"{node_label.upper()}_DATA_RECV_OK", flush=True)
    else:
        print(f"{node_label.upper()}_DATA_RECV_FAIL:timeout", flush=True)
else:
    print(f"{node_label.upper()}_PEER_NOT_FOUND", flush=True)

time.sleep(2)
print(f"{node_label.upper()}_DONE", flush=True)
"""


def main():
    with InteropTest("ifac-relay", default_port=4282) as t:
        IFAC = "secure-net"
        port1 = t.port       # 4282
        port2 = t.port + 1   # 4283

        # Start rnsd_1 and rnsd_2 with IFAC
        t.start_rnsd(port=port1, ifac_netname=IFAC)
        t.start_rnsd(port=port2, ifac_netname=IFAC)

        # Start Rust transport node connecting to both rnsd instances with IFAC
        rust = t.start_rust(
            port=port1,
            extra_args=[
                "--connect", f"127.0.0.1:{port2}",
                "--transport",
                "--ifac-netname", IFAC,
            ],
        )

        # Get the Rust transport node's dest hash (for Python nodes to filter)
        rust_dest_hex = t.wait_for_line(rust, "IDENTITY:", timeout=10) or ""
        t._log(f"Rust transport dest hash: {rust_dest_hex}")

        # Give Rust time to connect and announce on both interfaces
        time.sleep(3)

        # Write configs for both Python nodes with IFAC
        py_a_config_dir = os.path.join(t.tmpdir, "py_a_config")
        os.makedirs(py_a_config_dir, exist_ok=True)
        with open(os.path.join(py_a_config_dir, "config"), "w") as cf:
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
    target_port = {port1}
    ingress_control = false
    networkname = {IFAC}
""")

        py_b_config_dir = os.path.join(t.tmpdir, "py_b_config")
        os.makedirs(py_b_config_dir, exist_ok=True)
        with open(os.path.join(py_b_config_dir, "config"), "w") as cf:
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
    target_port = {port2}
    ingress_control = false
    networkname = {IFAC}
""")

        # Start both Python nodes -- they both announce and discover each other
        py_a = t.start_py_helper(write_py_node_script(
            t.tmpdir, py_a_config_dir, port1, IFAC,
            "py_a", "hello from A via ifac relay",
            t.timeout, exclude_dest_hex=rust_dest_hex,
        ))

        py_b = t.start_py_helper(write_py_node_script(
            t.tmpdir, py_b_config_dir, port2, IFAC,
            "py_b", "hello from B via ifac relay",
            t.timeout, exclude_dest_hex=rust_dest_hex,
        ))

        # Wait for both Python helpers to finish
        t.wait_for_line(py_a, "PY_A_DONE", timeout=t.timeout + 15)
        t.wait_for_line(py_b, "PY_B_DONE", timeout=15)
        time.sleep(2)

        # Collect output
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Python_A output", py_a)
        t.dump_output("Python_B output", py_b)
        t.dump_output("Rust stdout", rust)

        # --- Assertions ---

        # 1. Python_B's announce reaches Rust (through IFAC-protected rnsd_2)
        t.check(
            t.has_line(rust, "ANNOUNCE:"),
            "Announce reaches Rust through IFAC-protected interface",
        )

        # 2. Python_B's announce reaches Python_A (through IFAC-protected relay chain)
        t.check(
            t.has_line(py_a, "PY_A_PEER_FOUND"),
            "Python_A discovers Python_B via IFAC-protected relay chain",
        )

        # 3. Python_A's DATA reaches Python_B (through IFAC-protected relay)
        t.check(
            t.has_line(py_b, "PY_B_DATA_RECEIVED:", contains="hello from A via ifac relay"),
            "Python_A's DATA reaches Python_B through IFAC-protected relay",
        )


if __name__ == "__main__":
    main()
