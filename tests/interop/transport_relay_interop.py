#!/usr/bin/env python3
"""Multi-interface transport relay E2E test:
  Python_A <-TCP:4260-> rnsd_1 <-TCP-> Rust_Transport <-TCP-> rnsd_2 <-TCP:4261-> Python_B

The Rust node connects to TWO separate rnsd instances (--connect x2, --transport)
and acts as the transport relay between them.

Assertions:
  1. Python_B discovers Python_A's announce (relayed through Rust)
  2. Python_A discovers Python_B's announce (relayed through Rust)
  3. Python_A sends DATA to Python_B -> received (relayed through Rust)
  4. Python_B sends DATA to Python_A -> received (relayed through Rust)

Usage:
  cd tests/interop
  uv run python transport_relay_interop.py --rust-binary ../../target/debug/rete-linux
"""

import time

from interop_helpers import InteropTest


def _py_node_script(
    tmpdir: str,
    port: int,
    node_label: str,
    send_msg: str,
    timeout: float,
    exclude_dest_hex: str,
) -> str:
    """Return the Python RNS node script text for a node that announces,
    discovers a peer, sends DATA, and waits for DATA."""
    return f"""\
import RNS
import time
import sys
import os
import threading

config_dir = os.path.join("{tmpdir}", "{node_label}_config")
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
    target_port = {port}
\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

# Dest hash to exclude (the transport relay node)
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
print(f"{node_label.upper()}_IDENTITY_HASH:{{identity.hexhash}}", flush=True)

# Announce
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

    # Send DATA to peer
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

    # Wait for DATA from peer
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
    with InteropTest("transport-relay", default_port=4260) as t:
        port1 = t.port
        port2 = t.port + 1

        # --- Start two rnsd instances ---
        t.start_rnsd(port=port1)
        t.start_rnsd(port=port2)

        # --- Start Rust transport node (connects to BOTH rnsd instances) ---
        rust = t.start_rust(
            port=port1,
            extra_args=[
                "--connect", f"127.0.0.1:{port2}",
                "--transport",
            ],
        )

        # --- Get the Rust transport node's dest hash so Python nodes can filter it ---
        rust_dest_hex = t.wait_for_line(rust, "IDENTITY:", timeout=10) or ""
        print(f"[transport-relay] Rust transport dest hash: {rust_dest_hex}")

        # Give Rust node time to connect and announce on both interfaces
        time.sleep(3)

        # --- Start Python nodes (connects to rnsd_1 and rnsd_2) ---
        # Start both simultaneously; they each announce and wait for the
        # other's announce to be relayed through Rust.
        py_a = t.start_py_helper(_py_node_script(
            t.tmpdir, port1, "node_a", "hello from A to B",
            t.timeout, rust_dest_hex,
        ))
        # Small stagger avoids rnsd race when two clients connect simultaneously
        time.sleep(1)
        py_b = t.start_py_helper(_py_node_script(
            t.tmpdir, port2, "node_b", "hello from B to A",
            t.timeout, rust_dest_hex,
        ))

        # Wait for both Python nodes to finish
        t.wait_for_line(py_a, "NODE_A_DONE", timeout=t.timeout + 15)
        t.wait_for_line(py_b, "NODE_B_DONE", timeout=t.timeout + 15)
        time.sleep(1)

        # Collect output
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Node A output", py_a)
        t.dump_output("Node B output", py_b)
        t.dump_output("Rust transport stdout", rust)
        t.dump_output("Rust transport stderr (last 800)", rust_stderr.strip().split("\n"))

        # --- Assertions ---

        # 1. Node B discovers Node A's announce (relayed through Rust)
        t.check(
            t.has_line(py_b, "NODE_B_PEER_FOUND"),
            "Node B discovered Node A via Rust relay",
        )

        # 2. Node A discovers Node B's announce (relayed through Rust)
        t.check(
            t.has_line(py_a, "NODE_A_PEER_FOUND"),
            "Node A discovered Node B via Rust relay",
        )

        # 3. Node A sends DATA to Node B -> received
        t.check(
            t.has_line(py_b, "NODE_B_DATA_RECEIVED:", contains="hello from A to B"),
            "Node A -> Node B DATA relayed through Rust",
        )

        # 4. Node B sends DATA to Node A -> received
        t.check(
            t.has_line(py_a, "NODE_A_DATA_RECEIVED:", contains="hello from B to A"),
            "Node B -> Node A DATA relayed through Rust",
        )


if __name__ == "__main__":
    main()
