#!/usr/bin/env python3
"""Mixed-interface transport relay E2E test:
  Python_A <-TCP:portA-> rnsd <-TCP-> Rust_Transport <--listen:portB--> Python_B

Python_A connects to rnsd (simulating a remote node behind ESP32/LoRa).
Python_B connects DIRECTLY to the Rust daemon's --listen port (simulating
MeshChat connecting directly to the daemon).

This tests the exact topology that was reported as broken: announces
forwarded from the --connect interface to the --listen interface and
bidirectional DATA through a mixed Direct+Hub interface setup.

Assertions:
  1. Python_B discovers Python_A's announce (remote -> daemon -> direct client)
  2. Python_A discovers Python_B's announce (direct client -> daemon -> rnsd -> remote)
  3. Python_A sends DATA to Python_B -> received
  4. Python_B sends DATA to Python_A -> received

Usage:
  cd tests/interop
  uv run python mixed_relay_interop.py --rust-binary ../../target/debug/rete
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
    ingress_control = false
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

# Wait for peer announce (skip our own hash and the transport relay).
# Re-announce every 5 seconds in case the first announce arrived before
# the peer node connected.
timeout = {timeout}
deadline = time.time() + timeout
peer_dest_hash = None
last_announce = time.time()

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
    if time.time() - last_announce > 5:
        dest.announce()
        last_announce = time.time()
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
    with InteropTest("mixed-relay", default_port=4275) as t:
        port_rnsd = t.port       # rnsd (simulates ESP32/remote side)
        port_listen = t.port + 1  # Rust daemon's --listen (for MeshChat)

        # --- Start rnsd on port_rnsd (simulates ESP32/remote network) ---
        t.start_rnsd(port=port_rnsd)

        # --- Start Rust daemon: --connect to rnsd, --listen for direct clients ---
        # This creates: iface 0 = Direct(TCP to rnsd), iface 1 = Hub(TCP server)
        rust = t.start_rust(
            port=port_rnsd,
            extra_args=[
                "--listen", f"127.0.0.1:{port_listen}",
                "--transport",
            ],
        )

        # Get the Rust transport node's dest hash
        rust_dest_hex = t.wait_for_line(rust, "IDENTITY:", timeout=10) or ""
        print(f"[mixed-relay] Rust transport dest hash: {rust_dest_hex}")

        # Give Rust node time to connect and announce on both interfaces
        time.sleep(3)

        # --- Start Python nodes ---
        # Python_A connects to rnsd (remote side, like the LoRa/ESP32 network)
        py_a = t.start_py_helper(_py_node_script(
            t.tmpdir, port_rnsd, "node_a", "hello from remote to local",
            t.timeout, rust_dest_hex,
        ))
        time.sleep(1)
        # Python_B connects DIRECTLY to daemon's --listen port (like MeshChat)
        py_b = t.start_py_helper(_py_node_script(
            t.tmpdir, port_listen, "node_b", "hello from local to remote",
            t.timeout, rust_dest_hex,
        ))

        # Wait for both Python nodes to finish
        t.wait_for_line(py_a, "NODE_A_DONE", timeout=t.timeout + 15)
        t.wait_for_line(py_b, "NODE_B_DONE", timeout=t.timeout + 15)
        time.sleep(1)

        # Collect output
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Node A (remote) output", py_a)
        t.dump_output("Node B (local/MeshChat) output", py_b)
        t.dump_output("Rust transport stdout", rust)
        t.dump_output("Rust transport stderr (last 800)", rust_stderr.strip().split("\n"))

        # --- Assertions ---

        # 1. Node B (MeshChat) discovers Node A (remote) via daemon relay
        t.check(
            t.has_line(py_b, "NODE_B_PEER_FOUND"),
            "MeshChat discovered remote node via Rust relay (mixed interfaces)",
        )

        # 2. Node A (remote) discovers Node B (MeshChat) via daemon relay
        t.check(
            t.has_line(py_a, "NODE_A_PEER_FOUND"),
            "Remote node discovered MeshChat via Rust relay (mixed interfaces)",
        )

        # 3. Node A sends DATA to Node B -> received
        t.check(
            t.has_line(py_b, "NODE_B_DATA_RECEIVED:", contains="hello from remote to local"),
            "Remote -> MeshChat DATA relayed through Rust (mixed interfaces)",
        )

        # 4. Node B sends DATA to Node A -> received
        t.check(
            t.has_line(py_a, "NODE_A_DATA_RECEIVED:", contains="hello from local to remote"),
            "MeshChat -> Remote DATA relayed through Rust (mixed interfaces)",
        )


if __name__ == "__main__":
    main()
