#!/usr/bin/env python3
"""Docker-isolated transport relay interop test.

Topology (Docker Compose):
  rnsd-1:         Python rnsd transport node
  rnsd-2:         Python rnsd transport node
  rust-transport:  rete --connect rnsd-1:4242 --connect rnsd-2:4242 --transport
  python-a:       relay_node.py --host rnsd-1 (connected to subnet 1)
  python-b:       relay_node.py --host rnsd-2 (connected to subnet 2)

Rust bridges two isolated rnsd instances. Python_A and Python_B cannot
see each other except through the Rust transport relay.

Startup is staged: rnsd + Rust start first to get the Rust dest hash,
then Python nodes start with --exclude-dest to skip the transport relay.

Assertions:
  1. Node B discovered Node A via Rust relay
  2. Node A discovered Node B via Rust relay
  3. Node A -> Node B DATA relayed through Rust
  4. Node B -> Node A DATA relayed through Rust

Usage:
  cd tests/interop
  uv run python docker_transport_relay_interop.py
"""

import time

from docker_helpers import DockerTopologyTest


def main():
    with DockerTopologyTest("docker-transport-relay", "tcp-5node-relay.yml", timeout=90) as t:
        # Stage 1: Start rnsd instances and Rust transport only (Python nodes in "nodes" profile)
        t.start()

        # Get Rust transport dest hash
        identity_line = t.wait_for_line("rust-transport", "IDENTITY:", timeout=30)
        rust_dest_hex = ""
        if identity_line:
            rust_dest_hex = identity_line.split("IDENTITY:")[-1].strip()
        print(f"[docker-transport-relay] Rust transport dest hash: {rust_dest_hex}")

        # Give Rust time to announce on both interfaces
        time.sleep(3)

        # Stage 2: Start Python nodes with exclude-dest set
        t.up_service("python-a", env={
            "PY_A_CMD": f"/opt/tests/docker_py_helpers/relay_node.py --host rnsd-1 --port 4242 --label NODE_A --send-msg 'hello from A to B' --exclude-dest {rust_dest_hex}",
        })
        time.sleep(1)
        t.up_service("python-b", env={
            "PY_B_CMD": f"/opt/tests/docker_py_helpers/relay_node.py --host rnsd-2 --port 4242 --label NODE_B --send-msg 'hello from B to A' --exclude-dest {rust_dest_hex}",
        })

        # Wait for both Python nodes to finish
        t.wait_for_line("python-a", "NODE_A_DONE", timeout=75)
        t.wait_for_line("python-b", "NODE_B_DONE", timeout=75)
        time.sleep(2)

        # --- Assertions ---
        t.check(
            t.has_line("python-b", "NODE_B_PEER_FOUND"),
            "Node B discovered Node A via Rust relay",
        )

        t.check(
            t.has_line("python-a", "NODE_A_PEER_FOUND"),
            "Node A discovered Node B via Rust relay",
        )

        t.check(
            t.has_line("python-b", "NODE_B_DATA_RECEIVED:"),
            "Node A -> Node B DATA relayed through Rust",
        )

        t.check(
            t.has_line("python-a", "NODE_A_DATA_RECEIVED:"),
            "Node B -> Node A DATA relayed through Rust",
        )

        if t.failed > 0:
            t.dump_logs("rust-transport", "Rust transport")
            t.dump_logs("python-a", "Python A")
            t.dump_logs("python-b", "Python B")
            t.dump_logs("rnsd-1", "rnsd-1")
            t.dump_logs("rnsd-2", "rnsd-2")


if __name__ == "__main__":
    main()
