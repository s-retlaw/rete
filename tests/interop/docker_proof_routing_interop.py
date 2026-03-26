#!/usr/bin/env python3
"""Docker-isolated proof routing interop test.

Topology (Docker Compose):
  rnsd-1:          Python rnsd transport node
  rnsd-2:          Python rnsd transport node
  rust-transport:  rete-linux --connect rnsd-1:4242 --connect rnsd-2:4242 --transport
  python-a:        proof_sender.py --host rnsd-1 (sends DATA, waits for proof)
  python-b:        proof_receiver.py --host rnsd-2 (PROVE_ALL, receives DATA)

Startup is staged: rnsd + Rust start first, then Python_A (sender) starts,
then Python_B (receiver with PROVE_ALL). Same ordering as subprocess test
to avoid announce race conditions.

Assertions:
  1. Python_B received DATA from Python_A (relayed through Rust)
  2. Python_A received delivery proof (routed back through Rust)

Usage:
  cd tests/interop
  uv run python docker_proof_routing_interop.py
"""

import time

from docker_helpers import DockerTopologyTest


def main():
    with DockerTopologyTest("docker-proof-routing", "tcp-5node-relay.yml", timeout=90) as t:
        # Stage 1: Start rnsd + Rust transport only
        t.start()

        # Get Rust transport dest hash
        identity_line = t.wait_for_line("rust-transport", "IDENTITY:", timeout=30)
        rust_dest_hex = ""
        if identity_line:
            rust_dest_hex = identity_line.split("IDENTITY:")[-1].strip()

        # Give Rust time to announce
        time.sleep(3)

        # Stage 2: Start Python_A (sender) first
        t.up_service("python-a", env={
            "PY_A_CMD": f"/opt/tests/docker_py_helpers/proof_sender.py --host rnsd-1 --port 4242 --timeout 45 --exclude-dest {rust_dest_hex}",
        })
        t.wait_for_line("python-a", "PY_A_READY", timeout=15)
        time.sleep(1)

        # Stage 3: Start Python_B (receiver with PROVE_ALL)
        t.up_service("python-b", env={
            "PY_B_CMD": "/opt/tests/docker_py_helpers/proof_receiver.py --host rnsd-2 --port 4242 --timeout 45",
        })

        # Wait for both to finish
        t.wait_for_line("python-a", "PY_A_DONE", timeout=75)
        t.wait_for_line("python-b", "PY_B_DONE", timeout=75)
        time.sleep(1)

        # --- Assertions ---
        t.check(
            t.has_line("python-b", "PY_B_DATA_RECEIVED:"),
            "Python_B received DATA via Rust relay",
        )

        t.check(
            t.has_line("python-a", "PY_A_PROOF_RECEIVED"),
            "Python_A received delivery proof via Rust relay",
            detail="proof timed out" if t.has_line("python-a", "PY_A_PROOF_TIMEOUT") else None,
        )

        if t.failed > 0:
            t.dump_logs("rust-transport", "Rust transport")
            t.dump_logs("python-a", "Python A (sender)")
            t.dump_logs("python-b", "Python B (receiver)")
            t.dump_logs("rnsd-1", "rnsd-1")
            t.dump_logs("rnsd-2", "rnsd-2")


if __name__ == "__main__":
    main()
