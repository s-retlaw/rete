#!/usr/bin/env python3
"""Docker-isolated live interop test.

Topology (Docker Compose):
  rnsd:        Python rnsd transport node (TCP server on 0.0.0.0:4242)
  rust-node:   rete --connect rnsd:4242 --auto-reply "hello from rust"
  python-node: tcp_node.py --host rnsd --port 4242

Each node runs in its own container on a shared Docker bridge network.

Assertions:
  1. Python announce sent
  2. Python discovered Rust announce
  3. Rust received Python announce
  4. Rust->Python DATA received by Python
  5. Python->Rust DATA received by Rust

Usage:
  cd tests/interop
  uv run python docker_live_interop.py
"""

from docker_helpers import DockerTopologyTest


def main():
    with DockerTopologyTest("docker-live", "tcp-3node.yml", timeout=60) as t:
        t.start(env={
            "RUST_ARGS": "--connect rnsd:4242 --auto-reply 'hello from rust'",
            "PY_CMD": "/opt/tests/docker_py_helpers/tcp_node.py --host rnsd --port 4242",
        })

        # Wait for Rust node to initialize
        identity_line = t.wait_for_line("rust-node", "IDENTITY:", timeout=30)
        t.check(identity_line is not None, "Rust node initialized")

        # Wait for Python to finish
        t.wait_for_line("python-node", "PY_DONE", timeout=45)

        # Give Rust time to process final packets
        import time
        time.sleep(2)

        # --- Assertions ---
        t.check(
            t.has_line("python-node", "PY_ANNOUNCE_SENT"),
            "Python announce sent",
        )

        t.check(
            t.has_line("python-node", "PY_INTEROP_OK"),
            "Python discovered Rust announce",
        )

        t.check(
            t.has_line("rust-node", "ANNOUNCE:"),
            "Rust received Python announce",
        )

        t.check(
            t.has_line("python-node", "PY_DATA_RECEIVED:"),
            "Rust->Python DATA received by Python (auto-reply)",
        )

        t.check(
            t.has_line("rust-node", "DATA:"),
            "Python->Rust DATA received by Rust",
        )

        if t.failed > 0:
            t.dump_logs("rust-node", "Rust node")
            t.dump_logs("python-node", "Python node")
            t.dump_logs("rnsd", "rnsd")


if __name__ == "__main__":
    main()
