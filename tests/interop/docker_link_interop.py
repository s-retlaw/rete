#!/usr/bin/env python3
"""Docker-isolated Link interop test.

Topology (Docker Compose):
  rnsd:        Python rnsd transport node
  rust-node:   rete-linux --connect rnsd:4242
  python-node: link_node.py --host rnsd --port 4242

Assertions:
  1. Python discovered Rust announce
  2. Link established (both sides)
  3. Rust received link data from Python
  4. Link teardown confirmed

Usage:
  cd tests/interop
  uv run python docker_link_interop.py
"""

import time

from docker_helpers import DockerTopologyTest


def main():
    with DockerTopologyTest("docker-link", "tcp-3node.yml", timeout=60) as t:
        t.start(env={
            "RUST_ARGS": "--connect rnsd:4242",
            "PY_CMD": "/opt/tests/docker_py_helpers/link_node.py --host rnsd --port 4242",
        })

        t.wait_for_line("rust-node", "IDENTITY:", timeout=30)
        t.wait_for_line("python-node", "PY_DONE", timeout=45)
        time.sleep(2)

        t.check(
            t.has_line("python-node", "PY_DISCOVERED:"),
            "Python discovered Rust announce",
        )

        rust_link_ok = t.has_line("rust-node", "LINK_ESTABLISHED:")
        py_link_ok = (t.has_line("python-node", "PY_LINK_ESTABLISHED:")
                      or t.has_line("python-node", "PY_LINK_ACTIVE")
                      or t.has_line("python-node", "PY_INBOUND_LINK_ESTABLISHED:"))
        t.check(
            rust_link_ok and py_link_ok,
            "Link established (both sides)",
            detail=f"Rust={rust_link_ok} Python={py_link_ok}",
        )

        t.check(
            t.has_line("rust-node", "LINK_DATA:"),
            "Rust received link data from Python",
        )

        t.check(
            t.has_line("rust-node", "LINK_CLOSED:"),
            "Link teardown confirmed",
        )

        if t.failed > 0:
            t.dump_logs("rust-node", "Rust node")
            t.dump_logs("python-node", "Python node")
            t.dump_logs("rnsd", "rnsd")


if __name__ == "__main__":
    main()
