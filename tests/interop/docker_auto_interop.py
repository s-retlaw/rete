#!/usr/bin/env python3
"""Docker-isolated AutoInterface interop test.

Topology (Docker Compose):
  rust-node:   rete with --auto --auto-group docker_autotest
  python-node: Python RNS with AutoInterface (same group)
  Both on a shared IPv6-enabled Docker bridge network.

Each container gets its own link-local address, enabling real
multicast peer discovery without the same-host port conflicts
that force soft-skip in the subprocess-based auto_interop.py.

Assertions (hard-fail, no soft-skip):
  1. Rust AutoInterface initialized and announced
  2. Python discovered Rust via multicast
  3. Rust received Python's announce

Usage:
  cd tests/interop
  uv run python docker_auto_interop.py
"""

from docker_helpers import DockerTopologyTest


def main():
    with DockerTopologyTest("docker-auto", "auto-2node.yml", timeout=60) as t:
        t.start()

        # Wait for Rust node to initialize and announce
        identity_line = t.wait_for_line("rust-node", "IDENTITY:", timeout=30)
        t.check(identity_line is not None, "Rust node initialized and announced")

        rust_dest_hash = None
        if identity_line:
            rust_dest_hash = identity_line.split(":")[-1].strip()

        # Wait for Python to discover Rust via multicast
        discovered_line = t.wait_for_line("python-node", "PY_DISCOVERED:", timeout=30)
        t.check(discovered_line is not None, "Python discovered Rust via AutoInterface multicast")

        if discovered_line and rust_dest_hash:
            discovered_hash = discovered_line.split(":")[-1].strip()
            t.check(
                discovered_hash == rust_dest_hash,
                "Discovered hash matches Rust identity",
                detail=f"expected={rust_dest_hash} got={discovered_hash}"
                if discovered_hash != rust_dest_hash
                else None,
            )
        else:
            t.check(False, "Discovered hash matches Rust identity",
                    detail="missing identity or discovery line")

        # Wait for Rust to receive Python's announce (multicast may need time)
        rust_announce = t.wait_for_line("rust-node", "ANNOUNCE:", timeout=30)
        t.check(rust_announce is not None, "Rust received Python's announce via multicast")

        # Check Python completed successfully
        py_done = t.wait_for_line("python-node", "PY_DONE", timeout=15)
        t.check(py_done is not None, "Python node completed successfully")

        # Dump logs on failure for debugging
        if t.failed > 0:
            t.dump_logs("rust-node", "Rust node")
            t.dump_logs("python-node", "Python node")


if __name__ == "__main__":
    main()
