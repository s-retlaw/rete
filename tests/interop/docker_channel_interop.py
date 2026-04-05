#!/usr/bin/env python3
"""Docker-isolated Channel interop test.

Topology (Docker Compose):
  rnsd:        Python rnsd transport node
  rust-node:   rete --connect rnsd:4242
  python-node: channel_node.py --host rnsd --port 4242

Assertions:
  1. Link established (both sides)
  2. Rust received first channel message (type=0x0100)
  3. Rust received second channel message (type=0x0200)
  4. Link teardown confirmed

Usage:
  cd tests/interop
  uv run python docker_channel_interop.py
"""

import time

from docker_helpers import DockerTopologyTest


def main():
    with DockerTopologyTest("docker-channel", "tcp-3node.yml", timeout=60) as t:
        t.start(env={
            "RUST_ARGS": "--connect rnsd:4242",
            "PY_CMD": "/opt/tests/docker_py_helpers/channel_node.py --host rnsd --port 4242",
        })

        t.wait_for_line("rust-node", "IDENTITY:", timeout=30)
        t.wait_for_line("python-node", "PY_DONE", timeout=45)
        time.sleep(2)

        t.check(
            t.has_line("rust-node", "LINK_ESTABLISHED:") and t.has_line("python-node", "PY_LINK_ACTIVE"),
            "Link established (both sides)",
        )

        t.check(
            t.has_line("rust-node", "CHANNEL_MSG:"),
            "Rust received first channel message (type=0x0100)",
        )

        # Check for second channel message
        channel_lines = [l for l in t.get_lines("rust-node") if "CHANNEL_MSG:" in l]
        t.check(
            len(channel_lines) >= 2,
            "Rust received second channel message (type=0x0200)",
            detail=f"Got {len(channel_lines)} channel messages" if len(channel_lines) < 2 else None,
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
