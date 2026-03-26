#!/usr/bin/env python3
"""Docker-isolated relay interop test.

Topology (Docker Compose):
  rnsd:        Python rnsd transport relay (TCP 0.0.0.0:4242)
  rust-node:   rete-linux --connect rnsd:4242 --auto-reply "hello from rust via relay"
  python-node: tcp_node.py --host rnsd --port 4242

All traffic between Python and Rust is relayed through rnsd.

Assertions:
  1. Python announce sent
  2. Rust received Python announce via relay
  3. Python discovered Rust announce via relay
  4. Python->Rust encrypted DATA sent via relay
  5. Rust received and decrypted DATA from Python via relay
  6. Rust->Python auto-reply received via relay

Usage:
  cd tests/interop
  uv run python docker_relay_interop.py
"""

import time

from docker_helpers import DockerTopologyTest


def main():
    with DockerTopologyTest("docker-relay", "tcp-3node.yml", timeout=60) as t:
        t.start(env={
            "RUST_ARGS": "--connect rnsd:4242 --auto-reply 'hello from rust via relay'",
            "PY_CMD": "/opt/tests/docker_py_helpers/tcp_node.py --host rnsd --port 4242 --send-msg 'hello from python via relay'",
        })

        # Wait for Rust node to initialize
        t.wait_for_line("rust-node", "IDENTITY:", timeout=30)

        # Wait for Python to finish
        t.wait_for_line("python-node", "PY_DONE", timeout=45)
        time.sleep(2)

        # --- Assertions ---
        t.check(
            t.has_line("python-node", "PY_ANNOUNCE_SENT"),
            "Python announce sent",
        )

        t.check(
            t.has_line("rust-node", "ANNOUNCE:"),
            "Rust received Python announce via relay",
        )

        t.check(
            t.has_line("python-node", "PY_INTEROP_OK"),
            "Python discovered Rust announce via relay",
        )

        t.check(
            t.has_line("python-node", "PY_DATA_SENT"),
            "Python->Rust encrypted DATA sent via relay",
        )

        t.check(
            t.has_line("rust-node", "DATA:"),
            "Rust received and decrypted DATA from Python via relay",
        )

        t.check(
            t.has_line("python-node", "PY_DATA_RECEIVED:"),
            "Rust->Python auto-reply received via relay",
        )

        if t.failed > 0:
            t.dump_logs("rust-node", "Rust node")
            t.dump_logs("python-node", "Python node")
            t.dump_logs("rnsd", "rnsd")


if __name__ == "__main__":
    main()
