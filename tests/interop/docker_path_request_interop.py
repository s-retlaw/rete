#!/usr/bin/env python3
"""Docker-isolated path request interop test.

Topology (Docker Compose):
  rnsd:            Python rnsd transport node
  rust-transport:  rete-linux --connect rnsd:4242 --transport
  python-a:        path_a_node.py (announces, then exits)
  python-c:        path_c_node.py (late-join, requests path to A)

Flow:
  1. rnsd + rust-transport + python-a start
  2. Python_A announces, Rust caches it
  3. python-c starts with A's dest hash, requests path
  4. rnsd (or Rust) responds with cached announce
  5. Python_A is stopped after Python_C has resolved the path

Note: Python_C starts while Python_A is still connected so that
rnsd's path table still has the entry.  Python RNS's table-culling
removes paths whose receiving interface has been torn down, and the
TCPServerInterface uses MODE_FULL which is not in DISCOVER_PATHS_FOR,
so rnsd will not forward an unknown-path request to Rust.

Assertions:
  1. Rust received Python_A's announce
  2. Python_C discovered Python_A via path request

Usage:
  cd tests/interop
  uv run python docker_path_request_interop.py
"""

import time

from docker_helpers import DockerTopologyTest


def main():
    with DockerTopologyTest("docker-path-request", "tcp-path-request.yml", timeout=60) as t:
        t.start()

        # Wait for Rust to initialize
        t.wait_for_line("rust-transport", "IDENTITY:", timeout=30)

        # Wait for Python_A to announce and report its dest hash
        a_dest_line = t.wait_for_line("python-a", "PY_A_DEST_HASH:", timeout=15)
        a_dest_hex = ""
        if a_dest_line:
            a_dest_hex = a_dest_line.split("PY_A_DEST_HASH:")[-1].strip()

        # Wait for Rust to receive the announce
        if a_dest_hex:
            t.wait_for_line("rust-transport", f"ANNOUNCE:{a_dest_hex}", timeout=15)

        # Start Python_C while Python_A is still connected, so rnsd's
        # path table still has the entry (avoids table-culling race).
        if a_dest_hex:
            t.up_service("python-c", env={"TARGET_HASH": a_dest_hex})
        else:
            t.check(False, "Could not get Python_A dest hash")
            return

        # Wait for Python_C to finish
        t.wait_for_line("python-c", "PY_C_DONE", timeout=30)
        time.sleep(1)

        # Now stop Python_A (it may have already exited on its own)
        t.stop_service("python-a")

        # --- Assertions ---
        t.check(
            t.has_line("rust-transport", f"ANNOUNCE:{a_dest_hex}"),
            "Rust received Python_A's announce",
        )

        t.check(
            t.has_line("python-c", "PY_C_PATH_FOUND"),
            "Python_C discovered Python_A via path request",
        )

        if t.failed > 0:
            t.dump_logs("rust-transport", "Rust transport")
            t.dump_logs("python-a", "Python A")
            t.dump_logs("python-c", "Python C")
            t.dump_logs("rnsd", "rnsd")


if __name__ == "__main__":
    main()
