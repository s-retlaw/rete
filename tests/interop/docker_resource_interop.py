#!/usr/bin/env python3
"""Docker-isolated Resource interop test.

Topology (Docker Compose):
  rnsd:        Python rnsd transport node
  rust-node:   rete --connect rnsd:4242 (stdin_open for resource commands)
  python-node: resource_node.py --host rnsd --port 4242

Assertions:
  1. Link established (both sides)
  2. Rust received RESOURCE_OFFERED from Python
  3. Rust received RESOURCE_COMPLETE with matching data
  4. Rust->Python with ACCEPT_ALL -- Python received resource
  5. Rust->Python with ACCEPT_APP -- callback invoked and resource received

Usage:
  cd tests/interop
  uv run python docker_resource_interop.py
"""

import time

from docker_helpers import DockerTopologyTest


def main():
    with DockerTopologyTest("docker-resource", "tcp-3node.yml", timeout=180) as t:
        t.start(env={
            "RUST_ARGS": "--connect rnsd:4242",
            "PY_CMD": "/opt/tests/docker_py_helpers/resource_node.py --host rnsd --port 4242 --timeout 120",
        })

        # Wait for link establishment
        t.wait_for_line("rust-node", "LINK_ESTABLISHED:", timeout=45)
        t.wait_for_line("python-node", "PY_LINK_ACTIVE", timeout=45)

        # Wait for Python to send its resource and Rust to receive it
        t.wait_for_line("rust-node", "RESOURCE_COMPLETE:", timeout=60)

        # Get Rust link_id for stdin commands
        rust_link_id = None
        for line in t.get_lines("rust-node"):
            if "LINK_ESTABLISHED:" in line:
                parts = line.split("LINK_ESTABLISHED:")
                if len(parts) >= 2:
                    rust_link_id = parts[-1].strip()
                    break

        # Phase 1: Send ACCEPT_ALL resource from Rust
        sent_accept_all = False
        if rust_link_id:
            t.wait_for_line("python-node", "PY_READY_ACCEPT_ALL", timeout=30)
            cmd = f"resource {rust_link_id} hello_accept_all"
            print(f"[docker-resource] sending ACCEPT_ALL resource: {cmd}")
            t.send_to_stdin("rust-node", cmd)
            sent_accept_all = True

        # Wait for Python to receive accept_all resource
        if sent_accept_all:
            t.wait_for_line("python-node", "PY_RUST_RESOURCE_RECEIVED_ACCEPT_ALL", timeout=60)

        # Phase 2: Send ACCEPT_APP resource from Rust
        sent_accept_app = False
        if rust_link_id and sent_accept_all:
            t.wait_for_line("python-node", "PY_READY_ACCEPT_APP", timeout=30)
            cmd = f"resource {rust_link_id} hello_accept_app"
            print(f"[docker-resource] sending ACCEPT_APP resource: {cmd}")
            t.send_to_stdin("rust-node", cmd)
            sent_accept_app = True

        # Wait for Python to finish
        t.wait_for_line("python-node", "PY_DONE", timeout=60)
        time.sleep(2)

        # --- Assertions ---
        rust_link_ok = t.has_line("rust-node", "LINK_ESTABLISHED:")
        py_link_ok = t.has_line("python-node", "PY_LINK_ACTIVE")
        t.check(
            rust_link_ok and py_link_ok,
            "Link established (both sides)",
            detail=f"Rust={rust_link_ok} Python={py_link_ok}",
        )

        t.check(
            t.has_line("rust-node", "RESOURCE_OFFERED:"),
            "Rust received RESOURCE_OFFERED from Python",
        )

        t.check(
            t.has_line("rust-node", "RESOURCE_COMPLETE:"),
            "Rust received RESOURCE_COMPLETE with matching data",
        )

        if not sent_accept_all:
            t.check(False, "Rust->Python with ACCEPT_ALL",
                    detail="Could not send resource (no link_id)")
        else:
            t.check(
                t.has_line("python-node", "PY_RUST_RESOURCE_RECEIVED_ACCEPT_ALL"),
                "Rust->Python with ACCEPT_ALL -- Python received resource",
            )

        if not sent_accept_app:
            t.check(False, "Rust->Python with ACCEPT_APP",
                    detail="Could not send resource")
        else:
            t.check(
                t.has_line("python-node", "PY_RUST_RESOURCE_RECEIVED_ACCEPT_APP")
                and t.has_line("python-node", "PY_ADV_CALLBACK:"),
                "Rust->Python with ACCEPT_APP -- callback invoked and resource received",
            )

        if t.failed > 0:
            t.dump_logs("rust-node", "Rust node")
            t.dump_logs("python-node", "Python node")
            t.dump_logs("rnsd", "rnsd")


if __name__ == "__main__":
    main()
