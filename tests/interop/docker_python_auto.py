#!/usr/bin/env python3
"""Python AutoInterface node for Docker-based interop testing.

Runs inside a Docker container on a shared bridge network.
Starts RNS with AutoInterface, announces, discovers peers,
and prints structured output for the test orchestrator.

In Docker containers, binding to specific link-local or multicast
addresses fails with EADDRNOTAVAIL. We monkey-patch Python's socket
module to fall back to wildcard [::] binds, which works because each
container has its own network namespace (no port conflicts).

Usage (inside container):
  python3 docker_python_auto.py --group <group_id>
"""

import argparse
import os
import socket as _socket
import sys
import time

# Monkey-patch socket.socket.bind to fall back to [::] when specific
# IPv6 address binding fails (Docker container limitation).
_original_bind = _socket.socket.bind


def _docker_safe_bind(self, address):
    try:
        _original_bind(self, address)
    except OSError as e:
        if e.errno == 99 and self.family == _socket.AF_INET6:
            # EADDRNOTAVAIL — fall back to wildcard
            port = address[1] if isinstance(address, tuple) else 0
            _original_bind(self, ("::", port))
        else:
            raise


_socket.socket.bind = _docker_safe_bind

# Also enable SO_REUSEPORT on socketserver.UDPServer so data sockets
# can coexist with our wildcard-bound sockets.
import socketserver

socketserver.UDPServer.allow_reuse_address = True
socketserver.UDPServer.allow_reuse_port = True

import RNS


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--group", default="docker_autotest")
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()

    # Write AutoInterface config
    config_dir = "/tmp/rns_auto_config"
    os.makedirs(config_dir, exist_ok=True)
    with open(os.path.join(config_dir, "config"), "w") as f:
        f.write(f"""\
[reticulum]
  enable_transport = no
  share_instance = no

[logging]
  loglevel = 5

[interfaces]

  [[AutoInterface]]
    type = AutoInterface
    enabled = yes
    group_id = {args.group}
""")

    print("PY_STARTING", flush=True)
    reticulum = RNS.Reticulum(configdir=config_dir)

    identity = RNS.Identity()
    dest = RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        "rete",
        "example",
        "v1",
    )
    dest.announce()
    print(f"PY_IDENTITY:{identity.hexhash}", flush=True)
    print(f"PY_DEST_HASH:{dest.hexhash}", flush=True)
    print("PY_ANNOUNCE_SENT", flush=True)

    # Discover peers
    discovered = set()
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        for h in RNS.Transport.path_table:
            if h != dest.hash and h not in discovered:
                discovered.add(h)
                print(f"PY_DISCOVERED:{h.hex()}", flush=True)
        if discovered:
            break
        time.sleep(0.5)

    if discovered:
        print(f"PY_PEER_COUNT:{len(discovered)}", flush=True)
    else:
        print("PY_NO_PEERS_FOUND", flush=True)

    # Stay alive so Rust can also discover us via multicast
    # Python's AutoInterface re-announces periodically (~1.6s interval)
    time.sleep(15)
    print("PY_DONE", flush=True)


if __name__ == "__main__":
    main()
