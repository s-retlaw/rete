#!/usr/bin/env python3
"""S1-TCP-CTRL-001: Stock Python rnstatus queries rete-shared over TCP.

Topology:
  Rust daemon (rete-shared) in TCP shared mode
  + Python client that queries interface_stats via the TCP RPC control port

Usage:
  cargo build -p rete-daemon --bin rete-shared
  cd tests/interop
  uv run python shared_mode/tcp/control_status.py [--rust-binary PATH]
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Reuse the RPC helpers from the Unix test.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "unix"))
from control_status import derive_authkey, rpc_query_tcp

from shared_mode_helpers import SharedModeTest, parse_args

DATA_PORT = 49200 + (os.getpid() % 1000)
CTRL_PORT = DATA_PORT + 1


def main():
    args = parse_args()
    t = SharedModeTest("S1-TCP-CTRL-001", rust_binary=args.rust_binary)

    try:
        print(f"Starting rete-shared daemon (TCP mode, data={DATA_PORT}, ctrl={CTRL_PORT})...")
        t.start_daemon(instance_type="tcp", port=DATA_PORT, control_port=CTRL_PORT)
        time.sleep(0.3)

        # Derive authkey
        identity_path = os.path.join(t.data_dir, "identity")
        t.check(os.path.isfile(identity_path), "Identity file exists")
        authkey = derive_authkey(identity_path)

        # Query interface_stats via TCP control port
        print("Querying interface_stats via TCP control port...")
        response = rpc_query_tcp("127.0.0.1", CTRL_PORT, authkey, {"get": "interface_stats"})
        t.check(response is not None, "RPC query returned a response")

        if response:
            t.check("interfaces" in response, "Response has 'interfaces' key")
            t.check("rxb" in response, "Response has 'rxb' key")
            t.check("txb" in response, "Response has 'txb' key")
            t.check("rss" in response, "Response has 'rss' key")

            ifaces = response.get("interfaces", [])
            t.check(len(ifaces) >= 1, f"At least 1 interface (got {len(ifaces)})")

            if ifaces:
                iface = ifaces[0]
                name = iface.get("name", "")
                expected_name = f"Shared Instance[{DATA_PORT}]"
                t.check(
                    name == expected_name,
                    f"Interface name is '{expected_name}': got '{name}'",
                )
                t.check(
                    iface.get("type") == "LocalServerInterface",
                    f"Interface type is LocalServerInterface",
                )
                t.check(
                    iface.get("status") is True,
                    "Interface status is True",
                )

        # Test auth failure with wrong key
        print("Testing auth failure with wrong key...")
        bad_response = rpc_query_tcp("127.0.0.1", CTRL_PORT, b"wrong_key", {"get": "interface_stats"})
        t.check(bad_response is None, "Wrong key returns None (auth failed)")

    finally:
        t.finish()


if __name__ == "__main__":
    main()
