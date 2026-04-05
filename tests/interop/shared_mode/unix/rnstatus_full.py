#!/usr/bin/env python3
"""S2-UNX-OPER-002: Full rnstatus-style queries against rete-shared (Unix).

Topology:
  Rust daemon (rete-shared) in Unix shared mode
  + Python RNS client that announces, then queries interface_stats, path_table,
    link_count via the RPC control socket.

Usage:
  cargo build -p rete-daemon --bin rete-shared
  cd tests/interop
  uv run python shared_mode/unix/rnstatus_full.py [--rust-binary PATH]
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shared_mode_helpers import (
    SharedModeTest,
    parse_args,
    run_shared_client,
    wait_client,
    read_result,
    CLIENT_ATTACH_SCRIPT,
)

# Reuse RPC helpers from control_status.py
from unix.control_status import rpc_query_raw, derive_authkey


def main():
    args = parse_args()
    t = SharedModeTest("S2-UNX-OPER-002", rust_binary=args.rust_binary)

    try:
        print("Starting rete-shared daemon (Unix mode)...")
        t.start_daemon(instance_type="unix")
        time.sleep(0.3)

        # Derive authkey
        identity_path = os.path.join(t.data_dir, "identity")
        t.check(os.path.isfile(identity_path), "Identity file exists")
        authkey = derive_authkey(identity_path)

        # Attach a Python client that announces
        client_dir = t.make_client_dir("client_a")
        result_file = os.path.join(t.tmpdir, "client_a.json")
        client_proc = run_shared_client(
            CLIENT_ATTACH_SCRIPT,
            [client_dir, result_file, "testapp", "rnstatus", "20"],
        )

        # Wait for client to announce and daemon to process (client stays up 20s)
        time.sleep(8)

        sock_path = "\0rns/default/rpc"

        # 1. Query interface_stats — verify clients count
        print("Querying interface_stats...")
        response = rpc_query_raw(sock_path, authkey, {"get": "interface_stats"})
        t.check(response is not None, "interface_stats response received")

        if response:
            ifaces = response.get("interfaces", [])
            t.check(len(ifaces) >= 1, f"At least 1 interface (got {len(ifaces)})")
            if ifaces:
                clients = ifaces[0].get("clients", -1)
                t.check(clients >= 1, f"Interface reports clients >= 1 (got {clients})")

        # 2. Query path_table — verify non-empty after announce
        print("Querying path_table...")
        pt_response = rpc_query_raw(sock_path, authkey, {"get": "path_table"})
        t.check(pt_response is not None, "path_table response received")
        if pt_response is not None:
            t.check(
                isinstance(pt_response, dict),
                f"path_table is a dict (got {type(pt_response).__name__})",
            )
            t.check(
                len(pt_response) > 0,
                f"path_table has entries after announce (got {len(pt_response)})",
            )
            if pt_response:
                # Verify entries are keyed by bytes
                first_key = list(pt_response.keys())[0]
                t.check(
                    isinstance(first_key, bytes) and len(first_key) == 16,
                    f"path_table key is 16-byte dest_hash (got {type(first_key).__name__} len={len(first_key) if isinstance(first_key, bytes) else 'N/A'})",
                )

        # 3. Query link_count
        print("Querying link_count...")
        lc_response = rpc_query_raw(sock_path, authkey, {"get": "link_count"})
        t.check(lc_response is not None, "link_count response received")
        if lc_response is not None:
            t.check(
                isinstance(lc_response, int),
                f"link_count is int (got {type(lc_response).__name__}: {lc_response})",
            )

        # Clean up client
        wait_client(client_proc, timeout=10)

    finally:
        t.finish()


if __name__ == "__main__":
    main()
