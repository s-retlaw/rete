#!/usr/bin/env python3
"""S2-TCP-OPER-003: rnpath-style queries against rete-shared (TCP).

Topology:
  Rust daemon (rete-shared) in TCP shared mode
  + Python RNS client that announces, then queries next_hop, next_hop_if_name,
    first_hop_timeout via the TCP RPC control port.

Usage:
  cargo build -p rete-daemon --bin rete-shared
  cd tests/interop
  uv run python shared_mode/tcp/rnpath_query.py [--rust-binary PATH]
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

from unix.control_status import rpc_query_tcp, derive_authkey


DATA_PORT = 47430
CTRL_PORT = 47431


def main():
    args = parse_args()
    t = SharedModeTest("S2-TCP-OPER-003", rust_binary=args.rust_binary)

    try:
        print("Starting rete-shared daemon (TCP mode)...")
        t.start_daemon(
            instance_type="tcp",
            port=DATA_PORT,
            control_port=CTRL_PORT,
        )
        time.sleep(0.3)

        # Derive authkey
        identity_path = os.path.join(t.data_dir, "identity")
        authkey = derive_authkey(identity_path)

        # Attach a Python client that announces
        client_dir = t.make_client_dir(
            "client_a", mode="tcp",
            ports={"data_port": DATA_PORT, "ctrl_port": CTRL_PORT},
        )
        result_file = os.path.join(t.tmpdir, "client_a.json")
        client_proc = run_shared_client(
            CLIENT_ATTACH_SCRIPT,
            [client_dir, result_file, "testapp", "rnpath", "5"],
        )

        # Wait for client to finish (5s) + daemon to process
        wait_client(client_proc, timeout=15)
        time.sleep(3)

        result = read_result(result_file)
        t.check(result is not None, "Client result file exists")
        if not result:
            t.finish()
            return

        dest_hash_hex = result.get("dest_hash", "")
        t.check(len(dest_hash_hex) == 32, f"dest_hash is 32 hex chars: {dest_hash_hex[:16]}...")
        dest_hash_bytes = bytes.fromhex(dest_hash_hex)

        # 1. Query next_hop for known destination
        print(f"Querying next_hop for known dest {dest_hash_hex[:8]}...")
        nh_response = rpc_query_tcp(
            "127.0.0.1", CTRL_PORT, authkey,
            {"get": "next_hop", "destination_hash": dest_hash_bytes},
        )
        t.check(
            nh_response is None or isinstance(nh_response, (bytes, type(None))),
            f"next_hop is None or bytes (got {type(nh_response).__name__})",
        )

        # 2. Query next_hop for unknown destination
        unknown_hash = bytes(16)
        nh_unknown = rpc_query_tcp(
            "127.0.0.1", CTRL_PORT, authkey,
            {"get": "next_hop", "destination_hash": unknown_hash},
        )
        t.check(nh_unknown is None, f"next_hop for unknown is None (got {nh_unknown})")

        # 3. Query next_hop_if_name for known destination
        nhif_response = rpc_query_tcp(
            "127.0.0.1", CTRL_PORT, authkey,
            {"get": "next_hop_if_name", "destination_hash": dest_hash_bytes},
        )
        t.check(
            isinstance(nhif_response, str),
            f"next_hop_if_name is string (got {type(nhif_response).__name__})",
        )

        # 4. Query first_hop_timeout for known destination
        fht_response = rpc_query_tcp(
            "127.0.0.1", CTRL_PORT, authkey,
            {"get": "first_hop_timeout", "destination_hash": dest_hash_bytes},
        )
        t.check(
            fht_response is None or isinstance(fht_response, (int, float)),
            f"first_hop_timeout is numeric or None (got {type(fht_response).__name__})",
        )

    finally:
        t.finish()


if __name__ == "__main__":
    main()
