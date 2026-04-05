#!/usr/bin/env python3
"""S2-UNX-OPER-003: rnpath-style queries against rete-shared (Unix).

Topology:
  Rust daemon (rete-shared) in Unix shared mode
  + Python RNS client that announces, then queries next_hop, next_hop_if_name,
    first_hop_timeout via the RPC control socket.

Usage:
  cargo build -p rete-daemon --bin rete-shared
  cd tests/interop
  uv run python shared_mode/unix/rnpath_query.py [--rust-binary PATH]
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

from unix.control_status import rpc_query_raw, derive_authkey


def main():
    args = parse_args()
    t = SharedModeTest("S2-UNX-OPER-003", rust_binary=args.rust_binary)

    try:
        print("Starting rete-shared daemon (Unix mode)...")
        t.start_daemon(instance_type="unix")
        time.sleep(0.3)

        # Derive authkey
        identity_path = os.path.join(t.data_dir, "identity")
        authkey = derive_authkey(identity_path)

        # Attach a Python client that announces (runs for 5s, writes result at end)
        client_dir = t.make_client_dir("client_a")
        result_file = os.path.join(t.tmpdir, "client_a.json")
        client_proc = run_shared_client(
            CLIENT_ATTACH_SCRIPT,
            [client_dir, result_file, "testapp", "rnpath", "5"],
        )

        # Wait for client to finish (5s) + daemon to process
        wait_client(client_proc, timeout=15)
        time.sleep(3)  # extra time for daemon tick to process

        result = read_result(result_file)
        t.check(result is not None, "Client result file exists")
        if not result:
            t.finish()
            return

        dest_hash_hex = result.get("dest_hash", "")
        t.check(len(dest_hash_hex) == 32, f"dest_hash is 32 hex chars: {dest_hash_hex[:16]}...")
        dest_hash_bytes = bytes.fromhex(dest_hash_hex)

        sock_path = "\0rns/default/rpc"

        # 1. Query next_hop for the known destination (path persists after disconnect)
        print(f"Querying next_hop for known dest {dest_hash_hex[:8]}...")
        nh_response = rpc_query_raw(
            sock_path, authkey,
            {"get": "next_hop", "destination_hash": dest_hash_bytes},
        )
        # Direct path has no via, so next_hop is None
        t.check(
            nh_response is None or isinstance(nh_response, (bytes, type(None))),
            f"next_hop for known dest is None or bytes (got {type(nh_response).__name__})",
        )

        # 2. Query next_hop for an unknown destination
        unknown_hash = bytes(16)  # all zeros
        print("Querying next_hop for unknown dest...")
        nh_unknown = rpc_query_raw(
            sock_path, authkey,
            {"get": "next_hop", "destination_hash": unknown_hash},
        )
        t.check(
            nh_unknown is None,
            f"next_hop for unknown dest is None (got {type(nh_unknown).__name__}: {nh_unknown})",
        )

        # 3. Query next_hop_if_name for known destination
        print("Querying next_hop_if_name...")
        nhif_response = rpc_query_raw(
            sock_path, authkey,
            {"get": "next_hop_if_name", "destination_hash": dest_hash_bytes},
        )
        t.check(
            nhif_response is not None and isinstance(nhif_response, str),
            f"next_hop_if_name is a string (got {type(nhif_response).__name__})",
        )
        if isinstance(nhif_response, str):
            t.check(
                "Shared Instance" in nhif_response,
                f"Interface name contains 'Shared Instance': {nhif_response}",
            )

        # 4. Query first_hop_timeout for known destination
        print("Querying first_hop_timeout...")
        fht_response = rpc_query_raw(
            sock_path, authkey,
            {"get": "first_hop_timeout", "destination_hash": dest_hash_bytes},
        )
        t.check(
            fht_response is None or isinstance(fht_response, (int, float)),
            f"first_hop_timeout is numeric or None (got {type(fht_response).__name__}: {fht_response})",
        )

    finally:
        t.finish()


if __name__ == "__main__":
    main()
