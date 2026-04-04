#!/usr/bin/env python3
"""S1-UNX-ATTACH-002: Two stock Python clients attach to rete-shared over Unix.

Topology:
  Rust daemon (rete-shared) in Unix shared mode
  + 2 stock Python RNS clients with share_instance=Yes

Usage:
  cargo build -p rete-daemon --bin rete-shared
  cd tests/interop
  uv run python shared_mode/unix/attach_multi_client.py [--rust-binary PATH]
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shared_mode_helpers import (
    SharedModeTest,
    CLIENT_ATTACH_SCRIPT,
    run_shared_client,
    wait_client,
    read_result,
    parse_args,
)


def main():
    args = parse_args()
    t = SharedModeTest("S1-UNX-ATTACH-002", rust_binary=args.rust_binary)

    try:
        print("Starting rete-shared daemon (Unix mode)...")
        t.start_daemon()

        # --- Client A ---
        client_a_dir = t.make_client_dir("client_a")
        result_a_file = os.path.join(t.tmpdir, "client_a_result.json")

        print("Starting Python client A...")
        client_a_proc = run_shared_client(
            CLIENT_ATTACH_SCRIPT,
            [client_a_dir, result_a_file, "probe", "multi_a", "6"],
        )

        # Brief pause for client A to attach before starting B.
        time.sleep(1)

        # --- Client B ---
        client_b_dir = t.make_client_dir("client_b")
        result_b_file = os.path.join(t.tmpdir, "client_b_result.json")

        print("Starting Python client B...")
        client_b_proc = run_shared_client(
            CLIENT_ATTACH_SCRIPT,
            [client_b_dir, result_b_file, "probe", "multi_b", "5"],
        )

        _, stderr_b = wait_client(client_b_proc, timeout=args.timeout)
        _, stderr_a = wait_client(client_a_proc, timeout=args.timeout)

        if client_a_proc.returncode != 0:
            print(f"  Client A stderr: {stderr_a[-500:]}")
        if client_b_proc.returncode != 0:
            print(f"  Client B stderr: {stderr_b[-500:]}")

        t.check(client_a_proc.returncode == 0, "Client A exited cleanly")
        t.check(client_b_proc.returncode == 0, "Client B exited cleanly")

        result_a = read_result(result_a_file)
        result_b = read_result(result_b_file)

        t.check(result_a is not None, "Client A wrote result file")
        t.check(result_b is not None, "Client B wrote result file")

        if result_a:
            t.check(result_a.get("attached") is True, "Client A reports attached=True")
        if result_b:
            t.check(result_b.get("attached") is True, "Client B reports attached=True")

        if result_a and result_b:
            hash_a = result_a.get("dest_hash", "")
            hash_b = result_b.get("dest_hash", "")
            t.check(
                hash_a != hash_b and len(hash_a) == 32 and len(hash_b) == 32,
                f"Clients have unique dest hashes: {hash_a[:8]}... vs {hash_b[:8]}...",
            )

        t.check(t.daemon_proc.poll() is None, "Daemon still alive after both clients detach")

    finally:
        t.finish()


if __name__ == "__main__":
    main()
