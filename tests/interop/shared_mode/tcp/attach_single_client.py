#!/usr/bin/env python3
"""S1-TCP-ATTACH-001: Single stock Python client attaches to rete-shared over TCP.

Topology:
  Rust daemon (rete-shared) in TCP shared mode
  + 1 stock Python RNS client with share_instance=Yes, shared_instance_port set

Usage:
  cargo build -p rete-daemon --bin rete-shared
  cd tests/interop
  uv run python shared_mode/tcp/attach_single_client.py [--rust-binary PATH]
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shared_mode_helpers import (
    SharedModeTest,
    CLIENT_ATTACH_SCRIPT,
    run_shared_client,
    wait_client,
    read_result,
    parse_args,
)

DEST_HASH_HEX_LEN = 32  # 16-byte hash, hex-encoded
PORT = 49000 + (os.getpid() % 1000)


def main():
    args = parse_args()
    t = SharedModeTest("S1-TCP-ATTACH-001", rust_binary=args.rust_binary)

    try:
        print(f"Starting rete-shared daemon (TCP mode, port {PORT})...")
        t.start_daemon(instance_type="tcp", port=PORT)

        client_dir = t.make_client_dir(
            "client1", mode="tcp", ports={"data_port": PORT}
        )
        result_file = os.path.join(t.tmpdir, "client1_result.json")

        print("Starting Python shared-mode client...")
        client_proc = run_shared_client(
            CLIENT_ATTACH_SCRIPT,
            [client_dir, result_file, "probe", "attach", "3"],
        )
        _, stderr = wait_client(client_proc, timeout=args.timeout)

        if client_proc.returncode != 0:
            print(f"  Client stderr: {stderr[-500:]}")

        t.check(client_proc.returncode == 0, "Client process exited cleanly")

        result = read_result(result_file)
        t.check(result is not None, "Client wrote result file")

        if result:
            t.check(result.get("attached") is True, "Client reports attached=True")
            t.check(
                result.get("attach_time", 999) < 5.0,
                f"Client attached in {result.get('attach_time', '?')}s (< 5s)",
            )
            t.check(
                len(result.get("dest_hash", "")) == DEST_HASH_HEX_LEN,
                f"Client has valid dest_hash: {result.get('dest_hash', '?')[:16]}...",
            )

        t.check(t.daemon_proc.poll() is None, "Daemon still alive after client detach")

    finally:
        t.finish()


if __name__ == "__main__":
    main()
