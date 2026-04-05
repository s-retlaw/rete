#!/usr/bin/env python3
"""Shutdown interop test: graceful shutdown + snapshot save on SIGTERM.

Tests:
  1. Rust node shuts down cleanly on SIGTERM
  2. SHUTDOWN_COMPLETE marker appears in stdout
  3. Process exits with code 0
  4. Snapshot file is written to $HOME/.rete/snapshot.json
  5. Snapshot file contains valid JSON with path entries

Usage:
  cd tests/interop
  uv run python shutdown_interop.py --rust-binary ../../target/debug/rete
"""

import json
import os
import signal
import subprocess
import threading
import time

from interop_helpers import InteropTest, read_stdout_lines


def main():
    with InteropTest("shutdown-interop", default_port=4260) as t:
        t.start_rnsd()

        # Use a subdirectory of tmpdir as data-dir so snapshot goes to a known location
        rust_data_dir = os.path.join(t.tmpdir, "rust_data")
        os.makedirs(rust_data_dir, exist_ok=True)
        snapshot_path = os.path.join(rust_data_dir, "snapshot.json")

        cmd = [
            t.rust_binary,
            "--data-dir", rust_data_dir,
            "--connect", f"127.0.0.1:{t.port}",
        ]
        t._log("starting Rust node with --data-dir...")
        rust_proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        t._procs.append(rust_proc)
        t._rust_proc = rust_proc

        rust_lines = []
        stop = threading.Event()
        reader_thread = threading.Thread(
            target=read_stdout_lines,
            args=(rust_proc, rust_lines, stop),
            daemon=True,
        )
        reader_thread.start()

        # Wait for the Rust node to be ready (IDENTITY line)
        identity = t.wait_for_line(rust_lines, "IDENTITY:")
        t.check(identity is not None, "Rust node started and printed IDENTITY")

        # Start Python helper that announces so the Rust node learns a path
        py = t.start_py_helper(f"""\
import RNS
import time
import os

config_dir = os.path.join("{t.tmpdir}", "py_client_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config(transport=False)}\"\"\")

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
print("PY_ANNOUNCE_SENT", flush=True)
print(f"PY_DEST_HASH:{{dest.hexhash}}", flush=True)

# Keep alive long enough for Rust to receive the announce
time.sleep(10)
print("PY_DONE", flush=True)
""")

        # Wait for Rust to receive the announce
        announce = t.wait_for_line(rust_lines, "ANNOUNCE:")
        t.check(announce is not None, "Rust node received announce from Python")

        # Give a moment for the path to be fully registered
        time.sleep(1)

        # Send SIGTERM to the Rust process
        t._log("sending SIGTERM to Rust node...")
        os.kill(rust_proc.pid, signal.SIGTERM)

        # Wait for SHUTDOWN_COMPLETE in stdout
        shutdown_line = t.wait_for_line(rust_lines, "SHUTDOWN_COMPLETE", timeout=10)
        t.check(shutdown_line is not None, "SHUTDOWN_COMPLETE marker appeared in stdout")

        # Wait for the process to exit
        try:
            exit_code = rust_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            t._log("Rust process did not exit within 10s, killing...")
            rust_proc.kill()
            exit_code = rust_proc.wait()

        stop.set()

        t.check(exit_code == 0, f"Process exited cleanly (exit code {exit_code})")

        # Check snapshot file exists
        t.check(
            os.path.exists(snapshot_path),
            f"Snapshot file exists at {snapshot_path}",
        )

        # Check snapshot file contains valid JSON with path entries
        if os.path.exists(snapshot_path):
            try:
                with open(snapshot_path, "r") as f:
                    snap = json.load(f)
                t.check(
                    isinstance(snap, dict) and "paths" in snap,
                    "Snapshot file contains valid JSON with 'paths' key",
                )
                t.check(
                    len(snap.get("paths", [])) >= 1,
                    f"Snapshot contains at least 1 path entry (found {len(snap.get('paths', []))})",
                )
            except json.JSONDecodeError as e:
                t.check(False, f"Snapshot file contains valid JSON (parse error: {e})")
        else:
            t.check(False, "Snapshot file contains valid JSON (file missing)")
            t.check(False, "Snapshot contains at least 1 path entry (file missing)")

        # Dump output for diagnostics
        t.dump_output("Rust node stdout", rust_lines)


if __name__ == "__main__":
    main()
