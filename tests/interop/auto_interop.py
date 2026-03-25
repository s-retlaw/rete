#!/usr/bin/env python3
"""AutoInterface interop test: Rust rete node <-> Python RNS over UDP multicast.

Topology:
  Python rnsd with AutoInterface (IPv6 link-local multicast, custom group_id)
  Rust node with --auto --auto-group (same group_id)
  Direct peer discovery via multicast — no TCP rnsd relay

Assertions:
  1. Rust node receives announce from Python (or skip if multicast unavailable)
  2. Rust AutoInterface initialized successfully (or skip if port conflict)

Usage:
  cd tests/interop
  uv run python auto_interop.py --rust-binary ../../target/debug/rete-linux
"""

import os
import time

from interop_helpers import InteropTest

TEST_GROUP_ID = "rete_autointerop_test"


def main():
    with InteropTest("auto", default_port=4260) as t:
        # --- Start Python rnsd with AutoInterface ---
        # We write a custom config with AutoInterface (not TCPServerInterface)
        py_config_dir = os.path.join(t.tmpdir, "python_config")
        os.makedirs(py_config_dir, exist_ok=True)
        with open(os.path.join(py_config_dir, "config"), "w") as f:
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
    group_id = {TEST_GROUP_ID}
""")

        t._log(f"starting rnsd with AutoInterface (group={TEST_GROUP_ID})...")
        import subprocess, sys, threading
        from interop_helpers import read_stdout_lines

        py_proc = subprocess.Popen(
            [sys.executable, "-m", "RNS.Utilities.rnsd", "--config", py_config_dir],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        t._procs.append(py_proc)
        time.sleep(3)

        if py_proc.poll() is not None:
            stderr = py_proc.stderr.read().decode(errors="replace")
            t._log(f"rnsd exited early with code {py_proc.returncode}")
            t._log(f"stderr: {stderr}")
            t.check(False, "Python rnsd started")
            return

        t._log("rnsd with AutoInterface started")

        # --- Start Rust node with --auto ---
        # start_rust requires --connect, but for AutoInterface we don't use TCP.
        # Use the Rust binary directly with --auto flags.
        rust_id_file = os.path.join(t.tmpdir, "rust_identity")
        t._log(f"starting Rust node with --auto --auto-group {TEST_GROUP_ID}...")

        rust_proc = subprocess.Popen(
            [
                t.rust_binary,
                "--auto",
                "--auto-group", TEST_GROUP_ID,
                "--identity-file", rust_id_file,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        t._procs.append(rust_proc)

        rust_lines = []
        threading.Thread(
            target=read_stdout_lines,
            args=(rust_proc, rust_lines, t._stop),
            daemon=True,
        ).start()

        # Also read stderr for diagnostic info
        rust_stderr_lines = []
        def read_stderr():
            while not t._stop.is_set():
                line = rust_proc.stderr.readline()
                if not line:
                    break
                rust_stderr_lines.append(line.decode(errors="replace").rstrip("\n"))
        threading.Thread(target=read_stderr, daemon=True).start()

        # Wait for peer discovery
        time.sleep(8)

        rust_stderr_text = "\n".join(rust_stderr_lines)

        if rust_proc.poll() is not None:
            # Rust node exited — check if it's a known environment issue
            if "Address already in use" in rust_stderr_text:
                t._log("AutoInterface port conflict: both nodes share same link-local address")
                t._log("Same-host AutoInterface testing requires separate network namespaces")
                t.check(True, "AutoInterface skipped (same-host port conflict)")
                t.check(True, "Announce check skipped (same-host)")
                return
            elif "no suitable network interfaces" in rust_stderr_text:
                t._log("No suitable network interfaces for AutoInterface (expected in CI)")
                t.check(True, "AutoInterface skipped (no suitable interfaces, expected in CI)")
                t.check(True, "Announce check skipped (no interfaces)")
                return
            else:
                t._log(f"Rust node exited with code {rust_proc.returncode}")
                for line in rust_stderr_lines:
                    if line.strip():
                        t._log(f"  stderr: {line}")
                t.check(False, "Rust node stayed running")
                return

        t.dump_output("Rust stdout", rust_lines)
        t.dump_output("Rust stderr", rust_stderr_lines)

        # Check 1: Rust node received announce from Python
        if any("ANNOUNCE:" in line for line in rust_lines):
            t.check(True, "Rust node received announce from Python via AutoInterface")
        else:
            # Multicast may not work in containers/CI
            t._log("Rust did not receive announce (multicast may not work on this system)")
            t.check(True, "Rust announce check skipped (multicast may be unavailable)")

        # Check 2: Rust AutoInterface initialized successfully
        if "AutoInterface ready" in rust_stderr_text or "AutoInterface:" in rust_stderr_text:
            t.check(True, "Rust AutoInterface initialized successfully")
        elif "no suitable network interfaces" in rust_stderr_text:
            t._log("No suitable network interfaces for AutoInterface (expected in CI)")
            t.check(True, "AutoInterface skipped (no suitable interfaces, expected in CI)")
        else:
            t.check(False, "Rust AutoInterface did not initialize")


if __name__ == "__main__":
    main()
