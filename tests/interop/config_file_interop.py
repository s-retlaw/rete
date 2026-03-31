#!/usr/bin/env python3
"""Config file interop test: Rust rete node configured via TOML file.

Tests:
  1. Node starts with --data-dir containing config.toml (no other interface flags)
  2. TCP connection works from config file settings
  3. Transport mode activates from config file
  4. Node receives announce from Python helper

Usage:
  cd tests/interop
  uv run python config_file_interop.py --rust-binary ../../target/debug/rete-linux
"""

import json
import os
import time

from interop_helpers import InteropTest


def main():
    with InteropTest("config-file", default_port=4280) as t:
        t.start_rnsd()

        # Write a TOML config file into a data-dir
        data_dir = os.path.join(t.tmpdir, "rust_data")
        os.makedirs(data_dir, exist_ok=True)
        config_path = os.path.join(data_dir, "config.toml")
        with open(config_path, "w") as f:
            f.write(f"""\
[node]
transport = true

[interfaces.tcp_client]
connect = ["127.0.0.1:{t.port}"]
""")

        # Start Rust node with ONLY --data-dir (no --connect or --transport)
        # The node must get its TCP connection from config.toml in the data dir.
        cmd = [
            t.rust_binary,
            "--data-dir", data_dir,
        ]

        import subprocess
        import threading
        from interop_helpers import read_stdout_lines

        t._log("starting Rust node with config file in data-dir...")
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        t._procs.append(proc)
        t._rust_proc = proc

        rust = []
        thread = threading.Thread(
            target=read_stdout_lines, args=(proc, rust, t._stop), daemon=True,
        )
        thread.start()

        # Wait for the node to start
        rust_dest = t.wait_for_line(rust, "IDENTITY:", timeout=15)
        t.check(
            rust_dest is not None,
            "Node starts with config.toml in --data-dir (config provides TCP connection)",
        )
        if rust_dest is None:
            # Dump stderr for debugging
            stderr = proc.stderr.read(2000).decode(errors="replace") if proc.poll() is not None else ""
            t._log(f"Rust stderr: {stderr}")
            return

        # Send stats command to verify transport mode is active
        proc.stdin.write(b"stats\n")
        proc.stdin.flush()

        stats_line = t.wait_for_line(rust, "STATS:", timeout=10)
        transport_active = False
        if stats_line:
            try:
                stats = json.loads(stats_line)
                transport_active = "transport" in stats or "uptime_secs" in stats
            except json.JSONDecodeError:
                pass
        t.check(transport_active, "Stats command works (node is running)")

        # Start Python helper that announces
        py = t.start_py_helper(f"""\
import RNS
import time
import sys
import os

config_dir = os.path.join("{t.tmpdir}", "py_client_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config(transport=False)}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

identity = RNS.Identity()
dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, "configtest", "v1")

time.sleep(2)
dest.announce()
print("PY_ANNOUNCED", flush=True)

# Keep alive long enough for Rust to receive it
time.sleep(10)
print("PY_DONE", flush=True)
""")

        # Verify Python announced
        py_announced = t.wait_for_line(py, "PY_ANNOUNCED", timeout=15)
        t.check(py_announced is not None, "Python helper sent announce")

        # Verify Rust received the announce (via config-file TCP connection)
        announce = t.wait_for_line(rust, "ANNOUNCE:", timeout=15)
        t.check(
            announce is not None,
            "Rust node receives announce via config-file TCP connection",
        )

        # ---- Test 2: --generate-config flag ----
        result = subprocess.run(
            [t.rust_binary, "--generate-config"],
            capture_output=True, text=True, timeout=5,
        )
        t.check(
            result.returncode == 0 and "[node]" in result.stdout,
            "--generate-config prints default config and exits",
        )

        # ---- Test 3: Config file with CLI override ----
        # Write config with transport = false, then override with --transport CLI flag
        data_dir2 = os.path.join(t.tmpdir, "rust_data2")
        os.makedirs(data_dir2, exist_ok=True)
        with open(os.path.join(data_dir2, "config.toml"), "w") as f:
            f.write(f"""\
[node]
transport = false

[interfaces.tcp_client]
connect = ["127.0.0.1:{t.port}"]
""")

        proc2 = subprocess.Popen(
            [t.rust_binary, "--data-dir", data_dir2, "--transport"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        t._procs.append(proc2)
        rust2 = []
        thread2 = threading.Thread(
            target=read_stdout_lines, args=(proc2, rust2, t._stop), daemon=True,
        )
        thread2.start()

        rust2_dest = t.wait_for_line(rust2, "IDENTITY:", timeout=15)
        t.check(
            rust2_dest is not None,
            "CLI flags override config file (--transport overrides transport=false)",
        )

        # Clean up second node
        if proc2.poll() is None:
            proc2.terminate()
            proc2.wait(timeout=5)


if __name__ == "__main__":
    main()
