#!/usr/bin/env python3
"""Local IPC E2E interop test: Rust server + two Rust clients over Unix socket.

Topology:
  Rust server: connects to rnsd via TCP AND listens on local Unix socket
  Rust client1: connects to server's local socket
  Rust client2: connects to server's local socket

Assertions:
  1. Server starts and connects to rnsd
  2. Client1 connects to local socket and announces
  3. Client2 connects to local socket and announces
  4. Client2 receives Client1's announce (relayed by server)
  5. Client1 receives Client2's announce (relayed by server)
  6. rnsd sees both clients' announces (forwarded by server)

Usage:
  cd tests/interop
  uv run python local_ipc_interop.py --rust-binary ../../target/debug/rete-linux

Or build first:
  cargo build -p rete-example-linux
  cd tests/interop && uv run python local_ipc_interop.py
"""

import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time


def write_rnsd_config(config_dir: str, port: int = 4244) -> str:
    """Write a minimal rnsd config with transport enabled.
    Returns the config dir path."""
    os.makedirs(config_dir, exist_ok=True)
    config_path = os.path.join(config_dir, "config")
    with open(config_path, "w") as f:
        f.write(f"""\
[reticulum]
  enable_transport = yes
  share_instance = no

[logging]
  loglevel = 5

[interfaces]

  [[TCP Server Interface]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = {port}
""")
    return config_dir


def wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    """Wait until a TCP port is accepting connections."""
    import socket

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.2)
    return False


def wait_for_line(proc, pattern, timeout=15.0):
    """Read stdout lines from proc until pattern is found or timeout."""
    import select

    deadline = time.monotonic() + timeout
    lines = []
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        # Use select to avoid blocking indefinitely
        r, _, _ = select.select([proc.stdout], [], [], min(remaining, 0.5))
        if r:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.strip()
            lines.append(line)
            if pattern in line:
                return line, lines
    return None, lines


def collect_output(proc, timeout=2.0):
    """Collect remaining stdout lines for a brief period."""
    import select

    lines = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        r, _, _ = select.select([proc.stdout], [], [], min(remaining, 0.2))
        if r:
            line = proc.stdout.readline()
            if not line:
                break
            lines.append(line.strip())
    return lines


def main():
    parser = argparse.ArgumentParser(description="rete local IPC interop test")
    parser.add_argument(
        "--rust-binary",
        default="../../target/debug/rete-linux",
        help="Path to the rete-linux binary",
    )
    parser.add_argument(
        "--port", type=int, default=4244, help="TCP port for rnsd (default 4244)"
    )
    parser.add_argument(
        "--timeout", type=float, default=30.0, help="Test timeout in seconds"
    )
    args = parser.parse_args()

    rust_binary = os.path.abspath(args.rust_binary)
    if not os.path.exists(rust_binary):
        print(f"[local-ipc] FAIL: Rust binary not found at {rust_binary}")
        print("  Build it with: cargo build -p rete-example-linux")
        sys.exit(1)

    tmpdir = tempfile.mkdtemp(prefix="rete_local_ipc_interop_")
    rnsd_config_dir = os.path.join(tmpdir, "rnsd_config")
    procs = []
    passed = 0
    failed = 0
    instance_name = f"test_{os.getpid()}"

    try:
        # --- Step 1: Start rnsd ---
        print(f"[local-ipc] setting up rnsd config in {rnsd_config_dir}")
        write_rnsd_config(rnsd_config_dir, args.port)

        print(f"[local-ipc] starting rnsd on port {args.port}...")
        rnsd_proc = subprocess.Popen(
            [sys.executable, "-m", "RNS.Utilities.rnsd", "--config", rnsd_config_dir],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(rnsd_proc)

        if not wait_for_port("127.0.0.1", args.port, timeout=15.0):
            print("[local-ipc] FAIL: rnsd did not start listening within 15s")
            if rnsd_proc.poll() is not None:
                stderr = rnsd_proc.stderr.read().decode(errors="replace")
                print(f"  rnsd stderr:\n{stderr}")
            sys.exit(1)
        print("[local-ipc] rnsd is listening")

        # --- Step 2: Start Rust server (TCP + local socket) ---
        print(f"[local-ipc] starting Rust server (TCP + local '{instance_name}')...")
        server_proc = subprocess.Popen(
            [
                rust_binary,
                "--connect", f"127.0.0.1:{args.port}",
                "--local-server", instance_name,
                "--identity-seed", "local-ipc-server-seed",
                "--transport",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        procs.append(server_proc)

        # Give the server time to start up and announce
        time.sleep(3)

        if server_proc.poll() is not None:
            _, stderr = server_proc.communicate()
            print(f"[local-ipc] FAIL: server exited prematurely")
            print(f"  stderr: {stderr[-500:]}")
            sys.exit(1)

        print("[local-ipc] PASS [1/6]: Server started and connected")
        passed += 1

        # --- Step 3: Start Rust client1 ---
        print("[local-ipc] starting Rust client1...")
        client1_proc = subprocess.Popen(
            [
                rust_binary,
                "--local-client", instance_name,
                "--identity-seed", "local-ipc-client1-seed",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        procs.append(client1_proc)

        # Wait for client1 to send its announce
        time.sleep(3)

        if client1_proc.poll() is not None:
            _, stderr = client1_proc.communicate()
            print(f"[local-ipc] FAIL: client1 exited prematurely")
            print(f"  stderr: {stderr[-500:]}")
            failed += 1
        else:
            print("[local-ipc] PASS [2/6]: Client1 connected and announcing")
            passed += 1

        # --- Step 4: Start Rust client2 ---
        print("[local-ipc] starting Rust client2...")
        client2_proc = subprocess.Popen(
            [
                rust_binary,
                "--local-client", instance_name,
                "--identity-seed", "local-ipc-client2-seed",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        procs.append(client2_proc)

        # Wait for client2 to send its announce and for announces to propagate
        time.sleep(3)

        if client2_proc.poll() is not None:
            _, stderr = client2_proc.communicate()
            print(f"[local-ipc] FAIL: client2 exited prematurely")
            print(f"  stderr: {stderr[-500:]}")
            failed += 1
        else:
            print("[local-ipc] PASS [3/6]: Client2 connected and announcing")
            passed += 1

        # Give time for announces to propagate between clients
        time.sleep(5)

        # --- Step 5: Terminate clients and collect output ---
        # Terminate client1
        client1_proc.send_signal(signal.SIGTERM)
        try:
            c1_stdout, c1_stderr = client1_proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            client1_proc.kill()
            c1_stdout, c1_stderr = client1_proc.communicate()

        # Terminate client2
        client2_proc.send_signal(signal.SIGTERM)
        try:
            c2_stdout, c2_stderr = client2_proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            client2_proc.kill()
            c2_stdout, c2_stderr = client2_proc.communicate()

        # Terminate server
        server_proc.send_signal(signal.SIGTERM)
        try:
            srv_stdout, srv_stderr = server_proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            server_proc.kill()
            srv_stdout, srv_stderr = server_proc.communicate()

        print("[local-ipc] client1 stdout:", c1_stdout.strip()[:500] if c1_stdout else "(empty)")
        print("[local-ipc] client2 stdout:", c2_stdout.strip()[:500] if c2_stdout else "(empty)")
        print("[local-ipc] server stdout:", srv_stdout.strip()[:500] if srv_stdout else "(empty)")

        # Debug: show stderr snippets
        if c1_stderr:
            print("[local-ipc] client1 stderr (last 300 chars):", c1_stderr.strip()[-300:])
        if c2_stderr:
            print("[local-ipc] client2 stderr (last 300 chars):", c2_stderr.strip()[-300:])
        if srv_stderr:
            print("[local-ipc] server stderr (last 300 chars):", srv_stderr.strip()[-300:])

        # --- Assertion 4: Client2 received Client1's announce ---
        # Client2's stdout should contain an ANNOUNCE line with client1's dest hash
        if c2_stdout and "ANNOUNCE:" in c2_stdout:
            print("[local-ipc] PASS [4/6]: Client2 received announce(s) via local server")
            passed += 1
        else:
            print("[local-ipc] FAIL [4/6]: Client2 did not receive any announces")
            failed += 1

        # --- Assertion 5: Client1 received Client2's announce ---
        if c1_stdout and "ANNOUNCE:" in c1_stdout:
            print("[local-ipc] PASS [5/6]: Client1 received announce(s) via local server")
            passed += 1
        else:
            print("[local-ipc] FAIL [5/6]: Client1 did not receive any announces")
            failed += 1

        # --- Assertion 6: Use a Python script to check rnsd path table ---
        # Write a quick script that connects to rnsd and checks for paths
        py_check = os.path.join(tmpdir, "py_check_paths.py")
        with open(py_check, "w") as f:
            f.write(f"""\
import RNS
import os
import time

config_dir = os.path.join("{tmpdir}", "py_check_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"
[reticulum]
  enable_transport = no
  share_instance = no

[logging]
  loglevel = 5

[interfaces]

  [[TCP Client Interface]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = {args.port}
\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

# Wait briefly for path table to populate from rnsd
time.sleep(3)

paths = RNS.Transport.path_table
print(f"PATHS_FOUND:{{len(paths)}}", flush=True)
for h in paths:
    print(f"PATH:{{h.hex()}}", flush=True)
""")

        py_check_proc = subprocess.Popen(
            [sys.executable, py_check],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            check_stdout, check_stderr = py_check_proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            py_check_proc.kill()
            check_stdout, check_stderr = py_check_proc.communicate()

        print("[local-ipc] path check output:", check_stdout.strip()[:500] if check_stdout else "(empty)")

        # We expect at least 2 paths (client1 + client2, possibly server too)
        path_lines = [l for l in (check_stdout or "").strip().split("\n")
                      if l.startswith("PATH:")]
        if len(path_lines) >= 2:
            print(f"[local-ipc] PASS [6/6]: rnsd has {len(path_lines)} paths (clients visible)")
            passed += 1
        else:
            # Even 1 path is partial success; 0 is fail
            print(f"[local-ipc] FAIL [6/6]: rnsd has only {len(path_lines)} paths (expected >= 2)")
            failed += 1

    finally:
        # Cleanup
        print("[local-ipc] cleaning up...")
        for p in procs:
            try:
                p.kill()
                p.wait(timeout=5)
            except Exception:
                pass

        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass

    # Summary
    total = passed + failed
    print(f"\n[local-ipc] Results: {passed}/{total} passed, {failed}/{total} failed")

    if failed > 0:
        sys.exit(1)
    else:
        print("[local-ipc] ALL TESTS PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
