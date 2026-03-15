#!/usr/bin/env python3
"""Path request E2E test: Rust transport node responds to path requests.

Topology:
  Python_A <-TCP:4246-> rnsd <-TCP-> Rust_Transport
  Python_C connects later and requests path to Python_A via Rust.

Flow:
  1. Start rnsd + Rust transport node
  2. Python_A connects, announces, then disconnects
  3. Python_C connects and calls request_path(A's dest hash)
  4. Rust should respond with the cached announce for A
  5. Python_C discovers A's path

Assertions:
  1. Rust received Python_A's announce
  2. Python_C discovers Python_A via path request (without seeing the original announce)

Usage:
  cd tests/interop
  uv run python path_request_interop.py
"""

import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time


def write_rnsd_config(config_dir: str, port: int) -> str:
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
    import socket
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.2)
    return False


def main():
    parser = argparse.ArgumentParser(description="rete path request E2E test")
    parser.add_argument(
        "--rust-binary",
        default="../../target/debug/rete-linux",
        help="Path to the rete-linux binary",
    )
    parser.add_argument("--port", type=int, default=4246)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    rust_binary = os.path.abspath(args.rust_binary)
    if not os.path.exists(rust_binary):
        print(f"[path-request] FAIL: Rust binary not found at {rust_binary}")
        sys.exit(1)

    tmpdir = tempfile.mkdtemp(prefix="rete_path_request_")
    procs = []
    passed = 0
    failed = 0

    try:
        # --- Start rnsd ---
        config_dir = os.path.join(tmpdir, "rnsd_config")
        write_rnsd_config(config_dir, args.port)
        print(f"[path-request] starting rnsd on port {args.port}...")
        rnsd_proc = subprocess.Popen(
            [sys.executable, "-m", "RNS.Utilities.rnsd", "--config", config_dir],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        procs.append(rnsd_proc)
        if not wait_for_port("127.0.0.1", args.port):
            print("[path-request] FAIL: rnsd did not start")
            sys.exit(1)
        print("[path-request] rnsd is listening")

        # --- Start Rust transport node ---
        print("[path-request] starting Rust transport node...")
        rust_proc = subprocess.Popen(
            [
                rust_binary,
                "--connect", f"127.0.0.1:{args.port}",
                "--transport",
                "--identity-seed", "path-request-e2e-seed",
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        procs.append(rust_proc)
        time.sleep(2)

        # --- Python_A: connect, announce, capture dest hash, disconnect ---
        py_a_script = os.path.join(tmpdir, "py_a.py")
        with open(py_a_script, "w") as f:
            f.write(f"""\
import RNS
import time
import os

config_dir = os.path.join("{tmpdir}", "py_a_config")
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
identity = RNS.Identity()
dest = RNS.Destination(
    identity, RNS.Destination.IN, RNS.Destination.SINGLE,
    "rete", "example", "v1",
)
dest.announce()
print(f"PY_A_DEST_HASH:{{dest.hexhash}}", flush=True)
# Keep alive long enough for Rust to receive and cache the announce
time.sleep(5)
print("PY_A_DONE", flush=True)
""")

        print("[path-request] starting Python_A (announcer)...")
        py_a_proc = subprocess.Popen(
            [sys.executable, py_a_script],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        procs.append(py_a_proc)

        # Wait for Python_A to finish
        try:
            py_a_stdout, _ = py_a_proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            py_a_proc.kill()
            py_a_stdout, _ = py_a_proc.communicate()

        py_a_output = py_a_stdout.decode(errors="replace")
        print("[path-request] Python_A output:")
        for line in py_a_output.strip().split("\n"):
            if line.strip():
                print(f"  {line}")

        # Extract Python_A's dest hash
        a_dest_hex = ""
        for line in py_a_output.split("\n"):
            if line.startswith("PY_A_DEST_HASH:"):
                a_dest_hex = line.split(":")[1].strip()
                break

        if not a_dest_hex:
            print("[path-request] FAIL: Could not get Python_A dest hash")
            sys.exit(1)
        print(f"[path-request] Python_A dest hash: {a_dest_hex}")

        # Check Rust received the announce
        time.sleep(2)

        # Get Rust transport dest hash for filtering
        rust_dest_hex = ""
        result = subprocess.run(
            [rust_binary, "--identity-seed", "path-request-e2e-seed",
             "--connect", "127.0.0.99:1"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stderr.split("\n"):
            if "destination hash:" in line:
                rust_dest_hex = line.strip().split("destination hash: ")[-1]
                break

        # --- Python_C: connect, request path, check discovery ---
        py_c_script = os.path.join(tmpdir, "py_c.py")
        with open(py_c_script, "w") as f:
            f.write(f"""\
import RNS
import time
import os

config_dir = os.path.join("{tmpdir}", "py_c_config")
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

# The dest hash we want to find
target_hex = "{a_dest_hex}"
target_hash = bytes.fromhex(target_hex)
exclude_hex = "{rust_dest_hex}"
exclude_hash = bytes.fromhex(exclude_hex) if exclude_hex else None

# First check: we should NOT have the path yet (Python_A already disconnected)
has_path_before = RNS.Transport.has_path(target_hash)
print(f"PY_C_HAS_PATH_BEFORE:{{has_path_before}}", flush=True)

# Request the path
print("PY_C_REQUESTING_PATH", flush=True)
RNS.Transport.request_path(target_hash)

# Wait for path to appear
deadline = time.time() + 15
found = False
while time.time() < deadline:
    if RNS.Transport.has_path(target_hash):
        found = True
        print("PY_C_PATH_FOUND", flush=True)
        break
    time.sleep(0.5)

if not found:
    print("PY_C_PATH_NOT_FOUND", flush=True)

time.sleep(1)
print("PY_C_DONE", flush=True)
""")

        print("[path-request] starting Python_C (path requester)...")
        py_c_proc = subprocess.Popen(
            [sys.executable, py_c_script],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        procs.append(py_c_proc)

        try:
            py_c_stdout, py_c_stderr = py_c_proc.communicate(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            py_c_proc.kill()
            py_c_stdout, py_c_stderr = py_c_proc.communicate()

        py_c_output = py_c_stdout.decode(errors="replace")
        print("[path-request] Python_C output:")
        for line in py_c_output.strip().split("\n"):
            if line.strip():
                print(f"  {line}")

        # Terminate Rust and collect output
        time.sleep(1)
        rust_proc.send_signal(signal.SIGTERM)
        try:
            rust_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            rust_proc.kill()
            rust_proc.wait()

        rust_stdout = rust_proc.stdout.read().decode(errors="replace")
        rust_stderr = rust_proc.stderr.read().decode(errors="replace")

        print("[path-request] Rust node stdout:")
        for line in rust_stdout.strip().split("\n"):
            if line.strip():
                print(f"  {line}")
        print("[path-request] Rust node stderr (last 500 chars):")
        for line in rust_stderr[-500:].strip().split("\n"):
            if line.strip():
                print(f"  {line}")

        # --- Assertions ---

        # 1. Rust received Python_A's announce
        if f"ANNOUNCE:{a_dest_hex}" in rust_stdout:
            print(f"[path-request] PASS [1/2]: Rust received Python_A's announce")
            passed += 1
        else:
            print(f"[path-request] FAIL [1/2]: Rust did not receive Python_A's announce")
            failed += 1

        # 2. Python_C discovered Python_A via path request
        if "PY_C_PATH_FOUND" in py_c_output:
            print("[path-request] PASS [2/2]: Python_C discovered Python_A via path request through Rust")
            passed += 1
        else:
            print("[path-request] FAIL [2/2]: Python_C did not discover Python_A via path request")
            if py_c_stderr:
                print(f"  Python_C stderr (last 300 chars): {py_c_stderr.decode(errors='replace')[-300:]}")
            failed += 1

    finally:
        print("[path-request] cleaning up...")
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

    total = passed + failed
    print(f"\n[path-request] Results: {passed}/{total} passed, {failed}/{total} failed")
    if failed > 0:
        sys.exit(1)
    else:
        print("[path-request] ALL TESTS PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
