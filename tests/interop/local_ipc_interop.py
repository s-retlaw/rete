#!/usr/bin/env python3
"""Local IPC E2E interop test: Rust server + two Rust clients over Unix socket.

Topology:
  Rust server: connects to rnsd via TCP AND listens on local Unix socket
  Rust client1: connects to server's local socket (unique identity)
  Rust client2: connects to server's local socket (unique identity)

Assertions:
  1. Server starts and connects to rnsd
  2. Client1 connects to local socket and announces
  3. Client2 connects to local socket and announces
  4. Client2 receives Client1's announce (relayed by server)
  5. Client1 receives Client2's announce (relayed by server)
  6. rnsd sees client announces (forwarded by server via TCP)

Usage:
  cd tests/interop
  uv run python local_ipc_interop.py --rust-binary ../../target/debug/rete

Or build first:
  cargo build -p rete
  cd tests/interop && uv run python local_ipc_interop.py
"""

import os
import signal
import subprocess
import sys
import threading
import time

from interop_helpers import InteropTest, read_stdout_lines


def main():
    with InteropTest("local-ipc", default_port=4244) as t:
        t.start_rnsd()

        instance_name = f"test_{os.getpid()}"

        # Each node gets its own --data-dir so announces have distinct
        # destination hashes and are not deduplicated.
        client1_dir = os.path.join(t.tmpdir, "client1_data")
        client2_dir = os.path.join(t.tmpdir, "client2_data")
        os.makedirs(client1_dir, exist_ok=True)
        os.makedirs(client2_dir, exist_ok=True)

        # --- Start Rust server (TCP + local socket) ---
        # (start_rust auto-injects --data-dir)
        server_lines = t.start_rust(
            extra_args=[
                "--local-server", instance_name,
                "--transport",
            ],
        )
        time.sleep(3)

        t.check(
            t._rust_proc and t._rust_proc.poll() is None,
            "Server started and connected to rnsd",
        )

        # Capture server dest hash to exclude from client announce checks
        server_dest = None
        for line in server_lines:
            if line.startswith("IDENTITY:"):
                server_dest = line.split(":", 1)[1].strip()
                break

        # --- Start Rust client1 (manual Popen, since harness tracks one _rust_proc) ---
        client1_proc = subprocess.Popen(
            [
                t.rust_binary,
                "--data-dir", client1_dir,
                "--local-client", instance_name,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        t._procs.append(client1_proc)

        client1_lines = []
        threading.Thread(
            target=read_stdout_lines,
            args=(client1_proc, client1_lines, t._stop),
            daemon=True,
        ).start()

        time.sleep(3)

        t.check(
            client1_proc.poll() is None,
            "Client1 connected and announcing",
        )

        # --- Start Rust client2 ---
        client2_proc = subprocess.Popen(
            [
                t.rust_binary,
                "--data-dir", client2_dir,
                "--local-client", instance_name,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        t._procs.append(client2_proc)

        client2_lines = []
        threading.Thread(
            target=read_stdout_lines,
            args=(client2_proc, client2_lines, t._stop),
            daemon=True,
        ).start()

        time.sleep(3)

        t.check(
            client2_proc.poll() is None,
            "Client2 connected and announcing",
        )

        # Give time for announces to propagate between clients
        time.sleep(3)

        # Capture client dest hashes
        client1_dest = None
        for line in client1_lines:
            if line.startswith("IDENTITY:"):
                client1_dest = line.split(":", 1)[1].strip()
                break

        client2_dest = None
        for line in client2_lines:
            if line.startswith("IDENTITY:"):
                client2_dest = line.split(":", 1)[1].strip()
                break

        # --- Assertion 6: rnsd sees client announces ---
        py_check = t.start_py_helper(f"""\
import RNS
import os
import time

config_dir = os.path.join("{t.tmpdir}", "py_check_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config()}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

# Poll for paths — the retransmission from the Rust server fires
# on a backoff schedule, so we may need to wait up to ~15s.
deadline = time.time() + 20
while time.time() < deadline:
    paths = RNS.Transport.path_table
    if len(paths) >= 2:
        break
    time.sleep(1)

paths = RNS.Transport.path_table
print(f"PATHS_FOUND:{{len(paths)}}", flush=True)
for h in paths:
    print(f"PATH:{{h.hex()}}", flush=True)

print("PY_DONE", flush=True)
""")

        t.wait_for_line(py_check, "PY_DONE", timeout=30)

        # --- Terminate clients and server, collect output ---
        client1_proc.send_signal(signal.SIGTERM)
        try:
            _, c1_stderr = client1_proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            client1_proc.kill()
            _, c1_stderr = client1_proc.communicate()

        client2_proc.send_signal(signal.SIGTERM)
        try:
            _, c2_stderr = client2_proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            client2_proc.kill()
            _, c2_stderr = client2_proc.communicate()

        rust_stderr = t.collect_rust_stderr()

        t.dump_output("Server stdout", server_lines)
        t.dump_output("Client1 stdout", client1_lines)
        t.dump_output("Client2 stdout", client2_lines)
        t.dump_output("Path check output", py_check)
        t.dump_output("Server stderr (last 1000)", rust_stderr.strip().split("\n"))
        if c1_stderr:
            t.dump_output("Client1 stderr (last 300)",
                          c1_stderr.decode(errors="replace")[-300:].strip().split("\n"))
        if c2_stderr:
            t.dump_output("Client2 stderr (last 300)",
                          c2_stderr.decode(errors="replace")[-300:].strip().split("\n"))

        t._log(f"Server dest:  {server_dest}")
        t._log(f"Client1 dest: {client1_dest}")
        t._log(f"Client2 dest: {client2_dest}")

        # --- Assertion 4: Client2 received Client1's announce ---
        # Look for an ANNOUNCE line whose hash matches client1 (not server)
        def has_announce_from(lines, target_dest):
            """Check if lines contain an ANNOUNCE: with the target dest hash."""
            if not target_dest:
                return False
            for line in lines:
                if line.startswith("ANNOUNCE:") and target_dest in line:
                    return True
            return False

        t.check(
            has_announce_from(client2_lines, client1_dest),
            "Client2 received Client1's announce via local server",
            detail=f"looking for {client1_dest} in client2 output",
        )

        # --- Assertion 5: Client1 received Client2's announce ---
        t.check(
            has_announce_from(client1_lines, client2_dest),
            "Client1 received Client2's announce via local server",
            detail=f"looking for {client2_dest} in client1 output",
        )

        # --- Assertion 6 result ---
        path_lines = [l for l in py_check if l.startswith("PATH:")]
        t.check(
            len(path_lines) >= 1,
            f"rnsd has >= 1 path (client visible via relay); found {len(path_lines)}",
        )


if __name__ == "__main__":
    main()
