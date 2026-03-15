#!/usr/bin/env python3
"""Multi-interface transport relay E2E test:
  Python_A <-TCP:4244-> rnsd_1 <-TCP-> Rust_Transport <-TCP-> rnsd_2 <-TCP:4245-> Python_B

The Rust node connects to TWO separate rnsd instances (--connect x2, --transport)
and acts as the transport relay between them.

Assertions:
  1. Python_B discovers Python_A's announce (relayed through Rust)
  2. Python_A discovers Python_B's announce (relayed through Rust)
  3. Python_A sends DATA to Python_B -> received (relayed through Rust)
  4. Python_B sends DATA to Python_A -> received (relayed through Rust)

Usage:
  cd tests/interop
  uv run python transport_relay_interop.py

Or build first:
  cargo build -p rete-example-linux
  cd tests/interop && uv run python transport_relay_interop.py
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
    """Write a minimal rnsd config. Returns config dir path."""
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


def write_py_node_script(
    tmpdir: str,
    script_name: str,
    port: int,
    node_label: str,
    peer_label: str,
    send_msg: str,
    timeout: float,
    exclude_dest_hex: str = "",
) -> str:
    """Write a Python RNS node script that announces, discovers peers,
    sends DATA, and waits for DATA. Returns the script path.

    exclude_dest_hex: hex dest hash to skip when discovering peers
    (used to filter out the Rust transport node).
    """
    script_path = os.path.join(tmpdir, script_name)
    with open(script_path, "w") as f:
        f.write(f"""\
import RNS
import time
import sys
import os
import threading

config_dir = os.path.join("{tmpdir}", "{node_label}_config")
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
    target_port = {port}
\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

# Dest hash to exclude (the transport relay node)
exclude_hex = "{exclude_dest_hex}"
exclude_hash = bytes.fromhex(exclude_hex) if exclude_hex else None

data_received = threading.Event()
received_text = [None]

def packet_callback(data, packet):
    text = data.decode("utf-8", errors="replace")
    received_text[0] = text
    print(f"{node_label.upper()}_DATA_RECEIVED:{{text}}", flush=True)
    data_received.set()

identity = RNS.Identity()
dest = RNS.Destination(
    identity,
    RNS.Destination.IN,
    RNS.Destination.SINGLE,
    "rete",
    "example",
    "v1",
)
dest.set_packet_callback(packet_callback)

print(f"{node_label.upper()}_DEST_HASH:{{dest.hexhash}}", flush=True)
print(f"{node_label.upper()}_IDENTITY_HASH:{{identity.hexhash}}", flush=True)

# Announce
dest.announce()
print(f"{node_label.upper()}_ANNOUNCE_SENT", flush=True)

# Wait for peer announce (skip our own hash and the transport relay)
timeout = {timeout}
deadline = time.time() + timeout
peer_dest_hash = None

while time.time() < deadline:
    known = RNS.Transport.path_table
    for h in known:
        if h == dest.hash:
            continue
        if exclude_hash and h == exclude_hash:
            continue
        peer_dest_hash = h
        print(f"{node_label.upper()}_DISCOVERED:{{h.hex()}}", flush=True)
        break
    if peer_dest_hash:
        break
    time.sleep(0.5)

if peer_dest_hash:
    print(f"{node_label.upper()}_PEER_FOUND", flush=True)

    # Send DATA to peer
    peer_identity = RNS.Identity.recall(peer_dest_hash)
    if peer_identity:
        out_dest = RNS.Destination(
            peer_identity,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            "rete",
            "example",
            "v1",
        )
        pkt = RNS.Packet(out_dest, b"{send_msg}")
        pkt.send()
        print(f"{node_label.upper()}_DATA_SENT", flush=True)
    else:
        print(f"{node_label.upper()}_DATA_SEND_FAIL:identity_not_recalled", flush=True)

    # Wait for DATA from peer
    if data_received.wait(timeout=15):
        print(f"{node_label.upper()}_DATA_RECV_OK", flush=True)
    else:
        print(f"{node_label.upper()}_DATA_RECV_FAIL:timeout", flush=True)
else:
    print(f"{node_label.upper()}_PEER_NOT_FOUND", flush=True)

time.sleep(2)
print(f"{node_label.upper()}_DONE", flush=True)
""")
    return script_path


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


def main():
    parser = argparse.ArgumentParser(
        description="rete multi-interface transport relay E2E test"
    )
    parser.add_argument(
        "--rust-binary",
        default="../../target/debug/rete-linux",
        help="Path to the rete-linux binary",
    )
    parser.add_argument(
        "--port1", type=int, default=4244, help="TCP port for rnsd_1"
    )
    parser.add_argument(
        "--port2", type=int, default=4245, help="TCP port for rnsd_2"
    )
    parser.add_argument(
        "--timeout", type=float, default=30.0, help="Test timeout in seconds"
    )
    args = parser.parse_args()

    rust_binary = os.path.abspath(args.rust_binary)
    if not os.path.exists(rust_binary):
        print(f"[transport-relay] FAIL: Rust binary not found at {rust_binary}")
        print("  Build it with: cargo build -p rete-example-linux")
        sys.exit(1)

    tmpdir = tempfile.mkdtemp(prefix="rete_transport_relay_")
    procs = []
    passed = 0
    failed = 0

    try:
        # --- Start rnsd_1 and rnsd_2 ---
        for label, port in [("rnsd_1", args.port1), ("rnsd_2", args.port2)]:
            config_dir = os.path.join(tmpdir, f"{label}_config")
            write_rnsd_config(config_dir, port)
            print(f"[transport-relay] starting {label} on port {port}...")
            proc = subprocess.Popen(
                [sys.executable, "-m", "RNS.Utilities.rnsd", "--config", config_dir],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            procs.append(proc)

        for label, port in [("rnsd_1", args.port1), ("rnsd_2", args.port2)]:
            if not wait_for_port("127.0.0.1", port, timeout=15.0):
                print(f"[transport-relay] FAIL: {label} did not start on port {port}")
                sys.exit(1)
            print(f"[transport-relay] {label} is listening on port {port}")

        # --- Start Rust transport node (connects to BOTH rnsd instances) ---
        # Get the Rust node's dest hash so Python nodes can filter it out
        rust_seed = "transport-relay-e2e-seed"
        result = subprocess.run(
            [rust_binary, "--identity-seed", rust_seed, "--connect", "127.0.0.99:1"],
            capture_output=True, text=True, timeout=5,
        )
        rust_dest_hex = ""
        for line in result.stderr.split("\n"):
            if "destination hash:" in line:
                rust_dest_hex = line.strip().split("destination hash: ")[-1]
                break
        print(f"[transport-relay] Rust transport dest hash: {rust_dest_hex}")

        print("[transport-relay] starting Rust transport node...")
        rust_proc = subprocess.Popen(
            [
                rust_binary,
                "--connect", f"127.0.0.1:{args.port1}",
                "--connect", f"127.0.0.1:{args.port2}",
                "--transport",
                "--identity-seed", rust_seed,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(rust_proc)
        time.sleep(3)  # Give Rust node time to connect and announce on both

        # --- Start Python node A (connects to rnsd_1) ---
        py_a_script = write_py_node_script(
            tmpdir, "py_node_a.py", args.port1,
            "node_a", "node_b",
            "hello from A to B", args.timeout,
            exclude_dest_hex=rust_dest_hex,
        )
        print("[transport-relay] starting Python node A (on rnsd_1)...")
        py_a_proc = subprocess.Popen(
            [sys.executable, py_a_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(py_a_proc)

        # --- Start Python node B (connects to rnsd_2) ---
        py_b_script = write_py_node_script(
            tmpdir, "py_node_b.py", args.port2,
            "node_b", "node_a",
            "hello from B to A", args.timeout,
            exclude_dest_hex=rust_dest_hex,
        )
        print("[transport-relay] starting Python node B (on rnsd_2)...")
        py_b_proc = subprocess.Popen(
            [sys.executable, py_b_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(py_b_proc)

        # --- Collect results ---
        print(f"[transport-relay] waiting up to {args.timeout}s for results...")

        for label, proc in [("node_a", py_a_proc), ("node_b", py_b_proc)]:
            try:
                proc.wait(timeout=args.timeout + 15)
            except subprocess.TimeoutExpired:
                proc.kill()

        py_a_stdout = py_a_proc.stdout.read().decode(errors="replace")
        py_a_stderr = py_a_proc.stderr.read().decode(errors="replace")
        py_b_stdout = py_b_proc.stdout.read().decode(errors="replace")
        py_b_stderr = py_b_proc.stderr.read().decode(errors="replace")

        print("[transport-relay] Node A output:")
        for line in py_a_stdout.strip().split("\n"):
            if line.strip():
                print(f"  {line}")

        print("[transport-relay] Node B output:")
        for line in py_b_stdout.strip().split("\n"):
            if line.strip():
                print(f"  {line}")

        # Terminate Rust node and collect output
        time.sleep(1)
        rust_proc.send_signal(signal.SIGTERM)
        try:
            rust_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            rust_proc.kill()
            rust_proc.wait()

        rust_stdout = rust_proc.stdout.read().decode(errors="replace")
        rust_stderr = rust_proc.stderr.read().decode(errors="replace")

        print("[transport-relay] Rust transport node stdout:")
        for line in rust_stdout.strip().split("\n"):
            if line.strip():
                print(f"  {line}")
        print("[transport-relay] Rust transport node stderr (last 800 chars):")
        for line in rust_stderr[-800:].strip().split("\n"):
            if line.strip():
                print(f"  {line}")

        # --- Assertions ---

        # 1. Node B discovers Node A's announce (relayed through Rust)
        if "NODE_B_PEER_FOUND" in py_b_stdout:
            print("[transport-relay] PASS [1/4]: Node B discovered Node A via Rust relay")
            passed += 1
        else:
            print("[transport-relay] FAIL [1/4]: Node B did not discover Node A")
            if py_b_stderr:
                print(f"  Node B stderr (last 300 chars): {py_b_stderr[-300:]}")
            failed += 1

        # 2. Node A discovers Node B's announce (relayed through Rust)
        if "NODE_A_PEER_FOUND" in py_a_stdout:
            print("[transport-relay] PASS [2/4]: Node A discovered Node B via Rust relay")
            passed += 1
        else:
            print("[transport-relay] FAIL [2/4]: Node A did not discover Node B")
            if py_a_stderr:
                print(f"  Node A stderr (last 300 chars): {py_a_stderr[-300:]}")
            failed += 1

        # 3. Node A sends DATA to Node B -> received
        if "NODE_B_DATA_RECEIVED:hello from A to B" in py_b_stdout:
            print("[transport-relay] PASS [3/4]: Node A -> Node B DATA relayed through Rust")
            passed += 1
        else:
            print("[transport-relay] FAIL [3/4]: Node B did not receive DATA from Node A")
            failed += 1

        # 4. Node B sends DATA to Node A -> received
        if "NODE_A_DATA_RECEIVED:hello from B to A" in py_a_stdout:
            print("[transport-relay] PASS [4/4]: Node B -> Node A DATA relayed through Rust")
            passed += 1
        else:
            print("[transport-relay] FAIL [4/4]: Node A did not receive DATA from Node B")
            failed += 1

    finally:
        print("[transport-relay] cleaning up...")
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
    print(f"\n[transport-relay] Results: {passed}/{total} passed, {failed}/{total} failed")

    if failed > 0:
        sys.exit(1)
    else:
        print("[transport-relay] ALL TESTS PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
