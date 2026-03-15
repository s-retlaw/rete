#!/usr/bin/env python3
"""Proof routing E2E test: proofs route back through Rust transport relay.

Topology:
  Python_A <-TCP:4247-> rnsd_1 <-TCP-> Rust_Transport <-TCP-> rnsd_2 <-TCP:4248-> Python_B

Flow:
  1. Python_B sets PROVE_ALL on its destination
  2. Python_A discovers Python_B (via Rust relay), sends DATA
  3. Python_B receives DATA, automatically generates a PROOF
  4. PROOF routes back through rnsd_2 -> Rust -> rnsd_1 -> Python_A
  5. Python_A's PacketReceipt fires delivery callback

This tests Sprint 3 (proof routing via reverse table) end-to-end against
the Python reference implementation.

Assertions:
  1. Python_B received DATA from Python_A (relayed through Rust)
  2. Python_A received delivery proof (routed back through Rust)

Usage:
  cd tests/interop
  uv run python proof_routing_interop.py
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
    parser = argparse.ArgumentParser(description="rete proof routing E2E test")
    parser.add_argument(
        "--rust-binary",
        default="../../target/debug/rete-linux",
    )
    parser.add_argument("--port1", type=int, default=4247)
    parser.add_argument("--port2", type=int, default=4248)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    rust_binary = os.path.abspath(args.rust_binary)
    if not os.path.exists(rust_binary):
        print(f"[proof-routing] FAIL: Rust binary not found at {rust_binary}")
        sys.exit(1)

    tmpdir = tempfile.mkdtemp(prefix="rete_proof_routing_")
    procs = []
    passed = 0
    failed = 0

    try:
        # --- Start rnsd_1 and rnsd_2 ---
        for label, port in [("rnsd_1", args.port1), ("rnsd_2", args.port2)]:
            config_dir = os.path.join(tmpdir, f"{label}_config")
            write_rnsd_config(config_dir, port)
            print(f"[proof-routing] starting {label} on port {port}...")
            proc = subprocess.Popen(
                [sys.executable, "-m", "RNS.Utilities.rnsd", "--config", config_dir],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            procs.append(proc)

        for label, port in [("rnsd_1", args.port1), ("rnsd_2", args.port2)]:
            if not wait_for_port("127.0.0.1", port):
                print(f"[proof-routing] FAIL: {label} did not start")
                sys.exit(1)
            print(f"[proof-routing] {label} is listening")

        # --- Get Rust transport dest hash for filtering ---
        rust_seed = "proof-routing-e2e-seed"
        result = subprocess.run(
            [rust_binary, "--identity-seed", rust_seed, "--connect", "127.0.0.99:1"],
            capture_output=True, text=True, timeout=5,
        )
        rust_dest_hex = ""
        for line in result.stderr.split("\n"):
            if "destination hash:" in line:
                rust_dest_hex = line.strip().split("destination hash: ")[-1]
                break

        # --- Start Rust transport node ---
        print("[proof-routing] starting Rust transport node...")
        rust_proc = subprocess.Popen(
            [
                rust_binary,
                "--connect", f"127.0.0.1:{args.port1}",
                "--connect", f"127.0.0.1:{args.port2}",
                "--transport",
                "--identity-seed", rust_seed,
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        procs.append(rust_proc)
        time.sleep(3)

        # --- Python_B: receiver with PROVE_ALL ---
        py_b_script = os.path.join(tmpdir, "py_b.py")
        with open(py_b_script, "w") as f:
            f.write(f"""\
import RNS
import time
import os
import threading

config_dir = os.path.join("{tmpdir}", "py_b_config")
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
    target_port = {args.port2}
\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

data_received = threading.Event()

def packet_callback(data, packet):
    text = data.decode("utf-8", errors="replace")
    print(f"PY_B_DATA_RECEIVED:{{text}}", flush=True)
    data_received.set()

identity = RNS.Identity()
dest = RNS.Destination(
    identity, RNS.Destination.IN, RNS.Destination.SINGLE,
    "rete", "example", "v1",
)
# Enable automatic proof generation for ALL received packets
dest.set_proof_strategy(RNS.Destination.PROVE_ALL)
dest.set_packet_callback(packet_callback)
dest.announce()

print(f"PY_B_DEST_HASH:{{dest.hexhash}}", flush=True)
print("PY_B_PROVE_ALL_SET", flush=True)

# Wait for data
if data_received.wait(timeout={args.timeout}):
    print("PY_B_DATA_OK", flush=True)
else:
    print("PY_B_DATA_TIMEOUT", flush=True)

# Keep alive for proof to propagate back
time.sleep(5)
print("PY_B_DONE", flush=True)
""")

        # --- Python_A: sender that expects a proof back ---
        # (Script is written first, both nodes start simultaneously below)
        py_a_script = os.path.join(tmpdir, "py_a.py")
        with open(py_a_script, "w") as f:
            f.write(f"""\
import RNS
import time
import os
import threading

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
    target_port = {args.port1}
\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

# Dest hashes to filter
exclude_hex = "{rust_dest_hex}"
exclude_hash = bytes.fromhex(exclude_hex) if exclude_hex else None

identity = RNS.Identity()
dest = RNS.Destination(
    identity, RNS.Destination.IN, RNS.Destination.SINGLE,
    "rete", "example", "v1",
)
dest.announce()

# Wait for Python_B's announce (relayed through Rust)
deadline = time.time() + {args.timeout}
peer_hash = None
while time.time() < deadline:
    for h in RNS.Transport.path_table:
        if h == dest.hash:
            continue
        if exclude_hash and h == exclude_hash:
            continue
        peer_hash = h
        break
    if peer_hash:
        break
    time.sleep(0.5)

if not peer_hash:
    print("PY_A_PEER_NOT_FOUND", flush=True)
    time.sleep(1)
    exit(0)

print(f"PY_A_PEER_FOUND:{{peer_hash.hex()}}", flush=True)

# Build outbound destination and send DATA
peer_identity = RNS.Identity.recall(peer_hash)
if not peer_identity:
    print("PY_A_IDENTITY_NOT_RECALLED", flush=True)
    time.sleep(1)
    exit(0)

out_dest = RNS.Destination(
    peer_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
    "rete", "example", "v1",
)

packet = RNS.Packet(out_dest, b"prove this")
receipt = packet.send()

proof_received = threading.Event()

def delivery_callback(receipt):
    print("PY_A_PROOF_RECEIVED", flush=True)
    proof_received.set()

def timeout_callback(receipt):
    print("PY_A_PROOF_TIMEOUT", flush=True)

receipt.set_delivery_callback(delivery_callback)
receipt.set_timeout_callback(timeout_callback)
receipt.set_timeout(15)

print("PY_A_DATA_SENT", flush=True)

# Wait for proof
if proof_received.wait(timeout=20):
    print("PY_A_PROOF_OK", flush=True)
else:
    print("PY_A_PROOF_WAIT_TIMEOUT", flush=True)

time.sleep(2)
print("PY_A_DONE", flush=True)
""")

        # Start both Python nodes simultaneously so they both see each
        # other's announces when Rust re-broadcasts them.
        print("[proof-routing] starting Python_B (receiver, PROVE_ALL)...")
        py_b_proc = subprocess.Popen(
            [sys.executable, py_b_script],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        procs.append(py_b_proc)

        print("[proof-routing] starting Python_A (sender, expects proof)...")
        py_a_proc = subprocess.Popen(
            [sys.executable, py_a_script],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        procs.append(py_a_proc)

        # --- Collect results ---
        print(f"[proof-routing] waiting up to {args.timeout}s...")

        for proc in [py_a_proc, py_b_proc]:
            try:
                proc.wait(timeout=args.timeout + 15)
            except subprocess.TimeoutExpired:
                proc.kill()

        py_a_out = py_a_proc.stdout.read().decode(errors="replace")
        py_b_out = py_b_proc.stdout.read().decode(errors="replace")

        time.sleep(1)
        rust_proc.send_signal(signal.SIGTERM)
        try:
            rust_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            rust_proc.kill()
            rust_proc.wait()

        rust_stdout = rust_proc.stdout.read().decode(errors="replace")
        rust_stderr = rust_proc.stderr.read().decode(errors="replace")

        print("[proof-routing] Python_A output:")
        for line in py_a_out.strip().split("\n"):
            if line.strip():
                print(f"  {line}")

        print("[proof-routing] Python_B output:")
        for line in py_b_out.strip().split("\n"):
            if line.strip():
                print(f"  {line}")

        print("[proof-routing] Rust stderr (last 500 chars):")
        for line in rust_stderr[-500:].strip().split("\n"):
            if line.strip():
                print(f"  {line}")

        # --- Assertions ---

        # 1. Python_B received DATA
        if "PY_B_DATA_RECEIVED:prove this" in py_b_out:
            print("[proof-routing] PASS [1/2]: Python_B received DATA via Rust relay")
            passed += 1
        else:
            print("[proof-routing] FAIL [1/2]: Python_B did not receive DATA")
            failed += 1

        # 2. Python_A received proof (routed back through Rust)
        if "PY_A_PROOF_RECEIVED" in py_a_out:
            print("[proof-routing] PASS [2/2]: Python_A received delivery proof via Rust relay")
            passed += 1
        else:
            print("[proof-routing] FAIL [2/2]: Python_A did not receive delivery proof")
            if "PY_A_PROOF_TIMEOUT" in py_a_out:
                print("  (proof timed out)")
            if "PY_A_PROOF_WAIT_TIMEOUT" in py_a_out:
                print("  (wait timed out)")
            failed += 1

    finally:
        print("[proof-routing] cleaning up...")
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
    print(f"\n[proof-routing] Results: {passed}/{total} passed, {failed}/{total} failed")
    if failed > 0:
        sys.exit(1)
    else:
        print("[proof-routing] ALL TESTS PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
