#!/usr/bin/env python3
"""LXMF direct (Link+Resource/Packet) interop test: Python LXMF -> Rust rete node.

Tests:
  1. Rust LXMF announce received by Python
  2. Python sends LXMF via DIRECT delivery (Link+packet for small, Link+Resource for large)
  3. Rust receives and parses the LXMF message
  4. Large LXMF message via Resource transfer

Usage:
  cd tests/interop
  uv run python lxmf_direct_interop.py --rust-binary ../../target/debug/rete-linux

Requires:
  pip install rns lxmf
"""

import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import threading

from interop_helpers import write_rnsd_config, wait_for_port


def collect_stdout(proc, lines, label=""):
    for raw in proc.stdout:
        line = raw.decode("utf-8", errors="replace").strip()
        if line:
            lines.append(line)
            print(f"  [{label}] {line}", flush=True)


def main():
    parser = argparse.ArgumentParser(description="LXMF direct interop test")
    parser.add_argument(
        "--rust-binary",
        default="../../target/debug/rete-linux",
        help="Path to the rete-linux binary",
    )
    parser.add_argument("--port", type=int, default=4253, help="TCP port for rnsd")
    parser.add_argument("--timeout", type=float, default=45.0, help="Test timeout")
    args = parser.parse_args()

    rust_binary = os.path.abspath(args.rust_binary)
    if not os.path.exists(rust_binary):
        print(f"FAIL: Rust binary not found at {rust_binary}")
        print("  Build it with: cargo build -p rete-example-linux")
        sys.exit(1)

    try:
        import RNS
        import LXMF
    except ImportError:
        print("SKIP: LXMF/RNS Python packages not installed")
        print("  Install with: pip install rns lxmf")
        sys.exit(0)

    tmpdir = tempfile.mkdtemp(prefix="rete_lxmf_dir_")
    rnsd_config_dir = os.path.join(tmpdir, "rnsd_config")
    procs = []
    passed = 0
    failed = 0

    try:
        # --- Start rnsd ---
        write_rnsd_config(rnsd_config_dir, args.port)
        rnsd_proc = subprocess.Popen(
            [sys.executable, "-m", "RNS.Utilities.rnsd", "--config", rnsd_config_dir],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        procs.append(rnsd_proc)
        if not wait_for_port("127.0.0.1", args.port):
            print("FAIL: rnsd did not start")
            sys.exit(1)
        print("[lxmf-direct] rnsd ready")
        time.sleep(1)

        # --- Start Rust node ---
        rust_lines = []
        rust_stderr_lines = []
        rust_proc = subprocess.Popen(
            [
                rust_binary,
                "--connect", f"127.0.0.1:{args.port}",
                "--identity-seed", "lxmf-direct-rust",
                "--lxmf-announce",
                "--lxmf-name", "DirectRust",
            ],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        procs.append(rust_proc)
        threading.Thread(
            target=collect_stdout, args=(rust_proc, rust_lines, "rust"), daemon=True
        ).start()

        def read_stderr():
            for raw in rust_proc.stderr:
                line = raw.decode("utf-8", errors="replace").strip()
                if line:
                    rust_stderr_lines.append(line)
                    print(f"  [rust-err] {line}", flush=True)
        threading.Thread(target=read_stderr, daemon=True).start()
        time.sleep(3)

        # Get Rust LXMF delivery hash
        rust_lxmf_hash = None
        for line in rust_stderr_lines:
            if "LXMF delivery hash:" in line:
                rust_lxmf_hash = line.split(":")[-1].strip()
                break
        if not rust_lxmf_hash:
            print("FAIL: Could not find Rust LXMF delivery hash")
            sys.exit(1)
        print(f"[lxmf-direct] Rust LXMF delivery hash: {rust_lxmf_hash}")

        # --- Python LXMF setup ---
        py_config_dir = os.path.join(tmpdir, "py_config")
        os.makedirs(py_config_dir, exist_ok=True)
        with open(os.path.join(py_config_dir, "config"), "w") as f:
            f.write(f"""\
[reticulum]
  enable_transport = no
  share_instance = no

[interfaces]

  [[TCP Client Interface]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = {args.port}
""")

        reticulum = RNS.Reticulum(py_config_dir)
        time.sleep(2)

        py_identity = RNS.Identity()
        py_router = LXMF.LXMRouter(
            identity=py_identity,
            storagepath=os.path.join(tmpdir, "lxmf_storage"),
        )
        py_lxmf_dest = py_router.register_delivery_identity(
            py_identity, display_name="PythonDirect"
        )
        time.sleep(1)

        # --- TEST 1: Wait for Rust LXMF announce ---
        rust_dest_bytes = bytes.fromhex(rust_lxmf_hash)
        print("[lxmf-direct] waiting for Rust LXMF announce...")
        deadline = time.monotonic() + 20.0
        rust_announced = False
        while time.monotonic() < deadline:
            if RNS.Transport.has_path(rust_dest_bytes):
                rust_announced = True
                break
            time.sleep(0.5)

        if rust_announced:
            print("[lxmf-direct] TEST 1 PASS: Rust LXMF announce received")
            passed += 1
        else:
            print("FAIL: TEST 1: Rust LXMF announce not received")
            failed += 1
            # Can't continue without the announce
            return

        # --- TEST 2: Small LXMF via DIRECT (Link+Packet) ---
        print("[lxmf-direct] sending small LXMF via DIRECT delivery...")
        rust_id = RNS.Identity.recall(rust_dest_bytes)
        if not rust_id:
            print("FAIL: TEST 2: Could not recall Rust identity")
            failed += 1
            return

        lxmf_dest = RNS.Destination(
            rust_id, RNS.Destination.OUT, RNS.Destination.SINGLE,
            "lxmf", "delivery"
        )

        # Small message — will be sent as Link+Packet (DIRECT, PACKET representation)
        small_msg = LXMF.LXMessage(
            lxmf_dest, py_lxmf_dest,
            "Small direct message",
            title="Direct Small",
            desired_method=LXMF.LXMessage.DIRECT,
        )
        small_msg.try_propagation_on_fail = False

        small_delivered = threading.Event()
        def on_small_delivery(msg):
            print("  [python] small message delivery confirmed")
            small_delivered.set()
        small_msg.delivery_callback = on_small_delivery

        py_router.handle_outbound(small_msg)

        # Wait for Rust to receive it
        deadline = time.monotonic() + 20.0
        rust_got_small = False
        while time.monotonic() < deadline:
            for line in rust_lines:
                if "LXMF_RECEIVED:" in line and "Direct Small" in line:
                    rust_got_small = True
                    break
            if rust_got_small:
                break
            time.sleep(0.5)

        if rust_got_small:
            print("[lxmf-direct] TEST 2 PASS: Small LXMF received via DIRECT!")
            for line in rust_lines:
                if "LXMF_RECEIVED:" in line:
                    print(f"  {line}")
            passed += 1
        else:
            print("FAIL: TEST 2: Rust did not receive small direct LXMF")
            print("  Rust stdout:")
            for line in rust_lines:
                print(f"    {line}")
            failed += 1

        # --- TEST 3: Large LXMF via DIRECT (Link+Resource) ---
        print("[lxmf-direct] sending large LXMF via DIRECT delivery (Resource)...")

        # Large content — will be sent as Link+Resource (DIRECT, RESOURCE representation)
        large_content = "A" * 1000  # > LINK_PACKET_MAX_CONTENT, forces Resource
        large_msg = LXMF.LXMessage(
            lxmf_dest, py_lxmf_dest,
            large_content,
            title="Direct Large",
            desired_method=LXMF.LXMessage.DIRECT,
        )
        large_msg.try_propagation_on_fail = False

        large_delivered = threading.Event()
        def on_large_delivery(msg):
            print("  [python] large message delivery confirmed")
            large_delivered.set()
        large_msg.delivery_callback = on_large_delivery

        py_router.handle_outbound(large_msg)

        # Wait for Rust to receive it
        deadline = time.monotonic() + 25.0
        rust_got_large = False
        while time.monotonic() < deadline:
            for line in rust_lines:
                if "LXMF_RECEIVED:" in line and "Direct Large" in line:
                    rust_got_large = True
                    break
            if rust_got_large:
                break
            time.sleep(0.5)

        if rust_got_large:
            print("[lxmf-direct] TEST 3 PASS: Large LXMF received via DIRECT (Resource)!")
            for line in rust_lines:
                if "LXMF_RECEIVED:" in line and "Direct Large" in line:
                    print(f"  {line}")
            passed += 1
        else:
            print("FAIL: TEST 3: Rust did not receive large direct LXMF")
            print("  Rust stdout:")
            for line in rust_lines:
                print(f"    {line}")
            failed += 1

    finally:
        for proc in procs:
            try:
                proc.send_signal(signal.SIGTERM)
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
        shutil.rmtree(tmpdir, ignore_errors=True)

    total = passed + failed
    print(f"\n[lxmf-direct] Results: {passed}/{total} passed")
    if failed > 0:
        print("FAIL")
        sys.exit(1)
    else:
        print("PASS")
        sys.exit(0)


if __name__ == "__main__":
    main()
