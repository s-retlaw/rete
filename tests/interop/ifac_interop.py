#!/usr/bin/env python3
"""IFAC interop test: Rust rete node <-> Python rnsd with Interface Access Codes.

Tests:
  1. Both nodes with matching IFAC: announces and data exchange work
  2. Rust node without IFAC cannot see IFAC-protected traffic
  3. Rust node with wrong IFAC key cannot see IFAC-protected traffic

Usage:
  cd tests/interop
  uv run python ifac_interop.py --rust-binary ../../target/debug/rete-linux

Or build first:
  cargo build -p rete-example-linux
  cd tests/interop && uv run python ifac_interop.py
"""

import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from interop_helpers import write_rnsd_config, wait_for_port


def start_rnsd(config_dir: str, port: int, ifac_netname: str = None):
    """Start rnsd with optional IFAC."""
    write_rnsd_config(config_dir, port, ifac_netname)
    proc = subprocess.Popen(
        [sys.executable, "-m", "RNS.Utilities.rnsd", "--config", config_dir],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return proc


def start_rust_node(rust_binary: str, port: int, seed: str,
                    ifac_netname: str = None, extra_args: list = None):
    """Start Rust rete node with optional IFAC."""
    args = [
        rust_binary,
        "--connect", f"127.0.0.1:{port}",
        "--identity-seed", seed,
        "--auto-reply", "hello from rust",
    ]
    if ifac_netname:
        args.extend(["--ifac-netname", ifac_netname])
    if extra_args:
        args.extend(extra_args)
    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return proc


def write_py_client_script(tmpdir: str, port: int, ifac_netname: str = None,
                           timeout: float = 30.0) -> str:
    """Write a Python client script that connects, announces, and waits."""
    py_helper = os.path.join(tmpdir, "py_ifac_client.py")

    ifac_config = ""
    if ifac_netname:
        ifac_config = f"\n    networkname = {ifac_netname}"

    with open(py_helper, "w") as f:
        f.write(f"""\
import RNS
import time
import sys
import os
import threading

config_dir = os.path.join("{tmpdir}", "py_client_config")
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
    target_port = {port}{ifac_config}
\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

data_received = threading.Event()

def packet_callback(data, packet):
    text = data.decode("utf-8", errors="replace")
    print(f"PY_DATA_RECEIVED:{{text}}", flush=True)
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

print(f"PY_DEST_HASH:{{dest.hexhash}}", flush=True)
print(f"PY_IDENTITY_HASH:{{identity.hexhash}}", flush=True)

dest.announce()
print("PY_ANNOUNCE_SENT", flush=True)

timeout = {timeout}
deadline = time.time() + timeout
rust_dest_hash = None

while time.time() < deadline:
    known = RNS.Transport.path_table
    for h in known:
        if h != dest.hash:
            rust_dest_hash = h
            print(f"PY_DISCOVERED:{{h.hex()}}", flush=True)
            break
    if rust_dest_hash:
        break
    time.sleep(0.5)

if rust_dest_hash:
    print("PY_INTEROP_OK", flush=True)

    rust_identity = RNS.Identity.recall(rust_dest_hash)
    if rust_identity:
        out_dest = RNS.Destination(
            rust_identity,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            "rete",
            "example",
            "v1",
        )
        pkt = RNS.Packet(out_dest, b"hello from python")
        pkt.send()
        print("PY_DATA_SENT", flush=True)
    else:
        print("PY_DATA_SEND_FAIL:identity_not_recalled", flush=True)

    if data_received.wait(timeout=10):
        print("PY_DATA_RECV_OK", flush=True)
    else:
        print("PY_DATA_RECV_FAIL:timeout", flush=True)
else:
    print("PY_INTEROP_FAIL:timeout_waiting_for_rust_announce", flush=True)

time.sleep(2)
print("PY_DONE", flush=True)
""")
    return py_helper


def collect_output(proc, timeout=45.0):
    """Wait for a process and collect its output."""
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
    return stdout.decode(errors="replace"), stderr.decode(errors="replace")


def main():
    parser = argparse.ArgumentParser(description="rete IFAC interop test")
    parser.add_argument(
        "--rust-binary",
        default="../../target/debug/rete-linux",
        help="Path to the rete-linux binary",
    )
    parser.add_argument(
        "--port", type=int, default=4252, help="TCP port for rnsd (default: 4252)"
    )
    parser.add_argument(
        "--timeout", type=float, default=30.0, help="Test timeout in seconds"
    )
    args = parser.parse_args()

    rust_binary = os.path.abspath(args.rust_binary)
    if not os.path.exists(rust_binary):
        print(f"FAIL: Rust binary not found at {rust_binary}")
        print("  Build it with: cargo build -p rete-example-linux")
        sys.exit(1)

    IFAC_NETNAME = "rete-test-network"

    tmpdir = tempfile.mkdtemp(prefix="rete_ifac_interop_")
    procs = []
    passed = 0
    failed = 0

    try:
        # ==================================================================
        # TEST 1: Matching IFAC — Rust and Python can communicate
        # ==================================================================
        print("\n" + "=" * 60)
        print("TEST 1: Matching IFAC — bidirectional communication")
        print("=" * 60)

        rnsd_config = os.path.join(tmpdir, "rnsd_config_ifac")
        rnsd_proc = start_rnsd(rnsd_config, args.port, ifac_netname=IFAC_NETNAME)
        procs.append(rnsd_proc)

        if not wait_for_port("127.0.0.1", args.port, timeout=15.0):
            print("FAIL: rnsd did not start within 15s")
            if rnsd_proc.poll() is not None:
                _, stderr = collect_output(rnsd_proc, timeout=5)
                print(f"  rnsd stderr: {stderr[-500:]}")
            sys.exit(1)
        print("[ifac] rnsd with IFAC is listening")

        # Start Rust node with matching IFAC
        print("[ifac] starting Rust node with matching IFAC...")
        rust_proc = start_rust_node(
            rust_binary, args.port, "ifac-test-seed-42",
            ifac_netname=IFAC_NETNAME,
        )
        procs.append(rust_proc)
        time.sleep(2)

        # Start Python client with matching IFAC
        print("[ifac] starting Python client with matching IFAC...")
        py_helper = write_py_client_script(
            tmpdir, args.port, ifac_netname=IFAC_NETNAME, timeout=args.timeout
        )
        py_proc = subprocess.Popen(
            [sys.executable, py_helper],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(py_proc)

        # Collect results
        py_out, py_err = collect_output(py_proc, timeout=args.timeout + 10)
        print("[ifac] Python client output:")
        for line in py_out.strip().split("\n"):
            print(f"  {line}")

        time.sleep(2)
        rust_proc.send_signal(signal.SIGTERM)
        rust_out, rust_err = collect_output(rust_proc, timeout=5)

        print("[ifac] Rust node stdout:")
        for line in rust_out.strip().split("\n"):
            if line.strip():
                print(f"  {line}")

        # Check: Python discovered Rust announce
        if "PY_INTEROP_OK" in py_out:
            print("[ifac] PASS: Python discovered Rust announce (IFAC matched)")
            passed += 1
        else:
            print("[ifac] FAIL: Python did not discover Rust announce")
            failed += 1

        # Check: Rust received Python announce
        if "ANNOUNCE:" in rust_out:
            print("[ifac] PASS: Rust received Python announce (IFAC matched)")
            passed += 1
        else:
            print("[ifac] FAIL: Rust did not receive Python announce")
            print(f"  Rust stderr (last 500 chars): {rust_err[-500:]}")
            failed += 1

        # Check: Python received DATA from Rust (auto-reply)
        if "PY_DATA_RECEIVED:" in py_out:
            print("[ifac] PASS: Python received DATA from Rust")
            passed += 1
        else:
            print("[ifac] FAIL: Python did not receive DATA from Rust")
            failed += 1

        # Check: Rust received DATA from Python
        rust_data_lines = [l for l in rust_out.strip().split("\n") if l.startswith("DATA:")]
        if any("hello from python" in l for l in rust_data_lines):
            print("[ifac] PASS: Rust received DATA from Python")
            passed += 1
        else:
            print("[ifac] FAIL: Rust did not receive DATA from Python")
            if rust_data_lines:
                print(f"  Rust DATA lines: {rust_data_lines}")
            failed += 1

        # Verify IFAC is mentioned in Rust stderr
        if "IFAC enabled" in rust_err:
            print("[ifac] PASS: Rust reports IFAC enabled")
            passed += 1
        else:
            print("[ifac] FAIL: Rust does not report IFAC enabled")
            failed += 1

        # Stop rnsd for next test
        rnsd_proc.kill()
        rnsd_proc.wait(timeout=5)
        time.sleep(1)

        # ==================================================================
        # TEST 2: No IFAC on Rust — should not receive IFAC-protected traffic
        # ==================================================================
        print("\n" + "=" * 60)
        print("TEST 2: Rust WITHOUT IFAC cannot see IFAC-protected traffic")
        print("=" * 60)

        rnsd_config2 = os.path.join(tmpdir, "rnsd_config_ifac2")
        port2 = args.port + 1
        rnsd_proc2 = start_rnsd(rnsd_config2, port2, ifac_netname=IFAC_NETNAME)
        procs.append(rnsd_proc2)

        if not wait_for_port("127.0.0.1", port2, timeout=15.0):
            print("FAIL: rnsd did not start for test 2")
            sys.exit(1)

        # Start Rust node WITHOUT IFAC
        print("[ifac] starting Rust node WITHOUT IFAC...")
        rust_no_ifac = start_rust_node(
            rust_binary, port2, "no-ifac-seed-42",
            ifac_netname=None,  # no IFAC
        )
        procs.append(rust_no_ifac)
        time.sleep(2)

        # Start Python client WITH IFAC (same as rnsd)
        py_helper2 = os.path.join(tmpdir, "py_ifac_client2.py")
        tmpdir2 = os.path.join(tmpdir, "test2")
        os.makedirs(tmpdir2, exist_ok=True)
        py_script2 = write_py_client_script(
            tmpdir2, port2, ifac_netname=IFAC_NETNAME, timeout=10
        )
        py_proc2 = subprocess.Popen(
            [sys.executable, py_script2],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(py_proc2)

        py_out2, _ = collect_output(py_proc2, timeout=20)
        time.sleep(2)
        rust_no_ifac.send_signal(signal.SIGTERM)
        rust_out2, rust_err2 = collect_output(rust_no_ifac, timeout=5)

        # Rust without IFAC should NOT see any announces (IFAC flag set = drop)
        announce_lines = [l for l in rust_out2.strip().split("\n") if l.startswith("ANNOUNCE:")]
        if len(announce_lines) == 0:
            print("[ifac] PASS: Rust without IFAC saw 0 announces (IFAC packets dropped)")
            passed += 1
        else:
            print(f"[ifac] FAIL: Rust without IFAC saw {len(announce_lines)} announces")
            for line in announce_lines:
                print(f"  {line}")
            failed += 1

        rnsd_proc2.kill()
        rnsd_proc2.wait(timeout=5)
        time.sleep(1)

        # ==================================================================
        # TEST 3: Wrong IFAC key — should not communicate
        # ==================================================================
        print("\n" + "=" * 60)
        print("TEST 3: Rust with WRONG IFAC key cannot communicate")
        print("=" * 60)

        rnsd_config3 = os.path.join(tmpdir, "rnsd_config_ifac3")
        port3 = args.port + 2
        rnsd_proc3 = start_rnsd(rnsd_config3, port3, ifac_netname=IFAC_NETNAME)
        procs.append(rnsd_proc3)

        if not wait_for_port("127.0.0.1", port3, timeout=15.0):
            print("FAIL: rnsd did not start for test 3")
            sys.exit(1)

        # Start Rust node with WRONG IFAC key
        print("[ifac] starting Rust node with wrong IFAC key...")
        rust_wrong_ifac = start_rust_node(
            rust_binary, port3, "wrong-ifac-seed-42",
            ifac_netname="wrong-network-name",  # wrong key
        )
        procs.append(rust_wrong_ifac)
        time.sleep(2)

        # Start Python client with correct IFAC
        tmpdir3 = os.path.join(tmpdir, "test3")
        os.makedirs(tmpdir3, exist_ok=True)
        py_script3 = write_py_client_script(
            tmpdir3, port3, ifac_netname=IFAC_NETNAME, timeout=10
        )
        py_proc3 = subprocess.Popen(
            [sys.executable, py_script3],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(py_proc3)

        py_out3, _ = collect_output(py_proc3, timeout=20)
        time.sleep(2)
        rust_wrong_ifac.send_signal(signal.SIGTERM)
        rust_out3, rust_err3 = collect_output(rust_wrong_ifac, timeout=5)

        # Rust with wrong key should NOT see any valid announces
        announce_lines3 = [l for l in rust_out3.strip().split("\n") if l.startswith("ANNOUNCE:")]
        if len(announce_lines3) == 0:
            print("[ifac] PASS: Rust with wrong IFAC key saw 0 announces")
            passed += 1
        else:
            print(f"[ifac] FAIL: Rust with wrong key saw {len(announce_lines3)} announces")
            for line in announce_lines3:
                print(f"  {line}")
            failed += 1

        rnsd_proc3.kill()
        rnsd_proc3.wait(timeout=5)

    finally:
        # Cleanup
        print("\n[ifac] cleaning up...")
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
    print(f"\n[ifac] Results: {passed}/{total} passed, {failed}/{total} failed")

    if failed > 0:
        sys.exit(1)
    else:
        print("[ifac] ALL TESTS PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
