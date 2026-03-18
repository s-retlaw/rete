#!/usr/bin/env python3
"""Link-initiation E2E interop test: Rust initiates a Link to a Python node via rnsd.

Topology:
  rnsd (transport=yes, TCP server on localhost:4250)
  Rust node connects as TCP client to rnsd
  Python node connects as TCP client to rnsd
  Rust discovers Python via announce, then initiates a Link

Assertions:
  1. Rust discovered Python's announce
  2. Link established (both sides)
  3. Python received data from Rust over the link
  4. Rust received data from Python over the link
  5. Link teardown (Rust prints LINK_CLOSED)

Usage:
  cd tests/interop
  uv run python link_initiate_interop.py --rust-binary ../../target/debug/rete-linux
"""

import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

from interop_helpers import write_rnsd_config, wait_for_port, read_stdout_lines


def main():
    parser = argparse.ArgumentParser(description="rete link-initiation interop test")
    parser.add_argument(
        "--rust-binary",
        default="../../target/debug/rete-linux",
        help="Path to the rete-linux binary",
    )
    parser.add_argument(
        "--port", type=int, default=4250, help="TCP port for rnsd"
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

    tmpdir = tempfile.mkdtemp(prefix="rete_link_init_interop_")
    rnsd_config_dir = os.path.join(tmpdir, "rnsd_config")
    procs = []
    passed = 0
    failed = 0
    stop_event = threading.Event()

    try:
        # --- Step 1: Start rnsd ---
        print(f"[link-init-interop] setting up rnsd config in {rnsd_config_dir}")
        write_rnsd_config(rnsd_config_dir, args.port)

        print(f"[link-init-interop] starting rnsd on port {args.port}...")
        rnsd_proc = subprocess.Popen(
            [sys.executable, "-m", "RNS.Utilities.rnsd", "--config", rnsd_config_dir],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(rnsd_proc)

        if not wait_for_port("127.0.0.1", args.port, timeout=15.0):
            print("[link-init-interop] FAIL: rnsd did not start listening within 15s")
            if rnsd_proc.poll() is not None:
                stderr = rnsd_proc.stderr.read().decode(errors="replace")
                print(f"  rnsd stderr:\n{stderr}")
            sys.exit(1)
        print("[link-init-interop] rnsd is listening")

        # --- Step 2: Start Rust node with stdin piped ---
        print("[link-init-interop] starting Rust node...")
        rust_proc = subprocess.Popen(
            [
                rust_binary,
                "--connect", f"127.0.0.1:{args.port}",
                "--identity-seed", "link-init-seed-99",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(rust_proc)

        rust_lines = []
        rust_reader = threading.Thread(
            target=read_stdout_lines, args=(rust_proc, rust_lines, stop_event)
        )
        rust_reader.daemon = True
        rust_reader.start()

        # Give Rust time to connect and announce
        time.sleep(3)

        # --- Step 3: Start Python helper that accepts inbound links ---
        py_helper = os.path.join(tmpdir, "py_link_responder.py")
        with open(py_helper, "w") as f:
            f.write(f"""\
import RNS
import time
import sys
import os
import threading

config_dir = os.path.join("{tmpdir}", "py_responder_config")
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

link_established = threading.Event()
link_data_received = threading.Event()
received_data_text = [None]
active_link = [None]

py_identity = RNS.Identity()
py_dest = RNS.Destination(
    py_identity,
    RNS.Destination.IN,
    RNS.Destination.SINGLE,
    "rete",
    "example",
    "v1",
)

def inbound_link_established(link):
    print(f"PY_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
    active_link[0] = link
    link_established.set()

    def link_packet_cb(data, packet):
        text = data.decode("utf-8", errors="replace")
        print(f"PY_LINK_DATA_RECEIVED:{{text}}", flush=True)
        received_data_text[0] = text
        link_data_received.set()

    link.set_packet_callback(link_packet_cb)

    # Send data back to Rust over the link
    time.sleep(0.5)
    pkt = RNS.Packet(link, b"hello from python via link")
    pkt.send()
    print("PY_LINK_DATA_SENT", flush=True)

def link_closed_cb(link):
    print(f"PY_LINK_CLOSED:{{link.link_id.hex()}}", flush=True)

py_dest.set_link_established_callback(inbound_link_established)

# Announce so Rust can discover us
py_dest.announce()
print(f"PY_DEST_HASH:{{py_dest.hexhash}}", flush=True)
print(f"PY_IDENTITY_HASH:{{py_identity.hexhash}}", flush=True)
print("PY_ANNOUNCE_SENT", flush=True)

# Wait for link establishment
timeout = {args.timeout}
if not link_established.wait(timeout=timeout):
    print("PY_FAIL:no_link_established", flush=True)
    sys.exit(1)

# Wait for data from Rust
if not link_data_received.wait(timeout=15):
    print("PY_FAIL:no_data_received", flush=True)
else:
    print(f"PY_DATA_OK:{{received_data_text[0]}}", flush=True)

# Give time for Rust to receive our data
time.sleep(3)

# Teardown the link
if active_link[0]:
    active_link[0].teardown()
    print("PY_LINK_TEARDOWN_SENT", flush=True)
    time.sleep(2)

print("PY_DONE", flush=True)
""")

        print("[link-init-interop] starting Python responder...")
        py_proc = subprocess.Popen(
            [sys.executable, py_helper],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(py_proc)

        # --- Step 4: Read Python stdout for dest hash, then tell Rust to link ---
        py_lines = []
        py_reader = threading.Thread(
            target=read_stdout_lines, args=(py_proc, py_lines, stop_event)
        )
        py_reader.daemon = True
        py_reader.start()

        # Wait for Python's dest hash
        deadline = time.time() + args.timeout
        py_dest_hash = None
        while time.time() < deadline:
            for line in py_lines:
                if line.startswith("PY_DEST_HASH:"):
                    py_dest_hash = line.split(":", 1)[1].strip()
                    break
            if py_dest_hash:
                break
            time.sleep(0.3)

        if not py_dest_hash:
            print("[link-init-interop] FAIL: Python did not report dest hash")
            sys.exit(1)
        print(f"[link-init-interop] Python dest hash: {py_dest_hash}")

        # Wait for Rust to see Python's announce
        print("[link-init-interop] waiting for Rust to discover Python's announce...")
        rust_saw_announce = False
        while time.time() < deadline:
            for line in rust_lines:
                if line.startswith("ANNOUNCE:") and py_dest_hash in line:
                    rust_saw_announce = True
                    break
            if rust_saw_announce:
                break
            time.sleep(0.3)

        if not rust_saw_announce:
            print("[link-init-interop] FAIL: Rust did not see Python's announce")
            print(f"  Rust stdout lines: {rust_lines}")
            # Try proceeding anyway — the announce may still arrive
        else:
            print("[link-init-interop] Rust discovered Python's announce")

        # --- Step 5: Tell Rust to initiate a link ---
        print(f"[link-init-interop] sending 'link {py_dest_hash}' to Rust stdin...")
        rust_proc.stdin.write(f"link {py_dest_hash}\n".encode())
        rust_proc.stdin.flush()

        # Wait for Rust LINK_ESTABLISHED
        print("[link-init-interop] waiting for link establishment...")
        rust_link_id = None
        while time.time() < deadline:
            for line in rust_lines:
                if line.startswith("LINK_ESTABLISHED:"):
                    rust_link_id = line.split(":", 1)[1].strip()
                    break
            if rust_link_id:
                break
            time.sleep(0.3)

        if rust_link_id:
            print(f"[link-init-interop] Rust link established: {rust_link_id}")

            # --- Step 6: Send data from Rust to Python over the link ---
            time.sleep(1)  # let link fully settle
            print(f"[link-init-interop] sending 'linkdata {rust_link_id} hello from rust via link' ...")
            rust_proc.stdin.write(f"linkdata {rust_link_id} hello from rust via link\n".encode())
            rust_proc.stdin.flush()
        else:
            print("[link-init-interop] link not established on Rust side")

        # --- Step 7: Wait for Python to finish ---
        print(f"[link-init-interop] waiting up to {args.timeout}s for Python to finish...")
        try:
            py_proc.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            py_proc.kill()
            py_proc.wait()

        # Give Rust time to process remaining events
        time.sleep(2)

        # Collect results
        stop_event.set()
        rust_proc.send_signal(signal.SIGTERM)
        try:
            _, rust_stderr = rust_proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            rust_proc.kill()
            _, rust_stderr = rust_proc.communicate()

        rust_err_output = rust_stderr.decode(errors="replace")
        py_output = "\n".join(py_lines)

        print("[link-init-interop] Python responder stdout:")
        for line in py_lines:
            if line.strip():
                print(f"  {line}")

        print("[link-init-interop] Rust node stdout:")
        for line in rust_lines:
            if line.strip():
                print(f"  {line}")

        print("[link-init-interop] Rust node stderr (last 1000 chars):")
        for line in rust_err_output[-1000:].strip().split("\n"):
            if line.strip():
                print(f"  {line}")

        # --- Assertions ---

        # 1. Rust discovered Python's announce
        if rust_saw_announce:
            print("[link-init-interop] PASS [1/5]: Rust discovered Python's announce")
            passed += 1
        else:
            print("[link-init-interop] FAIL [1/5]: Rust did not discover Python's announce")
            failed += 1

        # 2. Link established (both sides)
        rust_link_ok = any(l.startswith("LINK_ESTABLISHED:") for l in rust_lines)
        py_link_ok = any(l.startswith("PY_LINK_ESTABLISHED:") for l in py_lines)
        if rust_link_ok and py_link_ok:
            print("[link-init-interop] PASS [2/5]: Link established (both sides)")
            passed += 1
        else:
            print(f"[link-init-interop] FAIL [2/5]: Link established — Rust={rust_link_ok} Python={py_link_ok}")
            failed += 1

        # 3. Python received data from Rust
        py_got_rust_data = any(
            l.startswith("PY_LINK_DATA_RECEIVED:") and "hello from rust via link" in l
            for l in py_lines
        )
        if py_got_rust_data:
            print("[link-init-interop] PASS [3/5]: Python received data from Rust")
            passed += 1
        else:
            print("[link-init-interop] FAIL [3/5]: Python did not receive data from Rust")
            py_data_lines = [l for l in py_lines if "PY_LINK_DATA" in l]
            if py_data_lines:
                print(f"  Python data lines: {py_data_lines}")
            failed += 1

        # 4. Rust received data from Python
        rust_got_py_data = any(
            l.startswith("LINK_DATA:") and "hello from python via link" in l
            for l in rust_lines
        )
        if rust_got_py_data:
            print("[link-init-interop] PASS [4/5]: Rust received data from Python")
            passed += 1
        else:
            print("[link-init-interop] FAIL [4/5]: Rust did not receive data from Python")
            rust_data_lines = [l for l in rust_lines if l.startswith("LINK_DATA:")]
            if rust_data_lines:
                print(f"  Rust LINK_DATA lines: {rust_data_lines}")
            failed += 1

        # 5. Link teardown
        rust_link_closed = any(l.startswith("LINK_CLOSED:") for l in rust_lines)
        if rust_link_closed:
            print("[link-init-interop] PASS [5/5]: Link teardown confirmed")
            passed += 1
        else:
            print("[link-init-interop] FAIL [5/5]: Rust did not receive LINK_CLOSED")
            failed += 1

    finally:
        print("[link-init-interop] cleaning up...")
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
    print(f"\n[link-init-interop] Results: {passed}/{total} passed, {failed}/{total} failed")

    if failed > 0:
        sys.exit(1)
    else:
        print("[link-init-interop] ALL TESTS PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
