#!/usr/bin/env python3
"""Channel E2E interop test: Python client sends Channel messages to Rust node via Link.

Topology:
  rnsd (transport=yes, TCP server on localhost:4245)
  Rust node connects as TCP client to rnsd
  Python client connects as TCP client to rnsd
  Python discovers Rust via announce, establishes a Link, then sends Channel messages

Assertions:
  1. Link established (both sides)
  2. Python sends channel message, Rust receives CHANNEL_MSG
  3. Second channel message also received
  4. Link teardown works

Usage:
  cd tests/interop
  uv run python channel_interop.py --rust-binary ../../target/debug/rete-linux

Or build first:
  cargo build -p rete-example-linux
  cd tests/interop && uv run python channel_interop.py
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


def write_rnsd_config(config_dir: str, port: int = 4245) -> str:
    """Write a minimal rnsd config file. Returns the config dir path."""
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


def read_stdout_lines(proc, lines, stop_event):
    """Read stdout lines from a subprocess into a list."""
    while not stop_event.is_set():
        line = proc.stdout.readline()
        if not line:
            break
        lines.append(line.decode(errors="replace").rstrip("\n"))


def main():
    parser = argparse.ArgumentParser(description="rete channel interop test")
    parser.add_argument(
        "--rust-binary",
        default="../../target/debug/rete-linux",
        help="Path to the rete-linux binary",
    )
    parser.add_argument(
        "--port", type=int, default=4245, help="TCP port for rnsd"
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

    tmpdir = tempfile.mkdtemp(prefix="rete_channel_interop_")
    rnsd_config_dir = os.path.join(tmpdir, "rnsd_config")
    procs = []
    passed = 0
    failed = 0
    stop_event = threading.Event()

    try:
        # --- Step 1: Start rnsd ---
        print(f"[channel-interop] setting up rnsd config in {rnsd_config_dir}")
        write_rnsd_config(rnsd_config_dir, args.port)

        print(f"[channel-interop] starting rnsd on port {args.port}...")
        rnsd_proc = subprocess.Popen(
            [sys.executable, "-m", "RNS.Utilities.rnsd", "--config", rnsd_config_dir],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(rnsd_proc)

        if not wait_for_port("127.0.0.1", args.port, timeout=15.0):
            print("[channel-interop] FAIL: rnsd did not start listening within 15s")
            if rnsd_proc.poll() is not None:
                stderr = rnsd_proc.stderr.read().decode(errors="replace")
                print(f"  rnsd stderr:\n{stderr}")
            sys.exit(1)
        print("[channel-interop] rnsd is listening")

        # --- Step 2: Start Rust node ---
        print("[channel-interop] starting Rust node...")
        rust_proc = subprocess.Popen(
            [
                rust_binary,
                "--connect", f"127.0.0.1:{args.port}",
                "--identity-seed", "channel-interop-test-seed-88",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(rust_proc)

        # Start thread to collect Rust stdout
        rust_lines = []
        rust_reader = threading.Thread(
            target=read_stdout_lines, args=(rust_proc, rust_lines, stop_event)
        )
        rust_reader.daemon = True
        rust_reader.start()

        # Give the Rust node time to connect and send its announce
        time.sleep(3)

        # --- Step 3: Write and start Python client helper ---
        py_helper = os.path.join(tmpdir, "py_channel_client.py")
        with open(py_helper, "w") as f:
            f.write(f"""\
import RNS
import RNS.Channel
import time
import sys
import os
import threading

# Create a Reticulum config that connects as a TCP client
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
    target_port = {args.port}
\"\"\")

# Initialize
reticulum = RNS.Reticulum(configdir=config_dir)

# Define custom message types for testing
class TestMessage(RNS.Channel.MessageBase):
    MSGTYPE = 0x0100
    def __init__(self):
        self.data = b""
    def pack(self):
        return self.data
    def unpack(self, raw):
        self.data = raw

class TestMessage2(RNS.Channel.MessageBase):
    MSGTYPE = 0x0200
    def __init__(self):
        self.data = b""
    def pack(self):
        return self.data
    def unpack(self, raw):
        self.data = raw

# Track link events
link_established = threading.Event()
link_closed = threading.Event()
active_link = [None]

def link_established_cb(link):
    print(f"PY_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
    active_link[0] = link
    link_established.set()

def link_closed_cb(link):
    print(f"PY_LINK_CLOSED:{{link.link_id.hex()}}", flush=True)
    link_closed.set()

# Wait for Rust announce to appear
timeout = {args.timeout}
deadline = time.time() + timeout
rust_dest_hash = None

print("PY_WAITING_FOR_ANNOUNCE", flush=True)

while time.time() < deadline:
    known = RNS.Transport.path_table
    for h in known:
        rust_dest_hash = h
        print(f"PY_DISCOVERED:{{h.hex()}}", flush=True)
        break
    if rust_dest_hash:
        break
    time.sleep(0.5)

if not rust_dest_hash:
    print("PY_FAIL:timeout_waiting_for_rust_announce", flush=True)
    sys.exit(1)

# Recall identity and create destination for Rust node
rust_identity = RNS.Identity.recall(rust_dest_hash)
if not rust_identity:
    print("PY_FAIL:identity_not_recalled", flush=True)
    sys.exit(1)

rust_dest = RNS.Destination(
    rust_identity,
    RNS.Destination.OUT,
    RNS.Destination.SINGLE,
    "rete",
    "example",
    "v1",
)

print(f"PY_RUST_DEST_HASH:{{rust_dest.hexhash}}", flush=True)

# Establish link to Rust node
print("PY_INITIATING_LINK", flush=True)
link = RNS.Link(rust_dest, established_callback=link_established_cb, closed_callback=link_closed_cb)

# Wait for link establishment
if not link_established.wait(timeout=15):
    print(f"PY_LINK_TIMEOUT:status={{link.status}}", flush=True)
    sys.exit(1)

print("PY_LINK_ACTIVE", flush=True)

# Get the channel and register message types
channel = link.get_channel()
channel.register_message_type(TestMessage)
channel.register_message_type(TestMessage2)

# Send first channel message (MSGTYPE 0x0100)
msg1 = TestMessage()
msg1.data = b"channel msg from python"
channel.send(msg1)
print("PY_CHANNEL_MSG1_SENT:0x0100", flush=True)

# Wait for delivery
time.sleep(3)

# Send second channel message (MSGTYPE 0x0200)
msg2 = TestMessage2()
msg2.data = b"second channel message"
channel.send(msg2)
print("PY_CHANNEL_MSG2_SENT:0x0200", flush=True)

# Wait for delivery
time.sleep(3)

# Teardown the link
link.teardown()
print("PY_LINK_TEARDOWN_SENT", flush=True)

# Wait for teardown to propagate
time.sleep(2)

print("PY_DONE", flush=True)
""")

        print("[channel-interop] starting Python client...")
        py_proc = subprocess.Popen(
            [sys.executable, py_helper],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(py_proc)

        # --- Step 4: Collect results ---
        print(f"[channel-interop] waiting up to {args.timeout}s for results...")

        # Wait for Python helper to complete
        try:
            py_stdout, py_stderr = py_proc.communicate(timeout=args.timeout + 15)
        except subprocess.TimeoutExpired:
            py_proc.kill()
            py_stdout, py_stderr = py_proc.communicate()

        py_output = py_stdout.decode(errors="replace")
        py_err_output = py_stderr.decode(errors="replace")

        print("[channel-interop] Python helper output:")
        for line in py_output.strip().split("\n"):
            print(f"  {line}")

        # Give the Rust node a moment to finish processing
        time.sleep(2)

        # Stop reader, terminate Rust node, collect remaining output
        stop_event.set()
        rust_proc.send_signal(signal.SIGTERM)
        try:
            _, rust_stderr = rust_proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            rust_proc.kill()
            _, rust_stderr = rust_proc.communicate()

        rust_err_output = rust_stderr.decode(errors="replace")

        print("[channel-interop] Rust node stdout:")
        for line in rust_lines:
            if line.strip():
                print(f"  {line}")

        print("[channel-interop] Rust node stderr (last 1000 chars):")
        for line in rust_err_output[-1000:].strip().split("\n"):
            if line.strip():
                print(f"  {line}")

        # --- Assertion 1: Link established (both sides) ---
        rust_link_established = any(l.startswith("LINK_ESTABLISHED:") for l in rust_lines)
        py_link_ok = "PY_LINK_ACTIVE" in py_output

        if rust_link_established and py_link_ok:
            print("[channel-interop] PASS [1/4]: Link established (both sides)")
            passed += 1
        elif rust_link_established:
            print("[channel-interop] FAIL [1/4]: Link established on Rust but Python timed out")
            print("  This may indicate LRPROOF routing through rnsd is not working.")
            failed += 1
        elif py_link_ok:
            print("[channel-interop] FAIL [1/4]: Link established on Python but not Rust")
            failed += 1
        else:
            print("[channel-interop] FAIL [1/4]: Link not established on either side")
            failed += 1

        # --- Assertion 2: First channel message received by Rust ---
        rust_channel_msgs = [l for l in rust_lines if l.startswith("CHANNEL_MSG:")]

        first_msg_ok = any("channel msg from python" in l and "0x0100" in l
                           for l in rust_channel_msgs)
        if first_msg_ok:
            print("[channel-interop] PASS [2/4]: Rust received first channel message (type=0x0100)")
            passed += 1
        else:
            print("[channel-interop] FAIL [2/4]: Rust did not receive first channel message")
            if rust_channel_msgs:
                print(f"  Rust CHANNEL_MSG lines: {rust_channel_msgs}")
            elif not (rust_link_established and py_link_ok):
                print("  (link was not established on both sides)")
            failed += 1

        # --- Assertion 3: Second channel message received by Rust ---
        second_msg_ok = any("second channel message" in l and "0x0200" in l
                            for l in rust_channel_msgs)
        if second_msg_ok:
            print("[channel-interop] PASS [3/4]: Rust received second channel message (type=0x0200)")
            passed += 1
        else:
            print("[channel-interop] FAIL [3/4]: Rust did not receive second channel message")
            if rust_channel_msgs:
                print(f"  Rust CHANNEL_MSG lines: {rust_channel_msgs}")
            elif not (rust_link_established and py_link_ok):
                print("  (link was not established on both sides)")
            failed += 1

        # --- Assertion 4: Link teardown ---
        rust_link_closed = any(l.startswith("LINK_CLOSED:") for l in rust_lines)
        if rust_link_closed:
            print("[channel-interop] PASS [4/4]: Link teardown confirmed (Rust received LINK_CLOSED)")
            passed += 1
        else:
            print("[channel-interop] FAIL [4/4]: Rust did not receive link close")
            if not (rust_link_established and py_link_ok):
                print("  (link was not established on both sides)")
            failed += 1

    finally:
        # Cleanup
        print("[channel-interop] cleaning up...")
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
    print(f"\n[channel-interop] Results: {passed}/{total} passed, {failed}/{total} failed")

    if failed > 0:
        sys.exit(1)
    else:
        print("[channel-interop] ALL TESTS PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
