#!/usr/bin/env python3
"""Python-to-Python baseline: channel messages through an rnsd relay.

Topology:
  Python-A (initiator) <-TCP-> rnsd (transport=yes) <-TCP-> Python-B (responder)

This is a BASELINE test — no Rust involved.  It establishes ground truth
for how channel messages work through a relay using only the Python RNS
reference implementation.

Python-B runs as a subprocess (RNS uses singletons, so each node needs its
own process).  Python-A runs in the main process and drives assertions.

Phases:
  1. Start rnsd transport node
  2. Python-B (subprocess): create identity/destination, register TestMessage, announce
  3. Python-A (main): wait for announce, establish link through rnsd
  4. Python-B: send greeting on link established
  5. Python-A: receive greeting, send "relay-test-msg", wait for echo
  6. Verify link closes cleanly

Usage:
  cd tests/interop
  uv run python py_channel_relay_baseline.py [--port 4260] [--timeout 30]
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time

import RNS
import RNS.Channel

from interop_helpers import write_rnsd_config, wait_for_port

APP_NAME = "rete"
ASPECTS = ["example", "v1"]

# ---------------------------------------------------------------------------
# TestMessage — identical layout to the one used by rete and the ESP32 tests
# ---------------------------------------------------------------------------

class TestMessage(RNS.Channel.MessageBase):
    MSGTYPE = 0x0001

    def __init__(self, data=None):
        self.data = data or b""

    def pack(self):
        return self.data

    def unpack(self, raw):
        self.data = raw


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_client_config(config_dir, port):
    """Write a minimal RNS config that connects as a TCP client."""
    os.makedirs(config_dir, exist_ok=True)
    config_path = os.path.join(config_dir, "config")
    with open(config_path, "w") as f:
        f.write(f"""\
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
""")
    return config_dir


def log(msg):
    print(f"[py-channel-relay-baseline] {msg}", flush=True)


def read_stdout_lines(proc, lines, stop_event):
    """Read stdout lines from a subprocess into a list."""
    while not stop_event.is_set():
        line = proc.stdout.readline()
        if not line:
            break
        lines.append(line.decode(errors="replace").rstrip("\n"))


# ---------------------------------------------------------------------------
# Python-B responder script (runs as subprocess)
# ---------------------------------------------------------------------------

PYB_SCRIPT = r'''
import os
import sys
import time

import RNS
import RNS.Channel

APP_NAME = "rete"
ASPECTS = ["example", "v1"]

class TestMessage(RNS.Channel.MessageBase):
    MSGTYPE = 0x0001

    def __init__(self, data=None):
        self.data = data or b""

    def pack(self):
        return self.data

    def unpack(self, raw):
        self.data = raw

config_dir = sys.argv[1]

reticulum = RNS.Reticulum(configdir=config_dir, loglevel=RNS.LOG_VERBOSE)
time.sleep(1.0)

identity = RNS.Identity()
dest = RNS.Destination(
    identity, RNS.Destination.IN, RNS.Destination.SINGLE,
    APP_NAME, *ASPECTS,
)

print(f"PYB_DEST_HASH:{dest.hexhash}", flush=True)

# Track the active inbound link so the channel handler can echo on it
active_link = [None]

def channel_msg_handler(message):
    print(f"PYB_CHANNEL_RECV:{message.data!r}", flush=True)
    # Echo with "echo:" prefix
    if active_link[0] is not None:
        ch = active_link[0].get_channel()
        echo = TestMessage(b"echo:" + message.data)
        ch.send(echo)
        print(f"PYB_ECHO_SENT:echo:{message.data!r}", flush=True)

def link_closed_cb(link):
    print(f"PYB_LINK_CLOSED:{link.link_id.hex()}", flush=True)
    active_link[0] = None

def link_established_cb(link):
    print(f"PYB_LINK_ESTABLISHED:{link.link_id.hex()}", flush=True)
    active_link[0] = link

    # Set close callback on the link itself
    link.set_link_closed_callback(link_closed_cb)

    # Register channel handler on the inbound link
    ch = link.get_channel()
    ch.register_message_type(TestMessage)
    ch.add_message_handler(channel_msg_handler)

    # Send greeting
    greeting = TestMessage(b"py-b-hello")
    ch.send(greeting)
    print("PYB_GREETING_SENT:py-b-hello", flush=True)

dest.set_link_established_callback(link_established_cb)

# Announce
dest.announce()
print("PYB_ANNOUNCED", flush=True)

# Keep running until stdin closes or parent kills us
try:
    while True:
        time.sleep(0.5)
except (KeyboardInterrupt, EOFError):
    pass
finally:
    RNS.Reticulum.exit_handler()
'''


# ---------------------------------------------------------------------------
# Main test
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Python-to-Python baseline: channel messages through rnsd relay",
    )
    parser.add_argument("--port", type=int, default=4260,
                        help="TCP port for rnsd (default: 4260)")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="Test timeout in seconds (default: 30)")
    args = parser.parse_args()

    port = args.port
    timeout = args.timeout
    passed = 0
    failed = 0
    total_checks = 0
    tmpdir = tempfile.mkdtemp(prefix="rete_py_channel_relay_baseline_")
    rnsd_proc = None
    pyb_proc = None
    stop_event = threading.Event()

    def check(condition, description, detail=None):
        nonlocal passed, failed, total_checks
        total_checks += 1
        if condition:
            log(f"PASS [{total_checks}]: {description}")
            passed += 1
        else:
            log(f"FAIL [{total_checks}]: {description}")
            if detail:
                print(f"  {detail}", flush=True)
            failed += 1

    def wait_for_pyb_line(lines, prefix, wait_timeout=None):
        """Poll pyb lines for one starting with prefix. Returns value after ':'."""
        deadline = time.time() + (wait_timeout or timeout)
        while time.time() < deadline:
            for line in lines:
                if line.startswith(prefix):
                    _, _, value = line.partition(":")
                    return value.strip() if value else ""
            time.sleep(0.3)
        return None

    try:
        # === 1. Start rnsd transport node ===
        log("starting rnsd transport node...")
        rnsd_config = os.path.join(tmpdir, "rnsd_config")
        write_rnsd_config(rnsd_config, port)

        rnsd_proc = subprocess.Popen(
            [sys.executable, "-m", "RNS.Utilities.rnsd", "--config", rnsd_config],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

        if not wait_for_port("127.0.0.1", port, timeout=15.0):
            log("FAIL: rnsd did not start within 15 s")
            if rnsd_proc.poll() is not None:
                err = rnsd_proc.stderr.read().decode(errors="replace")
                print(f"  rnsd stderr:\n{err}", flush=True)
            sys.exit(1)
        log("rnsd is listening")

        # === 2. Start Python-B (responder) as subprocess ===
        log("starting Python-B (responder) subprocess...")
        pyb_config_dir = os.path.join(tmpdir, "pyb_config")
        _write_client_config(pyb_config_dir, port)

        pyb_script_path = os.path.join(tmpdir, "pyb_responder.py")
        with open(pyb_script_path, "w") as f:
            f.write(PYB_SCRIPT)

        pyb_proc = subprocess.Popen(
            [sys.executable, pyb_script_path, pyb_config_dir],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        pyb_lines = []
        pyb_reader = threading.Thread(
            target=read_stdout_lines, args=(pyb_proc, pyb_lines, stop_event),
            daemon=True,
        )
        pyb_reader.start()

        # Wait for Python-B to announce
        pyb_dest_hash_hex = wait_for_pyb_line(pyb_lines, "PYB_DEST_HASH")
        if pyb_dest_hash_hex is None:
            log("FAIL: Python-B did not start properly")
            sys.exit(1)
        log(f"Python-B dest hash: {pyb_dest_hash_hex}")

        announced = wait_for_pyb_line(pyb_lines, "PYB_ANNOUNCED")
        if announced is None:
            log("FAIL: Python-B did not announce")
            sys.exit(1)
        log("Python-B announced")

        # === 3. Create Python-A (initiator) in main process ===
        log("creating Python-A (initiator)...")
        pya_config_dir = os.path.join(tmpdir, "pya_config")
        _write_client_config(pya_config_dir, port)

        rns_a = RNS.Reticulum(configdir=pya_config_dir, loglevel=RNS.LOG_VERBOSE)
        time.sleep(1.0)

        id_a = RNS.Identity()

        # Wait for Python-B's announce (path discovery)
        log("Python-A waiting for Python-B announce...")
        dest_b_hash = bytes.fromhex(pyb_dest_hash_hex)
        deadline = time.time() + timeout
        path_found = False
        while time.time() < deadline:
            if RNS.Transport.has_path(dest_b_hash):
                path_found = True
                break
            time.sleep(0.5)

        check(path_found, "Python-A discovered Python-B via announce")

        if not path_found:
            log("Cannot proceed without path to Python-B")
            return

        # Recall Python-B's identity
        recalled_id = RNS.Identity.recall(dest_b_hash)
        check(recalled_id is not None, "Python-A recalled Python-B identity")

        if recalled_id is None:
            log("Cannot proceed without recalled identity")
            return

        # Build outbound destination to Python-B
        dest_b_out = RNS.Destination(
            recalled_id, RNS.Destination.OUT, RNS.Destination.SINGLE,
            APP_NAME, *ASPECTS,
        )

        # === 4. Establish link through rnsd ===
        log("Python-A establishing link to Python-B through rnsd...")
        link_established_event = threading.Event()
        link_closed_event = threading.Event()

        def pya_link_established(link):
            log(f"Python-A: link established ({link.link_id.hex()})")
            link_established_event.set()

        def pya_link_closed(link):
            log(f"Python-A: link closed ({link.link_id.hex()})")
            link_closed_event.set()

        link = RNS.Link(
            dest_b_out,
            established_callback=pya_link_established,
            closed_callback=pya_link_closed,
        )

        established = link_established_event.wait(timeout=timeout)
        check(established, "Link established through relay")

        if not established:
            log(f"Link status: {link.status}")
            return

        # Confirm Python-B also sees the link
        pyb_link_line = wait_for_pyb_line(pyb_lines, "PYB_LINK_ESTABLISHED", wait_timeout=10)
        check(pyb_link_line is not None, "Python-B confirmed link established")

        # === 5. Channel messaging ===
        log("setting up channel on Python-A side...")
        pya_received_msgs = []

        def pya_channel_msg_handler(message):
            log(f"Python-A received channel msg: {message.data!r}")
            pya_received_msgs.append(message.data)

        channel_a = link.get_channel()
        channel_a.register_message_type(TestMessage)
        channel_a.add_message_handler(pya_channel_msg_handler)

        # Wait for greeting from Python-B
        log("Python-A waiting for greeting from Python-B...")
        deadline = time.time() + timeout
        got_greeting = False
        while time.time() < deadline:
            if any(b"py-b-hello" in m for m in pya_received_msgs):
                got_greeting = True
                break
            time.sleep(0.3)

        check(got_greeting, "Greeting received from Python-B",
              detail=f"received {len(pya_received_msgs)} channel msgs: {pya_received_msgs!r}")

        # Send message and wait for echo
        log("Python-A sending channel message: relay-test-msg")
        msg = TestMessage(b"relay-test-msg")
        channel_a.send(msg)

        deadline = time.time() + timeout
        got_echo = False
        while time.time() < deadline:
            if any(b"echo:relay-test-msg" in m for m in pya_received_msgs):
                got_echo = True
                break
            time.sleep(0.3)

        check(got_echo, "Channel echo received through relay",
              detail=f"received {len(pya_received_msgs)} channel msgs: {pya_received_msgs!r}")

        # === 6. Teardown ===
        log("tearing down link...")
        link.teardown()
        closed = link_closed_event.wait(timeout=10.0)
        check(closed, "Link closed cleanly")

        # Confirm Python-B sees the link close too
        pyb_close_line = wait_for_pyb_line(pyb_lines, "PYB_LINK_CLOSED", wait_timeout=10)
        check(pyb_close_line is not None, "Python-B confirmed link closed")

    finally:
        # Cleanup
        log("cleaning up...")
        stop_event.set()
        try:
            RNS.Reticulum.exit_handler()
        except Exception:
            pass
        for proc in [pyb_proc, rnsd_proc]:
            if proc is not None:
                try:
                    proc.kill()
                    proc.wait(timeout=5)
                except Exception:
                    pass
        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass

        # Print summary
        total = passed + failed
        print(f"\n[py-channel-relay-baseline] Results: {passed}/{total} passed, {failed}/{total} failed",
              flush=True)
        if failed > 0:
            sys.exit(1)
        else:
            log("ALL TESTS PASSED")
            sys.exit(0)


if __name__ == "__main__":
    main()
