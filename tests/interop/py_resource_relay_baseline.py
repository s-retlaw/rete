#!/usr/bin/env python3
"""Python-to-Python baseline: resource transfer through an rnsd relay.

Topology:
  Python-A (initiator) <-TCP-> rnsd (transport=yes) <-TCP-> Python-B (responder)

No Rust involved -- establishes ground truth for resource transfers through a relay.

Python-B runs as a subprocess (RNS can only be initialized once per process).
The main process runs Python-A and orchestrates the test.

Phases:
  1. Python-B announces, Python-A discovers it
  2. Python-A establishes link through rnsd
  3. Python-A sends small resource (~200 bytes), verifies completion + content
  4. Python-A sends larger resource (~2KB), verifies completion + content
  5. Link closes cleanly

Usage:
  cd tests/interop
  uv run python py_resource_relay_baseline.py [--port 4265] [--timeout 60]
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

from interop_helpers import write_rnsd_config, wait_for_port, read_stdout_lines

APP_NAME = "rete"
ASPECTS = ["example", "v1"]
DEFAULT_PORT = 4265
DEFAULT_TIMEOUT = 60

# Python-B responder script -- runs as subprocess
PY_B_SCRIPT = r'''
import os
import sys
import time

import RNS

APP_NAME = "rete"
ASPECTS = ["example", "v1"]

config_dir = sys.argv[1]
port = int(sys.argv[2])

def log(msg):
    print(f"PYB:{msg}", flush=True)

# Write config
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as f:
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

rns = RNS.Reticulum(configdir=config_dir, loglevel=RNS.LOG_VERBOSE)
time.sleep(1.0)

identity = RNS.Identity()
dest = RNS.Destination(
    identity, RNS.Destination.IN, RNS.Destination.SINGLE,
    APP_NAME, *ASPECTS,
)

link_ref = [None]

def link_closed_cb(link):
    log(f"LINK_CLOSED:{link.link_id.hex()}")

def inbound_link_cb(link):
    log(f"LINK_ESTABLISHED:{link.link_id.hex()}")
    link_ref[0] = link
    link.set_link_closed_callback(link_closed_cb)
    link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
    link.set_resource_started_callback(resource_started_cb)
    link.set_resource_concluded_callback(resource_concluded_cb)

def resource_started_cb(resource):
    log(f"RESOURCE_STARTED:{resource.hash.hex()}:{resource.total_size}")

def resource_concluded_cb(resource):
    status_map = {0x06: "COMPLETE", 0x07: "FAILED", 0x08: "CORRUPT"}
    status_name = status_map.get(resource.status, f"status={resource.status}")
    log(f"RESOURCE_STATUS:{resource.hash.hex()}:{status_name}")
    if resource.status == RNS.Resource.COMPLETE:
        data = b""
        try:
            if hasattr(resource, "data") and resource.data is not None:
                if hasattr(resource.data, "read"):
                    data = resource.data.read()
                    resource.data.close()
                elif isinstance(resource.data, (bytes, bytearray)):
                    data = bytes(resource.data)
        except Exception as e:
            log(f"RESOURCE_READ_ERROR:{e}")
        log(f"RESOURCE_COMPLETE:{resource.hash.hex()}:{len(data)}:{data.hex()}")

dest.set_link_established_callback(inbound_link_cb)

dest.announce()
log(f"ANNOUNCED:{dest.hexhash}")

# Keep running until stdin closes or timeout
try:
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        cmd = line.strip()
        if cmd == "QUIT":
            break
except Exception:
    pass

if link_ref[0] and link_ref[0].status == RNS.Link.ACTIVE:
    link_ref[0].teardown()
    time.sleep(1.0)

RNS.Reticulum.exit_handler()
log("DONE")
'''


def main():
    parser = argparse.ArgumentParser(description="Python-to-Python resource relay baseline")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="TCP port for rnsd")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Test timeout in seconds")
    args = parser.parse_args()

    port = args.port
    timeout = args.timeout
    passed = 0
    failed = 0
    check_num = 0
    tmpdir = tempfile.mkdtemp(prefix="rete_py_resource_relay_baseline_")
    procs = []
    stop_event = threading.Event()

    def log(msg):
        print(f"[py-resource-relay-baseline] {msg}", flush=True)

    def check(condition, description, detail=None):
        nonlocal passed, failed, check_num
        check_num += 1
        if condition:
            log(f"PASS [{check_num}]: {description}")
            passed += 1
        else:
            log(f"FAIL [{check_num}]: {description}")
            if detail:
                print(f"  {detail}", flush=True)
            failed += 1

    def cleanup():
        log("cleaning up...")
        stop_event.set()
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

    def wait_for_pyb_line(pyb_lines, prefix, wait_timeout=None):
        """Poll pyb_lines for a line starting with prefix. Returns remainder after prefix + ':'."""
        deadline = time.time() + (wait_timeout or timeout)
        while time.time() < deadline:
            for line in pyb_lines:
                if line.startswith(prefix):
                    rest = line[len(prefix):]
                    if rest.startswith(":"):
                        rest = rest[1:]
                    return rest.strip()
            time.sleep(0.3)
        return None

    def has_pyb_line(pyb_lines, prefix, contains=None):
        for line in pyb_lines:
            if line.startswith(prefix):
                if contains is None or contains in line:
                    return True
        return False

    try:
        # --- Start rnsd transport relay ---
        log("starting rnsd transport relay...")
        rnsd_config_dir = os.path.join(tmpdir, "rnsd_config")
        write_rnsd_config(rnsd_config_dir, port)

        rnsd_proc = subprocess.Popen(
            [sys.executable, "-m", "RNS.Utilities.rnsd", "--config", rnsd_config_dir],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        procs.append(rnsd_proc)

        if not wait_for_port("127.0.0.1", port, timeout=15.0):
            log(f"FAIL: rnsd did not start on port {port} within 15s")
            if rnsd_proc.poll() is not None:
                err = rnsd_proc.stderr.read().decode(errors="replace")
                print(f"  rnsd stderr:\n{err}")
            cleanup()
            sys.exit(1)
        log("rnsd is listening")

        # --- Start Python-B (responder) as subprocess ---
        log("starting Python-B (responder) subprocess...")
        pyb_script_path = os.path.join(tmpdir, "py_b_responder.py")
        with open(pyb_script_path, "w") as f:
            f.write(PY_B_SCRIPT)

        pyb_config_dir = os.path.join(tmpdir, "py_b_config")
        pyb_proc = subprocess.Popen(
            [sys.executable, pyb_script_path, pyb_config_dir, str(port)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        procs.append(pyb_proc)

        pyb_lines = []
        pyb_reader = threading.Thread(
            target=read_stdout_lines, args=(pyb_proc, pyb_lines, stop_event), daemon=True,
        )
        pyb_reader.start()

        # Wait for Python-B to announce
        announced = wait_for_pyb_line(pyb_lines, "PYB:ANNOUNCED", wait_timeout=20)
        if announced is None:
            log("FAIL: Python-B did not announce within 20s")
            cleanup()
            sys.exit(1)
        dest_b_hex = announced.strip()
        dest_b_hash = bytes.fromhex(dest_b_hex)
        log(f"Python-B announced: dest_hash={dest_b_hex}")

        # --- Initialize Python-A (initiator) in this process ---
        log("setting up Python-A (initiator)...")
        pya_config_dir = os.path.join(tmpdir, "py_a_config")
        os.makedirs(pya_config_dir, exist_ok=True)
        with open(os.path.join(pya_config_dir, "config"), "w") as f:
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

        rns_a = RNS.Reticulum(configdir=pya_config_dir, loglevel=RNS.LOG_VERBOSE)
        time.sleep(1.0)

        # --- Phase 1: Wait for Python-B's announce to reach Python-A ---
        log("=== Phase 1: Waiting for Python-B's announce ===")

        deadline = time.time() + timeout
        path_found = False
        while time.time() < deadline:
            if RNS.Transport.has_path(dest_b_hash):
                path_found = True
                break
            time.sleep(0.5)

        check(path_found, "Python-A discovered Python-B through relay")

        if not path_found:
            log("Cannot proceed without path to Python-B")
            RNS.Reticulum.exit_handler()
            cleanup()
            total = passed + failed
            print(f"\n[py-resource-relay-baseline] Results: {passed}/{total} passed, {failed}/{total} failed")
            sys.exit(1)

        hops = RNS.Transport.hops_to(dest_b_hash)
        log(f"Hops to Python-B: {hops}")

        # Recall identity and create outbound destination
        recalled_id = RNS.Identity.recall(dest_b_hash)
        if not recalled_id:
            log("FAIL: could not recall Python-B identity")
            RNS.Reticulum.exit_handler()
            cleanup()
            sys.exit(1)

        dest_b_out = RNS.Destination(
            recalled_id, RNS.Destination.OUT, RNS.Destination.SINGLE,
            APP_NAME, *ASPECTS,
        )

        # --- Phase 2: Establish link ---
        log("=== Phase 2: Establishing link through relay ===")

        link_a_established = threading.Event()
        link_a_closed = threading.Event()

        def link_a_established_cb(link):
            log(f"Python-A: link established id={link.link_id.hex()}")
            link_a_established.set()

        def link_a_closed_cb(link):
            log(f"Python-A: link closed id={link.link_id.hex()}")
            link_a_closed.set()

        link_a = RNS.Link(
            dest_b_out,
            established_callback=link_a_established_cb,
            closed_callback=link_a_closed_cb,
        )

        ok_a = link_a_established.wait(timeout=20)
        check(ok_a, "Link established (Python-A side)")

        # Also verify Python-B saw the link
        pyb_link = wait_for_pyb_line(pyb_lines, "PYB:LINK_ESTABLISHED", wait_timeout=10)
        check(pyb_link is not None, "Link established (Python-B side)")

        if not ok_a or pyb_link is None:
            log("Cannot proceed without link")
            RNS.Reticulum.exit_handler()
            cleanup()
            total = passed + failed
            print(f"\n[py-resource-relay-baseline] Results: {passed}/{total} passed, {failed}/{total} failed")
            sys.exit(1)

        # Allow LRRTT handshake to stabilize
        time.sleep(2.0)

        # --- Phase 3: Small resource (~200 bytes) ---
        log("=== Phase 3: Small resource transfer (~200 bytes) ===")

        small_data = b"small-resource-payload:" + (b"A" * 170)
        log(f"Small resource size: {len(small_data)} bytes")

        small_complete = threading.Event()

        def small_resource_cb(resource):
            status_map = {0x06: "COMPLETE", 0x07: "FAILED", 0x08: "CORRUPT"}
            status_name = status_map.get(resource.status, f"status={resource.status}")
            log(f"Python-A: small resource concluded status={status_name}")
            if resource.status == RNS.Resource.COMPLETE:
                small_complete.set()

        small_resource = RNS.Resource(small_data, link_a, callback=small_resource_cb)
        log(f"Small resource initiated: hash={small_resource.hash.hex()}")

        ok = small_complete.wait(timeout=30)
        check(ok, "Small resource transfer completed (sender callback)")

        # Wait for Python-B to report receipt
        time.sleep(2.0)

        # Find the RESOURCE_COMPLETE line for the small resource
        small_data_hex = small_data.hex()
        small_received = has_pyb_line(pyb_lines, "PYB:RESOURCE_COMPLETE", contains=small_data_hex)
        check(small_received, "Small resource received by Python-B with correct data",
              detail=f"looking for {len(small_data)} bytes in PYB output")

        # --- Phase 4: Larger resource (~2KB) ---
        log("=== Phase 4: Larger resource transfer (~2KB) ===")

        large_data = b"large-resource-payload:" + (b"B" * 2000)
        log(f"Large resource size: {len(large_data)} bytes")

        large_complete = threading.Event()

        def large_resource_cb(resource):
            status_map = {0x06: "COMPLETE", 0x07: "FAILED", 0x08: "CORRUPT"}
            status_name = status_map.get(resource.status, f"status={resource.status}")
            log(f"Python-A: large resource concluded status={status_name}")
            if resource.status == RNS.Resource.COMPLETE:
                large_complete.set()

        large_resource = RNS.Resource(large_data, link_a, callback=large_resource_cb)
        log(f"Large resource initiated: hash={large_resource.hash.hex()}")

        ok = large_complete.wait(timeout=30)
        check(ok, "Large resource transfer completed (sender callback)")

        # Wait for Python-B to report receipt
        time.sleep(2.0)

        large_data_hex = large_data.hex()
        large_received = has_pyb_line(pyb_lines, "PYB:RESOURCE_COMPLETE", contains=large_data_hex)
        check(large_received, "Large resource received by Python-B with correct data",
              detail=f"looking for {len(large_data)} bytes in PYB output")

        # --- Phase 5: Clean link teardown ---
        log("=== Phase 5: Link teardown ===")

        link_a.teardown()
        time.sleep(2.0)

        link_closed_a = link_a_closed.is_set() or link_a.status == RNS.Link.CLOSED
        check(link_closed_a, "Link closed cleanly (Python-A)")

        # Check Python-B saw the close
        pyb_closed = has_pyb_line(pyb_lines, "PYB:LINK_CLOSED")
        # Give it a moment if not yet seen
        if not pyb_closed:
            time.sleep(2.0)
            pyb_closed = has_pyb_line(pyb_lines, "PYB:LINK_CLOSED")
        check(pyb_closed, "Link closed cleanly (Python-B)")

        # Tell Python-B to quit
        try:
            pyb_proc.stdin.write(b"QUIT\n")
            pyb_proc.stdin.flush()
        except Exception:
            pass

        # Shutdown RNS
        RNS.Reticulum.exit_handler()

        # Dump Python-B output for diagnostics
        log("Python-B output:")
        for line in pyb_lines:
            if line.strip():
                print(f"  {line}", flush=True)

    except Exception as e:
        log(f"EXCEPTION: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        failed += 1
    finally:
        cleanup()

    total = passed + failed
    print(f"\n[py-resource-relay-baseline] Results: {passed}/{total} passed, {failed}/{total} failed")
    if failed > 0:
        sys.exit(1)
    else:
        log("ALL TESTS PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
