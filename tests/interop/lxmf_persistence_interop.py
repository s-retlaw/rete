#!/usr/bin/env python3
"""LXMF persistence interop test: messages survive Rust node restart.

Topology:
  rnsd (transport=yes, TCP server on localhost:4291)
  Rust node connects as TCP client (--propagation --lxmf-name PropNode)
  Python client connects, deposits, then retrieves after restart

Flow:
  1. Start rnsd + Rust propagation node (with --data-dir)
  2. Python deposits 1 LXMF message, wait for PROP_DEPOSIT
  3. SIGTERM Rust node, wait for clean exit
  4. Restart Rust node with SAME --data-dir
  5. Python opens new link, retrieves message via link.request
  6. Assert retrieved message matches deposited message

Assertions:
  1. PROP_DEPOSIT confirmed on first run
  2. Rust exits cleanly on SIGTERM
  3. Message retrieved after restart (file-backed store survives)
  4. Retrieved message dest hash matches expected

Usage:
  cd tests/interop
  uv run python lxmf_persistence_interop.py --rust-binary ../../target/debug/rete-linux
"""

import os
import signal
import subprocess
import sys
import threading
import time

from interop_helpers import InteropTest, read_stdout_lines


def main():
    with InteropTest("lxmf-persistence", default_port=4291, default_timeout=60.0) as t:
        try:
            import RNS
        except ImportError:
            print("SKIP: RNS Python package not installed")
            sys.exit(0)

        # --- Start rnsd ---
        rnsd_proc = t.start_rnsd()
        time.sleep(1)

        # Use a fixed data dir for both Rust runs
        rust_data_dir = os.path.join(t.tmpdir, "rete_persist_data")
        os.makedirs(rust_data_dir, exist_ok=True)

        # ============================================================
        # PHASE 1: Start Rust, deposit message, then stop
        # ============================================================

        rust_cmd = [
            t.rust_binary,
            "--data-dir", rust_data_dir,
            "--connect", f"127.0.0.1:{t.port}",
            "--propagation",
            "--lxmf-name", "PersistNode",
        ]

        t._log("Starting Rust node (first run)...")
        rust1 = subprocess.Popen(
            rust_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        t._procs.append(rust1)
        t._rust_proc = rust1

        rust1_stdout = []
        stop1 = threading.Event()
        threading.Thread(
            target=read_stdout_lines, args=(rust1, rust1_stdout, stop1), daemon=True
        ).start()

        rust1_stderr_lines = []
        def read_stderr1():
            while not stop1.is_set():
                if rust1.stderr:
                    line = rust1.stderr.readline()
                    if not line:
                        break
                    rust1_stderr_lines.append(line.decode(errors="replace").rstrip("\n"))
        threading.Thread(target=read_stderr1, daemon=True).start()

        time.sleep(3)

        # Extract propagation hash
        prop_hash = None
        for line in rust1_stderr_lines:
            if "LXMF propagation hash:" in line:
                prop_hash = line.split(":")[-1].strip()
                break

        t.check(
            prop_hash is not None and len(prop_hash) == 32,
            "Rust propagation dest hash found (run 1)",
            detail=f"prop_hash={prop_hash}" if prop_hash else "not found",
        )

        if not prop_hash:
            return

        # --- Python: deposit message ---
        py_deposit = t.start_py_helper(f"""\
import RNS
import time
import sys
import os
import struct
import hashlib
import threading
import traceback

config_dir = os.path.join("{t.tmpdir}", "py_deposit_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config()}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

try:
    sender_identity = RNS.Identity()
    receiver_identity = RNS.Identity()

    receiver_lxmf_dest = RNS.Destination(
        receiver_identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        "lxmf",
        "delivery",
    )
    receiver_dest_hash = receiver_lxmf_dest.hash
    print(f"PY_RECEIVER_DEST_HASH:{{receiver_dest_hash.hex()}}", flush=True)

    # Save receiver identity hash for retrieval phase
    with open(os.path.join("{t.tmpdir}", "receiver_dest_hash.txt"), "w") as f:
        f.write(receiver_dest_hash.hex())

    prop_dest_bytes = bytes.fromhex("{prop_hash}")
    deadline = time.time() + {t.timeout}

    while time.time() < deadline:
        if RNS.Transport.has_path(prop_dest_bytes):
            break
        time.sleep(0.5)
    else:
        print("PY_FAIL:prop_announce_timeout", flush=True)
        sys.exit(1)

    print("PY_PROP_ANNOUNCE_RECEIVED", flush=True)

    prop_identity = RNS.Identity.recall(prop_dest_bytes)
    prop_dest = RNS.Destination(
        prop_identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        "lxmf",
        "propagation",
    )

    link_established = threading.Event()
    def link_cb(link):
        print(f"PY_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
        link_established.set()

    link = RNS.Link(prop_dest, established_callback=link_cb)
    if not link_established.wait(timeout=20):
        print("PY_FAIL:link_timeout", flush=True)
        sys.exit(1)

    # Build LXMF message
    source_hash = sender_identity.hash[:16]
    timestamp = time.time()
    title = b"PersistTest"
    content = b"This message should survive a restart"

    payload = bytearray()
    payload.append(0x94)
    payload.append(0xcb)
    payload.extend(struct.pack(">d", timestamp))
    payload.append(0xc4)
    payload.append(len(title))
    payload.extend(title)
    payload.append(0xc4)
    payload.append(len(content))
    payload.extend(content)
    payload.append(0x80)

    hashed_part = receiver_dest_hash + source_hash + bytes(payload)
    msg_hash = hashlib.sha256(hashed_part).digest()
    sign_data = hashed_part + msg_hash
    signature = sender_identity.sign(sign_data)
    packed = receiver_dest_hash + source_hash + signature + bytes(payload)

    resource_sent = threading.Event()
    def resource_cb(resource):
        print(f"PY_RESOURCE_SENT:{{resource.hash.hex()}}", flush=True)
        resource_sent.set()

    resource = RNS.Resource(packed, link, callback=resource_cb)
    if not resource_sent.wait(timeout=30):
        print("PY_FAIL:resource_timeout", flush=True)
        sys.exit(1)

    print("PY_DEPOSIT_DONE", flush=True)
    time.sleep(2)
    link.teardown()
    time.sleep(2)

except Exception as e:
    print(f"PY_ERROR:{{type(e).__name__}}:{{e}}", flush=True)
    traceback.print_exc()

print("PY_DEPOSIT_SCRIPT_DONE", flush=True)
""")

        t.wait_for_line(py_deposit, "PY_DEPOSIT_SCRIPT_DONE", timeout=t.timeout + 10)
        time.sleep(2)

        t.check(
            t.has_line(py_deposit, "PY_DEPOSIT_DONE"),
            "Message deposited successfully (run 1)",
        )

        t.check(
            t.has_line(rust1_stdout, "PROP_DEPOSIT:"),
            "Rust confirmed deposit (PROP_DEPOSIT, run 1)",
        )

        # --- Stop Rust node 1 ---
        t._log("Stopping Rust node (SIGTERM)...")
        stop1.set()
        rust1.send_signal(signal.SIGTERM)
        try:
            rust1.wait(timeout=10)
            t.check(True, "Rust node exited cleanly on SIGTERM")
        except subprocess.TimeoutExpired:
            rust1.kill()
            rust1.wait()
            t.check(False, "Rust node exited cleanly on SIGTERM",
                    detail="had to SIGKILL")

        time.sleep(2)

        # ============================================================
        # PHASE 2: Restart Rust with same data-dir, retrieve message
        # ============================================================

        t._log("Starting Rust node (second run, same data-dir)...")
        rust2 = subprocess.Popen(
            rust_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        t._procs.append(rust2)
        t._rust_proc = rust2

        rust2_stdout = []
        stop2 = threading.Event()
        threading.Thread(
            target=read_stdout_lines, args=(rust2, rust2_stdout, stop2), daemon=True
        ).start()

        rust2_stderr_lines = []
        def read_stderr2():
            while not stop2.is_set():
                if rust2.stderr:
                    line = rust2.stderr.readline()
                    if not line:
                        break
                    rust2_stderr_lines.append(line.decode(errors="replace").rstrip("\n"))
        threading.Thread(target=read_stderr2, daemon=True).start()

        time.sleep(4)

        # Extract new propagation hash (should be same identity from data-dir)
        prop_hash2 = None
        for line in rust2_stderr_lines:
            if "LXMF propagation hash:" in line:
                prop_hash2 = line.split(":")[-1].strip()
                break

        t.check(
            prop_hash2 is not None,
            "Rust propagation hash found (run 2)",
            detail=f"prop_hash2={prop_hash2}" if prop_hash2 else "not found",
        )

        # Check file-backed store log
        file_store_log = any("file-backed store" in l for l in rust2_stderr_lines)
        t.check(file_store_log, "Rust reports file-backed store in use (run 2)")

        if not prop_hash2:
            return

        # Read the receiver dest hash saved by deposit script
        receiver_dest_hex = open(
            os.path.join(t.tmpdir, "receiver_dest_hash.txt")
        ).read().strip()

        # --- Python: retrieve message ---
        py_retrieve = t.start_py_helper(f"""\
import RNS
import time
import sys
import os
import threading
import traceback
import bz2

config_dir = os.path.join("{t.tmpdir}", "py_retrieve_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config()}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

try:
    prop_dest_bytes = bytes.fromhex("{prop_hash2}")
    receiver_dest_hash = bytes.fromhex("{receiver_dest_hex}")

    deadline = time.time() + {t.timeout}
    while time.time() < deadline:
        if RNS.Transport.has_path(prop_dest_bytes):
            break
        time.sleep(0.5)
    else:
        print("PY_FAIL:prop_announce_timeout_r2", flush=True)
        sys.exit(1)

    print("PY_PROP_ANNOUNCE_RECEIVED_R2", flush=True)

    prop_identity = RNS.Identity.recall(prop_dest_bytes)
    prop_dest = RNS.Destination(
        prop_identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        "lxmf",
        "propagation",
    )

    link_established = threading.Event()
    received_resources = []
    received_response = threading.Event()
    response_data = [None]

    def link_cb(link):
        print(f"PY_RETRIEVE_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
        link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
        link.set_resource_started_callback(resource_started_cb)
        link.set_resource_concluded_callback(resource_concluded_cb)
        link_established.set()

    def resource_started_cb(resource):
        print(f"PY_RESOURCE_STARTED:{{resource.hash.hex()}}", flush=True)

    def resource_concluded_cb(resource):
        if resource.status == RNS.Resource.COMPLETE:
            data = resource.data.read()
            try:
                data = bz2.decompress(data)
            except Exception:
                pass
            if len(data) >= 96:
                dest = data[:16]
                print(f"PY_RETRIEVED_MSG_DEST:{{dest.hex()}}", flush=True)
                if dest == receiver_dest_hash:
                    print("PY_DEST_MATCH", flush=True)
                received_resources.append(data)
            print(f"PY_RESOURCE_COMPLETE:{{len(data)}}", flush=True)
        else:
            print(f"PY_RESOURCE_FAILED:{{resource.status}}", flush=True)

    link = RNS.Link(prop_dest, established_callback=link_cb)
    if not link_established.wait(timeout=20):
        print("PY_FAIL:retrieve_link_timeout", flush=True)
        sys.exit(1)

    def response_callback(receipt):
        if receipt.response is not None:
            response_data[0] = receipt.response
            print(f"PY_RESPONSE_OK:{{receipt.response}}", flush=True)
        else:
            print("PY_RESPONSE_NONE", flush=True)
        received_response.set()

    def failed_callback(receipt):
        print(f"PY_REQUEST_FAILED:{{receipt.status}}", flush=True)
        received_response.set()

    link.request(
        "/lxmf/propagation/retrieve",
        receiver_dest_hash,
        response_callback=response_callback,
        failed_callback=failed_callback,
    )
    print("PY_REQUEST_SENT", flush=True)

    received_response.wait(timeout={t.timeout})

    resource_deadline = time.time() + {t.timeout}
    while time.time() < resource_deadline:
        if len(received_resources) >= 1:
            break
        time.sleep(0.5)

    print(f"PY_RECEIVED_RESOURCES:{{len(received_resources)}}", flush=True)

    time.sleep(2)
    link.teardown()
    time.sleep(2)

except Exception as e:
    print(f"PY_ERROR:{{type(e).__name__}}:{{e}}", flush=True)
    traceback.print_exc()

print("PY_RETRIEVE_SCRIPT_DONE", flush=True)
""")

        t.wait_for_line(py_retrieve, "PY_RETRIEVE_SCRIPT_DONE", timeout=t.timeout + 30)
        time.sleep(3)

        # Collect output
        stop2.set()
        t.dump_output("Rust run 1 stdout", rust1_stdout)
        t.dump_output("Rust run 1 stderr", rust1_stderr_lines[-30:])
        t.dump_output("Rust run 2 stdout", rust2_stdout)
        t.dump_output("Rust run 2 stderr", rust2_stderr_lines[-30:])
        t.dump_output("Python deposit output", py_deposit)
        t.dump_output("Python retrieve output", py_retrieve)

        # --- Assertions ---

        t.check(
            t.has_line(py_retrieve, "PY_PROP_ANNOUNCE_RECEIVED_R2"),
            "Propagation announce received after restart",
        )

        t.check(
            t.has_line(py_retrieve, "PY_REQUEST_SENT"),
            "Retrieval request sent after restart",
        )

        t.check(
            t.has_line(rust2_stdout, "PROP_RETRIEVAL_REQUEST:"),
            "Rust handled retrieval request after restart",
        )

        t.check(
            t.has_line(py_retrieve, "PY_RECEIVED_RESOURCES:1"),
            "Message retrieved after restart (persistence works!)",
        )

        t.check(
            t.has_line(py_retrieve, "PY_DEST_MATCH"),
            "Retrieved message dest hash matches expected",
        )


if __name__ == "__main__":
    main()
