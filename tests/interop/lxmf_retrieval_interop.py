#!/usr/bin/env python3
"""LXMF propagation retrieval interop test: Python deposits then retrieves from Rust propagation node.

Topology:
  rnsd (transport=yes, TCP server on localhost:4289)
  Rust node connects as TCP client (--propagation --lxmf-name PropNode)
  Python client connects, deposits 1 LXMF message, then retrieves it via link.request

Flow:
  1. Start rnsd + Rust propagation node
  2. Python links to Rust, deposits 1 LXMF message via Resource, tears down link
  3. Wait for PROP_DEPOSIT on Rust
  4. Python opens a NEW link to Rust's propagation destination
  5. Python sends link.request("/lxmf/propagation/retrieve", dest_hash)
  6. Rust handles request, sends count as response, sends message as Resource
  7. Python receives response + message
  8. Assert received message matches deposited message

Usage:
  cd tests/interop
  uv run python lxmf_retrieval_interop.py --rust-binary ../../target/debug/rete
"""

import os
import subprocess
import sys
import threading
import time

from interop_helpers import InteropTest


def main():
    with InteropTest("lxmf-retrieval", default_port=4289, default_timeout=60.0) as t:
        try:
            import RNS
            import LXMF
        except ImportError:
            print("SKIP: LXMF/RNS Python packages not installed")
            print("  Install with: pip install rns lxmf")
            sys.exit(0)

        # --- Start rnsd ---
        rnsd_proc = t.start_rnsd()
        time.sleep(1)

        # --- Start Rust propagation node ---
        rust = t.start_rust(
            extra_args=["--propagation", "--lxmf-name", "PropNode"],
        )

        # Read Rust stderr to get the propagation dest hash
        rust_stderr_lines = []
        stop = threading.Event()
        def read_stderr():
            while not stop.is_set():
                if t._rust_proc and t._rust_proc.stderr:
                    line = t._rust_proc.stderr.readline()
                    if not line:
                        break
                    rust_stderr_lines.append(line.decode(errors="replace").rstrip("\n"))
        stderr_thread = threading.Thread(target=read_stderr, daemon=True)
        stderr_thread.start()

        # Wait for Rust to start up and emit the propagation hash
        time.sleep(3)

        # Extract propagation dest hash from Rust stderr
        prop_hash = None
        for line in rust_stderr_lines:
            if "LXMF propagation hash:" in line:
                prop_hash = line.split(":")[-1].strip()
                break

        t.check(
            prop_hash is not None and len(prop_hash) == 32,
            "Rust propagation dest hash found in stderr",
            detail=f"prop_hash={prop_hash}" if prop_hash else "not found",
        )

        if not prop_hash:
            print("[lxmf-retrieval] Cannot continue without propagation hash")
            return

        # --- Single Python process: deposit then retrieve ---
        py = t.start_py_helper(f"""\
import RNS
import time
import sys
import os
import struct
import hashlib
import threading
import traceback
import bz2

config_dir = os.path.join("{t.tmpdir}", "py_client_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config()}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

try:
    # Create identities
    sender_identity = RNS.Identity()
    receiver_identity = RNS.Identity()

    # Compute the receiver's lxmf.delivery dest hash
    receiver_lxmf_dest = RNS.Destination(
        receiver_identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        "lxmf",
        "delivery",
    )
    receiver_dest_hash = receiver_lxmf_dest.hash
    print(f"PY_RECEIVER_DEST_HASH:{{receiver_dest_hash.hex()}}", flush=True)

    # Wait for Rust propagation announce
    prop_dest_bytes = bytes.fromhex("{prop_hash}")
    deadline = time.time() + {t.timeout}

    print("PY_WAITING_FOR_PROP_ANNOUNCE", flush=True)
    while time.time() < deadline:
        if RNS.Transport.has_path(prop_dest_bytes):
            break
        time.sleep(0.5)
    else:
        print("PY_FAIL:prop_announce_timeout", flush=True)
        sys.exit(1)

    print("PY_PROP_ANNOUNCE_RECEIVED", flush=True)

    prop_identity = RNS.Identity.recall(prop_dest_bytes)
    if not prop_identity:
        print("PY_FAIL:identity_not_recalled", flush=True)
        sys.exit(1)

    prop_dest = RNS.Destination(
        prop_identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        "lxmf",
        "propagation",
    )

    # ===== PHASE 1: DEPOSIT =====

    link1_established = threading.Event()
    def link1_cb(link):
        print(f"PY_DEPOSIT_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
        link1_established.set()

    print("PY_DEPOSIT_LINK_INITIATING", flush=True)
    link1 = RNS.Link(prop_dest, established_callback=link1_cb)

    if not link1_established.wait(timeout=20):
        print(f"PY_FAIL:deposit_link_timeout:status={{link1.status}}", flush=True)
        sys.exit(1)

    # Build LXMF message
    source_hash = sender_identity.hash[:16]
    timestamp = time.time()
    title = b"RetrieveTest"
    content = b"Retrieval test message from Python"

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
    print(f"PY_LXMF_PACKED:{{len(packed)}}", flush=True)

    resource_sent = threading.Event()
    def resource_cb(resource):
        print(f"PY_RESOURCE_SENT:{{resource.hash.hex()}}", flush=True)
        resource_sent.set()

    resource = RNS.Resource(packed, link1, callback=resource_cb)
    if not resource_sent.wait(timeout=30):
        print("PY_FAIL:resource_send_timeout", flush=True)
        sys.exit(1)

    print("PY_DEPOSIT_DONE", flush=True)

    # Teardown deposit link and wait
    time.sleep(2)
    link1.teardown()
    time.sleep(3)

    # ===== PHASE 2: RETRIEVE =====

    link2_established = threading.Event()
    received_resources = []
    received_response = threading.Event()
    response_data = [None]

    def link2_cb(link):
        print(f"PY_RETRIEVE_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
        link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
        link.set_resource_started_callback(resource_started_cb)
        link.set_resource_concluded_callback(resource_concluded_cb)
        link2_established.set()

    def resource_started_cb(resource):
        print(f"PY_RETRIEVE_RESOURCE_STARTED:{{resource.hash.hex()}}:{{resource.total_size}}", flush=True)

    def resource_concluded_cb(resource):
        if resource.status == RNS.Resource.COMPLETE:
            data = resource.data.read()
            print(f"PY_RETRIEVE_RESOURCE_COMPLETE:{{resource.hash.hex()}}:{{len(data)}}", flush=True)
            try:
                decompressed = bz2.decompress(data)
                data = decompressed
                print(f"PY_RETRIEVE_RESOURCE_DECOMPRESSED:{{len(data)}}", flush=True)
            except Exception:
                print("PY_RETRIEVE_RESOURCE_NOT_BZ2", flush=True)
            if len(data) >= 96:
                dest = data[:16]
                print(f"PY_RETRIEVE_MSG_DEST:{{dest.hex()}}", flush=True)
                if dest == receiver_dest_hash:
                    print("PY_RETRIEVE_MSG_DEST_MATCH", flush=True)
                received_resources.append(data)
            else:
                print(f"PY_RETRIEVE_DATA_TOO_SHORT:{{len(data)}}", flush=True)
        else:
            print(f"PY_RETRIEVE_RESOURCE_FAILED:{{resource.status}}", flush=True)

    print("PY_RETRIEVE_LINK_INITIATING", flush=True)
    link2 = RNS.Link(prop_dest, established_callback=link2_cb)

    if not link2_established.wait(timeout=20):
        print(f"PY_FAIL:retrieve_link_timeout:status={{link2.status}}", flush=True)
        sys.exit(1)

    print("PY_RETRIEVE_LINK_ACTIVE", flush=True)

    # Send retrieval request
    def response_callback(request_receipt):
        if request_receipt.response is not None:
            response_data[0] = request_receipt.response
            resp = request_receipt.response
            print(f"PY_RESPONSE_RECEIVED:{{len(resp) if isinstance(resp, (bytes, bytearray)) else resp}}", flush=True)
        else:
            print("PY_RESPONSE_NONE", flush=True)
        received_response.set()

    def failed_callback(request_receipt):
        print(f"PY_REQUEST_FAILED:{{request_receipt.status}}", flush=True)
        received_response.set()

    print(f"PY_SENDING_REQUEST:dest_hash={{receiver_dest_hash.hex()}}", flush=True)
    receipt = link2.request(
        "/lxmf/propagation/retrieve",
        receiver_dest_hash,
        response_callback=response_callback,
        failed_callback=failed_callback,
    )
    print("PY_REQUEST_SENT", flush=True)

    # Wait for response
    if received_response.wait(timeout={t.timeout}):
        print(f"PY_RESPONSE_OK:{{response_data[0]}}", flush=True)
    else:
        print("PY_RESPONSE_TIMEOUT", flush=True)

    # Wait for resource(s) to arrive
    resource_deadline = time.time() + {t.timeout}
    while time.time() < resource_deadline:
        if len(received_resources) >= 1:
            break
        time.sleep(0.5)

    print(f"PY_RECEIVED_RESOURCES:{{len(received_resources)}}", flush=True)

    time.sleep(2)
    link2.teardown()
    time.sleep(2)

except Exception as e:
    print(f"PY_ERROR:{{type(e).__name__}}:{{e}}", flush=True)
    traceback.print_exc()

print("PY_DONE", flush=True)
""")

        # Wait for completion
        t.wait_for_line(py, "PY_DONE", timeout=t.timeout + 30)
        time.sleep(3)

        # Collect output
        stop.set()
        rust_stderr = t.collect_rust_stderr(last_chars=4000)
        t.dump_output("Python output", py)
        t.dump_output("Rust node stdout", rust)
        t.dump_output("Rust node stderr", rust_stderr_lines[-50:])

        # Dump rnsd stderr for debugging
        try:
            rnsd_proc.terminate()
            rnsd_out, rnsd_err = rnsd_proc.communicate(timeout=5)
            rnsd_err_str = rnsd_err.decode(errors="replace") if rnsd_err else ""
            # Look for link-related messages
            link_lines = [l for l in rnsd_err_str.split("\n") if "ink" in l.lower() or "close" in l.lower() or "tear" in l.lower()]
            if link_lines:
                t.dump_output("rnsd link-related stderr", link_lines[-30:])
        except Exception:
            pass

        # --- Assertions ---

        t.check(
            t.has_line(py, "PY_PROP_ANNOUNCE_RECEIVED"),
            "Propagation announce received by Python",
        )

        t.check(
            t.has_line(py, "PY_DEPOSIT_DONE"),
            "Message deposited successfully",
        )

        t.check(
            t.has_line(rust, "PROP_DEPOSIT:"),
            "Rust confirmed deposit (PROP_DEPOSIT)",
        )

        t.check(
            t.has_line(py, "PY_RETRIEVE_LINK_ACTIVE"),
            "Retrieval link established",
        )

        t.check(
            t.has_line(py, "PY_REQUEST_SENT"),
            "Retrieval request sent",
        )

        t.check(
            t.has_line(rust, "PROP_RETRIEVAL_REQUEST:"),
            "Rust handled retrieval request (PROP_RETRIEVAL_REQUEST)",
        )

        t.check(
            t.has_line(py, "PY_RESPONSE_OK:") or t.has_line(py, "PY_RESPONSE_RECEIVED:"),
            "Response received by Python",
        )

        t.check(
            t.has_line(py, "PY_RECEIVED_RESOURCES:1"),
            "Python received 1 LXMF message as Resource",
        )

        t.check(
            t.has_line(py, "PY_RETRIEVE_MSG_DEST_MATCH"),
            "Received message dest hash matches expected",
        )


if __name__ == "__main__":
    main()
