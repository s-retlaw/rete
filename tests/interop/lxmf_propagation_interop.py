#!/usr/bin/env python3
"""LXMF propagation deposit interop test: Python deposits LXMF message to Rust propagation node.

Topology:
  rnsd (transport=yes, TCP server on localhost:4285)
  Rust node connects as TCP client (--propagation --lxmf-name PropNode)
  Python client connects as TCP client, discovers Rust prop node, deposits message

Assertions:
  1. Rust propagation announce received by Python
  2. Link to propagation node established
  3. Resource transfer completed (LXMF message deposited)
  4. Rust prints PROP_DEPOSIT confirming storage

Usage:
  cd tests/interop
  uv run python lxmf_propagation_interop.py --rust-binary ../../target/debug/rete
"""

import os
import subprocess
import sys
import threading
import time

from interop_helpers import InteropTest


def main():
    with InteropTest("lxmf-propagation", default_port=4285, default_timeout=60.0) as t:
        try:
            import RNS
            import LXMF
        except ImportError:
            print("SKIP: LXMF/RNS Python packages not installed")
            print("  Install with: pip install rns lxmf")
            sys.exit(0)

        # --- Start rnsd ---
        t.start_rnsd()
        time.sleep(1)

        # --- Start Rust propagation node ---
        rust = t.start_rust(
            extra_args=["--propagation", "--lxmf-name", "PropNode"],
        )

        # Read Rust stderr in a thread to extract propagation dest hash.
        # The binary prints: [rete] LXMF propagation hash: <hex>
        rust_stderr_lines = []
        stop_stderr = threading.Event()
        def read_stderr():
            while not stop_stderr.is_set():
                if t._rust_proc and t._rust_proc.stderr:
                    line = t._rust_proc.stderr.readline()
                    if not line:
                        break
                    rust_stderr_lines.append(line.decode(errors="replace").rstrip("\n"))
        stderr_thread = threading.Thread(target=read_stderr, daemon=True)
        stderr_thread.start()

        # Wait for Rust to emit the propagation dest hash
        time.sleep(4)

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
            print("[lxmf-propagation] Cannot continue without propagation hash")
            return

        # --- Python client: discover, link, deposit ---
        py = t.start_py_helper(f"""\
import RNS
import time
import sys
import os
import struct
import hashlib
import threading
import traceback

config_dir = os.path.join("{t.tmpdir}", "py_client_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config()}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

try:
    # Create a source identity
    py_identity = RNS.Identity()

    # Wait for Rust propagation announce
    prop_dest_bytes = bytes.fromhex("{prop_hash}")
    deadline = time.time() + {t.timeout}
    prop_found = False

    print("PY_WAITING_FOR_PROP_ANNOUNCE", flush=True)

    while time.time() < deadline:
        if RNS.Transport.has_path(prop_dest_bytes):
            prop_found = True
            break
        time.sleep(0.5)

    if not prop_found:
        print("PY_FAIL:prop_announce_timeout", flush=True)
        sys.exit(1)

    print("PY_PROP_ANNOUNCE_RECEIVED", flush=True)

    # Recall the propagation node's identity
    prop_identity = RNS.Identity.recall(prop_dest_bytes)
    if not prop_identity:
        print("PY_FAIL:identity_not_recalled", flush=True)
        sys.exit(1)

    print("PY_IDENTITY_RECALLED", flush=True)

    # Create destination for the propagation node
    prop_dest = RNS.Destination(
        prop_identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        "lxmf",
        "propagation",
    )

    print(f"PY_PROP_DEST:{{prop_dest.hexhash}}", flush=True)

    # Create Link to propagation node
    link_established = threading.Event()
    link_closed = threading.Event()

    def link_established_cb(link):
        print(f"PY_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
        link_established.set()

    def link_closed_cb(link):
        print(f"PY_LINK_CLOSED:{{link.link_id.hex()}}", flush=True)
        link_closed.set()

    print("PY_INITIATING_LINK", flush=True)
    link = RNS.Link(prop_dest, established_callback=link_established_cb, closed_callback=link_closed_cb)

    if not link_established.wait(timeout=20):
        print(f"PY_LINK_TIMEOUT:status={{link.status}}", flush=True)
        sys.exit(1)

    print("PY_LINK_ACTIVE", flush=True)

    # Build a raw LXMF message to deposit.
    # Format: dest_hash[16] || source_hash[16] || signature[64] || msgpack_payload
    # msgpack_payload: fixarray(4) + float64(timestamp) + bin(title) + bin(content) + fixmap(0)
    fake_dest_hash = hashlib.sha256(b"fake-recipient-01").digest()[:16]
    source_hash = py_identity.hash[:16]

    # msgpack payload: [timestamp, title, content, {{}}]
    timestamp = time.time()
    title = b"PropTest"
    content = b"Propagation test message"

    payload = bytearray()
    payload.append(0x94)  # fixarray(4)
    payload.append(0xcb)  # float64
    payload.extend(struct.pack(">d", timestamp))
    # title as bin8
    payload.append(0xc4)
    payload.append(len(title))
    payload.extend(title)
    # content as bin8
    payload.append(0xc4)
    payload.append(len(content))
    payload.extend(content)
    # empty fixmap
    payload.append(0x80)

    # Build the signing data: dest_hash + source_hash + payload + SHA256(dest_hash + source_hash + payload)
    hashed_part = fake_dest_hash + source_hash + bytes(payload)
    msg_hash = hashlib.sha256(hashed_part).digest()
    sign_data = hashed_part + msg_hash

    # Sign it
    signature = py_identity.sign(sign_data)

    # Build the full packed message
    packed = fake_dest_hash + source_hash + signature + bytes(payload)
    print(f"PY_LXMF_PACKED:{{len(packed)}}", flush=True)

    # Send the packed message as a Resource over the link
    resource_sent = threading.Event()

    def resource_complete_cb(resource):
        print(f"PY_RESOURCE_SENT:{{resource.hash.hex()}}:{{resource.total_size}}", flush=True)
        resource_sent.set()

    resource = RNS.Resource(packed, link, callback=resource_complete_cb)
    print(f"PY_RESOURCE_STARTED:{{resource.hash.hex()}}", flush=True)

    if not resource_sent.wait(timeout=30):
        print("PY_FAIL:resource_send_timeout", flush=True)
        sys.exit(1)

    print("PY_RESOURCE_TRANSFER_DONE", flush=True)

    # Give Rust time to process the deposit
    time.sleep(3)

    # Teardown
    link.teardown()
    time.sleep(2)

except Exception as e:
    print(f"PY_ERROR:{{type(e).__name__}}:{{e}}", flush=True)
    traceback.print_exc()

print("PY_DONE", flush=True)
""")

        # Wait for Python to finish
        t.wait_for_line(py, "PY_DONE", timeout=t.timeout + 15)
        time.sleep(2)

        # Stop stderr reader
        stop_stderr.set()

        # Collect remaining output
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Python helper output", py)
        t.dump_output("Rust node stdout", rust)
        t.dump_output("Rust node stderr (last 1000)", rust_stderr.strip().split("\n"))

        # --- Assertions ---

        # 1. Rust propagation announce received by Python
        t.check(
            t.has_line(py, "PY_PROP_ANNOUNCE_RECEIVED"),
            "Rust propagation announce received by Python",
        )

        # 2. Link to propagation node established
        t.check(
            t.has_line(py, "PY_LINK_ACTIVE") and t.has_line(rust, "LINK_ESTABLISHED:"),
            "Link to propagation node established (both sides)",
        )

        # 3. Resource transfer completed
        t.check(
            t.has_line(py, "PY_RESOURCE_TRANSFER_DONE"),
            "Resource transfer completed (LXMF message deposited)",
        )

        # 4. Rust printed PROP_DEPOSIT
        t.check(
            t.has_line(rust, "PROP_DEPOSIT:"),
            "Rust propagation node confirmed deposit (PROP_DEPOSIT)",
        )


if __name__ == "__main__":
    main()
