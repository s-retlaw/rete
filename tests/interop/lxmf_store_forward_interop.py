#!/usr/bin/env python3
"""LXMF store-and-forward interop test: deposit message, then recipient announces.

Topology:
  rnsd (transport=yes, TCP server on localhost:4287)
  Rust node connects as TCP client (--propagation --lxmf-name PropNode)
  Python_sender connects as TCP client, deposits LXMF message
  Python_receiver (late joiner) connects, announces its destination

Tests:
  1. Propagation announce received
  2. Link to prop node established
  3. Message deposited (PROP_DEPOSIT printed)
  4. Receiver announces, Rust detects stored messages (PROP_FORWARD printed)

Note: Auto-forwarding (actually delivering the stored message to the receiver
via Link+Resource) is not yet implemented in the Rust binary. This test verifies
the store-and-forward detection mechanism. When forwarding is implemented, this
test can be extended to verify actual delivery.

Usage:
  cd tests/interop
  uv run python lxmf_store_forward_interop.py --rust-binary ../../target/debug/rete
"""

import os
import subprocess
import sys
import threading
import time

from interop_helpers import InteropTest


def main():
    with InteropTest("lxmf-store-forward", default_port=4287, default_timeout=60.0) as t:
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
            print("[lxmf-store-forward] Cannot continue without propagation hash")
            return

        # --- Python sender: deposit message to propagation node ---
        py_sender = t.start_py_helper(f"""\
import RNS
import time
import sys
import os
import struct
import hashlib
import threading
import traceback

config_dir = os.path.join("{t.tmpdir}", "py_sender_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config()}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

try:
    # Create sender identity
    sender_identity = RNS.Identity()

    # Create a receiver identity and save it for the receiver to load later
    receiver_identity = RNS.Identity()
    receiver_prv_bytes = receiver_identity.get_private_key()
    with open(os.path.join("{t.tmpdir}", "receiver_identity"), "wb") as f:
        f.write(receiver_prv_bytes)

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

    # Create Link to propagation node
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

    link_established = threading.Event()

    def link_established_cb(link):
        print(f"PY_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
        link_established.set()

    print("PY_INITIATING_LINK", flush=True)
    link = RNS.Link(prop_dest, established_callback=link_established_cb)

    if not link_established.wait(timeout=20):
        print(f"PY_LINK_TIMEOUT:status={{link.status}}", flush=True)
        sys.exit(1)

    print("PY_LINK_ACTIVE", flush=True)

    # Build raw LXMF message for the offline receiver
    # Format: dest_hash[16] || source_hash[16] || signature[64] || msgpack_payload
    source_hash = sender_identity.hash[:16]

    # msgpack payload: [timestamp, title, content, {{}}]
    timestamp = time.time()
    title = b"StoreForward"
    content = b"Store and forward test message"

    payload = bytearray()
    payload.append(0x94)  # fixarray(4)
    payload.append(0xcb)  # float64
    payload.extend(struct.pack(">d", timestamp))
    payload.append(0xc4)  # bin8
    payload.append(len(title))
    payload.extend(title)
    payload.append(0xc4)  # bin8
    payload.append(len(content))
    payload.extend(content)
    payload.append(0x80)  # empty fixmap

    # Sign: dest_hash + source_hash + payload + SHA256(dest_hash + source_hash + payload)
    hashed_part = receiver_dest_hash + source_hash + bytes(payload)
    msg_hash = hashlib.sha256(hashed_part).digest()
    sign_data = hashed_part + msg_hash
    signature = sender_identity.sign(sign_data)

    packed = receiver_dest_hash + source_hash + signature + bytes(payload)
    print(f"PY_LXMF_PACKED:{{len(packed)}}", flush=True)

    # Send as Resource
    resource_sent = threading.Event()

    def resource_complete_cb(resource):
        print(f"PY_RESOURCE_SENT:{{resource.hash.hex()}}:{{resource.total_size}}", flush=True)
        resource_sent.set()

    resource = RNS.Resource(packed, link, callback=resource_complete_cb)
    print(f"PY_RESOURCE_STARTED:{{resource.hash.hex()}}", flush=True)

    if not resource_sent.wait(timeout=30):
        print("PY_FAIL:resource_send_timeout", flush=True)
        sys.exit(1)

    print("PY_DEPOSIT_DONE", flush=True)

    # Teardown sender link
    time.sleep(2)
    link.teardown()
    time.sleep(2)

except Exception as e:
    print(f"PY_ERROR:{{type(e).__name__}}:{{e}}", flush=True)
    traceback.print_exc()

print("PY_SENDER_DONE", flush=True)
""")

        # Wait for sender to finish depositing
        sender_done = t.wait_for_line(py_sender, "PY_SENDER_DONE", timeout=t.timeout)

        # Get the receiver dest hash from sender output
        receiver_dest_hash = None
        for line in py_sender:
            if line.startswith("PY_RECEIVER_DEST_HASH:"):
                receiver_dest_hash = line.split(":")[1].strip()
                break

        t.check(
            receiver_dest_hash is not None,
            "Receiver dest hash extracted from sender",
            detail=f"receiver_dest_hash={receiver_dest_hash}",
        )

        # Check deposit happened
        t.check(
            t.has_line(rust, "PROP_DEPOSIT:"),
            "Message deposited in propagation node (PROP_DEPOSIT)",
        )

        if not receiver_dest_hash:
            print("[lxmf-store-forward] Cannot continue without receiver dest hash")
            return

        # --- Python receiver: late joiner announces ---
        time.sleep(2)

        py_receiver = t.start_py_helper(f"""\
import RNS
import time
import sys
import os

config_dir = os.path.join("{t.tmpdir}", "py_receiver_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config()}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

# Load the receiver identity (saved by sender)
identity_path = os.path.join("{t.tmpdir}", "receiver_identity")
receiver_identity = RNS.Identity.from_file(identity_path)
if not receiver_identity:
    print("PY_FAIL:receiver_identity_load_failed", flush=True)
    sys.exit(1)

# Create the LXMF delivery destination for the receiver
receiver_dest = RNS.Destination(
    receiver_identity,
    RNS.Destination.IN,
    RNS.Destination.SINGLE,
    "lxmf",
    "delivery",
)

print(f"PY_RECEIVER_DEST:{{receiver_dest.hexhash}}", flush=True)
print("PY_RECEIVER_ANNOUNCING", flush=True)

# Announce the receiver's destination so the propagation node can detect it
receiver_dest.announce()
time.sleep(1)
# Announce again for reliability
receiver_dest.announce()

print("PY_RECEIVER_ANNOUNCED", flush=True)

# Wait a bit for Rust to detect the announce and potentially trigger forwarding
time.sleep(10)

print("PY_RECEIVER_DONE", flush=True)
""")

        # Wait for receiver to finish
        t.wait_for_line(py_receiver, "PY_RECEIVER_DONE", timeout=t.timeout)
        time.sleep(3)

        # Collect output
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Python sender output", py_sender)
        t.dump_output("Python receiver output", py_receiver)
        t.dump_output("Rust node stdout", rust)
        t.dump_output("Rust node stderr (last 1500)", rust_stderr.strip().split("\n"))

        # --- Assertions ---

        # 1. Propagation announce received by sender
        t.check(
            t.has_line(py_sender, "PY_PROP_ANNOUNCE_RECEIVED"),
            "Propagation announce received by sender",
        )

        # 2. Link established for deposit
        t.check(
            t.has_line(py_sender, "PY_LINK_ACTIVE") and t.has_line(rust, "LINK_ESTABLISHED:"),
            "Link to prop node established for deposit",
        )

        # 3. Deposit confirmed (already checked above, check Rust stdout)
        deposit_found = t.has_line(rust, "PROP_DEPOSIT:")
        t.check(
            deposit_found,
            "PROP_DEPOSIT printed by Rust (message stored)",
        )

        # 4. Receiver announce detected and forward triggered
        # When the receiver announces its lxmf.delivery destination, the Rust
        # propagation node should detect it has stored messages and print
        # PROP_FORWARD. Note: The current implementation triggers PROP_FORWARD
        # on ANY announce matching a stored dest hash, including lxmf.delivery
        # announces that come through as general AnnounceReceived events.
        forward_found = t.has_line(rust, "PROP_FORWARD:")
        t.check(
            forward_found,
            "PROP_FORWARD triggered when receiver announced",
            detail="Note: auto-forwarding (actual delivery) is not yet implemented" if forward_found else "PROP_FORWARD not seen in Rust output",
        )


if __name__ == "__main__":
    main()
