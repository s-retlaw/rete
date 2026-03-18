#!/usr/bin/env python3
"""LXMF auto-forward interop test: Rust propagation node auto-forwards messages.

Topology:
  rnsd (transport=yes, TCP server on localhost:4288)
  Rust node connects as TCP client (--propagation --lxmf-name PropNode)
  Python_sender connects as TCP client, deposits LXMF message
  Python_receiver (late joiner) connects, announces, receives auto-forwarded message

Flow:
  1. Start rnsd + Rust propagation node
  2. Python sender links to Rust, deposits LXMF message via Resource
  3. Wait for PROP_DEPOSIT on Rust
  4. Python receiver creates lxmf.delivery destination, announces
  5. Rust sees announce, fires PropagationForward, initiates link to receiver
  6. Rust sends message via Resource to receiver
  7. Assert Python receiver gets the LXMF message

Usage:
  cd tests/interop
  uv run python lxmf_auto_forward_interop.py --rust-binary ../../target/debug/rete-linux
"""

import os
import subprocess
import sys
import threading
import time

from interop_helpers import InteropTest


def main():
    with InteropTest("lxmf-auto-forward", default_port=4288, default_timeout=60.0) as t:
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
            seed="lxmf-af-seed-01",
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
            print("[lxmf-auto-forward] Cannot continue without propagation hash")
            return

        # --- Create the receiver identity (offline for now) ---
        # We generate the receiver identity in the sender and save it,
        # then the receiver loads it to create its destination.

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
    source_hash = sender_identity.hash[:16]

    # msgpack payload: [timestamp, title, content, {{}}]
    timestamp = time.time()
    title = b"AutoForward"
    content = b"Auto-forwarded test message"

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
            print("[lxmf-auto-forward] Cannot continue without receiver dest hash")
            return

        # --- Python receiver: late joiner announces and receives forwarded message ---
        time.sleep(2)

        py_receiver = t.start_py_helper(f"""\
import RNS
import time
import sys
import os
import threading
import traceback
import bz2

config_dir = os.path.join("{t.tmpdir}", "py_receiver_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config()}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

try:
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

    # Track received messages
    received_messages = []
    received_event = threading.Event()

    # Register a link callback to accept incoming links and resources
    def link_established_cb(link):
        print(f"PY_RECEIVER_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
        link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
        link.set_resource_started_callback(resource_started_cb)
        link.set_resource_concluded_callback(resource_concluded_cb)

    def resource_started_cb(resource):
        print(f"PY_RECEIVER_RESOURCE_STARTED:{{resource.hash.hex()}}:{{resource.total_size}}", flush=True)

    def resource_concluded_cb(resource):
        if resource.status == RNS.Resource.COMPLETE:
            data = resource.data.read()
            print(f"PY_RECEIVER_RESOURCE_COMPLETE:{{resource.hash.hex()}}:{{len(data)}}", flush=True)

            # Try bz2 decompression (Rust sends bz2-compressed LXMF)
            try:
                decompressed = bz2.decompress(data)
                data = decompressed
                print(f"PY_RECEIVER_DECOMPRESSED:{{len(data)}}", flush=True)
            except Exception:
                print("PY_RECEIVER_NOT_BZ2", flush=True)

            # Try to parse as LXMF
            if len(data) >= 96:
                dest_hash = data[:16]
                source_hash = data[16:32]
                print(f"PY_RECEIVER_MSG_DEST:{{dest_hash.hex()}}", flush=True)
                print(f"PY_RECEIVER_MSG_SOURCE:{{source_hash.hex()}}", flush=True)
                received_messages.append(data)
                received_event.set()
            else:
                print(f"PY_RECEIVER_DATA_TOO_SHORT:{{len(data)}}", flush=True)
        else:
            print(f"PY_RECEIVER_RESOURCE_FAILED:{{resource.status}}", flush=True)

    receiver_dest.set_link_established_callback(link_established_cb)

    print("PY_RECEIVER_ANNOUNCING", flush=True)

    # Announce the receiver's destination so the propagation node can detect it
    receiver_dest.announce()
    time.sleep(1)
    # Announce again for reliability
    receiver_dest.announce()

    print("PY_RECEIVER_ANNOUNCED", flush=True)

    # Wait for the auto-forwarded message
    if received_event.wait(timeout={t.timeout}):
        print(f"PY_RECEIVER_GOT_MESSAGE:{{len(received_messages)}}", flush=True)
    else:
        print("PY_RECEIVER_TIMEOUT:no_message_received", flush=True)

except Exception as e:
    print(f"PY_ERROR:{{type(e).__name__}}:{{e}}", flush=True)
    traceback.print_exc()

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
        t.dump_output("Rust node stderr (last 2000)", rust_stderr.strip().split("\n"))

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

        # 3. Deposit confirmed
        t.check(
            t.has_line(rust, "PROP_DEPOSIT:"),
            "PROP_DEPOSIT printed by Rust (message stored)",
        )

        # 4. Forward triggered on receiver announce
        t.check(
            t.has_line(rust, "PROP_FORWARD:"),
            "PROP_FORWARD triggered when receiver announced",
        )

        # 5. Forward link initiated
        t.check(
            t.has_line(rust, "PROP_FORWARD_LINK:"),
            "PROP_FORWARD_LINK: Rust initiated link to receiver for forwarding",
        )

        # 6. Receiver got a link from the propagation node
        t.check(
            t.has_line(py_receiver, "PY_RECEIVER_LINK_ESTABLISHED:"),
            "Receiver accepted incoming link from propagation node",
        )

        # 7. Receiver got the forwarded message via Resource
        t.check(
            t.has_line(py_receiver, "PY_RECEIVER_GOT_MESSAGE:"),
            "Receiver received auto-forwarded LXMF message",
        )


if __name__ == "__main__":
    main()
