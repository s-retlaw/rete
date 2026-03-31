#!/usr/bin/env python3
"""LXMF propagation peering interop test: two Rust propagation nodes sync messages.

Topology:
  rnsd (transport=yes, TCP server on localhost:4290)
  Rust node A: propagation + autopeer (has a message deposited via Python before B joins)
  Rust node B: propagation + autopeer
  Verify: nodes discover each other, A syncs message to B

Tests:
  1. Peer discovery (PEER_DISCOVERED) on both nodes
  2. Python deposits LXMF message on node A (PROP_DEPOSIT)
  3. Node A syncs message to node B (PEER_SYNC_COMPLETE or offer exchange)

Usage:
  cd tests/interop
  uv run python lxmf_peering_interop.py --rust-binary ../../target/debug/rete-linux
"""

import os
import subprocess
import sys
import threading
import time

from interop_helpers import InteropTest


def main():
    with InteropTest("lxmf-peering", default_port=4290, default_timeout=90.0) as t:
        try:
            import RNS
        except ImportError:
            print("SKIP: RNS Python package not installed")
            sys.exit(0)

        # --- Start rnsd ---
        t.start_rnsd()
        time.sleep(1)

        # Each node gets its own data dir for isolated identity + snapshot
        data_dir_a = os.path.join(t.tmpdir, "data_a")
        data_dir_b = os.path.join(t.tmpdir, "data_b")
        os.makedirs(data_dir_a, exist_ok=True)
        os.makedirs(data_dir_b, exist_ok=True)

        # --- Start Rust node A ---
        rust_a_proc = subprocess.Popen(
            [
                t.rust_binary,
                "--data-dir", data_dir_a,
                "--connect", f"127.0.0.1:{t.port}",
                "--propagation",
                "--lxmf-name", "NodeA",
                "--lxmf-announce",
                "--autopeer",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        t._procs.append(rust_a_proc)
        t._rust_proc = rust_a_proc

        rust_a = []
        rust_a_stderr = []

        def read_a_stdout():
            for raw in rust_a_proc.stdout:
                rust_a.append(raw.decode(errors="replace").rstrip("\n"))

        def read_a_stderr():
            for raw in rust_a_proc.stderr:
                rust_a_stderr.append(raw.decode(errors="replace").rstrip("\n"))

        threading.Thread(target=read_a_stdout, daemon=True).start()
        threading.Thread(target=read_a_stderr, daemon=True).start()

        # Wait for A to start
        time.sleep(4)

        # Get node A's propagation hash
        prop_hash_a = None
        for line in rust_a_stderr:
            if "LXMF propagation hash:" in line:
                prop_hash_a = line.split(":")[-1].strip()
                break

        t.check(
            prop_hash_a is not None and len(prop_hash_a) == 32,
            "Node A propagation hash found",
            detail=f"prop_hash={prop_hash_a}" if prop_hash_a else "not found",
        )

        if not prop_hash_a:
            print("[lxmf-peering] Cannot continue without prop hash")
            return

        # --- Deposit a message on A using Python (before B starts) ---
        # We need to also send the delivery announce so Python can find node A.
        # Use lxmf-prop-announce command to send it now
        py_sender = t.start_py_helper(f"""\
import RNS
import time
import sys
import os
import struct
import hashlib
import threading

config_dir = os.path.join("{t.tmpdir}", "py_sender_config")
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

    # Wait for prop announce
    prop_dest_bytes = bytes.fromhex("{prop_hash_a}")
    deadline = time.time() + 40
    while time.time() < deadline:
        if RNS.Transport.has_path(prop_dest_bytes):
            break
        time.sleep(0.5)
    else:
        print("PY_FAIL:prop_announce_timeout", flush=True)
        print("PY_SENDER_DONE", flush=True)
        sys.exit(0)

    print("PY_PROP_FOUND", flush=True)

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
        link_established.set()

    link = RNS.Link(prop_dest, established_callback=link_cb)
    if not link_established.wait(timeout=20):
        print("PY_FAIL:link_timeout", flush=True)
        print("PY_SENDER_DONE", flush=True)
        sys.exit(0)

    source_hash = sender_identity.hash[:16]
    timestamp = time.time()
    title = b"PeerTest"
    content = b"Peering sync test message"

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
        resource_sent.set()

    resource = RNS.Resource(packed, link, callback=resource_cb)
    if not resource_sent.wait(timeout=30):
        print("PY_FAIL:resource_timeout", flush=True)
        print("PY_SENDER_DONE", flush=True)
        sys.exit(0)

    print("PY_DEPOSIT_DONE", flush=True)
    time.sleep(2)
    link.teardown()

except Exception as e:
    print(f"PY_ERROR:{{type(e).__name__}}:{{e}}", flush=True)
    import traceback
    traceback.print_exc()

print("PY_SENDER_DONE", flush=True)
""")

        t.wait_for_line(py_sender, "PY_SENDER_DONE", timeout=50)

        deposit_ok = any("PROP_DEPOSIT:" in line for line in rust_a)
        py_deposit_ok = any("PY_DEPOSIT_DONE" in line for line in py_sender)
        t.check(deposit_ok or py_deposit_ok, "Message deposited on node A")

        if not deposit_ok:
            # Python couldn't reach prop node — skip remaining sync tests
            t.dump_output("Python sender", py_sender)
            t.dump_output("Rust A stderr", rust_a_stderr[-20:])
            print("[lxmf-peering] Deposit failed, skipping sync checks")
            t.check(False, "Node A completed peer sync (skipped)")
            t.check(False, "Node B received message via peer sync (skipped)")
            return

        # --- Now start node B ---
        rust_b_proc = subprocess.Popen(
            [
                t.rust_binary,
                "--data-dir", data_dir_b,
                "--connect", f"127.0.0.1:{t.port}",
                "--propagation",
                "--autopeer",
                "--lxmf-name", "NodeB",
                "--lxmf-announce",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        t._procs.append(rust_b_proc)

        rust_b = []
        rust_b_stderr = []

        def read_b_stdout():
            for raw in rust_b_proc.stdout:
                rust_b.append(raw.decode(errors="replace").rstrip("\n"))

        def read_b_stderr():
            for raw in rust_b_proc.stderr:
                rust_b_stderr.append(raw.decode(errors="replace").rstrip("\n"))

        threading.Thread(target=read_b_stdout, daemon=True).start()
        threading.Thread(target=read_b_stderr, daemon=True).start()

        # Wait for peer discovery + sync cycle
        time.sleep(25)

        # Check peer discovery
        has_peer_a = any("PEER_DISCOVERED:" in line for line in rust_a)
        has_peer_b = any("PEER_DISCOVERED:" in line for line in rust_b)
        t.check(has_peer_a or has_peer_b, "At least one node discovered a peer")

        # Check sync events
        has_sync = any(
            "PEER_SYNC_COMPLETE:" in line or "PEER_OFFER_RECEIVED:" in line
            for line in rust_a + rust_b
        )
        t.check(has_sync, "Peer sync exchange occurred")

        # Check if node B received the message via sync
        has_b_deposit = any(
            "PROP_DEPOSIT:" in line or "PEER_SYNC_DEPOSIT:" in line
            for line in rust_b
        )
        t.check(has_b_deposit, "Node B received message via peer sync")

        # Dump output for diagnostics
        t.dump_output("Python sender", py_sender)
        t.dump_output("Rust A stdout (last 20)", rust_a[-20:] if rust_a else [])
        t.dump_output("Rust B stdout (last 20)", rust_b[-20:] if rust_b else [])
        t.dump_output("Rust A stderr (last 20)", rust_a_stderr[-20:] if rust_a_stderr else [])
        t.dump_output("Rust B stderr (last 20)", rust_b_stderr[-20:] if rust_b_stderr else [])


if __name__ == "__main__":
    main()
