#!/usr/bin/env python3
"""Live interop test: Rust rete node <-> Python rnsd over TCP.

Tests:
  1. Python sends an announce, Rust node receives and validates it
  2. Rust sends an announce, Python sees it via Transport.has_path()

Usage:
  cd tests/interop
  uv run python live_interop.py --rust-binary ../../target/debug/rete

Or build first:
  cargo build -p rete
  cd tests/interop && uv run python live_interop.py
"""

import time

from interop_helpers import InteropTest


def main():
    with InteropTest("live-interop", default_port=4242) as t:
        t.start_rnsd()
        rust = t.start_rust(
            extra_args=["--auto-reply", "hello from rust"],
        )

        # Give Rust time to connect and announce
        time.sleep(2)

        # Start Python client that announces and discovers Rust
        py = t.start_py_helper(f"""\
import RNS
import time
import sys
import os
import threading

config_dir = os.path.join("{t.tmpdir}", "py_client_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config(transport=False)}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

data_received = threading.Event()

def packet_callback(data, packet):
    text = data.decode("utf-8", errors="replace")
    print(f"PY_DATA_RECEIVED:{{text}}", flush=True)
    data_received.set()

identity = RNS.Identity()
dest = RNS.Destination(
    identity,
    RNS.Destination.IN,
    RNS.Destination.SINGLE,
    "rete",
    "example",
    "v1",
)
dest.set_packet_callback(packet_callback)

print(f"PY_DEST_HASH:{{dest.hexhash}}", flush=True)
print(f"PY_IDENTITY_HASH:{{identity.hexhash}}", flush=True)

dest.announce()
print("PY_ANNOUNCE_SENT", flush=True)

# Wait for Rust announce to appear
timeout = {t.timeout}
deadline = time.time() + timeout
rust_dest_hash = None

while time.time() < deadline:
    known = RNS.Transport.path_table
    for h in known:
        if h != dest.hash:
            rust_dest_hash = h
            print(f"PY_DISCOVERED:{{h.hex()}}", flush=True)
            break
    if rust_dest_hash:
        break
    time.sleep(0.5)

if rust_dest_hash:
    print("PY_INTEROP_OK", flush=True)

    # Send DATA to Rust node
    rust_identity = RNS.Identity.recall(rust_dest_hash)
    if rust_identity:
        out_dest = RNS.Destination(
            rust_identity,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            "rete",
            "example",
            "v1",
        )
        pkt = RNS.Packet(out_dest, b"hello from python")
        pkt.send()
        print("PY_DATA_SENT", flush=True)
    else:
        print("PY_DATA_SEND_FAIL:identity_not_recalled", flush=True)

    # Wait for DATA from Rust (auto-reply)
    if data_received.wait(timeout=10):
        print("PY_DATA_RECV_OK", flush=True)
    else:
        print("PY_DATA_RECV_FAIL:timeout", flush=True)
else:
    print("PY_INTEROP_FAIL:timeout_waiting_for_rust_announce", flush=True)

time.sleep(2)
print("PY_DONE", flush=True)
""")

        # Wait for Python to finish
        t.wait_for_line(py, "PY_DONE", timeout=t.timeout + 10)

        # Give Rust time to process the Python announce
        time.sleep(2)

        # Collect Rust stderr for dest hash extraction
        rust_stderr = t.collect_rust_stderr()

        # Dump output for diagnostics
        t.dump_output("Python helper output", py)
        t.dump_output("Rust node stdout", rust)
        t.dump_output("Rust node stderr (last 1000)", rust_stderr.strip().split("\n"))

        # --- Assertion 1: Python announce sent ---
        t.check(
            t.has_line(py, "PY_ANNOUNCE_SENT"),
            "Python announce sent",
        )

        # --- Assertion 2: Python discovered Rust announce ---
        t.check(
            t.has_line(py, "PY_INTEROP_OK"),
            "Python discovered Rust announce",
        )

        # --- Assertion 3: Rust received Python announce ---
        t.check(
            t.has_line(rust, "ANNOUNCE:"),
            "Rust received Python announce",
        )

        # --- Assertion 4: Rust->Python DATA received by Python ---
        t.check(
            t.has_line(py, "PY_DATA_RECEIVED:"),
            "Rust->Python DATA received by Python",
        )

        # --- Assertion 5: Python->Rust DATA received by Rust ---
        t.check(
            t.has_line(rust, "DATA:", contains="hello from python"),
            "Python->Rust DATA received by Rust",
        )

        # --- Assertion 6: No duplicate announces ---
        announce_lines = [l for l in rust if l.startswith("ANNOUNCE:")]
        identity_hashes = []
        for line in announce_lines:
            parts = line.split(":")
            if len(parts) >= 3:
                identity_hashes.append(parts[2])
        unique_ids = set(identity_hashes)
        t.check(
            len(identity_hashes) == len(unique_ids),
            f"No duplicate announces ({len(announce_lines)} unique announces processed)",
        )

        # --- Assertion 7: Path learned from announce ---
        t.check(
            t.has_line(rust, "ANNOUNCE:"),
            "Path learned from announce (implicit from announce receipt)",
        )

        # --- Assertion 8: Self-announce filtering ---
        # Extract Rust dest hash from IDENTITY line on stdout (preferred)
        # or fall back to parsing stderr.
        rust_dest_hex = None
        for line in rust:
            if line.startswith("IDENTITY:"):
                rust_dest_hex = line.partition(":")[2].strip()
                break
        if not rust_dest_hex:
            for line in rust_stderr.split("\n"):
                if "destination hash:" in line:
                    rust_dest_hex = line.strip().split("destination hash: ")[-1]
                    break

        if rust_dest_hex:
            self_announce_lines = [l for l in announce_lines
                                   if l.startswith(f"ANNOUNCE:{rust_dest_hex}:")]
            t.check(
                len(self_announce_lines) == 0,
                f"Self-announce filtered (own dest {rust_dest_hex[:16]}... never in ANNOUNCE output)",
            )
        else:
            t.check(False, "Could not determine Rust dest hash from stderr")


if __name__ == "__main__":
    main()
