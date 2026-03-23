#!/usr/bin/env python3
"""Announce app_data E2E test: near-MTU announces with large app_data (200 bytes).

Tests HDLC + crypto + announce parsing at payload boundaries.

Topology:
  rnsd (transport=yes, TCP server on localhost:4306)
  Rust node connects as TCP client
  Python sends announce with 200-byte app_data

Assertions:
  1. Rust received announce from Python (ANNOUNCE: line present)
  2. Rust stdout ANNOUNCE: line includes app_data hex field
  3. No crash

Usage:
  cd tests/interop
  uv run python announce_appdata_interop.py --rust-binary ../../target/debug/rete-linux
"""

import time

from interop_helpers import InteropTest


def main():
    with InteropTest("announce-appdata", default_port=4306) as t:
        t.start_rnsd()
        rust = t.start_rust()

        # Give Rust time to connect and announce
        time.sleep(3)

        # Python sends announce with large app_data
        py = t.start_py_helper(f"""\
import RNS
import time
import sys
import os

config_dir = os.path.join("{t.tmpdir}", "py_client_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config(transport=False)}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

identity = RNS.Identity()
dest = RNS.Destination(
    identity,
    RNS.Destination.IN,
    RNS.Destination.SINGLE,
    "rete", "example", "v1",
)

# 200-byte app_data
app_data = b"X" * 200
dest.announce(app_data=app_data)
print(f"PY_DEST_HASH:{{dest.hexhash}}", flush=True)
print(f"PY_IDENTITY_HASH:{{identity.hexhash}}", flush=True)
print(f"PY_APPDATA_LEN:{{len(app_data)}}", flush=True)
print(f"PY_APPDATA_HEX:{{app_data.hex()}}", flush=True)
print("PY_ANNOUNCE_SENT", flush=True)

time.sleep(5)
print("PY_DONE", flush=True)
""")

        # Wait for Python to finish
        t.wait_for_line(py, "PY_DONE", timeout=t.timeout + 10)
        time.sleep(2)

        # Collect output
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Python output", py)
        t.dump_output("Rust stdout", rust)
        t.dump_output("Rust stderr (last 1000)", rust_stderr.strip().split("\n"))

        # --- Assertion 1: Rust received announce ---
        announce_lines = [l for l in rust if l.startswith("ANNOUNCE:")]
        t.check(
            len(announce_lines) >= 1,
            "Rust received announce from Python",
        )

        # --- Assertion 2: App_data present in ANNOUNCE output ---
        # The ANNOUNCE: format is now ANNOUNCE:dest_hash:identity_hash:hops:app_data_hex
        # 200 bytes of 0x58 ('X') = "58" * 200 = 400 hex chars
        expected_appdata_hex = "58" * 200
        appdata_in_announce = any(
            expected_appdata_hex in l
            for l in announce_lines
        )
        # Also check stderr for app_data (the eprintln output)
        appdata_in_stderr = 'app_data="' in rust_stderr and "X" * 50 in rust_stderr
        t.check(
            appdata_in_announce or appdata_in_stderr,
            "App_data (200 bytes) correctly parsed and reported",
            detail=f"In stdout={appdata_in_announce} In stderr={appdata_in_stderr}",
        )

        # --- Assertion 3: No crash ---
        has_panic = "panicked" in rust_stderr.lower() or "sigsegv" in rust_stderr.lower()
        t.check(
            not has_panic,
            "No crash (no panic/SIGSEGV in stderr)",
        )


if __name__ == "__main__":
    main()
