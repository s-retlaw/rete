#!/usr/bin/env python3
"""Stats/metrics E2E interop test: verify TransportStats counters work.

Topology:
  rnsd (transport=yes, TCP server on localhost:4248)
  Rust node connects as TCP client to rnsd
  Python client connects as TCP client to rnsd
  Python announces, Rust receives it, then stats command is sent

Assertions:
  1. Stats command returns valid JSON
  2. packets_received > 0
  3. announces_received > 0
  4. paths_learned > 0
  5. uptime_secs >= 0
  6. identity_hash is non-empty

Usage:
  cd tests/interop
  uv run python stats_interop.py --rust-binary ../../target/debug/rete

Or build first:
  cargo build -p rete
  cd tests/interop && uv run python stats_interop.py
"""

import json
import time

from interop_helpers import InteropTest


def main():
    with InteropTest("stats-interop", default_port=4248) as t:
        t.start_rnsd()
        rust = t.start_rust()

        # Give Rust time to connect and announce
        time.sleep(2)

        # Start Python client that announces its presence
        py = t.start_py_helper(f"""\
import RNS
import time
import sys
import os

config_dir = os.path.join("{t.tmpdir}", "py_stats_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config(transport=False)}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

py_identity = RNS.Identity()
py_dest = RNS.Destination(
    py_identity,
    RNS.Destination.IN,
    RNS.Destination.SINGLE,
    "rete",
    "stats",
    "test",
)

py_dest.announce()
print("PY_ANNOUNCE_SENT", flush=True)

# Keep alive so the announce propagates and Rust can see it
time.sleep(8)
print("PY_DONE", flush=True)
""")

        # Wait for Python to send its announce
        t.wait_for_line(py, "PY_ANNOUNCE_SENT")

        # Wait for Rust to receive an announce (either its own reflection or Python's)
        # Give some time for propagation
        time.sleep(3)

        # Send stats command to Rust
        t.send_rust("stats")

        # Wait for STATS: line — value after prefix is the JSON string
        stats_value = t.wait_for_line(rust, "STATS:")

        t.check(
            stats_value is not None,
            "Stats command returned STATS: output",
        )

        if stats_value is not None:
            # The value after "STATS:" prefix in wait_for_line is everything after first ":"
            # But the JSON itself contains ":", so we need to reconstruct the full JSON.
            # wait_for_line returns line.partition(":")[2] which is everything after first ":"
            # For "STATS:{...}" it returns "{...}". Good.
            stats_json_str = stats_value

            try:
                stats = json.loads(stats_json_str)
                t.check(True, "Stats JSON is valid")
            except (json.JSONDecodeError, ValueError) as e:
                t.check(False, f"Stats JSON parse error: {e} (raw: {stats_json_str!r})")
                stats = None

            if stats:
                transport = stats.get("transport", {})

                t.check(
                    transport.get("packets_received", 0) > 0,
                    f"packets_received > 0 (got {transport.get('packets_received', 0)})",
                )
                t.check(
                    transport.get("announces_received", 0) > 0,
                    f"announces_received > 0 (got {transport.get('announces_received', 0)})",
                )
                t.check(
                    transport.get("paths_learned", 0) > 0,
                    f"paths_learned > 0 (got {transport.get('paths_learned', 0)})",
                )
                t.check(
                    stats.get("uptime_secs", -1) >= 0,
                    f"uptime_secs >= 0 (got {stats.get('uptime_secs', -1)})",
                )
                t.check(
                    len(stats.get("identity_hash", "")) > 0,
                    f"identity_hash is non-empty (got {stats.get('identity_hash', '')!r})",
                )
        else:
            # Mark remaining assertions as failed
            for _ in range(5):
                t.check(False, "Skipped: no STATS: output received")

        # Wait for Python to finish
        t.wait_for_line(py, "PY_DONE")


if __name__ == "__main__":
    main()
